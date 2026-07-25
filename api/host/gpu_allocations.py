"""Validator-owned GPU inventory, allocation, reservation, and reset lifecycle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, null, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import generate_uuid
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReconcileResponseV1,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    GpuLaunchReservationClaimsV1,
    GpuLaunchReservationResponseV1,
    GpuMinerReservationRequestV1,
    GpuPlatformReservationRequestV1,
    GpuQuoteCommitmentV1,
    GpuRecoveryAuthorizationV1,
    GpuRecoveryAuthorizeRequestV1,
    GpuRecoveryResetResultV1,
    GpuRecoveryStartRequestV1,
    GpuReservationClaimRequestV1,
    GpuReservationStateRequestV1,
    GpuResetResultV1,
    GpuSignedLaunchClaimsEnvelopeV1,
    canonical_json_bytes,
    canonical_sha256,
)
from api.host.locks import acquire_gpu_lifecycle_lock
from api.releases.provenance import ProvenanceError, load_canonical_provenance
from api.releases.schemas import GuestRelease, RELEASE_STATUS_ACTIVE
from api.server.schemas import (
    GpuInfraCustody,
    GpuLegacyMigration,
    GpuMinerIdentity,
    Host,
    Server,
    ServerAttestation,
    VmCacheConfig,
)

GPU_RESERVATION_LIFETIME_SECONDS = 900
_ACTIVE_RESERVATION_STATES = {
    "reserved",
    "claimed",
    "launching",
    "running",
    "resetting",
}
_LAUNCH_DEADLINE_STATES = {"reserved", "claimed", "launching"}
_NON_IDLE_GROUP_STATES = {
    "reserved",
    "launching",
    "running",
    "resetting",
    "quarantined",
}


class GpuAllocationError(ValueError):
    pass


class GpuAllocationQuarantinedError(GpuAllocationError):
    """The rejection intentionally mutated durable state to quarantine."""


def sign_gpu_launch_claims(
    claims: GpuLaunchReservationClaimsV1,
) -> GpuSignedLaunchClaimsEnvelopeV1:
    """Sign the frozen canonical claim bytes with the validator launch key."""

    private_key = getattr(settings, "launch_config_private_key", None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise GpuAllocationError(
            "GPU launch claims require the configured P-256 launch signing key."
        )
    key_epoch = getattr(settings, "gpu_launch_key_epoch", None)
    if not isinstance(key_epoch, int) or isinstance(key_epoch, bool) or key_epoch < 1:
        raise GpuAllocationError("GPU launch signing key epoch must be positive.")
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = private_key.sign(
        canonical_json_bytes(claims),
        ec.ECDSA(hashes.SHA256()),
    )
    return GpuSignedLaunchClaimsEnvelopeV1(
        key_id=hashlib.sha256(public_der).hexdigest(),
        key_epoch=key_epoch,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=base64.b64encode(signature).decode("ascii"),
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _parse_mem_mib(value: Optional[str]) -> Optional[int]:
    if not value or len(value) < 2:
        return None
    try:
        amount = int(value[:-1])
    except ValueError:
        return None
    return amount * (1024 if value[-1] == "G" else 1) if value[-1] in "GM" else None


async def _host_lock(db: AsyncSession, host_id: str) -> Host:
    await acquire_gpu_lifecycle_lock(db)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"gpu-allocation-host:{host_id}"},
    )
    host = (
        await db.execute(select(Host).where(Host.host_id == host_id).with_for_update())
    ).scalar_one_or_none()
    if host is None:
        raise GpuAllocationError("GPU logical host is unknown.")
    return host


async def _stable_miner_identity(
    db: AsyncSession,
    host: Host,
    legacy_vm_name: Optional[str],
) -> GpuMinerIdentity:
    """Create or return the validator-owned logical miner fabric identity."""

    identity = (
        await db.execute(
            select(GpuMinerIdentity)
            .where(GpuMinerIdentity.host_id == host.host_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if identity is None:
        identity = GpuMinerIdentity(
            host_id=host.host_id,
            server_id=f"gpu-miner-{generate_uuid()}",
            owner_hotkey=host.miner_hotkey,
            legacy_vm_name=legacy_vm_name,
        )
        db.add(identity)
        await db.flush()
    elif identity.owner_hotkey != host.miner_hotkey:
        raise GpuAllocationError("Stable GPU miner identity belongs to another host owner.")
    elif legacy_vm_name is not None and legacy_vm_name != identity.legacy_vm_name:
        raise GpuAllocationError(
            "Stable GPU miner identity cannot change its legacy migration source."
        )
    server = await db.get(Server, identity.server_id)
    if server is not None and (
        server.miner_hotkey != host.miner_hotkey
        or (server.gpu_retired_at is None and server.gpu_launch_reservation_id is not None)
    ):
        raise GpuAllocationError(
            "Stable GPU miner identity still has an active or conflicting server lineage."
        )
    identity.updated_at = _utcnow()
    return identity


async def _require_resumable_legacy_migration(
    db: AsyncSession,
    migration: GpuLegacyMigration,
    host: Host,
) -> None:
    if migration.state == "ready":
        return
    if migration.state not in {"leased", "promoted"}:
        raise GpuAllocationError("Legacy GPU migration is not resumable.")
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == migration.target_server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    target_server = (
        await db.execute(
            select(Server).where(Server.server_id == migration.target_server_id).with_for_update()
        )
    ).scalar_one_or_none()
    legacy_server = (
        await db.execute(
            select(Server).where(Server.server_id == migration.legacy_server_id).with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None:
        raise GpuAllocationError("Resumed migration has no sealed target custody.")
    prior_reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == custody.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    failure_metadata = (
        dict(prior_reservation.failure_metadata or {}) if prior_reservation is not None else {}
    )
    qemu_reset_proven = bool(
        prior_reservation is not None
        and (
            prior_reservation.state == "released"
            or (
                prior_reservation.state == "quarantined"
                and failure_metadata.get("qemu_absent") is True
                and failure_metadata.get("reset_succeeded") is True
                and failure_metadata.get("original_drivers_restored") is True
            )
        )
    )
    legacy_config = (
        await db.execute(
            select(VmCacheConfig)
            .where(
                VmCacheConfig.miner_hotkey == migration.owner_hotkey,
                VmCacheConfig.vm_name == migration.legacy_vm_name,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    stored = dict(legacy_config.volume_passphrases or {}) if legacy_config else {}
    floors = dict(legacy_config.volume_epochs or {}) if legacy_config else {}
    leases = dict(legacy_config.volume_generation_leases or {}) if legacy_config else {}
    if (
        migration.host_id != host.host_id
        or migration.owner_hotkey != host.miner_hotkey
        or custody.migration_id != migration.migration_id
        or custody.state != "sealed"
        or target_server is None
        or target_server.gpu_retired_at is None
        or target_server.gpu_runtime_session_attestation_id is not None
        or target_server.gpu_runtime_session_expires_at is not None
        or legacy_server is None
        or legacy_server.gpu_retired_at is None
        or not qemu_reset_proven
        or any(
            key in stored
            for key in (
                "storage",
                "pending_storage",
                "tdx-cache",
                "pending_tdx-cache",
            )
        )
        or any(key in floors for key in ("storage", "tdx-cache"))
        or any(key in leases for key in ("storage", "tdx-cache"))
    ):
        raise GpuAllocationError("Prior target teardown or legacy dual-reader fence is not exact.")


async def _active_gpu_release(
    db: AsyncSession,
    host: Host,
    *,
    for_update: bool = True,
) -> tuple[GuestRelease, dict[str, Any], dict[str, Any]]:
    query = select(GuestRelease).where(
        GuestRelease.status == RELEASE_STATUS_ACTIVE,
        GuestRelease.channel == host.release_channel,
        GuestRelease.tee_type == "tdx",
        GuestRelease.compute_type == "gpu",
    )
    if for_update:
        query = query.with_for_update()
    release = (await db.execute(query)).scalar_one_or_none()
    image = (release.images or {}).get("gpu") if release is not None else None
    if release is None or not isinstance(image, dict):
        raise GpuAllocationError("GPU host has no active exact GPU release.")
    from api.releases.service import ReleaseError, _validate_active_release

    try:
        _validate_active_release(release)
    except ReleaseError as exc:
        raise GpuAllocationError(
            f"Active GPU release failed current trust revalidation: {exc}"
        ) from exc
    payload = image.get("provenance_payload")
    if not isinstance(payload, str) or not payload:
        raise GpuAllocationError("Active GPU release has no canonical provenance.")
    try:
        provenance = load_canonical_provenance(payload)
    except ProvenanceError as exc:
        raise GpuAllocationError(f"Active GPU release provenance is not trusted: {exc}") from exc
    if (
        provenance.get("schema_version") != 3
        or provenance.get("compute_type") != "gpu"
        or provenance.get("tee_type") != "tdx"
        or provenance.get("role") != "gpu"
    ):
        raise GpuAllocationError("Active GPU release provenance is not GPU TDX v3.")
    return release, image, provenance


async def _trusted_platform_workload(
    db: AsyncSession,
    request: GpuPlatformReservationRequestV1,
) -> tuple[str, str, str, str, dict[str, Any]]:
    from api.chute.schemas import Chute, NodeSelector
    from api.image.forge import get_image_digest
    from api.image.schemas import Image
    from api.job.schemas import Job

    await acquire_gpu_lifecycle_lock(db)
    chute = (
        await db.execute(select(Chute).where(Chute.chute_id == request.chute_id).with_for_update())
    ).scalar_one_or_none()
    if chute is None or not chute.tee or chute.disabled:
        raise GpuAllocationError("Platform GPU reservation requires an enabled TEE chute.")
    image = (
        await db.execute(select(Image).where(Image.image_id == chute.image_id).with_for_update())
    ).scalar_one_or_none()
    if (
        image is None
        or image.compute_type != "gpu"
        or image.user_id != chute.user_id
        or image.status != "built and pushed"
    ):
        raise GpuAllocationError("Chute GPU image is not a completed validator-owned build.")
    job = None
    if request.job_id is not None:
        job = (
            await db.execute(select(Job).where(Job.job_id == request.job_id).with_for_update())
        ).scalar_one_or_none()
        if (
            job is None
            or job.chute_id != chute.chute_id
            or job.version != chute.version
            or job.finished_at is not None
            or job.gpu_management_mode not in {None, "platform"}
        ):
            raise GpuAllocationError(
                "GPU job no longer matches the reserved chute/version lineage."
            )
    try:
        selector = NodeSelector(
            **(job.node_selector if job is not None and job.node_selector else chute.node_selector)
        )
    except ValueError as exc:
        raise GpuAllocationError("GPU workload selector is malformed.") from exc
    if (
        selector.compute_type != "gpu"
        or selector.gpu_count != request.gpu_count
        or request.gpu_identifier not in selector.supported_gpus
        or request.minimum_vram_mib < int(selector.min_vram_gb_per_gpu or 0) * 1024
    ):
        raise GpuAllocationError(
            "GPU reservation request does not match chute/job include, exclude, count, or VRAM."
        )
    image_ref = f"{image.user.username}/{image.name}:{image.tag}".lower()
    if image.patch_version not in (None, "initial"):
        image_ref += f"-{image.patch_version}"
    repository = image_ref.rsplit(":", 1)[0]
    try:
        manifest_digest = await get_image_digest(f"{settings.registry_host}/{image_ref}")
    except Exception as exc:
        raise GpuAllocationError("Validator could not resolve the chute image digest.") from exc
    from api.registry.oci import OciClosureError, resolve_oci_descriptor_closure

    try:
        closure = await resolve_oci_descriptor_closure(
            repository,
            manifest_digest,
        )
    except OciClosureError as exc:
        raise GpuAllocationError(
            "Validator could not resolve the descriptor-closed cosign image graph."
        ) from exc
    closure_document = {
        "descriptor_closure_sha256": closure.sha256,
        "allowed_manifests": list(closure.manifests),
        "allowed_blobs": list(closure.blobs),
        "allowed_manifest_tags": list(closure.manifest_tags),
        "manifest_tag_digests": dict(closure.manifest_tag_digests),
    }
    return (
        job.user_id if job is not None else chute.user_id,
        job.version if job is not None else chute.version,
        repository,
        manifest_digest,
        closure_document,
    )


def _gpu_release_target_sha256(
    *,
    release: GuestRelease,
    image: dict[str, Any],
    group: GpuAllocationGroup,
    management_mode: str,
    measurement_name: str,
    environment: dict[str, Any],
    artifacts: dict[str, Any],
) -> str:
    return canonical_sha256(
        {
            "schema": "chutes.gpu-release-target",
            "version": 1,
            "release_id": release.release_id,
            "compute_type": "gpu",
            "tee_type": "tdx",
            "management_mode": management_mode,
            "allocation_group_id": group.allocation_group_id,
            "allocation_group_generation": group.generation,
            "profile_id": group.profile_id,
            "profile_contract_sha256": group.profile_contract_sha256,
            "topology_fingerprint": group.topology_fingerprint,
            "measurement_name": measurement_name,
            "qemu_binary_sha256": environment["qemu_binary_sha256"],
            "qemu_package_version": environment["qemu_package_version"],
            "machine_type": environment["machine_type"],
            "tdvf_sha256": environment["firmware_sha256"],
            "image_sha256": image["sha256"],
            "image_version": image["version"],
            "kernel_sha256": artifacts["kernel_sha256"],
            "initrd_sha256": artifacts["initrd_sha256"],
            "mode_cmdline_sha256": artifacts["cmdline_sha256"][management_mode],
            "kernel_measurement_mode": artifacts["kernel_measurement_mode"],
        }
    )


def _profile_for_report(
    report: GpuInventoryReportV1,
    provenance: dict[str, Any],
    required_profile_id: str,
) -> dict[str, Any]:
    contract = provenance["profile_contract"]
    if report.profile_contract_sha256 != provenance["profile_contract_sha256"]:
        raise GpuAllocationError(
            "Inventory profile-contract identity does not match signed provenance."
        )
    group = report.groups[0]
    if group.reported_profile_id != required_profile_id:
        raise GpuAllocationError(
            "Inventory profile differs from the signed L0 GPU profile closure."
        )
    unsupported_ids = {item["id"] for item in contract.get("unsupported_profiles", [])}
    if (
        group.reported_profile_id in unsupported_ids
        or group.reported_profile_id.startswith("b300")
        or group.model == "B300"
        or any(device.gpu_identifier == "b300" for device in group.devices)
    ):
        raise GpuAllocationError("B300 inventory is uncharacterized and cannot enter allocation.")
    profile = next(
        (item for item in contract["profiles"] if item["id"] == group.reported_profile_id),
        None,
    )
    if profile is None:
        raise GpuAllocationError("Inventory cannot select a profile absent from signed provenance.")
    allocation = profile["allocation"]
    if allocation != {
        "kind": "whole-fabric",
        "groups": 1,
        "devices_per_group": profile["gpu_count"],
        "allow_partial": False,
    }:
        raise GpuAllocationError(
            "The active GPU profile does not define one indivisible whole fabric."
        )
    devices = group.devices
    identifiers = {item.gpu_identifier for item in devices}
    device_ids = {item.pci_device_id for item in devices}
    if (
        group.model != profile["model"]
        or len(devices) != profile["gpu_count"]
        or len(identifiers) != 1
        or not identifiers.issubset(set(profile["expected_gpu_identifiers"]))
        or not device_ids.issubset(set(profile["pci_device_ids"]))
        or any(item.vram_mib != profile["vram_mib"] for item in devices)
    ):
        raise GpuAllocationError(
            "Inventory model/count/VRAM/identifier set does not match signed profile."
        )
    topology = profile["topology"]
    observed_nodes = [item.numa_node for item in devices]
    if (
        group.host_numa_nodes != topology["host_numa_nodes"]
        or len(group.nvswitches) != topology["nvswitch_count"]
        or len(group.infiniband_devices) != topology["infiniband_count"]
        or any(item.link_count != topology["nvlink_links_per_pair"] for item in group.nvlink_edges)
    ):
        raise GpuAllocationError(
            "Inventory host NUMA/NVSwitch/InfiniBand dimensions differ from signed profile."
        )
    if topology["kind"] == "numa-pxb":
        if observed_nodes != topology["gpu_numa_nodes"]:
            raise GpuAllocationError("Inventory GPU NUMA topology does not match signed profile.")
    elif len(devices) != profile["gpu_count"]:
        raise GpuAllocationError("Flat GPU topology count does not match signed profile.")
    return profile


def _l0_gpu_profile_id(
    manifest: dict[str, Any],
    provenance: dict[str, Any],
) -> str:
    profile_id = manifest.get("gpu_profile_id")
    environment = next(
        (item for item in provenance["launch_environments"] if item["profile_id"] == profile_id),
        None,
    )
    if (
        manifest.get("version") != 2
        or manifest.get("compute_type") != "gpu"
        or not isinstance(profile_id, str)
        or environment is None
        or manifest.get("gpu_qemu_sha256s") != [environment["qemu_binary_sha256"]]
        or manifest.get("gpu_tdvf_sha256s") != [environment["firmware_sha256"]]
    ):
        raise GpuAllocationError(
            "Signed L0 GPU profile/QEMU/TDVF closure differs from release provenance."
        )
    return profile_id


def _validate_resource_budget(
    host: Host,
    report: GpuInventoryReportV1,
    profile: dict[str, Any],
) -> None:
    resources = report.resources
    signed_host = profile["host"]
    guest = profile["guest"]
    pci = profile["pci"]
    storage_memory_mib = _parse_mem_mib(host.storage_td_mem)
    if (
        resources.logical_cpus != signed_host["logical_cpus"]
        or resources.storage_vcpus != host.storage_td_vcpus
        or storage_memory_mib is None
        or resources.storage_memory_mib != storage_memory_mib
    ):
        raise GpuAllocationError(
            "Reported CPU/storage shape does not match validator-owned host profile."
        )
    if (
        guest["vcpus"] > resources.qemu_max_vcpus
        or guest["memory_mib"] > resources.qemu_max_memory_mib
        or guest["vcpus"] > 4096
        or guest["memory_mib"] * 1024**2 > 2**63 - 1
    ):
        raise GpuAllocationError("GPU profile exceeds QEMU integer limits.")
    if (
        resources.storage_vcpus + resources.l0_reserved_vcpus > signed_host["reserved_logical_cpus"]
        or guest["vcpus"] + resources.storage_vcpus + resources.l0_reserved_vcpus
        > resources.logical_cpus
    ):
        raise GpuAllocationError(
            "GPU guest, storage TD, and L0 CPU reserves exceed aggregate capacity."
        )
    required_memory = (
        guest["memory_mib"]
        + resources.gpu_overhead_mib
        + resources.storage_memory_mib
        + resources.storage_overhead_mib
        + resources.l0_reserved_memory_mib
    )
    if required_memory > resources.memory_mib:
        raise GpuAllocationError(
            "GPU guest, storage TD, and L0 RAM reserves exceed aggregate capacity."
        )
    required_disk = (
        resources.storage_disk_mib
        + resources.storage_scratch_disk_mib
        + resources.gpu_infra_disk_mib
        + resources.gpu_scratch_disk_mib
    )
    if (
        required_disk > resources.data_disk_total_mib
        or resources.disk_allocation_shortfall_mib > resources.data_disk_free_mib
    ):
        raise GpuAllocationError(
            "Mandatory storage, gpu-infra, and GPU scratch exceed free data disk."
        )
    required_mmio = pci["gpu_bar_mib"] * profile["gpu_count"]
    address_space_mib = (1 << resources.physical_address_bits) // (1024**2)
    if (
        required_mmio > resources.mmio64_aperture_mib
        or required_mmio + guest["memory_mib"] > address_space_mib
    ):
        raise GpuAllocationError(
            "GPU BAR/MMIO requirements exceed the characterized address-space limits."
        )


def _group_values(
    report: GpuInventoryReportV1,
    profile: dict[str, Any],
) -> dict[str, Any]:
    group = report.groups[0]
    devices = group.devices
    iommu = [
        {
            "bdf": item.bdf,
            "group": item.iommu_group,
            "members": item.iommu_members,
        }
        for item in devices
    ]
    reset = [
        {
            "bdf": item.bdf,
            "domain": item.reset_domain,
            "members": item.reset_members,
            "original_driver": item.original_driver,
        }
        for item in devices
    ]
    switches = [item.model_dump(mode="json") for item in group.nvswitches]
    infiniband = [item.model_dump(mode="json") for item in group.infiniband_devices]
    fabrics = [item.model_dump(mode="json") for item in group.fabrics]
    return {
        "profile_id": profile["id"],
        "profile_contract_sha256": report.profile_contract_sha256,
        "topology_fingerprint": group.topology_fingerprint,
        "gpu_bdfs": [item.bdf for item in devices],
        "gpu_uuids": sorted(item.uuid for item in devices),
        "gpu_identifiers": sorted(item.gpu_identifier for item in devices),
        "gpu_attestation_certificate_sha256s": sorted(
            item.attestation_certificate_sha256 for item in devices
        ),
        "iommu_domains": iommu,
        "reset_domains": reset,
        "nvlink_edges": [item.model_dump(mode="json") for item in group.nvlink_edges],
        "nvswitch_fabric": switches + infiniband + fabrics,
        "model": profile["model"],
        "gpu_count": profile["gpu_count"],
        "vram_mib": profile["vram_mib"],
    }


def _quarantine_group(
    group: GpuAllocationGroup,
    *,
    code: str,
    reason: str,
    metadata: Optional[dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> None:
    now = now or _utcnow()
    group.state = "quarantined"
    group.quarantined_at = now
    group.failure_code = code
    group.failure_reason = reason
    group.failure_metadata = metadata or {}
    group.updated_at = now


def _quarantine_reservation(
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
    *,
    code: str,
    reason: str,
    metadata: Optional[dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> None:
    now = now or _utcnow()
    reservation.state = "quarantined"
    reservation.quarantined_at = now
    reservation.failure_code = code
    reservation.failure_reason = reason
    reservation.failure_metadata = metadata or {}
    _quarantine_group(group, code=code, reason=reason, metadata=metadata, now=now)


async def _quarantine_group_reservations(
    db: AsyncSession,
    group: GpuAllocationGroup,
    *,
    code: str,
    reason: str,
    metadata: Optional[dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> None:
    await acquire_gpu_lifecycle_lock(db)
    now = now or _utcnow()
    reservations = (
        (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.allocation_group_id == group.allocation_group_id,
                    GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                )
                .order_by(GpuLaunchReservation.reservation_generation)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for reservation in reservations:
        if reservation.state != "resetting":
            _quarantine_reservation(
                reservation,
                group,
                code=code,
                reason=reason,
                metadata=metadata,
                now=now,
            )
            await _retire_gpu_runtime_lineage(
                db,
                reservation,
                now,
                reason=reason,
            )
    if not reservations:
        _quarantine_group(
            group,
            code=code,
            reason=reason,
            metadata=metadata,
            now=now,
        )


async def fence_gpu_host_authority(
    db: AsyncSession,
    host_id: str,
    *,
    code: str,
    reason: str,
) -> None:
    """Fence every group/reservation under the global host→group→reservation order."""

    host = await _host_lock(db, host_id)
    if host.compute_type != "gpu":
        return
    now = _utcnow()
    groups = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.host_id == host_id)
                .order_by(GpuAllocationGroup.allocation_group_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for group in groups:
        reservations = (
            (
                await db.execute(
                    select(GpuLaunchReservation)
                    .where(
                        GpuLaunchReservation.allocation_group_id == group.allocation_group_id,
                        GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                    )
                    .order_by(GpuLaunchReservation.reservation_generation)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for reservation in reservations:
            if reservation.state == "reserved" and reservation.claimed_at is None:
                reservation.state = "expired"
                reservation.expired_at = now
            elif reservation.state in {"claimed", "launching", "running"}:
                _quarantine_reservation(
                    reservation,
                    group,
                    code=code,
                    reason=reason,
                    now=now,
                )
                await _retire_gpu_runtime_lineage(
                    db,
                    reservation,
                    now,
                    reason=reason,
                )
        if group.state in {"discovered", "available", "reserved"} and not any(
            item.state in {"claimed", "launching", "running", "quarantined"}
            for item in reservations
        ):
            group.state = "retired"
            group.retired_at = now
            group.management_mode = None
            group.reservation_owner = None
            group.reservation_id = None
            group.process_incarnation = None
            group.updated_at = now
    await db.flush()


async def advance_gpu_host_boot(
    db: AsyncSession,
    authenticated_host: Host,
    boot_id: str,
) -> int:
    """Advance the logical boot fence and quarantine ownership across a reboot."""

    if authenticated_host.compute_type != "gpu":
        raise GpuAllocationError("Only GPU hosts carry a GPU boot generation.")
    boot_id = boot_id.lower()
    host = await _host_lock(db, authenticated_host.host_id)
    if host.active_key_generation != authenticated_host.active_key_generation:
        raise GpuAllocationError("GPU host key generation changed during registration.")
    if host.boot_id == boot_id:
        if int(host.boot_generation or 0) < 1:
            raise GpuAllocationError("GPU host has an invalid persisted boot generation.")
        return int(host.boot_generation)

    now = _utcnow()
    groups = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.host_id == host.host_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    reservations = (
        (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.host_id == host.host_id,
                    GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    groups_by_id = {item.allocation_group_id: item for item in groups}
    for reservation in reservations:
        group = groups_by_id.get(reservation.allocation_group_id)
        if group is not None:
            if reservation.state == "reserved" and reservation.claimed_at is None:
                reservation.state = "expired"
                reservation.expired_at = now
            elif reservation.state in {"claimed", "launching", "running"}:
                _quarantine_reservation(
                    reservation,
                    group,
                    code="host_boot_changed_with_ownership",
                    reason=("Logical host boot changed while PCI ownership was not proven reset."),
                    metadata={"previous_boot_id": host.boot_id, "new_boot_id": boot_id},
                    now=now,
                )
                await _retire_gpu_runtime_lineage(
                    db,
                    reservation,
                    now,
                    reason="Logical host boot changed with active GPU ownership.",
                )
    for group in groups:
        if group.state in {"discovered", "available", "reserved"} and not any(
            item.state in {"claimed", "launching", "running", "quarantined"}
            for item in reservations
            if item.allocation_group_id == group.allocation_group_id
        ):
            group.state = "retired"
            group.retired_at = now
            group.management_mode = None
            group.reservation_owner = None
            group.reservation_id = None
            group.process_incarnation = None
            group.updated_at = now
        elif group.state == "resetting":
            continue
        elif group.state != "retired" and group.state != "quarantined":
            _quarantine_group(
                group,
                code="host_boot_changed_with_ambiguous_state",
                reason="Logical host boot changed before exact group reset completed.",
                metadata={"previous_boot_id": host.boot_id, "new_boot_id": boot_id},
                now=now,
            )
    host.boot_id = boot_id
    host.boot_generation = int(host.boot_generation or 0) + 1
    host.gpu_inventory_report_generation = 0
    host.gpu_inventory_fingerprint = None
    host.gpu_inventory_reconciled_at = None
    await db.flush()
    return int(host.boot_generation)


async def _expire_locked_reservations(
    db: AsyncSession,
    host_id: str,
    *,
    now: Optional[datetime] = None,
) -> None:
    now = now or _utcnow()
    groups = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.host_id == host_id)
                .order_by(GpuAllocationGroup.allocation_group_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for group in groups:
        reservations = (
            (
                await db.execute(
                    select(GpuLaunchReservation)
                    .where(
                        GpuLaunchReservation.allocation_group_id == group.allocation_group_id,
                        GpuLaunchReservation.state.in_(_LAUNCH_DEADLINE_STATES),
                        GpuLaunchReservation.expires_at <= now,
                    )
                    .order_by(GpuLaunchReservation.reservation_generation)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for reservation in reservations:
            if reservation.state == "reserved" and reservation.claimed_at is None:
                reservation.state = "expired"
                reservation.expired_at = now
                if group.reservation_id == reservation.reservation_id and group.state == "reserved":
                    group.state = "available"
                    group.management_mode = None
                    group.reservation_owner = None
                    group.reservation_id = None
                    group.process_incarnation = None
                    group.available_at = now
                    group.reserved_at = None
                    group.updated_at = now
            elif reservation.state in {"claimed", "launching"}:
                _quarantine_reservation(
                    reservation,
                    group,
                    code="reservation_expired_after_host_claim",
                    reason=(
                        "A claimed or launching GPU reservation passed its launch "
                        "deadline without exact reset proof."
                    ),
                    now=now,
                )
                await _retire_gpu_runtime_lineage(
                    db,
                    reservation,
                    now,
                    reason="GPU launch deadline expired after host claim.",
                )


async def reconcile_gpu_inventory(
    db: AsyncSession,
    authenticated_host: Host,
    report: GpuInventoryReportV1,
) -> GpuInventoryReconcileResponseV1:
    """Reconcile signed logical-host telemetry only against signed release provenance."""

    host = await _host_lock(db, authenticated_host.host_id)
    observed_at = report.observed_at
    if observed_at.tzinfo is None:
        raise GpuAllocationError("GPU inventory observed_at must be timezone-aware.")
    if abs((_utcnow() - observed_at).total_seconds()) > 300:
        raise GpuAllocationError("GPU inventory observed_at is stale or future-dated.")
    if (
        host.compute_type != "gpu"
        or host.tee_type != "tdx"
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or report.host_id != host.host_id
        or report.host_key_generation != host.active_key_generation
        or report.host_boot_id != host.boot_id
        or report.host_boot_generation != host.boot_generation
    ):
        raise GpuAllocationError("GPU inventory host/key/boot generation is stale or mismatched.")
    expected_generation = int(host.gpu_inventory_report_generation or 0) + 1
    if report.report_generation != expected_generation:
        raise GpuAllocationError(
            f"GPU inventory report generation must be exactly {expected_generation}."
        )
    if await db.get(GpuInventoryReport, report.report_id) is not None:
        raise GpuAllocationError("GPU inventory report was already consumed.")

    release, image, provenance = await _active_gpu_release(db, host)
    manifest = release.l0_manifest if isinstance(release.l0_manifest, dict) else None
    if (
        report.gpu_release_id != release.release_id
        or report.gpu_image_sha256 != image.get("sha256")
        or report.l0_manifest_sha256 != release.l0_manifest_digest
        or report.l0_manifest_generation != release.l0_manifest_generation
        or not isinstance(manifest, dict)
        or report.l0_version != manifest.get("l0_version")
        or host.l0_version != report.l0_version
        or host.last_accepted_manifest_generation != report.l0_manifest_generation
    ):
        raise GpuAllocationError(
            "GPU inventory is not bound to the active signed L0/GPU release identity."
        )
    l0_profile_id = _l0_gpu_profile_id(manifest, provenance)

    status = "accepted"
    reason = None
    profile: Optional[dict[str, Any]] = None
    try:
        profile = _profile_for_report(report, provenance, l0_profile_id)
        _validate_resource_budget(host, report, profile)
    except GpuAllocationError as exc:
        status = "rejected"
        reason = str(exc)

    topology_fingerprint = report.groups[0].topology_fingerprint
    report_row = GpuInventoryReport(
        report_id=report.report_id,
        host_id=host.host_id,
        host_key_generation=report.host_key_generation,
        host_boot_generation=report.host_boot_generation,
        report_generation=report.report_generation,
        gpu_release_id=report.gpu_release_id,
        profile_contract_sha256=report.profile_contract_sha256,
        topology_fingerprint=topology_fingerprint,
        claims=report.model_dump(mode="json"),
        claims_sha256=canonical_sha256(report),
        reconciliation_status=status,
        failure_reason=reason,
        accepted_at=_utcnow() if status == "accepted" else None,
    )
    db.add(report_row)
    await db.flush()
    await _expire_locked_reservations(db, host.host_id)
    groups = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.host_id == host.host_id)
                .order_by(GpuAllocationGroup.allocation_group_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    non_idle = [item for item in groups if item.state in _NON_IDLE_GROUP_STATES]
    allocation_group: Optional[GpuAllocationGroup] = None
    now = _utcnow()

    if status == "accepted" and profile is not None:
        values = _group_values(report, profile)
        exact = next(
            (
                item
                for item in groups
                if item.profile_id == values["profile_id"]
                and item.topology_fingerprint == topology_fingerprint
            ),
            None,
        )
        if exact is not None:
            allocation_group = exact
            if allocation_group.state == "quarantined":
                status = "quarantined"
                reason = (
                    "GPU allocation group remains quarantined pending explicit "
                    "reset/recovery evidence."
                )
                await _quarantine_group_reservations(
                    db,
                    allocation_group,
                    code=allocation_group.failure_code or "group_quarantined",
                    reason=allocation_group.failure_reason or reason,
                    metadata=allocation_group.failure_metadata,
                    now=now,
                )
            elif allocation_group.state in _NON_IDLE_GROUP_STATES:
                immutable_mismatch = {
                    key: (getattr(allocation_group, key), value)
                    for key, value in values.items()
                    if getattr(allocation_group, key) != value
                }
                if (
                    allocation_group.host_key_generation != report.host_key_generation
                    or allocation_group.host_boot_generation != report.host_boot_generation
                    or allocation_group.gpu_release_id != report.gpu_release_id
                ):
                    immutable_mismatch["lineage"] = (
                        (
                            allocation_group.host_key_generation,
                            allocation_group.host_boot_generation,
                            allocation_group.gpu_release_id,
                        ),
                        (
                            report.host_key_generation,
                            report.host_boot_generation,
                            report.gpu_release_id,
                        ),
                    )
                if immutable_mismatch:
                    status = "quarantined"
                    reason = (
                        "Non-idle GPU allocation lineage differs from current "
                        "inventory/release evidence and cannot be rewritten."
                    )
                    await _quarantine_group_reservations(
                        db,
                        allocation_group,
                        code="non_idle_gpu_lineage_changed",
                        reason=reason,
                        metadata={"mismatches": immutable_mismatch},
                        now=now,
                    )
                else:
                    allocation_group.last_report_id = report.report_id
                    allocation_group.last_seen_at = now
                    allocation_group.updated_at = now
            else:
                for key, value in values.items():
                    setattr(allocation_group, key, value)
                allocation_group.host_key_generation = report.host_key_generation
                allocation_group.host_boot_generation = report.host_boot_generation
                allocation_group.gpu_release_id = report.gpu_release_id
                allocation_group.last_report_id = report.report_id
                allocation_group.last_seen_at = now
                allocation_group.updated_at = now
            if allocation_group.state in {"discovered", "retired"}:
                allocation_group.generation = int(allocation_group.generation or 0) + 1
                allocation_group.state = "available"
                allocation_group.retired_at = None
                allocation_group.available_at = now
        elif non_idle:
            status = "quarantined"
            reason = (
                "GPU topology changed while a group was non-idle or already quarantined; "
                "allocation identity cannot be rewritten."
            )
            for item in non_idle:
                if item.state != "quarantined":
                    await _quarantine_group_reservations(
                        db,
                        item,
                        code="inventory_changed_with_non_idle_group",
                        reason=reason,
                        metadata={"reported_topology_fingerprint": topology_fingerprint},
                        now=now,
                    )
            allocation_group = non_idle[0]
        else:
            same_profile = next(
                (item for item in groups if item.profile_id == values["profile_id"]),
                None,
            )
            if same_profile is not None:
                allocation_group = same_profile
                for key, value in values.items():
                    setattr(allocation_group, key, value)
                allocation_group.generation = int(allocation_group.generation or 0) + 1
                allocation_group.host_key_generation = report.host_key_generation
                allocation_group.host_boot_generation = report.host_boot_generation
                allocation_group.gpu_release_id = report.gpu_release_id
                allocation_group.last_report_id = report.report_id
                allocation_group.state = "available"
                allocation_group.available_at = now
                allocation_group.retired_at = None
                allocation_group.last_seen_at = now
                allocation_group.updated_at = now
            else:
                for item in groups:
                    if item.state != "retired":
                        item.state = "retired"
                        item.retired_at = now
                        item.updated_at = now
                allocation_group = GpuAllocationGroup(
                    allocation_group_id=generate_uuid(),
                    host_id=host.host_id,
                    host_key_generation=report.host_key_generation,
                    host_boot_generation=report.host_boot_generation,
                    generation=1,
                    gpu_release_id=report.gpu_release_id,
                    last_report_id=report.report_id,
                    state="available",
                    available_at=now,
                    last_seen_at=now,
                    updated_at=now,
                    reservation_generation=0,
                    **values,
                )
                db.add(allocation_group)
    elif groups:
        for item in groups:
            if item.state not in {"retired", "quarantined"}:
                await _quarantine_group_reservations(
                    db,
                    item,
                    code="inventory_profile_evidence_mismatch",
                    reason=reason or "GPU inventory failed signed-profile validation.",
                    metadata={"reported_topology_fingerprint": topology_fingerprint},
                    now=now,
                )
        allocation_group = groups[0]

    report_row.reconciliation_status = status
    report_row.failure_reason = reason
    report_row.accepted_at = now if status == "accepted" else None
    host.gpu_inventory_report_generation = report.report_generation
    host.gpu_inventory_fingerprint = topology_fingerprint
    host.gpu_inventory_reconciled_at = now
    await db.flush()
    return GpuInventoryReconcileResponseV1(
        report_id=report.report_id,
        report_generation=report.report_generation,
        host_boot_generation=report.host_boot_generation,
        status=status,
        allocation_group_id=(
            allocation_group.allocation_group_id if allocation_group is not None else None
        ),
        allocation_group_generation=(
            allocation_group.generation if allocation_group is not None else None
        ),
        topology_fingerprint=topology_fingerprint,
        reason=reason,
    )


def gpu_reservation_token(reservation_id: str, expected_hash: Optional[str] = None) -> str:
    """Reconstruct one reservation capability for idempotent command retries.

    Only the validator can derive the token because the HMAC key is the existing
    launch-config secret. The database retains only its digest.
    """

    secret = hmac.new(
        settings.launch_config_key.encode("ascii"),
        f"gpu-launch-reservation:{reservation_id}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    token = f"{reservation_id}.{encoded}"
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    if expected_hash is not None and not hmac.compare_digest(token_hash, expected_hash):
        raise GpuAllocationError("Persisted GPU reservation token derivation changed.")
    return token


def _reservation_token() -> tuple[str, str, str]:
    reservation_id = generate_uuid()
    token = gpu_reservation_token(reservation_id)
    return reservation_id, token, hashlib.sha256(token.encode("ascii")).hexdigest()


def _parse_reservation_token(token: str) -> tuple[str, str]:
    try:
        reservation_id, secret = token.split(".", 1)
        raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    except (TypeError, ValueError) as exc:
        raise GpuAllocationError("GPU launch reservation token is malformed.") from exc
    if not reservation_id or len(raw) != 32:
        raise GpuAllocationError("GPU launch reservation token is malformed.")
    return reservation_id, hashlib.sha256(token.encode("ascii")).hexdigest()


async def reserve_gpu_group(
    db: AsyncSession,
    host_id: str,
    request: GpuPlatformReservationRequestV1 | GpuMinerReservationRequestV1,
    *,
    expected_owner_hotkey: Optional[str] = None,
    expected_allocation_group_id: Optional[str] = None,
    expected_profile_id: Optional[str] = None,
    expected_topology_fingerprint: Optional[str] = None,
) -> GpuLaunchReservationResponseV1:
    """Lock one exact available group and create its capability in one transaction."""

    await acquire_gpu_lifecycle_lock(db)
    management_mode = (
        "platform" if isinstance(request, GpuPlatformReservationRequestV1) else "miner"
    )
    if isinstance(request, GpuPlatformReservationRequestV1):
        (
            workload_owner,
            chute_version,
            container_repository,
            container_manifest_digest,
            descriptor_closure,
        ) = await _trusted_platform_workload(db, request)
    else:
        workload_owner = None
        chute_version = None
        container_repository = None
        container_manifest_digest = None
        descriptor_closure = {
            "descriptor_closure_sha256": None,
            "allowed_manifests": [],
            "allowed_blobs": [],
            "allowed_manifest_tags": [],
            "manifest_tag_digests": {},
        }
    host = await _host_lock(db, host_id)
    if expected_owner_hotkey is not None and host.miner_hotkey != expected_owner_hotkey:
        raise GpuAllocationError("GPU host is unknown or owned by another miner.")
    if (
        host.compute_type != "gpu"
        or host.tee_type != "tdx"
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or int(host.boot_generation or 0) < 1
    ):
        raise GpuAllocationError("GPU host is not allocation-ready.")
    if management_mode == "platform":
        server_id = request.server_id
        process_incarnation = request.process_incarnation
        legacy_vm_name = None
        legacy_migration_id = None
    release, image, provenance = await _active_gpu_release(db, host)
    if not isinstance(release.l0_manifest, dict):
        raise GpuAllocationError("GPU release has no signed L0 profile closure.")
    l0_profile_id = _l0_gpu_profile_id(release.l0_manifest, provenance)
    if workload_owner is None:
        workload_owner = host.miner_hotkey
    from api.host.reservations import gpu_host_storage_readiness

    storage_readiness = await gpu_host_storage_readiness(
        db,
        host,
        include_allocation=False,
    )
    if (
        not storage_readiness.trusted_storage_ready
        or not storage_readiness.control_channel_eligible
    ):
        raise GpuAllocationError(
            f"GPU storage sibling is not allocation-ready: {storage_readiness.reason}."
        )
    if management_mode == "miner":
        miner_identity = await _stable_miner_identity(
            db,
            host,
            request.legacy_vm_name,
        )
        server_id = miner_identity.server_id
        process_incarnation = "gpu" + generate_uuid().replace("-", "")
        legacy_vm_name = miner_identity.legacy_vm_name
        legacy_migration_id = None
        if legacy_vm_name is not None:
            migration = (
                await db.execute(
                    select(GpuLegacyMigration)
                    .where(
                        GpuLegacyMigration.target_server_id == server_id,
                        GpuLegacyMigration.legacy_vm_name == legacy_vm_name,
                        GpuLegacyMigration.host_id == host.host_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if migration is None:
                raise GpuAllocationError(
                    "Legacy GPU migration has not completed old-guest and host closure."
                )
            await _require_resumable_legacy_migration(db, migration, host)
            legacy_migration_id = migration.migration_id
    await _expire_locked_reservations(db, host.host_id)
    groups = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(
                    GpuAllocationGroup.host_id == host.host_id,
                    GpuAllocationGroup.host_key_generation == host.active_key_generation,
                    GpuAllocationGroup.host_boot_generation == host.boot_generation,
                    GpuAllocationGroup.gpu_release_id == release.release_id,
                    GpuAllocationGroup.profile_id == l0_profile_id,
                    GpuAllocationGroup.state == "available",
                    GpuAllocationGroup.gpu_count == request.gpu_count,
                    GpuAllocationGroup.vram_mib >= request.minimum_vram_mib,
                    *(
                        (GpuAllocationGroup.allocation_group_id == expected_allocation_group_id,)
                        if expected_allocation_group_id is not None
                        else ()
                    ),
                    *(
                        (GpuAllocationGroup.profile_id == expected_profile_id,)
                        if expected_profile_id is not None
                        else ()
                    ),
                    *(
                        (GpuAllocationGroup.topology_fingerprint == expected_topology_fingerprint,)
                        if expected_topology_fingerprint is not None
                        else ()
                    ),
                )
                .order_by(
                    GpuAllocationGroup.vram_mib,
                    GpuAllocationGroup.allocation_group_id,
                )
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    group = next(
        (item for item in groups if set(item.gpu_identifiers) == {request.gpu_identifier}),
        None,
    )
    if group is None:
        raise GpuAllocationError("No exact matching available GPU allocation group.")
    profile = next(
        (
            item
            for item in provenance["profile_contract"]["profiles"]
            if item["id"] == group.profile_id
        ),
        None,
    )
    environment = next(
        (
            item
            for item in provenance["launch_environments"]
            if item["profile_id"] == group.profile_id
        ),
        None,
    )
    measurement = next(
        (
            item
            for item in provenance["measurements"]
            if item["profile_id"] == group.profile_id and item["management_mode"] == management_mode
        ),
        None,
    )
    if (
        profile is None
        or environment is None
        or measurement is None
        or group.profile_contract_sha256 != provenance["profile_contract_sha256"]
        or group.gpu_count != profile["gpu_count"]
        or group.vram_mib != profile["vram_mib"]
    ):
        _quarantine_group(
            group,
            code="reservation_profile_evidence_mismatch",
            reason="Allocation group no longer matches active signed GPU provenance.",
        )
        raise GpuAllocationError("GPU allocation group no longer matches active signed provenance.")
    artifacts = provenance["artifacts"]
    release_target_sha256 = _gpu_release_target_sha256(
        release=release,
        image=image,
        group=group,
        management_mode=management_mode,
        measurement_name=measurement["name"],
        environment=environment,
        artifacts=artifacts,
    )
    reservation_id, token, token_hash = _reservation_token()
    token_id = generate_uuid()
    now = _utcnow()
    reservation_generation = int(group.reservation_generation or 0) + 1
    claims = GpuLaunchReservationClaimsV1(
        reservation_id=reservation_id,
        token_id=token_id,
        owner_hotkey=host.miner_hotkey,
        workload_owner=workload_owner,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        host_boot_generation=host.boot_generation,
        management_mode=management_mode,
        allocation_group_id=group.allocation_group_id,
        allocation_group_generation=group.generation,
        reservation_generation=reservation_generation,
        gpu_bdfs=list(group.gpu_bdfs),
        gpu_uuids=list(group.gpu_uuids),
        gpu_identifiers=list(group.gpu_identifiers),
        gpu_attestation_certificate_sha256s=list(group.gpu_attestation_certificate_sha256s),
        topology_fingerprint=group.topology_fingerprint,
        gpu_release_id=release.release_id,
        gpu_profile_id=group.profile_id,
        profile_contract_sha256=group.profile_contract_sha256,
        measurement_name=measurement["name"],
        kernel_measurement_mode=artifacts["kernel_measurement_mode"],
        qemu_binary_sha256=environment["qemu_binary_sha256"],
        qemu_package_version=environment["qemu_package_version"],
        machine_type=environment["machine_type"],
        tdvf_sha256=environment["firmware_sha256"],
        image_sha256=image["sha256"],
        image_version=image["version"],
        kernel_sha256=artifacts["kernel_sha256"],
        initrd_sha256=artifacts["initrd_sha256"],
        mode_cmdline_sha256=artifacts["cmdline_sha256"][management_mode],
        release_target_sha256=release_target_sha256,
        server_id=server_id,
        process_incarnation=process_incarnation,
        legacy_vm_name=legacy_vm_name,
        legacy_migration_id=legacy_migration_id,
        chute_id=(
            request.chute_id if isinstance(request, GpuPlatformReservationRequestV1) else None
        ),
        job_id=(request.job_id if isinstance(request, GpuPlatformReservationRequestV1) else None),
        container_repository=container_repository,
        container_manifest_digest=container_manifest_digest,
        descriptor_closure_sha256=descriptor_closure["descriptor_closure_sha256"],
        allowed_manifests=descriptor_closure["allowed_manifests"],
        allowed_blobs=descriptor_closure["allowed_blobs"],
        allowed_manifest_tags=descriptor_closure["allowed_manifest_tags"],
        manifest_tag_digests=descriptor_closure["manifest_tag_digests"],
        miner_hourly_cost=(
            request.miner_hourly_cost if isinstance(request, GpuMinerReservationRequestV1) else None
        ),
        launch_nonce=base64.b64encode(
            hmac.new(
                settings.launch_config_key.encode("ascii"),
                f"gpu-launch-nonce:{reservation_id}".encode("ascii"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii"),
        issued_at=now,
        expires_at=now + timedelta(seconds=GPU_RESERVATION_LIFETIME_SECONDS),
    )
    claims_sha256 = canonical_sha256(claims)
    reservation = GpuLaunchReservation(
        reservation_id=reservation_id,
        token_id=token_id,
        token_hash=token_hash,
        claims_version=1,
        claims=claims.model_dump(mode="json", exclude_none=True),
        claims_sha256=claims_sha256,
        owner_hotkey=host.miner_hotkey,
        workload_owner=workload_owner,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        host_boot_generation=host.boot_generation,
        allocation_group_id=group.allocation_group_id,
        allocation_group_generation=group.generation,
        reservation_generation=reservation_generation,
        management_mode=management_mode,
        server_id=server_id,
        process_incarnation=process_incarnation,
        legacy_vm_name=legacy_vm_name,
        legacy_migration_id=legacy_migration_id,
        gpu_release_id=release.release_id,
        profile_id=group.profile_id,
        profile_contract_sha256=group.profile_contract_sha256,
        measurement_name=measurement["name"],
        kernel_measurement_mode=artifacts["kernel_measurement_mode"],
        topology_fingerprint=group.topology_fingerprint,
        gpu_bdfs=list(group.gpu_bdfs),
        gpu_uuids=list(group.gpu_uuids),
        gpu_identifiers=list(group.gpu_identifiers),
        gpu_attestation_certificate_sha256s=list(group.gpu_attestation_certificate_sha256s),
        qemu_binary_sha256=environment["qemu_binary_sha256"],
        qemu_package_version=environment["qemu_package_version"],
        machine_type=environment["machine_type"],
        tdvf_sha256=environment["firmware_sha256"],
        image_sha256=image["sha256"],
        image_version=image["version"],
        kernel_sha256=artifacts["kernel_sha256"],
        initrd_sha256=artifacts["initrd_sha256"],
        mode_cmdline_sha256=artifacts["cmdline_sha256"][management_mode],
        release_target_sha256=release_target_sha256,
        chute_id=claims.chute_id,
        job_id=claims.job_id,
        container_repository=claims.container_repository,
        container_manifest_digest=claims.container_manifest_digest,
        chute_version=chute_version,
        descriptor_closure_sha256=descriptor_closure["descriptor_closure_sha256"],
        allowed_manifests=descriptor_closure["allowed_manifests"],
        allowed_blobs=descriptor_closure["allowed_blobs"],
        allowed_manifest_tags=descriptor_closure["allowed_manifest_tags"],
        manifest_tag_digests=descriptor_closure["manifest_tag_digests"],
        launch_nonce=claims.launch_nonce,
        state="reserved",
        issued_at=now,
        expires_at=claims.expires_at,
    )
    db.add(reservation)
    await db.flush()
    if isinstance(request, GpuPlatformReservationRequestV1) and request.job_id:
        from api.job.schemas import Job

        result = await db.execute(
            update(Job)
            .where(
                Job.job_id == request.job_id,
                Job.finished_at.is_(None),
                or_(
                    Job.gpu_management_mode.is_(None),
                    Job.gpu_management_mode == "platform",
                ),
            )
            .values(
                gpu_management_mode="platform",
                gpu_launch_reservation_id=reservation.reservation_id,
            )
        )
        if result.rowcount != 1:
            raise GpuAllocationError("GPU job manager changed during reservation arbitration.")
    group.state = "reserved"
    group.management_mode = management_mode
    group.reservation_owner = workload_owner
    group.reservation_id = reservation_id
    group.reservation_generation = reservation_generation
    group.process_incarnation = process_incarnation
    group.reserved_at = now
    group.available_at = None
    group.updated_at = now
    await db.flush()
    return GpuLaunchReservationResponseV1(
        token=token,
        claims=claims,
        claims_sha256=claims_sha256,
    )


def _validate_row_claims(
    reservation: GpuLaunchReservation,
) -> GpuLaunchReservationClaimsV1:
    try:
        claims = GpuLaunchReservationClaimsV1.model_validate(reservation.claims)
    except ValueError as exc:
        raise GpuAllocationError("Persisted GPU reservation claims are malformed.") from exc
    comparisons = {
        "reservation_id": reservation.reservation_id,
        "owner_hotkey": reservation.owner_hotkey,
        "workload_owner": reservation.workload_owner,
        "host_id": reservation.host_id,
        "host_key_generation": reservation.host_key_generation,
        "host_boot_generation": reservation.host_boot_generation,
        "management_mode": reservation.management_mode,
        "allocation_group_id": reservation.allocation_group_id,
        "allocation_group_generation": reservation.allocation_group_generation,
        "reservation_generation": reservation.reservation_generation,
        "gpu_release_id": reservation.gpu_release_id,
        "gpu_profile_id": reservation.profile_id,
        "profile_contract_sha256": reservation.profile_contract_sha256,
        "measurement_name": reservation.measurement_name,
        "kernel_measurement_mode": reservation.kernel_measurement_mode,
        "topology_fingerprint": reservation.topology_fingerprint,
        "qemu_binary_sha256": reservation.qemu_binary_sha256,
        "qemu_package_version": reservation.qemu_package_version,
        "machine_type": reservation.machine_type,
        "tdvf_sha256": reservation.tdvf_sha256,
        "image_sha256": reservation.image_sha256,
        "image_version": reservation.image_version,
        "kernel_sha256": reservation.kernel_sha256,
        "initrd_sha256": reservation.initrd_sha256,
        "mode_cmdline_sha256": reservation.mode_cmdline_sha256,
        "release_target_sha256": reservation.release_target_sha256,
        "server_id": reservation.server_id,
        "process_incarnation": reservation.process_incarnation,
        "legacy_vm_name": reservation.legacy_vm_name,
        "legacy_migration_id": reservation.legacy_migration_id,
        "chute_id": reservation.chute_id,
        "job_id": reservation.job_id,
        "container_repository": reservation.container_repository,
        "container_manifest_digest": reservation.container_manifest_digest,
        "launch_nonce": reservation.launch_nonce,
    }
    if (
        any(getattr(claims, key) != value for key, value in comparisons.items())
        or claims.gpu_bdfs != reservation.gpu_bdfs
        or claims.gpu_uuids != reservation.gpu_uuids
        or claims.gpu_identifiers != reservation.gpu_identifiers
        or claims.gpu_attestation_certificate_sha256s
        != reservation.gpu_attestation_certificate_sha256s
        or canonical_sha256(claims) != reservation.claims_sha256
    ):
        raise GpuAllocationError("Persisted GPU reservation row does not match canonical claims.")
    return claims


async def _locked_reservation_group(
    db: AsyncSession,
    reservation_id: str,
) -> tuple[GpuLaunchReservation, GpuAllocationGroup]:
    await acquire_gpu_lifecycle_lock(db)
    identity = (
        await db.execute(
            select(
                GpuLaunchReservation.host_id,
                GpuLaunchReservation.allocation_group_id,
            ).where(GpuLaunchReservation.reservation_id == reservation_id)
        )
    ).one_or_none()
    if identity is None:
        raise GpuAllocationError("GPU reservation is unknown.")
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == identity.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if group is None:
        raise GpuAllocationError("GPU reservation allocation group is missing.")
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None or reservation.allocation_group_id != group.allocation_group_id:
        raise GpuAllocationError("GPU reservation changed during lock acquisition.")
    return reservation, group


def _assert_host_association(
    host: Host,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
) -> None:
    if (
        host.host_id != reservation.host_id
        or host.active_key_generation != reservation.host_key_generation
        or host.boot_generation != reservation.host_boot_generation
        or group.host_id != host.host_id
        or group.host_key_generation != reservation.host_key_generation
        or group.host_boot_generation != reservation.host_boot_generation
        or group.generation != reservation.allocation_group_generation
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
        or group.gpu_release_id != reservation.gpu_release_id
        or group.profile_id != reservation.profile_id
        or group.profile_contract_sha256 != reservation.profile_contract_sha256
        or group.topology_fingerprint != reservation.topology_fingerprint
        or group.gpu_bdfs != reservation.gpu_bdfs
        or group.gpu_uuids != reservation.gpu_uuids
    ):
        raise GpuAllocationError("GPU reservation host/group generation is stale.")


def _assert_recovery_association(
    host: Host,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
) -> None:
    if (
        host.host_id != reservation.host_id
        or host.miner_hotkey != reservation.owner_hotkey
        or group.host_id != host.host_id
        or group.allocation_group_id != reservation.allocation_group_id
        or group.generation != reservation.allocation_group_generation
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
        or group.gpu_release_id != reservation.gpu_release_id
        or group.profile_id != reservation.profile_id
        or group.topology_fingerprint != reservation.topology_fingerprint
    ):
        raise GpuAllocationError("GPU reset recovery association is ambiguous.")


async def resolve_gpu_registration_reservation(
    db: AsyncSession,
    token: str,
    commitment: GpuQuoteCommitmentV1,
) -> tuple[
    Host,
    GpuLaunchReservation,
    GpuAllocationGroup,
    GpuLaunchReservationClaimsV1,
]:
    reservation_id, token_hash = _parse_reservation_token(token)
    identity = (
        await db.execute(
            select(GpuLaunchReservation.host_id).where(
                GpuLaunchReservation.reservation_id == reservation_id
            )
        )
    ).scalar_one_or_none()
    if identity is None:
        raise GpuAllocationError("GPU registration reservation is unknown.")
    host = await _host_lock(db, identity)
    release, _image, _provenance = await _active_gpu_release(db, host)
    reservation, group = await _locked_reservation_group(db, reservation_id)
    claims = _validate_row_claims(reservation)
    _assert_host_association(host, reservation, group)
    now = _utcnow()
    consumed_retry = bool(
        reservation.state == "running"
        and group.state == "running"
        and reservation.guest_consumed_at is not None
        and reservation.registration_attestation_id is not None
        and reservation.server_id is not None
    )
    if reservation.expires_at <= now and not consumed_retry:
        _quarantine_reservation(
            reservation,
            group,
            code="gpu_registration_missed_launch_deadline",
            reason="GPU guest registration arrived after the claimed launch deadline.",
            now=now,
        )
        await _retire_gpu_runtime_lineage(
            db,
            reservation,
            now,
            reason="GPU guest registration missed its launch deadline.",
        )
        await db.flush()
        raise GpuAllocationQuarantinedError("GPU guest registration missed its launch deadline.")
    if (
        (
            not consumed_retry
            and (
                reservation.state != "launching"
                or group.state != "launching"
                or reservation.guest_consumed_at is not None
            )
        )
        or reservation.gpu_release_id != release.release_id
        or not secrets.compare_digest(reservation.token_hash, token_hash)
        or commitment.claims != claims
        or commitment.reservation_sha256 != reservation.claims_sha256
        or commitment.release_target_sha256 != reservation.release_target_sha256
        or commitment.launch_nonce != reservation.launch_nonce
    ):
        raise GpuAllocationError(
            "GPU guest registration reservation is stale, consumed, or mismatched."
        )
    return host, reservation, group, claims


async def claim_gpu_reservation(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuReservationClaimRequestV1,
) -> GpuLaunchReservationClaimsV1:
    reservation_id, token_hash = _parse_reservation_token(request.token)
    host = await _host_lock(db, authenticated_host.host_id)
    release, _image, _provenance = await _active_gpu_release(db, host)
    await _expire_locked_reservations(db, host.host_id)
    reservation, group = await _locked_reservation_group(db, reservation_id)
    claims = _validate_row_claims(reservation)
    _assert_host_association(host, reservation, group)
    now = _utcnow()
    if release.release_id != reservation.gpu_release_id:
        _quarantine_reservation(
            reservation,
            group,
            code="claim_active_release_changed",
            reason="GPU reservation no longer matches the active exact release.",
            now=now,
        )
        await _retire_gpu_runtime_lineage(
            db,
            reservation,
            now,
            reason="GPU reservation release changed before claim.",
        )
        await db.flush()
        raise GpuAllocationQuarantinedError("GPU reservation release changed before claim.")
    if (
        reservation.state == "claimed"
        and group.state == "reserved"
        and reservation.claimed_at is not None
        and reservation.expires_at > now
        and secrets.compare_digest(reservation.token_hash, token_hash)
        and secrets.compare_digest(reservation.claims_sha256, request.claims_sha256)
    ):
        return claims
    if reservation.state in {"expired", "quarantined"}:
        raise GpuAllocationQuarantinedError(
            "GPU reservation launch deadline changed durable allocation state."
        )
    if (
        reservation.state != "reserved"
        or group.state != "reserved"
        or reservation.claimed_at is not None
        or reservation.expires_at <= now
        or not secrets.compare_digest(reservation.token_hash, token_hash)
        or not secrets.compare_digest(reservation.claims_sha256, request.claims_sha256)
    ):
        raise GpuAllocationError(
            "GPU reservation is expired, consumed, stale, or does not match its token."
        )
    reservation.state = "claimed"
    reservation.claimed_at = now
    await db.flush()
    return claims


async def mark_gpu_launching(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuReservationStateRequestV1,
) -> None:
    host = await _host_lock(db, authenticated_host.host_id)
    release, _image, _provenance = await _active_gpu_release(db, host)
    await _expire_locked_reservations(db, host.host_id)
    reservation, group = await _locked_reservation_group(db, request.reservation_id)
    _validate_row_claims(reservation)
    _assert_host_association(host, reservation, group)
    if release.release_id != reservation.gpu_release_id:
        _quarantine_reservation(
            reservation,
            group,
            code="launch_active_release_changed",
            reason="GPU reservation no longer matches the active exact release.",
        )
        await db.flush()
        raise GpuAllocationQuarantinedError("GPU reservation release changed before launch.")
    if reservation.state == "quarantined":
        raise GpuAllocationQuarantinedError(
            "GPU reservation passed its launch deadline and was quarantined."
        )
    if (
        reservation.state != "claimed"
        or group.state != "reserved"
        or reservation.claims_sha256 != request.claims_sha256
        or reservation.process_incarnation != request.process_incarnation
    ):
        raise GpuAllocationError("GPU reservation cannot transition to launching.")
    now = _utcnow()
    reservation.state = "launching"
    reservation.launching_at = now
    group.state = "launching"
    group.launching_at = now
    group.updated_at = now
    await db.flush()


async def begin_gpu_teardown(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuReservationStateRequestV1,
) -> None:
    host = await _host_lock(db, authenticated_host.host_id)
    reservation, group = await _locked_reservation_group(db, request.reservation_id)
    _validate_row_claims(reservation)
    if reservation.state == "quarantined" and group.state == "quarantined":
        _assert_recovery_association(host, reservation, group)
    else:
        _assert_host_association(host, reservation, group)
    if (
        reservation.state not in {"claimed", "launching", "running", "quarantined"}
        or group.state not in {"reserved", "launching", "running", "quarantined"}
        or reservation.claims_sha256 != request.claims_sha256
        or reservation.process_incarnation != request.process_incarnation
    ):
        raise GpuAllocationError("GPU reservation cannot begin exact teardown.")
    if reservation.management_mode == "miner":
        from api.server.gpu_infra import GpuInfraError, seal_gpu_infra_for_reservation

        try:
            await seal_gpu_infra_for_reservation(db, reservation)
        except GpuInfraError as exc:
            raise GpuAllocationError(str(exc)) from exc
    now = _utcnow()
    reservation.state = "resetting"
    reservation.teardown_started_at = now
    reservation.quarantined_at = None
    reservation.failure_code = None
    reservation.failure_reason = None
    reservation.failure_metadata = null()
    group.state = "resetting"
    group.resetting_at = now
    group.quarantined_at = None
    group.failure_code = None
    group.failure_reason = None
    group.failure_metadata = null()
    group.updated_at = now
    await db.flush()


async def _retire_gpu_runtime_lineage(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    now: datetime,
    *,
    reason: str = "allocation reset completed",
    remove_nodes: bool = False,
    successful: bool = False,
) -> None:
    from api.instance.schemas import Instance, LaunchConfig, instance_nodes
    from api.job.schemas import Job
    from api.node.schemas import Node
    from api.host.schemas import RegistrySession

    server = (
        await db.execute(
            select(Server)
            .where(Server.gpu_launch_reservation_id == reservation.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if server is None:
        return
    naive_now = now.replace(tzinfo=None)
    nodes = (
        (
            await db.execute(
                select(Node)
                .where(Node.server_id == server.server_id)
                .order_by(Node.uuid)
                .with_for_update(of=Node)
            )
        )
        .scalars()
        .all()
    )
    node_ids = [item.uuid for item in nodes]
    instance_ids: list[str] = []
    if node_ids:
        instance_ids = list(
            (
                await db.execute(
                    select(instance_nodes.c.instance_id).where(
                        instance_nodes.c.node_id.in_(node_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
    instance_ids.extend(
        (
            await db.execute(
                select(Instance.instance_id).where(Instance.server_id == server.server_id)
            )
        )
        .scalars()
        .all()
    )
    instance_ids = sorted(set(instance_ids))
    launch_update = update(LaunchConfig).where(
        LaunchConfig.gpu_launch_reservation_id == reservation.reservation_id,
        LaunchConfig.failed_at.is_(None),
        LaunchConfig.completed_at.is_(None),
    )
    if successful:
        await db.execute(launch_update.values(completed_at=now))
    else:
        await db.execute(
            launch_update.values(
                failed_at=naive_now,
                verification_error=f"GPU allocation retired: {reason[:1500]}",
            )
        )
    await db.execute(
        update(LaunchConfig)
        .where(
            LaunchConfig.gpu_launch_reservation_id == reservation.reservation_id,
            LaunchConfig.container_repository.isnot(None),
        )
        .values(
            registry_scope_active=False,
            registry_scope_revoked_at=now,
        )
    )
    if instance_ids:
        await db.execute(
            update(Job)
            .where(
                Job.instance_id.in_(instance_ids),
                Job.finished_at.is_(None),
            )
            .values(
                status="error",
                error_detail=f"Platform GPU allocation retired: {reason[:1500]}",
                miner_terminated=True,
                finished_at=naive_now,
            )
        )
        await db.execute(
            update(Instance)
            .where(Instance.instance_id.in_(instance_ids))
            .values(
                active=False,
                verified=False,
                verification_error="GPU allocation reset and retired",
                stop_billing_at=naive_now,
            )
        )
        await db.execute(
            delete(instance_nodes).where(instance_nodes.c.instance_id.in_(instance_ids))
        )
    if node_ids:
        if remove_nodes:
            await db.execute(delete(Node).where(Node.uuid.in_(node_ids)))
        else:
            await db.execute(
                update(Node)
                .where(Node.uuid.in_(node_ids))
                .values(
                    verified_at=None,
                    verification_error="GPU allocation retired",
                    gpu_retired_at=now,
                )
            )
    await db.execute(
        update(RegistrySession)
        .where(
            RegistrySession.server_id == server.server_id,
            RegistrySession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await db.execute(
        update(ServerAttestation)
        .where(
            ServerAttestation.server_id == server.server_id,
            ServerAttestation.gpu_retired_at.is_(None),
        )
        .values(gpu_retired_at=now)
    )
    server.gpu_retired_at = now
    server.gpu_retirement_reason = reason[:2000]
    server.gpu_runtime_session_attestation_id = None
    server.gpu_runtime_session_expires_at = None
    server.last_health_at = None
    await db.flush()


async def complete_gpu_reset(
    db: AsyncSession,
    authenticated_host: Host,
    result: GpuResetResultV1,
) -> bool:
    host = await _host_lock(db, authenticated_host.host_id)
    reservation, group = await _locked_reservation_group(db, result.reservation_id)
    _validate_row_claims(reservation)
    _assert_recovery_association(host, reservation, group)
    exact_evidence = bool(
        reservation.state == "resetting"
        and group.state == "resetting"
        and reservation.claims_sha256 == result.claims_sha256
        and reservation.process_incarnation == result.process_incarnation
        and reservation.gpu_bdfs == result.gpu_bdfs
        and reservation.gpu_uuids == result.gpu_uuids
        and reservation.topology_fingerprint == result.topology_fingerprint
    )
    success = bool(
        exact_evidence
        and result.qemu_absent
        and result.reset_succeeded
        and result.original_drivers_restored
    )
    gpu_infra_error: Optional[str] = None
    if success and reservation.management_mode == "miner":
        from api.server.gpu_infra import GpuInfraError, require_gpu_infra_sealed

        try:
            if result.guest_shutdown_clean is not True:
                raise GpuInfraError("Miner guest shutdown did not prove a clean flush.")
            await require_gpu_infra_sealed(db, reservation)
        except GpuInfraError as exc:
            gpu_infra_error = str(exc)
            success = False
    now = _utcnow()
    if not success:
        _quarantine_reservation(
            reservation,
            group,
            code=(
                result.failure_code
                or ("gpu_infra_unclosed" if gpu_infra_error else "gpu_reset_evidence_mismatch")
            ),
            reason=(
                result.failure_reason
                or gpu_infra_error
                or "GPU reset evidence was ambiguous or mismatched."
            ),
            metadata={
                **dict(result.evidence or {}),
                "qemu_absent": result.qemu_absent,
                "reset_succeeded": result.reset_succeeded,
                "original_drivers_restored": result.original_drivers_restored,
                "guest_shutdown_clean": result.guest_shutdown_clean,
            },
            now=now,
        )
        await _retire_gpu_runtime_lineage(
            db,
            reservation,
            now,
            reason=result.failure_reason or gpu_infra_error or "GPU reset evidence mismatch.",
        )
        await db.flush()
        return False
    await _retire_gpu_runtime_lineage(
        db,
        reservation,
        now,
        remove_nodes=True,
        successful=True,
    )
    reservation.state = "released"
    reservation.reset_completed_at = now
    reservation.released_at = now
    group.state = "available"
    group.management_mode = None
    group.reservation_owner = None
    group.reservation_id = None
    group.process_incarnation = None
    group.available_at = now
    group.reserved_at = None
    group.launching_at = None
    group.running_at = None
    group.resetting_at = None
    group.updated_at = now
    await db.flush()
    return True


async def record_gpu_command_dispatch(
    db: AsyncSession,
    reservation_id: str,
    *,
    command: str,
    command_id: str,
) -> None:
    """Persist one launch/teardown dispatch without changing reservation identity."""

    reservation, group = await _locked_reservation_group(db, reservation_id)
    now = _utcnow()
    if command == "launch_gpu":
        if reservation.state not in {"reserved", "claimed", "launching"}:
            raise GpuAllocationError("GPU launch command targets a non-launchable reservation.")
        if (
            reservation.launch_command_id is not None
            and reservation.launch_command_id != command_id
        ):
            raise GpuAllocationError("GPU launch retry changed its durable command id.")
        reservation.launch_command_id = command_id
        reservation.launch_dispatched_at = now
        reservation.launch_ack_at = None
        reservation.launch_ack_status = None
        reservation.launch_ack_detail = None
    elif command == "delete_gpu":
        if reservation.state not in {
            "claimed",
            "launching",
            "running",
            "resetting",
            "quarantined",
            "released",
        }:
            raise GpuAllocationError("GPU teardown command targets a terminal reservation.")
        if (
            reservation.teardown_command_id is not None
            and reservation.teardown_command_id != command_id
        ):
            raise GpuAllocationError("GPU teardown retry changed its durable command id.")
        reservation.teardown_command_id = command_id
        reservation.teardown_dispatched_at = now
        reservation.teardown_ack_at = None
        reservation.teardown_ack_status = None
        reservation.teardown_ack_detail = None
    else:
        raise GpuAllocationError("Unknown GPU lifecycle command.")
    reservation.last_reconciled_at = now
    await db.flush()


async def request_gpu_teardown(
    db: AsyncSession,
    reservation_id: str,
    *,
    reason: str,
) -> GpuLaunchReservation:
    """Durably request exact teardown; retries reuse the same reservation."""

    await acquire_gpu_lifecycle_lock(db)
    reservation, group = await _locked_reservation_group(db, reservation_id)
    if reservation.state in {"released", "expired"}:
        return reservation
    if reservation.state == "reserved" and reservation.claimed_at is None:
        now = _utcnow()
        reservation.state = "expired"
        reservation.expired_at = now
        if group.reservation_id == reservation.reservation_id:
            group.state = "available"
            group.management_mode = None
            group.reservation_owner = None
            group.reservation_id = None
            group.process_incarnation = None
            group.reserved_at = None
            group.available_at = now
            group.updated_at = now
        await db.flush()
        return reservation
    if reservation.teardown_requested_at is None:
        reservation.teardown_requested_at = _utcnow()
        reservation.teardown_reason = reason[:2000]
    reservation.last_reconciled_at = _utcnow()
    await db.flush()
    return reservation


async def record_gpu_command_ack(
    db: AsyncSession,
    reservation_id: str,
    *,
    command: str,
    command_id: str,
    status: str,
    detail: str,
) -> None:
    """Bind an acknowledgement to the exact persisted dispatch generation."""

    reservation, group = await _locked_reservation_group(db, reservation_id)
    now = _utcnow()
    failed = status.lower() in {
        "error",
        "rejected",
        "failed",
        "unhandled",
        "unknown_command",
    }
    if command == "launch_gpu":
        if reservation.launch_command_id != command_id:
            raise GpuAllocationError("GPU launch acknowledgement is stale.")
        reservation.launch_ack_at = now
        reservation.launch_ack_status = status[:64]
        reservation.launch_ack_detail = detail[:2000] if detail else None
        if failed:
            if reservation.state == "reserved" and reservation.claimed_at is None:
                reservation.state = "expired"
                reservation.expired_at = now
                if group.reservation_id == reservation.reservation_id:
                    group.state = "available"
                    group.management_mode = None
                    group.reservation_owner = None
                    group.reservation_id = None
                    group.process_incarnation = None
                    group.reserved_at = None
                    group.available_at = now
                    group.updated_at = now
            elif reservation.teardown_requested_at is None:
                reservation.teardown_requested_at = now
                reservation.teardown_reason = "terminal launch command acknowledgement"
    elif command == "delete_gpu":
        if reservation.teardown_command_id != command_id:
            raise GpuAllocationError("GPU teardown acknowledgement is stale.")
        reservation.teardown_ack_at = now
        reservation.teardown_ack_status = status[:64]
        reservation.teardown_ack_detail = detail[:2000] if detail else None
        if failed and reservation.state not in {"released", "expired"}:
            _quarantine_reservation(
                reservation,
                group,
                code="gpu_teardown_command_failed",
                reason=detail[:2000] or "GPU teardown command failed.",
                now=now,
            )
            await _retire_gpu_runtime_lineage(
                db,
                reservation,
                now,
                reason=detail or "GPU teardown command failed.",
            )
    else:
        raise GpuAllocationError("Unknown GPU lifecycle acknowledgement.")
    reservation.last_reconciled_at = now
    await db.flush()


async def quarantine_gpu_reservation_control_plane(
    db: AsyncSession,
    reservation_id: str,
    *,
    code: str,
    reason: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Fence a lost or ambiguous reservation when no host proof can release it."""

    host_id = (
        await db.execute(
            select(GpuLaunchReservation.host_id).where(
                GpuLaunchReservation.reservation_id == reservation_id
            )
        )
    ).scalar_one_or_none()
    if host_id is None:
        raise GpuAllocationError("GPU reservation is unknown.")
    await _host_lock(db, host_id)
    reservation, group = await _locked_reservation_group(db, reservation_id)
    if reservation.state in {"released", "expired"}:
        return
    now = _utcnow()
    _quarantine_reservation(
        reservation,
        group,
        code=code,
        reason=reason,
        metadata=metadata,
        now=now,
    )
    await _retire_gpu_runtime_lineage(
        db,
        reservation,
        now,
        reason=reason,
    )
    await db.flush()


async def quarantine_gpu_reservation(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuReservationStateRequestV1,
    *,
    code: str,
    reason: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    host = await _host_lock(db, authenticated_host.host_id)
    reservation, group = await _locked_reservation_group(db, request.reservation_id)
    _validate_row_claims(reservation)
    _assert_host_association(host, reservation, group)
    if (
        reservation.claims_sha256 != request.claims_sha256
        or reservation.process_incarnation != request.process_incarnation
    ):
        raise GpuAllocationError("GPU quarantine request does not match reservation.")
    _quarantine_reservation(reservation, group, code=code, reason=reason, metadata=metadata)
    await _retire_gpu_runtime_lineage(
        db,
        reservation,
        _utcnow(),
        reason=reason,
    )
    await db.flush()


async def authorize_gpu_group_recovery(
    db: AsyncSession,
    allocation_group_id: str,
    request: GpuRecoveryAuthorizeRequestV1,
    *,
    authorized_by: str,
) -> GpuRecoveryAuthorizationV1:
    """Authorize one ownerless quarantined group after exact current inventory."""

    await acquire_gpu_lifecycle_lock(db)
    host_id = (
        await db.execute(
            select(GpuAllocationGroup.host_id).where(
                GpuAllocationGroup.allocation_group_id == allocation_group_id
            )
        )
    ).scalar_one_or_none()
    if host_id is None:
        raise GpuAllocationError("GPU recovery group is unknown.")
    host = await _host_lock(db, host_id)
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == allocation_group_id)
            .with_for_update()
        )
    ).scalar_one()
    report = await db.get(GpuInventoryReport, request.report_id)
    if report is None:
        raise GpuAllocationError("GPU recovery inventory report is unknown.")
    try:
        report_claims = GpuInventoryReportV1.model_validate(report.claims)
    except ValueError as exc:
        raise GpuAllocationError("GPU recovery inventory report is malformed.") from exc
    reported_group = report_claims.groups[0]
    if (
        group.state != "quarantined"
        or group.reservation_id is not None
        or group.management_mode is not None
        or group.process_incarnation is not None
        or group.last_report_id != report.report_id
        or report.reconciliation_status not in {"accepted", "quarantined"}
        or report.host_id != host.host_id
        or report.host_key_generation != host.active_key_generation
        or report.host_boot_generation != host.boot_generation
        or report_claims.host_boot_id != host.boot_id
        or reported_group.topology_fingerprint != group.topology_fingerprint
        or [item.bdf for item in reported_group.devices] != group.gpu_bdfs
        or sorted(item.uuid for item in reported_group.devices) != group.gpu_uuids
        or sorted(item.attestation_certificate_sha256 for item in reported_group.devices)
        != group.gpu_attestation_certificate_sha256s
    ):
        raise GpuAllocationError(
            "GPU recovery requires exact current host-signed inventory for an ownerless group."
        )
    authorization_id = generate_uuid()
    recovery_nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    now = _utcnow()
    group.recovery_authorization_id = authorization_id
    group.recovery_report_id = report.report_id
    group.recovery_nonce_hash = hashlib.sha256(recovery_nonce.encode("ascii")).hexdigest()
    group.recovery_authorized_by = authorized_by
    group.recovery_authorized_at = now
    group.recovery_started_at = None
    group.recovery_completed_at = None
    group.failure_metadata = {
        **(group.failure_metadata or {}),
        "recovery_authorization_reason": request.reason,
    }
    group.updated_at = now
    await db.flush()
    return GpuRecoveryAuthorizationV1(
        authorization_id=authorization_id,
        allocation_group_id=group.allocation_group_id,
        allocation_group_generation=group.generation,
        report_id=report.report_id,
        topology_fingerprint=group.topology_fingerprint,
        recovery_nonce=recovery_nonce,
    )


def _assert_gpu_recovery_authorization(
    group: GpuAllocationGroup,
    request: GpuRecoveryStartRequestV1 | GpuRecoveryResetResultV1,
) -> None:
    if (
        group.recovery_authorization_id != request.authorization_id
        or group.allocation_group_id != request.allocation_group_id
        or group.generation != request.allocation_group_generation
        or group.recovery_report_id != request.report_id
        or group.last_report_id != request.report_id
        or group.topology_fingerprint != request.topology_fingerprint
        or not group.recovery_nonce_hash
        or not secrets.compare_digest(
            group.recovery_nonce_hash,
            hashlib.sha256(request.recovery_nonce.encode("ascii")).hexdigest(),
        )
    ):
        raise GpuAllocationError("GPU recovery authorization is stale or mismatched.")


async def start_gpu_group_recovery(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuRecoveryStartRequestV1,
) -> None:
    host = await _host_lock(db, authenticated_host.host_id)
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == request.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if group is None or group.host_id != host.host_id:
        raise GpuAllocationError("GPU recovery group is unknown to this host.")
    _assert_gpu_recovery_authorization(group, request)
    if (
        group.state != "quarantined"
        or group.reservation_id is not None
        or group.host_key_generation != host.active_key_generation
        or group.host_boot_generation != host.boot_generation
    ):
        raise GpuAllocationError("GPU group cannot enter ownerless recovery.")
    now = _utcnow()
    group.state = "resetting"
    group.resetting_at = now
    group.recovery_started_at = now
    group.quarantined_at = None
    group.failure_code = None
    group.failure_reason = None
    group.failure_metadata = null()
    group.updated_at = now
    await db.flush()


async def complete_gpu_group_recovery(
    db: AsyncSession,
    authenticated_host: Host,
    result: GpuRecoveryResetResultV1,
) -> bool:
    host = await _host_lock(db, authenticated_host.host_id)
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == result.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if group is None or group.host_id != host.host_id:
        raise GpuAllocationError("GPU recovery group is unknown to this host.")
    _assert_gpu_recovery_authorization(group, result)
    exact = bool(
        group.state == "resetting"
        and group.reservation_id is None
        and group.recovery_started_at is not None
        and group.host_key_generation == host.active_key_generation
        and group.host_boot_generation == host.boot_generation
        and group.gpu_bdfs == result.gpu_bdfs
        and group.gpu_uuids == result.gpu_uuids
    )
    success = bool(
        exact and result.qemu_absent and result.reset_succeeded and result.original_drivers_restored
    )
    now = _utcnow()
    if not success:
        _quarantine_group(
            group,
            code=result.failure_code or "gpu_ownerless_recovery_failed",
            reason=result.failure_reason or "Ownerless GPU recovery proof mismatched.",
            metadata=result.evidence,
            now=now,
        )
        await db.flush()
        return False
    group.state = "available"
    group.generation = int(group.generation) + 1
    group.available_at = now
    group.resetting_at = None
    group.recovery_completed_at = now
    group.updated_at = now
    await db.flush()
    return True


async def gpu_group_available(db: AsyncSession, host: Host) -> bool:
    if host.compute_type != "gpu" or int(host.boot_generation or 0) < 1:
        return False
    host = await _host_lock(db, host.host_id)
    await _active_gpu_release(db, host)
    await _expire_locked_reservations(db, host.host_id)
    group = (
        await db.execute(
            select(GpuAllocationGroup.allocation_group_id)
            .where(
                GpuAllocationGroup.host_id == host.host_id,
                GpuAllocationGroup.host_key_generation == host.active_key_generation,
                GpuAllocationGroup.host_boot_generation == host.boot_generation,
                GpuAllocationGroup.state == "available",
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return group is not None
