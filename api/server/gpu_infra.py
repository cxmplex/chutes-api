"""Attested generation custody and two-source legacy GPU migration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, null, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import generate_uuid
from api.gpu_models import GpuRegistrationAttempt
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.reservations import (
    gpu_host_storage_readiness,
    observe_gpu_storage_liveness,
)
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation, RegistrySession
from api.instance.schemas import Instance
from api.server.gpu_sessions import (
    _current_attestation,
    _latest_attestation_attempt,
    _revocation_failed,
)
from api.server.schemas import (
    GpuInfraAbandonRequestV1,
    GpuInfraAbandonResponseV1,
    GpuInfraAcknowledgeRequestV1,
    GpuInfraAcknowledgeResponseV1,
    GpuInfraCloseRequestV1,
    GpuInfraCloseResponseV1,
    GpuInfraConfirmRequestV1,
    GpuInfraConfirmResponseV1,
    GpuInfraCustody,
    GpuInfraLeaseRequestV1,
    GpuInfraLeaseResponseV1,
    GpuInfraLegacyMigrationV2,
    GpuInfraLegacySourceV1,
    GpuInfraMigrationCompleteRequestV1,
    GpuInfraMigrationCompleteResponseV1,
    GpuInfraMigrationEntryV1,
    GpuInfraMigrationPromoteRequestV1,
    GpuInfraMigrationPromoteResponseV1,
    GpuInfraMigrationRefreshRequestV1,
    GpuInfraMigrationRefreshResponseV1,
    GpuInfraRetireRequestV1,
    GpuInfraRetireResponseV1,
    GpuLegacyCloseRequestV1,
    GpuLegacyCloseResponseV1,
    GpuLegacyCutoverAuthorization,
    GpuLegacyCutoverAuthorizeRequestV1,
    GpuLegacyCutoverAuthorizeResponseV1,
    GpuLegacyHostConfirmRequestV1,
    GpuLegacyHostConfirmResponseV1,
    GpuLegacyMigration,
    GpuMinerIdentity,
    Host,
    LuksCapabilityPurpose,
    LuksVolumeGenerationLease,
    Server,
    ServerAttestation,
    VmCacheConfig,
)
from api.server.util import (
    decrypt_passphrase,
    encrypt_passphrase,
    generate_cache_passphrase,
)

GPU_INFRA_LEASE_SECONDS = 300
GPU_LEGACY_CAPABILITY_SECONDS = 900
GPU_LEGACY_CUTOVER_SECONDS = 900

LEGACY_REQUIRED_ENTRIES = (
    {
        "name": "k3s-server-db",
        "source_volume": "storage",
        "source_path": "k3s/server/db",
        "destination_name": "k3s-server-db",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "k3s-server-tls",
        "source_volume": "storage",
        "source_path": "k3s/server/tls",
        "destination_name": "k3s-server-tls",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "k3s-server-cred",
        "source_volume": "storage",
        "source_path": "k3s/server/cred",
        "destination_name": "k3s-server-cred",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "k3s-server-token",
        "source_volume": "storage",
        "source_path": "k3s/server/token",
        "destination_name": "k3s-server-token",
        "kind": "file",
        "required": True,
    },
    {
        "name": "kubelet-pki",
        "source_volume": "storage",
        "source_path": "kubelet/pki",
        "destination_name": "kubelet-pki",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "admission-certs",
        "source_volume": "storage",
        "source_path": "admission-controller-certs",
        "destination_name": "admission-certs",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "registrar",
        "source_volume": "storage",
        "source_path": "chutes-agent",
        "destination_name": "registrar",
        "kind": "directory",
        "required": True,
    },
    {
        "name": "postgres",
        "source_volume": "tdx-cache",
        "source_path": "postgres-data",
        "destination_name": "postgres",
        "kind": "directory",
        "required": True,
    },
)
LEGACY_OPTIONAL_ENTRIES: tuple[dict[str, Any], ...] = ()


class GpuInfraError(RuntimeError):
    """A fail-closed gpu-infra custody transition was rejected."""


def _conflict(detail: str) -> None:
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encrypted_k3s_key() -> str:
    return encrypt_passphrase(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))


def _migration_capability(migration_id: str) -> str:
    return f"{migration_id}.{secrets.token_urlsafe(32)}"


def _capability_hash(capability: str) -> str:
    return hashlib.sha256(capability.encode("ascii")).hexdigest()


def _validate_capability(migration: GpuLegacyMigration, capability: str) -> None:
    if (
        not migration.source_capability_hash
        or not hmac.compare_digest(
            migration.source_capability_hash,
            _capability_hash(capability),
        )
        or migration.source_capability_expires_at is None
        or migration.source_capability_expires_at <= _now()
        or migration.source_capability_consumed_at is not None
    ):
        _conflict("Legacy migration capability is invalid or expired.")


async def _locked_current_lineage(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
) -> tuple[Server, GpuLaunchReservation, GpuAllocationGroup, Host]:
    observed_live_storage_ids = await observe_gpu_storage_liveness(
        db, runtime_server.host_id
    )
    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == runtime_server.server_id).with_for_update()
        )
    ).scalar_one_or_none()
    if server is None:
        _conflict("GPU server disappeared before gpu-infra custody was locked.")
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == server.gpu_launch_reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == server.gpu_allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    host = (
        await db.execute(select(Host).where(Host.host_id == server.host_id).with_for_update())
    ).scalar_one_or_none()
    registration_id = reservation.registration_attestation_id if reservation is not None else None
    registration_attestation = (
        await db.execute(
            select(ServerAttestation)
            .where(
                ServerAttestation.attestation_id
                == registration_id
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    registration_attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(
                GpuRegistrationAttempt.attestation_id
                == registration_id
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    latest = await _latest_attestation_attempt(db, server.server_id)
    try:
        _current_attestation(
            server,
            latest,
            expected_id=runtime_payload.get("attestation_id"),
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="gpu-infra requires the latest successful GPU attestation attempt.",
        ) from exc
    if (
        reservation is None
        or group is None
        or host is None
        or registration_attestation is None
        or registration_attempt is None
        or server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or server.gpu_management_mode != "miner"
        or server.gpu_retired_at is not None
        or reservation.state != "running"
        or group.state != "running"
        or reservation.management_mode != "miner"
        or reservation.server_id != server.server_id
        or reservation.host_id != host.host_id
        or reservation.host_boot_generation != host.boot_generation
        or reservation.reservation_id != runtime_payload.get("reservation_id")
        or registration_attempt.state != "completed"
        or registration_attempt.reservation_id != reservation.reservation_id
        or registration_attempt.attestation_id
        != reservation.registration_attestation_id
        or registration_attempt.peer_spki_sha256 != cert_hash.lower()
        or registration_attempt.peer_certificate_pem != server.attested_cert
        or registration_attestation.server_id != server.server_id
        or registration_attestation.verification_error is not None
        or registration_attestation.verified_at is None
        or registration_attestation.gpu_retired_at is not None
        or registration_attestation.gpu_launch_reservation_id
        != reservation.reservation_id
        or registration_attestation.gpu_allocation_group_id
        != reservation.allocation_group_id
        or registration_attestation.gpu_allocation_group_generation
        != reservation.allocation_group_generation
        or registration_attestation.gpu_host_boot_generation
        != reservation.host_boot_generation
        or registration_attestation.gpu_reservation_generation
        != reservation.reservation_generation
        or registration_attestation.gpu_management_mode != "miner"
        or registration_attestation.gpu_process_incarnation
        != reservation.process_incarnation
        or registration_attestation.gpu_claims_sha256 != reservation.claims_sha256
        or reservation.allocation_group_id != group.allocation_group_id
        or reservation.allocation_group_generation != group.generation
        or reservation.reservation_generation != group.reservation_generation
        or reservation.process_incarnation != server.gpu_process_incarnation
        or group.management_mode != "miner"
        or group.reservation_id != reservation.reservation_id
        or group.reservation_owner != server.miner_hotkey
        or group.process_incarnation != reservation.process_incarnation
        or runtime_payload.get("management_mode") != "miner"
        or runtime_payload.get("owner_hotkey") != server.miner_hotkey
        or runtime_payload.get("server_id") != server.server_id
        or runtime_payload.get("attested_spki_sha256") != cert_hash.lower()
        or server.attested_cert_pubkey_hash != cert_hash.lower()
    ):
        _conflict("GPU runtime session no longer matches its exact miner allocation lineage.")
    readiness = await gpu_host_storage_readiness(
        db,
        host,
        include_allocation=False,
        observed_live_storage_ids=observed_live_storage_ids,
    )
    if not (readiness.trusted_storage_ready and readiness.control_channel_eligible):
        _conflict(f"ChuteFS storage sibling is not currently trusted: {readiness.reason}.")
    return server, reservation, group, host


def _lineage_matches(
    custody: GpuInfraCustody,
    server: Server,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
    host: Host,
) -> bool:
    return bool(
        custody.server_id == server.server_id
        and custody.owner_hotkey == server.miner_hotkey
        and custody.host_id == host.host_id
        and custody.host_boot_generation == reservation.host_boot_generation
        and custody.reservation_id == reservation.reservation_id
        and custody.reservation_generation == reservation.reservation_generation
        and custody.allocation_group_id == group.allocation_group_id
        and custody.allocation_group_generation == group.generation
        and custody.management_mode == "miner"
    )


def _adopt_new_lineage(
    custody: GpuInfraCustody,
    server: Server,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
    host: Host,
) -> None:
    if custody.owner_hotkey != server.miner_hotkey or custody.host_id != host.host_id:
        _conflict("Stable gpu-infra identity cannot move to another owner or logical host.")
    if custody.state == "conflict":
        _conflict("gpu-infra custody is conflict-fenced.")
    if custody.state == "sealed":
        if custody.reservation_id == reservation.reservation_id:
            _conflict("gpu-infra is sealed for an in-progress teardown.")
        custody.state = "current"
        custody.sealed_at = None
        custody.guest_closed_at = None
        custody.guest_closed_generation = None
    elif custody.state != "current":
        _conflict("An unresolved gpu-infra generation cannot move to a new allocation lineage.")
    elif custody.reservation_id != reservation.reservation_id:
        _conflict("gpu-infra lineage changed without a completed seal/reset lifecycle.")
    custody.host_boot_generation = reservation.host_boot_generation
    custody.reservation_id = reservation.reservation_id
    custody.reservation_generation = reservation.reservation_generation
    custody.allocation_group_id = group.allocation_group_id
    custody.allocation_group_generation = group.generation
    custody.updated_at = _now()


def _generic_attestation_current(server: Server, attempt: ServerAttestation | None) -> bool:
    cutoff = _now() - timedelta(seconds=settings.release_attestation_max_age_seconds)
    return bool(
        attempt is not None
        and attempt.server_id == server.server_id
        and attempt.verification_error is None
        and attempt.verified_at is not None
        and attempt.verified_at >= cutoff
        and attempt.gpu_retired_at is None
        and attempt.measurement_name == server.measurement_name
        and attempt.measurement_config_fingerprint == server.measurement_config_fingerprint
        and attempt.trust_set_fingerprint == server.trust_set_fingerprint
        and dict(attempt.revocation_status or {})
        == dict(server.attestation_revocation_status or {})
        and not _revocation_failed(attempt.revocation_status)
    )


def _validated_legacy_lease(
    raw: Any,
    *,
    server: Server,
    volume: str,
    confirmed_generation: int,
) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        lease = LuksVolumeGenerationLease.model_validate(raw)
    except (TypeError, ValueError) as exc:
        _conflict(f"Legacy {volume} generation lease is malformed: {exc}.")
    if (
        lease.generation != confirmed_generation + 1
        or lease.server_id != server.server_id
        or lease.miner_hotkey != server.miner_hotkey
        or lease.vm_name != server.name
        or lease.cert_hash != server.attested_cert_pubkey_hash
        or lease.measurement_name != server.measurement_name
        or lease.measurement_version != server.version
        or lease.measurement_config_fingerprint != server.measurement_config_fingerprint
        or lease.trust_set_fingerprint != server.trust_set_fingerprint
        or lease.tee_type != server.tee_type
        or lease.purpose != LuksCapabilityPurpose.BOOT
        or lease.storage_role
    ):
        _conflict(f"Legacy {volume} generation lease belongs to another custody identity.")
    return lease.model_dump(mode="json")


async def authorize_legacy_gpu_cutover(
    db: AsyncSession,
    host_id: str,
    owner_hotkey: str,
    request: GpuLegacyCutoverAuthorizeRequestV1,
) -> GpuLegacyCutoverAuthorizeResponseV1:
    await acquire_gpu_lifecycle_lock(db)
    host = (
        await db.execute(select(Host).where(Host.host_id == host_id).with_for_update())
    ).scalar_one_or_none()
    server = (
        await db.execute(
            select(Server).where(Server.server_id == request.legacy_server_id).with_for_update()
        )
    ).scalar_one_or_none()
    latest = (
        await _latest_attestation_attempt(db, request.legacy_server_id)
        if server is not None
        else None
    )
    if (
        host is None
        or server is None
        or host.miner_hotkey != owner_hotkey
        or server.miner_hotkey != owner_hotkey
        or server.compute_type != "gpu"
        or not server.is_tee
        or server.gpu_retired_at is not None
        or not _generic_attestation_current(server, latest)
    ):
        _conflict("Legacy cutover authorization requires the current attested owner lineage.")
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
            owner_hotkey=owner_hotkey,
            legacy_vm_name=server.name,
        )
        db.add(identity)
        await db.flush()
    elif identity.owner_hotkey != owner_hotkey or identity.legacy_vm_name not in {
        None,
        server.name,
    }:
        _conflict("Stable miner identity conflicts with the requested legacy source.")
    else:
        identity.legacy_vm_name = server.name
    existing_migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.legacy_server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing_migration is not None:
        _conflict("Legacy source already transferred into migration custody.")
    authorization = (
        await db.execute(
            select(GpuLegacyCutoverAuthorization)
            .where(GpuLegacyCutoverAuthorization.legacy_server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    token = secrets.token_urlsafe(48)
    now = _now()
    if authorization is None:
        authorization = GpuLegacyCutoverAuthorization(
            authorization_id=generate_uuid(),
            token_hash=_capability_hash(token),
            host_id=host.host_id,
            owner_hotkey=owner_hotkey,
            legacy_server_id=server.server_id,
            legacy_vm_name=server.name,
            target_server_id=identity.server_id,
            state="issued",
            expires_at=now + timedelta(seconds=GPU_LEGACY_CUTOVER_SECONDS),
        )
        db.add(authorization)
    elif (
        authorization.state != "issued"
        or authorization.host_id != host.host_id
        or authorization.owner_hotkey != owner_hotkey
        or authorization.target_server_id != identity.server_id
    ):
        _conflict("Legacy cutover authorization is already consumed or conflicts.")
    else:
        authorization.token_hash = _capability_hash(token)
        authorization.expires_at = now + timedelta(seconds=GPU_LEGACY_CUTOVER_SECONDS)
    authorization.updated_at = now
    await db.flush()
    return GpuLegacyCutoverAuthorizeResponseV1(
        authorization_id=authorization.authorization_id,
        cutover_authorization=token,
        legacy_server_id=server.server_id,
        legacy_vm_name=server.name,
        target_server_id=identity.server_id,
        target_host_id=host.host_id,
        expires_at=authorization.expires_at.isoformat(),
    )


async def close_legacy_gpu_sources(
    db: AsyncSession,
    legacy_server_id: str,
    cert_hash: str,
    request: GpuLegacyCloseRequestV1,
) -> GpuLegacyCloseResponseV1:
    """Fence both old namespaces after the old measured guest quiesces them."""

    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == legacy_server_id).with_for_update()
        )
    ).scalar_one_or_none()
    host = (
        await db.execute(
            select(Host).where(Host.host_id == request.target_host_id).with_for_update()
        )
    ).scalar_one_or_none()
    latest = await _latest_attestation_attempt(db, legacy_server_id)
    existing_source = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.legacy_server_id == legacy_server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    cutover = (
        await db.execute(
            select(GpuLegacyCutoverAuthorization)
            .where(GpuLegacyCutoverAuthorization.legacy_server_id == legacy_server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    token_matches = bool(
        cutover is not None
        and hmac.compare_digest(
            cutover.token_hash,
            _capability_hash(request.cutover_authorization),
        )
    )
    if existing_source is not None:
        if (
            server is not None
            and host is not None
            and existing_source.host_id == host.host_id
            and existing_source.owner_hotkey == host.miner_hotkey
            and existing_source.close_cert_hash == cert_hash.lower()
            and server.attested_cert_pubkey_hash == cert_hash.lower()
            and existing_source.storage_luks_uuid == request.storage_luks_uuid
            and existing_source.storage_filesystem_uuid == request.storage_filesystem_uuid
            and existing_source.storage_generation == request.storage_generation
            and existing_source.cache_luks_uuid == request.cache_luks_uuid
            and existing_source.cache_filesystem_uuid == request.cache_filesystem_uuid
            and existing_source.cache_filesystem_type == request.cache_filesystem_type
            and existing_source.cache_generation == request.cache_generation
            and existing_source.state in {"guest_closed", "ready"}
            and token_matches
            and cutover.state == "consumed"
            and cutover.migration_id == existing_source.migration_id
        ):
            return GpuLegacyCloseResponseV1(
                migration_id=existing_source.migration_id,
                legacy_server_id=legacy_server_id,
                status="guest_closed",
            )
        _conflict("Legacy closure retry differs from persisted source custody.")
    if (
        server is None
        or host is None
        or server.compute_type != "gpu"
        or not server.is_tee
        or server.miner_hotkey != host.miner_hotkey
        or server.attested_cert_pubkey_hash != cert_hash.lower()
        or server.gpu_retired_at is not None
        or not _generic_attestation_current(server, latest)
        or cutover is None
        or not token_matches
        or cutover.state != "issued"
        or cutover.expires_at <= _now()
        or cutover.host_id != host.host_id
        or cutover.owner_hotkey != server.miner_hotkey
        or cutover.legacy_vm_name != server.name
    ):
        _conflict("Legacy closure requires the current attested GPU server and target host owner.")
    active_instances = int(
        (
            await db.execute(
                select(func.count(Instance.instance_id)).where(
                    or_(
                        Instance.server_id == legacy_server_id,
                        Instance.host == server.ip,
                    ),
                    Instance.active.is_(True),
                )
            )
        ).scalar()
        or 0
    )
    if active_instances:
        _conflict("Legacy GPU guest still has active workload instances.")
    vm_config = (
        await db.execute(
            select(VmCacheConfig)
            .where(
                VmCacheConfig.miner_hotkey == server.miner_hotkey,
                VmCacheConfig.vm_name == server.name,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if vm_config is None:
        _conflict("Legacy GPU key custody is absent.")
    stored = dict(vm_config.volume_passphrases or {})
    floors = dict(vm_config.volume_epochs or {})
    leases = dict(vm_config.volume_generation_leases or {})
    if (
        any(key in stored for key in ("gpu-infra", "pending_gpu-infra"))
        or "gpu-infra" in floors
        or "gpu-infra" in leases
    ):
        _conflict("Legacy key row already contains conflicting gpu-infra custody.")
    if (
        not stored.get("storage")
        or not stored.get("tdx-cache")
        or floors.get("storage", 0) != request.storage_generation
        or floors.get("tdx-cache", 0) != request.cache_generation
    ):
        _conflict("Legacy source keys or confirmed generations do not match closure evidence.")
    storage_lease = _validated_legacy_lease(
        leases.get("storage"),
        server=server,
        volume="storage",
        confirmed_generation=request.storage_generation,
    )
    cache_lease = _validated_legacy_lease(
        leases.get("tdx-cache"),
        server=server,
        volume="tdx-cache",
        confirmed_generation=request.cache_generation,
    )
    if (storage_lease is None) != (stored.get("pending_storage") is None):
        _conflict("Legacy storage pending key and generation lease disagree.")
    if (cache_lease is None) != (stored.get("pending_tdx-cache") is None):
        _conflict("Legacy tdx-cache pending key and generation lease disagree.")
    identity = (
        await db.execute(
            select(GpuMinerIdentity)
            .where(
                GpuMinerIdentity.host_id == host.host_id,
                GpuMinerIdentity.server_id == cutover.target_server_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        identity is None
        or identity.owner_hotkey != server.miner_hotkey
        or identity.legacy_vm_name != server.name
    ):
        _conflict("Cutover authorization lost its stable target identity.")

    existing = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.target_server_id == identity.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        if (
            existing.legacy_server_id == server.server_id
            and existing.state in {"guest_closed", "ready"}
            and existing.storage_luks_uuid == request.storage_luks_uuid
            and existing.cache_luks_uuid == request.cache_luks_uuid
        ):
            return GpuLegacyCloseResponseV1(
                migration_id=existing.migration_id,
                legacy_server_id=server.server_id,
                status="guest_closed",
            )
        _conflict("Legacy source already has conflicting migration custody.")
    conflicting_custody = await db.get(GpuInfraCustody, identity.server_id)
    if conflicting_custody is not None:
        _conflict("Target server already has conflicting gpu-infra custody.")

    migration = GpuLegacyMigration(
        migration_id=generate_uuid(),
        host_id=host.host_id,
        owner_hotkey=server.miner_hotkey,
        legacy_server_id=server.server_id,
        legacy_vm_name=server.name,
        target_server_id=identity.server_id,
        state="guest_closed",
        close_attestation_id=latest.attestation_id,
        close_cert_hash=cert_hash.lower(),
        storage_luks_uuid=request.storage_luks_uuid,
        storage_filesystem_uuid=request.storage_filesystem_uuid,
        storage_generation=request.storage_generation,
        storage_current_passphrase=stored.pop("storage"),
        storage_pending_passphrase=stored.pop("pending_storage", None),
        storage_lease=storage_lease,
        cache_luks_uuid=request.cache_luks_uuid,
        cache_filesystem_uuid=request.cache_filesystem_uuid,
        cache_filesystem_type=request.cache_filesystem_type,
        cache_generation=request.cache_generation,
        cache_current_passphrase=stored.pop("tdx-cache"),
        cache_pending_passphrase=stored.pop("pending_tdx-cache", None),
        cache_lease=cache_lease,
        k3s_encryption_key=vm_config.k3s_encryption_key,
        postgres_password=encrypt_passphrase(request.postgres_password.get_secret_value()),
        required_entries=list(LEGACY_REQUIRED_ENTRIES),
        optional_entries=list(LEGACY_OPTIONAL_ENTRIES),
        guest_closed_at=_now(),
    )
    db.add(migration)
    await db.flush([migration])
    cutover.state = "consumed"
    cutover.consumed_at = _now()
    cutover.migration_id = migration.migration_id
    cutover.updated_at = _now()
    leases.pop("storage", None)
    leases.pop("tdx-cache", None)
    floors.pop("storage", None)
    floors.pop("tdx-cache", None)
    vm_config.volume_passphrases = stored
    vm_config.volume_epochs = floors
    vm_config.volume_generation_leases = leases
    vm_config.k3s_encryption_key = None
    server.gpu_retired_at = _now()
    server.gpu_retirement_reason = "legacy gpu-infra migration custody fenced"
    server.gpu_runtime_session_attestation_id = None
    server.gpu_runtime_session_expires_at = None
    await db.execute(
        update(RegistrySession)
        .where(
            RegistrySession.server_id == server.server_id,
            RegistrySession.revoked_at.is_(None),
        )
        .values(revoked_at=_now())
    )
    await db.flush()
    return GpuLegacyCloseResponseV1(
        migration_id=migration.migration_id,
        legacy_server_id=server.server_id,
        status="guest_closed",
    )


async def confirm_legacy_sources_unowned(
    db: AsyncSession,
    host: Host,
    migration_id: str,
    request: GpuLegacyHostConfirmRequestV1,
) -> GpuLegacyHostConfirmResponseV1:
    await acquire_gpu_lifecycle_lock(db)
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        migration is None
        or migration.host_id != host.host_id
        or migration.owner_hotkey != host.miner_hotkey
        or migration.state not in {"guest_closed", "ready"}
        or request.storage_luks_uuid != migration.storage_luks_uuid
        or request.cache_luks_uuid != migration.cache_luks_uuid
    ):
        _conflict("Legacy source confirmation does not match the authenticated host.")
    if migration.state == "guest_closed":
        capability = _migration_capability(migration.migration_id)
        migration.source_capability_hash = _capability_hash(capability)
        migration.source_capability_expires_at = _now() + timedelta(
            seconds=GPU_LEGACY_CAPABILITY_SECONDS
        )
        migration.source_capability_consumed_at = None
        migration.host_confirmed_at = _now()
        migration.state = "ready"
        migration.updated_at = _now()
        await db.flush()
    return GpuLegacyHostConfirmResponseV1(
        migration_id=migration.migration_id,
        status="ready",
    )


def _legacy_source(
    migration: GpuLegacyMigration,
    namespace: str,
) -> GpuInfraLegacySourceV1:
    if namespace == "storage":
        return GpuInfraLegacySourceV1(
            namespace="storage",
            hotplug_serial="gpu-legacy-storage",
            filesystem_type="xfs",
            luks_uuid=migration.storage_luks_uuid,
            filesystem_uuid=migration.storage_filesystem_uuid,
            generation=migration.storage_generation,
            current=(
                decrypt_passphrase(migration.storage_current_passphrase)
                if migration.storage_current_passphrase
                else None
            ),
            next=(
                decrypt_passphrase(migration.storage_pending_passphrase)
                if migration.storage_pending_passphrase
                else None
            ),
            lease_generation=(
                migration.storage_lease.get("generation")
                if isinstance(migration.storage_lease, dict)
                else None
            ),
        )
    return GpuInfraLegacySourceV1(
        namespace="tdx-cache",
        hotplug_serial="gpu-legacy-cache",
        filesystem_type=migration.cache_filesystem_type,
        luks_uuid=migration.cache_luks_uuid,
        filesystem_uuid=migration.cache_filesystem_uuid,
        generation=migration.cache_generation,
        current=(
            decrypt_passphrase(migration.cache_current_passphrase)
            if migration.cache_current_passphrase
            else None
        ),
        next=(
            decrypt_passphrase(migration.cache_pending_passphrase)
            if migration.cache_pending_passphrase
            else None
        ),
        lease_generation=(
            migration.cache_lease.get("generation")
            if isinstance(migration.cache_lease, dict)
            else None
        ),
    )


def _legacy_response(
    migration: GpuLegacyMigration | None,
    capability: str | None,
) -> GpuInfraLegacyMigrationV2 | None:
    if migration is None or migration.state not in {"leased", "promoted"}:
        return None
    if capability is None:
        _conflict("Legacy migration capability plaintext is unavailable.")
    _validate_capability(migration, capability)
    return GpuInfraLegacyMigrationV2(
        migration_id=migration.migration_id,
        legacy_server_id=migration.legacy_server_id,
        capability=capability,
        expires_at=migration.source_capability_expires_at.isoformat(),
        postgres_password=decrypt_passphrase(migration.postgres_password),
        storage=_legacy_source(migration, "storage"),
        cache=_legacy_source(migration, "tdx-cache"),
        required_entries=[
            GpuInfraMigrationEntryV1.model_validate(item) for item in migration.required_entries
        ],
        optional_entries=[
            GpuInfraMigrationEntryV1.model_validate(item) for item in migration.optional_entries
        ],
    )


def _clear_lease(custody: GpuInfraCustody) -> None:
    custody.pending_passphrase = None
    custody.pending_key_slot = None
    custody.lease_id = None
    custody.lease_generation = None
    custody.lease_expires_at = None
    custody.lease_attestation_id = None
    custody.lease_cert_hash = None
    custody.lease_session_jti = None
    custody.pending_marker_sha256 = None


def _abandon_locked(custody: GpuInfraCustody, *, preserve_rollback: bool) -> None:
    if custody.state not in {"leased", "awaiting_ack"}:
        return
    if preserve_rollback:
        custody.rollback_generation = custody.lease_generation
        custody.rollback_key_slot = custody.pending_key_slot
        custody.rollback_passphrase = custody.pending_passphrase
    _clear_lease(custody)
    custody.state = "current"


async def lease_gpu_infra(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraLeaseRequestV1,
) -> GpuInfraLeaseResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    if request.legacy_vm_name is not None and request.legacy_vm_name != reservation.legacy_vm_name:
        _conflict("Guest legacy migration hint differs from its validator reservation.")
    migration = None
    if reservation.legacy_migration_id is not None:
        migration = (
            await db.execute(
                select(GpuLegacyMigration)
                .where(GpuLegacyMigration.migration_id == reservation.legacy_migration_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if migration is not None and migration.state == "completed":
            migration = None
        elif (
            migration is None
            or migration.target_server_id != server.server_id
            or migration.host_id != host.host_id
            or migration.state not in {"ready", "leased", "promoted"}
        ):
            _conflict("Legacy migration is not ready for this exact target server.")
        from api.gpu_models import GpuHotplugCommand

        hotplug = (
            await db.execute(
                select(GpuHotplugCommand)
                .where(
                    GpuHotplugCommand.reservation_id == reservation.reservation_id,
                    GpuHotplugCommand.reservation_generation
                    == reservation.reservation_generation,
                    GpuHotplugCommand.claims_sha256 == reservation.claims_sha256,
                    GpuHotplugCommand.allocation_group_id
                    == reservation.allocation_group_id,
                    GpuHotplugCommand.allocation_group_generation
                    == reservation.allocation_group_generation,
                    GpuHotplugCommand.process_incarnation
                    == reservation.process_incarnation,
                    GpuHotplugCommand.stable_server_id == server.server_id,
                    GpuHotplugCommand.migration_id == migration.migration_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            hotplug is None
            or hotplug.state != "acked"
            or hotplug.ack is None
            or hotplug.ack_sha256 is None
            or hotplug.acknowledged_at is None
        ):
            _conflict(
                "Legacy gpu-infra adoption requires the exact successful hotplug ACK."
            )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == runtime_server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None:
        floor = (
            max(migration.storage_generation, migration.cache_generation)
            if migration is not None
            else 0
        )
        custody = GpuInfraCustody(
            server_id=server.server_id,
            owner_hotkey=server.miner_hotkey,
            host_id=host.host_id,
            host_boot_generation=reservation.host_boot_generation,
            reservation_id=reservation.reservation_id,
            reservation_generation=reservation.reservation_generation,
            allocation_group_id=group.allocation_group_id,
            allocation_group_generation=group.generation,
            management_mode="miner",
            volume_name="gpu-infra",
            k3s_encryption_key=(
                migration.k3s_encryption_key
                if migration is not None and migration.k3s_encryption_key
                else _encrypted_k3s_key()
            ),
            confirmed_generation=floor,
            state="current",
            migration_id=migration.migration_id if migration is not None else None,
        )
        db.add(custody)
        await db.flush()
    elif not _lineage_matches(custody, server, reservation, group, host):
        _adopt_new_lineage(custody, server, reservation, group, host)
    capability = None
    if migration is not None:
        if custody.migration_id not in {None, migration.migration_id}:
            _conflict("gpu-infra custody references another legacy migration.")
        custody.migration_id = migration.migration_id
        if migration.state == "ready":
            capability = _migration_capability(migration.migration_id)
            migration.source_capability_hash = _capability_hash(capability)
            migration.source_capability_expires_at = _now() + timedelta(
                seconds=GPU_LEGACY_CAPABILITY_SECONDS
            )
            migration.source_capability_consumed_at = None
            migration.state = "leased"
        elif migration.state in {"leased", "promoted"}:
            capability = _migration_capability(migration.migration_id)
            migration.source_capability_hash = _capability_hash(capability)
            migration.source_capability_expires_at = _now() + timedelta(
                seconds=GPU_LEGACY_CAPABILITY_SECONDS
            )
            migration.source_capability_consumed_at = None

    reused = custody.state in {"leased", "awaiting_ack"}
    if reused:
        if custody.lease_generation != custody.confirmed_generation + 1:
            _conflict("Persisted gpu-infra pending generation is malformed.")
    elif custody.state == "current":
        current = (
            decrypt_passphrase(custody.current_passphrase) if custody.current_passphrase else None
        )
        if (current is None) != (custody.active_key_slot is None):
            _conflict("gpu-infra current key and active slot disagree.")
        if custody.rollback_passphrase is not None and current is None:
            custody.pending_passphrase = custody.rollback_passphrase
            custody.pending_key_slot = custody.rollback_key_slot
            custody.rollback_generation = None
            custody.rollback_key_slot = None
            custody.rollback_passphrase = None
            reused = True
        else:
            custody.pending_passphrase = encrypt_passphrase(generate_cache_passphrase())
            custody.pending_key_slot = (
                0 if custody.active_key_slot is None else 1 - custody.active_key_slot
            )
        custody.lease_id = secrets.token_hex(32)
        custody.lease_generation = custody.confirmed_generation + 1
        custody.state = "leased"
    else:
        _conflict(f"gpu-infra cannot lease while custody state is {custody.state}.")

    custody.lease_expires_at = _now() + timedelta(seconds=GPU_INFRA_LEASE_SECONDS)
    custody.lease_attestation_id = runtime_payload["attestation_id"]
    custody.lease_cert_hash = cert_hash.lower()
    custody.lease_session_jti = runtime_payload["jti"]
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraLeaseResponseV1(
        server_id=server.server_id,
        lease_id=custody.lease_id,
        generation=custody.lease_generation,
        confirmed_generation=custody.confirmed_generation,
        current=(
            decrypt_passphrase(custody.current_passphrase) if custody.current_passphrase else None
        ),
        next=decrypt_passphrase(custody.pending_passphrase),
        active_key_slot=custody.active_key_slot,
        next_key_slot=custody.pending_key_slot,
        lease_expires_at=custody.lease_expires_at.isoformat(),
        lease_reused=reused,
        awaiting_ack=custody.state == "awaiting_ack",
        rollback_generation=custody.rollback_generation,
        rollback_key_slot=custody.rollback_key_slot,
        rollback_key=(
            decrypt_passphrase(custody.rollback_passphrase) if custody.rollback_passphrase else None
        ),
        retire_key_slot=custody.retiring_key_slot,
        k3s_encryption_key=decrypt_passphrase(custody.k3s_encryption_key),
        legacy_migration=_legacy_response(migration, capability),
    )


async def confirm_gpu_infra(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraConfirmRequestV1,
) -> GpuInfraConfirmResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == runtime_server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None or not _lineage_matches(custody, server, reservation, group, host):
        _conflict("gpu-infra confirmation has no exact current custody lineage.")
    if (
        request.lease_id != custody.lease_id
        or request.generation != custody.lease_generation
        or request.active_key_slot != custody.pending_key_slot
    ):
        _conflict("gpu-infra confirmation does not own the pending generation.")
    if custody.state == "awaiting_ack":
        if custody.pending_marker_sha256 != request.marker_sha256:
            _conflict("gpu-infra confirmation retry changed its durable marker.")
        return GpuInfraConfirmResponseV1(
            server_id=server.server_id,
            lease_id=custody.lease_id,
            generation=custody.lease_generation,
            status="awaiting_ack",
        )
    if (
        custody.state != "leased"
        or custody.lease_expires_at is None
        or custody.lease_expires_at <= _now()
        or custody.lease_attestation_id != runtime_payload["attestation_id"]
        or custody.lease_cert_hash != cert_hash.lower()
        or not custody.pending_passphrase
    ):
        _conflict("gpu-infra generation lease expired or changed before confirmation.")
    custody.lease_session_jti = runtime_payload["jti"]
    custody.pending_marker_sha256 = request.marker_sha256
    custody.state = "awaiting_ack"
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraConfirmResponseV1(
        server_id=server.server_id,
        lease_id=custody.lease_id,
        generation=custody.lease_generation,
        status="awaiting_ack",
    )


async def acknowledge_gpu_infra(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraAcknowledgeRequestV1,
) -> GpuInfraAcknowledgeResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None or not _lineage_matches(custody, server, reservation, group, host):
        _conflict("gpu-infra acknowledgement has no exact current custody lineage.")
    if (
        custody.state != "awaiting_ack"
        or request.lease_id != custody.lease_id
        or request.generation != custody.lease_generation
        or request.active_key_slot != custody.pending_key_slot
        or request.marker_sha256 != custody.pending_marker_sha256
        or custody.pending_passphrase is None
    ):
        _conflict("gpu-infra acknowledgement does not match the confirmed pending generation.")
    retire_slot = custody.active_key_slot
    custody.retiring_passphrase = custody.current_passphrase
    custody.retiring_key_slot = retire_slot
    custody.current_passphrase = custody.pending_passphrase
    custody.confirmed_generation = custody.lease_generation
    custody.active_key_slot = custody.pending_key_slot
    _clear_lease(custody)
    custody.rollback_generation = None
    custody.rollback_key_slot = None
    custody.rollback_passphrase = None
    custody.state = "current"
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraAcknowledgeResponseV1(
        server_id=server.server_id,
        generation=custody.confirmed_generation,
        retire_key_slot=retire_slot,
        status="current",
    )


async def abandon_gpu_infra(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraAbandonRequestV1,
) -> GpuInfraAbandonResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        custody is None
        or not _lineage_matches(custody, server, reservation, group, host)
        or custody.state not in {"leased", "awaiting_ack"}
        or custody.lease_id != request.lease_id
        or custody.lease_generation != request.generation
        or custody.confirmed_generation != request.restored_generation
        or custody.pending_key_slot != request.removed_key_slot
    ):
        _conflict("gpu-infra abandon evidence does not match its pending generation.")
    _abandon_locked(custody, preserve_rollback=False)
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraAbandonResponseV1(
        server_id=server.server_id,
        confirmed_generation=custody.confirmed_generation,
        status="current",
    )


async def retire_gpu_infra_key(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraRetireRequestV1,
) -> GpuInfraRetireResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        custody is None
        or not _lineage_matches(custody, server, reservation, group, host)
        or custody.state not in {"current", "leased"}
        or custody.confirmed_generation != request.generation
        or custody.active_key_slot != request.active_key_slot
        or custody.retiring_key_slot != request.retired_key_slot
        or custody.retiring_passphrase is None
    ):
        _conflict("gpu-infra retirement does not match the acknowledged generation.")
    custody.retiring_key_slot = None
    custody.retiring_passphrase = None
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraRetireResponseV1(
        server_id=server.server_id,
        generation=custody.confirmed_generation,
        status="current",
    )


def _validate_migration_marker(
    migration: GpuLegacyMigration,
    custody: GpuInfraCustody,
    marker: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    required_keys = {
        "schema",
        "version",
        "server_id",
        "volume_name",
        "custody_generation",
        "migration_id",
        "state",
        "sources",
        "copied_entries",
        "omitted_optional_entries",
        "content_summary_sha256",
        "active_tree",
    }
    marker_sources = marker.get("sources") if isinstance(marker, dict) else None
    storage_marker = marker_sources.get("storage") if isinstance(marker_sources, dict) else None
    cache_marker = marker_sources.get("tdx-cache") if isinstance(marker_sources, dict) else None
    storage_generation = (
        storage_marker.get("generation") if isinstance(storage_marker, dict) else None
    )
    cache_generation = cache_marker.get("generation") if isinstance(cache_marker, dict) else None
    storage_allowed = {migration.storage_generation}
    cache_allowed = {migration.cache_generation}
    if isinstance(migration.storage_lease, dict):
        storage_allowed.add(migration.storage_lease.get("generation"))
    if isinstance(migration.cache_lease, dict):
        cache_allowed.add(migration.cache_lease.get("generation"))
    expected_sources = {
        "storage": {
            "generation": storage_generation,
            "luks_uuid": migration.storage_luks_uuid,
            "filesystem_uuid": migration.storage_filesystem_uuid,
            "filesystem_type": "xfs",
            "hotplug_serial": "gpu-legacy-storage",
        },
        "tdx-cache": {
            "generation": cache_generation,
            "luks_uuid": migration.cache_luks_uuid,
            "filesystem_uuid": migration.cache_filesystem_uuid,
            "filesystem_type": migration.cache_filesystem_type,
            "hotplug_serial": "gpu-legacy-cache",
        },
    }
    required_names = {entry["name"] for entry in migration.required_entries}
    optional_names = {entry["name"] for entry in migration.optional_entries}
    copied = set(marker.get("copied_entries") or [])
    omitted = set(marker.get("omitted_optional_entries") or [])
    summary_sha256 = hashlib.sha256(
        json.dumps(
            summary,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    summary_entries = summary.get("entries") if isinstance(summary, dict) else None
    summary_generations = summary.get("source_generations") if isinstance(summary, dict) else None
    summary_valid = bool(
        isinstance(summary_entries, dict)
        and isinstance(summary_generations, dict)
        and set(summary)
        == {
            "schema",
            "version",
            "migration_id",
            "source_generations",
            "entries",
        }
        and summary.get("schema") == "chutes.gpu-infra-copy-summary"
        and summary.get("version") == 1
        and summary.get("migration_id") == migration.migration_id
        and summary_generations
        == {
            "storage": storage_generation,
            "tdx-cache": cache_generation,
        }
        and set(summary_entries) == copied
        and all(
            isinstance(value, dict)
            and set(value) == {"records", "total_bytes"}
            and isinstance(value["records"], list)
            and isinstance(value["total_bytes"], int)
            and value["total_bytes"] >= 0
            and all(
                isinstance(record, dict)
                and record.get("kind") in {"file", "directory"}
                and isinstance(record.get("path"), str)
                and ".." not in record["path"].split("/")
                and isinstance(record.get("mode"), int)
                and isinstance(record.get("uid"), int)
                and isinstance(record.get("gid"), int)
                and isinstance(record.get("size"), int)
                and (
                    record["kind"] == "directory"
                    or (
                        set(record) == {"path", "kind", "mode", "uid", "gid", "size", "sha256"}
                        and isinstance(record.get("sha256"), str)
                        and len(record["sha256"]) == 64
                    )
                )
                for record in value["records"]
            )
            for value in summary_entries.values()
        )
    )
    if (
        set(marker) != required_keys
        or marker["schema"] != "chutes.gpu-infra-migration-marker"
        or marker["version"] != 2
        or marker["server_id"] != custody.server_id
        or marker["volume_name"] != "gpu-infra"
        or marker["custody_generation"] != custody.confirmed_generation
        or marker["migration_id"] != migration.migration_id
        or marker["state"] != "promoted"
        or storage_generation not in storage_allowed
        or cache_generation not in cache_allowed
        or marker["sources"] != expected_sources
        or not required_names.issubset(copied)
        or copied.union(omitted) != required_names.union(optional_names)
        or copied.intersection(omitted)
        or marker["content_summary_sha256"] != summary_sha256
        or marker["active_tree"] != f"migrations/{migration.migration_id}"
        or not summary_valid
    ):
        _conflict("Legacy migration marker or content summary is not exact.")


async def refresh_gpu_infra_migration(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraMigrationRefreshRequestV1,
) -> GpuInfraMigrationRefreshResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db,
        runtime_server,
        runtime_payload,
        cert_hash,
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == request.migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        custody is None
        or migration is None
        or not _lineage_matches(custody, server, reservation, group, host)
        or custody.state != "current"
        or custody.migration_id != migration.migration_id
        or migration.target_server_id != server.server_id
        or migration.state not in {"leased", "promoted"}
    ):
        _conflict("Legacy migration capability refresh does not own current custody.")
    capability = _migration_capability(migration.migration_id)
    migration.source_capability_hash = _capability_hash(capability)
    migration.source_capability_expires_at = _now() + timedelta(
        seconds=GPU_LEGACY_CAPABILITY_SECONDS
    )
    migration.source_capability_consumed_at = None
    migration.updated_at = _now()
    await db.flush()
    return GpuInfraMigrationRefreshResponseV1(
        server_id=server.server_id,
        migration_id=migration.migration_id,
        capability=capability,
        expires_at=migration.source_capability_expires_at.isoformat(),
        status="ready",
    )


async def promote_gpu_infra_migration(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraMigrationPromoteRequestV1,
) -> GpuInfraMigrationPromoteResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == request.migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        custody is None
        or migration is None
        or not _lineage_matches(custody, server, reservation, group, host)
        or custody.state != "current"
        or custody.migration_id != migration.migration_id
        or migration.target_server_id != server.server_id
        or migration.state not in {"leased", "promoted"}
    ):
        _conflict("Legacy promotion does not match current gpu-infra custody.")
    canonical_marker = (
        json.dumps(
            request.marker,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if hashlib.sha256(canonical_marker).hexdigest() != request.marker_sha256:
        _conflict("Legacy migration marker hash is not canonical.")
    if migration.state == "promoted":
        if (
            migration.promoted_marker_sha256 == request.marker_sha256
            and migration.promoted_summary == request.content_summary
        ):
            return GpuInfraMigrationPromoteResponseV1(
                server_id=server.server_id,
                migration_id=migration.migration_id,
                status="promoted",
            )
        _conflict("Legacy migration promotion retry changed its content.")
    _validate_capability(migration, request.capability)
    _validate_migration_marker(migration, custody, request.marker, request.content_summary)
    migration.promoted_marker_sha256 = request.marker_sha256
    migration.promoted_summary = request.content_summary
    migration.promoted_at = _now()
    migration.state = "promoted"
    migration.source_capability_hash = None
    migration.source_capability_expires_at = None
    migration.source_capability_consumed_at = _now()
    migration.updated_at = _now()
    await db.flush()
    return GpuInfraMigrationPromoteResponseV1(
        server_id=server.server_id,
        migration_id=migration.migration_id,
        status="promoted",
    )


async def complete_gpu_infra_migration(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraMigrationCompleteRequestV1,
) -> GpuInfraMigrationCompleteResponseV1:
    server, reservation, group, host = await _locked_current_lineage(
        db, runtime_server, runtime_payload, cert_hash
    )
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == request.migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        migration is not None
        and migration.state == "completed"
        and migration.target_server_id == server.server_id
        and migration.promoted_marker_sha256 == request.marker_sha256
    ):
        return GpuInfraMigrationCompleteResponseV1(
            server_id=server.server_id,
            migration_id=migration.migration_id,
            status="completed",
        )
    if (
        custody is None
        or migration is None
        or not _lineage_matches(custody, server, reservation, group, host)
        or custody.state != "current"
        or custody.migration_id != migration.migration_id
        or migration.target_server_id != server.server_id
        or migration.state not in {"promoted", "completed"}
        or migration.promoted_marker_sha256 != request.marker_sha256
    ):
        _conflict("Legacy migration discard acknowledgement is stale or mismatched.")
    _validate_capability(migration, request.capability)
    if migration.state != "completed":
        migration.storage_current_passphrase = None
        migration.storage_pending_passphrase = None
        migration.storage_lease = null()
        migration.cache_current_passphrase = None
        migration.cache_pending_passphrase = None
        migration.cache_lease = null()
        migration.k3s_encryption_key = None
        migration.postgres_password = None
        migration.source_capability_hash = None
        migration.source_capability_expires_at = None
        migration.source_capability_consumed_at = _now()
        migration.discarded_at = _now()
        migration.completed_at = _now()
        migration.state = "completed"
        migration.updated_at = _now()
        identity = (
            await db.execute(
                select(GpuMinerIdentity)
                .where(GpuMinerIdentity.server_id == server.server_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if identity is None or identity.legacy_vm_name != migration.legacy_vm_name:
            _conflict("Stable miner identity lost its exact legacy migration source.")
        identity.legacy_vm_name = None
        identity.updated_at = _now()
        custody.migration_id = None
        custody.updated_at = _now()
        await db.flush()
    return GpuInfraMigrationCompleteResponseV1(
        server_id=server.server_id,
        migration_id=migration.migration_id,
        status="completed",
    )


async def acknowledge_gpu_infra_closed(
    db: AsyncSession,
    runtime_server: Server,
    runtime_payload: dict[str, Any],
    cert_hash: str,
    request: GpuInfraCloseRequestV1,
) -> GpuInfraCloseResponseV1:
    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == runtime_server.server_id).with_for_update()
        )
    ).scalar_one_or_none()
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == runtime_payload.get("reservation_id"))
            .with_for_update()
        )
    ).scalar_one_or_none()
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == runtime_server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        server is None
        or reservation is None
        or custody is None
        or server.attested_cert_pubkey_hash != cert_hash.lower()
        or server.gpu_runtime_session_attestation_id != runtime_payload.get("attestation_id")
        or reservation.server_id != server.server_id
        or reservation.state != "resetting"
        or custody.reservation_id != reservation.reservation_id
        or custody.reservation_generation != reservation.reservation_generation
        or custody.state != "sealed"
        or request.generation != custody.confirmed_generation
    ):
        _conflict("gpu-infra close acknowledgement does not match sealed custody.")
    custody.guest_closed_generation = request.generation
    custody.guest_closed_at = _now()
    custody.updated_at = _now()
    await db.flush()
    return GpuInfraCloseResponseV1(
        server_id=server.server_id,
        generation=request.generation,
        status="closed",
    )


async def seal_gpu_infra_for_reservation(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
) -> None:
    if reservation.management_mode != "miner":
        return
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == reservation.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None:
        return
    if (
        custody.reservation_id != reservation.reservation_id
        or custody.reservation_generation != reservation.reservation_generation
        or custody.allocation_group_id != reservation.allocation_group_id
        or custody.allocation_group_generation != reservation.allocation_group_generation
        or custody.state == "conflict"
    ):
        raise GpuInfraError("Miner GPU teardown does not own current gpu-infra custody.")
    _abandon_locked(custody, preserve_rollback=True)
    custody.state = "sealed"
    custody.sealed_at = _now()
    custody.guest_closed_at = None
    custody.guest_closed_generation = None
    custody.updated_at = _now()
    await db.flush()


async def force_seal_gpu_infra_from_recovery(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    source_reader_result,
) -> None:
    """Seal exact miner custody after L0 proves both source namespaces reader-free."""

    if reservation.management_mode != "miner":
        return
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == reservation.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None:
        return
    if (
        source_reader_result.readers_absent is not True
        or [item.namespace for item in source_reader_result.sources]
        != ["storage", "tdx-cache"]
        or any(item.reader_pids for item in source_reader_result.sources)
        or source_reader_result.migration_id != reservation.legacy_migration_id
        or custody.owner_hotkey != reservation.owner_hotkey
        or custody.host_id != reservation.host_id
        or custody.host_boot_generation != reservation.host_boot_generation
        or custody.reservation_id != reservation.reservation_id
        or custody.reservation_generation != reservation.reservation_generation
        or custody.allocation_group_id != reservation.allocation_group_id
        or custody.allocation_group_generation
        != reservation.allocation_group_generation
        or custody.management_mode != reservation.management_mode
        or custody.migration_id != reservation.legacy_migration_id
        or custody.state == "conflict"
    ):
        raise GpuInfraError(
            "Forced recovery source-reader result differs from current gpu-infra custody."
        )
    now = _now()
    if custody.state != "sealed":
        _abandon_locked(custody, preserve_rollback=True)
        custody.state = "sealed"
        custody.sealed_at = now
    custody.guest_closed_generation = custody.confirmed_generation
    custody.guest_closed_at = now
    custody.updated_at = now
    await db.flush()


async def require_gpu_infra_sealed(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
) -> None:
    if reservation.management_mode != "miner":
        return
    custody = (
        await db.execute(
            select(GpuInfraCustody)
            .where(GpuInfraCustody.server_id == reservation.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if custody is None:
        return
    if (
        custody.state != "sealed"
        or custody.reservation_id != reservation.reservation_id
        or custody.reservation_generation != reservation.reservation_generation
        or custody.guest_closed_at is None
        or custody.guest_closed_generation != custody.confirmed_generation
    ):
        raise GpuInfraError("Miner GPU reset cannot release an unclosed gpu-infra generation.")
