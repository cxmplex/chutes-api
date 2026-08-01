"""Canonical GPU inventory and reservation wire-contract tests."""

import copy
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from api.host import gpu_allocations, router as host_router
from api.host.gpu_allocations import (
    GpuAllocationError,
    _l0_gpu_profile_id,
    _profile_for_report,
    _require_resumable_legacy_migration,
    _validate_resource_budget,
    reserve_gpu_group,
    sign_gpu_launch_claims,
)
from api.gpu_contracts import (
    GpuLifecycleOperationV1,
    GpuPhysicalResultV1,
    GpuRecoveryAuthorizationEnvelopeV1,
    GpuRegistrationNonceRequestV2,
)
from api.gpu_lifecycle_service import gpu_recovery_authorization_document
from api.gpu_registration_service import issue_gpu_registration_nonce
from api.host.schemas import (
    GpuInventoryGroupV1,
    GpuInventoryReportV1,
    GpuLaunchReservationClaimsV1,
    GpuMinerReservationRequestV1,
    GpuPlatformReservationRequestV1,
    canonical_sha256,
)
from api.server.schemas import Host
from api.server.schemas import NvidiaVerificationResultV1
from api.server.exceptions import InvalidGpuEvidenceError
from api.server.service import _assert_reserved_nvidia_devices
from pydantic import ValidationError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from tests.unit.test_release_provenance import _gpu_document


UUIDS = [f"GPU-00000000-0000-0000-0000-{index:012x}" for index in range(1, 9)]
BDFS = [f"0000:{index:02x}:00.0" for index in range(1, 9)]
GPU_CLAIM_FIXTURE_SHA256 = "b3b0199bd6c87befdd682f9c847a196b19d44773d78ffd6bf131e15f77543197"


@pytest.mark.asyncio
async def test_gpu_registration_nonce_rejects_non_ascii_request_id_before_db_work():
    db = SimpleNamespace(execute=AsyncMock())
    request = GpuRegistrationNonceRequestV2(
        client_request_id="gpu-registration-v2-é",
        request_generation=1,
        launch_reservation="reservation-1." + "x" * 64,
        claims_sha256="a" * 64,
        server_id="server-1",
    )

    with pytest.raises(HTTPException) as exc:
        await issue_gpu_registration_nonce(db, "127.0.0.1", request, "b" * 64)

    assert exc.value.status_code == 409
    db.execute.assert_not_awaited()


def test_gpu_claims_receive_measured_es256_envelope(monkeypatch):
    claims = GpuLaunchReservationClaimsV1.model_validate(
        json.loads(
            (Path(__file__).resolve().parents[1] / "fixtures/gpu_launch_claims_v1.json").read_text()
        )
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(
        gpu_allocations,
        "settings",
        SimpleNamespace(
            launch_config_private_key=private_key,
            gpu_launch_key_epoch=7,
        ),
    )

    envelope = sign_gpu_launch_claims(claims)

    assert envelope.claims == claims
    assert envelope.claims_sha256 == canonical_sha256(claims)
    assert envelope.key_epoch == 7
    private_key.public_key().verify(
        base64.b64decode(envelope.signature),
        json.dumps(
            claims.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )


def test_gpu_claim_signing_fails_without_validator_asymmetric_key(monkeypatch):
    claims = GpuLaunchReservationClaimsV1.model_validate(
        json.loads(
            (Path(__file__).resolve().parents[1] / "fixtures/gpu_launch_claims_v1.json").read_text()
        )
    )
    monkeypatch.setattr(
        gpu_allocations,
        "settings",
        SimpleNamespace(launch_config_private_key=None),
    )

    with pytest.raises(GpuAllocationError, match="P-256"):
        sign_gpu_launch_claims(claims)


def test_gpu_claim_signing_rejects_nonpositive_key_epoch(monkeypatch):
    claims = GpuLaunchReservationClaimsV1.model_validate(
        json.loads(
            (Path(__file__).resolve().parents[1] / "fixtures/gpu_launch_claims_v1.json").read_text()
        )
    )
    monkeypatch.setattr(
        gpu_allocations,
        "settings",
        SimpleNamespace(
            launch_config_private_key=ec.generate_private_key(ec.SECP256R1()),
            gpu_launch_key_epoch=0,
        ),
    )
    with pytest.raises(GpuAllocationError, match="epoch must be positive"):
        sign_gpu_launch_claims(claims)


def _group():
    devices = [
        {
            "bdf": bdf,
            "uuid": uuid,
            "gpu_identifier": "b200",
            "model": "NVIDIA B200",
            "vram_mib": 196608,
            "pci_vendor_id": "10de",
            "pci_device_id": "2901",
            "iommu_group": index,
            "iommu_members": [bdf],
            "reset_domain": "sbr:0000:00:01.0",
            "reset_members": list(BDFS),
            "numa_node": 0 if index <= 4 else 1,
            "original_driver": "nvidia",
            "attestation_certificate_sha256": f"{index:064x}",
        }
        for index, (bdf, uuid) in enumerate(zip(BDFS, UUIDS, strict=True), start=1)
    ]
    fabric_identity = {"gpu_uuids": sorted(UUIDS), "nvswitch_bdfs": []}
    value = {
        "reported_profile_id": "b200-8gpu",
        "model": "B200",
        "host_numa_nodes": 2,
        "devices": devices,
        "nvswitches": [],
        "infiniband_devices": [],
        "nvlink_edges": [
            {
                "source_uuid": source,
                "target_uuid": target,
                "link_count": 18,
            }
            for index, source in enumerate(sorted(UUIDS))
            for target in sorted(UUIDS)[index + 1 :]
        ],
        "fabrics": [
            {
                "fabric_id": canonical_sha256(fabric_identity),
                **fabric_identity,
            }
        ],
    }
    value["topology_fingerprint"] = canonical_sha256(value)
    return value


def _report():
    provenance = _gpu_document()
    return GpuInventoryReportV1(
        report_generation=1,
        host_id="gpu-host",
        host_key_generation=1,
        host_boot_id="11111111-1111-1111-1111-111111111111",
        host_boot_generation=1,
        l0_version="l0-gpu-test",
        l0_manifest_generation=1,
        l0_manifest_sha256="a" * 64,
        gpu_release_id="gpu-release",
        gpu_image_sha256=provenance["image"]["sha256"],
        profile_contract_sha256=provenance["profile_contract_sha256"],
        observed_at=datetime.now(timezone.utc),
        resources={
            "logical_cpus": 192,
            "memory_mib": 2_100_000,
            "data_disk_total_mib": 10_000_000,
            "data_disk_free_mib": 9_000_000,
            "storage_vcpus": 2,
            "storage_memory_mib": 8192,
            "storage_overhead_mib": 4096,
            "gpu_overhead_mib": 4096,
            "storage_disk_mib": 500_000,
            "storage_scratch_disk_mib": 20_000,
            "gpu_infra_disk_mib": 500_000,
            "gpu_scratch_disk_mib": 20_000,
            "disk_allocation_shortfall_mib": 1_020_000,
            "l0_reserved_vcpus": 4,
            "l0_reserved_memory_mib": 8192,
            "qemu_max_vcpus": 4096,
            "qemu_max_memory_mib": 8_000_000,
            "mmio64_aperture_mib": 3_000_000,
            "physical_address_bits": 46,
        },
        groups=[_group()],
    )


def test_exact_inventory_canonicalization_binds_every_topology_field():
    report = _report()
    assert report.groups[0].topology_fingerprint == canonical_sha256(
        report.groups[0].model_dump(mode="json", exclude={"topology_fingerprint"})
    )
    changed = _group()
    changed["devices"][0]["reset_domain"] = "sbr:0000:00:02.0"
    with pytest.raises(
        ValidationError,
        match="topology_fingerprint|not reciprocal",
    ):
        GpuInventoryGroupV1.model_validate(changed)

    disconnected = _group()
    disconnected["nvlink_edges"].pop()
    disconnected["topology_fingerprint"] = canonical_sha256(
        {key: value for key, value in disconnected.items() if key != "topology_fingerprint"}
    )
    with pytest.raises(ValidationError, match="complete and connected"):
        GpuInventoryGroupV1.model_validate(disconnected)

    unsafe = _group()
    unsafe["devices"][0]["reset_members"].append("0000:ff:00.0")
    unsafe["devices"][0]["reset_members"].sort()
    unsafe["topology_fingerprint"] = canonical_sha256(
        {key: value for key, value in unsafe.items() if key != "topology_fingerprint"}
    )
    with pytest.raises(ValidationError, match="unsafe"):
        GpuInventoryGroupV1.model_validate(unsafe)

    contradictory = _group()
    contradictory["devices"][1]["iommu_group"] = contradictory["devices"][0]["iommu_group"]
    contradictory["topology_fingerprint"] = canonical_sha256(
        {key: value for key, value in contradictory.items() if key != "topology_fingerprint"}
    )
    with pytest.raises(ValidationError, match="contradictory"):
        GpuInventoryGroupV1.model_validate(contradictory)

    arbitrary_fabric = _group()
    arbitrary_fabric["fabrics"][0]["fabric_id"] = "f" * 64
    arbitrary_fabric["topology_fingerprint"] = canonical_sha256(
        {key: value for key, value in arbitrary_fabric.items() if key != "topology_fingerprint"}
    )
    with pytest.raises(ValidationError, match="fabric_id"):
        GpuInventoryGroupV1.model_validate(arbitrary_fabric)


def test_inventory_profile_is_selected_only_from_signed_provenance():
    report = _report()
    provenance = _gpu_document()
    profile = _profile_for_report(report, provenance, "b200-8gpu")
    assert profile["id"] == "b200-8gpu"

    tampered = report.model_copy(
        update={
            "groups": [
                report.groups[0].model_copy(
                    update={"reported_profile_id": "b300-8gpu", "model": "B300"}
                )
            ]
        }
    )
    with pytest.raises(GpuAllocationError, match="B300"):
        _profile_for_report(tampered, provenance, "b300-8gpu")


def test_inventory_profile_is_bound_to_signed_l0_qemu_tdvf_closure():
    provenance = json.loads(
        (
            Path(__file__).resolve().parents[1] / "fixtures/gpu_provenance_v3_complete.json"
        ).read_text()
    )
    environment = provenance["launch_environments"][0]
    manifest = {
        "version": 2,
        "compute_type": "gpu",
        "gpu_profile_id": environment["profile_id"],
        "gpu_qemu_sha256s": [environment["qemu_binary_sha256"]],
        "gpu_tdvf_sha256s": [environment["firmware_sha256"]],
    }
    assert _l0_gpu_profile_id(manifest, provenance) == environment["profile_id"]

    wrong_profile = dict(manifest)
    wrong_profile["gpu_profile_id"] = provenance["launch_environments"][1]["profile_id"]
    with pytest.raises(GpuAllocationError, match="profile/QEMU/TDVF"):
        _l0_gpu_profile_id(wrong_profile, provenance)


def test_aggregate_resource_budget_includes_storage_and_l0_reserves():
    report = _report()
    provenance = _gpu_document()
    profile = provenance["profile_contract"]["profiles"][0]
    host = Host(
        host_id="gpu-host",
        name="gpu-host",
        miner_hotkey="owner",
        tee_type="tdx",
        compute_type="gpu",
        storage_requested=True,
        storage_enabled=True,
        storage_td_vcpus=2,
        storage_td_mem="8G",
    )
    _validate_resource_budget(host, report, profile)

    starved = report.model_copy(
        update={
            "resources": report.resources.model_copy(
                update={"memory_mib": profile["guest"]["memory_mib"]}
            )
        }
    )
    with pytest.raises(GpuAllocationError, match="RAM reserves"):
        _validate_resource_budget(host, starved, profile)


def _claims(mode="platform"):
    now = datetime.now(timezone.utc)
    result = {
        "reservation_id": "reservation",
        "token_id": "token",
        "owner_hotkey": "miner",
        "workload_owner": "user",
        "host_id": "gpu-host",
        "host_key_generation": 1,
        "host_boot_generation": 1,
        "management_mode": mode,
        "allocation_group_id": "group",
        "allocation_group_generation": 1,
        "reservation_generation": 1,
        "gpu_bdfs": BDFS,
        "gpu_uuids": sorted(UUIDS),
        "gpu_identifiers": ["b200"] * 8,
        "gpu_attestation_certificate_sha256s": [f"{index:064x}" for index in range(1, 9)],
        "topology_fingerprint": "1" * 64,
        "gpu_release_id": "release",
        "gpu_profile_id": "b200-8gpu",
        "profile_contract_sha256": "2" * 64,
        "measurement_name": f"gpu-baremetal-tdx-1.11.0-b200-8gpu-{mode}",
        "kernel_measurement_mode": "efi-image-as-is",
        "qemu_binary_sha256": "3" * 64,
        "qemu_package_version": "1:10.2.1+ds-1ubuntu4",
        "machine_type": "pc-q35-10.2",
        "tdvf_sha256": "4" * 64,
        "image_sha256": "5" * 64,
        "image_version": "1.11.0",
        "kernel_sha256": "6" * 64,
        "initrd_sha256": "7" * 64,
        "mode_cmdline_sha256": "8" * 64,
        "release_target_sha256": "a" * 64,
        "server_id": "gpu-server",
        "process_incarnation": "gpu-process",
        "miner_hourly_cost": 12.5 if mode == "miner" else None,
        "chute_id": "chute" if mode == "platform" else None,
        "container_repository": "org/image" if mode == "platform" else None,
        "container_manifest_digest": f"sha256:{'9' * 64}" if mode == "platform" else None,
        "launch_nonce": "bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4=",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=15),
    }
    if mode == "platform":
        result.pop("miner_hourly_cost")
        signature_tag = f"sha256-{'9' * 64}.sig"
        signature_digest = f"sha256:{'b' * 64}"
        closure = {
            "schema": "chutes.oci-descriptor-closure",
            "version": 1,
            "root_manifest": result["container_manifest_digest"],
            "manifests": [
                result["container_manifest_digest"],
                signature_digest,
            ],
            "blobs": [f"sha256:{'c' * 64}"],
            "manifest_tags": [signature_tag],
            "manifest_tag_digests": {
                signature_tag: signature_digest,
            },
        }
        result.update(
            descriptor_closure_sha256=canonical_sha256(closure),
            allowed_manifests=closure["manifests"],
            allowed_blobs=closure["blobs"],
            allowed_manifest_tags=closure["manifest_tags"],
            manifest_tag_digests=closure["manifest_tag_digests"],
        )
    return result


def test_gpu_claims_fail_closed_on_mode_device_and_profile_tamper():
    claims = GpuLaunchReservationClaimsV1(**_claims())
    assert claims.compute_type == "gpu"
    for field, value in (
        ("management_mode", "miner"),
        ("gpu_bdfs", BDFS[:-1]),
        ("profile_contract_sha256", "not-a-digest"),
    ):
        document = copy.deepcopy(_claims())
        document[field] = value
        with pytest.raises(ValidationError):
            GpuLaunchReservationClaimsV1(**document)


def test_platform_reservation_request_cannot_supply_owner_or_container_truth():
    common = {
        "server_id": "gpu-server",
        "process_incarnation": "gpu-process",
        "gpu_identifier": "b200",
        "gpu_count": 8,
        "minimum_vram_mib": 196608,
        "chute_id": "chute",
    }
    GpuPlatformReservationRequestV1(**common)
    with pytest.raises(ValidationError, match="Extra inputs"):
        GpuPlatformReservationRequestV1(
            **common,
            workload_owner="attacker",
            container_repository="attacker/image",
            container_manifest_digest=f"sha256:{'1' * 64}",
        )


def test_cross_repo_gpu_claim_fixture_is_exact_v1_contract():
    fixture = Path(__file__).resolve().parents[1] / "fixtures/gpu_launch_claims_v1.json"
    raw = json.loads(fixture.read_text())
    claims = GpuLaunchReservationClaimsV1.model_validate(raw)
    assert set(GpuLaunchReservationClaimsV1.model_fields) == {
        *raw,
        "legacy_vm_name",
        "legacy_migration_id",
        "miner_hourly_cost",
    }
    assert set(claims.model_dump(mode="json", exclude_none=True)) == set(raw)
    assert canonical_sha256(raw) == GPU_CLAIM_FIXTURE_SHA256
    assert claims.release_target_sha256 == "a" * 64
    assert claims.gpu_attestation_certificate_sha256s == ["1" * 64]


def test_same_sized_nvidia_evidence_from_another_group_fails():
    claims = GpuLaunchReservationClaimsV1.model_validate(_claims())
    result = NvidiaVerificationResultV1(
        schema="chutes.nvidia-verification-result",
        version=1,
        nonce="f" * 64,
        devices=[
            {
                "attestation_certificate_sha256": f"{index + 20:064x}",
                "evidence_sha256": f"{index + 40:064x}",
                "architecture": "BLACKWELL",
            }
            for index in range(8)
        ],
    )
    with pytest.raises(InvalidGpuEvidenceError, match="selected reservation devices"):
        _assert_reserved_nvidia_devices(claims, result)


@pytest.mark.asyncio
async def test_reservation_checks_full_storage_gate_before_group_locks():
    db = AsyncMock()
    host = Host(
        host_id="gpu-host",
        miner_hotkey="owner",
        compute_type="gpu",
        tee_type="tdx",
        provisioning_state="ready",
        identity_durable_at=datetime.now(timezone.utc),
        boot_generation=1,
    )
    request = GpuMinerReservationRequestV1(
        gpu_identifier="b200",
        gpu_count=8,
        minimum_vram_mib=1,
        miner_hourly_cost=12.5,
    )
    provenance = _gpu_document()
    environment = provenance["launch_environments"][0]
    release = SimpleNamespace(
        l0_manifest={
            "version": 2,
            "compute_type": "gpu",
            "gpu_profile_id": environment["profile_id"],
            "gpu_qemu_sha256s": [environment["qemu_binary_sha256"]],
            "gpu_tdvf_sha256s": [environment["firmware_sha256"]],
        }
    )
    with (
        patch(
            "api.host.gpu_allocations._host_lock",
            AsyncMock(return_value=host),
        ),
        patch(
            "api.host.gpu_allocations._active_gpu_release",
            AsyncMock(return_value=(release, {}, provenance)),
        ),
        patch(
            "api.host.reservations.observe_gpu_storage_liveness",
            AsyncMock(return_value=set()),
        ),
        patch(
            "api.host.reservations.gpu_host_storage_readiness",
            AsyncMock(
                return_value=SimpleNamespace(
                    trusted_storage_ready=False,
                    control_channel_eligible=False,
                    reason="storage_health_not_fresh",
                )
            ),
        ),
    ):
        with pytest.raises(GpuAllocationError, match="storage_health_not_fresh"):
            await reserve_gpu_group(db, "gpu-host", request)
    assert db.execute.await_count == 1
    assert "pg_advisory_xact_lock" in str(db.execute.await_args.args[0])


def test_physical_result_requires_absence_reset_and_driver_restore_together():
    common = {
        "operation_id": "operation",
        "allocation_group_id": "group",
        "allocation_group_generation": 1,
        "reservation_id": "reservation",
        "reservation_generation": 1,
        "claims_sha256": "1" * 64,
        "process_incarnation": "gpu-process",
        "gpu_bdfs": BDFS,
        "gpu_uuids": sorted(UUIDS),
        "topology_fingerprint": "2" * 64,
    }
    success = GpuPhysicalResultV1(
        **common,
        qemu_absent=True,
        reset_succeeded=True,
        original_drivers_restored=True,
    )
    assert success.reset_succeeded
    with pytest.raises(ValidationError, match="failure metadata"):
        GpuPhysicalResultV1(
            **common,
            qemu_absent=True,
            reset_succeeded=False,
            original_drivers_restored=False,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["leased", "promoted"])
async def test_failed_target_cutover_rebinds_same_migration_after_exact_reset(state):
    migration = SimpleNamespace(
        migration_id="migration-1",
        state=state,
        target_server_id="logical-server",
        legacy_server_id="legacy-server",
        legacy_vm_name="legacy-vm",
        owner_hotkey="owner",
        host_id="host-1",
        storage_generation=9,
        cache_generation=6,
    )
    values = [
        SimpleNamespace(
            migration_id="migration-1",
            state="sealed",
            reservation_id="prior",
        ),
        SimpleNamespace(
            gpu_retired_at=datetime.now(timezone.utc),
            gpu_runtime_session_attestation_id=None,
            gpu_runtime_session_expires_at=None,
        ),
        SimpleNamespace(gpu_retired_at=datetime.now(timezone.utc)),
        SimpleNamespace(
            reservation_id="prior",
            state="quarantined",
            failure_metadata={
                "qemu_absent": True,
                "reset_succeeded": True,
                "original_drivers_restored": True,
            },
        ),
        SimpleNamespace(
            physical_result={
                "qemu_absent": True,
                "reset_succeeded": True,
                "original_drivers_restored": True,
            },
            physical_result_sha256=canonical_sha256(
                {
                    "qemu_absent": True,
                    "reset_succeeded": True,
                    "original_drivers_restored": True,
                }
            ),
        ),
        SimpleNamespace(
            volume_passphrases={},
            volume_epochs={},
            volume_generation_leases={},
        ),
    ]

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def first(self):
            return self.value

    db = SimpleNamespace(execute=AsyncMock(side_effect=[Result(value) for value in values]))
    await _require_resumable_legacy_migration(
        db,
        migration,
        SimpleNamespace(host_id="host-1", miner_hotkey="owner"),
    )
    assert (migration.storage_generation, migration.cache_generation) == (9, 6)


@pytest.mark.asyncio
async def test_ready_cutover_uses_initial_target_without_resume_checks():
    db = SimpleNamespace(execute=AsyncMock())
    await _require_resumable_legacy_migration(
        db,
        SimpleNamespace(state="ready"),
        SimpleNamespace(),
    )
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_target_cutover_rejects_ambiguous_qemu_reset():
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="leased",
        target_server_id="logical-server",
        legacy_server_id="legacy-server",
        legacy_vm_name="legacy-vm",
        owner_hotkey="owner",
        host_id="host-1",
    )
    values = [
        SimpleNamespace(
            migration_id="migration-1",
            state="sealed",
            reservation_id="prior",
        ),
        SimpleNamespace(
            gpu_retired_at=datetime.now(timezone.utc),
            gpu_runtime_session_attestation_id=None,
            gpu_runtime_session_expires_at=None,
        ),
        SimpleNamespace(gpu_retired_at=datetime.now(timezone.utc)),
        SimpleNamespace(
            reservation_id="prior",
            state="quarantined",
            failure_metadata={"qemu_absent": False},
        ),
        SimpleNamespace(
            physical_result={
                "qemu_absent": False,
                "reset_succeeded": True,
                "original_drivers_restored": True,
            },
            physical_result_sha256=canonical_sha256(
                {
                    "qemu_absent": False,
                    "reset_succeeded": True,
                    "original_drivers_restored": True,
                }
            ),
        ),
        SimpleNamespace(
            volume_passphrases={},
            volume_epochs={},
            volume_generation_leases={},
        ),
    ]

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def first(self):
            return self.value

    db = SimpleNamespace(execute=AsyncMock(side_effect=[Result(value) for value in values]))
    with pytest.raises(GpuAllocationError, match="not exact"):
        await _require_resumable_legacy_migration(
            db,
            migration,
            SimpleNamespace(host_id="host-1", miner_hotkey="owner"),
        )


@pytest.mark.asyncio
async def test_recovery_dispatch_commits_before_guard_and_reuses_operation_id(
    monkeypatch,
):
    calls = []

    class Db:
        def __init__(self):
            self.info = {}

        async def commit(self):
            calls.append("commit")
            self.info.clear()

        async def rollback(self):
            calls.append("rollback")

    db = Db()
    operation = GpuLifecycleOperationV1(
        operation_id="10000000-0000-4000-8000-000000000005",
        operation_type="ownerless_group_recovery",
        phase="intent",
        host_id="host-1",
        host_key_generation=2,
        host_boot_generation=3,
        allocation_group_id="group-1",
        allocation_group_generation=4,
        topology_fingerprint="a" * 64,
        gpu_bdfs=["0000:01:00.0"],
        gpu_uuids=["GPU-00000000-0000-0000-0000-000000000001"],
        owner_hotkey="owner-1",
        recovery_authorization_id="authorization-1",
    )
    envelope = GpuRecoveryAuthorizationEnvelopeV1(
        authorization_id="authorization-1",
        operation=operation,
        inventory_report_id="report-1",
        inventory_report_sha256="b" * 64,
        recovery_nonce="c" * 64,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    async def authorize(current_db, *_args, **_kwargs):
        assert current_db is db
        current_db.info["gpu_lifecycle_lock_held"] = True
        calls.append("authorize")
        return envelope

    async def send(host_id, command, payload, *, command_id=None):
        assert not db.info.get("gpu_lifecycle_lock_held")
        calls.append(("send", host_id, command, command_id, payload))
        return command_id

    monkeypatch.setattr(host_router, "authorize_gpu_recovery", authorize)
    monkeypatch.setattr(host_router, "send_agent_command", send)
    user = SimpleNamespace(user_id="admin-1", has_role=lambda _role: True)

    result = await host_router.authorize_gpu_group_recovery_endpoint(
        "group-1",
        SimpleNamespace(report_id="report-1", reason="focused test"),
        db=db,
        current_user=user,
    )

    assert result is envelope
    assert calls[:2] == ["authorize", "commit"]
    assert calls[2][0:4] == (
        "send",
        "host-1",
        "recover_gpu_group",
        operation.operation_id,
    )
    payload = calls[2][4]
    assert payload["authorization"] == gpu_recovery_authorization_document(envelope)
    assert payload["lifecycle_operation"] is payload["authorization"]["operation"]
    assert not {
        "reservation_id",
        "reservation_generation",
        "claims_sha256",
        "process_incarnation",
        "stable_server_id",
        "management_mode",
        "migration_id",
    }.intersection(payload["lifecycle_operation"])
