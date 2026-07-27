"""Real-Postgres GPU allocation races, replay fencing, expiry, and reset."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import subprocess
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
import pytest_asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.requests import Request
from api.database import Base
from api.config import TeeMeasurementConfig
from api.host import gpu_allocations
from api.host.locks import acquire_gpu_lifecycle_lock
from api.gpu_contracts import (
    GpuLocalReleaseAckV1,
    GpuPhysicalResultV1,
    GpuRegistrationRequestV2,
    GpuResetReceiptV1,
    GpuSourceReaderResultV1,
)
from api.gpu_lifecycle_service import (
    GpuLifecycleError,
    authorize_gpu_recovery,
    ensure_reservation_lifecycle_operation,
    get_gpu_lifecycle_operation,
    record_gpu_local_release_ack,
    record_gpu_physical_result,
    start_gpu_recovery,
)
from api.gpu_models import (
    GpuHotplugCommand,
    GpuLifecycleOperation,
    GpuRecoveryAuthorization,
    GpuRecoveryEvent,
    GpuRegistrationAttempt,
    GpuRegistrationConflict,
    GpuRegistrationNonce,
)
from api.gpu_hotplug_service import (
    GpuHotplugGoneError,
    _new_command,
    dispatch_gpu_hotplug_command,
    get_gpu_hotplug_command,
)
from api.gpu_registration_service import (
    _claim_attempt,
    _complete_attempt,
    _registration_request_audit,
    _verify_recorded_conflict,
    cleanup_expired_gpu_registration_nonces,
    process_gpu_registration,
    registration_attempt_response,
)
from api.host.gpu_allocations import (
    GpuAllocationError,
    _active_gpu_release,
    _expire_locked_reservations,
    _host_lock,
    advance_gpu_host_boot,
    claim_gpu_reservation,
    fence_gpu_host_authority,
    mark_gpu_launching,
    quarantine_gpu_reservation_control_plane,
    record_gpu_command_ack,
    record_gpu_command_dispatch,
    reserve_gpu_group,
)
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    EnrollmentKeyChallengeRequestV2,
    EnrollmentVoucherMintRequestV2,
    GpuMinerReservationRequestV1,
    GpuPlatformReservationRequestV1,
    HostEnrollmentRedemptionV2,
    HostKeyGeneration,
    GpuReservationClaimRequestV1,
    GpuReservationStateRequestV1,
    canonical_sha256,
    GpuQuoteCommitmentV1,
    GpuRecoveryAuthorizeRequestV1,
)
from api.releases.provenance import (
    canonical_provenance_bytes,
    gpu_measurement_fingerprint,
)
from api.releases import service as release_service
from api.releases.schemas import GuestRelease
from api.host.service import (
    HostAuthError,
    create_enrollment_key_challenge,
    mint_enrollment_voucher,
    redeem_enrollment_voucher,
    revoke_host_credentials,
)
from api.node.schemas import Node
from api.server.exceptions import InvalidGpuEvidenceError, InvalidQuoteError
from api.server.gpu_sessions import (
    latest_gpu_runtime_session,
    validate_gpu_runtime_session,
)
from api.server.schemas import Host, NvidiaVerificationResultV1
from api.server.service import (
    _validate_runtime_gpu_selection,
    process_runtime_attestation,
)
from api.server.schemas import (
    DefaultChuteFSVolumeBinding,
    GpuInfraCustody,
    GpuLegacyCloseRequestV1,
    GpuLegacyMigration,
    GpuMinerIdentity,
    Server,
    ServerAttestation,
    RuntimeAttestationArgs,
    RuntimeAttestationNonceContext,
    StorageVolume,
    StorageVolumeKey,
    VmCacheConfig,
)
from api.server.gpu_infra import close_legacy_gpu_sources
from api.server.gpu_infra import (
    _capability_hash,
    _migration_capability,
    acknowledge_gpu_infra,
    authorize_legacy_gpu_cutover,
    complete_gpu_infra_migration,
    confirm_legacy_sources_unowned,
    confirm_gpu_infra,
    lease_gpu_infra,
)
from api.storage import launch_sessions
from api.server.schemas import (
    GpuInfraAcknowledgeRequestV1,
    GpuInfraConfirmRequestV1,
    GpuInfraLeaseRequestV1,
    GpuInfraMigrationCompleteRequestV1,
    GpuLegacyHostConfirmRequestV1,
    GpuLegacyCutoverAuthorizeRequestV1,
)
from api.server.util import decrypt_passphrase, encrypt_passphrase
from api.user.schemas import User
from api.image.schemas import Image
from api.chute.schemas import Chute, NodeSelector
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import load_launch_config_from_jwt
from api.metagraph import MetagraphNode
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from tests.unit.test_release_provenance import _gpu_document

import api.database.orms  # noqa: F401, E402
from api import gpu_scheduler

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real GPU allocation tests",
    ),
]

UUIDS = [f"GPU-00000000-0000-0000-0000-{index:012x}" for index in range(1, 9)]
BDFS = [f"0000:{index:02x}:00.0" for index in range(1, 9)]


def _inventory_group():
    devices = [
        {
            "bdf": bdf,
            "uuid": gpu_uuid,
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
        for index, (bdf, gpu_uuid) in enumerate(zip(BDFS, UUIDS, strict=True), start=1)
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
            {"source_uuid": source, "target_uuid": target, "link_count": 18}
            for index, source in enumerate(sorted(UUIDS))
            for target in sorted(UUIDS)[index + 1 :]
        ],
        "fabrics": [
            {"fabric_id": canonical_sha256(fabric_identity), **fabric_identity}
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
        groups=[_inventory_group()],
    )


def _current_host_report(host: Host, report_id: str) -> GpuInventoryReportV1:
    return _report().model_copy(
        update={
            "report_id": report_id,
            "report_generation": int(host.gpu_inventory_report_generation or 0) + 1,
            "host_key_generation": host.active_key_generation,
            "host_boot_id": host.boot_id,
            "host_boot_generation": host.boot_generation,
            "observed_at": datetime.now(timezone.utc),
        }
    )


@pytest.fixture(autouse=True)
def nv_attest():
    """Allocation state-machine tests do not invoke runtime GPU evidence."""
    yield


@pytest_asyncio.fixture
async def postgres_schema():
    schema = f"gpu_allocation_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        connect_args={"server_settings": {"search_path": schema}},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield sessionmaker(engine, class_=AsyncSession, expire_on_commit=False), schema
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def _apply_migration(
    schema: str,
    direction: str,
    migration_name: str = "20260723050000_gpu_allocation_groups.sql",
) -> None:
    migration = Path(__file__).resolve().parents[2] / "api/migrations" / migration_name
    up_sql, down_sql = migration.read_text().split("-- migrate:down", 1)
    sql = up_sql if direction == "up" else f"BEGIN;\n{down_sql}\nCOMMIT;"
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    connection_url = (
        f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    )
    process = await asyncio.create_subprocess_exec(
        "psql",
        connection_url,
        "-v",
        "ON_ERROR_STOP=1",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "PGPASSWORD": parsed.password or "",
            "PGOPTIONS": f"-c search_path={schema}",
        },
    )
    stdout, stderr = await process.communicate(sql.encode())
    assert process.returncode == 0, (stdout + stderr).decode(errors="replace")


@pytest.fixture(autouse=True)
def unsigned_debug_provenance():
    document = _gpu_document()
    names = [entry["name"] for entry in document["measurements"]]
    profile = document["profile_contract"]["profiles"][0]
    pins = []
    for entry in document["measurements"]:
        values = entry["values"]
        pins.append(
            TeeMeasurementConfig(
                version=document["version"],
                name=entry["name"],
                tee_type="tdx",
                provider="bare-metal",
                debug=True,
                mrtd=values["mrtd"],
                rtmr0=values["runtime_rtmrs"]["RTMR0"],
                rtmr1=values["runtime_rtmrs"]["RTMR1"],
                rtmr2=values["runtime_rtmrs"]["RTMR2"],
                boot_rtmr3=values["boot_rtmrs"]["RTMR3"],
                runtime_rtmr3=values["runtime_rtmrs"]["RTMR3"],
                expected_gpus=profile["expected_gpu_identifiers"],
                gpu_count=profile["gpu_count"],
                image_sha256=document["image"]["sha256"],
                image_measurement_names=names,
                compute_type="gpu",
                role="gpu",
                management_mode=entry["management_mode"],
                gpu_profile_id=entry["profile_id"],
                gpu_profile_contract_sha256=document["profile_contract_sha256"],
                gpu_measurement_fingerprint=gpu_measurement_fingerprint(
                    document, entry
                ),
                gpu_fingerprint_version=1,
                provenance_schema_version=3,
            )
        )
    configured = SimpleNamespace(
        allow_debug_measurements=True,
        skip_metagraph_check=True,
        tee_measurements=pins,
    )
    ready_storage = SimpleNamespace(
        trusted_storage_ready=True,
        control_channel_eligible=True,
        reason="storage_ready",
    )
    with (
        patch.object(release_service, "settings", configured),
        patch.object(
            release_service,
            "_configured_gpu_launch_signer_identity",
            return_value=(
                document["launch_public_key_id"],
                document["launch_public_key_epoch"],
            ),
        ),
        patch.object(release_service, "_validate_active_release", return_value=None),
        patch(
            "api.host.reservations.gpu_host_storage_readiness",
            AsyncMock(return_value=ready_storage),
        ),
    ):
        yield


async def _seed(sessions):
    provenance = _gpu_document()
    provenance["image"]["filename"] = "1.11.0-debug.qcow2"
    provenance["build_flags"] = {"debug_build": True, "debug_logging": False}
    payload = canonical_provenance_bytes(provenance).decode()
    image = {
        "url": "https://artifacts.chutes.ai/gpu/1.11.0-debug.qcow2",
        "sha256": provenance["image"]["sha256"],
        "debug": True,
        "version": provenance["version"],
        "measurement_names": [item["name"] for item in provenance["measurements"]],
        "kernel_sha256": provenance["artifacts"]["kernel_sha256"],
        "initrd_sha256": provenance["artifacts"]["initrd_sha256"],
        "cmdline_sha256": provenance["artifacts"]["cmdline_sha256"],
        "provenance_payload": payload,
        "provenance_signature": None,
    }
    now = datetime.now(timezone.utc)
    environment = provenance["launch_environments"][0]
    release = GuestRelease(
        release_id="gpu-release",
        channel="gpu-test",
        tee_type="tdx",
        compute_type="gpu",
        status="active",
        images={"gpu": image},
        l0_manifest={
            "version": 2,
            "l0_version": "l0-gpu-test",
            "compute_type": "gpu",
            "gpu_profile_id": "b200-8gpu",
            "gpu_qemu_sha256s": [environment["qemu_binary_sha256"]],
            "gpu_tdvf_sha256s": [environment["firmware_sha256"]],
        },
        l0_manifest_digest="a" * 64,
        l0_manifest_generation=1,
        l0_manifest_key_id="test-key",
        l0_manifest_key_epoch=1,
    )
    host = Host(
        host_id="gpu-host",
        name="gpu-host",
        miner_hotkey="owner",
        tee_type="tdx",
        compute_type="gpu",
        capacity=0,
        reported_capacity=1,
        storage_enabled=True,
        storage_td_vcpus=2,
        storage_td_mem="8G",
        release_channel="gpu-test",
        provisioning_state="ready",
        enrollment_generation=1,
        active_key_generation=1,
        enrolled_at=now,
        identity_durable_at=now,
        identity_metadata_sha256="a" * 64,
        steady_config_sha256="b" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        boot_generation=1,
        gpu_inventory_report_generation=1,
        gpu_inventory_fingerprint="c" * 64,
        gpu_inventory_reconciled_at=now,
        l0_version="l0-gpu-test",
        last_accepted_manifest_generation=1,
    )
    report_claims = _report()
    reported_group = report_claims.groups[0]
    report = GpuInventoryReport(
        report_id=report_claims.report_id,
        host_id=host.host_id,
        host_key_generation=report_claims.host_key_generation,
        host_boot_generation=report_claims.host_boot_generation,
        report_generation=report_claims.report_generation,
        gpu_release_id=release.release_id,
        profile_contract_sha256=provenance["profile_contract_sha256"],
        topology_fingerprint=reported_group.topology_fingerprint,
        claims=report_claims.model_dump(mode="json"),
        claims_sha256=canonical_sha256(report_claims),
        reconciliation_status="accepted",
        accepted_at=now,
    )
    host_key = HostKeyGeneration(
        host_id=host.host_id,
        generation=1,
        enrollment_generation=1,
        ed25519_public_key="test-ed25519",
        ed25519_fingerprint="e" * 64,
        x25519_public_key="test-x25519",
        x25519_fingerprint="f" * 64,
    )
    metagraph = MetagraphNode(
        hotkey="owner",
        netuid=64,
        checksum="test",
        coldkey="owner",
        node_id=1,
    )
    group_values = gpu_allocations._group_values(
        report_claims,
        provenance["profile_contract"]["profiles"][0],
    )
    group = GpuAllocationGroup(
        allocation_group_id="allocation-group",
        host_id=host.host_id,
        host_key_generation=1,
        host_boot_generation=1,
        generation=1,
        gpu_release_id=release.release_id,
        state="available",
        reservation_generation=0,
        last_report_id=report.report_id,
        available_at=now,
        last_seen_at=now,
        updated_at=now,
        **group_values,
    )
    async with sessions() as session:
        session.add_all([release, host, metagraph])
        await session.flush()
        session.add(host_key)
        await session.flush()
        session.add(report)
        await session.flush()
        session.add(group)
        await session.commit()


def _request(_server_id="gpu-server", _process="gpu-process"):
    return GpuMinerReservationRequestV1(
        gpu_identifier="b200",
        gpu_count=8,
        minimum_vram_mib=196608,
        miner_hourly_cost=12.5,
    )


def _trusted_platform_workload(owner: str = "platform-workload-owner"):
    root_manifest = f"sha256:{'9' * 64}"
    manifests = [root_manifest, f"sha256:{'8' * 64}"]
    blobs = [f"sha256:{'7' * 64}"]
    tags = [f"sha256-{'9' * 64}.sig"]
    tag_digests = {tags[0]: manifests[1]}
    closure = {
        "schema": "chutes.oci-descriptor-closure",
        "version": 1,
        "root_manifest": root_manifest,
        "manifests": manifests,
        "blobs": blobs,
        "manifest_tags": tags,
        "manifest_tag_digests": tag_digests,
    }
    return (
        owner,
        "1",
        f"{owner}/image",
        root_manifest,
        {
            "descriptor_closure_sha256": canonical_sha256(closure),
            "allowed_manifests": manifests,
            "allowed_blobs": blobs,
            "allowed_manifest_tags": tags,
            "manifest_tag_digests": tag_digests,
        },
    )


async def _reserve_platform_group(
    session,
    *,
    owner: str = "platform-workload-owner",
    server_id: str = "platform-server",
):
    with patch(
        "api.host.gpu_allocations._assert_platform_workload_current",
        AsyncMock(return_value=None),
    ):
        return await reserve_gpu_group(
            session,
            "gpu-host",
            GpuPlatformReservationRequestV1(
                server_id=server_id,
                process_incarnation=f"{server_id}-process",
                gpu_identifier="b200",
                gpu_count=8,
                minimum_vram_mib=196608,
                chute_id="platform-chute",
            ),
            trusted_platform_workload=_trusted_platform_workload(owner),
        )


async def test_gpu_allocation_migration_round_trip(postgres_schema):
    sessions, schema = postgres_schema
    await _apply_migration(
        schema,
        "down",
        "20260725120000_gpu_lifecycle_durability.sql",
    )
    await _apply_migration(
        schema,
        "down",
        "20260724110000_gpu_miner_infra_custody.sql",
    )
    await _apply_migration(
        schema,
        "down",
        "20260724100000_gpu_platform_scheduler.sql",
    )
    await _apply_migration(schema, "down")
    await _apply_migration(
        schema,
        "down",
        "20260723040000_gpu_l0_storage_sibling.sql",
    )
    await _apply_migration(
        schema,
        "down",
        "20260723030000_gpu_release_compute_type.sql",
    )
    await _apply_migration(
        schema,
        "up",
        "20260723030000_gpu_release_compute_type.sql",
    )
    await _apply_migration(
        schema,
        "up",
        "20260723040000_gpu_l0_storage_sibling.sql",
    )
    await _apply_migration(schema, "up")
    await _apply_migration(
        schema,
        "up",
        "20260724100000_gpu_platform_scheduler.sql",
    )
    await _apply_migration(
        schema,
        "up",
        "20260724110000_gpu_miner_infra_custody.sql",
    )
    await _apply_migration(
        schema,
        "up",
        "20260725120000_gpu_lifecycle_durability.sql",
    )
    async with sessions() as session:
        columns = set(
            (
                await session.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = :schema "
                        "AND table_name = 'server_attestations'"
                    ),
                    {"schema": schema},
                )
            )
            .scalars()
            .all()
        )
        assert columns == {
            column.name for column in ServerAttestation.__table__.columns
        }
        assert "gpu_retired_at" in columns


async def test_concurrent_double_reservation_has_one_winner(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)

    async def attempt(server_id):
        async with sessions() as session:
            try:
                response = await reserve_gpu_group(
                    session, "gpu-host", _request(server_id, server_id)
                )
                await session.commit()
                return response
            except GpuAllocationError:
                await session.rollback()
                return None

    results = await asyncio.gather(attempt("gpu-a"), attempt("gpu-b"))
    assert sum(item is not None for item in results) == 1
    async with sessions() as session:
        groups = (await session.execute(select(GpuAllocationGroup))).scalars().all()
        identities = (await session.execute(select(GpuMinerIdentity))).scalars().all()
        assert len(groups) == 1
        assert len(identities) == 1
        winner = next(item for item in results if item is not None)
        assert winner.claims.server_id == identities[0].server_id
        assert winner.claims.server_id.startswith("gpu-miner-")
        assert groups[0].state == "reserved"


async def test_two_legacy_namespaces_move_atomically_after_attested_close(
    postgres_schema,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    monkeypatch.setattr(
        "api.server.util.settings.fernet_key",
        Fernet(Fernet.generate_key()),
    )
    await _seed(sessions)
    now = datetime.now(timezone.utc)
    async with sessions() as session:
        legacy_server = Server(
            server_id="legacy-server-id",
            netuid=64,
            name="legacy-gpu-server",
            ip="192.0.2.40",
            miner_hotkey="owner",
            is_tee=True,
            self_registered=True,
            compute_type="gpu",
            tee_type="tdx",
            host_id="gpu-host",
            storage_role=False,
            version="1.10.0",
            attested_cert_pubkey_hash="e" * 64,
            measurement_name="legacy-gpu",
            measurement_config_fingerprint="a" * 64,
            trust_set_fingerprint="b" * 64,
            attestation_revocation_status={},
        )
        session.add(legacy_server)
        await session.flush()
        attestation = ServerAttestation(
            quote_data="quote",
            server_id=legacy_server.server_id,
            created_at=now,
            verified_at=now,
            measurement_version=legacy_server.version,
            measurement_name=legacy_server.measurement_name,
            measurement_config_fingerprint=(
                legacy_server.measurement_config_fingerprint
            ),
            trust_set_fingerprint=legacy_server.trust_set_fingerprint,
            revocation_status={},
        )
        session.add(attestation)
        session.add(
            VmCacheConfig(
                miner_hotkey="owner",
                vm_name="legacy-gpu-server",
                volume_passphrases={
                    "storage": "storage-current",
                    "pending_storage": "storage-pending",
                    "tdx-cache": "cache-current",
                    "pending_tdx-cache": "cache-pending",
                    "unrelated": "keep",
                },
                volume_epochs={"storage": 9, "tdx-cache": 6, "unrelated": 1},
                volume_generation_leases={
                    "storage": {
                        "generation": 10,
                        "lease_id": "s" * 32,
                        "server_id": legacy_server.server_id,
                        "miner_hotkey": legacy_server.miner_hotkey,
                        "vm_name": legacy_server.name,
                        "cert_hash": legacy_server.attested_cert_pubkey_hash,
                        "measurement_name": legacy_server.measurement_name,
                        "measurement_version": legacy_server.version,
                        "measurement_config_fingerprint": (
                            legacy_server.measurement_config_fingerprint
                        ),
                        "trust_set_fingerprint": legacy_server.trust_set_fingerprint,
                        "tee_type": "tdx",
                        "purpose": "boot_luks",
                        "storage_role": False,
                        "promotion_required": True,
                    },
                    "tdx-cache": {
                        "generation": 7,
                        "lease_id": "c" * 32,
                        "server_id": legacy_server.server_id,
                        "miner_hotkey": legacy_server.miner_hotkey,
                        "vm_name": legacy_server.name,
                        "cert_hash": legacy_server.attested_cert_pubkey_hash,
                        "measurement_name": legacy_server.measurement_name,
                        "measurement_version": legacy_server.version,
                        "measurement_config_fingerprint": (
                            legacy_server.measurement_config_fingerprint
                        ),
                        "trust_set_fingerprint": legacy_server.trust_set_fingerprint,
                        "tee_type": "tdx",
                        "purpose": "boot_luks",
                        "storage_role": False,
                        "promotion_required": True,
                    },
                },
                k3s_encryption_key="encrypted-k3s",
            )
        )
        await session.flush()
        monkeypatch.setattr(
            "api.server.gpu_infra._latest_attestation_attempt",
            AsyncMock(return_value=attestation),
        )
        cutover = await authorize_legacy_gpu_cutover(
            session,
            "gpu-host",
            "owner",
            GpuLegacyCutoverAuthorizeRequestV1(
                legacy_server_id=legacy_server.server_id,
            ),
        )
        close_request = GpuLegacyCloseRequestV1(
            cutover_authorization=cutover.cutover_authorization,
            target_host_id="gpu-host",
            storage_luks_uuid="00000000-0000-0000-0000-000000000001",
            storage_filesystem_uuid="00000000-0000-0000-0000-000000000002",
            storage_generation=9,
            cache_luks_uuid="00000000-0000-0000-0000-000000000003",
            cache_filesystem_uuid="00000000-0000-0000-0000-000000000004",
            cache_filesystem_type="xfs",
            cache_generation=6,
            postgres_password="stable-postgres-password",
            workloads_stopped=True,
            postgres_stopped=True,
            filesystems_synced=True,
            filesystems_unmounted=True,
            storage_mapper_closed=True,
            cache_mapper_closed=True,
        )
        result = await close_legacy_gpu_sources(
            session,
            legacy_server.server_id,
            "e" * 64,
            close_request,
        )
        await session.commit()

    async with sessions() as session:
        retry = await close_legacy_gpu_sources(
            session,
            "legacy-server-id",
            "e" * 64,
            close_request,
        )
        assert retry.migration_id == result.migration_id
        with pytest.raises(HTTPException):
            await authorize_legacy_gpu_cutover(
                session,
                "gpu-host",
                "owner",
                GpuLegacyCutoverAuthorizeRequestV1(
                    legacy_server_id="legacy-server-id",
                ),
            )
        moved = await session.get(GpuLegacyMigration, result.migration_id)
        legacy = await session.get(
            VmCacheConfig,
            ("owner", "legacy-gpu-server"),
        )
        assert moved.state == "guest_closed"
        assert moved.storage_generation == 9
        assert moved.cache_generation == 6
        assert moved.storage_current_passphrase == "storage-current"
        assert moved.storage_pending_passphrase == "storage-pending"
        assert moved.cache_current_passphrase == "cache-current"
        assert moved.cache_pending_passphrase == "cache-pending"
        assert moved.k3s_encryption_key == "encrypted-k3s"
        assert decrypt_passphrase(moved.postgres_password) == "stable-postgres-password"
        assert legacy.volume_passphrases == {"unrelated": "keep"}
        assert legacy.volume_epochs == {"unrelated": 1}
        assert legacy.volume_generation_leases == {}
        assert legacy.k3s_encryption_key is None
        retired = await session.get(Server, "legacy-server-id")
        assert retired.gpu_retired_at is not None

        host = await session.get(Host, "gpu-host")
        await confirm_legacy_sources_unowned(
            session,
            host,
            moved.migration_id,
            GpuLegacyHostConfirmRequestV1(
                old_qemu_absent=True,
                storage_source_unowned=True,
                cache_source_unowned=True,
                storage_luks_uuid=moved.storage_luks_uuid,
                cache_luks_uuid=moved.cache_luks_uuid,
            ),
        )
        await session.commit()

    async with sessions() as session:
        reservation_response = await reserve_gpu_group(
            session,
            "gpu-host",
            GpuMinerReservationRequestV1(
                gpu_identifier="b200",
                gpu_count=8,
                minimum_vram_mib=196608,
                miner_hourly_cost=12.5,
                legacy_vm_name="legacy-gpu-server",
            ),
        )
        claims = reservation_response.claims
        server = Server(
            server_id=claims.server_id,
            netuid=64,
            name=claims.server_id,
            ip="192.0.2.44",
            miner_hotkey=claims.owner_hotkey,
            is_tee=True,
            self_registered=True,
            compute_type="gpu",
            tee_type="tdx",
            host_id=claims.host_id,
            storage_role=False,
            gpu_launch_reservation_id=claims.reservation_id,
            gpu_allocation_group_id=claims.allocation_group_id,
            gpu_allocation_group_generation=claims.allocation_group_generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=claims.process_incarnation,
            gpu_topology_fingerprint=claims.topology_fingerprint,
        )
        session.add(server)
        await session.flush()
        custody = GpuInfraCustody(
            server_id=claims.server_id,
            owner_hotkey=claims.owner_hotkey,
            host_id=claims.host_id,
            host_boot_generation=claims.host_boot_generation,
            reservation_id=claims.reservation_id,
            reservation_generation=claims.reservation_generation,
            allocation_group_id=claims.allocation_group_id,
            allocation_group_generation=claims.allocation_group_generation,
            management_mode="miner",
            volume_name="gpu-infra",
            k3s_encryption_key=encrypt_passphrase("k3s-key"),
            confirmed_generation=10,
            state="current",
            migration_id=claims.legacy_migration_id,
        )
        session.add(custody)
        migration = await session.get(
            GpuLegacyMigration,
            claims.legacy_migration_id,
        )
        capability = _migration_capability(migration.migration_id)
        migration.source_capability_hash = _capability_hash(capability)
        migration.source_capability_expires_at = now + timedelta(minutes=15)
        migration.source_capability_consumed_at = None
        migration.promoted_marker_sha256 = "f" * 64
        migration.promoted_summary = {"entries": {}}
        migration.promoted_at = now
        migration.state = "promoted"
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            claims.reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            claims.allocation_group_id,
        )
        host = await session.get(Host, claims.host_id)
        await session.flush()

        async def locked_lineage(*_args, **_kwargs):
            return server, reservation, group, host

        with patch(
            "api.server.gpu_infra._locked_current_lineage",
            side_effect=locked_lineage,
        ):
            await complete_gpu_infra_migration(
                session,
                server,
                {},
                "e" * 64,
                GpuInfraMigrationCompleteRequestV1(
                    migration_id=migration.migration_id,
                    capability=capability,
                    marker_sha256="f" * 64,
                    storage_discarded=True,
                    cache_discarded=True,
                ),
            )
        await session.commit()

    async with sessions() as session:
        identity = await session.get(GpuMinerIdentity, "gpu-host")
        migration = await session.get(
            GpuLegacyMigration,
            claims.legacy_migration_id,
        )
        custody = await session.get(GpuInfraCustody, claims.server_id)
        assert identity.legacy_vm_name is None
        assert migration.state == "completed"
        assert migration.storage_current_passphrase is None
        assert migration.storage_lease is None
        assert migration.cache_current_passphrase is None
        assert migration.cache_lease is None
        assert migration.k3s_encryption_key is None
        assert migration.postgres_password is None
        assert migration.source_capability_hash is None
        assert custody.migration_id is None


async def test_concurrent_gpu_infra_lease_reuses_one_generation_and_key(
    postgres_schema,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    monkeypatch.setattr(
        "api.server.util.settings.fernet_key",
        Fernet(Fernet.generate_key()),
    )
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        claims = response.claims
        now = datetime.now(timezone.utc)
        server = Server(
            server_id=claims.server_id,
            netuid=64,
            name=claims.server_id,
            ip="192.0.2.41",
            miner_hotkey=claims.owner_hotkey,
            is_tee=True,
            self_registered=True,
            compute_type="gpu",
            tee_type="tdx",
            host_id=claims.host_id,
            storage_role=False,
            gpu_launch_reservation_id=claims.reservation_id,
            gpu_allocation_group_id=claims.allocation_group_id,
            gpu_allocation_group_generation=claims.allocation_group_generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=claims.process_incarnation,
            gpu_topology_fingerprint=claims.topology_fingerprint,
            attested_cert_pubkey_hash="e" * 64,
        )
        session.add(server)
        await session.flush()
        attestation = ServerAttestation(
            quote_data="quote",
            server_id=claims.server_id,
            created_at=now,
            verified_at=now,
            measurement_version=claims.image_version,
            measurement_name=claims.measurement_name,
            measurement_config_fingerprint="a" * 64,
            trust_set_fingerprint="b" * 64,
            revocation_status={},
            gpu_launch_reservation_id=claims.reservation_id,
            gpu_allocation_group_id=claims.allocation_group_id,
            gpu_allocation_group_generation=claims.allocation_group_generation,
            gpu_host_boot_generation=claims.host_boot_generation,
            gpu_reservation_generation=claims.reservation_generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=claims.process_incarnation,
            gpu_topology_fingerprint=claims.topology_fingerprint,
            gpu_release_id=claims.gpu_release_id,
            gpu_profile_id=claims.gpu_profile_id,
            gpu_claims_sha256=response.claims_sha256,
            gpu_evidence={"raw": []},
            gpu_evidence_sha256="c" * 64,
            gpu_evidence_certificate_sha256s=(
                claims.gpu_attestation_certificate_sha256s
            ),
        )
        session.add(attestation)
        await session.flush()
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, claims.allocation_group_id)
        reservation.state = "running"
        reservation.guest_consumed_at = now
        reservation.running_at = now
        reservation.registration_attestation_id = attestation.attestation_id
        group.state = "running"
        group.management_mode = "miner"
        group.reservation_owner = claims.owner_hotkey
        group.reservation_id = claims.reservation_id
        group.process_incarnation = claims.process_incarnation
        group.running_at = now
        server.gpu_runtime_session_attestation_id = attestation.attestation_id
        server.gpu_runtime_session_expires_at = now + timedelta(minutes=15)
        await session.commit()

    async def locked_lineage(db, *_args):
        await acquire_gpu_lifecycle_lock(db)
        server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == claims.server_id)
                .with_for_update()
            )
        ).scalar_one()
        reservation = (
            await db.execute(
                select(gpu_allocations.GpuLaunchReservation)
                .where(
                    gpu_allocations.GpuLaunchReservation.reservation_id
                    == claims.reservation_id
                )
                .with_for_update()
            )
        ).scalar_one()
        group = (
            await db.execute(
                select(GpuAllocationGroup)
                .where(
                    GpuAllocationGroup.allocation_group_id == claims.allocation_group_id
                )
                .with_for_update()
            )
        ).scalar_one()
        host = (
            await db.execute(
                select(Host).where(Host.host_id == claims.host_id).with_for_update()
            )
        ).scalar_one()
        return server, reservation, group, host

    async def attempt(jti):
        async with sessions() as session:
            runtime = await session.get(Server, claims.server_id)
            result = await lease_gpu_infra(
                session,
                runtime,
                {
                    "server_id": claims.server_id,
                    "owner_hotkey": claims.owner_hotkey,
                    "reservation_id": claims.reservation_id,
                    "attestation_id": runtime.gpu_runtime_session_attestation_id,
                    "management_mode": "miner",
                    "attested_spki_sha256": "e" * 64,
                    "jti": jti,
                },
                "e" * 64,
                GpuInfraLeaseRequestV1(),
            )
            await session.commit()
            return result

    with patch(
        "api.server.gpu_infra._locked_current_lineage",
        side_effect=locked_lineage,
    ):
        first, second = await asyncio.gather(attempt("session-a"), attempt("session-b"))
    assert first.generation == second.generation == 1
    assert first.next == second.next
    assert {first.lease_reused, second.lease_reused} == {False, True}
    async with sessions() as session:
        custody = await session.get(GpuInfraCustody, claims.server_id)
        assert custody.state == "leased"
        assert custody.confirmed_generation == 0
        assert custody.lease_generation == 1
        lease_id = custody.lease_id
        pending_slot = custody.pending_key_slot

    runtime_payload = {
        "server_id": claims.server_id,
        "owner_hotkey": claims.owner_hotkey,
        "reservation_id": claims.reservation_id,
        "attestation_id": attestation.attestation_id,
        "management_mode": "miner",
        "attested_spki_sha256": "e" * 64,
        "jti": "session-confirm",
    }
    marker_sha256 = "f" * 64
    with patch(
        "api.server.gpu_infra._locked_current_lineage",
        side_effect=locked_lineage,
    ):
        async with sessions() as session:
            runtime = await session.get(Server, claims.server_id)
            await confirm_gpu_infra(
                session,
                runtime,
                runtime_payload,
                "e" * 64,
                GpuInfraConfirmRequestV1(
                    lease_id=lease_id,
                    generation=1,
                    active_key_slot=pending_slot,
                    marker_sha256=marker_sha256,
                ),
            )
            await session.commit()
        async with sessions() as session:
            custody = await session.get(GpuInfraCustody, claims.server_id)
            assert custody.state == "awaiting_ack"
            assert custody.confirmed_generation == 0
            assert custody.current_passphrase is None
            assert custody.pending_passphrase is not None
            runtime = await session.get(Server, claims.server_id)
            await acknowledge_gpu_infra(
                session,
                runtime,
                runtime_payload,
                "e" * 64,
                GpuInfraAcknowledgeRequestV1(
                    lease_id=lease_id,
                    generation=1,
                    active_key_slot=pending_slot,
                    marker_sha256=marker_sha256,
                ),
            )
            await session.commit()
        async with sessions() as session:
            custody = await session.get(GpuInfraCustody, claims.server_id)
            assert custody.state == "current"
            assert custody.confirmed_generation == 1
            assert custody.current_passphrase is not None
            assert custody.pending_passphrase is None


async def test_concurrent_platform_and_miner_reservation_choose_one_manager(
    postgres_schema,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    root_manifest = f"sha256:{'9' * 64}"
    manifests = [root_manifest, f"sha256:{'8' * 64}"]
    blobs = [f"sha256:{'7' * 64}"]
    tags = [f"sha256-{'9' * 64}.sig"]
    tag_digests = {tags[0]: manifests[1]}
    closure_sha256 = canonical_sha256(
        {
            "schema": "chutes.oci-descriptor-closure",
            "version": 1,
            "root_manifest": root_manifest,
            "manifests": manifests,
            "blobs": blobs,
            "manifest_tags": tags,
            "manifest_tag_digests": tag_digests,
        }
    )

    async def trusted_platform(_db, _request):
        return (
            "owner",
            "1",
            "owner/image",
            root_manifest,
            {
                "descriptor_closure_sha256": closure_sha256,
                "allowed_manifests": manifests,
                "allowed_blobs": blobs,
                "allowed_manifest_tags": tags,
                "manifest_tag_digests": tag_digests,
            },
        )

    monkeypatch.setattr(
        gpu_allocations,
        "_trusted_platform_workload",
        trusted_platform,
    )

    async def platform_attempt():
        async with sessions() as session:
            try:
                result = await reserve_gpu_group(
                    session,
                    "gpu-host",
                    GpuPlatformReservationRequestV1(
                        server_id="platform-server",
                        process_incarnation="platform-process",
                        gpu_identifier="b200",
                        gpu_count=8,
                        minimum_vram_mib=196608,
                        chute_id="platform-chute",
                    ),
                )
                await session.commit()
                return result
            except GpuAllocationError:
                await session.rollback()
                return None

    async def miner_attempt():
        async with sessions() as session:
            try:
                result = await reserve_gpu_group(
                    session,
                    "gpu-host",
                    _request("miner-server", "miner-process"),
                )
                await session.commit()
                return result
            except GpuAllocationError:
                await session.rollback()
                return None

    results = await asyncio.gather(platform_attempt(), miner_attempt())
    winners = [item for item in results if item is not None]
    assert len(winners) == 1
    async with sessions() as session:
        group = await session.get(GpuAllocationGroup, "allocation-group")
        reservations = (
            (await session.execute(select(gpu_allocations.GpuLaunchReservation)))
            .scalars()
            .all()
        )
        assert len(reservations) == 1
        assert group.management_mode == reservations[0].management_mode
        assert group.reservation_id == reservations[0].reservation_id


async def test_failed_launch_ack_is_idempotent_and_persists_pre_slot_reset(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await record_gpu_command_dispatch(
            session,
            response.claims.reservation_id,
            command="launch_gpu",
            command_id="command-1",
        )
        await record_gpu_command_dispatch(
            session,
            response.claims.reservation_id,
            command="launch_gpu",
            command_id="command-1",
        )
        with pytest.raises(GpuAllocationError, match="command id"):
            await record_gpu_command_dispatch(
                session,
                response.claims.reservation_id,
                command="launch_gpu",
                command_id="command-2",
            )
        await session.commit()

    for _attempt in range(2):
        async with sessions() as session:
            await record_gpu_command_ack(
                session,
                response.claims.reservation_id,
                command="launch_gpu",
                command_id="command-1",
                status="rejected",
                detail="host rejected before claim",
            )
            await session.commit()

    async with sessions() as session:
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert reservation.state == "resetting"
        assert reservation.launch_ack_status == "rejected"
        assert group.state == "resetting"
        assert group.reservation_id == reservation.reservation_id
        operation = (
            await session.execute(
                select(GpuLifecycleOperation).where(
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id,
                    GpuLifecycleOperation.phase == "intent",
                )
            )
        ).scalar_one()
        assert operation.operation_type == "pre_slot_claim_quarantine"
        assert (
            await session.execute(
                select(func.count(gpu_allocations.GpuLaunchReservation.reservation_id))
            )
        ).scalar_one() == 1


async def test_non_idle_inventory_never_rewrites_release_lineage(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        active = await session.get(GuestRelease, "gpu-release")
        active_manifest = {
            **active.l0_manifest,
            "l0_version": "l0-gpu-test",
        }
        active.l0_manifest = active_manifest
        session.add(
            GuestRelease(
                release_id="gpu-release-old",
                channel="gpu-old",
                tee_type="tdx",
                compute_type="gpu",
                status="retired",
                images=active.images,
                l0_manifest=active_manifest,
                l0_manifest_digest="d" * 64,
                l0_manifest_generation=1,
                l0_manifest_key_id="test-key",
                l0_manifest_key_epoch=1,
            )
        )
        response = await reserve_gpu_group(
            session,
            "gpu-host",
            _request(),
        )
        group = await session.get(
            GpuAllocationGroup,
            response.claims.allocation_group_id,
        )
        group.gpu_release_id = "gpu-release-old"
        await session.commit()
    updated_report = _report().model_copy(
        update={
            "report_id": "inventory-report-2",
            "report_generation": 2,
        }
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        result = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            updated_report,
        )
        await session.commit()
        group = await session.get(
            GpuAllocationGroup,
            response.claims.allocation_group_id,
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        assert result.status == "quarantined"
        assert group.gpu_release_id == "gpu-release-old"
        assert reservation.gpu_release_id == "gpu-release"
        assert group.state == reservation.state == "quarantined"


async def _seed_ordinary_lifecycle_phase(sessions, phase: str):
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = "running"
        reservation.running_at = now
        reservation.teardown_requested_at = now
        reservation.teardown_reason = "focused lifecycle phase test"
        group.state = "running"
        group.running_at = now
        operation = await ensure_reservation_lifecycle_operation(
            session,
            response.claims.reservation_id,
            operation_type="normal_delete",
        )
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        result = GpuPhysicalResultV1(
            operation_id=operation.operation_id,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            reservation_generation=operation.reservation_generation,
            claims_sha256=operation.claims_sha256,
            process_incarnation=operation.process_incarnation,
            topology_fingerprint=operation.topology_fingerprint,
            gpu_bdfs=operation.gpu_bdfs,
            gpu_uuids=operation.gpu_uuids,
            qemu_absent=True,
            reset_succeeded=True,
            original_drivers_restored=True,
            guest_shutdown_clean=True,
            evidence={"postconditions_rechecked": True},
        )
        result_document = result.model_dump(mode="json", exclude_none=True)
        result_sha256 = canonical_sha256(result_document)
        if phase != "intent":
            row.physical_result = result_document
            row.physical_result_sha256 = result_sha256
            row.phase = "physical_result"
            row.reporting_state = "physical_result"
        receipt = None
        if phase in {"receipt_accepted", "local_release_acked"}:
            receipt = GpuResetReceiptV1(
                operation_id=operation.operation_id,
                receipt_id=f"receipt-{operation.operation_id}",
                result_sha256=result_sha256,
                outcome="accepted",
                local_release_required=True,
                phase="receipt_accepted",
                accepted_at=now,
            )
            row.result_outcome = "accepted"
            row.receipt_id = receipt.receipt_id
            row.receipt_sha256 = canonical_sha256(receipt)
            row.receipt_accepted_at = now
            row.phase = "receipt_accepted"
            row.reporting_state = "receipt_accepted"
            group.state = "release_pending"
            group.resetting_at = None
        ack = None
        if phase == "local_release_acked":
            ack = GpuLocalReleaseAckV1(
                operation_id=operation.operation_id,
                receipt_id=receipt.receipt_id,
                result_sha256=result_sha256,
                allocation_group_id=operation.allocation_group_id,
                allocation_group_generation=operation.allocation_group_generation,
                reservation_id=operation.reservation_id,
                process_incarnation=operation.process_incarnation,
                local_owner_absent=True,
                local_claim_absent=True,
                local_slot_absent=True,
                local_state_sha256="a" * 64,
                observed_at=now,
            )
            row.local_release_ack = ack.model_dump(mode="json", exclude_none=True)
            row.local_release_ack_sha256 = canonical_sha256(row.local_release_ack)
            row.local_release_acked_at = now
            row.phase = "local_release_acked"
            row.reporting_state = "local_release_acked"
        await session.commit()
        return operation, result, receipt, ack


async def _seed_running_miner_nodes(sessions):
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = "running"
        reservation.running_at = now
        group.state = "running"
        group.running_at = now
        server = Server(
            server_id=reservation.server_id,
            ip="192.0.2.25",
            miner_hotkey=reservation.owner_hotkey,
            name=reservation.server_id,
            netuid=64,
            is_tee=True,
            compute_type="gpu",
            tee_type="tdx",
            host_id=reservation.host_id,
            gpu_launch_reservation_id=reservation.reservation_id,
            gpu_allocation_group_id=reservation.allocation_group_id,
            gpu_allocation_group_generation=reservation.allocation_group_generation,
            gpu_management_mode=reservation.management_mode,
            gpu_process_incarnation=reservation.process_incarnation,
            gpu_topology_fingerprint=reservation.topology_fingerprint,
        )
        session.add(server)
        await session.flush()
        for index, gpu_uuid in enumerate(reservation.gpu_uuids):
            session.add(
                Node(
                    uuid=gpu_uuid,
                    name=f"NVIDIA B200 {index}",
                    memory=192_000_000_000,
                    processors=148,
                    clock_rate=1_590_000.0,
                    max_threads_per_processor=1024,
                    concurrent_kernels=True,
                    ecc=True,
                    seed=index + 1,
                    miner_hotkey=reservation.owner_hotkey,
                    gpu_identifier="b200",
                    device_index=index,
                    server_id=server.server_id,
                    verification_host="127.0.0.1",
                    verification_port=8000 + index,
                    gpu_allocation_group_id=reservation.allocation_group_id,
                    gpu_allocation_group_generation=reservation.allocation_group_generation,
                    gpu_launch_reservation_id=reservation.reservation_id,
                    gpu_process_incarnation=reservation.process_incarnation,
                    gpu_inventory_report_id=group.last_report_id,
                )
            )
        await session.commit()
        return response


def _verified_gpu_subset(*indices: int) -> NvidiaVerificationResultV1:
    return NvidiaVerificationResultV1(
        schema="chutes.nvidia-verification-result",
        version=1,
        nonce="f" * 64,
        devices=[
            {
                "attestation_certificate_sha256": f"{index:064x}",
                "evidence_sha256": f"{index + 32:064x}",
                "architecture": "BLACKWELL",
            }
            for index in indices
        ],
    )


async def test_miner_runtime_selection_accepts_nonempty_exact_lineage_subset(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    response = await _seed_running_miner_nodes(sessions)
    async with sessions() as session:
        server = await session.get(Server, response.claims.server_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        selected = await _validate_runtime_gpu_selection(
            session,
            server,
            reservation,
            response.claims,
            _verified_gpu_subset(1, 2),
        )
        assert selected == UUIDS[:2]
        await session.rollback()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("server_id", "conflicting-server"),
        ("gpu_allocation_group_id", "conflicting-group"),
        ("gpu_allocation_group_generation", 2),
        ("gpu_launch_reservation_id", "conflicting-reservation"),
        ("gpu_process_incarnation", "conflicting-process"),
        ("gpu_inventory_report_id", None),
        ("gpu_retired_at", "retired"),
    ],
)
async def test_miner_runtime_selection_rejects_every_node_lineage_substitution(
    postgres_schema,
    field,
    value,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    response = await _seed_running_miner_nodes(sessions)
    async with sessions() as session:
        server = await session.get(Server, response.claims.server_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        node = await session.get(Node, UUIDS[0])
        setattr(
            node,
            field,
            datetime.now(timezone.utc) if value == "retired" else value,
        )
        with session.no_autoflush:
            with pytest.raises(
                InvalidGpuEvidenceError,
                match="server/group/generation/inventory lineage",
            ):
                await _validate_runtime_gpu_selection(
                    session,
                    server,
                    reservation,
                    response.claims,
                    _verified_gpu_subset(1),
                )
        await session.rollback()


@pytest.mark.parametrize("phase", ["intent", "physical_result"])
async def test_control_plane_fence_terminalizes_pre_receipt_lifecycle_frontier(
    postgres_schema,
    phase,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, result, receipt, ack = await _seed_ordinary_lifecycle_phase(
        sessions, phase
    )

    async with sessions() as session:
        await fence_gpu_host_authority(
            session,
            "gpu-host",
            code="focused_control_plane_fence",
            reason="focused lifecycle frontier fence",
        )
        await session.commit()

    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, operation.reservation_id
        )
        assert row.phase == "quarantined"
        assert row.reporting_state == "quarantined"
        assert row.failure_code == "focused_control_plane_fence"
        assert row.finalized_at is not None
        assert (row.physical_result_sha256 is not None) == (
            result is not None and phase != "intent"
        )
        assert (row.receipt_sha256 is not None) == (phase != "intent")
        assert (row.local_release_ack_sha256 is not None) == (ack is not None)
        assert group.state == reservation.state == "quarantined"
        assert (
            group.failure_code
            == reservation.failure_code
            == "focused_control_plane_fence"
        )


@pytest.mark.parametrize("phase", ["receipt_accepted", "local_release_acked"])
@pytest.mark.parametrize("fence_kind", ["control_plane", "host", "inventory"])
async def test_phase_two_receipt_frontier_survives_fence_and_finalizes(
    postgres_schema,
    phase,
    fence_kind,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, physical, receipt, ack = await _seed_ordinary_lifecycle_phase(
        sessions, phase
    )

    async with sessions() as session:
        if fence_kind == "control_plane":
            await quarantine_gpu_reservation_control_plane(
                session,
                operation.reservation_id,
                code="focused_phase_two_control_plane_fence",
                reason="focused authoritative receipt preservation",
            )
        elif fence_kind == "host":
            await fence_gpu_host_authority(
                session,
                "gpu-host",
                code="focused_phase_two_host_fence",
                reason="focused authoritative receipt preservation",
            )
        else:
            host = await session.get(Host, "gpu-host")
            report_data = _report().model_dump(mode="json")
            changed_group = _inventory_group()
            changed_group.pop("topology_fingerprint", None)
            changed_group["devices"][0]["attestation_certificate_sha256"] = "f" * 64
            changed_group["topology_fingerprint"] = canonical_sha256(changed_group)
            report_data.update(
                {
                    "report_id": f"phase-two-{phase}-inventory-fence",
                    "report_generation": 2,
                    "groups": [changed_group],
                }
            )
            reconciled = await gpu_allocations.reconcile_gpu_inventory(
                session,
                host,
                GpuInventoryReportV1.model_validate(report_data),
            )
            assert reconciled.status == "quarantined"
        await session.commit()

    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, operation.reservation_id
        )
        assert row.phase == phase
        assert row.reporting_state == phase
        assert row.result_outcome == "accepted"
        assert row.receipt_id == receipt.receipt_id
        assert row.receipt_sha256 == canonical_sha256(receipt)
        if fence_kind == "inventory":
            assert row.failure_code == "gpu_inventory_changed_during_release"
            assert row.failure_reason is not None
        else:
            assert row.failure_code is None
            assert row.failure_reason is None
        assert row.finalized_at is None
        assert group.state == "release_pending"
        assert reservation.state == "resetting"
        host = await session.get(Host, "gpu-host")
        assert await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        ) == receipt
        exact_ack = ack or GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            exact_ack,
        )
        if fence_kind == "inventory":
            assert finalized.phase == "quarantined"
            assert finalized.group_state == "quarantined"
            assert reservation.state == "quarantined"
        else:
            assert finalized.phase == "finalized"
            assert finalized.group_state == "available"
            assert reservation.state == "released"
        await session.commit()


async def _prepare_gpu_rotation_request(sessions) -> HostEnrollmentRedemptionV2:
    request = EnrollmentVoucherMintRequestV2(
        host_id="gpu-host",
        tee_type="tdx",
        compute_type="gpu",
        storage_enabled=True,
        channel="gpu-test",
    )
    async with sessions() as session:
        await mint_enrollment_voucher(session, "owner", request)
    async with sessions() as session:
        voucher = await mint_enrollment_voucher(session, "owner", request)

    ed25519 = Ed25519PrivateKey.generate()
    x25519 = X25519PrivateKey.generate()
    ed_public = base64.b64encode(
        ed25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    x_public = base64.b64encode(
        x25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    challenge_request = EnrollmentKeyChallengeRequestV2(
        voucher=voucher.voucher,
        compute_type="gpu",
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    challenge_request = challenge_request.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(challenge_request.signing_bytes())
            ).decode()
        }
    )
    async with sessions() as session:
        challenge = await create_enrollment_key_challenge(session, challenge_request)

    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(challenge.server_ephemeral_public_key)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(hashlib.sha256(voucher.voucher.encode("ascii")).hexdigest()),
        info=b"chutes/model-b/enrollment-x25519-proof/v2",
    ).derive(x25519.exchange(peer))
    signing_aad = challenge_request.signing_bytes() + challenge.challenge_id.encode(
        "ascii"
    )
    plaintext = ChaCha20Poly1305(key).decrypt(
        base64.b64decode(challenge.nonce),
        base64.b64decode(challenge.ciphertext),
        signing_aad,
    )
    redemption = HostEnrollmentRedemptionV2(
        voucher=voucher.voucher,
        compute_type="gpu",
        challenge_id=challenge.challenge_id,
        challenge_plaintext=base64.b64encode(plaintext).decode(),
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    return redemption.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(redemption.signing_bytes())
            ).decode()
        }
    )


async def _seed_recovery_required_group(sessions) -> None:
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        group.state = "recovery_required"
        group.recovery_authorization_id = "focused-recovery-authorization"
        group.recovery_report_id = group.last_report_id
        group.recovery_nonce_hash = "a" * 64
        group.recovery_authorized_by = "focused-test"
        group.recovery_authorized_at = now
        group.recovery_started_at = now
        group.recovery_completed_at = now
        await session.commit()


@pytest.mark.parametrize(
    "frontier",
    ["intent", "physical_result", "receipt_accepted", "recovery_required"],
)
@pytest.mark.parametrize("mutation", ["rotation", "revocation"])
async def test_gpu_credential_mutation_is_blocked_before_safe_release_frontier(
    postgres_schema,
    frontier,
    mutation,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    rotation = (
        await _prepare_gpu_rotation_request(sessions)
        if mutation == "rotation"
        else None
    )
    if frontier == "recovery_required":
        await _seed_recovery_required_group(sessions)
    else:
        await _seed_ordinary_lifecycle_phase(sessions, frontier)

    async with sessions() as session:
        with pytest.raises(
            HostAuthError,
            match="blocked until lifecycle custody",
        ):
            if mutation == "rotation":
                await redeem_enrollment_voucher(session, rotation)
            else:
                await revoke_host_credentials(
                    session,
                    "gpu-host",
                    "owner",
                    "focused explicit revocation",
                )
        await session.rollback()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        key = await session.get(HostKeyGeneration, ("gpu-host", 1))
        assert host.active_key_generation == 1
        assert host.provisioning_state == "ready"
        assert key.revoked_at is None


@pytest.mark.parametrize(
    "frontier", ["local_release_acked"]
)
@pytest.mark.parametrize("mutation", ["rotation", "revocation_then_rotation"])
async def test_current_gpu_host_finishes_exact_release_after_credential_change(
    postgres_schema,
    frontier,
    mutation,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, physical, receipt, ack = await _seed_ordinary_lifecycle_phase(
        sessions, frontier
    )

    if mutation == "revocation_then_rotation":
        async with sessions() as session:
            with patch(
                "api.agent_channel.send_agent_command",
                AsyncMock(return_value=None),
            ):
                await revoke_host_credentials(
                    session,
                    "gpu-host",
                    "owner",
                    "focused post-physical revocation",
                )
        async with sessions() as session:
            row = await session.get(GpuLifecycleOperation, operation.operation_id)
            assert row.phase == frontier
            host = await session.get(Host, "gpu-host")
            assert host.provisioning_state == "revoked"

    rotation = await _prepare_gpu_rotation_request(sessions)
    async with sessions() as session:
        with patch(
            "api.agent_channel.send_agent_command",
            AsyncMock(return_value=None),
        ):
            rotated = await redeem_enrollment_voucher(session, rotation)
        assert rotated.key_generation == 2

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        old_key = await session.get(HostKeyGeneration, ("gpu-host", 1))
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        assert host.active_key_generation == 2
        assert old_key.revoked_at is not None
        assert row.phase == frontier
        assert row.physical_result_sha256 == canonical_sha256(physical)
        accepted_receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        )
        if receipt is not None:
            assert accepted_receipt == receipt
        exact_ack = ack or GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=accepted_receipt.receipt_id,
            result_sha256=accepted_receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            exact_ack,
        )
        assert finalized.phase == "finalized"
        assert finalized.group_state == "available"
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, operation.reservation_id
        )
        assert reservation.state == "released"
        await session.commit()


@pytest.mark.parametrize(
    ("reservation_state", "invalid_type", "valid_type"),
    [
        ("claimed", "normal_delete", "launch_rollback"),
        ("launching", "normal_delete", "launch_rollback"),
        ("running", "launch_rollback", "normal_delete"),
    ],
)
async def test_lifecycle_operation_type_is_derived_from_server_custody_state(
    postgres_schema,
    reservation_state,
    invalid_type,
    valid_type,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = reservation_state
        reservation.teardown_requested_at = now
        reservation.teardown_reason = "focused state/type derivation"
        group.state = "running" if reservation_state == "running" else "launching"
        if reservation_state == "launching":
            reservation.launching_at = now
            group.launching_at = now
        elif reservation_state == "running":
            reservation.running_at = now
            group.running_at = now
        await session.flush()

        with pytest.raises(
            GpuLifecycleError,
            match="differs from server-side custody state",
        ):
            await ensure_reservation_lifecycle_operation(
                session,
                reservation.reservation_id,
                operation_type=invalid_type,
            )
        operation = await ensure_reservation_lifecycle_operation(
            session,
            reservation.reservation_id,
            operation_type=valid_type,
        )
        assert operation.operation_type == valid_type

        if reservation_state == "running":
            physical = GpuPhysicalResultV1(
                operation_id=operation.operation_id,
                allocation_group_id=operation.allocation_group_id,
                allocation_group_generation=operation.allocation_group_generation,
                reservation_id=operation.reservation_id,
                reservation_generation=operation.reservation_generation,
                claims_sha256=operation.claims_sha256,
                process_incarnation=operation.process_incarnation,
                topology_fingerprint=operation.topology_fingerprint,
                gpu_bdfs=operation.gpu_bdfs,
                gpu_uuids=operation.gpu_uuids,
                qemu_absent=True,
                reset_succeeded=True,
                original_drivers_restored=True,
                evidence={"postconditions_rechecked": True},
            )
            receipt = await record_gpu_physical_result(
                session,
                host,
                operation.operation_id,
                physical,
            )
            row = await session.get(GpuLifecycleOperation, operation.operation_id)
            reservation = await session.get(
                gpu_allocations.GpuLaunchReservation, operation.reservation_id
            )
            group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
            assert receipt.outcome == "quarantined"
            assert receipt.local_release_required is False
            assert row.phase == "quarantined"
            assert row.physical_result == physical.model_dump(
                mode="json", exclude_none=True
            )
            assert row.physical_result_sha256 == canonical_sha256(physical)
            assert row.failure_code == "gpu_guest_shutdown_unclean"
            assert reservation.state == group.state == "quarantined"
        await session.rollback()


@pytest.mark.parametrize("rollover_point", ["before_claim", "before_launch"])
async def test_release_rollover_persists_intent_before_fence_and_finalizes(
    postgres_schema,
    rollover_point,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        if rollover_point == "before_launch":
            await claim_gpu_reservation(
                session,
                host,
                GpuReservationClaimRequestV1(
                    token=response.token,
                    claims_sha256=response.claims_sha256,
                ),
            )
        active = await session.get(GuestRelease, "gpu-release")
        active.status = "retired"
        await session.flush()
        session.add(
            GuestRelease(
                release_id="gpu-release-successor",
                channel=active.channel,
                tee_type=active.tee_type,
                compute_type=active.compute_type,
                status="active",
                images=active.images,
                l0_manifest=active.l0_manifest,
                l0_manifest_digest=active.l0_manifest_digest,
                l0_manifest_generation=active.l0_manifest_generation,
                l0_manifest_key_id=active.l0_manifest_key_id,
                l0_manifest_key_epoch=active.l0_manifest_key_epoch,
            )
        )
        await session.flush()
        with pytest.raises(
            gpu_allocations.GpuAllocationQuarantinedError,
            match="reset is pending",
        ):
            if rollover_point == "before_claim":
                await claim_gpu_reservation(
                    session,
                    host,
                    GpuReservationClaimRequestV1(
                        token=response.token,
                        claims_sha256=response.claims_sha256,
                    ),
                )
            else:
                await mark_gpu_launching(
                    session,
                    host,
                    GpuReservationStateRequestV1(
                        reservation_id=response.claims.reservation_id,
                        claims_sha256=response.claims_sha256,
                        process_incarnation=response.claims.process_incarnation,
                    ),
                )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        operation = (
            await session.execute(
                select(GpuLifecycleOperation).where(
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id
                )
            )
        ).scalar_one()
        assert operation.operation_type == "release_rollover"
        assert operation.phase == "intent"
        assert reservation.state == group.state == "resetting"
        assert reservation.teardown_reason == (
            "GPU reservation release changed before claim."
            if rollover_point == "before_claim"
            else "GPU reservation release changed before launch."
        )

        physical = GpuPhysicalResultV1(
            operation_id=operation.operation_id,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            reservation_generation=operation.reservation_generation,
            claims_sha256=operation.claims_sha256,
            process_incarnation=operation.process_incarnation,
            topology_fingerprint=operation.topology_fingerprint,
            gpu_bdfs=operation.gpu_bdfs,
            gpu_uuids=operation.gpu_uuids,
            qemu_absent=True,
            reset_succeeded=True,
            original_drivers_restored=True,
            evidence={"postconditions_rechecked": True},
        )
        receipt = await record_gpu_physical_result(
            session, host, operation.operation_id, physical
        )
        assert receipt.outcome == "accepted"
        assert receipt.local_release_required is True
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        assert group.state == "release_pending"
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session, host, operation.operation_id, ack
        )
        assert finalized.phase == "finalized"
        assert finalized.group_state == "available"
        assert reservation.state == "released"
        await session.commit()


async def test_late_registration_creates_one_replayable_launch_rollback_intent(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        await mark_gpu_launching(
            session,
            host,
            GpuReservationStateRequestV1(
                reservation_id=response.claims.reservation_id,
                claims_sha256=response.claims_sha256,
                process_incarnation=response.claims.process_incarnation,
            ),
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        expired_now = reservation.expires_at + timedelta(seconds=1)
        commitment = GpuQuoteCommitmentV1(
            reservation_sha256=response.claims_sha256,
            release_target_sha256=response.claims.release_target_sha256,
            launch_nonce=response.claims.launch_nonce,
            attested_spki_sha256="e" * 64,
            claims=response.claims,
        )
        with patch(
            "api.host.gpu_allocations._utcnow",
            return_value=expired_now,
        ):
            for _ in range(2):
                with pytest.raises(
                    gpu_allocations.GpuAllocationQuarantinedError,
                    match="reset is pending",
                ):
                    await gpu_allocations.resolve_gpu_registration_reservation(
                        session,
                        response.token,
                        commitment,
                    )
        rows = list(
            (
                await session.execute(
                    select(GpuLifecycleOperation).where(
                        GpuLifecycleOperation.reservation_id
                        == reservation.reservation_id
                    )
                )
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].operation_type == "launch_rollback"
        assert rows[0].phase == "intent"
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert reservation.state == group.state == "resetting"
        assert reservation.teardown_reason == (
            "GPU guest registration missed its launch deadline."
        )
        await session.commit()


@pytest.mark.parametrize(
    ("operation_type", "reservation_state"),
    [
        ("pre_slot_claim_quarantine", "reserved"),
        ("launch_rollback", "claimed"),
        ("release_rollover", "reserved"),
        ("normal_delete", "running"),
    ],
)
async def test_reservation_lifecycle_producers_use_two_phase_release_and_replay(
    postgres_schema,
    operation_type,
    reservation_state,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        if reservation_state == "claimed":
            await claim_gpu_reservation(
                session,
                host,
                GpuReservationClaimRequestV1(
                    token=response.token,
                    claims_sha256=response.claims_sha256,
                ),
            )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = reservation_state
        reservation.teardown_requested_at = now
        reservation.teardown_reason = "focused lifecycle producer matrix"
        if operation_type == "pre_slot_claim_quarantine":
            reservation.launch_command_id = "focused-launch-command"
            reservation.launch_dispatched_at = now
        elif operation_type == "release_rollover":
            reservation.failure_code = "launch_active_release_changed"
            reservation.failure_reason = "focused release rollover"
        elif operation_type == "normal_delete":
            reservation.running_at = now
            group.state = "running"
            group.running_at = now
        operation = await ensure_reservation_lifecycle_operation(
            session,
            reservation.reservation_id,
            operation_type=operation_type,
        )
        assert operation.operation_type == operation_type
        assert operation.phase == "intent"
        physical = GpuPhysicalResultV1(
            operation_id=operation.operation_id,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            reservation_generation=operation.reservation_generation,
            claims_sha256=operation.claims_sha256,
            process_incarnation=operation.process_incarnation,
            topology_fingerprint=operation.topology_fingerprint,
            gpu_bdfs=operation.gpu_bdfs,
            gpu_uuids=operation.gpu_uuids,
            qemu_absent=True,
            reset_succeeded=True,
            original_drivers_restored=True,
            guest_shutdown_clean=(True if operation_type == "normal_delete" else None),
            evidence={"postconditions_rechecked": True},
        )
        receipt = await record_gpu_physical_result(
            session, host, operation.operation_id, physical
        )
        assert receipt.outcome == "accepted"
        replayed_receipt = await record_gpu_physical_result(
            session, host, operation.operation_id, physical
        )
        assert replayed_receipt == receipt
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, operation.reservation_id
        )
        assert row.phase == "receipt_accepted"
        assert group.state == "release_pending"
        assert reservation.state == "resetting"
        assert group.available_at is None
        generation = group.generation
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="d" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session, host, operation.operation_id, ack
        )
        replayed_final = await record_gpu_local_release_ack(
            session, host, operation.operation_id, ack
        )
        assert finalized.phase == replayed_final.phase == "finalized"
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, operation.reservation_id
        )
        assert group.state == "available"
        assert group.generation == generation
        assert reservation.state == "released"
        finalized_bytes = finalized.model_dump(mode="json")
        await session.commit()

    async with sessions() as session:
        next_response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=next_response.token,
                claims_sha256=next_response.claims_sha256,
            ),
        )
        await mark_gpu_launching(
            session,
            host,
            GpuReservationStateRequestV1(
                reservation_id=next_response.claims.reservation_id,
                claims_sha256=next_response.claims_sha256,
                process_incarnation=next_response.claims.process_incarnation,
            ),
        )
        next_reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            next_response.claims.reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            next_response.claims.allocation_group_id,
        )
        now = datetime.now(timezone.utc)
        next_reservation.state = "running"
        next_reservation.running_at = now
        group.state = "running"
        group.running_at = now
        prior_key = await session.get(HostKeyGeneration, ("gpu-host", 1))
        prior_key.revoked_at = now
        prior_key.revocation_reason = "focused terminal replay rotation"
        session.add(
            HostKeyGeneration(
                host_id="gpu-host",
                generation=2,
                enrollment_generation=2,
                ed25519_public_key="ordinary-replay-ed25519",
                ed25519_fingerprint="1" * 64,
                x25519_public_key="ordinary-replay-x25519",
                x25519_fingerprint="2" * 64,
            )
        )
        host.active_key_generation = 2
        host.boot_generation = 2
        host.boot_id = "22222222-2222-2222-2222-222222222222"
        await session.commit()

    async with sessions() as session:
        current_host = await session.get(Host, "gpu-host")
        assert await record_gpu_physical_result(
            session,
            current_host,
            operation.operation_id,
            physical,
        ) == receipt
        replayed = await record_gpu_local_release_ack(
            session,
            current_host,
            operation.operation_id,
            ack,
        )
        assert replayed.model_dump(mode="json") == finalized_bytes
        changed_ack = ack.model_copy(update={"local_state_sha256": "e" * 64})
        with pytest.raises(GpuLifecycleError, match="changed canonical bytes"):
            await record_gpu_local_release_ack(
                session,
                current_host,
                operation.operation_id,
                changed_ack,
            )
        await session.rollback()


@pytest.mark.parametrize(
    ("phase", "expected_group_state"),
    [
        ("intent", "resetting"),
        ("physical_result", "resetting"),
        ("receipt_accepted", "release_pending"),
        ("local_release_acked", "release_pending"),
    ],
)
async def test_ordinary_lifecycle_operation_resumes_across_host_reboot(
    postgres_schema,
    phase,
    expected_group_state,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, _result, _receipt, _ack = await _seed_ordinary_lifecycle_phase(
        sessions, phase
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        assert (
            await advance_gpu_host_boot(
                session,
                host,
                "22222222-2222-2222-2222-222222222222",
            )
            == 2
        )
        await session.commit()
    async with sessions() as session:
        current_host = await session.get(Host, "gpu-host")
        resumed = await get_gpu_lifecycle_operation(
            session,
            current_host,
            operation.operation_id,
        )
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            operation.reservation_id,
        )
        assert resumed.phase == phase
        assert group.state == expected_group_state
        assert reservation.state == "resetting"
        assert resumed.host_boot_generation == 1
        assert current_host.boot_generation == 2


@pytest.mark.parametrize("phase", ["intent", "physical_result"])
async def test_reboot_inventory_preserves_reset_journal_until_exact_release(
    postgres_schema,
    phase,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, physical, _receipt, _ack = await _seed_ordinary_lifecycle_phase(
        sessions, phase
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        original_report_id = group.last_report_id
        await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report = _current_host_report(host, f"ordinary-{phase}-restart-report")
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            report,
        )
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        assert reconciled.status == "accepted"
        assert group.state == "resetting"
        assert group.last_report_id == original_report_id
        assert group.host_boot_generation == 1
        assert row.phase == phase
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        )
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            ack,
        )
        assert finalized.phase == "finalized"
        assert finalized.group_state == "available"
        await session.commit()


@pytest.mark.parametrize("conflict", ["generation", "process"])
async def test_host_reboot_does_not_resume_stale_or_conflicting_lifecycle_custody(
    postgres_schema,
    conflict,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, _result, _receipt, _ack = await _seed_ordinary_lifecycle_phase(
        sessions, "intent"
    )
    async with sessions() as session:
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        if conflict == "generation":
            group.generation += 1
        else:
            group.process_incarnation = "conflicting-process"
        await session.commit()
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        await session.commit()
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            operation.reservation_id,
        )
        assert group.state == reservation.state == "quarantined"
        assert group.failure_code == "host_boot_changed_with_ambiguous_state"


async def test_lost_reset_receipt_reboots_then_replays_ack_and_finalizes(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, result, receipt, _ack = await _seed_ordinary_lifecycle_phase(
        sessions, "receipt_accepted"
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        await session.commit()
    ack = GpuLocalReleaseAckV1(
        operation_id=operation.operation_id,
        receipt_id=receipt.receipt_id,
        result_sha256=canonical_sha256(
            result.model_dump(mode="json", exclude_none=True)
        ),
        allocation_group_id=operation.allocation_group_id,
        allocation_group_generation=operation.allocation_group_generation,
        reservation_id=operation.reservation_id,
        process_incarnation=operation.process_incarnation,
        local_owner_absent=True,
        local_claim_absent=True,
        local_slot_absent=True,
        local_state_sha256="b" * 64,
        observed_at=datetime.now(timezone.utc),
    )
    async with sessions() as session:
        current_host = await session.get(Host, "gpu-host")
        finalized = await record_gpu_local_release_ack(
            session,
            current_host,
            operation.operation_id,
            ack,
        )
        assert finalized.phase == "finalized"
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            operation.reservation_id,
        )
        assert group.state == "available"
        assert reservation.state == "released"


async def test_new_host_boot_quarantines_unreset_gpu_ownership(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        generation = await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert generation == 2
        assert group.state == "quarantined"
        assert group.failure_code == "host_boot_changed_with_ownership"
        await session.commit()


async def test_old_key_forced_recovery_bridges_to_current_signed_inventory(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        await fence_gpu_host_authority(
            session,
            "gpu-host",
            code="test_key_rotation",
            reason="key rotated",
        )
        prior_key = await session.get(HostKeyGeneration, ("gpu-host", 1))
        prior_key.revoked_at = datetime.now(timezone.utc)
        prior_key.revocation_reason = "rotated"
        session.add(
            HostKeyGeneration(
                host_id="gpu-host",
                generation=2,
                enrollment_generation=2,
                ed25519_public_key="rotated-ed25519",
                ed25519_fingerprint="1" * 64,
                x25519_public_key="rotated-x25519",
                x25519_fingerprint="2" * 64,
            )
        )
        host.active_key_generation = 2
        host.gpu_inventory_report_generation = 2
        await session.flush()
        report_claims = _report().model_copy(
            update={
                "report_id": "recovery-report-key-2",
                "report_generation": 2,
                "host_key_generation": 2,
            }
        )
        reported_group = report_claims.groups[0]
        report = GpuInventoryReport(
            report_id=report_claims.report_id,
            host_id=host.host_id,
            host_key_generation=2,
            host_boot_generation=host.boot_generation,
            report_generation=2,
            gpu_release_id="gpu-release",
            profile_contract_sha256=report_claims.profile_contract_sha256,
            topology_fingerprint=reported_group.topology_fingerprint,
            claims=report_claims.model_dump(mode="json"),
            claims_sha256=canonical_sha256(report_claims),
            reconciliation_status="quarantined",
            failure_reason="same fabric under rotated host key",
        )
        session.add(report)
        await session.flush()
        group = await session.get(
            GpuAllocationGroup,
            response.claims.allocation_group_id,
        )
        group.last_report_id = report.report_id
        envelope = await authorize_gpu_recovery(
            session,
            response.claims.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=report.report_id,
                reason="operator confirmed exact rotated-key inventory",
            ),
            authorized_by="admin",
        )
        authorization = await session.get(
            GpuRecoveryAuthorization, envelope.authorization_id
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert envelope.operation.operation_type == "forced_dead_guest_recovery"
        assert envelope.operation.host_key_generation == 2
        assert authorization.prior_host_key_generation == 1
        assert authorization.prior_host_boot_generation == 1
        assert authorization.host_key_generation == 2
        assert reservation.host_key_generation == 1
        assert group.host_key_generation == 2
        assert group.state == "quarantined"
        await session.commit()


async def test_old_boot_ownerless_recovery_bridges_to_current_signed_inventory(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        group.state = "quarantined"
        group.available_at = None
        group.quarantined_at = datetime.now(timezone.utc)
        group.failure_code = "ownerless"
        group.failure_reason = "ownerless quarantine"
        group.failure_metadata = {}
        await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        assert host.boot_generation == 2
        assert group.host_boot_generation == 1
        report_claims = _report().model_copy(
            update={
                "report_id": "recovery-report-boot-2",
                "report_generation": 2,
                "host_boot_id": host.boot_id,
                "host_boot_generation": 2,
            }
        )
        reported_group = report_claims.groups[0]
        report = GpuInventoryReport(
            report_id=report_claims.report_id,
            host_id=host.host_id,
            host_key_generation=host.active_key_generation,
            host_boot_generation=2,
            report_generation=2,
            gpu_release_id="gpu-release",
            profile_contract_sha256=report_claims.profile_contract_sha256,
            topology_fingerprint=reported_group.topology_fingerprint,
            claims=report_claims.model_dump(mode="json"),
            claims_sha256=canonical_sha256(report_claims),
            reconciliation_status="quarantined",
            failure_reason="same ownerless fabric after reboot",
        )
        session.add(report)
        await session.flush()
        host.gpu_inventory_report_generation = 2
        group.last_report_id = report.report_id
        envelope = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=report.report_id,
                reason="operator confirmed exact current-boot inventory",
            ),
            authorized_by="admin",
        )
        authorization = await session.get(
            GpuRecoveryAuthorization, envelope.authorization_id
        )
        assert envelope.operation.operation_type == "ownerless_group_recovery"
        assert envelope.operation.host_boot_generation == 2
        assert authorization.prior_host_boot_generation == 1
        assert authorization.host_boot_generation == 2
        assert group.host_boot_generation == 2
        assert group.state == "quarantined"
        await session.commit()


@pytest.mark.parametrize(
    ("active_pair", "invalid_pair"),
    [
        (("reserved", "reserved"), ("reserved", "launching")),
        (("claimed", "reserved"), ("launching", "reserved")),
        (("launching", "launching"), ("launching", "resetting")),
        (("running", "running"), ("resetting", "resetting")),
    ],
)
async def test_recovery_required_reboot_reclaim_binds_current_inventory_event(
    postgres_schema,
    active_pair,
    invalid_pair,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await quarantine_gpu_reservation_control_plane(
            session,
            response.claims.reservation_id,
            code="dead_guest_requires_recovery",
            reason="guest is dead while the exact GPU group remains owned",
        )
        host = await session.get(Host, "gpu-host")
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        envelope = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=group.last_report_id,
                reason="operator authorized exact dead-guest recovery",
            ),
            authorized_by="admin",
        )
        operation = await start_gpu_recovery(
            session, host, envelope.operation.operation_id, envelope
        )
        reader_result = GpuSourceReaderResultV1(
            migration_id=None,
            readers_absent=True,
            sources=[
                {
                    "namespace": namespace,
                    "source_path_sha256": digest * 64,
                    "reader_pids": [],
                }
                for namespace, digest in (("storage", "8"), ("tdx-cache", "9"))
            ],
        )
        physical = GpuPhysicalResultV1(
            operation_id=operation.operation_id,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            reservation_generation=operation.reservation_generation,
            claims_sha256=operation.claims_sha256,
            process_incarnation=operation.process_incarnation,
            topology_fingerprint=operation.topology_fingerprint,
            gpu_bdfs=operation.gpu_bdfs,
            gpu_uuids=operation.gpu_uuids,
            qemu_absent=True,
            reset_succeeded=True,
            original_drivers_restored=True,
            source_reader_result=reader_result,
            evidence={"postconditions_rechecked": True},
        )
        receipt = await record_gpu_physical_result(
            session, host, operation.operation_id, physical
        )
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session, host, operation.operation_id, ack
        )
        assert finalized.phase == "finalized"
        assert group.state == "recovery_required"
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        assert (
            await advance_gpu_host_boot(
                session,
                host,
                "22222222-2222-2222-2222-222222222222",
            )
            == 2
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert group.state == "recovery_required"
        assert group.host_boot_generation == 1
        await session.commit()

    current_report = _report().model_copy(
        update={
            "report_id": "inventory-report-recovery-required-boot-2",
            "report_generation": 1,
            "host_boot_id": "22222222-2222-2222-2222-222222222222",
            "host_boot_generation": 2,
        }
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session, host, current_report
        )
        assert reconciled.status == "accepted"
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert group.state == "recovery_required"
        assert group.host_boot_generation == 2
        assert group.last_report_id == current_report.report_id
        await session.commit()

    async with sessions() as session:
        reclaimed = await reserve_gpu_group(
            session,
            "gpu-host",
            _request(),
            recovery_authorization_id=envelope.authorization_id,
        )
        event = (
            await session.execute(
                select(GpuRecoveryEvent).where(
                    GpuRecoveryEvent.operation_id == operation.operation_id,
                    GpuRecoveryEvent.state == "reclaimed",
                )
            )
        ).scalar_one()
        current_row = await session.get(GpuInventoryReport, current_report.report_id)
        assert event.reclaim_reservation_id == reclaimed.claims.reservation_id
        assert event.current_inventory_report_id == current_report.report_id
        assert event.current_inventory_report_sha256 == current_row.claims_sha256
        assert event.current_host_key_generation == 1
        assert event.current_host_boot_generation == 2
        assert event.reclaim_request_sha256 is not None
        assert event.reclaim_response_sha256 == canonical_sha256(reclaimed)
        assert event.reclaim_replay_until > event.completed_at
        first_response = reclaimed.model_dump(mode="json")
        await session.commit()

    if active_pair != ("reserved", "reserved"):
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            await claim_gpu_reservation(
                session,
                host,
                GpuReservationClaimRequestV1(
                    token=reclaimed.token,
                    claims_sha256=reclaimed.claims_sha256,
                ),
            )
            if active_pair in {("launching", "launching"), ("running", "running")}:
                await mark_gpu_launching(
                    session,
                    host,
                    GpuReservationStateRequestV1(
                        reservation_id=reclaimed.claims.reservation_id,
                        claims_sha256=reclaimed.claims_sha256,
                        process_incarnation=reclaimed.claims.process_incarnation,
                    ),
                )
            if active_pair == ("running", "running"):
                now = datetime.now(timezone.utc)
                reservation = await session.get(
                    gpu_allocations.GpuLaunchReservation,
                    reclaimed.claims.reservation_id,
                )
                group = await session.get(
                    GpuAllocationGroup,
                    reclaimed.claims.allocation_group_id,
                )
                reservation.state = "running"
                reservation.running_at = now
                group.state = "running"
                group.running_at = now
                group.updated_at = now
            await session.commit()

    # A later exact periodic report may advance the mutable group report pointer
    # after the reclaim response was lost. The immutable reclaim event still
    # reconstructs the same response against host-latest exact evidence.
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        newer_report = _current_host_report(
            host,
            f"reclaim-replay-{active_pair[0]}-{active_pair[1]}",
        )
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            newer_report,
        )
        group = await session.get(
            GpuAllocationGroup,
            reclaimed.claims.allocation_group_id,
        )
        assert reconciled.status == "accepted"
        assert group.last_report_id == newer_report.report_id
        await session.commit()

    # Simulate a committed reclaim whose HTTP response was lost after the
    # reservation advanced through any exact active lifecycle phase.
    async with sessions() as session:
        replay = await reserve_gpu_group(
            session,
            "gpu-host",
            _request(),
            recovery_authorization_id=envelope.authorization_id,
        )
        assert replay.model_dump(mode="json") == first_response
        events = list(
            (
                await session.execute(
                    select(GpuRecoveryEvent).where(
                        GpuRecoveryEvent.operation_id == operation.operation_id,
                        GpuRecoveryEvent.state == "reclaimed",
                    )
                )
            ).scalars()
        )
        reservations = list(
            (
                await session.execute(
                    select(gpu_allocations.GpuLaunchReservation).where(
                        gpu_allocations.GpuLaunchReservation.allocation_group_id
                        == response.claims.allocation_group_id
                    )
                )
            ).scalars()
        )
        assert len(events) == 1
        assert len(reservations) == 2
        reclaimed_row = next(
            item
            for item in reservations
            if item.reservation_id == replay.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup,
            replay.claims.allocation_group_id,
        )
        assert (reclaimed_row.state, group.state) == active_pair
        await session.rollback()

    async with sessions() as session:
        conflicting = _request().model_copy(update={"miner_hourly_cost": 9.99})
        with pytest.raises(GpuAllocationError, match="replay is stale or conflicting"):
            await reserve_gpu_group(
                session,
                "gpu-host",
                conflicting,
                recovery_authorization_id=envelope.authorization_id,
            )
        await session.rollback()

    async with sessions() as session:
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            reclaimed.claims.reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            reclaimed.claims.allocation_group_id,
        )
        reservation.state, group.state = invalid_pair
        if "resetting" in invalid_pair:
            now = datetime.now(timezone.utc)
            reservation.teardown_started_at = now
            group.resetting_at = now
        await session.commit()

    async with sessions() as session:
        with pytest.raises(GpuAllocationError, match="replay is stale or conflicting"):
            await reserve_gpu_group(
                session,
                "gpu-host",
                _request(),
                recovery_authorization_id=envelope.authorization_id,
            )
        await session.rollback()


def _recovery_physical_result(
    operation,
    *,
    succeeded: bool,
) -> GpuPhysicalResultV1:
    source_reader_result = None
    if operation.operation_type == "forced_dead_guest_recovery":
        source_reader_result = GpuSourceReaderResultV1(
            migration_id=operation.migration_id,
            readers_absent=succeeded,
            sources=[
                {
                    "namespace": namespace,
                    "source_path_sha256": digest * 64,
                    "reader_pids": [] if succeeded else [4321],
                }
                for namespace, digest in (("storage", "8"), ("tdx-cache", "9"))
            ],
        )
    return GpuPhysicalResultV1(
        operation_id=operation.operation_id,
        allocation_group_id=operation.allocation_group_id,
        allocation_group_generation=operation.allocation_group_generation,
        reservation_id=operation.reservation_id,
        reservation_generation=operation.reservation_generation,
        claims_sha256=operation.claims_sha256,
        process_incarnation=operation.process_incarnation,
        topology_fingerprint=operation.topology_fingerprint,
        gpu_bdfs=operation.gpu_bdfs,
        gpu_uuids=operation.gpu_uuids,
        qemu_absent=succeeded,
        reset_succeeded=succeeded,
        original_drivers_restored=succeeded,
        source_reader_result=source_reader_result,
        failure_code=None if succeeded else "focused_recovery_reset_failed",
        failure_reason=None if succeeded else "focused physical recovery failure",
        evidence={"postconditions_rechecked": True},
    )


async def _seed_recovery_lifecycle_phase(sessions, recovery_mode: str, phase: str):
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        if recovery_mode == "forced":
            response = await reserve_gpu_group(session, "gpu-host", _request())
            await quarantine_gpu_reservation_control_plane(
                session,
                response.claims.reservation_id,
                code="focused_recovery_reboot",
                reason="focused recovery reboot frontier",
            )
            group = await session.get(GpuAllocationGroup, "allocation-group")
        else:
            group.state = "quarantined"
            group.available_at = None
            group.quarantined_at = datetime.now(timezone.utc)
            group.failure_code = "focused_ownerless_recovery_reboot"
            group.failure_reason = "focused ownerless recovery reboot frontier"
            group.failure_metadata = {}
        envelope = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=group.last_report_id,
                reason="focused recovery reboot authorization",
            ),
            authorized_by="admin",
        )
        operation = await start_gpu_recovery(
            session,
            host,
            envelope.operation.operation_id,
            envelope,
        )
        result = _recovery_physical_result(operation, succeeded=True)
        result_document = result.model_dump(mode="json", exclude_none=True)
        result_sha256 = canonical_sha256(result_document)
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        row.physical_result = result_document
        row.physical_result_sha256 = result_sha256
        row.phase = "physical_result"
        row.reporting_state = "physical_result"
        receipt = None
        ack = None
        if phase in {"receipt_accepted", "local_release_acked"}:
            now = datetime.now(timezone.utc)
            receipt = GpuResetReceiptV1(
                operation_id=operation.operation_id,
                receipt_id=f"recovery-reboot-receipt-{operation.operation_id}",
                result_sha256=result_sha256,
                outcome="accepted",
                local_release_required=True,
                phase="receipt_accepted",
                accepted_at=now,
            )
            row.result_outcome = "accepted"
            row.receipt_id = receipt.receipt_id
            row.receipt_sha256 = canonical_sha256(receipt)
            row.receipt_accepted_at = now
            row.phase = "receipt_accepted"
            row.reporting_state = "receipt_accepted"
            group.state = "release_pending"
            group.resetting_at = None
        if phase == "local_release_acked":
            ack = GpuLocalReleaseAckV1(
                operation_id=operation.operation_id,
                receipt_id=receipt.receipt_id,
                result_sha256=result_sha256,
                allocation_group_id=operation.allocation_group_id,
                allocation_group_generation=operation.allocation_group_generation,
                reservation_id=operation.reservation_id,
                process_incarnation=operation.process_incarnation,
                local_owner_absent=True,
                local_claim_absent=True,
                local_slot_absent=True,
                local_state_sha256="a" * 64,
                observed_at=now,
            )
            row.local_release_ack = ack.model_dump(mode="json", exclude_none=True)
            row.local_release_ack_sha256 = canonical_sha256(row.local_release_ack)
            row.local_release_acked_at = now
            row.phase = "local_release_acked"
            row.reporting_state = "local_release_acked"
        await session.commit()
        return operation, result, receipt, ack, envelope.authorization_id


@pytest.mark.parametrize("recovery_mode", ["ownerless", "forced"])
async def test_same_boot_inventory_preserves_recovery_authorization_report(
    postgres_schema,
    recovery_mode,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, result, _receipt, _ack, authorization_id = (
        await _seed_recovery_lifecycle_phase(
            sessions,
            recovery_mode,
            "physical_result",
        )
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        original_report_id = group.last_report_id
        report = _current_host_report(
            host,
            f"{recovery_mode}-same-boot-recovery-report",
        )
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            report,
        )
        authorization = await session.get(
            GpuRecoveryAuthorization,
            authorization_id,
        )
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        assert reconciled.status == "accepted"
        assert group.state == "resetting"
        assert group.last_report_id == original_report_id
        assert authorization.inventory_report_id == original_report_id
        assert row.phase == "physical_result"
        receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            result,
        )
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            ack,
        )
        assert finalized.group_state == (
            "recovery_required" if recovery_mode == "forced" else "available"
        )
        await session.commit()


@pytest.mark.parametrize("recovery_mode", ["ownerless", "forced"])
@pytest.mark.parametrize(
    "phase", ["physical_result", "receipt_accepted", "local_release_acked"]
)
async def test_post_physical_recovery_resumes_across_boot_and_finalizes(
    postgres_schema,
    recovery_mode,
    phase,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, result, receipt, ack, authorization_id = (
        await _seed_recovery_lifecycle_phase(sessions, recovery_mode, phase)
    )

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        original_report_id = group.last_report_id
        assert await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        ) == 2
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report = _current_host_report(
            host,
            f"{recovery_mode}-{phase}-restart-report",
        )
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            report,
        )
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        assert reconciled.status == "accepted"
        assert group.last_report_id == original_report_id
        await session.commit()

    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        revoked = await session.scalar(
            select(func.count())
            .select_from(GpuRecoveryEvent)
            .where(
                GpuRecoveryEvent.operation_id == operation.operation_id,
                GpuRecoveryEvent.state == "revoked",
            )
        )
        assert row.phase == phase
        assert row.reporting_state == phase
        assert row.failure_code is None
        assert row.finalized_at is None
        assert group.recovery_authorization_id == authorization_id
        assert revoked == 0
        host = await session.get(Host, "gpu-host")
        accepted_receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            result,
        )
        if receipt is not None:
            assert accepted_receipt == receipt
        exact_ack = ack or GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=accepted_receipt.receipt_id,
            result_sha256=accepted_receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="a" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            exact_ack,
        )
        assert finalized.phase == "finalized"
        assert finalized.group_state == (
            "recovery_required" if recovery_mode == "forced" else "available"
        )
        await session.commit()


@pytest.mark.parametrize("recovery_mode", ["ownerless", "forced"])
async def test_failed_recovery_allows_one_fresh_report_successor_and_full_retry(
    postgres_schema,
    recovery_mode,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        if recovery_mode == "forced":
            response = await reserve_gpu_group(session, "gpu-host", _request())
            await quarantine_gpu_reservation_control_plane(
                session,
                response.claims.reservation_id,
                code="focused_dead_guest",
                reason="focused dead guest recovery",
            )
            group = await session.get(GpuAllocationGroup, "allocation-group")
        else:
            group.state = "quarantined"
            group.available_at = None
            group.quarantined_at = datetime.now(timezone.utc)
            group.failure_code = "focused_ownerless"
            group.failure_reason = "focused ownerless recovery"
            group.failure_metadata = {}
        first = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=group.last_report_id,
                reason="focused initial recovery",
            ),
            authorized_by="admin",
        )
        operation = await start_gpu_recovery(
            session,
            host,
            first.operation.operation_id,
            first,
        )
        failed_result = _recovery_physical_result(operation, succeeded=False)
        failed_receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            failed_result,
        )
        assert failed_receipt.outcome == "quarantined"
        old_operation = await session.get(
            GpuLifecycleOperation,
            operation.operation_id,
        )
        old_authorization = await session.get(
            GpuRecoveryAuthorization,
            first.authorization_id,
        )
        old_snapshot = {
            "phase": old_operation.phase,
            "intent": dict(old_operation.intent),
            "physical_result": dict(old_operation.physical_result),
            "physical_result_sha256": old_operation.physical_result_sha256,
            "result_outcome": old_operation.result_outcome,
            "receipt_id": old_operation.receipt_id,
            "receipt_sha256": old_operation.receipt_sha256,
            "failure_code": old_operation.failure_code,
            "authorization_id": old_authorization.authorization_id,
            "authorization_report": old_authorization.inventory_report_id,
            "authorization_nonce_hash": old_authorization.recovery_nonce_hash,
        }
        await session.commit()

    fresh_claims = _report().model_copy(
        update={
            "report_id": f"fresh-{recovery_mode}-recovery-report",
            "report_generation": 2,
        }
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            fresh_claims,
        )
        assert reconciled.status == "quarantined"
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert group.state == "quarantined"
        assert group.last_report_id == fresh_claims.report_id
        assert group.host_key_generation == fresh_claims.host_key_generation
        assert group.host_boot_generation == fresh_claims.host_boot_generation
        await session.commit()

    async def authorize_successor():
        async with sessions() as session:
            successor = await authorize_gpu_recovery(
                session,
                "allocation-group",
                GpuRecoveryAuthorizeRequestV1(
                    report_id=fresh_claims.report_id,
                    reason="focused successor recovery",
                ),
                authorized_by="admin",
            )
            await session.commit()
            return successor

    successor_a, successor_b = await asyncio.gather(
        authorize_successor(),
        authorize_successor(),
    )
    assert successor_a.authorization_id == successor_b.authorization_id
    assert successor_a.operation.operation_id == successor_b.operation.operation_id
    assert successor_a.authorization_id != first.authorization_id
    assert successor_a.operation.operation_id != first.operation.operation_id

    async with sessions() as session:
        old_operation = await session.get(
            GpuLifecycleOperation,
            first.operation.operation_id,
        )
        old_authorization = await session.get(
            GpuRecoveryAuthorization,
            first.authorization_id,
        )
        assert {
            "phase": old_operation.phase,
            "intent": dict(old_operation.intent),
            "physical_result": dict(old_operation.physical_result),
            "physical_result_sha256": old_operation.physical_result_sha256,
            "result_outcome": old_operation.result_outcome,
            "receipt_id": old_operation.receipt_id,
            "receipt_sha256": old_operation.receipt_sha256,
            "failure_code": old_operation.failure_code,
            "authorization_id": old_authorization.authorization_id,
            "authorization_report": old_authorization.inventory_report_id,
            "authorization_nonce_hash": old_authorization.recovery_nonce_hash,
        } == old_snapshot
        host = await session.get(Host, "gpu-host")
        successor_operation = await start_gpu_recovery(
            session,
            host,
            successor_a.operation.operation_id,
            successor_a,
        )
        succeeded_result = _recovery_physical_result(
            successor_operation,
            succeeded=True,
        )
        receipt = await record_gpu_physical_result(
            session,
            host,
            successor_operation.operation_id,
            succeeded_result,
        )
        assert receipt.outcome == "accepted"
        ack = GpuLocalReleaseAckV1(
            operation_id=successor_operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=successor_operation.allocation_group_id,
            allocation_group_generation=(
                successor_operation.allocation_group_generation
            ),
            reservation_id=successor_operation.reservation_id,
            process_incarnation=successor_operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="c" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            successor_operation.operation_id,
            ack,
        )
        assert finalized.phase == "finalized"
        assert finalized.group_state == (
            "recovery_required" if recovery_mode == "forced" else "available"
        )
        finalized_bytes = finalized.model_dump(mode="json")
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        prior_key = await session.get(HostKeyGeneration, ("gpu-host", 1))
        prior_key.revoked_at = datetime.now(timezone.utc)
        prior_key.revocation_reason = "focused replay key rotation"
        session.add(
            HostKeyGeneration(
                host_id="gpu-host",
                generation=2,
                enrollment_generation=2,
                ed25519_public_key="replay-ed25519",
                ed25519_fingerprint="1" * 64,
                x25519_public_key="replay-x25519",
                x25519_fingerprint="2" * 64,
            )
        )
        host.active_key_generation = 2
        host.boot_generation = 2
        host.boot_id = "22222222-2222-2222-2222-222222222222"
        await session.commit()

    async with sessions() as session:
        current_host = await session.get(Host, "gpu-host")
        replayed_receipt = await record_gpu_physical_result(
            session,
            current_host,
            successor_operation.operation_id,
            succeeded_result,
        )
        assert replayed_receipt == receipt
        replayed_final = await record_gpu_local_release_ack(
            session,
            current_host,
            successor_operation.operation_id,
            ack,
        )
        assert replayed_final.model_dump(mode="json") == finalized_bytes
        changed_result = succeeded_result.model_copy(
            update={"evidence": {"postconditions_rechecked": False}}
        )
        with pytest.raises(GpuLifecycleError, match="changed canonical bytes"):
            await record_gpu_physical_result(
                session,
                current_host,
                successor_operation.operation_id,
                changed_result,
            )
        await session.rollback()

    async with sessions() as session:
        current_host = await session.get(Host, "gpu-host")
        changed_ack = ack.model_copy(update={"local_state_sha256": "d" * 64})
        with pytest.raises(GpuLifecycleError, match="changed canonical bytes"):
            await record_gpu_local_release_ack(
                session,
                current_host,
                successor_operation.operation_id,
                changed_ack,
            )
        await session.rollback()


@pytest.mark.parametrize(
    "phase",
    ["intent", "physical_result", "receipt_accepted", "local_release_acked"],
)
async def test_inventory_mismatch_never_releases_reset_journal(
    postgres_schema,
    phase,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation, physical, receipt, ack = await _seed_ordinary_lifecycle_phase(
        sessions,
        phase,
    )

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report_data = _current_host_report(
            host,
            f"reset-{phase}-conflicting-report",
        ).model_dump(mode="json")
        changed_group = dict(report_data["groups"][0])
        changed_group["devices"] = [dict(item) for item in changed_group["devices"]]
        changed_group["devices"][0]["attestation_certificate_sha256"] = "d" * 64
        changed_group.pop("topology_fingerprint", None)
        changed_group["topology_fingerprint"] = canonical_sha256(changed_group)
        report_data["groups"] = [changed_group]
        conflicting_report = GpuInventoryReportV1.model_validate(report_data)
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            conflicting_report,
        )
        assert reconciled.status == "quarantined"
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            operation.reservation_id,
        )
        assert group.state != "available"
        if phase in {"intent", "physical_result"}:
            assert row.phase == "quarantined"
            assert group.state == "quarantined"
            assert reservation.state == "quarantined"
            if phase == "physical_result":
                quarantined_receipt = await record_gpu_physical_result(
                    session,
                    host,
                    operation.operation_id,
                    physical,
                )
                assert quarantined_receipt.outcome == "quarantined"
            await session.rollback()
            return

        assert row.phase == phase
        assert row.failure_code == "gpu_inventory_changed_during_release"
        assert group.state == "release_pending"
        public = await get_gpu_lifecycle_operation(
            session,
            host,
            operation.operation_id,
        )
        assert public.phase == phase
        assert public.failure_code is None
        accepted_receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        )
        assert accepted_receipt == receipt
        exact_ack = ack or GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=accepted_receipt.receipt_id,
            result_sha256=accepted_receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="b" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        terminal = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            exact_ack,
        )
        terminal_bytes = terminal.model_dump(mode="json")
        assert terminal.phase == "quarantined"
        assert terminal.group_state == "quarantined"
        assert (
            await record_gpu_local_release_ack(
                session,
                host,
                operation.operation_id,
                exact_ack,
            )
        ).model_dump(mode="json") == terminal_bytes
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            operation.reservation_id,
        )
        assert group.state == reservation.state == "quarantined"
        await session.commit()


async def _seed_protected_reconciliation_state(sessions, protected_state: str):
    if protected_state == "release_pending":
        operation, _result, _receipt, _ack = await _seed_ordinary_lifecycle_phase(
            sessions,
            "receipt_accepted",
        )
        return operation
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await quarantine_gpu_reservation_control_plane(
            session,
            response.claims.reservation_id,
            code="focused_recovery_required",
            reason="focused forced recovery before inventory reconciliation",
        )
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        envelope = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=group.last_report_id,
                reason="focused forced recovery authorization",
            ),
            authorized_by="admin",
        )
        operation = await start_gpu_recovery(
            session,
            host,
            envelope.operation.operation_id,
            envelope,
        )
        result = _recovery_physical_result(operation, succeeded=True)
        receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            result,
        )
        ack = GpuLocalReleaseAckV1(
            operation_id=operation.operation_id,
            receipt_id=receipt.receipt_id,
            result_sha256=receipt.result_sha256,
            allocation_group_id=operation.allocation_group_id,
            allocation_group_generation=operation.allocation_group_generation,
            reservation_id=operation.reservation_id,
            process_incarnation=operation.process_incarnation,
            local_owner_absent=True,
            local_claim_absent=True,
            local_slot_absent=True,
            local_state_sha256="f" * 64,
            observed_at=datetime.now(timezone.utc),
        )
        finalized = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            ack,
        )
        assert finalized.group_state == "recovery_required"
        await session.commit()
        return operation


@pytest.mark.parametrize("protected_state", ["release_pending", "recovery_required"])
@pytest.mark.parametrize("report_variant", ["exact", "topology", "profile"])
async def test_inventory_reconciliation_cannot_release_protected_lifecycle_state(
    postgres_schema,
    protected_state,
    report_variant,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation = await _seed_protected_reconciliation_state(
        sessions,
        protected_state,
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        original = {
            "generation": group.generation,
            "reservation_id": group.reservation_id,
            "reservation_generation": group.reservation_generation,
            "process_incarnation": group.process_incarnation,
            "last_report_id": group.last_report_id,
            "host_key_generation": group.host_key_generation,
            "host_boot_generation": group.host_boot_generation,
            "gpu_uuids": list(group.gpu_uuids),
            "topology_fingerprint": group.topology_fingerprint,
        }
        await advance_gpu_host_boot(
            session,
            host,
            "22222222-2222-2222-2222-222222222222",
        )
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report_data = _report().model_dump(mode="json")
        report_data.update(
            {
                "report_id": f"{protected_state}-{report_variant}-next-boot",
                "report_generation": int(host.gpu_inventory_report_generation or 0)
                + 1,
                "host_boot_id": host.boot_id,
                "host_boot_generation": host.boot_generation,
            }
        )
        if report_variant != "exact":
            changed_group = _inventory_group()
            changed_group.pop("topology_fingerprint", None)
            if report_variant == "topology":
                changed_group["devices"][0][
                    "attestation_certificate_sha256"
                ] = "f" * 64
            else:
                changed_group["reported_profile_id"] = "unsupported-profile"
            changed_group["topology_fingerprint"] = canonical_sha256(changed_group)
            report_data["groups"] = [changed_group]
        report = GpuInventoryReportV1.model_validate(report_data)
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            report,
        )
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        expected_state = (
            "quarantined"
            if protected_state == "recovery_required" and report_variant != "exact"
            else protected_state
        )
        assert group.state == expected_state
        assert group.available_at is None
        assert group.generation == original["generation"]
        assert group.reservation_id == original["reservation_id"]
        assert group.reservation_generation == original["reservation_generation"]
        assert group.process_incarnation == original["process_incarnation"]
        assert list(group.gpu_uuids) == original["gpu_uuids"]
        assert group.topology_fingerprint == original["topology_fingerprint"]
        if report_variant == "exact":
            assert reconciled.status == "accepted"
            if protected_state == "release_pending":
                assert group.last_report_id == original["last_report_id"]
                assert group.host_key_generation == original["host_key_generation"]
                assert group.host_boot_generation == original["host_boot_generation"]
                assert row.phase == "receipt_accepted"
            else:
                assert group.last_report_id == report.report_id
                assert group.host_key_generation == report.host_key_generation
                assert group.host_boot_generation == report.host_boot_generation
                assert row.phase == "finalized"
        else:
            assert reconciled.status == "quarantined"
            assert group.last_report_id == original["last_report_id"]
            assert group.host_key_generation == original["host_key_generation"]
            assert group.host_boot_generation == original["host_boot_generation"]
            if protected_state == "recovery_required":
                assert group.failure_code == "gpu_inventory_changed_during_release"
                assert row.phase == "finalized"
                assert await session.scalar(
                    select(func.count())
                    .select_from(GpuRecoveryEvent)
                    .where(
                        GpuRecoveryEvent.operation_id == operation.operation_id,
                        GpuRecoveryEvent.state == "revoked",
                    )
                ) == 1
        await session.commit()


@pytest.mark.parametrize("newer_variant", ["exact", "conflicting"])
async def test_unstarted_recovery_requires_latest_inventory_and_allows_successor(
    postgres_schema,
    newer_variant,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        group.state = "quarantined"
        group.available_at = None
        group.quarantined_at = datetime.now(timezone.utc)
        group.failure_code = "focused_unstarted_recovery"
        group.failure_reason = "focused unstarted recovery"
        group.failure_metadata = {}
        first = await authorize_gpu_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=group.last_report_id,
                reason="focused initial authorization",
            ),
            authorized_by="admin",
        )
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report_data = _current_host_report(
            host,
            f"unstarted-{newer_variant}-report",
        ).model_dump(mode="json")
        if newer_variant == "conflicting":
            changed_group = dict(report_data["groups"][0])
            changed_group["devices"] = [
                dict(item) for item in changed_group["devices"]
            ]
            changed_group["devices"][0]["attestation_certificate_sha256"] = "f" * 64
            changed_group.pop("topology_fingerprint", None)
            changed_group["topology_fingerprint"] = canonical_sha256(changed_group)
            report_data["groups"] = [changed_group]
        newer_report = GpuInventoryReportV1.model_validate(report_data)
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            newer_report,
        )
        assert reconciled.status == "quarantined"
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        with pytest.raises(GpuLifecycleError, match="current host-signed inventory"):
            await start_gpu_recovery(
                session,
                host,
                first.operation.operation_id,
                first,
            )
        await session.rollback()

    successor_report = newer_report
    if newer_variant == "conflicting":
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            successor_report = _current_host_report(
                host,
                "unstarted-conflicting-fresh-exact-report",
            )
            reconciled = await gpu_allocations.reconcile_gpu_inventory(
                session,
                host,
                successor_report,
            )
            assert reconciled.status == "quarantined"
            await session.commit()

    async with sessions() as session:
        successor = await authorize_gpu_recovery(
            session,
            "allocation-group",
            GpuRecoveryAuthorizeRequestV1(
                report_id=successor_report.report_id,
                reason="focused latest-report successor",
            ),
            authorized_by="admin",
        )
        assert successor.authorization_id != first.authorization_id
        assert successor.operation.operation_id != first.operation.operation_id
        old_operation = await session.get(
            GpuLifecycleOperation,
            first.operation.operation_id,
        )
        assert old_operation.phase == "quarantined"
        assert old_operation.failure_code == "gpu_recovery_inventory_superseded"
        assert await session.scalar(
            select(func.count())
            .select_from(GpuRecoveryEvent)
            .where(
                GpuRecoveryEvent.operation_id == first.operation.operation_id,
                GpuRecoveryEvent.state == "revoked",
            )
        ) == 1
        assert await session.scalar(
            select(func.count())
            .select_from(GpuRecoveryEvent)
            .where(
                GpuRecoveryEvent.operation_id == first.operation.operation_id,
                GpuRecoveryEvent.state == "started",
            )
        ) == 0
        await session.commit()


async def test_completed_recovery_invalidation_keeps_terminal_replay_immutable(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    operation = await _seed_protected_reconciliation_state(
        sessions,
        "recovery_required",
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        original_report_id = group.last_report_id
        physical = GpuPhysicalResultV1.model_validate(row.physical_result)
        ack = GpuLocalReleaseAckV1.model_validate(row.local_release_ack)
        terminal = await get_gpu_lifecycle_operation(
            session,
            host,
            operation.operation_id,
        )
        receipt = await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        )
        terminal = await record_gpu_local_release_ack(
            session,
            host,
            operation.operation_id,
            ack,
        )
        terminal_bytes = terminal.model_dump(mode="json")
        row_snapshot = {
            "phase": row.phase,
            "reporting_state": row.reporting_state,
            "physical_result": dict(row.physical_result),
            "physical_result_sha256": row.physical_result_sha256,
            "receipt_id": row.receipt_id,
            "receipt_sha256": row.receipt_sha256,
            "local_release_ack": dict(row.local_release_ack),
            "local_release_ack_sha256": row.local_release_ack_sha256,
            "failure_code": row.failure_code,
            "failure_reason": row.failure_reason,
            "finalized_at": row.finalized_at,
        }
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        report_data = _current_host_report(
            host,
            "completed-recovery-conflicting-report",
        ).model_dump(mode="json")
        changed_group = dict(report_data["groups"][0])
        changed_group["devices"] = [dict(item) for item in changed_group["devices"]]
        changed_group["devices"][0]["attestation_certificate_sha256"] = "e" * 64
        changed_group.pop("topology_fingerprint", None)
        changed_group["topology_fingerprint"] = canonical_sha256(changed_group)
        report_data["groups"] = [changed_group]
        conflicting_report = GpuInventoryReportV1.model_validate(report_data)
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            conflicting_report,
        )
        assert reconciled.status == "quarantined"
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        assert {
            "phase": row.phase,
            "reporting_state": row.reporting_state,
            "physical_result": dict(row.physical_result),
            "physical_result_sha256": row.physical_result_sha256,
            "receipt_id": row.receipt_id,
            "receipt_sha256": row.receipt_sha256,
            "local_release_ack": dict(row.local_release_ack),
            "local_release_ack_sha256": row.local_release_ack_sha256,
            "failure_code": row.failure_code,
            "failure_reason": row.failure_reason,
            "finalized_at": row.finalized_at,
        } == row_snapshot
        assert group.state == "quarantined"
        assert group.recovery_authorization_id == operation.recovery_authorization_id
        assert await session.scalar(
            select(func.count())
            .select_from(GpuRecoveryEvent)
            .where(
                GpuRecoveryEvent.operation_id == operation.operation_id,
                GpuRecoveryEvent.state == "completed",
            )
        ) == 1
        assert await session.scalar(
            select(func.count())
            .select_from(GpuRecoveryEvent)
            .where(
                GpuRecoveryEvent.operation_id == operation.operation_id,
                GpuRecoveryEvent.state == "revoked",
            )
        ) == 1
        assert (
            await get_gpu_lifecycle_operation(session, host, operation.operation_id)
        ).model_dump(mode="json") == terminal_bytes
        assert await record_gpu_physical_result(
            session,
            host,
            operation.operation_id,
            physical,
        ) == receipt
        assert (
            await record_gpu_local_release_ack(
                session,
                host,
                operation.operation_id,
                ack,
            )
        ).model_dump(mode="json") == terminal_bytes
        with pytest.raises(GpuLifecycleError, match="current host-signed inventory"):
            await authorize_gpu_recovery(
                session,
                group.allocation_group_id,
                GpuRecoveryAuthorizeRequestV1(
                    report_id=original_report_id,
                    reason="stale completed recovery report",
                ),
                authorized_by="admin",
            )
        await session.rollback()

    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        fresh_report = _current_host_report(
            host,
            "completed-recovery-fresh-exact-report",
        )
        reconciled = await gpu_allocations.reconcile_gpu_inventory(
            session,
            host,
            fresh_report,
        )
        assert reconciled.status == "quarantined"
        await session.commit()

    async with sessions() as session:
        successor = await authorize_gpu_recovery(
            session,
            operation.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=fresh_report.report_id,
                reason="fresh successor after completed invalidation",
            ),
            authorized_by="admin",
        )
        assert successor.authorization_id != operation.recovery_authorization_id
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        assert row.phase == "finalized"
        assert row.failure_code is None
        await session.commit()


async def test_lost_claim_response_retries_exactly_but_stale_boot_fails_closed(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await session.commit()
    claim = GpuReservationClaimRequestV1(
        token=response.token,
        claims_sha256=response.claims_sha256,
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        claims = await claim_gpu_reservation(session, host, claim)
        assert claims.management_mode == "miner"
        await session.commit()
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        retried = await claim_gpu_reservation(session, host, claim)
        assert retried == response.claims
        await session.commit()
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        with pytest.raises(GpuAllocationError, match="expired, consumed, stale"):
            await claim_gpu_reservation(
                session,
                host,
                GpuReservationClaimRequestV1(
                    token=response.token,
                    claims_sha256="f" * 64,
                ),
            )
        await session.rollback()

    async with sessions() as session:
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        reservation.state = "reserved"
        reservation.claimed_at = None
        host = await session.get(Host, "gpu-host")
        host.boot_generation = 2
        await session.commit()
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        with pytest.raises(GpuAllocationError, match="stale"):
            await claim_gpu_reservation(session, host, claim)
        await session.rollback()


async def test_claim_boot_advance_and_expiry_share_deadlock_free_lock_order(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await session.commit()

    async def claim():
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            try:
                await claim_gpu_reservation(
                    session,
                    host,
                    GpuReservationClaimRequestV1(
                        token=response.token,
                        claims_sha256=response.claims_sha256,
                    ),
                )
                await session.commit()
                return "claimed"
            except GpuAllocationError:
                await session.rollback()
                return "rejected"

    async def boot():
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            await advance_gpu_host_boot(
                session,
                host,
                "33333333-3333-3333-3333-333333333333",
            )
            await session.commit()
            return "booted"

    results = await asyncio.wait_for(asyncio.gather(claim(), boot()), timeout=10)
    assert "booted" in results
    async with sessions() as session:
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert (row.state, group.state) in {
            ("quarantined", "quarantined"),
            ("expired", "retired"),
        }


async def test_global_gpu_lifecycle_lock_serializes_opposite_row_orders(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(
            session,
            "gpu-host",
            _request(),
        )
        await session.commit()

    async def lock_rows(first, second):
        async with sessions() as session:
            await acquire_gpu_lifecycle_lock(session)
            await session.execute(first.with_for_update())
            await asyncio.sleep(0.05)
            await session.execute(second.with_for_update())
            await session.commit()

    reservation_query = select(gpu_allocations.GpuLaunchReservation).where(
        gpu_allocations.GpuLaunchReservation.reservation_id
        == response.claims.reservation_id
    )
    group_query = select(GpuAllocationGroup).where(
        GpuAllocationGroup.allocation_group_id == response.claims.allocation_group_id
    )
    await asyncio.wait_for(
        asyncio.gather(
            lock_rows(reservation_query, group_query),
            lock_rows(group_query, reservation_query),
        ),
        timeout=5,
    )


async def test_launch_config_claim_vs_gpu_teardown_has_no_deadlock(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(
            session,
            "gpu-host",
            _request(),
        )
        user = User(
            user_id="launch-user",
            coldkey="launch-coldkey",
            username="launch-user",
            fingerprint_hash="launch-fingerprint",
        )
        image = Image(
            image_id="launch-image",
            artifact_id="launch-artifact",
            user_id=user.user_id,
            name="launch-image",
            tag="v1",
            compute_type="gpu",
        )
        chute = Chute(
            chute_id="launch-chute",
            user_id=user.user_id,
            image_id=image.image_id,
            name="launch-chute",
            cords=[],
            node_selector=NodeSelector(
                compute_type="gpu",
                gpu_count=8,
            ),
            code="from chutes import Chute",
            filename="launch.py",
            ref_str="launch:launch",
            version="v1",
        )
        server = Server(
            server_id=response.claims.server_id,
            ip="192.0.2.20",
            miner_hotkey="owner",
            name=response.claims.server_id,
            compute_type="gpu",
            tee_type="tdx",
            self_registered=True,
            gpu_launch_reservation_id=response.claims.reservation_id,
            gpu_allocation_group_id=response.claims.allocation_group_id,
            gpu_allocation_group_generation=(
                response.claims.allocation_group_generation
            ),
            gpu_management_mode="miner",
            gpu_process_incarnation=response.claims.process_incarnation,
            gpu_topology_fingerprint=(response.claims.topology_fingerprint),
        )
        config = LaunchConfig(
            config_id="claim-vs-teardown",
            seed=0,
            env_key="env-key",
            chute_id=chute.chute_id,
            user_id=user.user_id,
            compute_type="gpu",
            default_volume_id="claim-vs-teardown-volume",
            storage_session_exchange_allowed=True,
            miner_uid=1,
            miner_hotkey="owner",
            miner_coldkey="coldkey",
            server_id=server.server_id,
            gpu_management_mode="miner",
            gpu_launch_reservation_id=response.claims.reservation_id,
        )
        session.add(user)
        await session.flush()
        image.user_id = user.user_id
        chute.user_id = user.user_id
        config.user_id = user.user_id
        session.add(image)
        await session.flush()
        session.add(chute)
        await session.flush()
        session.add(
            StorageVolume(
                volume_id="claim-vs-teardown-volume",
                user_id=user.user_id,
                name="claim-vs-teardown-volume",
                replication_factor=1,
                quota_bytes=1024,
                used_bytes=0,
            )
        )
        await session.flush()
        session.add_all(
            [
                StorageVolumeKey(
                    volume_id="claim-vs-teardown-volume",
                    encrypted_key="test-key",
                ),
                DefaultChuteFSVolumeBinding(
                    user_id=user.user_id,
                    chute_id=chute.chute_id,
                    volume_id="claim-vs-teardown-volume",
                ),
            ]
        )
        await session.flush()
        session.add(server)
        await session.flush()
        session.add(config)
        await session.commit()
        launch_user_id = config.user_id

    async def claim():
        async with sessions() as session:
            with patch(
                "api.instance.util._decode_chutes_jwt",
                return_value={
                    "sub": "claim-vs-teardown",
                    "user_id": launch_user_id,
                    "chute_id": "launch-chute",
                    "job_id": None,
                    "compute_type": "gpu",
                    "management_mode": "miner",
                    "server_id": response.claims.server_id,
                    "instance_id": None,
                    "default_volume_id": "claim-vs-teardown-volume",
                    "env_type": None,
                    "storage_session_exchange_allowed": True,
                    "permissions": ["storage_session:exchange"],
                },
            ):
                config = await load_launch_config_from_jwt(
                    session,
                    "claim-vs-teardown",
                    "token",
                )
                await asyncio.sleep(0.05)
                await session.commit()
                return config.config_id

    async def teardown():
        await asyncio.sleep(0.01)
        async with sessions() as session:
            await quarantine_gpu_reservation_control_plane(
                session,
                response.claims.reservation_id,
                code="claim_vs_teardown",
                reason="concurrent teardown probe",
            )
            await session.commit()
            return "torn-down"

    results = await asyncio.wait_for(
        asyncio.gather(claim(), teardown()),
        timeout=10,
    )
    assert results == ["claim-vs-teardown", "torn-down"]
    async with sessions() as session:
        config = await session.get(
            LaunchConfig,
            "claim-vs-teardown",
        )
        assert config.retrieved_at is not None
        assert config.failed_at is not None
        assert "concurrent teardown probe" in config.verification_error


async def test_request_level_auth_vs_reserve_has_no_deadlock(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)

    async def authenticate_request():
        async with sessions() as session:
            await acquire_gpu_lifecycle_lock(session)
            await session.execute(
                select(Host).where(Host.host_id == "gpu-host").with_for_update()
            )
            await asyncio.sleep(0.05)
            await session.commit()
            return "authenticated"

    async def reserve_request():
        async with sessions() as session:
            result = await reserve_gpu_group(session, "gpu-host", _request())
            await session.commit()
            return result.claims.reservation_id

    results = await asyncio.wait_for(
        asyncio.gather(authenticate_request(), reserve_request()),
        timeout=10,
    )
    assert "authenticated" in results


async def test_request_level_enrollment_vs_claim_has_no_deadlock(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await session.commit()

    async def reenrollment_request():
        async with sessions() as session:
            await acquire_gpu_lifecycle_lock(session)
            await session.execute(
                select(HostKeyGeneration)
                .where(HostKeyGeneration.host_id == "gpu-host")
                .with_for_update()
            )
            await session.execute(
                select(Host).where(Host.host_id == "gpu-host").with_for_update()
            )
            await asyncio.sleep(0.05)
            await session.commit()
            return "enrollment"

    async def claim_request():
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            try:
                await claim_gpu_reservation(
                    session,
                    host,
                    GpuReservationClaimRequestV1(
                        token=response.token,
                        claims_sha256=response.claims_sha256,
                    ),
                )
                await session.commit()
                return "claimed"
            except GpuAllocationError:
                await session.rollback()
                return "fenced"

    results = await asyncio.wait_for(
        asyncio.gather(reenrollment_request(), claim_request()),
        timeout=10,
    )
    assert "enrollment" in results


async def test_request_level_release_activation_vs_inventory_has_no_deadlock(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)

    async def release_composition():
        async with sessions() as session:
            await release_service._lock_release_streams(
                session,
                channel="gpu-test",
                tee_type="tdx",
                compute_type="gpu",
            )
            await asyncio.sleep(0.05)
            await session.commit()
            return "release"

    async def inventory_reconcile_locking():
        async with sessions() as session:
            host = await _host_lock(session, "gpu-host")
            await _active_gpu_release(session, host)
            await session.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.host_id == "gpu-host")
                .with_for_update()
            )
            await session.commit()
            return "inventory"

    assert set(
        await asyncio.wait_for(
            asyncio.gather(
                release_composition(),
                inventory_reconcile_locking(),
            ),
            timeout=10,
        )
    ) == {"release", "inventory"}


async def test_mode_device_and_profile_tamper_never_claims_group(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await session.commit()
    reservation_id = response.claims.reservation_id
    original = response.claims.model_dump(mode="json", exclude_none=True)
    mutations = (
        {"management_mode": "platform"},
        {"gpu_bdfs": BDFS[:-1]},
        {"gpu_profile_id": "other-profile"},
    )
    for mutation in mutations:
        async with sessions() as session:
            row = await session.get(
                gpu_allocations.GpuLaunchReservation,
                reservation_id,
            )
            row.claims = {**original, **mutation}
            await session.commit()
        async with sessions() as session:
            host = await session.get(Host, "gpu-host")
            with pytest.raises(GpuAllocationError, match="claims"):
                await claim_gpu_reservation(
                    session,
                    host,
                    GpuReservationClaimRequestV1(
                        token=response.token,
                        claims_sha256=response.claims_sha256,
                    ),
                )
            await session.rollback()
        async with sessions() as session:
            row = await session.get(
                gpu_allocations.GpuLaunchReservation,
                reservation_id,
            )
            row.claims = original
            await session.commit()


async def test_expiry_before_claim_releases_but_after_claim_quarantines(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        before = await reserve_gpu_group(session, "gpu-host", _request())
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            before.claims.reservation_id,
        )
        row.issued_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await _expire_locked_reservations(session, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert row.state == "expired"
        assert group.state == "available"
        await session.commit()

    async with sessions() as session:
        after = await reserve_gpu_group(
            session, "gpu-host", _request("gpu-after", "gpu-after")
        )
        await session.commit()
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=after.token,
                claims_sha256=after.claims_sha256,
            ),
        )
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            after.claims.reservation_id,
        )
        row.issued_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await _expire_locked_reservations(session, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        operation = await session.scalar(
            select(GpuLifecycleOperation).where(
                GpuLifecycleOperation.reservation_id == row.reservation_id,
                GpuLifecycleOperation.operation_type == "launch_rollback",
            )
        )
        assert row.state == "resetting"
        assert group.state == "resetting"
        assert operation is not None
        assert operation.phase == "intent"
        await session.commit()


async def test_running_and_resetting_ignore_launch_token_expiry(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        row.state = "running"
        row.claimed_at = datetime.now(timezone.utc) - timedelta(hours=2)
        row.guest_consumed_at = datetime.now(timezone.utc) - timedelta(hours=2)
        row.running_at = datetime.now(timezone.utc) - timedelta(hours=2)
        row.issued_at = datetime.now(timezone.utc) - timedelta(hours=3)
        row.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
        group.state = "running"
        group.running_at = row.running_at
        await _expire_locked_reservations(session, "gpu-host")
        assert row.state == "running"
        assert group.state == "running"
        row.state = "resetting"
        group.state = "resetting"
        await _expire_locked_reservations(session, "gpu-host")
        assert row.state == "resetting"
        assert group.state == "resetting"
        await session.commit()


async def test_miner_chutefs_session_rechecks_gpu_lineage_and_latest_attempt(
    postgres_schema,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        claims = response.claims
        now = datetime.now(timezone.utc)
        user_id = "storage-launch-user"
        await session.execute(
            User.__table__.insert().values(
                user_id=user_id,
                coldkey="storage-launch-cold",
                username="storlaunch",
                fingerprint_hash="storage-launch-fingerprint",
            )
        )
        image = Image(
            image_id="storage-launch-image",
            artifact_id="storage-launch-artifact",
            user_id=user_id,
            name="storage-launch-image",
            tag="v1",
            compute_type="gpu",
        )
        chute = Chute(
            chute_id="storage-launch-chute",
            user_id=user_id,
            image_id=image.image_id,
            name="storage-launch-chute",
            cords=[],
            node_selector=NodeSelector(compute_type="gpu", gpu_count=8),
            code="from chutes import Chute",
            filename="launch.py",
            ref_str="launch:launch",
            version="v1",
            tee=True,
        )
        volume = StorageVolume(
            volume_id="storage-launch-volume",
            user_id=user_id,
            name="storage-launch-volume",
            replication_factor=3,
            quota_bytes=1024**3,
            used_bytes=0,
        )
        session.add(image)
        await session.flush()
        session.add_all([chute, volume])
        await session.flush()
        session.add_all(
            [
                StorageVolumeKey(
                    volume_id=volume.volume_id,
                    encrypted_key="test-key",
                ),
                DefaultChuteFSVolumeBinding(
                    user_id=user_id,
                    chute_id=chute.chute_id,
                    volume_id=volume.volume_id,
                ),
            ]
        )
        server = Server(
            server_id=claims.server_id,
            netuid=64,
            name=claims.server_id,
            ip="192.0.2.61",
            miner_hotkey=claims.owner_hotkey,
            is_tee=True,
            self_registered=True,
            compute_type="gpu",
            tee_type="tdx",
            host_id=claims.host_id,
            storage_role=False,
            version=claims.image_version,
            measurement_name=claims.measurement_name,
            measurement_config_fingerprint="a" * 64,
            trust_set_fingerprint="b" * 64,
            attestation_revocation_status={},
            attested_cert_pubkey_hash="e" * 64,
            gpu_launch_reservation_id=claims.reservation_id,
            gpu_allocation_group_id=claims.allocation_group_id,
            gpu_allocation_group_generation=claims.allocation_group_generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=claims.process_incarnation,
            gpu_topology_fingerprint=claims.topology_fingerprint,
        )
        session.add(server)
        await session.flush()
        attestation = ServerAttestation(
            quote_data="quote",
            server_id=claims.server_id,
            created_at=now,
            verified_at=now,
            measurement_version=claims.image_version,
            measurement_name=claims.measurement_name,
            measurement_config_fingerprint="a" * 64,
            trust_set_fingerprint="b" * 64,
            revocation_status={},
            gpu_launch_reservation_id=claims.reservation_id,
            gpu_allocation_group_id=claims.allocation_group_id,
            gpu_allocation_group_generation=claims.allocation_group_generation,
            gpu_host_boot_generation=claims.host_boot_generation,
            gpu_reservation_generation=claims.reservation_generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=claims.process_incarnation,
            gpu_topology_fingerprint=claims.topology_fingerprint,
            gpu_release_id=claims.gpu_release_id,
            gpu_profile_id=claims.gpu_profile_id,
            gpu_claims_sha256=response.claims_sha256,
            gpu_evidence={"raw": []},
            gpu_evidence_sha256="c" * 64,
            gpu_evidence_certificate_sha256s=(
                claims.gpu_attestation_certificate_sha256s
            ),
        )
        session.add(attestation)
        await session.flush()
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, claims.allocation_group_id)
        reservation.state = "running"
        reservation.guest_consumed_at = now
        reservation.running_at = now
        reservation.registration_attestation_id = attestation.attestation_id
        group.state = "running"
        group.management_mode = "miner"
        group.reservation_owner = claims.owner_hotkey
        group.reservation_id = claims.reservation_id
        group.process_incarnation = claims.process_incarnation
        group.running_at = now
        server.gpu_runtime_session_attestation_id = attestation.attestation_id
        server.gpu_runtime_session_expires_at = now + timedelta(minutes=15)
        config = LaunchConfig(
            config_id="storage-launch-config",
            seed=0,
            env_key="env-key",
            chute_id=chute.chute_id,
            user_id=user_id,
            compute_type="gpu",
            default_volume_id=volume.volume_id,
            storage_session_exchange_allowed=True,
            miner_uid=1,
            miner_hotkey=claims.owner_hotkey,
            miner_coldkey="coldkey",
            server_id=server.server_id,
            gpu_management_mode="miner",
            gpu_launch_reservation_id=reservation.reservation_id,
            verified_at=now.replace(tzinfo=None),
        )
        instance = Instance(
            instance_id="storage-launch-instance",
            host=server.ip,
            port=8000,
            chute_id=chute.chute_id,
            version=chute.version,
            miner_uid=1,
            miner_hotkey=claims.owner_hotkey,
            miner_coldkey="coldkey",
            active=True,
            verified=True,
            activated_at=now,
            config_id=config.config_id,
            server_id=server.server_id,
            gpu_management_mode="miner",
            gpu_launch_reservation_id=reservation.reservation_id,
            gpu_allocation_group_id=reservation.allocation_group_id,
            gpu_allocation_group_generation=reservation.allocation_group_generation,
            gpu_process_incarnation=reservation.process_incarnation,
        )
        session.add_all([config, instance])
        await session.commit()

        monkeypatch.setattr(
            launch_sessions,
            "_require_not_disabled",
            AsyncMock(return_value=None),
        )
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/storage/default-volume",
                "headers": [],
            }
        )
        context, issued = await launch_sessions.issue_launch_storage_session(
            session,
            config.config_id,
            request,
        )
        assert context.management_mode == "miner"
        assert (
            await launch_sessions.authorize_default_volume(
                session,
                f"Bearer {issued.access_token}",
                request,
                "list",
            )
        ).instance.instance_id == instance.instance_id

        group.state = "resetting"
        await session.commit()
        with pytest.raises(HTTPException, match="reservation or allocation"):
            await launch_sessions.authorize_default_volume(
                session,
                f"Bearer {issued.access_token}",
                request,
                "list",
            )
        group.state = "running"
        session.add(
            ServerAttestation(
                server_id=server.server_id,
                verification_error="forced latest failure",
                created_at=now + timedelta(seconds=1),
            )
        )
        await session.commit()
        with pytest.raises(HTTPException, match="latest GPU attestation"):
            await launch_sessions.authorize_default_volume(
                session,
                f"Bearer {issued.access_token}",
                request,
                "list",
            )


async def _prepare_registration_request(session, mode: str):
    if mode == "platform":
        response = await _reserve_platform_group(session)
        selected_uuids = list(response.claims.gpu_uuids)
    else:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        selected_uuids = list(response.claims.gpu_uuids[:2])
    host = await session.get(Host, "gpu-host")
    await claim_gpu_reservation(
        session,
        host,
        GpuReservationClaimRequestV1(
            token=response.token,
            claims_sha256=response.claims_sha256,
        ),
    )
    reservation = await session.get(
        gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
    )
    group = await session.get(GpuAllocationGroup, response.claims.allocation_group_id)
    now = datetime.now(timezone.utc)
    reservation.state = "launching"
    reservation.launching_at = now
    group.state = "launching"
    group.launching_at = now
    cert_pem = f"fixture-{mode}-registration-certificate"
    spki_sha256 = "e" * 64
    nonce_value = "12" * 32
    nonce = GpuRegistrationNonce(
        nonce_id=f"{mode}-registration-nonce",
        client_request_id=f"{mode}-registration-request",
        request_generation=1,
        peer_spki_sha256=spki_sha256,
        reservation_id=reservation.reservation_id,
        server_ip="192.0.2.30",
        nonce_value=nonce_value,
        nonce_hash=hashlib.sha256(bytes.fromhex(nonce_value)).hexdigest(),
        state="issued",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    commitment = GpuQuoteCommitmentV1(
        reservation_sha256=response.claims_sha256,
        release_target_sha256=response.claims.release_target_sha256,
        launch_nonce=response.claims.launch_nonce,
        attested_spki_sha256=spki_sha256,
        claims=response.claims,
    )
    request = GpuRegistrationRequestV2(
        nonce_id=nonce.nonce_id,
        nonce=nonce_value,
        server_id=response.claims.server_id,
        quote=f"{mode}-registration-quote",
        gpu_evidence=[{"device": item} for item in selected_uuids],
        gpu_uuids=selected_uuids,
        launch_reservation=response.token,
        quote_commitment=commitment,
        td_signature=f"{mode}-registration-signature",
    )
    session.add(nonce)
    await session.flush()
    return response, request, cert_pem, spki_sha256


def _registration_competitor(
    primary: GpuRegistrationRequestV2,
    *,
    spki_sha256: str,
    suffix: str,
) -> GpuRegistrationRequestV2:
    commitment = primary.quote_commitment.model_dump(mode="json")
    commitment["attested_spki_sha256"] = spki_sha256
    return GpuRegistrationRequestV2.model_validate(
        {
            **primary.model_dump(mode="json"),
            "quote": f"competitor-{suffix}-quote",
            "gpu_evidence": [
                {"competitor": suffix, "device": item} for item in primary.gpu_uuids
            ],
            "quote_commitment": commitment,
            "td_signature": f"competitor-{suffix}-signature",
        }
    )


async def _publish_completed_registration_fixture(
    session,
    response,
    request,
    cert_pem: str,
    spki_sha256: str,
):
    reservation = await session.get(
        gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
    )
    group = await session.get(GpuAllocationGroup, response.claims.allocation_group_id)
    now = datetime.now(timezone.utc)
    server = Server(
        server_id=reservation.server_id,
        ip="192.0.2.30",
        miner_hotkey=reservation.owner_hotkey,
        name=reservation.server_id,
        netuid=64,
        is_tee=True,
        compute_type="gpu",
        tee_type="tdx",
        host_id=reservation.host_id,
        gpu_launch_reservation_id=reservation.reservation_id,
        gpu_allocation_group_id=reservation.allocation_group_id,
        gpu_allocation_group_generation=reservation.allocation_group_generation,
        gpu_management_mode=reservation.management_mode,
        gpu_process_incarnation=reservation.process_incarnation,
        gpu_topology_fingerprint=reservation.topology_fingerprint,
        attested_cert=cert_pem,
        attested_cert_pubkey_hash=spki_sha256,
        version=response.claims.image_version,
        measurement_name=response.claims.measurement_name,
        measurement_config_fingerprint="a" * 64,
        trust_set_fingerprint="b" * 64,
        attestation_revocation_status={},
    )
    session.add(server)
    await session.flush()
    selected_identifiers = []
    inventory_by_uuid = {
        gpu_uuid: identifier
        for gpu_uuid, identifier in zip(
            reservation.gpu_uuids, reservation.gpu_identifiers, strict=True
        )
    }
    for gpu_uuid in request.gpu_uuids:
        index = reservation.gpu_uuids.index(gpu_uuid)
        gpu_identifier = inventory_by_uuid[gpu_uuid]
        selected_identifiers.append(gpu_identifier)
        session.add(
            Node(
                uuid=gpu_uuid,
                name=f"NVIDIA B200 {index}",
                memory=192_000_000_000,
                processors=148,
                clock_rate=1_590_000.0,
                max_threads_per_processor=1024,
                concurrent_kernels=True,
                ecc=True,
                seed=index + 1,
                miner_hotkey=reservation.owner_hotkey,
                gpu_identifier=gpu_identifier,
                device_index=index,
                server_id=server.server_id,
                verification_host="127.0.0.1",
                verification_port=8000 + index,
                gpu_allocation_group_id=reservation.allocation_group_id,
                gpu_allocation_group_generation=reservation.allocation_group_generation,
                gpu_launch_reservation_id=reservation.reservation_id,
                gpu_process_incarnation=reservation.process_incarnation,
                gpu_inventory_report_id=group.last_report_id,
            )
        )
    attestation = ServerAttestation(
        quote_data=request.quote,
        server_id=server.server_id,
        created_at=now,
        verified_at=now,
        measurement_version=response.claims.image_version,
        measurement_name=response.claims.measurement_name,
        measurement_config_fingerprint="a" * 64,
        trust_set_fingerprint="b" * 64,
        revocation_status={},
        gpu_launch_reservation_id=reservation.reservation_id,
        gpu_allocation_group_id=reservation.allocation_group_id,
        gpu_allocation_group_generation=reservation.allocation_group_generation,
        gpu_host_boot_generation=reservation.host_boot_generation,
        gpu_reservation_generation=reservation.reservation_generation,
        gpu_management_mode=reservation.management_mode,
        gpu_process_incarnation=reservation.process_incarnation,
        gpu_topology_fingerprint=reservation.topology_fingerprint,
        gpu_release_id=reservation.gpu_release_id,
        gpu_profile_id=reservation.profile_id,
        gpu_claims_sha256=reservation.claims_sha256,
        gpu_evidence={"raw": request.gpu_evidence},
        gpu_evidence_sha256=canonical_sha256({"raw": request.gpu_evidence}),
        gpu_evidence_certificate_sha256s=[
            reservation.gpu_attestation_certificate_sha256s[
                reservation.gpu_uuids.index(gpu_uuid)
            ]
            for gpu_uuid in request.gpu_uuids
        ],
    )
    session.add(attestation)
    await session.flush()
    reservation.guest_consumed_at = now
    reservation.registration_attestation_id = attestation.attestation_id
    reservation.state = "running"
    reservation.running_at = now
    group.state = "running"
    group.running_at = now
    group.updated_at = now
    return {
        "server_id": server.server_id,
        "owner_hotkey": reservation.owner_hotkey,
        "reservation_id": reservation.reservation_id,
        "claims_sha256": reservation.claims_sha256,
        "allocation_group_id": group.allocation_group_id,
        "allocation_group_generation": group.generation,
        "process_incarnation": reservation.process_incarnation,
        "gpu_uuids": list(request.gpu_uuids),
        "gpu_identifiers": selected_identifiers,
        "management_mode": reservation.management_mode,
        "measurement_version": response.claims.image_version,
        "measurement_name": response.claims.measurement_name,
        "measurement_config_fingerprint": "a" * 64,
        "trust_set_fingerprint": "b" * 64,
        "attestation_id": attestation.attestation_id,
        "verified_at": now.isoformat(),
        "status": "registered",
    }


@pytest.mark.parametrize("mode", ["platform", "miner"])
async def test_registration_claim_and_completed_replay_preserve_mode_owners(
    postgres_schema, mode
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, mode
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            request,
            spki_sha256,
            cert_pem,
        )
        assert lease_owner is not None
        assert conflict is None
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert reservation.owner_hotkey == "owner"
        assert group.reservation_owner == reservation.workload_owner
        if mode == "platform":
            assert reservation.workload_owner == "platform-workload-owner"
            assert group.reservation_owner != reservation.owner_hotkey
        else:
            assert reservation.workload_owner == reservation.owner_hotkey
        result = await _publish_completed_registration_fixture(
            session, response, request, cert_pem, spki_sha256
        )
        completed = await _complete_attempt(
            session, attempt.attempt_id, lease_owner, result
        )
        await session.commit()
        assert (
            completed.registration_replay_until - completed.completed_at
            == timedelta(minutes=15)
        )
        assert completed.registration_replay_until > reservation.expires_at

    async with sessions() as session:
        attempt = await session.get(GpuRegistrationAttempt, attempt.attempt_id)
        runtime_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        with patch(
            "api.server.gpu_sessions.latest_gpu_runtime_session",
            AsyncMock(
                return_value=(
                    f"runtime-{mode}-session",
                    runtime_expiry,
                    attempt.attestation_id,
                )
            ),
        ):
            replay = await registration_attempt_response(session, attempt, spki_sha256)
        assert replay.state == "completed"
        assert replay.management_mode == mode
        assert replay.runtime_session == f"runtime-{mode}-session"
        assert replay.registration_replay_until == attempt.registration_replay_until


async def test_failed_gpu_runtime_attestation_persists_normal_delete_intent(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session,
            "miner",
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            request,
            spki_sha256,
            cert_pem,
        )
        assert lease_owner is not None
        assert conflict is None
        result = await _publish_completed_registration_fixture(
            session,
            response,
            request,
            cert_pem,
            spki_sha256,
        )
        await _complete_attempt(session, attempt.attempt_id, lease_owner, result)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        server = await session.get(Server, response.claims.server_id)
        nonce_context = RuntimeAttestationNonceContext(
            server_id=server.server_id,
            miner_hotkey=server.miner_hotkey,
            vm_name=server.name,
            cert_hash=spki_sha256,
            role="compute",
            compute_type="gpu",
            tee_type="tdx",
            provider="bare-metal",
            deployment_model="bare-metal-model-b",
            host_id=server.host_id,
            measurement_name=server.measurement_name,
            measurement_version=server.version,
            measurement_config_fingerprint=server.measurement_config_fingerprint,
            trust_set_fingerprint=server.trust_set_fingerprint,
            gpu_launch_reservation_id=reservation.reservation_id,
            gpu_allocation_group_id=reservation.allocation_group_id,
            gpu_allocation_group_generation=reservation.allocation_group_generation,
            gpu_host_boot_generation=reservation.host_boot_generation,
            gpu_reservation_generation=reservation.reservation_generation,
            gpu_management_mode=reservation.management_mode,
            gpu_process_incarnation=reservation.process_incarnation,
            gpu_topology_fingerprint=reservation.topology_fingerprint,
            gpu_release_id=reservation.gpu_release_id,
            gpu_profile_id=reservation.profile_id,
            gpu_chute_id=reservation.chute_id,
            gpu_job_id=reservation.job_id,
            gpu_claims_sha256=reservation.claims_sha256,
        )
        await session.commit()

    async with sessions() as session:
        context_loader = AsyncMock(return_value=nonce_context)
        with (
            patch(
                "api.server.service.runtime_attestation_context_for_server_db",
                context_loader,
            ),
            patch(
                "api.server.service.build_runtime_quote",
                side_effect=InvalidQuoteError("focused invalid quote"),
            ),
        ):
            with pytest.raises(
                InvalidGpuEvidenceError,
                match="requires fresh NVIDIA evidence",
            ):
                await process_runtime_attestation(
                    session,
                    response.claims.server_id,
                    "192.0.2.30",
                    RuntimeAttestationArgs(quote="Zm9jdXNlZC1xdW90ZQ=="),
                    response.claims.owner_hotkey,
                    "34" * 32,
                    spki_sha256,
                    nonce_context,
                )
        assert context_loader.await_count == 2

    async with sessions() as session:
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            response.claims.allocation_group_id,
        )
        operation = (
            await session.execute(
                select(GpuLifecycleOperation).where(
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id,
                    GpuLifecycleOperation.phase.notin_(("finalized", "quarantined")),
                )
            )
        ).scalar_one()
        failed_attestation = (
            await session.execute(
                select(ServerAttestation)
                .where(
                    ServerAttestation.server_id == response.claims.server_id,
                    ServerAttestation.verification_error.is_not(None),
                )
                .order_by(ServerAttestation.created_at.desc())
            )
        ).scalars().first()
        assert failed_attestation is not None
        assert failed_attestation.verification_error == (
            "GPU runtime re-attestation requires fresh NVIDIA evidence."
        )
        assert reservation.state == group.state == "resetting"
        assert reservation.teardown_requested_at is not None
        assert operation.operation_type == "normal_delete"
        assert operation.phase == "intent"
        assert operation.failure_code is None


@pytest.mark.parametrize(
    "mutation",
    ["host_generation", "group_lineage", "running", "quarantined"],
)
async def test_issued_registration_nonce_is_not_consumed_after_lineage_change(
    postgres_schema, mutation
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        host = await session.get(Host, "gpu-host")
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        if mutation == "host_generation":
            host.active_key_generation = 2
        elif mutation == "group_lineage":
            group.process_incarnation = "changed-group-process"
        elif mutation == "running":
            reservation.state = group.state = "running"
            reservation.running_at = group.running_at = now
        else:
            reservation.state = group.state = "quarantined"
            reservation.quarantined_at = group.quarantined_at = now
            reservation.failure_code = group.failure_code = "focused_quarantine"
            reservation.failure_reason = group.failure_reason = "focused quarantine"
            reservation.failure_metadata = group.failure_metadata = {}
        with pytest.raises(HTTPException, match="lineage is stale or mismatched"):
            await _claim_attempt(session, "192.0.2.30", request, spki_sha256, cert_pem)
        nonce = await session.get(GpuRegistrationNonce, request.nonce_id)
        attempts = list(
            (await session.execute(select(GpuRegistrationAttempt))).scalars()
        )
        assert nonce.state == "issued"
        assert nonce.claimed_attempt_id is None
        assert attempts == []
        await session.rollback()


async def test_duplicate_registration_while_processing_reuses_attempt(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        _response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        assert conflict is None
        await session.commit()
        attempt_id = attempt.attempt_id

    async with sessions() as session:
        verifier = AsyncMock()
        with patch("api.gpu_registration_service.register_gpu_server", verifier):
            replay, response_status = await process_gpu_registration(
                session, "192.0.2.30", request, spki_sha256, cert_pem
            )
        assert response_status == 202
        assert replay.state == "processing"
        assert replay.attempt_id == attempt_id
        assert replay.status_url.endswith(attempt_id)
        assert replay.retry_after_seconds == 2
        verifier.assert_not_awaited()
        attempts = list(
            (await session.execute(select(GpuRegistrationAttempt))).scalars()
        )
        assert [item.attempt_id for item in attempts] == [attempt_id]


async def test_published_registration_requires_completed_attempt_before_authority(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        assert conflict is None
        result = await _publish_completed_registration_fixture(
            session, response, request, cert_pem, spki_sha256
        )
        # This commit is the exact crash boundary: server/attestation/nodes are
        # published as running while the Registration V2 attempt is processing.
        await session.commit()

    async with sessions() as session:
        server_id = response.claims.server_id
        server = await session.get(Server, server_id)
        with pytest.raises(HTTPException, match="not durably completed"):
            await latest_gpu_runtime_session(session, server)
        await session.rollback()
        server = await session.get(Server, server_id)
        assert not await gpu_scheduler._latest_current_gpu_attestation(session, server)
        assert (
            await session.scalar(
                select(func.count(ServerAttestation.attestation_id)).where(
                    ServerAttestation.server_id == server_id
                )
            )
            == 1
        )
        assert await session.scalar(
            select(func.count(Node.uuid)).where(Node.server_id == server_id)
        ) == len(request.gpu_uuids)
        assert (
            await session.scalar(select(func.count(GpuHotplugCommand.command_id))) == 0
        )
        attempt = await session.get(GpuRegistrationAttempt, attempt.attempt_id)
        attempt.processing_lease_expires_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
        await session.commit()

    async with sessions() as session:
        attempt, resumed_lease, conflict = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert resumed_lease is not None and resumed_lease != lease_owner
        assert conflict is None
        completed = await _complete_attempt(
            session, attempt.attempt_id, resumed_lease, result
        )
        # Response replay expiry is independent of durable runtime authority.
        completed.completed_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        completed.registration_replay_until = datetime.now(timezone.utc) - timedelta(
            minutes=5
        )
        await session.commit()

    async with sessions() as session:
        server = await session.get(Server, response.claims.server_id)
        token, expires_at, attestation_id = await latest_gpu_runtime_session(
            session, server
        )
        server.gpu_runtime_session_attestation_id = attestation_id
        server.gpu_runtime_session_expires_at = expires_at
        await session.commit()
        validated_server, payload = await validate_gpu_runtime_session(
            session, token, required_purpose="miner"
        )
        assert validated_server.server_id == server.server_id
        assert payload["reservation_id"] == response.claims.reservation_id
        assert await gpu_scheduler._latest_current_gpu_attestation(session, server)
        assert (
            await session.scalar(select(func.count(GpuRegistrationAttempt.attempt_id)))
            == 1
        )
        assert (
            await session.scalar(
                select(func.count(ServerAttestation.attestation_id)).where(
                    ServerAttestation.server_id == server.server_id
                )
            )
            == 1
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "peer_spki",
        "peer_certificate_pem",
        "peer_certificate_sha256",
        "stable_bytes",
        "stable_hash",
        "stable_shape",
        "noncanonical_miner_uuids",
        "inconsistent_reservation_arrays",
    ],
)
async def test_runtime_authority_rejects_registration_audit_tamper(
    postgres_schema, tamper
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, _ = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        result = await _publish_completed_registration_fixture(
            session, response, request, cert_pem, spki_sha256
        )
        completed = await _complete_attempt(
            session, attempt.attempt_id, lease_owner, result
        )
        if tamper == "peer_spki":
            completed.peer_spki_sha256 = "d" * 64
        elif tamper == "peer_certificate_pem":
            completed.peer_certificate_pem = "tampered-certificate"
        elif tamper == "peer_certificate_sha256":
            completed.peer_certificate_sha256 = "d" * 64
        elif tamper == "stable_bytes":
            completed.stable_response = {
                **completed.stable_response,
                "owner_hotkey": "tampered-owner",
            }
        elif tamper == "stable_hash":
            completed.stable_response_sha256 = "d" * 64
        elif tamper == "stable_shape":
            completed.stable_response = {
                **completed.stable_response,
                "unexpected": "field",
            }
            completed.stable_response_sha256 = canonical_sha256(
                completed.stable_response
            )
        elif tamper == "noncanonical_miner_uuids":
            completed.stable_response = {
                **completed.stable_response,
                "gpu_uuids": list(reversed(completed.stable_response["gpu_uuids"])),
                "gpu_identifiers": list(
                    reversed(completed.stable_response["gpu_identifiers"])
                ),
            }
            completed.stable_response_sha256 = canonical_sha256(
                completed.stable_response
            )
        else:
            reservation = await session.get(
                gpu_allocations.GpuLaunchReservation,
                response.claims.reservation_id,
            )
            reservation.gpu_identifiers = list(reservation.gpu_identifiers[:-1])
        await session.commit()

    async with sessions() as session:
        server_id = response.claims.server_id
        server = await session.get(Server, server_id)
        with pytest.raises(HTTPException, match="completion audit"):
            await latest_gpu_runtime_session(session, server)
        await session.rollback()
        server = await session.get(Server, server_id)
        assert not await gpu_scheduler._latest_current_gpu_attestation(session, server)


async def test_completed_registration_replay_rejects_stable_response_tamper(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, request, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        assert conflict is None
        result = await _publish_completed_registration_fixture(
            session, response, request, cert_pem, spki_sha256
        )
        completed = await _complete_attempt(
            session, attempt.attempt_id, lease_owner, result
        )
        completed.stable_response = {
            **completed.stable_response,
            "server_id": "tampered-server",
        }
        await session.commit()

    async with sessions() as session:
        attempt = await session.get(GpuRegistrationAttempt, attempt.attempt_id)
        runtime_session = AsyncMock()
        with patch(
            "api.server.gpu_sessions.latest_gpu_runtime_session", runtime_session
        ):
            with pytest.raises(HTTPException, match="stable response audit"):
                await registration_attempt_response(session, attempt, spki_sha256)
        runtime_session.assert_not_awaited()


async def test_verified_competitors_before_primary_completion_fence_once(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response, primary, cert_pem, spki_sha256 = await _prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", primary, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        assert conflict is None
        conflicts = []
        competitor_spki = "d" * 64
        competitor_cert = "fixture-miner-competitor-certificate"
        for suffix in ("a", "b"):
            competitor = _registration_competitor(
                primary, spki_sha256=competitor_spki, suffix=suffix
            )
            replay_attempt, replay_lease, competitor_row = await _claim_attempt(
                session,
                "192.0.2.30",
                competitor,
                competitor_spki,
                competitor_cert,
            )
            assert replay_attempt.attempt_id == attempt.attempt_id
            assert replay_lease is None
            assert competitor_row is not None
            with patch(
                "api.gpu_registration_service.verify_gpu_registration_evidence",
                AsyncMock(
                    return_value=(object(), object(), _verified_gpu_subset(1, 2))
                ),
            ):
                state = await _verify_recorded_conflict(
                    session,
                    competitor_row,
                    competitor,
                    competitor_spki,
                    competitor_cert,
                )
            assert state == "verified_competitor"
            conflicts.append(competitor_row.conflict_id)

        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert reservation.state == group.state == "launching"
        assert attempt.state == "processing"
        result = await _publish_completed_registration_fixture(
            session, response, primary, cert_pem, spki_sha256
        )
        primary_attempt_id = attempt.attempt_id
        server_id = response.claims.server_id
        await session.commit()
        server = await session.get(Server, server_id)
        with pytest.raises(HTTPException, match="not durably completed"):
            await latest_gpu_runtime_session(session, server)
        await session.rollback()
        server = await session.get(Server, server_id)
        assert not await gpu_scheduler._latest_current_gpu_attestation(session, server)
        completed = await _complete_attempt(
            session, primary_attempt_id, lease_owner, result
        )
        assert completed.state == "completed"
        await session.commit()

    async with sessions() as session:
        attempt = await session.get(GpuRegistrationAttempt, primary_attempt_id)
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        rows = list(
            (
                await session.execute(
                    select(GpuRegistrationConflict)
                    .where(GpuRegistrationConflict.attempt_id == attempt.attempt_id)
                    .order_by(GpuRegistrationConflict.conflict_id)
                )
            ).scalars()
        )
        assert [item.conflict_id for item in rows] == sorted(conflicts)
        assert {item.state for item in rows} == {"verified_competitor"}
        assert reservation.state == group.state == "resetting"
        operation = (
            await session.execute(
                select(GpuLifecycleOperation).where(
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id
                )
            )
        ).scalar_one()
        assert operation.operation_type == "normal_delete"
        assert operation.phase == "intent"
        assert reservation.teardown_requested_at is not None
        assert reservation.teardown_reason == (
            "Independently verified requests competed for the completed nonce."
        )
        server = await session.get(Server, response.claims.server_id)
        with pytest.raises(HTTPException, match="reservation is not current"):
            await latest_gpu_runtime_session(session, server)
        stable_hash = attempt.stable_response_sha256
        completed_at = attempt.completed_at
        replay = await _complete_attempt(session, attempt.attempt_id, lease_owner, {})
        assert replay.state == "completed"
        assert replay.stable_response_sha256 == stable_hash
        assert replay.completed_at == completed_at
        await session.rollback()


async def test_invalid_cross_certificate_competitor_does_not_fence(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        (
            response,
            primary,
            primary_cert,
            primary_spki,
        ) = await _prepare_registration_request(session, "miner")
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", primary, primary_spki, primary_cert
        )
        assert lease_owner is not None
        assert conflict is None
        competitor_spki = "d" * 64
        competitor_cert = "fixture-miner-invalid-competitor-certificate"
        competitor = _registration_competitor(
            primary, spki_sha256=competitor_spki, suffix="invalid"
        )
        replay_attempt, replay_lease, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            competitor,
            competitor_spki,
            competitor_cert,
        )
        assert replay_attempt.attempt_id == attempt.attempt_id
        assert replay_lease is None
        assert conflict is not None
        with patch(
            "api.gpu_registration_service.verify_gpu_registration_evidence",
            AsyncMock(side_effect=InvalidGpuEvidenceError("invalid competitor")),
        ):
            state = await _verify_recorded_conflict(
                session,
                conflict,
                competitor,
                competitor_spki,
                competitor_cert,
            )
        assert state == "invalid"
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert reservation.state == group.state == "launching"
        assert reservation.failure_code is None


async def test_valid_cross_certificate_competitor_after_completion_fences(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        (
            response,
            primary,
            primary_cert,
            primary_spki,
        ) = await _prepare_registration_request(session, "miner")
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", primary, primary_spki, primary_cert
        )
        assert lease_owner is not None
        assert conflict is None
        result = await _publish_completed_registration_fixture(
            session, response, primary, primary_cert, primary_spki
        )
        completed = await _complete_attempt(
            session, attempt.attempt_id, lease_owner, result
        )
        await session.commit()
        assert completed.state == "completed"

        competitor_spki = "d" * 64
        competitor_cert = "fixture-miner-late-competitor-certificate"
        competitor = _registration_competitor(
            primary, spki_sha256=competitor_spki, suffix="late"
        )
        replay_attempt, replay_lease, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            competitor,
            competitor_spki,
            competitor_cert,
        )
        assert replay_attempt.attempt_id == attempt.attempt_id
        assert replay_lease is None
        assert conflict is not None
        with patch(
            "api.gpu_registration_service.verify_gpu_registration_evidence",
            AsyncMock(return_value=(object(), object(), _verified_gpu_subset(1, 2))),
        ):
            state = await _verify_recorded_conflict(
                session,
                conflict,
                competitor,
                competitor_spki,
                competitor_cert,
            )
        assert state == "verified_competitor"
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        assert reservation.state == group.state == "resetting"
        operation = (
            await session.execute(
                select(GpuLifecycleOperation).where(
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id
                )
            )
        ).scalar_one()
        assert operation.operation_type == "normal_delete"
        assert operation.phase == "intent"
        assert reservation.teardown_requested_at is not None
        assert reservation.teardown_reason == (
            "A second independently verified request used the completed registration nonce."
        )


async def test_hotplug_dispatch_refuses_quarantined_custody_without_send(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = "running"
        reservation.running_at = now
        group.state = "running"
        group.running_at = now
        command = _new_command(
            SimpleNamespace(
                legacy_migration_id="missing-migration",
                server_id=reservation.server_id,
                reservation_id=reservation.reservation_id,
                claims_sha256=reservation.claims_sha256,
                process_incarnation=reservation.process_incarnation,
                host_id=reservation.host_id,
                host_key_generation=reservation.host_key_generation,
                host_boot_generation=reservation.host_boot_generation,
                reservation_generation=reservation.reservation_generation,
                allocation_group_id=reservation.allocation_group_id,
                allocation_group_generation=reservation.allocation_group_generation,
            )
        )
        session.add(
            GpuHotplugCommand(
                command_id=command.command_id,
                host_id=command.host_id,
                host_key_generation=command.host_key_generation,
                host_boot_generation=command.host_boot_generation,
                reservation_id=command.reservation_id,
                reservation_generation=command.reservation_generation,
                claims_sha256=command.claims_sha256,
                allocation_group_id=command.allocation_group_id,
                allocation_group_generation=command.allocation_group_generation,
                process_incarnation=command.process_incarnation,
                stable_server_id=command.stable_server_id,
                migration_id=command.migration_id,
                payload=command.payload.model_dump(mode="json"),
                payload_sha256=command.payload_sha256,
                state="pending",
                attempt_count=0,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()

    async with sessions() as session:
        await quarantine_gpu_reservation_control_plane(
            session,
            response.claims.reservation_id,
            code="focused_hotplug_quarantine",
            reason="custody changed before durable hotplug dispatch",
        )
        await session.commit()

    async with sessions() as session:
        host = await session.get(Host, response.claims.host_id)
        with pytest.raises(GpuHotplugGoneError, match="must not be executed"):
            await get_gpu_hotplug_command(session, host, command.command_id)
        canceled = await session.get(GpuHotplugCommand, command.command_id)
        assert canceled.state == "failed"
        assert canceled.failure_code == "gpu_hotplug_custody_ended"
        assert canceled.ack is None
        await session.commit()

    @asynccontextmanager
    async def scoped_session():
        async with sessions() as session:
            yield session

    adapter = AsyncMock()
    with (
        patch("api.gpu_hotplug_service.get_session", scoped_session),
        patch("api.gpu_hotplug_service.send_agent_command", adapter),
    ):
        assert await dispatch_gpu_hotplug_command(command.command_id) is False
    adapter.assert_not_awaited()

    async with sessions() as session:
        row = await session.get(GpuHotplugCommand, command.command_id)
        assert row.state == "failed"
        assert row.attempt_count == 0
        assert row.failure_code == "gpu_hotplug_custody_ended"
        assert row.ack is None
        assert row.ack_sha256 is None
        assert row.acknowledged_at is None


async def test_registration_cleanup_scrubs_every_nonce_and_token_payload_copy(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        now = datetime.now(timezone.utc)
        nonce_value = "ab" * 32
        request_payload = {
            "nonce": nonce_value,
            "launch_reservation": response.token,
            "audit": "transient-request",
        }
        conflict_payload = {
            "nonce": nonce_value,
            "launch_reservation": response.token,
            "audit": "transient-conflict",
        }
        nonce = GpuRegistrationNonce(
            nonce_id="registration-cleanup-nonce",
            client_request_id="registration-cleanup-request",
            request_generation=1,
            peer_spki_sha256="a" * 64,
            reservation_id=response.claims.reservation_id,
            server_ip="192.0.2.10",
            nonce_value=nonce_value,
            nonce_hash=hashlib.sha256(bytes.fromhex(nonce_value)).hexdigest(),
            state="issued",
            issued_at=now - timedelta(minutes=30),
            expires_at=now + timedelta(minutes=30),
        )
        session.add(nonce)
        await session.flush()
        attempt = GpuRegistrationAttempt(
            attempt_id="registration-cleanup-attempt",
            nonce_id=nonce.nonce_id,
            reservation_id=response.claims.reservation_id,
            request_sha256=canonical_sha256(request_payload),
            request_payload=request_payload,
            peer_certificate_pem="fixture-primary-certificate",
            peer_certificate_sha256=hashlib.sha256(
                b"fixture-primary-certificate"
            ).hexdigest(),
            peer_spki_sha256="a" * 64,
            state="failed",
            failure_code="fixture_failure",
            failure_detail="fixture terminal failure",
            created_at=now - timedelta(minutes=30),
            updated_at=now - timedelta(minutes=20),
            completed_at=now - timedelta(minutes=20),
            registration_replay_until=now - timedelta(minutes=5),
        )
        session.add(attempt)
        await session.flush()
        nonce.state = "claimed"
        nonce.claimed_attempt_id = attempt.attempt_id
        conflict = GpuRegistrationConflict(
            conflict_id="registration-cleanup-conflict",
            attempt_id=attempt.attempt_id,
            nonce_id=nonce.nonce_id,
            request_sha256=canonical_sha256(conflict_payload),
            request_payload=conflict_payload,
            peer_certificate_pem="fixture-conflict-certificate",
            peer_certificate_sha256=hashlib.sha256(
                b"fixture-conflict-certificate"
            ).hexdigest(),
            peer_spki_sha256="a" * 64,
            quote_sha256="b" * 64,
            evidence_sha256="c" * 64,
            signature_sha256="d" * 64,
            state="recorded",
            created_at=now - timedelta(minutes=10),
        )
        session.add(conflict)
        await session.commit()

    async with sessions() as session:
        assert await cleanup_expired_gpu_registration_nonces(session) == 1
        await session.commit()

    async with sessions() as session:
        nonce = await session.get(GpuRegistrationNonce, "registration-cleanup-nonce")
        attempt = await session.get(
            GpuRegistrationAttempt, "registration-cleanup-attempt"
        )
        conflict = await session.get(
            GpuRegistrationConflict, "registration-cleanup-conflict"
        )
        assert nonce.state == "expired"
        assert nonce.nonce_value is None
        assert attempt.request_payload is None
        assert attempt.request_sha256 == canonical_sha256(request_payload)
        assert conflict.state == "dismissed"
        assert conflict.request_payload is None
        assert conflict.request_sha256 == canonical_sha256(conflict_payload)
        durable_values = (
            nonce.nonce_value,
            attempt.request_payload,
            conflict.request_payload,
        )
        assert nonce_value not in repr(durable_values)
        assert response.token not in repr(durable_values)


async def test_registration_cleanup_fails_only_expired_processor_on_ended_lineage(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        now = datetime.now(timezone.utc)
        reservation.state = "launching"
        reservation.launching_at = now
        group.state = "launching"
        group.launching_at = now
        nonce_value = "cd" * 32
        request_payload = {
            "nonce": nonce_value,
            "launch_reservation": response.token,
        }
        nonce = GpuRegistrationNonce(
            nonce_id="registration-stale-processor-nonce",
            client_request_id="registration-stale-processor-request",
            request_generation=1,
            peer_spki_sha256="a" * 64,
            reservation_id=reservation.reservation_id,
            server_ip="192.0.2.10",
            nonce_value=nonce_value,
            nonce_hash=hashlib.sha256(bytes.fromhex(nonce_value)).hexdigest(),
            state="issued",
            issued_at=now - timedelta(minutes=5),
            expires_at=now + timedelta(minutes=30),
        )
        session.add(nonce)
        await session.flush()
        attempt = GpuRegistrationAttempt(
            attempt_id="registration-stale-processor-attempt",
            nonce_id=nonce.nonce_id,
            reservation_id=reservation.reservation_id,
            request_sha256=canonical_sha256(request_payload),
            request_payload=request_payload,
            peer_certificate_pem="fixture-processing-certificate",
            peer_certificate_sha256=hashlib.sha256(
                b"fixture-processing-certificate"
            ).hexdigest(),
            peer_spki_sha256="a" * 64,
            state="processing",
            processing_lease_owner="live-processor",
            processing_lease_expires_at=now + timedelta(minutes=5),
            created_at=now - timedelta(minutes=5),
            updated_at=now,
        )
        session.add(attempt)
        await session.flush()
        nonce.state = "claimed"
        nonce.claimed_attempt_id = attempt.attempt_id
        await session.commit()

    async with sessions() as session:
        assert await cleanup_expired_gpu_registration_nonces(session) == 0
        await session.commit()
        attempt = await session.get(
            GpuRegistrationAttempt, "registration-stale-processor-attempt"
        )
        assert attempt.state == "processing"
        attempt.processing_lease_expires_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, response.claims.reservation_id
        )
        group = await session.get(
            GpuAllocationGroup, response.claims.allocation_group_id
        )
        reservation.state = "resetting"
        reservation.teardown_started_at = datetime.now(timezone.utc)
        group.state = "resetting"
        group.resetting_at = datetime.now(timezone.utc)
        await session.commit()

    async with sessions() as session:
        assert await cleanup_expired_gpu_registration_nonces(session) == 1
        await session.commit()
        nonce = await session.get(
            GpuRegistrationNonce, "registration-stale-processor-nonce"
        )
        attempt = await session.get(
            GpuRegistrationAttempt, "registration-stale-processor-attempt"
        )
        assert attempt.state == "failed"
        assert attempt.failure_code == "gpu_registration_lineage_ended"
        assert attempt.processing_lease_owner is None
        assert attempt.processing_lease_expires_at is None
        assert attempt.registration_replay_until > attempt.completed_at
        assert attempt.registration_replay_until - attempt.completed_at == timedelta(
            minutes=15
        )
        assert nonce.state == "claimed"
        assert nonce.nonce_value == nonce_value


async def test_verified_registration_conflict_cannot_fence_changed_lineage(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    cert_pem = "fixture-live-peer-certificate"
    spki_sha256 = "e" * 64
    nonce_value = "12" * 32
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        claims = response.claims
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, claims.reservation_id
        )
        group = await session.get(GpuAllocationGroup, claims.allocation_group_id)
        now = datetime.now(timezone.utc)
        reservation.state = "launching"
        reservation.launching_at = now
        group.state = "launching"
        group.launching_at = now
        commitment = GpuQuoteCommitmentV1(
            reservation_sha256=response.claims_sha256,
            release_target_sha256=claims.release_target_sha256,
            launch_nonce=claims.launch_nonce,
            attested_spki_sha256=spki_sha256,
            claims=claims,
        )
        primary = GpuRegistrationRequestV2(
            nonce_id="registration-conflict-nonce",
            nonce=nonce_value,
            server_id=claims.server_id,
            quote="primary-quote",
            gpu_evidence=[{"request": "primary"}],
            gpu_uuids=claims.gpu_uuids,
            launch_reservation=response.token,
            quote_commitment=commitment,
            td_signature="primary-signature",
        )
        competitor = GpuRegistrationRequestV2.model_validate(
            {
                **primary.model_dump(mode="json"),
                "quote": "competitor-quote",
                "gpu_evidence": [{"request": "competitor"}],
                "td_signature": "competitor-signature",
            }
        )
        nonce = GpuRegistrationNonce(
            nonce_id=primary.nonce_id,
            client_request_id="registration-conflict-request",
            request_generation=1,
            peer_spki_sha256=spki_sha256,
            reservation_id=claims.reservation_id,
            server_ip="192.0.2.11",
            nonce_value=nonce_value,
            nonce_hash=hashlib.sha256(bytes.fromhex(nonce_value)).hexdigest(),
            state="issued",
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        session.add(nonce)
        await session.flush()
        attempt = GpuRegistrationAttempt(
            attempt_id="registration-conflict-attempt",
            nonce_id=nonce.nonce_id,
            reservation_id=claims.reservation_id,
            request_sha256=primary.request_sha256(),
            request_payload=primary.model_dump(mode="json", exclude_none=True),
            peer_certificate_pem=cert_pem,
            peer_certificate_sha256=hashlib.sha256(cert_pem.encode()).hexdigest(),
            peer_spki_sha256=spki_sha256,
            state="processing",
            created_at=now,
            updated_at=now,
        )
        session.add(attempt)
        await session.flush()
        nonce.state = "claimed"
        nonce.claimed_attempt_id = attempt.attempt_id
        audit = _registration_request_audit(competitor, spki_sha256, cert_pem)
        conflict = GpuRegistrationConflict(
            conflict_id="registration-conflict-row",
            attempt_id=attempt.attempt_id,
            nonce_id=nonce.nonce_id,
            request_sha256=audit["request_sha256"],
            request_payload=audit["request_payload"],
            peer_certificate_pem=audit["peer_certificate_pem"],
            peer_certificate_sha256=audit["peer_certificate_sha256"],
            peer_spki_sha256=audit["peer_spki_sha256"],
            quote_sha256=audit["quote_sha256"],
            evidence_sha256=audit["evidence_sha256"],
            signature_sha256=audit["signature_sha256"],
            state="recorded",
            created_at=now,
        )
        session.add(conflict)
        await session.commit()

    async with sessions() as session:
        conflict = await session.get(
            GpuRegistrationConflict, "registration-conflict-row"
        )

        async def verify_then_mutate_lineage(db, *_args, **_kwargs):
            group = await db.get(GpuAllocationGroup, claims.allocation_group_id)
            group.process_incarnation = "mutated-process-incarnation"
            await db.commit()

        with patch(
            "api.gpu_registration_service.verify_gpu_registration_evidence",
            side_effect=verify_then_mutate_lineage,
        ):
            result = await _verify_recorded_conflict(
                session,
                conflict,
                competitor,
                spki_sha256,
                cert_pem,
            )
        assert result == "invalid"

    async with sessions() as session:
        conflict = await session.get(
            GpuRegistrationConflict, "registration-conflict-row"
        )
        reservation = await session.get(
            gpu_allocations.GpuLaunchReservation, claims.reservation_id
        )
        group = await session.get(GpuAllocationGroup, claims.allocation_group_id)
        assert conflict.state == "invalid"
        assert reservation.state == "launching"
        assert reservation.quarantined_at is None
        assert group.state == "launching"
        assert group.quarantined_at is None
