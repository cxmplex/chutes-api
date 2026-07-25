"""Real-Postgres GPU allocation races, replay fencing, expiry, and reset."""

from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
import pytest_asyncio
from cryptography.fernet import Fernet
from starlette.requests import Request
from api.database import Base
from api.config import TeeMeasurementConfig
from api.host import gpu_allocations
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.gpu_allocations import (
    GpuAllocationError,
    _active_gpu_release,
    _expire_locked_reservations,
    _host_lock,
    advance_gpu_host_boot,
    authorize_gpu_group_recovery,
    begin_gpu_teardown,
    claim_gpu_reservation,
    complete_gpu_reset,
    complete_gpu_group_recovery,
    fence_gpu_host_authority,
    mark_gpu_launching,
    quarantine_gpu_reservation_control_plane,
    record_gpu_command_ack,
    record_gpu_command_dispatch,
    reserve_gpu_group,
    start_gpu_group_recovery,
)
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuMinerReservationRequestV1,
    GpuPlatformReservationRequestV1,
    HostKeyGeneration,
    GpuReservationClaimRequestV1,
    GpuReservationStateRequestV1,
    GpuResetResultV1,
    canonical_sha256,
    GpuQuoteCommitmentV1,
    GpuRecoveryAuthorizeRequestV1,
    GpuRecoveryResetResultV1,
    GpuRecoveryStartRequestV1,
)
from api.releases.provenance import (
    canonical_provenance_bytes,
    gpu_measurement_fingerprint,
)
from api.releases import service as release_service
from api.releases.schemas import GuestRelease
from api.server.schemas import Host
from api.server.schemas import (
    DefaultChuteFSVolumeBinding,
    GpuInfraCustody,
    GpuLegacyCloseRequestV1,
    GpuLegacyMigration,
    GpuMinerIdentity,
    GpuServerRegistrationArgs,
    NvidiaVerificationResultV1,
    Server,
    ServerAttestation,
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
from api.server.service import register_gpu_server
from api.server.util import decrypt_passphrase, encrypt_passphrase
from api.node.schemas import Node
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
from tests.unit.test_gpu_allocations import _report

import api.database.orms  # noqa: F401, E402

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
    sql = up_sql if direction == "up" else down_sql
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    connection_url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
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
                gpu_measurement_fingerprint=gpu_measurement_fingerprint(document, entry),
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
    report = GpuInventoryReport(
        report_id="inventory-report",
        host_id=host.host_id,
        host_key_generation=1,
        host_boot_generation=1,
        report_generation=1,
        gpu_release_id=release.release_id,
        profile_contract_sha256=provenance["profile_contract_sha256"],
        topology_fingerprint="c" * 64,
        claims={"seed": True},
        claims_sha256="d" * 64,
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
    group = GpuAllocationGroup(
        allocation_group_id="allocation-group",
        host_id=host.host_id,
        host_key_generation=1,
        host_boot_generation=1,
        generation=1,
        gpu_release_id=release.release_id,
        profile_id="b200-8gpu",
        profile_contract_sha256=provenance["profile_contract_sha256"],
        topology_fingerprint="c" * 64,
        gpu_bdfs=BDFS,
        gpu_uuids=sorted(UUIDS),
        gpu_identifiers=["b200"] * 8,
        gpu_attestation_certificate_sha256s=[f"{index:064x}" for index in range(1, 9)],
        iommu_domains=[],
        reset_domains=[],
        nvlink_edges=[],
        nvswitch_fabric=[],
        model="B200",
        gpu_count=8,
        vram_mib=196608,
        state="available",
        reservation_generation=0,
        last_report_id=report.report_id,
        available_at=now,
        last_seen_at=now,
        updated_at=now,
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


async def test_gpu_allocation_migration_round_trip(postgres_schema):
    sessions, schema = postgres_schema
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
        assert columns == {column.name for column in ServerAttestation.__table__.columns}
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
            measurement_config_fingerprint=(legacy_server.measurement_config_fingerprint),
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
            gpu_evidence_certificate_sha256s=(claims.gpu_attestation_certificate_sha256s),
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
                select(Server).where(Server.server_id == claims.server_id).with_for_update()
            )
        ).scalar_one()
        reservation = (
            await db.execute(
                select(gpu_allocations.GpuLaunchReservation)
                .where(gpu_allocations.GpuLaunchReservation.reservation_id == claims.reservation_id)
                .with_for_update()
            )
        ).scalar_one()
        group = (
            await db.execute(
                select(GpuAllocationGroup)
                .where(GpuAllocationGroup.allocation_group_id == claims.allocation_group_id)
                .with_for_update()
            )
        ).scalar_one()
        host = (
            await db.execute(select(Host).where(Host.host_id == claims.host_id).with_for_update())
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
            (await session.execute(select(gpu_allocations.GpuLaunchReservation))).scalars().all()
        )
        assert len(reservations) == 1
        assert group.management_mode == reservations[0].management_mode
        assert group.reservation_id == reservations[0].reservation_id


async def test_failed_launch_ack_is_idempotent_and_releases_only_unclaimed_group(
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
        assert reservation.state == "expired"
        assert reservation.launch_ack_status == "rejected"
        assert group.state == "available"
        assert group.reservation_id is None
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


async def test_key_rotation_fences_group_and_reservation_atomically(postgres_schema):
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
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert row.state == "quarantined"
        assert group.state == "quarantined"
        assert row.failure_code == group.failure_code == "test_key_rotation"
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
        await session.flush()
        state = GpuReservationStateRequestV1(
            reservation_id=response.claims.reservation_id,
            claims_sha256=response.claims_sha256,
            process_incarnation=response.claims.process_incarnation,
        )
        await begin_gpu_teardown(session, host, state)
        assert row.state == group.state == "resetting"
        await session.commit()


async def test_ownerless_quarantine_requires_admin_authorized_exact_reset(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    report_claims = _report().model_copy(
        update={
            "report_id": "recovery-report",
            "report_generation": 2,
            "host_id": "gpu-host",
            "host_key_generation": 1,
            "host_boot_id": "11111111-1111-1111-1111-111111111111",
            "host_boot_generation": 1,
            "gpu_release_id": "gpu-release",
        }
    )
    reported_group = report_claims.groups[0]
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        group = await session.get(GpuAllocationGroup, "allocation-group")
        report = GpuInventoryReport(
            report_id=report_claims.report_id,
            host_id=host.host_id,
            host_key_generation=1,
            host_boot_generation=1,
            report_generation=2,
            gpu_release_id="gpu-release",
            profile_contract_sha256=report_claims.profile_contract_sha256,
            topology_fingerprint=reported_group.topology_fingerprint,
            claims=report_claims.model_dump(mode="json"),
            claims_sha256=canonical_sha256(report_claims),
            reconciliation_status="quarantined",
            failure_reason="ownerless group remains quarantined",
        )
        session.add(report)
        await session.flush()
        group.topology_fingerprint = reported_group.topology_fingerprint
        group.gpu_bdfs = [item.bdf for item in reported_group.devices]
        group.gpu_uuids = sorted(item.uuid for item in reported_group.devices)
        group.gpu_attestation_certificate_sha256s = sorted(
            item.attestation_certificate_sha256 for item in reported_group.devices
        )
        group.last_report_id = report.report_id
        group.state = "quarantined"
        group.available_at = None
        group.quarantined_at = datetime.now(timezone.utc)
        group.failure_code = "ownerless"
        group.failure_reason = "ownerless quarantine"
        group.failure_metadata = {}
        host.gpu_inventory_report_generation = 2
        await session.flush()

        authorization = await authorize_gpu_group_recovery(
            session,
            group.allocation_group_id,
            GpuRecoveryAuthorizeRequestV1(
                report_id=report.report_id,
                reason="operator inspected exact reset domain",
            ),
            authorized_by="admin",
        )
        start = GpuRecoveryStartRequestV1(
            authorization_id=authorization.authorization_id,
            allocation_group_id=authorization.allocation_group_id,
            allocation_group_generation=authorization.allocation_group_generation,
            report_id=authorization.report_id,
            topology_fingerprint=authorization.topology_fingerprint,
            recovery_nonce=authorization.recovery_nonce,
        )
        await start_gpu_group_recovery(session, host, start)
        assert group.state == "resetting"
        released = await complete_gpu_group_recovery(
            session,
            host,
            GpuRecoveryResetResultV1(
                **start.model_dump(exclude={"schema"}),
                schema="chutes.gpu-recovery-reset-result",
                qemu_absent=True,
                reset_succeeded=True,
                original_drivers_restored=True,
                gpu_bdfs=group.gpu_bdfs,
                gpu_uuids=group.gpu_uuids,
            ),
        )
        assert released is True
        assert group.state == "available"
        assert group.generation == 2
        assert group.recovery_completed_at is not None
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
        gpu_allocations.GpuLaunchReservation.reservation_id == response.claims.reservation_id
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
            gpu_allocation_group_generation=(response.claims.allocation_group_generation),
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
            await session.execute(select(Host).where(Host.host_id == "gpu-host").with_for_update())
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
            await session.execute(select(Host).where(Host.host_id == "gpu-host").with_for_update())
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
        after = await reserve_gpu_group(session, "gpu-host", _request("gpu-after", "gpu-after"))
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
        assert row.state == "quarantined"
        assert group.state == "quarantined"
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


async def test_guest_registration_is_only_atomic_running_transition_and_reset_retires(
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
        await session.commit()
    state = GpuReservationStateRequestV1(
        reservation_id=response.claims.reservation_id,
        claims_sha256=response.claims_sha256,
        process_incarnation=response.claims.process_incarnation,
    )
    commitment = GpuQuoteCommitmentV1(
        reservation_sha256=response.claims_sha256,
        release_target_sha256=response.claims.release_target_sha256,
        launch_nonce=response.claims.launch_nonce,
        attested_spki_sha256="e" * 64,
        claims=response.claims,
    )
    args = GpuServerRegistrationArgs(
        server_id=response.claims.server_id,
        quote="cXVvdGU=",
        gpu_evidence=[{"evidence": str(index)} for index in range(8)],
        gpu_uuids=response.claims.gpu_uuids,
        launch_reservation=response.token,
        quote_commitment=commitment,
        td_signature="c2lnbmF0dXJl",
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        await mark_gpu_launching(session, host, state)
        await session.commit()
    measurement = release_service.settings.tee_measurements[1]
    with (
        patch(
            "api.server.service.build_runtime_quote",
            return_value=object(),
        ),
        patch(
            "api.server.service.verify_quote",
            AsyncMock(return_value=SimpleNamespace(revocation_status={"tdx": "ok"})),
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=measurement,
        ),
        patch(
            "api.server.service.verify_gpu_evidence",
            AsyncMock(
                return_value=NvidiaVerificationResultV1(
                    schema="chutes.nvidia-verification-result",
                    version=1,
                    nonce="f" * 64,
                    devices=[
                        {
                            "attestation_certificate_sha256": value,
                            "evidence_sha256": f"{index + 20:064x}",
                            "architecture": "BLACKWELL",
                        }
                        for index, value in enumerate(
                            response.claims.gpu_attestation_certificate_sha256s
                        )
                    ],
                )
            ),
        ) as verify_gpu,
        patch("api.server.service._verify_td_registration_signature"),
    ):
        async with sessions() as session:
            result = await register_gpu_server(
                session,
                "203.0.113.10",
                args,
                "f" * 64,
                "e" * 64,
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            assert result["status"] == "registered"
            retried_result = await register_gpu_server(
                session,
                "203.0.113.10",
                args,
                "f" * 64,
                "e" * 64,
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            assert retried_result["attestation_id"] == result["attestation_id"]
            attempts = (
                (
                    await session.execute(
                        select(ServerAttestation).where(
                            ServerAttestation.server_id == response.claims.server_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(attempts) == 1
    verify_gpu.assert_awaited_once()
    async with sessions() as session:
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        server = await session.get(Server, response.claims.server_id)
        nodes = (
            (await session.execute(select(Node).where(Node.server_id == response.claims.server_id)))
            .scalars()
            .all()
        )
        assert row.state == group.state == "running"
        assert row.guest_consumed_at is not None
        assert server.gpu_retired_at is None
        assert sorted(item.uuid for item in nodes) == response.claims.gpu_uuids
        custody = GpuInfraCustody(
            server_id=response.claims.server_id,
            owner_hotkey=response.claims.owner_hotkey,
            host_id=response.claims.host_id,
            host_boot_generation=response.claims.host_boot_generation,
            reservation_id=response.claims.reservation_id,
            reservation_generation=response.claims.reservation_generation,
            allocation_group_id=response.claims.allocation_group_id,
            allocation_group_generation=response.claims.allocation_group_generation,
            management_mode="miner",
            volume_name="gpu-infra",
            k3s_encryption_key=encrypt_passphrase("k3s-key"),
            confirmed_generation=0,
            state="current",
        )
        session.add(custody)
        await session.flush()
        await begin_gpu_teardown(session, host, state)
        custody.guest_closed_generation = 0
        custody.guest_closed_at = datetime.now(timezone.utc)
        released = await complete_gpu_reset(
            session,
            host,
            GpuResetResultV1(
                reservation_id=state.reservation_id,
                claims_sha256=state.claims_sha256,
                process_incarnation=state.process_incarnation,
                qemu_absent=True,
                reset_succeeded=True,
                gpu_bdfs=BDFS,
                gpu_uuids=sorted(UUIDS),
                topology_fingerprint="c" * 64,
                original_drivers_restored=True,
                guest_shutdown_clean=True,
            ),
        )
        assert released is True
        assert server.gpu_retired_at is not None
        attestation = await session.get(
            ServerAttestation,
            result["attestation_id"],
        )
        assert attestation.gpu_retired_at is not None
        retired_nodes = (
            (await session.execute(select(Node).where(Node.server_id == response.claims.server_id)))
            .scalars()
            .all()
        )
        assert retired_nodes == []
        await session.commit()

    async with sessions() as session:
        second = await reserve_gpu_group(
            session,
            "gpu-host",
            _request("gpu-server-second", "gpu-process-second"),
        )
        assert second.claims.server_id == response.claims.server_id
        host = await session.get(Host, "gpu-host")
        second_state = GpuReservationStateRequestV1(
            reservation_id=second.claims.reservation_id,
            claims_sha256=second.claims_sha256,
            process_incarnation=second.claims.process_incarnation,
        )
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=second.token,
                claims_sha256=second.claims_sha256,
            ),
        )
        await mark_gpu_launching(session, host, second_state)
        await session.commit()
    second_commitment = GpuQuoteCommitmentV1(
        reservation_sha256=second.claims_sha256,
        release_target_sha256=second.claims.release_target_sha256,
        launch_nonce=second.claims.launch_nonce,
        attested_spki_sha256="d" * 64,
        claims=second.claims,
    )
    second_args = GpuServerRegistrationArgs(
        server_id=second.claims.server_id,
        quote="cXVvdGU=",
        gpu_evidence=[{"evidence": str(index)} for index in range(8)],
        gpu_uuids=second.claims.gpu_uuids,
        launch_reservation=second.token,
        quote_commitment=second_commitment,
        td_signature="c2lnbmF0dXJl",
    )
    with (
        patch("api.server.service.build_runtime_quote", return_value=object()),
        patch(
            "api.server.service.verify_quote",
            AsyncMock(return_value=SimpleNamespace(revocation_status={"tdx": "ok"})),
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=measurement,
        ),
        patch(
            "api.server.service.verify_gpu_evidence",
            AsyncMock(
                return_value=NvidiaVerificationResultV1(
                    schema="chutes.nvidia-verification-result",
                    version=1,
                    nonce="f" * 64,
                    devices=[
                        {
                            "attestation_certificate_sha256": value,
                            "evidence_sha256": f"{index + 30:064x}",
                            "architecture": "BLACKWELL",
                        }
                        for index, value in enumerate(
                            second.claims.gpu_attestation_certificate_sha256s
                        )
                    ],
                )
            ),
        ),
        patch("api.server.service._verify_td_registration_signature"),
    ):
        async with sessions() as session:
            second_result = await register_gpu_server(
                session,
                "203.0.113.11",
                second_args,
                "f" * 64,
                "d" * 64,
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            assert second_result["status"] == "registered"
            second_nodes = (
                (
                    await session.execute(
                        select(Node).where(Node.server_id == second.claims.server_id)
                    )
                )
                .scalars()
                .all()
            )
            assert sorted(item.uuid for item in second_nodes) == (second.claims.gpu_uuids)
            runtime = await session.get(Server, second.claims.server_id)
            reservation = await session.get(
                gpu_allocations.GpuLaunchReservation,
                second.claims.reservation_id,
            )
            group = await session.get(
                GpuAllocationGroup,
                second.claims.allocation_group_id,
            )
            host = await session.get(Host, second.claims.host_id)

            async def locked_lineage(*_args, **_kwargs):
                return runtime, reservation, group, host

            with patch(
                "api.server.gpu_infra._locked_current_lineage",
                side_effect=locked_lineage,
            ):
                await lease_gpu_infra(
                    session,
                    runtime,
                    {
                        "server_id": second.claims.server_id,
                        "owner_hotkey": second.claims.owner_hotkey,
                        "reservation_id": second.claims.reservation_id,
                        "attestation_id": second_result["attestation_id"],
                        "management_mode": "miner",
                        "attested_spki_sha256": "d" * 64,
                        "jti": "reboot-session",
                    },
                    "d" * 64,
                    GpuInfraLeaseRequestV1(),
                )
            custody = await session.get(
                GpuInfraCustody,
                second.claims.server_id,
            )
            assert custody.reservation_id == second.claims.reservation_id
            assert custody.state == "leased"


async def test_late_guest_registration_quarantines_before_quote_verification(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        host = await session.get(Host, "gpu-host")
        state = GpuReservationStateRequestV1(
            reservation_id=response.claims.reservation_id,
            claims_sha256=response.claims_sha256,
            process_incarnation=response.claims.process_incarnation,
        )
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        await mark_gpu_launching(session, host, state)
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        row.issued_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()
    commitment = GpuQuoteCommitmentV1(
        reservation_sha256=response.claims_sha256,
        release_target_sha256=response.claims.release_target_sha256,
        launch_nonce=response.claims.launch_nonce,
        attested_spki_sha256="e" * 64,
        claims=response.claims,
    )
    args = GpuServerRegistrationArgs(
        server_id=response.claims.server_id,
        quote="cXVvdGU=",
        gpu_evidence=[{"evidence": str(index)} for index in range(8)],
        gpu_uuids=response.claims.gpu_uuids,
        launch_reservation=response.token,
        quote_commitment=commitment,
        td_signature="c2lnbmF0dXJl",
    )
    from api.server.exceptions import ServerRegistrationError

    async with sessions() as session:
        with pytest.raises(ServerRegistrationError, match="deadline"):
            await register_gpu_server(
                session,
                "203.0.113.10",
                args,
                "f" * 64,
                "e" * 64,
                "unused",
            )
    async with sessions() as session:
        row = await session.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert row.state == group.state == "quarantined"


async def test_reset_success_releases_and_failure_quarantines(postgres_schema):
    sessions, _schema = postgres_schema
    await _seed(sessions)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        await session.commit()
    state = GpuReservationStateRequestV1(
        reservation_id=response.claims.reservation_id,
        claims_sha256=response.claims_sha256,
        process_incarnation=response.claims.process_incarnation,
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=response.token,
                claims_sha256=response.claims_sha256,
            ),
        )
        await mark_gpu_launching(session, host, state)
        await begin_gpu_teardown(session, host, state)
        released = await complete_gpu_reset(
            session,
            host,
            GpuResetResultV1(
                reservation_id=state.reservation_id,
                claims_sha256=state.claims_sha256,
                process_incarnation=state.process_incarnation,
                qemu_absent=True,
                reset_succeeded=True,
                gpu_bdfs=BDFS,
                gpu_uuids=sorted(UUIDS),
                topology_fingerprint="c" * 64,
                original_drivers_restored=True,
                guest_shutdown_clean=True,
            ),
        )
        assert released is True
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert group.state == "available"
        await session.commit()

    async with sessions() as session:
        failed = await reserve_gpu_group(session, "gpu-host", _request("gpu-failed", "gpu-failed"))
        await session.commit()
    failed_state = GpuReservationStateRequestV1(
        reservation_id=failed.claims.reservation_id,
        claims_sha256=failed.claims_sha256,
        process_incarnation=failed.claims.process_incarnation,
    )
    async with sessions() as session:
        host = await session.get(Host, "gpu-host")
        await claim_gpu_reservation(
            session,
            host,
            GpuReservationClaimRequestV1(
                token=failed.token,
                claims_sha256=failed.claims_sha256,
            ),
        )
        await mark_gpu_launching(session, host, failed_state)
        await begin_gpu_teardown(session, host, failed_state)
        released = await complete_gpu_reset(
            session,
            host,
            GpuResetResultV1(
                reservation_id=failed_state.reservation_id,
                claims_sha256=failed_state.claims_sha256,
                process_incarnation=failed_state.process_incarnation,
                qemu_absent=True,
                reset_succeeded=False,
                gpu_bdfs=BDFS,
                gpu_uuids=sorted(UUIDS),
                topology_fingerprint="c" * 64,
                original_drivers_restored=False,
                failure_code="sbr_failed",
                failure_reason="assigned reset domain did not recover",
            ),
        )
        assert released is False
        group = await session.get(GpuAllocationGroup, "allocation-group")
        assert group.state == "quarantined"
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
            gpu_evidence_certificate_sha256s=(claims.gpu_attestation_certificate_sha256s),
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
