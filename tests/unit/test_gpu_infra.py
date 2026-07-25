import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.host.schemas import GpuMinerReservationRequestV1
from api.host import router as host_router
from api.server import gpu_infra
from api.server.gpu_sessions import (
    GPU_PLATFORM_RUNTIME_SESSION_PURPOSES,
    GPU_RUNTIME_SESSION_PURPOSES,
)
from api.server.schemas import (
    GpuInfraCloseRequestV1,
    GpuInfraLeaseResponseV1,
    GpuInfraMigrationCompleteRequestV1,
    GpuInfraMigrationPromoteRequestV1,
    GpuInfraMigrationRefreshRequestV1,
)


@pytest.mark.asyncio
async def test_gpu_infra_close_missing_server_returns_conflict_not_null_dereference():
    class Result:
        def scalar_one_or_none(self):
            return None

    db = SimpleNamespace(
        execute=AsyncMock(side_effect=[Result(), Result(), Result()]),
    )
    with (
        patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="does not match sealed custody") as exc,
    ):
        await gpu_infra.acknowledge_gpu_infra_closed(
            db,
            SimpleNamespace(server_id="deleted-server"),
            {"reservation_id": "reservation", "attestation_id": "attestation"},
            "a" * 64,
            GpuInfraCloseRequestV1(
                generation=1,
                filesystem_synced=True,
                unmounted=True,
                mapper_closed=True,
            ),
        )
    assert exc.value.status_code == 409


def test_miner_reservation_wire_cannot_choose_server_or_process_identity():
    request = GpuMinerReservationRequestV1(
        gpu_identifier="b200",
        gpu_count=8,
        minimum_vram_mib=1,
        miner_hourly_cost=12.5,
    )
    assert request.model_dump(exclude_none=True) == {
        "schema": "chutes.gpu-miner-reservation-request",
        "version": 1,
        "gpu_identifier": "b200",
        "gpu_count": 8,
        "minimum_vram_mib": 1,
        "miner_hourly_cost": 12.5,
    }
    with pytest.raises(ValidationError, match="Extra inputs"):
        GpuMinerReservationRequestV1(
            gpu_identifier="b200",
            gpu_count=8,
            minimum_vram_mib=1,
            miner_hourly_cost=12.5,
            server_id="caller-chosen",
            process_incarnation="caller-chosen",
        )


@pytest.mark.asyncio
async def test_legacy_gpu_start_waits_for_exact_async_command_ack():
    migration = SimpleNamespace(
        migration_id="migration-1",
        legacy_server_id="legacy-server",
        storage_luks_uuid="00000000-0000-0000-0000-000000000001",
        cache_luks_uuid="00000000-0000-0000-0000-000000000002",
        state="guest_closed",
    )

    class Result:
        def scalar_one_or_none(self):
            return migration

    db = AsyncMock()
    db.get.return_value = SimpleNamespace(owner_hotkey="owner")
    db.execute.return_value = Result()
    response = SimpleNamespace(claims=SimpleNamespace(reservation_id="reservation-1"))
    send = AsyncMock(return_value="gpu-legacy-confirm-migration-1")
    wait = AsyncMock(
        return_value={
            "command_id": "gpu-legacy-confirm-migration-1",
            "server_id": "gpu-host",
            "command": "confirm_gpu_legacy_sources",
            "status": "ok",
            "detail": "closed",
        }
    )
    with (
        patch.object(host_router, "send_agent_command", send),
        patch.object(host_router, "wait_for_agent_command_ack", wait),
        patch.object(host_router, "reserve_gpu_group", AsyncMock(return_value=response)),
        patch("api.gpu_scheduler._dispatch_launch", AsyncMock()),
    ):
        result = await host_router.create_miner_gpu_reservation_endpoint(
            "gpu-host",
            GpuMinerReservationRequestV1(
                gpu_identifier="b200",
                gpu_count=8,
                minimum_vram_mib=1,
                miner_hourly_cost=12.5,
                legacy_vm_name="legacy-vm",
            ),
            db,
            hotkey="owner",
            _=None,
        )
    assert result is response
    send.assert_awaited_once()
    assert send.await_args.kwargs["command_id"] == "gpu-legacy-confirm-migration-1"
    wait.assert_awaited_once_with(
        "gpu-host",
        "confirm_gpu_legacy_sources",
        "gpu-legacy-confirm-migration-1",
        timeout_seconds=15,
    )


def test_gpu_runtime_purposes_match_cross_repo_fixture():
    fixture = Path(__file__).resolve().parents[1] / "fixtures/gpu_runtime_purposes_v1.json"
    document = json.loads(fixture.read_text(encoding="ascii"))
    assert document == {
        "schema": "chutes.gpu-runtime-purposes",
        "version": 1,
        "miner": list(GPU_RUNTIME_SESSION_PURPOSES),
        "platform": list(GPU_PLATFORM_RUNTIME_SESSION_PURPOSES),
    }
    assert "gpu-infra" in document["miner"]


def test_awaiting_ack_retains_pending_key_without_advancing_floor():
    response = GpuInfraLeaseResponseV1(
        server_id="gpu-server",
        lease_id="a" * 64,
        generation=5,
        confirmed_generation=4,
        current="current-key",
        next="pending-key",
        active_key_slot=0,
        next_key_slot=1,
        lease_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        lease_reused=True,
        awaiting_ack=True,
        k3s_encryption_key="k3s-key",
    )
    assert response.awaiting_ack is True
    assert response.generation == response.confirmed_generation + 1
    with pytest.raises(ValidationError, match="exactly follow"):
        GpuInfraLeaseResponseV1(
            **{
                **response.model_dump(),
                "generation": response.confirmed_generation,
            }
        )


def test_migration_completion_requires_both_source_discards():
    common = {
        "migration_id": "migration",
        "capability": "c" * 64,
        "marker_sha256": "a" * 64,
    }
    with pytest.raises(ValidationError):
        GpuInfraMigrationCompleteRequestV1(
            **common,
            storage_discarded=False,
            cache_discarded=True,
        )
    with pytest.raises(ValidationError):
        GpuInfraMigrationCompleteRequestV1(
            **common,
            storage_discarded=True,
            cache_discarded=False,
        )


def test_teardown_abandon_preserves_one_authorized_rollback_generation():
    custody = SimpleNamespace(
        state="awaiting_ack",
        confirmed_generation=7,
        lease_generation=8,
        pending_key_slot=1,
        pending_passphrase="encrypted-pending",
        rollback_generation=None,
        rollback_key_slot=None,
        rollback_passphrase=None,
        lease_id="lease",
        lease_expires_at=datetime.now(timezone.utc),
        lease_attestation_id="attestation",
        lease_cert_hash="a" * 64,
        lease_session_jti="jti",
        pending_marker_sha256="b" * 64,
    )
    gpu_infra._abandon_locked(custody, preserve_rollback=True)
    assert custody.state == "current"
    assert custody.rollback_generation == 8
    assert custody.rollback_key_slot == 1
    assert custody.rollback_passphrase == "encrypted-pending"
    assert custody.lease_generation is None
    assert custody.pending_passphrase is None


def test_gpu_infra_migration_declares_two_source_custody_and_ack_floor():
    migration = (
        Path(__file__).resolve().parents[2]
        / "api/migrations/20260724110000_gpu_miner_infra_custody.sql"
    ).read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS gpu_legacy_migrations" in migration
    assert "storage_luks_uuid" in migration
    assert "cache_luks_uuid" in migration
    assert "storage_current_passphrase" in migration
    assert "cache_current_passphrase" in migration
    assert "lease_generation = confirmed_generation + 1" in migration
    assert "legacy_migration_state TEXT" not in migration
    assert "volume_name TEXT NOT NULL DEFAULT 'gpu-infra'" in migration


def test_legacy_source_lease_rejects_another_server_identity():
    server = SimpleNamespace(
        server_id="legacy-server",
        miner_hotkey="owner",
        name="legacy-vm",
        attested_cert_pubkey_hash="a" * 64,
        measurement_name="gpu-legacy",
        version="1.10.0",
        measurement_config_fingerprint="b" * 64,
        trust_set_fingerprint="c" * 64,
        tee_type="tdx",
    )
    lease = {
        "generation": 10,
        "lease_id": "d" * 32,
        "server_id": "other-server",
        "miner_hotkey": "owner",
        "vm_name": "legacy-vm",
        "cert_hash": "a" * 64,
        "measurement_name": "gpu-legacy",
        "measurement_version": "1.10.0",
        "measurement_config_fingerprint": "b" * 64,
        "trust_set_fingerprint": "c" * 64,
        "tee_type": "tdx",
        "purpose": "boot_luks",
        "storage_role": False,
        "promotion_required": True,
    }
    with pytest.raises(HTTPException, match="another custody identity"):
        gpu_infra._validated_legacy_lease(
            lease,
            server=server,
            volume="storage",
            confirmed_generation=9,
        )


def test_migration_marker_records_actual_leased_source_generation():
    migration = SimpleNamespace(
        migration_id="migration-1",
        storage_generation=9,
        storage_lease={"generation": 10},
        storage_luks_uuid="00000000-0000-0000-0000-000000000001",
        storage_filesystem_uuid="00000000-0000-0000-0000-000000000002",
        cache_generation=6,
        cache_lease=None,
        cache_luks_uuid="00000000-0000-0000-0000-000000000003",
        cache_filesystem_uuid="00000000-0000-0000-0000-000000000004",
        cache_filesystem_type="xfs",
        required_entries=[{"name": "postgres"}],
        optional_entries=[],
    )
    custody = SimpleNamespace(
        server_id="logical-server",
        confirmed_generation=11,
    )
    summary = {
        "schema": "chutes.gpu-infra-copy-summary",
        "version": 1,
        "migration_id": migration.migration_id,
        "source_generations": {"storage": 10, "tdx-cache": 6},
        "entries": {"postgres": {"records": [], "total_bytes": 0}},
    }
    summary_hash = hashlib.sha256(
        json.dumps(
            summary,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    marker = {
        "schema": "chutes.gpu-infra-migration-marker",
        "version": 2,
        "server_id": custody.server_id,
        "volume_name": "gpu-infra",
        "custody_generation": custody.confirmed_generation,
        "migration_id": migration.migration_id,
        "state": "promoted",
        "sources": {
            "storage": {
                "generation": 10,
                "luks_uuid": migration.storage_luks_uuid,
                "filesystem_uuid": migration.storage_filesystem_uuid,
                "filesystem_type": "xfs",
                "hotplug_serial": "gpu-legacy-storage",
            },
            "tdx-cache": {
                "generation": 6,
                "luks_uuid": migration.cache_luks_uuid,
                "filesystem_uuid": migration.cache_filesystem_uuid,
                "filesystem_type": "xfs",
                "hotplug_serial": "gpu-legacy-cache",
            },
        },
        "copied_entries": ["postgres"],
        "omitted_optional_entries": [],
        "content_summary_sha256": summary_hash,
        "active_tree": "migrations/migration-1",
    }
    gpu_infra._validate_migration_marker(migration, custody, marker, summary)
    marker["sources"]["storage"]["generation"] = 11
    with pytest.raises(HTTPException, match="not exact"):
        gpu_infra._validate_migration_marker(migration, custody, marker, summary)


@pytest.mark.asyncio
async def test_promoted_migration_resumes_after_new_custody_generation():
    marker = {"historical": "marker"}
    summary = {"historical": "summary"}
    marker_sha256 = hashlib.sha256(
        json.dumps(
            marker,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    ).hexdigest()
    capability = gpu_infra._migration_capability("migration-1")
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="promoted",
        target_server_id="logical-server",
        source_capability_hash=gpu_infra._capability_hash(capability),
        source_capability_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        promoted_marker_sha256=marker_sha256,
        promoted_summary=summary,
    )
    custody = SimpleNamespace(
        state="current",
        migration_id="migration-1",
        confirmed_generation=12,
    )

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    db = SimpleNamespace(execute=AsyncMock(side_effect=[Result(custody), Result(migration)]))
    server = SimpleNamespace(server_id="logical-server")
    request = GpuInfraMigrationPromoteRequestV1(
        migration_id="migration-1",
        capability=capability,
        marker_sha256=marker_sha256,
        marker=marker,
        content_summary=summary,
    )
    validate_marker = AsyncMock()
    with (
        patch.object(
            gpu_infra,
            "_locked_current_lineage",
            AsyncMock(
                return_value=(
                    server,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    SimpleNamespace(),
                )
            ),
        ),
        patch.object(gpu_infra, "_lineage_matches", return_value=True),
        patch.object(gpu_infra, "_validate_migration_marker", validate_marker),
    ):
        result = await gpu_infra.promote_gpu_infra_migration(
            db,
            server,
            {},
            "a" * 64,
            request,
        )
    assert result.status == "promoted"
    validate_marker.assert_not_called()


@pytest.mark.asyncio
async def test_current_attestation_refreshes_expired_migration_capability():
    old_capability = gpu_infra._migration_capability("migration-1")
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="leased",
        target_server_id="logical-server",
        source_capability_hash=gpu_infra._capability_hash(old_capability),
        source_capability_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        source_capability_consumed_at=None,
        updated_at=None,
    )
    custody = SimpleNamespace(state="current", migration_id="migration-1")

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    db = SimpleNamespace(
        execute=AsyncMock(side_effect=[Result(custody), Result(migration)]),
        flush=AsyncMock(),
    )
    server = SimpleNamespace(server_id="logical-server")
    with (
        patch.object(
            gpu_infra,
            "_locked_current_lineage",
            AsyncMock(
                return_value=(
                    server,
                    SimpleNamespace(),
                    SimpleNamespace(),
                    SimpleNamespace(),
                )
            ),
        ),
        patch.object(gpu_infra, "_lineage_matches", return_value=True),
    ):
        result = await gpu_infra.refresh_gpu_infra_migration(
            db,
            server,
            {},
            "a" * 64,
            GpuInfraMigrationRefreshRequestV1(migration_id="migration-1"),
        )
    assert result.status == "ready"
    assert result.capability != old_capability
    assert migration.source_capability_expires_at > datetime.now(timezone.utc)
    assert migration.source_capability_hash == gpu_infra._capability_hash(result.capability)
    with pytest.raises(HTTPException, match="invalid or expired"):
        gpu_infra._validate_capability(migration, old_capability)
    gpu_infra._validate_capability(migration, result.capability)
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_first_format_rollback_reuses_existing_disk_key():
    custody = SimpleNamespace(
        server_id="logical-server",
        owner_hotkey="owner",
        host_id="host",
        state="current",
        current_passphrase=None,
        active_key_slot=None,
        pending_passphrase=None,
        pending_key_slot=None,
        rollback_generation=1,
        rollback_key_slot=0,
        rollback_passphrase="encrypted-rollback",
        retiring_key_slot=None,
        confirmed_generation=0,
        migration_id=None,
        k3s_encryption_key="encrypted-k3s",
        lease_id=None,
        lease_generation=None,
        lease_expires_at=None,
        lease_attestation_id=None,
        lease_cert_hash=None,
        lease_session_jti=None,
        pending_marker_sha256=None,
        updated_at=None,
    )

    class Result:
        def scalar_one_or_none(self):
            return custody

    db = SimpleNamespace(execute=AsyncMock(return_value=Result()), flush=AsyncMock())
    server = SimpleNamespace(server_id="logical-server", miner_hotkey="owner")
    reservation = SimpleNamespace(
        legacy_vm_name=None,
        legacy_migration_id=None,
    )
    with (
        patch.object(
            gpu_infra,
            "_locked_current_lineage",
            AsyncMock(
                return_value=(
                    server,
                    reservation,
                    SimpleNamespace(),
                    SimpleNamespace(),
                )
            ),
        ),
        patch.object(gpu_infra, "_lineage_matches", return_value=True),
        patch.object(
            gpu_infra,
            "decrypt_passphrase",
            side_effect=lambda value: {
                "encrypted-rollback": "rollback-key",
                "encrypted-k3s": "k3s-key",
            }[value],
        ),
    ):
        response = await gpu_infra.lease_gpu_infra(
            db,
            server,
            {
                "attestation_id": "attestation",
                "jti": "session",
            },
            "a" * 64,
            gpu_infra.GpuInfraLeaseRequestV1(),
        )
    assert response.lease_reused is True
    assert response.next == "rollback-key"
    assert response.generation == 1
    assert response.rollback_generation is None
    assert custody.rollback_passphrase is None
