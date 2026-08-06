from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from api.server import gpu_infra
from api.server.schemas import (
    GpuDecommissionRequestV1,
    GpuServerDecommission,
)


class _Result:
    def __init__(self, *, scalar=None, rows=None):
        self.scalar = scalar
        self.rows = [] if rows is None else rows

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.scalar

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _Db:
    def __init__(self, results):
        self.execute = AsyncMock(side_effect=results)
        self.flush = AsyncMock()
        self.add = Mock()
        self.info = {}


def _request(request_id="11111111-1111-1111-1111-111111111111", reason="retired"):
    return GpuDecommissionRequestV1(request_id=request_id, reason=reason)


def _server(*, retired=True):
    return SimpleNamespace(
        server_id="gpu-server",
        miner_hotkey="owner",
        name="gpu-vm",
        compute_type="gpu",
        gpu_retired_at=(datetime.now(timezone.utc) if retired else None),
        gpu_launch_reservation_id="reservation-1",
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=4,
        gpu_management_mode="miner",
        gpu_process_incarnation="process-1",
        gpu_topology_fingerprint="a" * 64,
        gpu_runtime_session_attestation_id="attestation-1",
        gpu_runtime_session_expires_at=datetime.now(timezone.utc),
        attested_cert="certificate",
        attested_cert_pubkey_hash="b" * 64,
        external_host="gpu.example",
        external_ports={"primary": 31000},
        last_health_at=datetime.now(timezone.utc),
    )


def test_reservation_terminal_gate_requires_positive_physical_evidence():
    assert not gpu_infra._gpu_reservation_decommissionable(SimpleNamespace(state="quarantined"))
    assert not gpu_infra._gpu_reservation_decommissionable(
        SimpleNamespace(state="released", reset_completed_at=None, released_at=None)
    )
    assert gpu_infra._gpu_reservation_decommissionable(
        SimpleNamespace(
            state="expired",
            claimed_at=None,
            launching_at=None,
            running_at=None,
            launch_dispatched_at=None,
        )
    )
    assert not gpu_infra._gpu_reservation_decommissionable(
        SimpleNamespace(
            state="expired",
            claimed_at=datetime.now(timezone.utc),
            launching_at=None,
            running_at=None,
            launch_dispatched_at=None,
        )
    )


@pytest.mark.asyncio
async def test_active_gpu_decommission_is_a_conflict_before_any_terminal_mutation():
    server = _server(retired=False)
    active_reservation = SimpleNamespace(
        reservation_generation=1,
        reservation_id="reservation-1",
        state="running",
    )
    db = _Db(
        [
            _Result(scalar=server),
            _Result(scalar=server),
            _Result(rows=[]),
            _Result(rows=[active_reservation]),
        ]
    )
    lifecycle_lock = AsyncMock()
    with (
        patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", lifecycle_lock),
        pytest.raises(HTTPException, match="completed physical reset") as exc,
    ):
        await gpu_infra.decommission_gpu_server(db, server.server_id, "owner", _request())

    assert exc.value.status_code == 409
    lifecycle_lock.assert_awaited_once_with(db)
    db.add.assert_not_called()
    db.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_node_linked_active_instance_blocks_decommission():
    server = _server(retired=True)
    db = _Db(
        [
            _Result(scalar=server),
            _Result(scalar=server),
            _Result(rows=[]),
            _Result(rows=[]),
            _Result(scalar="active-instance"),
        ]
    )

    with (
        patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="Active GPU instances") as exc,
    ):
        await gpu_infra.decommission_gpu_server(db, server.server_id, "owner", _request())

    assert exc.value.status_code == 409
    active_query = db.execute.await_args_list[4].args[0]
    sql = str(active_query.compile(dialect=postgresql.dialect()))
    assert "LEFT OUTER JOIN instance_nodes" in sql
    assert "LEFT OUTER JOIN nodes" in sql
    assert "instances.server_id" in sql
    assert "nodes.server_id" in sql
    assert "FOR UPDATE OF instances" in sql
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_terminal_gpu_decommission_shreds_authority_and_retains_audit():
    now = datetime.now(timezone.utc)
    server = _server(retired=False)
    reservation = SimpleNamespace(
        reservation_id="reservation-1",
        reservation_generation=7,
        allocation_group_id="group-1",
        allocation_group_generation=4,
        host_id="host-1",
        state="released",
        reset_completed_at=now,
        released_at=now,
    )
    custody = SimpleNamespace(
        server_id=server.server_id,
        state="sealed",
        host_id="host-1",
        reservation_id=reservation.reservation_id,
        reservation_generation=reservation.reservation_generation,
        allocation_group_id=reservation.allocation_group_id,
        allocation_group_generation=reservation.allocation_group_generation,
        confirmed_generation=9,
        guest_closed_generation=9,
        guest_closed_at=now,
        current_passphrase="current",
        pending_passphrase=None,
        retiring_passphrase="retiring",
        k3s_encryption_key="k3s",
        rollback_passphrase="rollback",
        active_key_slot=0,
        pending_key_slot=None,
        retiring_key_slot=1,
        lease_id=None,
        lease_generation=None,
        lease_expires_at=None,
        lease_attestation_id=None,
        lease_cert_hash=None,
        lease_session_jti=None,
        pending_marker_sha256=None,
        rollback_generation=10,
        rollback_key_slot=2,
        decommission_request_id=None,
        decommissioned_at=None,
        updated_at=now,
    )
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="completed",
        legacy_server_id=server.server_id,
        legacy_vm_name=server.name,
        target_server_id="replacement-server",
        storage_current_passphrase=None,
        storage_pending_passphrase=None,
        storage_lease=None,
        cache_current_passphrase=None,
        cache_pending_passphrase=None,
        cache_lease=None,
        k3s_encryption_key=None,
        postgres_password=None,
        source_capability_hash=None,
        source_capability_expires_at=None,
        decommission_request_id=None,
        decommissioned_at=None,
        updated_at=now,
    )
    cutover = SimpleNamespace(state="consumed")
    vm_config = SimpleNamespace(
        volume_passphrases={"unrelated": "legacy-secret"},
        volume_generation_leases={"unrelated": {"generation": 2}},
        k3s_encryption_key="legacy-k3s-secret",
        updated_at=now,
    )
    identity = SimpleNamespace(legacy_vm_name="legacy-vm", updated_at=now)
    db = _Db(
        [
            _Result(scalar=server),
            _Result(scalar=server),
            _Result(rows=[]),
            _Result(rows=[reservation]),
            _Result(scalar=None),
            _Result(rows=[]),
            _Result(scalar=custody),
            _Result(rows=[migration]),
            _Result(rows=[cutover]),
            _Result(scalar=vm_config),
            _Result(scalar=identity),
            _Result(),
            _Result(),
            _Result(),
        ]
    )

    with patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()):
        response = await gpu_infra.decommission_gpu_server(
            db,
            server.server_id,
            "owner",
            _request(),
            replay_attested_spki_sha256="b" * 64,
        )

    assert response.status == "decommissioned"
    assert custody.state == "decommissioned"
    assert custody.decommission_request_id == response.request_id
    assert custody.guest_closed_generation == custody.confirmed_generation
    for name in (
        "current_passphrase",
        "pending_passphrase",
        "retiring_passphrase",
        "k3s_encryption_key",
        "rollback_passphrase",
        "active_key_slot",
        "retiring_key_slot",
        "rollback_generation",
        "rollback_key_slot",
    ):
        assert getattr(custody, name) is None
    assert migration.state == "decommissioned"
    assert migration.decommission_request_id == response.request_id
    assert identity.legacy_vm_name is None
    assert vm_config.volume_passphrases == {}
    assert vm_config.volume_generation_leases == {}
    assert vm_config.k3s_encryption_key is None
    assert server.gpu_launch_reservation_id is None
    assert server.gpu_allocation_group_id is None
    assert server.gpu_runtime_session_attestation_id is None
    assert server.attested_cert is None
    assert server.attested_cert_pubkey_hash is None
    assert server.gpu_retired_at is not None
    audit = db.add.call_args.args[0]
    assert isinstance(audit, GpuServerDecommission)
    assert audit.server_id == server.server_id
    assert audit.replay_attested_spki_sha256 == "b" * 64
    assert audit.migration_ids == [migration.migration_id]
    assert audit.response_json == response.model_dump(mode="json")
    node_query = db.execute.await_args_list[5].args[0]
    node_sql = str(node_query.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF nodes" in node_sql
    assert db.flush.await_count == 2


@pytest.mark.asyncio
async def test_target_migration_does_not_authorize_unrelated_legacy_key_shred():
    server = _server()
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="completed",
        legacy_server_id="different-legacy-server",
        legacy_vm_name=server.name,
        target_server_id=server.server_id,
    )
    vm_config = SimpleNamespace(
        volume_passphrases={"storage": "unproven-secret"},
        volume_generation_leases={},
        k3s_encryption_key=None,
    )
    db = _Db(
        [
            _Result(scalar=server),
            _Result(scalar=server),
            _Result(rows=[]),
            _Result(rows=[]),
            _Result(scalar=None),
            _Result(rows=[]),
            _Result(scalar=None),
            _Result(rows=[migration]),
            _Result(rows=[]),
            _Result(scalar=vm_config),
        ]
    )

    with (
        patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="Legacy GPU key custody") as exc,
    ):
        await gpu_infra.decommission_gpu_server(db, server.server_id, "owner", _request())

    assert exc.value.status_code == 409
    assert vm_config.volume_passphrases == {"storage": "unproven-secret"}
    db.add.assert_not_called()
    db.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_counterpart_can_decommission_after_shared_migration_is_terminal():
    now = datetime.now(timezone.utc)
    server = _server()
    migration = SimpleNamespace(
        migration_id="migration-1",
        state="decommissioned",
        legacy_server_id="legacy-server",
        legacy_vm_name="legacy-vm",
        target_server_id=server.server_id,
        decommission_request_id="33333333-3333-3333-3333-333333333333",
        decommissioned_at=now,
    )
    db = _Db(
        [
            _Result(scalar=server),
            _Result(scalar=server),
            _Result(rows=[]),
            _Result(rows=[]),
            _Result(scalar=None),
            _Result(rows=[]),
            _Result(scalar=None),
            _Result(rows=[migration]),
            _Result(rows=[]),
            _Result(scalar=None),
            _Result(scalar=None),
            _Result(),
            _Result(),
            _Result(),
        ]
    )

    with patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()):
        response = await gpu_infra.decommission_gpu_server(
            db,
            server.server_id,
            "owner",
            _request(request_id="44444444-4444-4444-4444-444444444444"),
        )

    assert response.status == "decommissioned"
    assert migration.state == "decommissioned"
    assert migration.decommission_request_id == "33333333-3333-3333-3333-333333333333"
    audit = db.add.call_args.args[0]
    assert audit.migration_ids == [migration.migration_id]
    assert db.flush.await_count == 2


@pytest.mark.asyncio
async def test_exact_decommission_retry_replays_audit_and_mismatch_fails_closed():
    server = _server()
    request = _request()
    timestamp = datetime.now(timezone.utc)
    audit = GpuServerDecommission(
        server_id=server.server_id,
        request_id=request.request_id,
        owner_hotkey="owner",
        reason=request.reason,
        replay_attested_spki_sha256="b" * 64,
        migration_ids=[],
        response_json={
            "schema": "chutes.gpu-decommissioned",
            "version": 1,
            "server_id": server.server_id,
            "request_id": request.request_id,
            "decommissioned_at": timestamp.isoformat(),
            "status": "decommissioned",
        },
        decommissioned_at=timestamp,
    )
    db = _Db([_Result(scalar=server), _Result(scalar=server), _Result(rows=[audit])])
    with patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()):
        replay = await gpu_infra.decommission_gpu_server(
            db,
            server.server_id,
            "owner",
            request,
            replay_attested_spki_sha256="b" * 64,
        )
    assert replay.decommissioned_at == timestamp
    db.add.assert_not_called()

    mismatch_db = _Db([_Result(scalar=server), _Result(scalar=server), _Result(rows=[audit])])
    with (
        patch.object(gpu_infra, "acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="identity was already consumed") as exc,
    ):
        await gpu_infra.decommission_gpu_server(
            mismatch_db,
            server.server_id,
            "owner",
            _request(reason="different terminal reason"),
            replay_attested_spki_sha256="b" * 64,
        )
    assert exc.value.status_code == 409


def test_decommission_wire_and_migration_are_fail_closed():
    with pytest.raises(ValidationError):
        _request(request_id="not-a-uuid")
    with pytest.raises(ValidationError):
        _request(reason="   ")

    migration = (
        Path(__file__).resolve().parents[2]
        / "api/migrations/20260728120000_gpu_terminal_decommission.sql"
    ).read_text()
    assert "state IN ('sealed', 'decommissioned')" in migration
    assert "current_passphrase IS NULL" in migration
    assert "k3s_encryption_key IS NULL" in migration
    assert "preserve_gpu_server_decommission_audit" in migration
    assert "BEFORE UPDATE OR DELETE ON gpu_server_decommissions" in migration
    assert "preserve_gpu_decommission_terminal" in migration
    assert "decommissioned GPU server rows are immutable" in migration
    assert "OLD.gpu_retired_at IS NULL" in migration
    assert "NEW.gpu_retired_at = _terminal_at" in migration
    assert "to_jsonb(NEW) - ARRAY[" in migration
    assert "decommissioned GPU custody cannot be recreated" in migration
    assert "BEFORE INSERT OR UPDATE OR DELETE ON gpu_infra_custodies" in migration
    assert "cannot remove GPU terminal-decommission schema" in migration
