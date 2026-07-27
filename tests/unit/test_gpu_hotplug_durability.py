from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.gpu_contracts import GpuHotplugCommandAckV1
from api.gpu_hotplug_service import (
    GpuHotplugError,
    _command_from_row,
    _new_command,
    record_gpu_hotplug_ack,
    require_gpu_hotplug_runtime_ack,
)
from api.host.schemas import canonical_sha256


def _command_row():
    reservation = SimpleNamespace(
        legacy_migration_id="migration-1",
        server_id="stable-server",
        reservation_id="reservation-1",
        claims_sha256="a" * 64,
        process_incarnation="process-1",
        host_id="host-1",
        host_key_generation=1,
        host_boot_generation=1,
        reservation_generation=1,
        allocation_group_id="group-1",
        allocation_group_generation=1,
    )
    command = _new_command(reservation)
    return SimpleNamespace(
        **command.model_dump(mode="python"),
        state="dispatched",
        dispatch_lease_owner=None,
        dispatch_lease_expires_at=None,
        ack=None,
        ack_sha256=None,
        acknowledged_at=None,
        failure_code=None,
        failure_reason=None,
        updated_at=None,
    )


def _failed_ack(row):
    document = {
        "schema": "chutes.gpu-hotplug-command-ack.v1",
        "version": 1,
        "command_id": row.command_id,
        "payload_sha256": row.payload_sha256,
        "state": "failed",
        "objects": [
            {
                "namespace": namespace,
                "block_node_name": f"block-{namespace}",
                "device_id": f"device-{namespace}",
                "serial": f"serial-{namespace}",
                "source_path_sha256": "b" * 64,
                "block_node_present": False,
                "device_present": False,
                "device_bound": False,
            }
            for namespace in ("storage", "tdx-cache")
        ],
        "failure_code": "custody_ended_before_hotplug_ack",
        "failure_reason": "Durable command could not complete before custody ended.",
    }
    return GpuHotplugCommandAckV1(
        **document,
        ack_sha256=canonical_sha256(document),
    )


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Db:
    def __init__(self, values):
        self.values = iter(values)
        self.info = {}
        self.flush = AsyncMock()

    async def execute(self, _query):
        return _Result(next(self.values))


@pytest.mark.asyncio
@pytest.mark.parametrize("ended_by", ["reboot", "teardown"])
async def test_exact_failed_hotplug_ack_terminalizes_after_custody_ended(ended_by):
    row = _command_row()
    host_boot = 2 if ended_by == "reboot" else 1
    current_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=1,
        boot_generation=host_boot,
    )
    locked_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=1,
        boot_generation=host_boot,
        provisioning_state="ready",
    )
    reservation = SimpleNamespace(
        host_id=row.host_id,
        host_key_generation=1,
        host_boot_generation=1,
        reservation_generation=1,
        claims_sha256=row.claims_sha256,
        process_incarnation=row.process_incarnation,
        server_id=row.stable_server_id,
        legacy_migration_id=row.migration_id,
        reservation_id=row.reservation_id,
        state="running" if ended_by == "reboot" else "resetting",
    )
    group = SimpleNamespace(
        state="running" if ended_by == "reboot" else "resetting",
        reservation_id=row.reservation_id,
        generation=1,
        reservation_generation=1,
        process_incarnation=row.process_incarnation,
    )
    migration = SimpleNamespace(
        host_id=row.host_id,
        target_server_id=row.stable_server_id,
        migration_id=row.migration_id,
        state="ready",
    )
    db = _Db([row, locked_host, reservation, group, migration])
    ack = _failed_ack(row)
    with (
        patch(
            "api.gpu_hotplug_service.acquire_gpu_lifecycle_lock",
            AsyncMock(return_value=None),
        ),
        patch(
            "api.host.gpu_allocations.quarantine_gpu_reservation_control_plane",
            AsyncMock(),
        ) as quarantine,
    ):
        result = await record_gpu_hotplug_ack(
            db,
            current_host,
            row.command_id,
            ack,
        )
    assert result == _command_from_row(row)
    assert row.state == "failed"
    assert row.ack_sha256 == ack.ack_sha256
    db.flush.assert_awaited_once()
    quarantine.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_hotplug_ack_creates_normal_delete_intent_before_release():
    row = _command_row()
    current_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=row.host_key_generation,
        boot_generation=row.host_boot_generation,
    )
    locked_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=row.host_key_generation,
        boot_generation=row.host_boot_generation,
        provisioning_state="ready",
    )
    reservation = _runtime_reservation(row)
    group = _runtime_group(row)
    migration = SimpleNamespace(
        host_id=row.host_id,
        target_server_id=row.stable_server_id,
        migration_id=row.migration_id,
        state="ready",
    )
    db = _Db([row, locked_host, reservation, group, migration])
    ack = _failed_ack(row)
    lifecycle_fence = AsyncMock()
    with (
        patch(
            "api.gpu_hotplug_service.acquire_gpu_lifecycle_lock",
            AsyncMock(return_value=None),
        ),
        patch(
            "api.host.gpu_allocations.request_gpu_lifecycle_fence",
            lifecycle_fence,
        ),
    ):
        result = await record_gpu_hotplug_ack(
            db,
            current_host,
            row.command_id,
            ack,
        )
    assert result == _command_from_row(row)
    lifecycle_fence.assert_awaited_once_with(
        db,
        row.reservation_id,
        code=ack.failure_code,
        reason=ack.failure_reason,
        operation_type="normal_delete",
        metadata={"hotplug_command_id": row.command_id},
    )
    assert row.state == "failed"
    assert row.ack_sha256 == ack.ack_sha256


@pytest.mark.asyncio
async def test_successful_hotplug_ack_cannot_terminalize_ended_custody():
    row = _command_row()
    failed = _failed_ack(row)
    document = failed.model_dump(
        mode="json",
        exclude={"ack_sha256", "failure_code", "failure_reason"},
    )
    document["state"] = "acked"
    for item in document["objects"]:
        item["block_node_present"] = True
        item["device_present"] = True
        item["device_bound"] = True
    ack = GpuHotplugCommandAckV1(
        **document,
        ack_sha256=canonical_sha256(document),
    )
    current_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=1,
        boot_generation=2,
    )
    locked_host = SimpleNamespace(
        host_id=row.host_id,
        active_key_generation=1,
        boot_generation=2,
        provisioning_state="ready",
    )
    db = _Db([row, locked_host, None, None, None])
    with patch(
        "api.gpu_hotplug_service.acquire_gpu_lifecycle_lock",
        AsyncMock(return_value=None),
    ):
        with pytest.raises(GpuHotplugError, match="custody changed"):
            await record_gpu_hotplug_ack(
                db,
                current_host,
                row.command_id,
                ack,
            )
    assert row.ack_sha256 is None


@pytest.mark.asyncio
async def test_exact_hotplug_ack_replay_precedes_mutable_custody_checks():
    row = _command_row()
    ack = _failed_ack(row)
    row.state = "failed"
    row.ack = ack.model_dump(mode="json", exclude_none=True)
    row.ack_sha256 = ack.ack_sha256
    db = _Db([row])
    host = SimpleNamespace(host_id=row.host_id)
    with patch(
        "api.gpu_hotplug_service.acquire_gpu_lifecycle_lock",
        AsyncMock(return_value=None),
    ):
        result = await record_gpu_hotplug_ack(
            db,
            host,
            row.command_id,
            ack,
        )
    assert result == _command_from_row(row)
    db.flush.assert_not_awaited()


def _successful_ack(row):
    document = _failed_ack(row).model_dump(
        mode="json",
        exclude={"ack_sha256", "failure_code", "failure_reason"},
    )
    document["state"] = "acked"
    for item in document["objects"]:
        item["block_node_present"] = True
        item["device_present"] = True
        item["device_bound"] = True
    return GpuHotplugCommandAckV1(
        **document,
        ack_sha256=canonical_sha256(document),
    )


def _runtime_reservation(row, *, legacy=True):
    return SimpleNamespace(
        legacy_migration_id=row.migration_id if legacy else None,
        server_id=row.stable_server_id,
        reservation_id=row.reservation_id,
        claims_sha256=row.claims_sha256,
        process_incarnation=row.process_incarnation,
        host_id=row.host_id,
        host_key_generation=row.host_key_generation,
        host_boot_generation=row.host_boot_generation,
        reservation_generation=row.reservation_generation,
        allocation_group_id=row.allocation_group_id,
        allocation_group_generation=row.allocation_group_generation,
        state="running",
        management_mode="miner",
    )


def _runtime_group(row):
    return SimpleNamespace(
        state="running",
        reservation_id=row.reservation_id,
        generation=row.allocation_group_generation,
        reservation_generation=row.reservation_generation,
        process_incarnation=row.process_incarnation,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("row_state", [None, "pending", "failed"])
async def test_runtime_gate_rejects_missing_pending_and_failed_hotplug(row_state):
    row = _command_row()
    reservation = _runtime_reservation(row)
    if row_state is None:
        command_row = None
    else:
        command_row = row
        row.state = row_state
        if row_state == "failed":
            ack = _failed_ack(row)
            row.ack = ack.model_dump(mode="json", exclude_none=True)
            row.ack_sha256 = ack.ack_sha256
            row.acknowledged_at = row.updated_at
    db = _Db([command_row, _runtime_group(row)])
    with pytest.raises(GpuHotplugError, match="hotplug|custody"):
        await require_gpu_hotplug_runtime_ack(
            db, reservation, row.stable_server_id
        )


@pytest.mark.asyncio
async def test_runtime_gate_accepts_only_exact_successful_hotplug_ack():
    row = _command_row()
    ack = _successful_ack(row)
    row.state = "acked"
    row.ack = ack.model_dump(mode="json", exclude_none=True)
    row.ack_sha256 = ack.ack_sha256
    row.acknowledged_at = object()
    await require_gpu_hotplug_runtime_ack(
        _Db([row, _runtime_group(row)]),
        _runtime_reservation(row),
        row.stable_server_id,
    )


@pytest.mark.asyncio
async def test_runtime_gate_does_not_apply_to_nonlegacy_reservation():
    row = _command_row()
    db = AsyncMock()
    await require_gpu_hotplug_runtime_ack(
        db, _runtime_reservation(row, legacy=False), row.stable_server_id
    )
    db.execute.assert_not_awaited()
