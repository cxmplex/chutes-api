"""Unit boundaries for durable miner launch response replay."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api import gpu_scheduler
from api.instance import router as instance_router


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.value


class _OrderedLockDb:
    def __init__(self, order: list[str]):
        self.order = order
        self.results = iter(
            (
                _ScalarResult(SimpleNamespace(user_id="user-1")),
                _ScalarResult(None),
            )
        )

    async def execute(self, statement):
        rendered = str(statement)
        if "FROM users" in rendered:
            self.order.append("user")
        elif "FROM launch_configs" in rendered:
            self.order.append("launch_config")
        else:  # pragma: no cover - makes unexpected query additions fail loudly.
            raise AssertionError(f"unexpected lock query: {rendered}")
        return next(self.results)


@pytest.mark.parametrize(
    "value",
    (
        None,
        "",
        "not-a-uuid",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}",
    ),
)
def test_miner_launch_request_id_must_be_canonical_lowercase_uuid(value):
    with pytest.raises(HTTPException) as exc:
        instance_router._canonical_miner_launch_request_id(value)
    assert exc.value.status_code == 422


def test_canonical_miner_launch_request_id_is_accepted():
    value = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert instance_router._canonical_miner_launch_request_id(value) == value


@pytest.mark.asyncio
async def test_new_miner_launch_uses_shared_storage_then_gpu_lock_order(monkeypatch):
    order: list[str] = []
    db = _OrderedLockDb(order)
    volume = SimpleNamespace(volume_id="volume-1")

    async def _ensure(_db, user_id, chute_id):
        assert (_db, user_id, chute_id) == (db, "user-1", "chute-1")
        order.append("binding_volume")
        return SimpleNamespace(), volume, SimpleNamespace()

    async def _gpu_lock(_db, chute_id, job_id):
        assert (_db, chute_id, job_id) == (db, "chute-1", "job-1")
        order.append("gpu_workload")

    async def _lifecycle_lock(_db):
        assert _db is db
        order.append("gpu_lifecycle")

    monkeypatch.setattr(instance_router, "ensure_default_volume_binding", _ensure)
    monkeypatch.setattr(
        instance_router,
        "acquire_gpu_lifecycle_lock",
        _lifecycle_lock,
    )
    monkeypatch.setattr(gpu_scheduler, "acquire_gpu_workload_lock", _gpu_lock)

    (
        locked_volume,
        existing,
    ) = await instance_router._lock_new_miner_launch_storage_before_gpu_workload(
        db,
        launch_owner_id="user-1",
        chute_id="chute-1",
        job_id="job-1",
        hotkey="miner-1",
        request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )

    assert locked_volume is volume
    assert existing is None
    assert order == [
        "user",
        "gpu_lifecycle",
        "launch_config",
        "binding_volume",
        "gpu_workload",
    ]
