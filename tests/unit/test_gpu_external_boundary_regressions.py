"""Focused regressions for GPU lifecycle external-work boundaries."""

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.host.locks import GPU_LIFECYCLE_LOCK_INFO_KEY
from api.host import router as host_router
from api.releases import service as release_service
from api.server import router as server_router
from api.storage import launch_sessions, router as storage_router, service as storage_service

with patch("ctypes.CDLL", return_value=MagicMock()):
    from api.instance import router as instance_router


class _BoundaryDb:
    def __init__(self, *, locked=False):
        self.info = {GPU_LIFECYCLE_LOCK_INFO_KEY: True} if locked else {}
        self.events = []

    async def execute(self, _statement, _params=None):
        self.events.append("execute")

    async def commit(self):
        self.events.append("commit")
        self.info.pop(GPU_LIFECYCLE_LOCK_INFO_KEY, None)

    async def rollback(self):
        self.events.append("rollback")
        self.info.pop(GPU_LIFECYCLE_LOCK_INFO_KEY, None)

    async def refresh(self, _row):
        self.events.append("refresh")


@pytest.mark.asyncio
async def test_job_port_failure_commits_before_deletion_publish(monkeypatch):
    db = _BoundaryDb(locked=True)
    instance = SimpleNamespace(
        instance_id="instance-1",
        miner_hotkey="miner-1",
        server_id=None,
        job=SimpleNamespace(started_at=None),
        port_mappings=[{"internal_port": 9000, "external_port": 19000}],
    )
    events = db.events

    async def _notify(_instance):
        events.append("notify")

    def _create_task(coro):
        assert events[-1] == "commit"
        coro.close()
        events.append("scheduled")
        return SimpleNamespace()

    monkeypatch.setattr(instance_router, "notify_deleted", _notify)
    monkeypatch.setattr(asyncio, "create_task", _create_task)

    with pytest.raises(HTTPException) as exc:
        await instance_router._verify_job_ports(
            db,
            instance,
            port_results={instance_router.canonical_sha256(instance.port_mappings[0]): False},
        )

    assert exc.value.status_code == 403
    assert events == ["execute", "commit", "scheduled"]


def test_verified_at_is_applied_only_after_port_cas():
    for function in (
        instance_router.validate_tee_launch_config_instance,
        instance_router.verify_graval_launch_config_instance,
        instance_router.verify_tee_launch_config_instance,
    ):
        source = inspect.getsource(function)
        assert source.index("await _verify_job_ports") < source.index(
            "launch_config.verified_at = func.now()",
            source.index("await _verify_job_ports"),
        )


@pytest.mark.asyncio
async def test_default_storage_observation_runs_between_exact_authorizations(monkeypatch):
    db = _BoundaryDb()
    calls = []
    first = SimpleNamespace(snapshot="same")
    second = SimpleNamespace(snapshot="same")
    results = iter((first, second))

    async def _authorize(current_db, _authorization, _request, operation):
        assert operation == "put"
        calls.append("authorize")
        current_db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True
        return next(results)

    def _snapshot(authorized, operation):
        assert operation == "put"
        return authorized.snapshot

    async def _observe(current_db):
        assert not current_db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        calls.append("observe")
        return {"storage-1"}

    monkeypatch.setattr(launch_sessions, "authorize_default_volume", _authorize)
    monkeypatch.setattr(launch_sessions, "default_volume_authorization_sha256", _snapshot)
    monkeypatch.setattr(storage_service, "observe_storage_liveness", _observe)

    current, observed = await storage_router._authorize_default_volume_with_storage_observation(
        db, "Bearer token", SimpleNamespace(), "put"
    )

    assert current is second
    assert observed == {"storage-1"}
    assert calls == ["authorize", "observe", "authorize"]
    assert db.events == ["commit", "commit"]


@pytest.mark.asyncio
async def test_default_storage_observation_rejects_authority_change(monkeypatch):
    db = _BoundaryDb()
    results = iter((SimpleNamespace(snapshot="first"), SimpleNamespace(snapshot="second")))

    async def _authorize(current_db, *_args):
        current_db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True
        return next(results)

    async def _observe(current_db):
        assert not current_db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return {"storage-1"}

    monkeypatch.setattr(launch_sessions, "authorize_default_volume", _authorize)
    monkeypatch.setattr(
        launch_sessions,
        "default_volume_authorization_sha256",
        lambda authorized, _operation: authorized.snapshot,
    )
    monkeypatch.setattr(storage_service, "observe_storage_liveness", _observe)

    with pytest.raises(HTTPException) as exc:
        await storage_router._authorize_default_volume_with_storage_observation(
            db, "Bearer token", SimpleNamespace(), "get"
        )

    assert exc.value.status_code == 409
    assert db.events == ["commit", "commit", "rollback"]


def test_default_authority_snapshot_binds_current_attestation():
    now = SimpleNamespace(isoformat=lambda: "2026-07-26T00:00:00+00:00")
    row = SimpleNamespace(
        session_id="session-1",
        config_id="config-1",
        instance_id="instance-1",
        binding_id="binding-1",
        user_id="user-1",
        chute_id="chute-1",
        job_id=None,
        compute_type="gpu",
        management_mode="platform",
        server_id="server-1",
        volume_id="volume-1",
        reservation_id="reservation-1",
        allocation_group_id="group-1",
        allocation_group_generation=3,
        process_incarnation="process-1",
        attestation_id="attestation-1",
        attested_cert_pubkey_hash="a" * 64,
        allowed_operations=["put", "get"],
        generation=2,
        access_token_hash="b" * 64,
        access_expires_at=now,
    )
    authorized = SimpleNamespace(session=row, config=SimpleNamespace(verified_at=now))
    first = launch_sessions.default_volume_authorization_sha256(authorized, "put")
    row.attestation_id = "attestation-2"
    second = launch_sessions.default_volume_authorization_sha256(authorized, "put")
    assert first != second


def test_runtime_and_host_liveness_are_precommitted_or_preobserved():
    nonce_source = inspect.getsource(server_router.get_runtime_nonce)
    assert nonce_source.index("await db.commit()") < nonce_source.index("await create_nonce(")

    host_source = inspect.getsource(host_router.list_hosts)
    assert host_source.index("observe_gpu_storage_liveness") < host_source.index(
        "gpu_host_storage_readiness"
    )
    assert "observed_live_storage_ids=observed_storage_by_host.get" in host_source

    status_source = inspect.getsource(release_service.release_status)
    assert status_source.index("observed_storage_by_host") < status_source.index(
        "staged = host.staged_images"
    )
    assert "online_by_server.get(server.server_id, False)" in status_source


def test_storage_external_adapters_are_guarded_and_observations_are_injected():
    grant_source = inspect.getsource(storage_service.issue_grant)
    assert grant_source.index("assert_gpu_external_work_allowed") < grant_source.index(
        "redis_client.setex"
    )

    placement_source = inspect.getsource(storage_service.plan_object_placement)
    locate_source = inspect.getsource(storage_service.locate_object)
    assert "observed_live_storage_ids=observed_live_storage_ids" in placement_source
    assert "observed_live_storage_ids=observed_live_storage_ids" in locate_source
