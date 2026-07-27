"""Focused regressions for GPU lifecycle external-work boundaries."""

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.chute.schemas import NodeSelector
from api.host import gpu_allocations, router as host_router, service as host_service
from api.host.locks import GPU_LIFECYCLE_LOCK_INFO_KEY
from api.releases import service as release_service
from api.releases.provenance import ProvenanceError
from api.server import router as server_router, service as server_service
from api.storage import launch_sessions, router as storage_router, service as storage_service
from tests.unit.test_gpu_allocations import _report

import api.gpu_scheduler as gpu_scheduler

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


@pytest.mark.asyncio
async def test_provenance_locked_refetch_is_cache_only_and_eviction_rejects(
    monkeypatch, tmp_path
):
    key_path = tmp_path / "cosign.pub"
    key_path.write_bytes(b"trusted-key-bytes")
    monkeypatch.setattr(
        release_service.settings,
        "trusted_provenance_public_key_path",
        key_path,
    )
    monkeypatch.setattr(release_service.settings, "provenance_cosign_binary", "cosign-test")
    calls = []
    document = {"schema_version": 3}

    def _verify(payload, signature, public_key_path, *, cosign_binary):
        calls.append((payload, signature, public_key_path, cosign_binary))
        return document

    monkeypatch.setattr(release_service, "verify_provenance_signature", _verify)
    release_service._PROVENANCE_VERIFICATION_CACHE.clear()
    db = _BoundaryDb()

    first = release_service._verified_provenance_document(
        db,
        image_role="gpu",
        payload="canonical-payload",
        signature="detached-signature",
    )
    assert first is document
    assert len(calls) == 1

    db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True
    replay = release_service._verified_provenance_document(
        db,
        image_role="gpu",
        payload="canonical-payload",
        signature="detached-signature",
    )
    assert replay is document
    assert len(calls) == 1

    release_service._PROVENANCE_VERIFICATION_CACHE.clear()
    with pytest.raises(ProvenanceError, match="absent or was evicted"):
        release_service._verified_provenance_document(
            db,
            image_role="gpu",
            payload="canonical-payload",
            signature="detached-signature",
        )
    assert len(calls) == 1


def test_release_provenance_preflight_precedes_activation_locks():
    activation_source = inspect.getsource(release_service.activate_release)
    assert activation_source.index("_preverify_release_images") < activation_source.index(
        "await acquire_gpu_lifecycle_lock"
    )
    validator_source = inspect.getsource(
        release_service._verified_provenance_document
    )
    locked_branch = validator_source.index("GPU_LIFECYCLE_LOCK_INFO_KEY")
    verifier_call = validator_source.rindex("verify_provenance_signature")
    assert locked_branch < verifier_call
    assert "key not in snapshot_keys or cached is None" in validator_source


def test_gpu_release_preverification_precedes_every_lifecycle_call_site():
    for function in (
        gpu_allocations.reconcile_gpu_inventory,
        gpu_allocations.claim_gpu_reservation,
        gpu_allocations.mark_gpu_launching,
    ):
        source = inspect.getsource(function)
        assert source.index("await _preverify_active_gpu_release") < source.index(
            "await _host_lock"
        )

    reserve_source = inspect.getsource(gpu_allocations.reserve_gpu_group)
    assert reserve_source.index("await _preverify_active_gpu_release") < (
        reserve_source.index("await acquire_gpu_lifecycle_lock")
    )
    assert "GPU_LIFECYCLE_LOCK_INFO_KEY" in reserve_source

    active_source = inspect.getsource(gpu_allocations._active_gpu_release)
    assert "_validate_active_release(release, db)" in active_source

    registration_source = inspect.getsource(server_service.register_gpu_server)
    assert registration_source.index(
        "await preverify_active_gpu_release_for_host"
    ) < registration_source.index("await before_publish()")

    platform_route_source = inspect.getsource(
        host_router.create_platform_gpu_reservation_endpoint
    )
    assert platform_route_source.index(
        "await _preverify_active_gpu_release"
    ) < platform_route_source.index("await acquire_gpu_workload_lock")

    socket_source = inspect.getsource(host_service.verify_host_socket_authentication)
    assert socket_source.index("await _preverify_active_gpu_release") < (
        socket_source.index("await acquire_gpu_lifecycle_lock")
    )

    scheduler_source = inspect.getsource(gpu_scheduler._place_workload)
    assert scheduler_source.index("await _preverify_active_gpu_release") < (
        scheduler_source.index("await acquire_gpu_workload_lock")
    )


class _CandidateSession:
    def __init__(self, group, host, report):
        self.row = (group, host, report)

    async def execute(self, _statement):
        return SimpleNamespace(all=lambda: [self.row])

    async def get(self, *_args, **_kwargs):
        raise AssertionError("scheduler must not load stale group.last_report_id")


def _scheduler_inventory_state(report):
    inventory_group = report.groups[0]
    group = SimpleNamespace(
        allocation_group_id="group-1",
        state="available",
        management_mode=None,
        reservation_id=None,
        gpu_count=len(inventory_group.devices),
        vram_mib=min(device.vram_mib for device in inventory_group.devices),
        gpu_identifiers=[device.gpu_identifier for device in inventory_group.devices],
        model=inventory_group.model,
        profile_id=inventory_group.reported_profile_id,
        topology_fingerprint=inventory_group.topology_fingerprint,
        gpu_bdfs=[device.bdf for device in inventory_group.devices],
        gpu_uuids=[device.uuid for device in inventory_group.devices],
        gpu_attestation_certificate_sha256s=[
            device.attestation_certificate_sha256 for device in inventory_group.devices
        ],
        gpu_release_id=report.gpu_release_id,
        profile_contract_sha256=report.profile_contract_sha256,
        last_report_id="report-r1",
    )
    host = SimpleNamespace(
        host_id=report.host_id,
        active_key_generation=report.host_key_generation,
        boot_generation=report.host_boot_generation,
        boot_id=report.host_boot_id,
        gpu_inventory_report_generation=report.report_generation,
    )
    report_row = SimpleNamespace(
        report_id=report.report_id,
        claims=report.model_dump(mode="json"),
        claims_sha256=gpu_allocations.canonical_sha256(report),
        reconciliation_status="accepted",
        host_id=report.host_id,
        host_key_generation=report.host_key_generation,
        host_boot_generation=report.host_boot_generation,
        report_generation=report.report_generation,
        topology_fingerprint=inventory_group.topology_fingerprint,
    )
    return group, host, report_row


@pytest.mark.asyncio
async def test_scheduler_uses_host_latest_r2_capacity_after_reset():
    base = _report()
    current = base.model_copy(
        update={"report_id": "report-r2", "report_generation": 2}
    )
    group, host, report_row = _scheduler_inventory_state(current)
    selector = NodeSelector(
        compute_type="gpu",
        gpu_count=len(current.groups[0].devices),
        min_vram_gb_per_gpu=16,
        include=["b200"],
    )

    assert not gpu_allocations._latest_gpu_inventory_matches_group(
        host, group, report_row
    )
    assert gpu_allocations._latest_gpu_inventory_matches_group(
        host,
        group,
        report_row,
        require_group_report_link=False,
    )
    candidates = await gpu_scheduler._candidate_groups(
        _CandidateSession(group, host, report_row),
        selector,
        required_disk_mib=10 * 1024,
    )
    assert candidates == [(group, host, report_row)]

    reduced = current.model_copy(
        update={
            "resources": current.resources.model_copy(
                update={"gpu_scratch_disk_mib": 10 * 1024 - 1}
            )
        }
    )
    reduced_group, reduced_host, reduced_row = _scheduler_inventory_state(reduced)
    assert await gpu_scheduler._candidate_groups(
        _CandidateSession(reduced_group, reduced_host, reduced_row),
        selector,
        required_disk_mib=10 * 1024,
    ) == []


def test_scheduler_carries_latest_report_into_locked_reservation_cas():
    scheduler_source = inspect.getsource(gpu_scheduler._place_workload)
    assert "expected_inventory_report_id=report.report_id" in scheduler_source
    assert "expected_inventory_report_sha256=report.claims_sha256" in scheduler_source

    reserve_source = inspect.getsource(gpu_allocations.reserve_gpu_group)
    assert "GpuInventoryReport.report_generation" in reserve_source
    assert "require_group_report_link=False" in reserve_source
    assert "current_report.report_id != expected_inventory_report_id" in reserve_source
    assert "current_report.claims_sha256" in reserve_source
