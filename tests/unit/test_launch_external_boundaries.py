import copy
import inspect
import json as std_json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.bounty import util as bounty_util
from api.config import settings
from api.host.locks import GPU_LIFECYCLE_LOCK_INFO_KEY
from api.host.schemas import canonical_sha256


with patch("ctypes.CDLL", return_value=MagicMock()):
    from api.instance import router as instance_router


class _Db:
    def __init__(self, *, locked=False):
        self.info = {GPU_LIFECYCLE_LOCK_INFO_KEY: True} if locked else {}


class _LostThenReplayRedis:
    def __init__(self, envelope):
        self.envelope = std_json.dumps(envelope, sort_keys=True).encode()
        self.calls = []

    async def eval(self, *args):
        self.calls.append(args)
        # Model SafeRedis's shielded timeout: Lua completed and cached the
        # envelope, but the first caller received no response.
        if len(self.calls) == 1:
            return None
        return self.envelope


def _activation_objects(*, extra=None):
    now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
    launch_config = SimpleNamespace(
        config_id="config-1",
        chute_id="chute-1",
        job_id=None,
        user_id="user-1",
        miner_hotkey="miner-1",
        compute_type="gpu",
        server_id="server-1",
        gpu_management_mode="miner",
        gpu_launch_reservation_id="reservation-1",
        verified_at=now,
        failed_at=None,
        completed_at=None,
    )
    instance = SimpleNamespace(
        instance_id="instance-1",
        config_id="config-1",
        chute_id="chute-1",
        server_id="server-1",
        gpu_management_mode="miner",
        gpu_launch_reservation_id="reservation-1",
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=9,
        gpu_process_incarnation="process-1",
        miner_hotkey="miner-1",
        deployment_id="deployment-1",
        host="192.0.2.10",
        port=8000,
        cacert="certificate",
        active=False,
        verified=True,
        activated_at=None,
        bounty=False,
        compute_multiplier=2.0,
        created_at=now,
        extra=copy.deepcopy(extra)
        if extra is not None
        else {"warmup_compute_multiplier": 2.0},
    )
    chute = SimpleNamespace(
        chute_id="chute-1",
        user_id="user-1",
        name="example",
        public=True,
        tee=True,
        disabled=False,
        shutdown_after_seconds=300,
        created_at=now,
    )
    return launch_config, instance, chute


def _external_results(attempt_id):
    bounty = {
        "schema": "chutes.activation-bounty-result.v1",
        "attempt_id": attempt_id,
        "chute_id": "chute-1",
        "claimed_at": 200.0,
        "bounty": {"amount": 250, "created_at": 150.0, "age_seconds": 50},
    }
    warmup = {
        "schema": "chutes.activation-warmup-result.v1",
        "attempt_id": attempt_id,
        "chute_id": "chute-1",
        "consumed_at": 200.0,
        "requested_at": "125.0",
    }
    return bounty, warmup


@pytest.mark.asyncio
async def test_default_volume_locks_before_gpu_workload(monkeypatch):
    db = _Db()
    calls = []
    volume = SimpleNamespace(volume_id="volume-1")

    async def _binding(current_db, owner_id, chute_id):
        assert current_db is db
        assert owner_id == "owner-1"
        assert chute_id == "chute-1"
        assert not current_db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        calls.append("user-binding-volume")
        return SimpleNamespace(), volume, 1

    async def _workload(current_db, chute_id, job_id):
        assert current_db is db
        assert chute_id == "chute-1"
        assert job_id == "job-1"
        calls.append("gpu-workload")
        current_db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True

    monkeypatch.setattr(instance_router, "ensure_default_volume_binding", _binding)
    monkeypatch.setattr(
        "api.gpu_scheduler.acquire_gpu_workload_lock",
        _workload,
    )

    result = await instance_router._lock_default_volume_before_gpu_workload(
        db,
        launch_owner_id="owner-1",
        chute_id="chute-1",
        job_id="job-1",
    )

    assert result is volume
    assert calls == ["user-binding-volume", "gpu-workload"]


@pytest.mark.asyncio
async def test_launch_external_adapter_guard_fails_before_pricing():
    class _Selector:
        async def current_estimated_price(self):
            raise AssertionError("pricing adapter must not run while locked")

    with pytest.raises(RuntimeError, match="launch pricing lookup"):
        await instance_router._collect_launch_external_work(
            _Db(locked=True),
            {},
            SimpleNamespace(job_id=None),
            SimpleNamespace(chute_id="chute-1"),
            _Selector(),
            is_private=False,
            managed_tee=False,
        )


@pytest.mark.asyncio
async def test_collect_launch_external_work_guards_adapters_and_hashes(monkeypatch):
    db = _Db()
    guard_operations = []

    def _guard(current_db, operation):
        assert current_db is db
        assert not current_db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        guard_operations.append(operation)

    class _Redis:
        async def get(self, key):
            assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
            if key == "scale:chute-1":
                return b"2"
            if key == "uqhist:miner-1":
                return b'[{"count":2}]'
            raise AssertionError(key)

    class _Task:
        async def wait_result(self, *, timeout):
            assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
            assert timeout == instance_router.FS_HASH_RESULT_TIMEOUT
            return SimpleNamespace(return_value="filesystem-1")

    async def _price():
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return {"usd": {"hour": 1.25}}

    async def _manual_boost(chute_id):
        assert chute_id == "chute-1"
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return 1.1

    async def _inspecto_hash(image_id):
        assert image_id == "image-1"
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return "inspecto-1"

    async def _bounty_exists(chute_id):
        assert chute_id == "chute-1"
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return True

    async def _dispatch(*args, **kwargs):
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        return _Task()

    monkeypatch.setattr(instance_router, "assert_gpu_external_work_allowed", _guard)
    monkeypatch.setattr(instance_router, "get_manual_boost", _manual_boost)
    monkeypatch.setattr(instance_router, "get_inspecto_hash", _inspecto_hash)
    monkeypatch.setattr(instance_router, "check_bounty_exists", _bounty_exists)
    monkeypatch.setattr(instance_router.settings, "_redis_client", _Redis())
    monkeypatch.setattr(
        instance_router.generate_fs_hash,
        "kiq",
        _dispatch,
    )
    monkeypatch.setenv("PS_OP", "1")
    monkeypatch.setenv("CFSV_OP", "1")

    input_document = {
        "schema": "chutes.launch-external-input.v1",
        "config_id": "config-1",
    }
    snapshot = await instance_router._collect_launch_external_work(
        db,
        input_document,
        SimpleNamespace(job_id=None, miner_hotkey="miner-1", config_id="config-1"),
        SimpleNamespace(
            chute_id="chute-1",
            tee=False,
            chutes_version="0.3.61",
            image_id="image-1",
            image=SimpleNamespace(patch_version="initial"),
            filename="chute.py",
        ),
        SimpleNamespace(current_estimated_price=_price),
        is_private=True,
        managed_tee=False,
    )

    assert snapshot == {
        "input_sha256": canonical_sha256(input_document),
        "hourly_price_usd": 1.25,
        "manual_boost": 1.1,
        "inspecto_hash": "inspecto-1",
        "scale_value": "2",
        "inventory_history": [{"count": 2}],
        "bounty_exists": True,
        "filesystem_hash": "filesystem-1",
        "result_sha256": snapshot["result_sha256"],
    }
    instance_router._validate_launch_external_snapshot(snapshot, input_document)
    assert guard_operations == [
        "launch pricing lookup",
        "launch manual boost lookup",
        "launch Inspecto hash lookup",
        "launch scale telemetry lookup",
        "private launch inventory telemetry lookup",
        "private launch bounty lookup",
        "launch filesystem hash dispatch",
        "launch filesystem hash wait",
    ]


@pytest.mark.asyncio
async def test_inspecto_lookup_guard_fails_before_separate_session(monkeypatch):
    monkeypatch.setenv("PS_OP", "1")
    with pytest.raises(RuntimeError, match="Inspecto hash lookup"):
        await instance_router._validate_launch_config_inspecto(
            _Db(locked=True),
            SimpleNamespace(config_id="config-1"),
            SimpleNamespace(chutes_version="0.3.50", image_id="image-1"),
            SimpleNamespace(inspecto="hash", rint_nonce=None),
            "test",
        )


@pytest.mark.asyncio
async def test_bounty_claim_lost_response_replays_exact_envelope(monkeypatch):
    attempt_id = "attempt-1"
    expected = _external_results(attempt_id)[0]
    redis = _LostThenReplayRedis(expected)
    monkeypatch.setattr(settings, "_lite_redis_client", redis)

    with pytest.raises(RuntimeError, match="no durable result"):
        await bounty_util.claim_bounty("chute-1", attempt_id=attempt_id)
    replayed = await bounty_util.claim_bounty("chute-1", attempt_id=attempt_id)

    assert replayed == expected
    assert redis.calls[0] == redis.calls[1]
    assert redis.calls[0][1:5] == (
        3,
        "bounty_v2:chute-1",
        "activation_bounty_result:attempt-1",
        "bounty_cooldown:chute-1",
    )
    assert "redis.call('GET', replay_key)" in bounty_util.CLAIM_BOUNTY_REPLAY_LUA
    assert (
        "redis.call('SET', replay_key, envelope" in bounty_util.CLAIM_BOUNTY_REPLAY_LUA
    )
    assert "redis.call('DEL', bounty_key)" in bounty_util.CLAIM_BOUNTY_REPLAY_LUA


@pytest.mark.asyncio
async def test_warmup_consume_lost_response_replays_exact_envelope(monkeypatch):
    attempt_id = "attempt-1"
    expected = _external_results(attempt_id)[1]
    redis = _LostThenReplayRedis(expected)
    monkeypatch.setattr(settings, "_redis_client", redis)
    db = _Db()

    with pytest.raises(RuntimeError, match="no durable result"):
        await instance_router._consume_activation_warmup(db, "chute-1", attempt_id)
    replayed = await instance_router._consume_activation_warmup(
        db, "chute-1", attempt_id
    )

    assert replayed == expected
    assert redis.calls[0] == redis.calls[1]
    assert redis.calls[0][1:4] == (
        2,
        "warmup_requested_at:chute-1",
        "activation_warmup_result:attempt-1",
    )
    assert "redis.call('GET', replay_key)" in instance_router._CONSUME_WARMUP_REPLAY_LUA
    assert (
        "redis.call('SET', replay_key, envelope"
        in instance_router._CONSUME_WARMUP_REPLAY_LUA
    )
    assert "redis.call('DEL', warmup_key)" in instance_router._CONSUME_WARMUP_REPLAY_LUA


@pytest.mark.asyncio
async def test_warmup_consume_guard_blocks_redis():
    with pytest.raises(RuntimeError, match="warmup telemetry consume"):
        await instance_router._consume_activation_warmup(
            _Db(locked=True), "chute-1", "attempt-1"
        )


def test_same_config_uses_one_durable_activation_attempt_identity():
    config_a, instance_a, chute_a = _activation_objects()
    config_b, instance_b, chute_b = _activation_objects()

    attempt_a, input_a = instance_router._activation_attempt(
        config_a, instance_a, chute_a, create=True
    )
    attempt_b, input_b = instance_router._activation_attempt(
        config_b, instance_b, chute_b, create=True
    )

    assert attempt_a["attempt_id"] == attempt_b["attempt_id"]
    assert attempt_a["input_sha256"] == attempt_b["input_sha256"] == input_a == input_b
    assert attempt_a["state"] == attempt_b["state"] == "processing"
    assert instance_router._activation_input_document(
        config_a, instance_a, chute_a
    ) == (instance_router._activation_input_document(config_b, instance_b, chute_b))


def test_completed_activation_applies_one_exact_result_and_rejects_conflict():
    launch_config, instance, chute = _activation_objects()
    attempt, _ = instance_router._activation_attempt(
        launch_config, instance, chute, create=True
    )
    bounty, warmup = _external_results(attempt["attempt_id"])
    result, result_sha256 = instance_router._activation_external_result(
        attempt["attempt_id"], chute.chute_id, bounty, warmup
    )
    completed = {
        **attempt,
        "state": "completed",
        "result": result,
        "result_sha256": result_sha256,
        "completed_at": "2026-07-25T12:01:00+00:00",
    }
    instance.extra = {
        **instance.extra,
        instance_router._ACTIVATION_ATTEMPT_EXTRA_KEY: completed,
    }
    instance.active = True

    instance_router._validate_completed_activation_attempt(
        launch_config,
        instance,
        expected_result=result,
        expected_result_sha256=result_sha256,
    )

    conflicting = copy.deepcopy(result)
    conflicting["warmup_result"]["requested_at"] = "126.0"
    with pytest.raises(HTTPException, match="conflicting launch activation result"):
        instance_router._validate_completed_activation_attempt(
            launch_config,
            instance,
            expected_result=conflicting,
            expected_result_sha256=canonical_sha256(conflicting),
        )


def test_active_retry_rejects_malformed_completed_result_hash():
    launch_config, instance, chute = _activation_objects()
    attempt, _ = instance_router._activation_attempt(
        launch_config, instance, chute, create=True
    )
    bounty, warmup = _external_results(attempt["attempt_id"])
    result, _ = instance_router._activation_external_result(
        attempt["attempt_id"], chute.chute_id, bounty, warmup
    )
    instance.extra = {
        **instance.extra,
        instance_router._ACTIVATION_ATTEMPT_EXTRA_KEY: {
            **attempt,
            "state": "completed",
            "result": result,
            "result_sha256": "0" * 64,
            "completed_at": "2026-07-25T12:01:00+00:00",
        },
    }
    instance.active = True

    with pytest.raises(HTTPException, match="invalid launch activation result"):
        instance_router._validate_completed_activation_attempt(launch_config, instance)


def test_activation_persists_attempt_before_redis_claim_source_order():
    source = inspect.getsource(instance_router.activate_launch_config_instance)
    attempt_index = source.index("_activation_attempt(")
    first_commit_after_attempt = source.index("await db.commit()", attempt_index)
    claim_index = source.index("await claim_bounty(")

    assert attempt_index < first_commit_after_attempt < claim_index
    assert "attempt_id=activation_attempt_id" in source
    assert "_validate_completed_activation_attempt" in source


@pytest.mark.asyncio
async def test_concurrent_same_config_activation_applies_bounty_once(monkeypatch):
    launch_config, instance, chute = _activation_objects()
    instance.created_at = None
    instance.cacert = None
    chute.public = True
    chute.tee = True
    shared_lock = __import__("asyncio").Lock()
    claim_gate = __import__("asyncio").Event()
    claim_attempt_ids = []
    notifications = []

    class _SerializedDb(_Db):
        def __init__(self):
            super().__init__()
            self.holds_lock = False

        async def commit(self):
            self.info.pop(GPU_LIFECYCLE_LOCK_INFO_KEY, None)
            if self.holds_lock:
                self.holds_lock = False
                shared_lock.release()

        async def execute(self, *args, **kwargs):
            raise AssertionError("public TEE activation should not need ad-hoc SQL")

    async def _load(*args, **kwargs):
        return launch_config

    async def _platform_owner():
        return "platform-owner"

    async def _locked(db, config_id):
        assert config_id == launch_config.config_id
        await shared_lock.acquire()
        db.holds_lock = True
        db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True
        return launch_config, instance, chute

    async def _claim(chute_id, *, attempt_id):
        assert chute_id == chute.chute_id
        claim_attempt_ids.append(attempt_id)
        if len(claim_attempt_ids) == 2:
            claim_gate.set()
        await claim_gate.wait()
        return _external_results(attempt_id)[0]

    async def _warmup(db, chute_id, attempt_id):
        assert not db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY)
        assert chute_id == chute.chute_id
        return _external_results(attempt_id)[1]

    async def _invalidate(*args, **kwargs):
        notifications.append("cache")

    async def _notify(*args, **kwargs):
        notifications.append("notify")

    monkeypatch.setattr(instance_router, "load_launch_config_from_jwt", _load)
    monkeypatch.setattr(instance_router, "chutes_user_id", _platform_owner)
    monkeypatch.setattr(instance_router, "_locked_activation_context", _locked)
    monkeypatch.setattr(instance_router, "claim_bounty", _claim)
    monkeypatch.setattr(instance_router, "_consume_activation_warmup", _warmup)
    monkeypatch.setattr(instance_router, "invalidate_instance_cache", _invalidate)
    monkeypatch.setattr(instance_router, "notify_activated", _notify)
    monkeypatch.setattr(instance_router, "track_warmup_seconds", lambda *a, **k: None)
    monkeypatch.setattr(
        instance_router, "track_warmup_seconds_since", lambda *a, **k: None
    )
    monkeypatch.setattr(
        instance_router,
        "instance_logger",
        lambda *a, **k: SimpleNamespace(info=lambda *a, **k: None),
    )

    async def _activate(db):
        return await instance_router.activate_launch_config_instance(
            launch_config.config_id,
            SimpleNamespace(),
            db=db,
            authorization="Bearer token",
        )

    first, second = await __import__("asyncio").wait_for(
        __import__("asyncio").gather(
            _activate(_SerializedDb()), _activate(_SerializedDb())
        ),
        timeout=5,
    )
    await __import__("asyncio").sleep(0)

    assert first == second == {"ok": True}
    assert len(claim_attempt_ids) == 2
    assert len(set(claim_attempt_ids)) == 1
    assert instance.active is True
    assert instance.bounty is True
    expected_boost = instance_router.calculate_bounty_boost(50)
    assert instance.compute_multiplier == pytest.approx(2.0 * expected_boost)
    assert instance.compute_multiplier != pytest.approx(
        2.0 * expected_boost * expected_boost
    )
    completed = instance.extra[instance_router._ACTIVATION_ATTEMPT_EXTRA_KEY]
    assert completed["state"] == "completed"
    assert completed["attempt_id"] == claim_attempt_ids[0]
    assert completed["result_sha256"] == canonical_sha256(completed["result"])
    assert notifications.count("cache") == 1
    assert notifications.count("notify") == 1


def test_activation_envelopes_reject_malformed_and_cross_chute_results():
    attempt_id = "attempt-1"
    bounty, warmup = _external_results(attempt_id)

    with pytest.raises(RuntimeError, match="identity mismatch"):
        bounty_util._parse_activation_claim_envelope(
            std_json.dumps({**bounty, "chute_id": "chute-2"}),
            attempt_id,
            "chute-1",
        )
    with pytest.raises(RuntimeError, match="invalid envelope"):
        bounty_util._parse_activation_claim_envelope(b"not-json", attempt_id, "chute-1")
    with pytest.raises(RuntimeError, match="identity mismatch"):
        instance_router._parse_activation_warmup_envelope(
            std_json.dumps({**warmup, "chute_id": "chute-2"}),
            attempt_id,
            "chute-1",
        )
    with pytest.raises(RuntimeError, match="invalid envelope"):
        instance_router._parse_activation_warmup_envelope(
            b"not-json", attempt_id, "chute-1"
        )


def test_launch_external_snapshot_hash_and_compare_and_set():
    input_document = {
        "schema": "chutes.launch-external-input.v1",
        "config_id": "config-1",
    }
    result_document = {
        "input_sha256": canonical_sha256(input_document),
        "hourly_price_usd": 1.25,
        "manual_boost": 1.0,
        "inspecto_hash": "inspecto-1",
        "scale_value": "2",
        "inventory_history": [{"count": 2}],
        "bounty_exists": True,
        "filesystem_hash": "filesystem-1",
    }
    snapshot = {
        **result_document,
        "result_sha256": canonical_sha256(result_document),
    }

    instance_router._validate_launch_external_snapshot(snapshot, input_document)

    with pytest.raises(HTTPException, match="authority changed"):
        instance_router._validate_launch_external_snapshot(
            {**snapshot, "manual_boost": 2.0}, input_document
        )
    with pytest.raises(HTTPException, match="authority changed"):
        instance_router._validate_launch_external_snapshot(
            snapshot,
            {**input_document, "config_id": "config-2"},
        )
