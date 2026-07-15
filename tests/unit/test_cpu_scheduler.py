"""Unit tests for api/cpu_scheduler.py (validator-side CPU TEE placement loop).

Covers the critical paths called out in the remediation plan: placement filtering,
version-aware placement / rolling updates, launch-config expiry, Model-B host launch
capacity accounting, dispatch payloads, and the per-tick distributed lock.

DB access is faked with a statement-classifying session (no postgres): each SELECT is
routed by its (entity, column) signature, so the tests pin the real query shapes
without depending on SQL string rendering.
"""

from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import api.cpu_scheduler as cs
from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.instance.schemas import LaunchConfig

NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)


class FakeRedis:
    """Dict-backed stand-in for the redis client (only the ops the scheduler uses)."""

    def __init__(self):
        self.store = {}
        self.published = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    async def delete(self, *keys):
        removed = 0
        for key in keys:
            if self.store.pop(key, None) is not None:
                removed += 1
        return removed

    async def exists(self, key):
        return 1 if key in self.store else 0

    async def incr(self, key):
        value = int(self.store.get(key) or 0) + 1
        self.store[key] = str(value)
        return value

    async def expire(self, key, ttl):
        return key in self.store

    async def publish(self, channel, payload):
        self.published.append((channel, payload))
        return 1

    async def keys(self, pattern):
        return [key for key in self.store if fnmatch(key, pattern)]


class FakeResult:
    def __init__(self, items=None, scalar=None, rows=None, rowcount=0):
        self._items = items if items is not None else []
        self._scalar = scalar
        self._rows = rows if rows is not None else []
        self.rowcount = rowcount

    def unique(self):
        return self

    def scalars(self):
        return self

    def all(self):
        return list(self._rows) if self._rows else list(self._items)

    def scalar(self):
        return self._scalar

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def first(self):
        return self._rows[0] if self._rows else (self._items[0] if self._items else None)


def _stmt_key(stmt):
    """(entity, column) signature for a select; 'text:...' for raw SQL."""
    text_sql = getattr(stmt, "text", None)
    if isinstance(text_sql, str):
        if "UPDATE launch_configs" in text_sql:
            return "text:update_launch_configs"
        if "DELETE FROM servers" in text_sql:
            return "text:delete_servers"
        return "text:other"
    parts = []
    for desc in stmt.column_descriptions:
        entity = desc.get("entity")
        parts.append(f"{entity.__name__ if entity is not None else None}.{desc['name']}")
    return "|".join(parts)


class FakeSession:
    """Routes session.execute(stmt) by statement signature.

    handlers values are either a FakeResult/callable (sticky) or a list consumed FIFO
    (for code paths that issue the same-shaped query more than once).
    """

    def __init__(self, handlers):
        self.handlers = handlers
        self.added = []
        self.committed = False
        self.executed = []

    async def execute(self, stmt, params=None):
        key = _stmt_key(stmt)
        self.executed.append((key, params))
        if key not in self.handlers:
            raise AssertionError(f"Unexpected query in test: {key}")
        handler = self.handlers[key]
        if isinstance(handler, list):
            if not handler:
                raise AssertionError(f"Query {key} issued more times than configured")
            handler = handler.pop(0)
        if callable(handler):
            handler = handler(params)
        return handler

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def refresh(self, obj):
        return None


def _session_ctx(session):
    """get_session() replacement returning an async context manager."""

    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *args):
            return False

    return lambda: _Ctx()


def _chute(
    chute_id="chute-1",
    version="1.0.0",
    cords=True,
    cpu_cores=2,
    ram_gb=4,
    min_benchmark_score=None,
    disabled=False,
    tee=True,
    jobs=None,
):
    image = SimpleNamespace(
        user=SimpleNamespace(username="User"), name="Img", tag="0.1", patch_version=None
    )
    node_selector = {"compute_type": "cpu", "cpu_cores": cpu_cores, "ram_gb": ram_gb}
    if min_benchmark_score is not None:
        node_selector["min_benchmark_score"] = min_benchmark_score
    return SimpleNamespace(
        chute_id=chute_id,
        version=version,
        disabled=disabled,
        cords=[{"path": "/x"}] if cords else [],
        jobs=jobs or [],
        node_selector=node_selector,
        image=image,
        chutes_version="0.6.10",
        standard_template=None,
        lock_modules=None,
        allow_external_egress=False,
        ref_str="chute:chute",
        tee=tee,
    )


def _server(
    server_id="srv-1",
    cpu_cores=2,
    ram_gb=8,
    benchmark_score=100.0,
    host_id=None,
    miner_hotkey="hk-miner",
    external_ports=None,
):
    return SimpleNamespace(
        server_id=server_id,
        cpu_cores=cpu_cores,
        ram_gb=ram_gb,
        benchmark_score=benchmark_score,
        host_id=host_id,
        miner_hotkey=miner_hotkey,
        external_ports=external_ports,
    )


def _instance(
    instance_id="inst-1",
    chute_id="chute-1",
    version="1.0.0",
    active=True,
    verified=True,
    created_at=NOW - timedelta(hours=1),
    server_id="srv-old",
    config_id="cfg-old",
):
    return SimpleNamespace(
        instance_id=instance_id,
        chute_id=chute_id,
        version=version,
        active=active,
        verified=verified,
        created_at=created_at,
        server_id=server_id,
        config_id=config_id,
    )


def _job(job_id="job-1", chute_id="chute-1", method="run", job_args=None):
    return SimpleNamespace(
        job_id=job_id,
        chute_id=chute_id,
        miner_hotkey=None,
        instance_id=None,
        finished_at=None,
        method=method,
        job_args=job_args or {},
    )


def _measurement(name="cpu-gcp-tdx-1vcpu"):
    return TeeMeasurementConfig(
        version="1.0.0-tdx-1vcpu",
        name=name,
        tee_type="tdx",
        provider="gcp",
        mrtd="A" * 96,
        boot_rtmrs={f"RTMR{index}": chr(66 + index) * 96 for index in range(4)},
        runtime_rtmrs={
            f"RTMR{index}": value * 96 for index, value in enumerate(("F", "0", "1", "2"))
        },
        expected_gpus=[],
        gpu_count=0,
        debug=False,
    )


class _AttestationSession:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _stmt):
        return FakeResult(rows=self.rows)


def _attested_server_and_row(*, verified_at=None):
    measurement = _measurement()
    config_fingerprint = measurement_config_fingerprint(measurement)
    trust_set_fingerprint = measurement_trust_set_fingerprint([measurement])
    server = _server()
    server.version = measurement.version
    server.measurement_name = measurement.name
    server.measurement_config_fingerprint = config_fingerprint
    server.trust_set_fingerprint = trust_set_fingerprint
    server.tee_type = "tdx"
    row = SimpleNamespace(
        server_id=server.server_id,
        verification_error=None,
        measurement_name=measurement.name,
        measurement_version=measurement.version,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
        verified_at=verified_at or datetime.now(timezone.utc),
    )
    return measurement, server, row


def _schedule_handlers(
    chutes,
    servers,
    occupied_instance_ids=None,
    occupied_config_ids=None,
    chute_instances=None,
    pending_count=0,
    jobs=None,
):
    return {
        "Chute.Chute": FakeResult(items=chutes),
        "Server.Server": FakeResult(items=servers),
        "Instance.server_id": FakeResult(items=occupied_instance_ids or []),
        "LaunchConfig.server_id": FakeResult(items=occupied_config_ids or []),
        "Instance.Instance": FakeResult(items=chute_instances or []),
        "LaunchConfig.count": FakeResult(scalar=pending_count),
        "Job.Job": FakeResult(items=jobs or []),
    }


@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def mock_settings(fake_redis):
    settings = MagicMock()
    settings.redis_client = fake_redis
    settings.netuid = 64
    settings.validator_ss58 = "5VALIDATOR"
    settings.registry_host = "registry:5000"
    settings.registry_external_host = "registry.example.com:5000"
    settings.registry_insecure = False
    with patch("api.cpu_scheduler.settings", settings):
        yield settings


class TestCurrentAttestedServerFilter:
    @pytest.mark.asyncio
    async def test_accepts_only_exact_fresh_current_identity(self, mock_settings):
        measurement, server, row = _attested_server_and_row()
        mock_settings.tee_measurements = [measurement]
        mock_settings.release_attestation_max_age_seconds = 3600

        result = await cs._current_attested_servers(_AttestationSession([row]), [server])

        assert result == [server]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "mutation",
        [
            "revoked",
            "full_trust_changed",
            "server_config_fingerprint",
            "attestation_trust_fingerprint",
            "stale",
            "latest_failed",
        ],
    )
    async def test_rejects_absent_revoked_mismatched_or_stale_identity(
        self, mock_settings, mutation
    ):
        measurement, server, row = _attested_server_and_row()
        measurements = [measurement]
        if mutation == "revoked":
            measurements = [_measurement("cpu-other")]
        elif mutation == "full_trust_changed":
            measurements.append(_measurement("cpu-added"))
        elif mutation == "server_config_fingerprint":
            server.measurement_config_fingerprint = "0" * 64
        elif mutation == "attestation_trust_fingerprint":
            row.trust_set_fingerprint = "0" * 64
        elif mutation == "stale":
            row.verified_at = datetime.now(timezone.utc) - timedelta(hours=2)
        elif mutation == "latest_failed":
            row.verification_error = "quote rejected"
        mock_settings.tee_measurements = measurements
        mock_settings.release_attestation_max_age_seconds = 3600

        result = await cs._current_attested_servers(_AttestationSession([row]), [server])

        assert result == []


class TestExpireStaleLaunchConfigs:
    @pytest.mark.asyncio
    async def test_expiry_updates_only_scheduler_minted_configs(self, mock_settings):
        expired_row = SimpleNamespace(config_id="cfg-1", chute_id="chute-1", server_id="srv-1")
        session = FakeSession({"text:update_launch_configs": FakeResult(rows=[expired_row])})
        with patch("api.cpu_scheduler.get_session", _session_ctx(session)):
            await cs.expire_stale_launch_configs()
        assert session.committed
        key, params = session.executed[0]
        assert key == "text:update_launch_configs"
        # Claimed (retrieved) configs get a doubled window before being declared dead.
        assert params == {
            "ttl": cs.LAUNCH_CONFIG_EXPIRY_SECONDS,
            "claimed_ttl": cs.LAUNCH_CONFIG_EXPIRY_SECONDS * 2,
        }

    @pytest.mark.asyncio
    async def test_expiry_no_rows_is_noop(self, mock_settings):
        session = FakeSession({"text:update_launch_configs": FakeResult(rows=[])})
        with patch("api.cpu_scheduler.get_session", _session_ctx(session)):
            await cs.expire_stale_launch_configs()
        assert session.committed


class TestScheduleOncePlacement:
    async def _run(self, handlers, online=True, dispatch=None, launch=None, purge=None):
        session = FakeSession(handlers)
        dispatch = dispatch or AsyncMock()
        launch = launch if launch is not None else AsyncMock(return_value=False)
        purge = purge or AsyncMock()
        online_mock = online if callable(online) else AsyncMock(return_value=online)
        current_attested = AsyncMock(side_effect=lambda _session, servers: servers)
        with (
            patch("api.cpu_scheduler.get_session", _session_ctx(session)),
            patch("api.cpu_scheduler._dispatch_deploy", dispatch),
            patch("api.cpu_scheduler._launch_on_host", launch),
            patch("api.cpu_scheduler.purge_and_notify", purge),
            patch("api.cpu_scheduler.is_agent_online", online_mock),
            patch(
                "api.cpu_scheduler._current_attested_servers",
                current_attested,
            ),
        ):
            await cs.schedule_once()
        return session, dispatch, launch, purge

    @pytest.mark.asyncio
    async def test_places_chute_on_free_matching_server(self, mock_settings):
        chute = _chute()
        free = _server(server_id="srv-free")
        occupied = _server(server_id="srv-busy")
        handlers = _schedule_handlers([chute], [occupied, free], occupied_instance_ids=["srv-busy"])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_awaited_once()
        assert dispatch.await_args.args[2] is free
        launch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_pending_launch_config_occupies_server_and_counts_to_target(self, mock_settings):
        chute = _chute()
        server = _server(server_id="srv-free")
        handlers = _schedule_handlers(
            [chute], [server], occupied_config_ids=["srv-free"], pending_count=1
        )
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "server_kwargs",
        [
            {"benchmark_score": 10.0},  # below the chute's min_benchmark_score
            {"cpu_cores": 1},  # too few cores (< req for both Model A >= and Model B exact)
            {"ram_gb": 2},  # insufficient RAM
        ],
    )
    async def test_unsuitable_servers_fall_through_to_host_launch(
        self, mock_settings, server_kwargs
    ):
        chute = _chute(cpu_cores=2, ram_gb=4, min_benchmark_score=50.0)
        server = _server(server_id="srv-bad", **server_kwargs)
        handlers = _schedule_handlers([chute], [server])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_awaited_once()
        # _launch_on_host(session, chute, req_cores, req_ram)
        assert launch.await_args.args[1] is chute
        assert launch.await_args.args[2:] == (2, 4)

    @pytest.mark.asyncio
    async def test_model_a_larger_server_is_placed(self, mock_settings):
        """Model A (standalone, host_id=None): a chute requesting fewer cores than the VM has is
        PLACED on it (>=), not stranded waiting for an exact match that never appears."""
        chute = _chute(cpu_cores=2, ram_gb=4, min_benchmark_score=50.0)
        server = _server(server_id="srv-big", cpu_cores=8, ram_gb=16)  # host_id=None => Model A
        handlers = _schedule_handlers([chute], [server])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_awaited_once()
        launch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_model_b_inexact_cores_fall_through(self, mock_settings):
        """Model B (host-launched, host_id set): a right-sized TD must match the chute's cores
        EXACTLY, so a larger TD is not reused for a smaller chute -- it falls through to a fresh
        per-chute TD launch."""
        chute = _chute(cpu_cores=2, ram_gb=4, min_benchmark_score=50.0)
        server = _server(server_id="td-big", cpu_cores=8, ram_gb=16, host_id="host-1")
        handlers = _schedule_handlers([chute], [server])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_offline_agent_skipped(self, mock_settings):
        chute = _chute()
        server = _server(server_id="srv-offline")
        handlers = _schedule_handlers([chute], [server])
        _, dispatch, launch, _ = await self._run(handlers, online=False)
        dispatch.assert_not_awaited()
        launch.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disabled_chute_skipped(self, mock_settings):
        chute = _chute(disabled=True)
        handlers = _schedule_handlers([chute], [_server()])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_at_target_no_dispatch(self, mock_settings):
        chute = _chute()
        current = _instance(version=chute.version)
        handlers = _schedule_handlers([chute], [_server()], chute_instances=[current])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_scale_target_from_redis_places_second_instance(self, mock_settings, fake_redis):
        chute = _chute()
        fake_redis.store[f"scale:{chute.chute_id}"] = "2"
        current = _instance(version=chute.version, server_id="srv-busy")
        free = _server(server_id="srv-free")
        handlers = _schedule_handlers(
            [chute],
            [free],
            occupied_instance_ids=["srv-busy"],
            chute_instances=[current],
        )
        _, dispatch, _, _ = await self._run(handlers)
        dispatch.assert_awaited_once()


class TestScheduleOnceVersionAware:
    _run = TestScheduleOncePlacement._run

    @pytest.mark.asyncio
    async def test_stale_instance_does_not_count_toward_target(self, mock_settings):
        """A new chute version must place a fresh instance even though an old one runs."""
        chute = _chute(version="2.0.0")
        stale = _instance(version="1.0.0", server_id="srv-busy")
        free = _server(server_id="srv-free")
        handlers = _schedule_handlers(
            [chute],
            [free],
            occupied_instance_ids=["srv-busy"],
            chute_instances=[stale],
        )
        _, dispatch, _, purge = await self._run(handlers)
        dispatch.assert_awaited_once()
        # The stale instance is NOT purged yet -- it serves until the new version is live.
        purge.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_stale_retired_once_current_version_live(self, mock_settings):
        chute = _chute(version="2.0.0")
        stale = _instance(instance_id="inst-old", version="1.0.0", server_id="srv-a")
        live = _instance(
            instance_id="inst-new",
            version="2.0.0",
            server_id="srv-b",
            active=True,
            verified=True,
        )
        handlers = _schedule_handlers(
            [chute],
            [],
            occupied_instance_ids=["srv-a", "srv-b"],
            chute_instances=[stale, live],
        )
        _, dispatch, _, purge = await self._run(handlers)
        purge.assert_awaited_once()
        assert purge.await_args.args[0] is stale
        dispatch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_stale_not_retired_when_current_not_yet_verified(self, mock_settings):
        chute = _chute(version="2.0.0")
        stale = _instance(instance_id="inst-old", version="1.0.0", server_id="srv-a")
        booting = _instance(
            instance_id="inst-new", version="2.0.0", server_id="srv-b", verified=False
        )
        handlers = _schedule_handlers(
            [chute],
            [],
            occupied_instance_ids=["srv-a", "srv-b"],
            chute_instances=[stale, booting],
            pending_count=0,
        )
        _, _, _, purge = await self._run(handlers)
        purge.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_replace_in_place_when_no_spare_capacity(self, mock_settings):
        """Oldest stale instance is purged so the next tick can place the new version."""
        chute = _chute(version="2.0.0")
        older = _instance(
            instance_id="inst-older",
            version="1.0.0",
            server_id="srv-a",
            created_at=NOW - timedelta(hours=2),
        )
        newer = _instance(
            instance_id="inst-newer",
            version="1.0.0",
            server_id="srv-b",
            created_at=NOW - timedelta(hours=1),
        )
        handlers = _schedule_handlers(
            [chute],
            [],
            occupied_instance_ids=["srv-a", "srv-b"],
            chute_instances=[older, newer],
        )
        _, dispatch, launch, purge = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_awaited_once()
        purge.assert_awaited_once()
        assert purge.await_args.args[0] is older

    @pytest.mark.asyncio
    async def test_no_replace_in_place_while_pending_config_exists(self, mock_settings):
        chute = _chute(version="2.0.0")
        stale = _instance(version="1.0.0", server_id="srv-a")
        handlers = _schedule_handlers(
            [chute],
            [],
            occupied_instance_ids=["srv-a"],
            chute_instances=[stale],
            pending_count=1,
        )
        _, _, _, purge = await self._run(handlers)
        purge.assert_not_awaited()


class TestScheduleOnceJobs:
    _run = TestScheduleOncePlacement._run

    @pytest.mark.asyncio
    async def test_job_only_chute_skipped_in_cord_pass_but_job_placed(self, mock_settings):
        chute = _chute(cords=False)
        job = _job(chute_id=chute.chute_id)
        server = _server(server_id="srv-free")
        handlers = _schedule_handlers([chute], [server], jobs=[job])
        _, dispatch, _, _ = await self._run(handlers)
        dispatch.assert_awaited_once()
        assert dispatch.await_args.args[2] is server
        assert dispatch.await_args.kwargs.get("job") is job

    @pytest.mark.asyncio
    async def test_job_with_no_capacity_falls_back_to_host_launch(self, mock_settings):
        chute = _chute(cords=False, cpu_cores=4, ram_gb=8)
        job = _job(chute_id=chute.chute_id)
        handlers = _schedule_handlers([chute], [], jobs=[job])
        _, dispatch, launch, _ = await self._run(handlers)
        dispatch.assert_not_awaited()
        launch.assert_awaited_once()
        assert launch.await_args.args[2:] == (4, 8)

    @pytest.mark.asyncio
    async def test_cord_and_job_share_occupancy(self, mock_settings):
        """One free server cannot take both the cord instance and the job."""
        chute_cord = _chute(chute_id="chute-cord")
        chute_job = _chute(chute_id="chute-job", cords=False)
        job = _job(chute_id="chute-job")
        server = _server(server_id="srv-only")
        handlers = _schedule_handlers(
            [chute_cord, chute_job],
            [server],
            chute_instances=[],
            jobs=[job],
        )
        # Both chutes query their instances: same statement shape, FIFO.
        handlers["Instance.Instance"] = [FakeResult(items=[]), FakeResult(items=[])]
        handlers["LaunchConfig.count"] = [FakeResult(scalar=0), FakeResult(scalar=0)]
        _, dispatch, launch, _ = await self._run(handlers)
        assert dispatch.await_count == 1  # the cord pass took srv-only
        assert dispatch.await_args_list[0].args[2] is server
        launch.assert_awaited_once()  # the job had to fall back to a host launch


class TestDispatchDeploy:
    @pytest.fixture
    def metagraph_node(self):
        return SimpleNamespace(node_id=7, coldkey="ck-cold")

    async def _dispatch(self, chute, server, miner, digest="sha256:abc", job=None):
        session = FakeSession(
            {
                "MetagraphNode.MetagraphNode": FakeResult(items=[miner] if miner else []),
                "text:update_launch_configs": FakeResult(rowcount=1),
            }
        )
        send = AsyncMock(return_value="cmd-1")
        digest_mock = AsyncMock(return_value=digest)
        if isinstance(digest, Exception):
            digest_mock = AsyncMock(side_effect=digest)
        with (
            patch("api.cpu_scheduler.send_agent_command", send),
            patch("api.cpu_scheduler.create_launch_jwt_v2", return_value="jwt-token"),
            patch("api.image.forge.get_image_digest", digest_mock),
        ):
            await cs._dispatch_deploy(session, chute, server, job=job)
        return session, send

    @pytest.mark.asyncio
    async def test_no_metagraph_node_no_dispatch(self, mock_settings):
        session, send = await self._dispatch(_chute(), _server(), miner=None)
        send.assert_not_awaited()
        assert session.added == []

    @pytest.mark.asyncio
    async def test_tee_without_digest_refuses_and_fails_config(self, mock_settings, metagraph_node):
        session, send = await self._dispatch(
            _chute(tee=True),
            _server(),
            metagraph_node,
            digest=RuntimeError("registry down"),
        )
        send.assert_not_awaited()
        # The launch config row was minted before the digest check and must be failed
        # immediately so it doesn't occupy the server / count as pending until expiry.
        assert len(session.added) == 1
        fail_updates = [p for k, p in session.executed if k == "text:update_launch_configs"]
        assert fail_updates and fail_updates[0]["config_id"] == session.added[0].config_id

    @pytest.mark.asyncio
    async def test_happy_path_payload(self, mock_settings, metagraph_node):
        chute = _chute()
        server = _server(server_id="srv-1", external_ports={"8000": 31000})
        session, send = await self._dispatch(chute, server, metagraph_node)
        send.assert_awaited_once()
        target_server_id, command = send.await_args.args[0], send.await_args.args[1]
        payload = send.await_args.args[2]
        assert target_server_id == "srv-1"
        assert command == "deploy_chute"
        assert payload["chute_id"] == chute.chute_id
        assert payload["image"] == "user/img:0.1"
        assert payload["image_digest"] == "sha256:abc"
        assert payload["token"] == "jwt-token"
        assert payload["registry"] == "registry.example.com:5000"
        assert payload["external_ports"] == {"8000": 31000}
        assert payload["job_ports"] == []
        # chutes 0.6.x exposes the attestation port.
        assert payload["ports"] == {
            "primary": 8000,
            "logging": 8001,
            "attestation": 8002,
        }
        added = session.added[0]
        assert isinstance(added, LaunchConfig)
        assert added.chute_id == chute.chute_id
        assert added.server_id == "srv-1"
        assert added.env_type == "tee"
        assert added.miner_uid == 7

    @pytest.mark.asyncio
    async def test_job_dispatch_carries_job_id_and_ports(self, mock_settings, metagraph_node):
        chute = _chute(
            jobs=[{"name": "run", "ports": [{"port": 8888, "proto": "tcp"}]}],
            cords=False,
        )
        job = _job(method="run", job_args={"_disk_gb": 50})
        session, send = await self._dispatch(chute, _server(), metagraph_node, job=job)
        payload = send.await_args.args[2]
        assert payload["job_ports"] == [{"port": 8888, "proto": "tcp"}]
        assert payload["disk_gb"] == 50
        assert session.added[0].job_id == job.job_id


class TestLaunchOnHost:
    def _handlers(self, hosts, used_rows=None, chute_host_ids=(set(), set())):
        return {
            "Host.Host": FakeResult(items=hosts),
            "Server.host_id|Server.count": FakeResult(rows=used_rows or []),
            # _hosts_running_chute issues two same-shaped queries (instances, launch configs).
            "Server.host_id": [
                FakeResult(items=list(chute_host_ids[0])),
                FakeResult(items=list(chute_host_ids[1])),
            ],
        }

    def _host(self, host_id="host-1", capacity=2, default_mem="8G", default_vcpus=4):
        return SimpleNamespace(
            host_id=host_id,
            capacity=capacity,
            default_mem=default_mem,
            default_vcpus=default_vcpus,
        )

    async def _run(self, handlers, online=True):
        session = FakeSession(handlers)
        send = AsyncMock(return_value="cmd-1")
        with (
            patch("api.cpu_scheduler.send_agent_command", send),
            patch("api.cpu_scheduler.is_agent_online", AsyncMock(return_value=online)),
        ):
            launched = await cs._launch_on_host(session, _chute(cpu_cores=2, ram_gb=4), 2, 4)
        return launched, send

    @pytest.mark.asyncio
    async def test_launches_on_host_with_capacity(self, mock_settings, fake_redis):
        launched, send = await self._run(self._handlers([self._host()]))
        assert launched
        send.assert_awaited_once()
        host_id, command, payload = send.await_args.args
        assert (host_id, command) == ("host-1", "deploy_chute")
        # TD is right-sized: chute RAM + guest OS overhead, exact vCPUs.
        assert payload == {
            "chute_id": "chute-1",
            "mem": f"{4 + cs.MB_TD_MEM_OVERHEAD_GB}G",
            "vcpus": 2,
        }
        assert "mb:launch:chute-1:host-1" in fake_redis.store
        assert fake_redis.store["mb:host_inflight:host-1"] == "1"

    @pytest.mark.asyncio
    async def test_skips_host_already_running_chute(self, mock_settings):
        handlers = self._handlers([self._host()], chute_host_ids=({"host-1"}, set()))
        launched, send = await self._run(handlers)
        assert not launched
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_host_at_capacity_from_used_rows(self, mock_settings):
        handlers = self._handlers([self._host(capacity=2)], used_rows=[("host-1", 2)])
        launched, send = await self._run(handlers)
        assert not launched
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_zero_schedulable_storage_host_is_never_dispatched(self, mock_settings):
        handlers = self._handlers([self._host(capacity=0)])
        launched, send = await self._run(handlers)
        assert not launched
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_inflight_launches_count_against_capacity(self, mock_settings, fake_redis):
        fake_redis.store["mb:host_inflight:host-1"] = "2"
        handlers = self._handlers([self._host(capacity=2)])
        launched, send = await self._run(handlers)
        assert not launched
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_inflight_same_chute_not_relaunched(self, mock_settings, fake_redis):
        fake_redis.store["mb:launch:chute-1:host-1"] = "host-1"
        handlers = self._handlers([self._host()])
        launched, send = await self._run(handlers)
        assert not launched
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_offline_host_skipped_falls_to_next(self, mock_settings, fake_redis):
        handlers = self._handlers([self._host("host-off"), self._host("host-on")])
        session = FakeSession(handlers)
        send = AsyncMock(return_value="cmd-1")
        online = AsyncMock(side_effect=lambda hid: hid == "host-on")
        with (
            patch("api.cpu_scheduler.send_agent_command", send),
            patch("api.cpu_scheduler.is_agent_online", online),
        ):
            launched = await cs._launch_on_host(session, _chute(), 2, 4)
        assert launched
        assert send.await_args.args[0] == "host-on"


class TestTickWithLock:
    @pytest.mark.asyncio
    async def test_skips_tick_when_lock_held(self, mock_settings, fake_redis):
        fake_redis.store[cs.SCHEDULER_LOCK_KEY] = "other-replica"
        expire = AsyncMock()
        schedule = AsyncMock()
        with (
            patch("api.cpu_scheduler.expire_stale_launch_configs", expire),
            patch("api.cpu_scheduler.schedule_once", schedule),
        ):
            await cs._tick_with_lock()
        expire.assert_not_awaited()
        schedule.assert_not_awaited()
        # The other replica's lock is untouched.
        assert fake_redis.store[cs.SCHEDULER_LOCK_KEY] == "other-replica"

    @pytest.mark.asyncio
    async def test_runs_and_releases_lock(self, mock_settings, fake_redis):
        expire = AsyncMock()
        schedule = AsyncMock()
        with (
            patch("api.cpu_scheduler.expire_stale_launch_configs", expire),
            patch("api.cpu_scheduler.schedule_once", schedule),
        ):
            await cs._tick_with_lock()
        expire.assert_awaited_once()
        schedule.assert_awaited_once()
        assert cs.SCHEDULER_LOCK_KEY not in fake_redis.store

    @pytest.mark.asyncio
    async def test_lock_released_even_when_tick_raises(self, mock_settings, fake_redis):
        with (
            patch(
                "api.cpu_scheduler.expire_stale_launch_configs",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch("api.cpu_scheduler.schedule_once", AsyncMock()),
        ):
            with pytest.raises(RuntimeError):
                await cs._tick_with_lock()
        assert cs.SCHEDULER_LOCK_KEY not in fake_redis.store

    @pytest.mark.asyncio
    async def test_lock_not_deleted_when_value_changed(self, mock_settings, fake_redis):
        """If the TTL expired and another replica took the lock, do not release theirs."""

        async def steal_lock():
            fake_redis.store[cs.SCHEDULER_LOCK_KEY] = "other-replica"

        with (
            patch("api.cpu_scheduler.expire_stale_launch_configs", AsyncMock()),
            patch("api.cpu_scheduler.schedule_once", AsyncMock(side_effect=steal_lock)),
        ):
            await cs._tick_with_lock()
        assert fake_redis.store[cs.SCHEDULER_LOCK_KEY] == "other-replica"
