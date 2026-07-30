"""Unit tests for the 1-click agent control plane:

* api/agent_channel.py -- command dispatch + ack correlation, teardown targeting
  (Model A vs Model B), and the heartbeat-driven reconcile loop.
* api/socket_server.py -- the agent_authenticate / agent_status / agent_command_ack
  socket events.

Reuses the statement-classifying FakeSession from the cpu_scheduler tests so the real
query shapes are pinned without a database.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import orjson as json
import pytest

import api.agent_channel as ac
import api.socket_server as ss
from api.constants import (
    ATTEST_SIGNATURE_HEADER,
    AGENT_COMMAND_CHANNEL,
    SERVER_ID_HEADER,
)
from api.gpu_contracts import GpuLifecycleOperationV1
from api.gpu_lifecycle_service import gpu_lifecycle_intent_document
from tests.unit.test_cpu_scheduler import (
    FakeRedis,
    FakeResult,
    FakeSession,
    _session_ctx,
)

NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(seconds=ac.SERVER_REAP_GRACE_SECONDS + 60)


@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def mock_settings(fake_redis):
    settings = MagicMock()
    settings.redis_client = fake_redis
    with patch("api.agent_channel.settings", settings):
        yield settings


class TestSendAgentCommand:
    @pytest.mark.asyncio
    async def test_publishes_to_agent_channel(self, mock_settings, fake_redis):
        command_id = await ac.send_agent_command("srv-1", "stop_instance", {"config_id": None})
        assert len(fake_redis.published) == 1
        channel, raw = fake_redis.published[0]
        assert channel == AGENT_COMMAND_CHANNEL
        payload = json.loads(raw)
        assert payload["server_id"] == "srv-1"
        assert payload["command"] == "stop_instance"
        assert payload["command_id"] == command_id

    @pytest.mark.asyncio
    async def test_config_id_stores_ack_correlation(self, mock_settings, fake_redis):
        command_id = await ac.send_agent_command(
            "srv-1", "deploy_chute", {"config_id": "cfg-1", "chute_id": "chute-1"}
        )
        stored = fake_redis.store.get(f"agent:cmd:{command_id}")
        assert stored is not None
        context = json.loads(stored)
        assert context == {
            "config_id": "cfg-1",
            "server_id": "srv-1",
            "command": "deploy_chute",
        }

    @pytest.mark.asyncio
    async def test_every_command_exposes_exact_pending_status(self, mock_settings, fake_redis):
        command_id = await ac.send_agent_command("srv-1", "stop_instance", {"chute_id": "c"})
        assert f"agent:cmd:{command_id}" in fake_redis.store
        assert await ac.get_agent_command_status("srv-1", "stop_instance", command_id) == {
            "command_id": command_id,
            "server_id": "srv-1",
            "command": "stop_instance",
            "status": "pending",
            "detail": None,
        }

    @pytest.mark.asyncio
    async def test_retry_reuses_persisted_command_id(
        self,
        mock_settings,
        fake_redis,
    ):
        for _ in range(2):
            returned = await ac.send_agent_command(
                "gpu-host",
                "launch_gpu",
                {"reservation_id": "gpu-reservation"},
                command_id="stable-command",
            )
            assert returned == "stable-command"
        payloads = [json.loads(raw) for _channel, raw in fake_redis.published]
        assert [payload["command_id"] for payload in payloads] == [
            "stable-command",
            "stable-command",
        ]

    @pytest.mark.asyncio
    async def test_terminal_ack_survives_idempotent_command_retry(
        self,
        mock_settings,
    ):
        command_id = await ac.send_agent_command(
            "gpu-host",
            "confirm_gpu_legacy_sources",
            {"migration_id": "migration-1"},
            command_id="stable-confirm",
        )
        await ac.handle_agent_command_ack(
            "gpu-host",
            {"command_id": command_id, "status": "ok", "detail": "closed"},
        )
        await ac.send_agent_command(
            "gpu-host",
            "confirm_gpu_legacy_sources",
            {"migration_id": "migration-1"},
            command_id=command_id,
        )
        assert await ac.wait_for_agent_command_ack(
            "gpu-host",
            "confirm_gpu_legacy_sources",
            command_id,
            timeout_seconds=0.01,
        ) == {
            "command_id": command_id,
            "server_id": "gpu-host",
            "command": "confirm_gpu_legacy_sources",
            "status": "ok",
            "detail": "closed",
        }


class TestSendGpuReservationTeardown:
    @pytest.mark.asyncio
    async def test_dispatches_strict_intent_instead_of_response_projection(self):
        session = FakeSession({})
        operation = GpuLifecycleOperationV1(
            operation_id="10000000-0000-4000-8000-000000000004",
            operation_type="normal_delete",
            phase="intent",
            host_id="host-1",
            host_key_generation=2,
            host_boot_generation=3,
            allocation_group_id="group-1",
            allocation_group_generation=4,
            reservation_id="reservation-1",
            reservation_generation=5,
            claims_sha256="a" * 64,
            process_incarnation="process-1",
            topology_fingerprint="b" * 64,
            gpu_bdfs=["0000:01:00.0"],
            gpu_uuids=["GPU-00000000-0000-0000-0000-000000000001"],
            owner_hotkey="owner-1",
            stable_server_id="server-1",
            management_mode="platform",
            group_state="resetting",
            created_at=NOW,
            updated_at=NOW,
        )
        reservation = SimpleNamespace(
            host_id="host-1",
            state="resetting",
            teardown_command_id="command-1",
        )
        request_teardown = AsyncMock(return_value=reservation)
        ensure_operation = AsyncMock(return_value=operation)
        record_dispatch = AsyncMock()
        guard = MagicMock()
        send = AsyncMock(return_value="command-1")

        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch(
                "api.host.gpu_allocations.request_gpu_teardown",
                request_teardown,
            ),
            patch(
                "api.gpu_lifecycle_service.ensure_reservation_lifecycle_operation",
                ensure_operation,
            ),
            patch(
                "api.host.gpu_allocations.record_gpu_command_dispatch",
                record_dispatch,
            ),
            patch("api.host.locks.assert_gpu_external_work_allowed", guard),
            patch.object(ac, "send_agent_command", send),
        ):
            result = await ac.send_gpu_reservation_teardown(
                "reservation-1", reason="operator deletion"
            )

        assert result == "command-1"
        target, command, payload = send.await_args.args
        assert (target, command) == ("host-1", "delete_gpu")
        assert payload["lifecycle_operation"] == gpu_lifecycle_intent_document(
            operation
        )
        assert not {"group_state", "created_at", "updated_at"}.intersection(
            payload["lifecycle_operation"]
        )
        assert send.await_args.kwargs == {"command_id": "command-1"}
        assert session.committed


class TestAgentLiveness:
    @pytest.mark.asyncio
    async def test_online_offline_roundtrip(self, mock_settings):
        assert not await ac.is_agent_online("srv-1")
        await ac.mark_agent_online("srv-1")
        assert await ac.is_agent_online("srv-1")
        await ac.mark_agent_offline("srv-1")
        assert not await ac.is_agent_online("srv-1")


class TestHandleAgentCommandAck:
    def _store_context(self, fake_redis, command_id="cmd-1", config_id="cfg-1"):
        fake_redis.store[f"agent:cmd:{command_id}"] = json.dumps(
            {"config_id": config_id, "server_id": "srv-1", "command": "deploy_chute"}
        )

    @pytest.mark.asyncio
    async def test_failed_ack_marks_launch_config_failed(self, mock_settings, fake_redis):
        self._store_context(fake_redis)
        session = FakeSession({"text:update_launch_configs": FakeResult(rowcount=1)})
        with patch("api.database.get_session", _session_ctx(session)):
            await ac.handle_agent_command_ack(
                "srv-1",
                {"command_id": "cmd-1", "status": "error", "detail": "pull failed"},
            )
        key, params = session.executed[0]
        assert key == "text:update_launch_configs"
        assert params["config_id"] == "cfg-1"
        assert "pull failed" in params["error"]
        assert session.committed
        # Correlation key consumed.
        assert "agent:cmd:cmd-1" not in fake_redis.store

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", sorted(ac.FAILED_ACK_STATUSES))
    async def test_all_failed_statuses_fail_the_config(self, mock_settings, fake_redis, status):
        self._store_context(fake_redis)
        session = FakeSession({"text:update_launch_configs": FakeResult(rowcount=1)})
        with patch("api.database.get_session", _session_ctx(session)):
            await ac.handle_agent_command_ack("srv-1", {"command_id": "cmd-1", "status": status})
        assert session.executed

    @pytest.mark.asyncio
    async def test_success_ack_only_clears_correlation(self, mock_settings, fake_redis):
        self._store_context(fake_redis)
        session = FakeSession({})
        with patch("api.database.get_session", _session_ctx(session)):
            await ac.handle_agent_command_ack("srv-1", {"command_id": "cmd-1", "status": "ok"})
        assert session.executed == []
        assert "agent:cmd:cmd-1" not in fake_redis.store

    @pytest.mark.asyncio
    async def test_unknown_command_id_is_noop(self, mock_settings):
        session = FakeSession({})
        with patch("api.database.get_session", _session_ctx(session)):
            await ac.handle_agent_command_ack(
                "srv-1", {"command_id": "never-dispatched", "status": "error"}
            )
        assert session.executed == []

    @pytest.mark.asyncio
    async def test_ack_from_wrong_session_ignored(self, mock_settings, fake_redis):
        """Only the channel the command was dispatched to may consume its correlation."""
        self._store_context(fake_redis)
        session = FakeSession({})
        with patch("api.database.get_session", _session_ctx(session)):
            await ac.handle_agent_command_ack(
                "srv-EVIL", {"command_id": "cmd-1", "status": "error"}
            )
        assert session.executed == []
        # Correlation key NOT consumed: the rightful agent's ack can still land.
        assert "agent:cmd:cmd-1" in fake_redis.store

    @pytest.mark.asyncio
    async def test_missing_command_id_is_noop(self, mock_settings):
        await ac.handle_agent_command_ack("srv-1", {"status": "error"})
        await ac.handle_agent_command_ack("srv-1", {})


def _server_row(
    server_id="srv-1",
    host_id=None,
    self_registered=True,
    created_at=OLD,
    attested_cert=None,
):
    return SimpleNamespace(
        server_id=server_id,
        host_id=host_id,
        self_registered=self_registered,
        created_at=created_at,
        attested_cert=attested_cert,
        attested_cert_pubkey_hash=None,
        miner_hotkey="hk-miner",
        compute_type="cpu",
        measurement_name="cpu-measurement",
        measurement_config_fingerprint="2" * 64,
        trust_set_fingerprint="3" * 64,
        attestation_revocation_status={},
    )


def _current_cpu_attestation(server, *, failed=False):
    return SimpleNamespace(
        attestation_id="cpu-attempt",
        server_id=server.server_id,
        verification_error="newer attestation failed" if failed else None,
        verified_at=None if failed else datetime.now(timezone.utc),
        measurement_name=server.measurement_name,
        measurement_config_fingerprint=server.measurement_config_fingerprint,
        trust_set_fingerprint=server.trust_set_fingerprint,
        revocation_status=dict(server.attestation_revocation_status),
    )


def _attested_keypair_and_cert(cn="attestation-service"):
    """Generate an RSA keypair + self-signed cert standing in for the in-TEE attested serving cert."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def _sign_attest(key, message: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    return key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256()).hex()


class TestSendInstanceTeardown:
    async def _run(self, server_row, server_id="srv-1"):
        session = FakeSession(
            {"Server.Server": FakeResult(items=[server_row] if server_row else [])}
        )
        send = AsyncMock(return_value="cmd-1")
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch.object(ac, "send_agent_command", send),
        ):
            result = await ac.send_instance_teardown(
                "chute-1", instance_id="inst-1", server_id=server_id, config_id="cfg-1"
            )
        return result, send

    @pytest.mark.asyncio
    async def test_no_server_id_is_noop(self, mock_settings):
        send = AsyncMock()
        with patch.object(ac, "send_agent_command", send):
            assert await ac.send_instance_teardown("chute-1", server_id=None) is None
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_model_a_stop_instance_to_server(self, mock_settings):
        result, send = await self._run(_server_row(host_id=None))
        assert result == "cmd-1"
        target, command, payload = send.await_args.args
        assert (target, command) == ("srv-1", "stop_instance")
        assert payload == {
            "chute_id": "chute-1",
            "instance_id": "inst-1",
            "config_id": "cfg-1",
        }

    @pytest.mark.asyncio
    async def test_model_b_delete_chute_to_host(self, mock_settings):
        result, send = await self._run(_server_row(host_id="host-9"))
        assert result == "cmd-1"
        target, command, payload = send.await_args.args
        assert (target, command) == ("host-9", "delete_chute")
        assert payload == {
            "chute_id": "chute-1",
            "instance_id": "inst-1",
            "server_id": "srv-1",
        }

    @pytest.mark.asyncio
    async def test_gpu_server_not_dispatched(self, mock_settings):
        """Miner-plane (non-self-registered) servers are torn down via miner_broadcast."""
        result, send = await self._run(_server_row(self_registered=False))
        assert result is None
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reaped_server_row_best_effort_stop(self, mock_settings):
        result, send = await self._run(None)
        assert result == "cmd-1"
        target, command, _ = send.await_args.args
        assert (target, command) == ("srv-1", "stop_instance")

    @pytest.mark.asyncio
    async def test_dispatch_errors_swallowed(self, mock_settings):
        """Deletion paths must never fail because an agent/redis hiccuped."""
        session = FakeSession({"Server.Server": FakeResult(items=[_server_row()])})
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch.object(
                ac,
                "send_agent_command",
                AsyncMock(side_effect=RuntimeError("redis down")),
            ),
        ):
            assert await ac.send_instance_teardown("chute-1", server_id="srv-1") is None


class TestSendJobInstanceTeardown:
    @pytest.mark.asyncio
    async def test_resolves_instance_row_and_dispatches(self, mock_settings):
        row = SimpleNamespace(chute_id="chute-1", server_id="srv-1", config_id="cfg-1")
        session = FakeSession(
            {"Instance.chute_id|Instance.server_id|Instance.config_id": FakeResult(rows=[row])}
        )
        teardown = AsyncMock(return_value="cmd-1")
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch.object(ac, "send_instance_teardown", teardown),
        ):
            assert await ac.send_job_instance_teardown("inst-1") == "cmd-1"
        teardown.assert_awaited_once_with(
            "chute-1", instance_id="inst-1", server_id="srv-1", config_id="cfg-1"
        )

    @pytest.mark.asyncio
    async def test_already_purged_instance_is_noop(self, mock_settings):
        """purge_and_notify already dispatched the teardown -> no double dispatch."""
        session = FakeSession(
            {"Instance.chute_id|Instance.server_id|Instance.config_id": FakeResult(rows=[])}
        )
        teardown = AsyncMock()
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch.object(ac, "send_instance_teardown", teardown),
        ):
            assert await ac.send_job_instance_teardown("inst-1") is None
        teardown.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_instance_id_is_noop(self, mock_settings):
        assert await ac.send_job_instance_teardown(None) is None


class TestHandleAgentStatusRouting:
    @pytest.mark.asyncio
    async def test_slots_routes_to_host_reconcile(self, mock_settings):
        host_rec = AsyncMock()
        srv_rec = AsyncMock()
        with (
            patch.object(ac, "_reconcile_host_slots", host_rec),
            patch.object(ac, "_reconcile_server_containers", srv_rec),
        ):
            await ac.handle_agent_status("host-1", {"slots": [{"server_id": "td-1"}]})
        host_rec.assert_awaited_once_with("host-1", [{"server_id": "td-1"}])
        srv_rec.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_containers_routes_to_server_reconcile(self, mock_settings):
        host_rec = AsyncMock()
        srv_rec = AsyncMock()
        with (
            patch.object(ac, "_reconcile_host_slots", host_rec),
            patch.object(ac, "_reconcile_server_containers", srv_rec),
        ):
            await ac.handle_agent_status("srv-1", {"containers": ["cfg-1"]})
        srv_rec.assert_awaited_once_with("srv-1", ["cfg-1"])
        host_rec.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_bare_liveness_heartbeat_reconciles_nothing(self, mock_settings):
        host_rec = AsyncMock()
        srv_rec = AsyncMock()
        with (
            patch.object(ac, "_reconcile_host_slots", host_rec),
            patch.object(ac, "_reconcile_server_containers", srv_rec),
        ):
            await ac.handle_agent_status("srv-1", {"uptime": 1})
            await ac.handle_agent_status("srv-1", "not-a-dict")
        host_rec.assert_not_awaited()
        srv_rec.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reconcile_errors_swallowed(self, mock_settings):
        with patch.object(ac, "_reconcile_host_slots", AsyncMock(side_effect=RuntimeError("boom"))):
            await ac.handle_agent_status("host-1", {"slots": []})


def _instance_row(instance_id="inst-1", config_id="cfg-1", created_at=OLD, server_id="srv-1"):
    return SimpleNamespace(
        instance_id=instance_id,
        config_id=config_id,
        created_at=created_at,
        server_id=server_id,
        chute_id="chute-1",
    )


class TestReconcileServerContainers:
    async def _run(self, instances, pending_config_ids, containers):
        session = FakeSession(
            {
                "Instance.Instance": FakeResult(items=instances),
                "LaunchConfig.config_id": FakeResult(items=pending_config_ids),
            }
        )
        purge = AsyncMock()
        send = AsyncMock()
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch("api.instance.util.purge_and_notify", purge),
            patch.object(ac, "send_agent_command", send),
        ):
            await ac._reconcile_server_containers("srv-1", containers)
        return purge, send

    @pytest.mark.asyncio
    async def test_running_container_keeps_instance(self, mock_settings):
        purge, send = await self._run([_instance_row()], [], ["cfg-1"])
        purge.assert_not_awaited()
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_missing_container_purges_old_instance(self, mock_settings):
        instance = _instance_row(created_at=OLD)
        purge, send = await self._run([instance], [], [])
        purge.assert_awaited_once()
        assert purge.await_args.args[0] is instance

    @pytest.mark.asyncio
    async def test_young_instance_grace_period(self, mock_settings):
        """A just-dispatched deploy must not be purged before the container appears."""
        young = datetime.now(timezone.utc) - timedelta(seconds=10)
        purge, _ = await self._run([_instance_row(created_at=young)], [], [])
        purge.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_orphan_container_stopped(self, mock_settings):
        purge, send = await self._run([], [], ["cfg-orphan"])
        purge.assert_not_awaited()
        send.assert_awaited_once_with("srv-1", "stop_instance", {"config_id": "cfg-orphan"})

    @pytest.mark.asyncio
    async def test_container_for_pending_launch_config_kept(self, mock_settings):
        """A container whose launch config is still verifying is in-flight, not an orphan."""
        purge, send = await self._run([], ["cfg-booting"], ["cfg-booting"])
        purge.assert_not_awaited()
        send.assert_not_awaited()


class TestReconcileHostSlots:
    def _handlers(
        self,
        servers,
        instances_by_server=None,
        slot_server_exists=None,
        slot_chute_exists=None,
    ):
        handlers = {
            "Server.Server": FakeResult(items=servers),
            "Instance.Instance": FakeResult(
                items=instances_by_server if instances_by_server else []
            ),
            "text:update_launch_configs": FakeResult(rowcount=0),
            "text:delete_servers": FakeResult(rowcount=1),
            "TdLaunchReservation.reservation_id": FakeResult(items=[]),
        }
        if slot_server_exists is not None:
            handlers["Server.server_id"] = FakeResult(
                items=[slot_server_exists] if slot_server_exists else []
            )
        if slot_chute_exists is not None:
            handlers["Chute.chute_id"] = FakeResult(
                items=[slot_chute_exists] if slot_chute_exists else []
            )
        return handlers

    async def _run(self, handlers, slots):
        session = FakeSession(handlers)
        purge = AsyncMock()
        send = AsyncMock()
        retire_server = AsyncMock(return_value=True)
        session.retire_server = retire_server
        with (
            patch("api.database.get_session", _session_ctx(session)),
            patch("api.instance.util.purge_and_notify", purge),
            patch("api.server.service.delete_server", retire_server),
            patch.object(ac, "send_agent_command", send),
        ):
            await ac._reconcile_host_slots("host-1", slots)
        return session, purge, send

    @pytest.mark.asyncio
    async def test_unreported_old_server_row_reaped(self, mock_settings):
        """The Model-B capacity leak: a torn-down TD's Server row must be reaped."""
        dead = _server_row(server_id="td-dead", host_id="host-1", created_at=OLD)
        instance = _instance_row(server_id="td-dead")
        handlers = self._handlers([dead], instances_by_server=[instance])
        session, purge, send = await self._run(handlers, [])
        purge.assert_awaited_once()
        assert purge.await_args.args[0] is instance
        session.retire_server.assert_awaited_once_with(
            session,
            "td-dead",
            dead.miner_hotkey,
        )

    @pytest.mark.asyncio
    async def test_reported_server_row_kept(self, mock_settings):
        live = _server_row(server_id="td-live", host_id="host-1", created_at=OLD)
        # The reported slot also runs through the host->validator drift pass; its Server
        # row and chute both exist, so nothing is torn down.
        handlers = self._handlers([live], slot_server_exists="td-live", slot_chute_exists="chute-1")
        session, purge, send = await self._run(
            handlers, [{"server_id": "td-live", "chute_id": "chute-1"}]
        )
        purge.assert_not_awaited()
        send.assert_not_awaited()
        session.retire_server.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_young_server_row_grace_period(self, mock_settings):
        """A TD still inside its boot+register window must not be reaped."""
        young = datetime.now(timezone.utc) - timedelta(seconds=10)
        booting = _server_row(server_id="td-young", host_id="host-1", created_at=young)
        handlers = self._handlers([booting])
        session, purge, _ = await self._run(handlers, [])
        purge.assert_not_awaited()
        session.retire_server.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_orphan_td_for_deleted_chute_torn_down(self, mock_settings):
        handlers = self._handlers([], slot_server_exists="td-1", slot_chute_exists=False)
        _, _, send = await self._run(handlers, [{"server_id": "td-1", "chute_id": "chute-gone"}])
        send.assert_awaited_once_with(
            "host-1", "delete_chute", {"chute_id": "chute-gone", "server_id": "td-1"}
        )

    @pytest.mark.asyncio
    async def test_unregistered_td_with_inflight_marker_kept(self, mock_settings, fake_redis):
        handlers = self._handlers([], slot_server_exists=False, slot_chute_exists="chute-1")
        handlers["TdLaunchReservation.reservation_id"] = FakeResult(items=["reservation-1"])
        _, _, send = await self._run(handlers, [{"server_id": "td-boot", "chute_id": "chute-1"}])
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unregistered_td_without_marker_torn_down(self, mock_settings):
        handlers = self._handlers([], slot_server_exists=False, slot_chute_exists="chute-1")
        _, _, send = await self._run(handlers, [{"server_id": "td-zombie", "chute_id": "chute-1"}])
        send.assert_awaited_once_with(
            "host-1", "delete_chute", {"chute_id": "chute-1", "server_id": "td-zombie"}
        )


# ---------------------------------------------------------------------------
# socket_server agent events
# ---------------------------------------------------------------------------


AGENT_HEADERS = {
    "X-Chutes-Hotkey": "hk-miner",
    "X-Chutes-Signature": "sig",
    "X-Chutes-Nonce": "12345",
    SERVER_ID_HEADER: "srv-1",
}


@pytest.fixture
def clean_sio():
    """Reset the module-level socket.io session maps and mock its IO methods."""
    ss.sio.agent_sessions = {}
    ss.sio.agent_meta = {}
    ss.sio.session_map = {}
    ss.sio.reverse_map = {}
    with (
        patch.object(ss.sio, "emit", AsyncMock()) as emit,
        patch.object(ss.sio, "disconnect", AsyncMock()) as disconnect,
    ):
        yield SimpleNamespace(emit=emit, disconnect=disconnect)


@pytest.fixture
def pass_auth():
    """get_current_user factory whose inner _authenticate always passes."""
    factory = MagicMock(return_value=AsyncMock(return_value=None))
    with patch.object(ss, "get_current_user", factory):
        yield factory


def _auth_session(server=None, host=None, *, attestation=None):
    if server is not None and attestation is None:
        attestation = _current_cpu_attestation(server)
    return FakeSession(
        {
            "Server.Server": FakeResult(items=[server] if server else []),
            "ServerAttestation.ServerAttestation": FakeResult(
                items=[attestation] if attestation else []
            ),
            "Host.Host": FakeResult(items=[host] if host else []),
        }
    )


class TestAgentAuthenticate:
    @pytest.mark.asyncio
    async def test_model_a_server_session_bound(self, clean_sio, pass_auth):
        # A self-registered CPU-TEE server must prove possession of its in-TEE attested key.
        key, cert_pem = _attested_keypair_and_cert()
        headers = dict(AGENT_HEADERS)
        headers[ATTEST_SIGNATURE_HEADER] = _sign_attest(key, "srv-1:12345:sockets-attest")
        session = _auth_session(server=_server_row(attested_cert=cert_pem))
        online = AsyncMock()
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", online),
        ):
            assert await ss.agent_authenticate("sess-1", headers) is True
        assert ss.sio.agent_sessions == {"srv-1": "sess-1"}
        assert ss.sio.agent_meta == {"sess-1": {"hotkey": "hk-miner", "server_id": "srv-1"}}
        online.assert_awaited_once_with("srv-1")
        assert clean_sio.emit.await_args.args[0] == "auth_success"
        clean_sio.disconnect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_newer_failed_attestation_rejects_valid_td_channel(
        self, clean_sio, pass_auth
    ):
        key, cert_pem = _attested_keypair_and_cert()
        headers = dict(AGENT_HEADERS)
        headers[ATTEST_SIGNATURE_HEADER] = _sign_attest(
            key, "srv-1:12345:sockets-attest"
        )
        server = _server_row(attested_cert=cert_pem)
        session = _auth_session(
            server=server,
            attestation=_current_cpu_attestation(server, failed=True),
        )
        online = AsyncMock()
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", online),
        ):
            assert await ss.agent_authenticate("sess-1", headers) is False
        assert ss.sio.agent_sessions == {}
        online.assert_not_awaited()
        clean_sio.disconnect.assert_awaited_once_with("sess-1")

    @pytest.mark.asyncio
    async def test_self_registered_missing_attested_sig_rejected(self, clean_sio, pass_auth):
        """The miner-hotkey signature alone (which the untrusted L0 host also has) must NOT bind a
        self-registered TD's channel -- without the attested-key signature, auth fails closed."""
        _key, cert_pem = _attested_keypair_and_cert()
        session = _auth_session(server=_server_row(attested_cert=cert_pem))
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", AsyncMock()),
        ):
            assert await ss.agent_authenticate("sess-1", dict(AGENT_HEADERS)) is False
        assert ss.sio.agent_sessions == {}
        clean_sio.disconnect.assert_awaited_once_with("sess-1")

    @pytest.mark.asyncio
    async def test_self_registered_wrong_attested_sig_rejected(self, clean_sio, pass_auth):
        """A signature from a DIFFERENT key (e.g. an attacker's, not the registration-bound one) is
        rejected -- only the in-TEE key whose pubkey is in the stored attested cert is accepted."""
        _key, cert_pem = _attested_keypair_and_cert()
        attacker_key, _ = _attested_keypair_and_cert()
        headers = dict(AGENT_HEADERS)
        headers[ATTEST_SIGNATURE_HEADER] = _sign_attest(attacker_key, "srv-1:12345:sockets-attest")
        session = _auth_session(server=_server_row(attested_cert=cert_pem))
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", AsyncMock()),
        ):
            assert await ss.agent_authenticate("sess-1", headers) is False
        assert ss.sio.agent_sessions == {}

    @pytest.mark.asyncio
    async def test_self_registered_no_attested_cert_on_record_rejected(self, clean_sio, pass_auth):
        """A self-registered server with no stored attested cert cannot have its channel bound; reject."""
        session = _auth_session(server=_server_row(attested_cert=None))
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", AsyncMock()),
        ):
            assert await ss.agent_authenticate("sess-1", dict(AGENT_HEADERS)) is False
        assert ss.sio.agent_sessions == {}

    @pytest.mark.asyncio
    async def test_model_b_host_cannot_fallback_to_miner_hotkey(self, clean_sio, pass_auth):
        """L0 hosts must use the dedicated server-challenge host-key flow."""
        host = SimpleNamespace(host_id="srv-1", miner_hotkey="hk-miner")
        session = _auth_session(server=None, host=host)
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(ss, "mark_agent_online", AsyncMock()),
        ):
            assert await ss.agent_authenticate("sess-1", dict(AGENT_HEADERS)) is False
        assert ss.sio.agent_sessions == {}

    @pytest.mark.asyncio
    async def test_missing_server_id_header_rejected(self, clean_sio, pass_auth):
        headers = {k: v for k, v in AGENT_HEADERS.items() if k != SERVER_ID_HEADER}
        session = _auth_session()
        with patch.object(ss, "get_session", _session_ctx(session)):
            assert await ss.agent_authenticate("sess-1", headers) is False
        assert clean_sio.emit.await_args.args[0] == "auth_failed"
        clean_sio.disconnect.assert_awaited_once_with("sess-1")
        assert ss.sio.agent_sessions == {}

    @pytest.mark.asyncio
    async def test_unowned_server_id_rejected(self, clean_sio, pass_auth):
        """A miner cannot bind a session to a server/host it does not own."""
        session = _auth_session(server=None, host=None)
        with patch.object(ss, "get_session", _session_ctx(session)):
            assert await ss.agent_authenticate("sess-1", dict(AGENT_HEADERS)) is False
        assert clean_sio.emit.await_args.args[0] == "auth_failed"
        clean_sio.disconnect.assert_awaited_once_with("sess-1")

    @pytest.mark.asyncio
    async def test_bad_signature_rejected(self, clean_sio):
        from fastapi import HTTPException, status as http_status

        factory = MagicMock(
            return_value=AsyncMock(
                side_effect=HTTPException(
                    status_code=http_status.HTTP_401_UNAUTHORIZED,
                    detail="bad signature",
                )
            )
        )
        with patch.object(ss, "get_current_user", factory):
            assert await ss.agent_authenticate("sess-1", dict(AGENT_HEADERS)) is False
        assert clean_sio.emit.await_args.args[0] == "auth_failed"
        clean_sio.disconnect.assert_awaited_once_with("sess-1")


class TestGpuTdSocketChallenge:
    @pytest.mark.asyncio
    async def test_gpu_challenge_binds_exact_reservation_lineage(
        self,
        clean_sio,
    ):
        server = SimpleNamespace(
            server_id="gpu-server",
            self_registered=True,
            compute_type="gpu",
            attested_cert="certificate",
            attested_cert_pubkey_hash="a" * 64,
            gpu_launch_reservation_id="gpu-reservation",
            gpu_allocation_group_id="gpu-group",
            gpu_allocation_group_generation=7,
            gpu_process_incarnation="gpu-process",
        )
        reservation = SimpleNamespace(
            reservation_id="gpu-reservation",
            state="running",
            server_id=server.server_id,
            claims_sha256="b" * 64,
            allocation_group_id="gpu-group",
            allocation_group_generation=7,
            process_incarnation="gpu-process",
        )
        result = MagicMock()
        result.scalar_one_or_none.return_value = server
        session = AsyncMock()
        session.execute.return_value = result
        session.get.return_value = reservation
        redis = AsyncMock()
        with (
            patch.object(ss, "get_session", _session_ctx(session)),
            patch.object(
                ss,
                "settings",
                SimpleNamespace(redis_client=redis),
            ),
            patch(
                "api.server.gpu_sessions._latest_attestation_attempt",
                AsyncMock(return_value=SimpleNamespace()),
            ),
            patch("api.server.gpu_sessions._current_attestation"),
        ):
            assert await ss.td_challenge(
                "sess-gpu",
                {"server_id": server.server_id},
            )
        event, payload = clean_sio.emit.await_args.args[:2]
        assert event == "td_challenge"
        assert payload["gpu_launch_reservation_id"] == (reservation.reservation_id)
        assert payload["gpu_claims_sha256"] == reservation.claims_sha256
        assert payload["gpu_allocation_group_id"] == (reservation.allocation_group_id)
        assert "launch_reservation_id" not in payload


class TestAgentStatusEvent:
    @pytest.mark.asyncio
    async def test_unauthenticated_session_disconnected(self, clean_sio):
        handler = AsyncMock()
        with patch.object(ss, "handle_agent_status", handler):
            await ss.agent_status("sess-unknown", {"containers": []})
        clean_sio.disconnect.assert_awaited_once_with("sess-unknown")
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_heartbeat_refreshes_liveness_and_reconciles(self, clean_sio):
        ss.sio.agent_meta["sess-1"] = {"hotkey": "hk", "server_id": "srv-1"}
        online = AsyncMock()
        handler = AsyncMock()
        with (
            patch.object(ss, "mark_agent_online", online),
            patch.object(ss, "handle_agent_status", handler),
        ):
            await ss.agent_status("sess-1", {"containers": ["cfg-1"]})
        online.assert_awaited_once_with("srv-1")
        handler.assert_awaited_once_with("srv-1", {"containers": ["cfg-1"]})
        clean_sio.disconnect.assert_not_awaited()


class TestAgentCommandAckEvent:
    @pytest.mark.asyncio
    async def test_unauthenticated_session_disconnected(self, clean_sio):
        handler = AsyncMock()
        with patch.object(ss, "handle_agent_command_ack", handler):
            await ss.agent_command_ack("sess-unknown", {"command_id": "x"})
        clean_sio.disconnect.assert_awaited_once_with("sess-unknown")
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ack_forwarded(self, clean_sio):
        ss.sio.agent_meta["sess-1"] = {"hotkey": "hk", "server_id": "srv-1"}
        handler = AsyncMock()
        with patch.object(ss, "handle_agent_command_ack", handler):
            await ss.agent_command_ack("sess-1", {"command_id": "cmd-1", "status": "ok"})
        handler.assert_awaited_once_with("srv-1", {"command_id": "cmd-1", "status": "ok"})

    @pytest.mark.asyncio
    async def test_non_dict_ack_wrapped(self, clean_sio):
        ss.sio.agent_meta["sess-1"] = {"hotkey": "hk", "server_id": "srv-1"}
        handler = AsyncMock()
        with patch.object(ss, "handle_agent_command_ack", handler):
            await ss.agent_command_ack("sess-1", "weird")
        handler.assert_awaited_once_with("srv-1", {"data": "weird"})


class TestAgentDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_clears_session_and_liveness(self, clean_sio):
        ss.sio.agent_sessions["srv-1"] = "sess-1"
        ss.sio.agent_meta["sess-1"] = {"hotkey": "hk", "server_id": "srv-1"}
        offline = AsyncMock()
        with patch.object(ss, "mark_agent_offline", offline):
            await ss.disconnect("sess-1")
        offline.assert_awaited_once_with("srv-1")
        assert ss.sio.agent_sessions == {}
        assert ss.sio.agent_meta == {}

    @pytest.mark.asyncio
    async def test_disconnect_of_stale_session_keeps_newer_binding(self, clean_sio):
        """A reconnected agent's new session must not be evicted by the old one closing."""
        ss.sio.agent_sessions["srv-1"] = "sess-NEW"
        ss.sio.agent_meta["sess-old"] = {"hotkey": "hk", "server_id": "srv-1"}
        ss.sio.agent_meta["sess-NEW"] = {"hotkey": "hk", "server_id": "srv-1"}
        offline = AsyncMock()
        with patch.object(ss, "mark_agent_offline", offline):
            await ss.disconnect("sess-old")
        assert ss.sio.agent_sessions == {"srv-1": "sess-NEW"}
