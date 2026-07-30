import base64
import hashlib
import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from api.database import get_db_session
from api.host import service as host_service
from api.host.router import router as host_router
from api.host.schemas import (
    HostIdentityDurabilityAckV1,
    HostKeyGeneration,
    HostPcsMailbox,
    HostProvisioningHeartbeatV1,
    HostSocketAuthenticationV1,
    PcsMailboxAckV1,
)
from cross_repo_tests import repository_root
from api.server.schemas import Host


def _host(tee_type="tdx", state="persisting_identity"):
    return Host(
        host_id="host-1",
        name="host-1",
        miner_hotkey="owner",
        netuid=64,
        tee_type=tee_type,
        capacity=1,
        storage_enabled=False,
        release_channel="stable",
        enrollment_generation=2,
        active_key_generation=3,
        provisioning_state=state,
        enrolled_at=datetime.now(timezone.utc),
    )


def _durability_ack():
    return HostIdentityDurabilityAckV1(
        enrollment_generation=2,
        key_generation=3,
        identity_metadata_sha256="1" * 64,
        steady_config_sha256="2" * 64,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tee_type", "expected_state"),
    [("sev-snp", "ready"), ("tdx", "awaiting_pcs")],
)
async def test_identity_durability_ack_controls_ready_transition(tee_type, expected_state):
    host = _host(tee_type)
    db = AsyncMock()

    result = await host_service.acknowledge_identity_durability(
        db,
        host,
        _durability_ack(),
    )

    assert result.provisioning_state == expected_state
    assert host.provisioning_state == expected_state
    assert host.identity_durable_at is not None
    assert host.identity_metadata_sha256 == "1" * 64
    assert host.steady_config_sha256 == "2" * 64
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["awaiting_pcs", "ready"])
async def test_existing_seedless_state_can_backfill_durability(state):
    host = _host("tdx", state)
    db = AsyncMock()

    result = await host_service.acknowledge_identity_durability(
        db,
        host,
        _durability_ack(),
    )

    assert result.provisioning_state == state
    assert host.provisioning_state == state
    assert host.identity_durable_at is not None
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_provisioning_heartbeat_is_limited_to_matching_transitional_state():
    host = _host(state="awaiting_pcs")
    host.identity_durable_at = datetime.now(timezone.utc)
    heartbeat = HostProvisioningHeartbeatV1(
        enrollment_generation=2,
        key_generation=3,
        provisioning_state="awaiting_pcs",
        observed_at=datetime.now(timezone.utc),
    )
    db = AsyncMock()

    status = await host_service.record_provisioning_heartbeat(
        db,
        host,
        heartbeat,
    )
    assert status.provisioning_state == "awaiting_pcs"
    assert host.provisioning_heartbeat_at is not None
    assert host.provisioning_status["schema"] == "chutes.host-provisioning-heartbeat"

    host.provisioning_state = "ready"
    with pytest.raises(host_service.HostAuthError, match="does not match"):
        await host_service.record_provisioning_heartbeat(db, host, heartbeat)


@pytest.mark.asyncio
async def test_pcs_ack_rechecks_expiry_before_ready_transition():
    now = datetime.now(timezone.utc)
    host = _host(state="awaiting_pcs")
    host.identity_durable_at = now - timedelta(minutes=5)
    row = HostPcsMailbox(
        message_id="message-1",
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        enrollment_generation=host.enrollment_generation,
        key_generation=host.active_key_generation,
        recipient_fingerprint="3" * 64,
        envelope={},
        envelope_sha256="4" * 64,
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
        delivered_at=now - timedelta(hours=1, minutes=30),
    )
    result = Mock()
    result.scalar_one_or_none.return_value = row
    db = AsyncMock()
    db.execute.return_value = result

    with pytest.raises(host_service.HostAuthError, match="expired"):
        await host_service.acknowledge_pcs_mailbox(
            db,
            host,
            PcsMailboxAckV1(
                message_id=row.message_id,
                envelope_sha256=row.envelope_sha256,
            ),
        )
    assert row.invalidated_at is not None
    assert host.provisioning_state == "awaiting_pcs"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_pcs_ack_retry_after_committed_ready_is_idempotent():
    now = datetime.now(timezone.utc)
    host = _host(state="ready")
    host.identity_durable_at = now - timedelta(minutes=5)
    row = HostPcsMailbox(
        message_id="message-1",
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        enrollment_generation=host.enrollment_generation,
        key_generation=host.active_key_generation,
        recipient_fingerprint="3" * 64,
        envelope={},
        envelope_sha256="4" * 64,
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
        delivered_at=now - timedelta(hours=1, minutes=30),
        consumed_at=now - timedelta(hours=1, minutes=29),
    )
    result = Mock()
    result.scalar_one_or_none.return_value = row
    db = AsyncMock()
    db.execute.return_value = result

    await host_service.acknowledge_pcs_mailbox(
        db,
        host,
        PcsMailboxAckV1(
            message_id=row.message_id,
            envelope_sha256=row.envelope_sha256,
        ),
    )

    db.commit.assert_not_awaited()


class _Redis:
    def __init__(self):
        self.values = {}

    async def setex(self, key, _ttl, value):
        self.values[key] = value

    async def getdel(self, key):
        return self.values.pop(key, None)


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Db:
    def __init__(self, host, key):
        self.host = host
        self.key = key
        self.execute_values = []
        self.commit_count = 0
        self.info = {}

    async def get(self, model, _identity):
        if model is Host:
            return self.host
        if model is HostKeyGeneration:
            return self.key
        return None

    async def execute(self, _query, _params=None):
        if "pg_advisory_xact_lock" in str(_query):
            return _Result(None)
        return _Result(self.execute_values.pop(0))

    async def commit(self):
        self.commit_count += 1
        self.info.clear()


def _load_node_agent_modules(monkeypatch):
    sek8s = repository_root("sek8s", start=Path(__file__)) / "src"
    for package in ("sek8s-common", "chutes-agent", "chutes-node-agent"):
        monkeypatch.syspath_prepend(str(sek8s / package))
    identity_module = importlib.import_module("chutes_node_agent.identity")
    auth_module = importlib.import_module("chutes_node_agent.host_auth")
    socket_auth_module = importlib.import_module("chutes_node_agent.socket_auth")
    return identity_module, auth_module, socket_auth_module


@pytest.mark.asyncio
async def test_cross_repo_http_host_challenge_and_signature_interoperate(monkeypatch):
    identity_module, auth_module, _channel_module = _load_node_agent_modules(monkeypatch)
    identity = identity_module.HostIdentity.create_unenrolled(
        "/unused",
        host_id="host-1",
        tee_type="tdx",
        channel="stable",
    ).enrolled(
        owner_hotkey="owner",
        enrollment_generation=2,
        key_generation=3,
    )
    host = _host(state="persisting_identity")
    key = HostKeyGeneration(
        host_id=host.host_id,
        generation=host.active_key_generation,
        enrollment_generation=host.enrollment_generation,
        ed25519_public_key=identity.ed25519_public_key_b64,
        ed25519_fingerprint=hashlib.sha256(
            base64.b64decode(identity.ed25519_public_key_b64)
        ).hexdigest(),
        x25519_public_key=identity.x25519_public_key_b64,
        x25519_fingerprint=identity.x25519_fingerprint,
    )
    database = _Db(host, key)
    database.execute_values = [host, key]
    redis = _Redis()

    app = FastAPI()
    app.include_router(host_router, prefix="/hosts")
    app.dependency_overrides[get_db_session] = lambda: database

    @app.get("/probe")
    async def probe(current_host: Host = Depends(host_service.get_current_host)):
        return {"host_id": current_host.host_id}

    with patch.object(host_service.settings, "_redis_client", redis):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://validator.test",
        ) as client:
            response = await auth_module.signed_host_request(
                client,
                identity,
                "GET",
                "/probe",
            )
    assert response.status_code == 200
    assert response.json() == {"host_id": "host-1"}
    assert not redis.values


@pytest.mark.asyncio
async def test_cross_repo_socket_challenge_and_signature_interoperate(monkeypatch):
    identity_module, _auth_module, channel_module = _load_node_agent_modules(monkeypatch)
    identity = identity_module.HostIdentity.create_unenrolled(
        "/unused",
        host_id="host-1",
        tee_type="tdx",
        channel="stable",
    ).enrolled(
        owner_hotkey="owner",
        enrollment_generation=2,
        key_generation=3,
    )
    host = _host(state="ready")
    host.identity_durable_at = datetime.now(timezone.utc)
    key = HostKeyGeneration(
        host_id=host.host_id,
        generation=host.active_key_generation,
        enrollment_generation=host.enrollment_generation,
        ed25519_public_key=identity.ed25519_public_key_b64,
        ed25519_fingerprint=hashlib.sha256(
            base64.b64decode(identity.ed25519_public_key_b64)
        ).hexdigest(),
        x25519_public_key=identity.x25519_public_key_b64,
        x25519_fingerprint=identity.x25519_fingerprint,
    )
    database = _Db(host, key)
    redis = _Redis()

    with patch.object(host_service.settings, "_redis_client", redis):
        challenge = await host_service.create_host_socket_challenge(
            database,
            "socket-session-1",
            host.host_id,
            host.active_key_generation,
        )
        authentication = channel_module.build_host_socket_authentication(
            identity,
            challenge.model_dump(mode="json"),
        )
        database.execute_values = [host, key]
        verified = await host_service.verify_host_socket_authentication(
            database,
            "socket-session-1",
            HostSocketAuthenticationV1.model_validate(authentication),
        )
    assert verified is host
    # Challenge publication commits the lifecycle-locked validation before Redis, then
    # authentication commits the post-consumption lineage recheck.
    assert database.commit_count == 2
    assert database.info == {}
    assert not redis.values
