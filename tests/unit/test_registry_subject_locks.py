import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from api.host.locks import (
    acquire_registry_subject_locks,
    registry_subject_lock_keys,
)
from api.host.schemas import RegistrySession, canonical_sha256
from api.registry import router as registry_router


def _registry_row() -> RegistrySession:
    now = datetime.now(timezone.utc)
    digest = f"sha256:{'a' * 64}"
    closure_sha256 = canonical_sha256(
        {
            "schema": "chutes.oci-descriptor-closure",
            "version": 1,
            "root_manifest": digest,
            "manifests": [digest],
            "blobs": [],
            "manifest_tags": [],
            "manifest_tag_digests": {},
        }
    )
    return RegistrySession(
        session_id="session-a",
        token_id="token-a",
        server_id="server-a",
        scope_id="launch-config:config-a",
        launch_config_id="config-a",
        attested_cert_pubkey_hash="c" * 64,
        repository="owner/image",
        actions=["pull"],
        manifest_digest=digest,
        allowed_manifests=[digest],
        allowed_blobs=[],
        allowed_manifest_tags=[],
        manifest_tag_digests={},
        descriptor_closure_sha256=closure_sha256,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        revoked_at=None,
        last_used_at=None,
    )


def _scalar_result(value):
    result = Mock()
    result.scalar_one_or_none.return_value = value
    return result


class _AdvisoryLockServer:
    def __init__(self):
        self.locks: dict[str, asyncio.Lock] = {}

    def connection(self):
        return _AdvisoryConnection(self)


class _AdvisoryConnection:
    def __init__(self, server: _AdvisoryLockServer):
        self.server = server
        self.info = {}
        self.attempts: list[str] = []
        self._held: list[asyncio.Lock] = []

    async def execute(self, statement, parameters):
        assert "pg_advisory_xact_lock" in str(statement)
        key = parameters["key"]
        self.attempts.append(key)
        lock = self.server.locks.setdefault(key, asyncio.Lock())
        await lock.acquire()
        self._held.append(lock)

    async def commit(self):
        for lock in reversed(self._held):
            lock.release()
        self._held.clear()


def test_registry_subject_lock_keys_are_deterministic_and_fail_closed():
    keys = registry_subject_lock_keys(
        server_id="server-a",
        launch_config_id="config-a",
    )
    assert keys == tuple(sorted(keys))
    assert keys == (
        "chutes:registry-auth:v1:launch-config:config-a",
        "chutes:registry-auth:v1:server:server-a",
    )
    with pytest.raises(ValueError, match="server id"):
        registry_subject_lock_keys(server_id="", launch_config_id=None)
    with pytest.raises(ValueError, match="launch config id"):
        registry_subject_lock_keys(server_id="server-a", launch_config_id=" ")


@pytest.mark.asyncio
async def test_invalid_registry_signature_acquires_no_lock():
    row = _registry_row()
    with patch.object(registry_router.settings, "launch_config_key", "attacker-key"):
        token = registry_router._encode_registry_session(row)
    db = AsyncMock()
    subject_locks = AsyncMock()
    with (
        patch.object(registry_router.settings, "launch_config_key", "trusted-key"),
        patch.object(
            registry_router,
            "acquire_registry_subject_locks",
            subject_locks,
        ),
        pytest.raises(HTTPException) as raised,
    ):
        await registry_router._validate_registry_session(
            db,
            token,
            "c" * 64,
            "GET",
            f"/v2/owner/image/manifests/{row.manifest_digest}",
            row.launch_config_id,
        )

    assert raised.value.status_code == 401
    subject_locks.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_signed_scope_is_rejected_before_subject_lock():
    row = _registry_row()
    db = AsyncMock()
    db.execute.return_value = _scalar_result(row)
    subject_locks = AsyncMock()
    with (
        patch.object(registry_router.settings, "launch_config_key", "trusted-key"),
        patch.object(
            registry_router,
            "acquire_registry_subject_locks",
            subject_locks,
        ),
        pytest.raises(HTTPException) as raised,
    ):
        token = registry_router._encode_registry_session(row)
        await registry_router._validate_registry_session(
            db,
            token,
            "c" * 64,
            "GET",
            f"/v2/owner/image/blobs/sha256:{'f' * 64}",
            row.launch_config_id,
        )

    assert raised.value.status_code == 403
    subject_locks.assert_not_awaited()
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_valid_session_is_checked_before_subject_lock_and_rechecked_after():
    row = _registry_row()
    db = AsyncMock()
    db.execute.side_effect = [_scalar_result(row), _scalar_result(row)]
    launch_config = Mock(
        config_id=row.launch_config_id,
        container_repository=row.repository,
        container_manifest_digest=row.manifest_digest,
    )
    db.get.return_value = launch_config
    server = Mock(
        server_id=row.server_id,
        compute_type="gpu",
        gpu_management_mode="miner",
    )

    async def acquire_after_preflight(*_args, **_kwargs):
        assert db.execute.await_count == 1

    subject_locks = AsyncMock(side_effect=acquire_after_preflight)
    with (
        patch.object(registry_router.settings, "launch_config_key", "trusted-key"),
        patch.object(
            registry_router,
            "acquire_registry_subject_locks",
            subject_locks,
        ),
        patch.object(
            registry_router,
            "_current_attested_registry_server",
            AsyncMock(return_value=server),
        ),
        patch.object(
            registry_router,
            "_miner_launch_scope_current",
            AsyncMock(return_value=True),
        ),
    ):
        token = registry_router._encode_registry_session(row)
        validated = await registry_router._validate_registry_session(
            db,
            token,
            "c" * 64,
            "GET",
            f"/v2/owner/image/manifests/{row.manifest_digest}",
            row.launch_config_id,
        )

    assert validated is row
    subject_locks.assert_awaited_once_with(
        db,
        server_id=row.server_id,
        launch_config_id=row.launch_config_id,
    )
    assert db.execute.await_count == 2
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_distinct_registry_subjects_cross_the_barrier_concurrently():
    server = _AdvisoryLockServer()
    release = asyncio.Event()
    entered = {name: asyncio.Event() for name in ("first", "second")}

    async def worker(name: str, server_id: str, launch_config_id: str):
        db = server.connection()
        await acquire_registry_subject_locks(
            db,
            server_id=server_id,
            launch_config_id=launch_config_id,
        )
        entered[name].set()
        try:
            await release.wait()
        finally:
            await db.commit()

    tasks = [
        asyncio.create_task(worker("first", "server-a", "config-a")),
        asyncio.create_task(worker("second", "server-b", "config-b")),
    ]
    try:
        await asyncio.wait_for(entered["first"].wait(), timeout=1)
        await asyncio.wait_for(entered["second"].wait(), timeout=1)
    finally:
        release.set()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_same_registry_server_serializes_different_configs():
    server = _AdvisoryLockServer()
    first = server.connection()
    second = server.connection()
    first_entered = asyncio.Event()
    second_entered = asyncio.Event()
    shared_server_key = "chutes:registry-auth:v1:server:server-a"
    release_first = asyncio.Event()

    async def hold_first():
        await acquire_registry_subject_locks(
            first,
            server_id="server-a",
            launch_config_id="config-a",
        )
        first_entered.set()
        try:
            await release_first.wait()
        finally:
            await first.commit()

    async def enter_second():
        await acquire_registry_subject_locks(
            second,
            server_id="server-a",
            launch_config_id="config-b",
        )
        second_entered.set()
        await second.commit()

    first_task = asyncio.create_task(hold_first())
    await asyncio.wait_for(first_entered.wait(), timeout=1)
    second_task = asyncio.create_task(enter_second())
    try:

        async def shared_key_was_attempted():
            while shared_server_key not in second.attempts:
                await asyncio.sleep(0)

        await asyncio.wait_for(shared_key_was_attempted(), timeout=1)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(second_entered.wait(), timeout=0.05)
    finally:
        release_first.set()
        await asyncio.gather(first_task, second_task)
    assert second_entered.is_set()
