"""Real-PostgreSQL key-epoch rollout, acknowledgement, and replay coverage."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from api.config import settings
from api.server.schemas import (
    ChuteFSLaunchSession,
    ChuteFSTokenKeyEpoch,
    ChuteFSTokenKeyEpochOperation,
    ChuteFSTokenKeyReplicaAck,
    DefaultChuteFSVolumeBinding,
    Server,
)
from api.storage import key_epochs, launch_sessions
from api.storage import startup as storage_startup
from api.storage.launch_sessions import ALLOWED_OPERATIONS
from tests.integration import test_gpu_chutefs_postgres as chutefs_pg
from tests.integration import test_storage_reconciliation_postgres as storage_pg

pytest_plugins = ["tests.integration.test_storage_reconciliation_postgres"]

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for ChuteFS key-epoch tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    yield


@pytest.fixture(autouse=True)
def storage_crypto(monkeypatch):
    monkeypatch.setattr(
        "api.server.util.settings.fernet_key",
        Fernet(Fernet.generate_key()),
    )


async def _install_rotation_migration(db) -> None:
    await db.commit()
    async with db.bind.begin() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(
            storage_pg._migration_up_sql(
                "20260726121000_chutefs_session_rotation_replay.sql"
            )
        )
    await db.rollback()


def _configure(
    monkeypatch,
    *,
    replica_id: str,
    new_secret: str = "n" * 32,
    keys: dict[str, str] | None = None,
) -> None:
    monkeypatch.setattr(settings, "chutefs_token_key_id", "old-key")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps(keys or {"old-key": "o" * 32, "new-key": new_secret}),
    )
    monkeypatch.setattr(settings, "chutefs_token_replica_id", replica_id)


async def test_rolling_replicas_ack_activate_retire_and_replay_lost_responses(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _install_rotation_migration(db)
    monkeypatch.setattr(storage_startup, "engine", db.bind)

    # Bootstrap before the successor is distributed.
    monkeypatch.setattr(settings, "chutefs_token_key_id", "old-key")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"old-key": "o" * 32}),
    )
    monkeypatch.setattr(settings, "chutefs_token_replica_id", "bootstrap-pod")
    await storage_startup.require_chutefs_token_key_retention()

    # A rolling deployment starts with old+new before the epoch exists. The
    # active per-key fingerprint still matches, so both new pod UIDs become ready.
    _configure(monkeypatch, replica_id="pod-a")
    await storage_startup.require_chutefs_token_key_retention()
    _configure(monkeypatch, replica_id="pod-b")
    await storage_startup.require_chutefs_token_key_retention()

    _configure(monkeypatch, replica_id="pod-a")
    stage_request_id = str(uuid.uuid4())
    staged = await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=stage_request_id,
        key_id="new-key",
        required_replica_ids=["pod-b", "pod-a"],
    )
    assert staged["required_replica_ids"] == ["pod-a", "pod-b"]
    # Lost response: the exact request returns the persisted response.
    assert (
        await key_epochs.stage_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=stage_request_id,
            key_id="new-key",
            required_replica_ids=["pod-a", "pod-b"],
        )
        == staged
    )

    # Readiness is the bounded, no-restart acknowledgement path for an epoch
    # staged after the rollout.
    await storage_startup.require_chutefs_token_key_retention()
    with pytest.raises(HTTPException, match="fresh acknowledgement"):
        await key_epochs.activate_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=str(uuid.uuid4()),
            key_id="new-key",
        )
    await db.rollback()
    _configure(monkeypatch, replica_id="pod-b")
    await storage_startup.require_chutefs_token_key_retention()

    activate_request_id = str(uuid.uuid4())
    activated = await key_epochs.activate_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=activate_request_id,
        key_id="new-key",
    )
    assert activated["state"] == "active"
    assert activated["active_key_id"] == "new-key"
    assert (
        await key_epochs.activate_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=activate_request_id,
            key_id="new-key",
        )
        == activated
    )

    old_epoch = await db.get(ChuteFSTokenKeyEpoch, "old-key")
    new_epoch = await db.get(ChuteFSTokenKeyEpoch, "new-key")
    assert old_epoch.state == "retiring"
    assert new_epoch.state == "active"

    retire_request_id = str(uuid.uuid4())
    retired = await key_epochs.retire_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=retire_request_id,
        key_id="old-key",
    )
    assert retired["state"] == "retired"
    assert (
        await key_epochs.retire_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=retire_request_id,
            key_id="old-key",
        )
        == retired
    )
    assert (
        await db.scalar(select(func.count()).select_from(ChuteFSTokenKeyEpochOperation))
        == 3
    )


async def test_same_key_ids_with_different_secret_bytes_cannot_activate(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _install_rotation_migration(db)
    monkeypatch.setattr(storage_startup, "engine", db.bind)

    monkeypatch.setattr(settings, "chutefs_token_key_id", "old-key")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"old-key": "o" * 32}),
    )
    monkeypatch.setattr(settings, "chutefs_token_replica_id", "bootstrap-pod")
    await storage_startup.require_chutefs_token_key_retention()

    _configure(monkeypatch, replica_id="pod-a", new_secret="n" * 32)
    await storage_startup.require_chutefs_token_key_retention()
    _configure(monkeypatch, replica_id="pod-b", new_secret="x" * 32)
    await storage_startup.require_chutefs_token_key_retention()

    _configure(monkeypatch, replica_id="pod-a", new_secret="n" * 32)
    await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="new-key",
        required_replica_ids=["pod-a", "pod-b"],
    )
    await storage_startup.require_chutefs_token_key_retention()
    _configure(monkeypatch, replica_id="pod-b", new_secret="x" * 32)
    await storage_startup.require_chutefs_token_key_retention()

    _configure(monkeypatch, replica_id="pod-a", new_secret="n" * 32)
    with pytest.raises(HTTPException, match="same complete keyring"):
        await key_epochs.activate_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=str(uuid.uuid4()),
            key_id="new-key",
        )
    await db.rollback()
    assert (await db.get(ChuteFSTokenKeyEpoch, "old-key")).state == "active"
    assert (await db.get(ChuteFSTokenKeyEpoch, "new-key")).state == "staged"
    assert (
        await db.scalar(
            select(func.count())
            .select_from(ChuteFSTokenKeyReplicaAck)
            .where(ChuteFSTokenKeyReplicaAck.key_id == "new-key")
        )
        == 2
    )


async def test_stale_replica_ack_cannot_activate_and_replacement_cohort_can(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _install_rotation_migration(db)
    monkeypatch.setattr(storage_startup, "engine", db.bind)

    _configure(
        monkeypatch,
        replica_id="bootstrap-pod",
        keys={"old-key": "o" * 32},
    )
    await storage_startup.require_chutefs_token_key_retention()

    stale_keys = {"old-key": "o" * 32, "stale-key": "s" * 32}
    _configure(monkeypatch, replica_id="pod-a", keys=stale_keys)
    await storage_startup.require_chutefs_token_key_retention()
    await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="stale-key",
        required_replica_ids=["pod-a"],
    )
    await storage_startup.require_chutefs_token_key_retention()
    await db.execute(
        update(ChuteFSTokenKeyReplicaAck)
        .where(
            ChuteFSTokenKeyReplicaAck.replica_id == "pod-a",
            ChuteFSTokenKeyReplicaAck.key_id == "stale-key",
        )
        .values(
            acknowledged_at=datetime.now(timezone.utc)
            - timedelta(seconds=storage_startup.TOKEN_KEY_ACK_MAX_AGE_SECONDS + 1)
        )
    )
    await db.commit()

    with pytest.raises(HTTPException, match="fresh acknowledgement"):
        await key_epochs.activate_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=str(uuid.uuid4()),
            key_id="stale-key",
        )
    await db.rollback()

    replacement_keys = {"old-key": "o" * 32, "replacement-key": "r" * 32}
    _configure(monkeypatch, replica_id="pod-b", keys=replacement_keys)
    await storage_startup.require_chutefs_token_key_retention()
    await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="replacement-key",
        required_replica_ids=["pod-b"],
    )
    await storage_startup.require_chutefs_token_key_retention()
    activated = await key_epochs.activate_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="replacement-key",
    )

    assert activated["active_key_id"] == "replacement-key"
    assert (await db.get(ChuteFSTokenKeyEpoch, "stale-key")).state == "staged"
    assert (await db.get(ChuteFSTokenKeyEpoch, "replacement-key")).state == "active"


async def test_retirement_requires_access_refresh_and_response_replay_expiry(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _install_rotation_migration(db)
    monkeypatch.setattr(storage_startup, "engine", db.bind)

    _configure(
        monkeypatch,
        replica_id="bootstrap-pod",
        keys={"old-key": "o" * 32},
    )
    await storage_startup.require_chutefs_token_key_retention()

    chute = await chutefs_pg._chute(
        db,
        storage_pg.USER_ID,
        f"retirement-{uuid.uuid4().hex}",
    )
    _, cert = chutefs_pg._identity("retirement-boundary")
    config, instance = await chutefs_pg._cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"retirement-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    binding = await db.scalar(
        select(DefaultChuteFSVolumeBinding).where(
            DefaultChuteFSVolumeBinding.user_id == storage_pg.USER_ID,
            DefaultChuteFSVolumeBinding.chute_id == chute.chute_id,
            DefaultChuteFSVolumeBinding.lifecycle_state == "active",
        )
    )
    server = await db.get(Server, config.server_id)
    now = datetime.now(timezone.utc)
    db.add(
        ChuteFSLaunchSession(
            session_id=f"old-key-session-{uuid.uuid4().hex}",
            config_id=config.config_id,
            instance_id=instance.instance_id,
            binding_id=binding.binding_id,
            user_id=storage_pg.USER_ID,
            chute_id=chute.chute_id,
            job_id=None,
            compute_type="cpu",
            management_mode="platform",
            server_id=server.server_id,
            volume_id=binding.volume_id,
            reservation_id=None,
            allocation_group_id=None,
            allocation_group_generation=None,
            process_incarnation=None,
            attestation_id=None,
            attested_cert_pubkey_hash=server.attested_cert_pubkey_hash,
            allowed_operations=list(ALLOWED_OPERATIONS),
            generation=1,
            access_token_hash=uuid.uuid4().hex * 2,
            refresh_token_hash=uuid.uuid4().hex * 2,
            access_expires_at=now - timedelta(minutes=1),
            refresh_expires_at=now + timedelta(hours=24),
            rotation_request_sha256=uuid.uuid4().hex * 2,
            token_seed=uuid.uuid4().hex * 2,
            token_key_id="old-key",
            response_replay_until=now - timedelta(seconds=1),
            revoked_at=now - timedelta(minutes=1),
        )
    )
    await db.commit()

    _configure(monkeypatch, replica_id="pod-a")
    await storage_startup.require_chutefs_token_key_retention()
    await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="new-key",
        required_replica_ids=["pod-a"],
    )
    await storage_startup.require_chutefs_token_key_retention()
    await key_epochs.activate_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="new-key",
    )

    with pytest.raises(HTTPException, match="unexpired session authority"):
        await key_epochs.retire_token_key_epoch(
            db,
            administrator_id="support-user",
            request_id=str(uuid.uuid4()),
            key_id="old-key",
        )
    await db.rollback()

    with pytest.raises(DBAPIError, match="referenced by replayable sessions"):
        await db.execute(
            update(ChuteFSTokenKeyEpoch)
            .where(ChuteFSTokenKeyEpoch.key_id == "old-key")
            .values(state="retired", retired_at=datetime.now(timezone.utc))
        )
        await db.commit()
    await db.rollback()
    assert (await db.get(ChuteFSTokenKeyEpoch, "old-key")).state == "retiring"


async def test_paused_mint_fences_activation_retirement_and_stale_direct_insert(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _install_rotation_migration(db)
    monkeypatch.setattr(storage_startup, "engine", db.bind)

    _configure(
        monkeypatch,
        replica_id="bootstrap-pod",
        keys={"old-key": "o" * 32},
    )
    await storage_startup.require_chutefs_token_key_retention()
    _configure(monkeypatch, replica_id="pod-a")
    await storage_startup.require_chutefs_token_key_retention()
    await key_epochs.stage_token_key_epoch(
        db,
        administrator_id="support-user",
        request_id=str(uuid.uuid4()),
        key_id="new-key",
        required_replica_ids=["pod-a"],
    )
    await storage_startup.require_chutefs_token_key_retention()

    chute = await chutefs_pg._chute(
        db,
        storage_pg.USER_ID,
        f"mint-epoch-fence-{uuid.uuid4().hex}",
    )
    _, cert = chutefs_pg._identity("mint-epoch-fence")
    config, _instance = await chutefs_pg._cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"mint-epoch-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    await db.commit()

    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = chutefs_pg._mtls_request(cert)
    active_key_read = asyncio.Event()
    release_mint = asyncio.Event()
    original_active_key = launch_sessions._active_token_key_id

    async def paused_active_key(candidate: AsyncSession) -> str:
        key_id = await original_active_key(candidate)
        active_key_read.set()
        await release_mint.wait()
        return key_id

    monkeypatch.setattr(launch_sessions, "_active_token_key_id", paused_active_key)
    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def mint():
        async with sessions() as candidate:
            return await launch_sessions.issue_launch_storage_session(
                candidate,
                config.config_id,
                request,
            )

    async def activate():
        async with sessions() as candidate:
            return await key_epochs.activate_token_key_epoch(
                candidate,
                administrator_id="support-user",
                request_id=str(uuid.uuid4()),
                key_id="new-key",
            )

    mint_task = asyncio.create_task(mint())
    await asyncio.wait_for(active_key_read.wait(), timeout=10)
    activation_task = asyncio.create_task(activate())
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(activation_task), timeout=0.1)
    release_mint.set()
    (_context, minted), activated = await asyncio.wait_for(
        asyncio.gather(mint_task, activation_task),
        timeout=10,
    )
    assert activated["active_key_id"] == "new-key"

    async with sessions() as candidate:
        minted_row = await candidate.scalar(
            select(ChuteFSLaunchSession).where(
                ChuteFSLaunchSession.access_token_hash
                == launch_sessions._token_hash(minted.access_token)
            )
        )
        assert minted_row.token_key_id == "old-key"
        minted_session_id = minted_row.session_id
        assert (await candidate.get(ChuteFSTokenKeyEpoch, "old-key")).state == "retiring"
        assert (await candidate.get(ChuteFSTokenKeyEpoch, "new-key")).state == "active"

        with pytest.raises(HTTPException, match="unexpired session authority"):
            await key_epochs.retire_token_key_epoch(
                candidate,
                administrator_id="support-user",
                request_id=str(uuid.uuid4()),
                key_id="old-key",
            )
        await candidate.rollback()

    async with sessions() as candidate:
        with pytest.raises(DBAPIError, match="not database-active"):
            await candidate.execute(
                text(
                    """
                    INSERT INTO chutefs_launch_sessions(
                        session_id, config_id, instance_id,
                        rotated_from_session_id, rotated_from_session_sha256,
                        binding_id, user_id, chute_id, job_id, compute_type,
                        management_mode, server_id, volume_id, reservation_id,
                        allocation_group_id, allocation_group_generation,
                        process_incarnation, attestation_id,
                        attested_cert_pubkey_hash, allowed_operations, generation,
                        access_token_hash, refresh_token_hash, access_expires_at,
                        refresh_expires_at, rotation_request_sha256, token_seed,
                        token_key_id, response_replay_until, created_at,
                        rotated_at, revoked_at
                    )
                    SELECT :new_session_id, config_id, instance_id,
                           NULL, NULL, binding_id, user_id, chute_id, job_id,
                           compute_type, management_mode, server_id, volume_id,
                           reservation_id, allocation_group_id,
                           allocation_group_generation, process_incarnation,
                           attestation_id, attested_cert_pubkey_hash,
                           allowed_operations, generation, :access_hash,
                           :refresh_hash, access_expires_at, refresh_expires_at,
                           :request_hash, :token_seed, 'old-key',
                           response_replay_until, NOW(), NOW(), NOW()
                      FROM chutefs_launch_sessions
                     WHERE session_id = :source_session_id
                    """
                ),
                {
                    "new_session_id": f"stale-key-{uuid.uuid4().hex}",
                    "source_session_id": minted_session_id,
                    "access_hash": "1" * 64,
                    "refresh_hash": "2" * 64,
                    "request_hash": "3" * 64,
                    "token_seed": "4" * 64,
                },
            )
            await candidate.commit()
        await candidate.rollback()
