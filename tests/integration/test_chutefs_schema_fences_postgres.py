"""Real-helper ChuteFS schema-fence and rollback regressions."""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from api.instance.schemas import Instance, LaunchConfig
from api.server.schemas import StorageObject, StorageVolume
from api.storage import launch_sessions
from api.storage import service as storage_service
from api.user.schemas import User
from tests.integration import test_gpu_chutefs_postgres as chutefs_pg
from tests.integration import test_storage_reconciliation_postgres as storage_pg

pytest_plugins = ["tests.integration.test_storage_reconciliation_postgres"]

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for ChuteFS schema-fence tests",
    ),
]

DEFAULT_VOLUME_MIGRATION = "20260724234500_gpu_chutefs_default_volume.sql"
ROTATION_MIGRATION = "20260726121000_chutefs_session_rotation_replay.sql"
TRUST_BOUNDARY_MIGRATION = "20260806120000_api_trust_boundary_hardening.sql"


@pytest.fixture(autouse=True)
def nv_attest():
    """These database-only tests do not invoke the NVIDIA evidence verifier."""
    yield


async def _apply_up(db: AsyncSession, migration: str) -> None:
    await db.commit()
    async with db.bind.begin() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(storage_pg._migration_up_sql(migration))
    await db.rollback()


async def _rewind_trust_boundary(db: AsyncSession) -> None:
    """Restore the exact rotation-migration catalog before exercising its DOWN path."""

    await db.commit()
    async with db.bind.begin() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(
            storage_pg._migration_down_sql(TRUST_BOUNDARY_MIGRATION)
        )
    await db.rollback()


async def _run_down(
    engine,
    migration: str,
    started: asyncio.Future[int] | None = None,
) -> None:
    async with engine.connect() as connection:
        transaction = await connection.begin()
        try:
            if started is not None:
                started.set_result(await connection.scalar(text("SELECT pg_backend_pid()")))
            raw = await connection.get_raw_connection()
            await raw.driver_connection.execute(storage_pg._migration_down_sql(migration))
        except BaseException:
            await transaction.rollback()
            raise
        await transaction.commit()


async def _wait_for_database_lock(engine, pid: int) -> None:
    for _ in range(500):
        async with engine.connect() as observer:
            waiting = await observer.scalar(
                text("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"),
                {"pid": pid},
            )
        if waiting:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"backend {pid} did not block on the runtime transaction")


async def _seed_lockable_config(db: AsyncSession) -> str:
    chute = await chutefs_pg._chute(
        db,
        storage_pg.USER_ID,
        f"schema-fence-{uuid.uuid4().hex}",
    )
    config = LaunchConfig(
        config_id=f"config-{uuid.uuid4().hex}",
        seed=0,
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=storage_pg.USER_ID,
        compute_type="cpu",
        storage_session_exchange_allowed=False,
        env_type="tee",
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        failed_at=datetime.now(),
    )
    instance = Instance(
        instance_id=f"instance-{uuid.uuid4().hex}",
        host=f"192.0.2.{int(uuid.uuid4().hex[:2], 16) % 200 + 1}",
        port=8000 + int(uuid.uuid4().hex[:3], 16) % 50000,
        chute_id=chute.chute_id,
        version=chute.version,
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        active=False,
        verified=False,
        config_id=config.config_id,
    )
    db.add_all([config, instance])
    await db.commit()
    return config.config_id


async def _bootstrap_epoch(db: AsyncSession, key_id: str = "bootstrap-key") -> None:
    await db.execute(
        text(
            "INSERT INTO chutefs_token_key_epochs "
            "(key_id, key_sha256, state, required_replica_ids) "
            "VALUES (:key_id, :key_sha256, 'staged', "
            "'[\"bootstrap-replica\"]'::jsonb)"
        ),
        {"key_id": key_id, "key_sha256": "a" * 64},
    )
    await db.execute(
        text(
            "INSERT INTO chutefs_token_key_replica_acks "
            "(replica_id, key_id, key_ids, key_fingerprints, keyring_sha256) "
            "VALUES ('bootstrap-replica', CAST(:key_id AS text), "
            "jsonb_build_array(CAST(:key_id AS text)), "
            "jsonb_build_object(CAST(:key_id AS text), CAST(:fingerprint AS text)), "
            ":keyring_sha256)"
        ),
        {
            "key_id": key_id,
            "fingerprint": "a" * 64,
            "keyring_sha256": "b" * 64,
        },
    )
    await db.execute(
        text(
            "UPDATE chutefs_token_key_epochs "
            "SET state = 'active', activated_at = NOW() "
            "WHERE key_id = :key_id"
        ),
        {"key_id": key_id},
    )
    await db.commit()


async def _run_runtime_helper_across_down(
    db: AsyncSession,
    monkeypatch,
    *,
    migration: str,
    preselect_session_table: bool,
) -> BaseException:
    config_id = await _seed_lockable_config(db)
    preflight_reached = asyncio.Event()
    release_preflight = asyncio.Event()

    async def paused_revocation_preflight(_db: AsyncSession, _instance_id: str) -> None:
        preflight_reached.set()
        await release_preflight.wait()

    monkeypatch.setattr(
        launch_sessions,
        "_require_not_disabled",
        paused_revocation_preflight,
    )
    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def runtime() -> BaseException | None:
        async with sessions() as candidate:
            try:
                if preselect_session_table:
                    await candidate.execute(text("SELECT 1 FROM chutefs_launch_sessions"))
                await launch_sessions.lock_launch_storage_configurations(
                    candidate,
                    [config_id],
                )
            except BaseException as exc:
                await candidate.rollback()
                return exc
        return None

    runtime_task = asyncio.create_task(runtime())
    await asyncio.wait_for(preflight_reached.wait(), timeout=10)
    down_started = asyncio.get_running_loop().create_future()
    down_task = asyncio.create_task(_run_down(db.bind, migration, down_started))
    down_pid = await asyncio.wait_for(down_started, timeout=10)
    await _wait_for_database_lock(db.bind, down_pid)
    release_preflight.set()
    runtime_result, _down_result = await asyncio.wait_for(
        asyncio.gather(runtime_task, down_task),
        timeout=10,
    )
    assert isinstance(runtime_result, BaseException)
    assert "deadlock detected" not in str(runtime_result).lower()
    return runtime_result


async def test_default_down_does_not_invert_real_helper_preflight(pg_session, monkeypatch):
    db, _redis = pg_session
    await _apply_up(db, DEFAULT_VOLUME_MIGRATION)

    await _run_runtime_helper_across_down(
        db,
        monkeypatch,
        migration=DEFAULT_VOLUME_MIGRATION,
        preselect_session_table=False,
    )


async def test_rotation_down_accepts_bootstrap_and_does_not_invert_real_helper(
    pg_session,
    monkeypatch,
):
    db, _redis = pg_session
    await _rewind_trust_boundary(db)
    await _bootstrap_epoch(db)

    await _run_runtime_helper_across_down(
        db,
        monkeypatch,
        migration=ROTATION_MIGRATION,
        preselect_session_table=True,
    )


async def test_rotation_down_rejects_nonbootstrap_history_without_catalog_damage(
    pg_session,
):
    db, _redis = pg_session
    await _rewind_trust_boundary(db)
    await _bootstrap_epoch(db)
    await db.execute(
        text(
            "INSERT INTO chutefs_token_key_epochs "
            "(key_id, predecessor_key_id, key_sha256, state, required_replica_ids) "
            "VALUES ('successor-key', 'bootstrap-key', repeat('c', 64), 'staged', "
            "'[\"bootstrap-replica\"]'::jsonb)"
        )
    )
    await db.commit()

    with pytest.raises(Exception, match="after it has been used"):
        await _run_down(db.bind, ROTATION_MIGRATION)

    assert await db.scalar(text("SELECT count(*) FROM chutefs_token_key_epochs")) == 2
    assert (
        await db.scalar(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'chutefs_launch_sessions' "
                "AND column_name = 'token_key_id'"
            )
        )
        == 1
    )
    assert await db.scalar(text("SELECT to_regclass('chutefs_token_key_replica_acks') IS NOT NULL"))


async def test_helper_rejects_pending_orm_writes_before_preflight_autoflush(pg_session):
    db, _redis = pg_session
    config_id = await _seed_lockable_config(db)
    user = await db.get(User, storage_pg.USER_ID)
    original_username = user.username
    user.username = f"p-{uuid.uuid4().hex[:8]}"

    with pytest.raises(RuntimeError, match="no pending ORM writes"):
        await launch_sessions.lock_launch_storage_configurations(db, [config_id])
    await db.rollback()

    db.expire_all()
    persisted_username = await db.scalar(
        select(User.username).where(User.user_id == storage_pg.USER_ID)
    )
    assert persisted_username == original_username


async def test_object_generation_grants_are_exact_and_durably_revocable(pg_session):
    db, _redis = pg_session
    await _apply_up(db, ROTATION_MIGRATION)
    await _apply_up(db, TRUST_BOUNDARY_MIGRATION)
    volume = await storage_pg._volume(db, replication_factor=1)
    generation = await storage_pg._object(
        db,
        volume,
        f"grant-generation-{uuid.uuid4().hex}",
    )
    volume_id = volume.volume_id
    object_id = generation.object_id
    generation_id = generation.generation
    object_key = generation.object_key
    other_generation = await storage_pg._object(
        db,
        volume,
        f"grant-cross-object-{uuid.uuid4().hex}",
    )

    grant = await storage_service.issue_grant(
        db,
        storage_pg.USER_ID,
        volume_id,
        ["put"],
        object_id=object_id,
        generation=generation_id,
    )
    verified = await storage_service.verify_grant(
        grant,
        volume_id,
        "put",
        object_id=object_id,
        generation=generation_id,
        db=db,
    )
    assert verified is not None
    assert verified["object_id"] == object_id
    assert verified["generation"] == generation_id
    assert verified["revocation_epoch"] == 0
    assert (
        await storage_service.verify_grant(
            grant,
            volume_id,
            "put",
            object_id=object_id,
            generation="different-generation",
            db=db,
        )
        is None
    )
    assert (
        await storage_service.verify_grant(
            grant,
            volume_id,
            "put",
            object_id=other_generation.object_id,
            generation=other_generation.generation,
            db=db,
        )
        is None
    )

    assert (
        await storage_service.revoke_volume_grants(
            db,
            volume_id,
            storage_pg.USER_ID,
        )
        == 1
    )
    assert (
        await storage_service.verify_grant(
            grant,
            volume_id,
            "put",
            object_id=object_id,
            generation=generation_id,
            db=db,
        )
        is None
    )

    with pytest.raises(DBAPIError, match="cannot decrease"):
        await db.execute(
            update(StorageVolume)
            .where(StorageVolume.volume_id == volume_id)
            .values(grant_revocation_epoch=0)
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError, match="generation is immutable"):
        await db.execute(
            update(StorageObject)
            .where(StorageObject.object_id == object_id)
            .values(generation="mutated-generation")
        )
        await db.commit()
    await db.rollback()

    replacement_grant = await storage_service.issue_grant(
        db,
        storage_pg.USER_ID,
        volume_id,
        ["put"],
        object_id=object_id,
        generation=generation_id,
    )
    volume = await db.get(StorageVolume, volume_id)
    await storage_service.delete_object(db, volume, object_key)
    await db.refresh(volume)
    assert volume.grant_revocation_epoch == 2
    assert (
        await storage_service.verify_grant(
            replacement_grant,
            volume_id,
            "put",
            object_id=object_id,
            generation=generation_id,
            db=db,
        )
        is None
    )

    list_grant = await storage_service.issue_grant(
        db,
        storage_pg.USER_ID,
        volume_id,
        ["list"],
    )
    await storage_service.delete_volume(db, volume_id, storage_pg.USER_ID)
    await db.refresh(volume)
    assert volume.deleted is True
    assert volume.grant_revocation_epoch == 3
    assert (
        await storage_service.verify_grant(
            list_grant,
            volume_id,
            "list",
            db=db,
        )
        is None
    )
