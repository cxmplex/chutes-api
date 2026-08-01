"""Real-PostgreSQL inverse-interleaving barrier for API-LOCK-01."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
import uuid

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from api.host.locks import acquire_gpu_lifecycle_lock
from api.instance import util as instance_util
from api.instance.locking import prepare_instance_terminal_writes
from api.instance.schemas import Instance, LaunchConfig


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for Instance lock-order tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    yield


async def _set_search_path(db: AsyncSession, schema: str) -> None:
    await db.execute(text(f'SET LOCAL search_path TO "{schema}"'))


async def test_former_inverse_interleaving_finishes_without_deadlock():
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    schema = f"instance_lock_order_{uuid.uuid4().hex}"
    config_id = f"config-{uuid.uuid4().hex}"
    instance_id = f"instance-{uuid.uuid4().hex}"
    launch_locked = asyncio.Event()
    let_storage_lock_instance = asyncio.Event()
    terminal_pid: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async with engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        await connection.execute(
            text(
                f"""
                CREATE TABLE "{schema}".launch_configs (
                    config_id VARCHAR PRIMARY KEY,
                    failed_at TIMESTAMP,
                    completed_at TIMESTAMPTZ,
                    registry_scope_active BOOLEAN NOT NULL DEFAULT FALSE,
                    registry_scope_revoked_at TIMESTAMPTZ
                )
                """
            )
        )
        await connection.execute(
            text(
                f"""
                CREATE TABLE "{schema}".instances (
                    instance_id VARCHAR PRIMARY KEY,
                    config_id VARCHAR REFERENCES "{schema}".launch_configs(config_id)
                )
                """
            )
        )
        await connection.execute(
            text(
                f'INSERT INTO "{schema}".launch_configs '
                "(config_id, registry_scope_active) VALUES (:config_id, TRUE)"
            ),
            {"config_id": config_id},
        )
        await connection.execute(
            text(
                f'INSERT INTO "{schema}".instances (instance_id, config_id) '
                "VALUES (:instance_id, :config_id)"
            ),
            {"instance_id": instance_id, "config_id": config_id},
        )

    async def storage_writer() -> None:
        async with sessions() as db:
            await _set_search_path(db, schema)
            await acquire_gpu_lifecycle_lock(db)
            await db.execute(
                select(LaunchConfig.config_id)
                .where(LaunchConfig.config_id == config_id)
                .with_for_update(of=LaunchConfig)
            )
            launch_locked.set()
            await let_storage_lock_instance.wait()
            await db.execute(
                select(Instance.instance_id)
                .where(Instance.instance_id == instance_id)
                .with_for_update(of=Instance)
            )
            await db.commit()

    async def terminal_writer() -> None:
        await launch_locked.wait()
        async with sessions() as db:
            await _set_search_path(db, schema)
            pid = await db.scalar(text("SELECT pg_backend_pid()"))
            terminal_pid.set_result(pid)
            await prepare_instance_terminal_writes(
                db,
                [instance_id],
                complete_launch_configs=True,
            )
            await db.execute(delete(Instance).where(Instance.instance_id == instance_id))
            await db.commit()

    storage_task = asyncio.create_task(storage_writer())
    terminal_task = asyncio.create_task(terminal_writer())
    try:
        await asyncio.wait_for(launch_locked.wait(), timeout=2)
        pid = await asyncio.wait_for(terminal_pid, timeout=2)
        observed_advisory_wait = False
        async with sessions() as observer:
            for _ in range(100):
                wait_event = (
                    await observer.execute(
                        text(
                            "SELECT wait_event_type, wait_event "
                            "FROM pg_stat_activity WHERE pid = :pid"
                        ),
                        {"pid": pid},
                    )
                ).one()
                if wait_event == ("Lock", "advisory"):
                    observed_advisory_wait = True
                    break
                await asyncio.sleep(0.01)
        assert observed_advisory_wait

        # The terminal writer is fenced before it can take the Instance row.
        # The storage writer can therefore complete LaunchConfig -> Instance,
        # after which the terminal writer takes the same order and finishes.
        let_storage_lock_instance.set()
        await asyncio.wait_for(
            asyncio.gather(storage_task, terminal_task),
            timeout=5,
        )

        async with sessions() as check:
            await _set_search_path(check, schema)
            assert (
                await check.scalar(
                    select(Instance.instance_id).where(Instance.instance_id == instance_id)
                )
                is None
            )
            state = (
                await check.execute(
                    select(
                        LaunchConfig.completed_at,
                        LaunchConfig.registry_scope_active,
                        LaunchConfig.registry_scope_revoked_at,
                    ).where(LaunchConfig.config_id == config_id)
                )
            ).one()
            assert state.completed_at is not None
            assert state.registry_scope_active is False
            assert state.registry_scope_revoked_at is not None
    finally:
        let_storage_lock_instance.set()
        await asyncio.gather(storage_task, terminal_task, return_exceptions=True)
        async with engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await engine.dispose()


async def test_platform_teardown_runs_after_lifecycle_transaction_commit(monkeypatch):
    """Platform teardown must be able to take the lifecycle lock itself."""

    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    schema = f"instance_platform_teardown_{uuid.uuid4().hex}"
    config_id = f"config-{uuid.uuid4().hex}"
    instance_id = f"instance-{uuid.uuid4().hex}"
    chute_id = f"chute-{uuid.uuid4().hex}"
    teardown_locked = asyncio.Event()

    async with engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        await connection.execute(
            text(
                f"""
                CREATE TABLE "{schema}".launch_configs (
                    config_id VARCHAR PRIMARY KEY,
                    failed_at TIMESTAMP,
                    completed_at TIMESTAMPTZ,
                    registry_scope_active BOOLEAN NOT NULL DEFAULT FALSE,
                    registry_scope_revoked_at TIMESTAMPTZ
                )
                """
            )
        )
        await connection.execute(
            text(
                f"""
                CREATE TABLE "{schema}".instances (
                    instance_id VARCHAR PRIMARY KEY,
                    config_id VARCHAR REFERENCES "{schema}".launch_configs(config_id),
                    server_id VARCHAR,
                    gpu_management_mode VARCHAR
                )
                """
            )
        )
        await connection.execute(
            text(
                f"""
                CREATE TABLE "{schema}".instance_audit (
                    instance_id VARCHAR PRIMARY KEY,
                    deletion_reason TEXT
                )
                """
            )
        )
        await connection.execute(
            text(
                f'INSERT INTO "{schema}".launch_configs '
                "(config_id, registry_scope_active) VALUES (:config_id, TRUE)"
            ),
            {"config_id": config_id},
        )
        await connection.execute(
            text(
                f'INSERT INTO "{schema}".instances '
                "(instance_id, config_id, server_id, gpu_management_mode) "
                "VALUES (:instance_id, :config_id, :server_id, 'platform')"
            ),
            {
                "instance_id": instance_id,
                "config_id": config_id,
                "server_id": "server-platform",
            },
        )
        await connection.execute(
            text(f'INSERT INTO "{schema}".instance_audit (instance_id) VALUES (:instance_id)'),
            {"instance_id": instance_id},
        )

    @asynccontextmanager
    async def scoped_session(readonly: bool = False):
        assert readonly is False
        async with sessions() as db:
            await _set_search_path(db, schema)
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def no_op(*_args, **_kwargs):
        return None

    async def teardown_that_reacquires_lifecycle(info, *, message):
        assert info.instance_id == instance_id
        assert info.config_id == config_id
        assert info.server_id == "server-platform"
        assert info.gpu_management_mode == "platform"
        assert instance_id in message
        async with sessions() as db:
            await _set_search_path(db, schema)
            await asyncio.wait_for(acquire_gpu_lifecycle_lock(db), timeout=1)
            teardown_locked.set()
            await db.rollback()

    monkeypatch.setattr(instance_util, "get_session", scoped_session)
    monkeypatch.setattr(instance_util, "invalidate_instance_cache", no_op)
    monkeypatch.setattr(instance_util, "cleanup_instance_conn_tracking", no_op)
    monkeypatch.setattr(instance_util, "notify_deleted", teardown_that_reacquires_lifecycle)

    try:
        deleted = await asyncio.wait_for(
            instance_util._execute_instance_deletion(
                instance_id,
                chute_id,
                "miner-hotkey",
                "platform teardown regression",
            ),
            timeout=5,
        )
        assert deleted is True
        assert teardown_locked.is_set()

        async with sessions() as check:
            await _set_search_path(check, schema)
            assert (
                await check.scalar(
                    text("SELECT instance_id FROM instances WHERE instance_id = :instance_id"),
                    {"instance_id": instance_id},
                )
                is None
            )
            state = (
                await check.execute(
                    text(
                        "SELECT completed_at, registry_scope_active, "
                        "registry_scope_revoked_at FROM launch_configs "
                        "WHERE config_id = :config_id"
                    ),
                    {"config_id": config_id},
                )
            ).one()
            assert state.completed_at is not None
            assert state.registry_scope_active is False
            assert state.registry_scope_revoked_at is not None
            assert (
                await check.scalar(
                    text(
                        "SELECT deletion_reason FROM instance_audit "
                        "WHERE instance_id = :instance_id"
                    ),
                    {"instance_id": instance_id},
                )
                == "platform teardown regression"
            )
    finally:
        async with engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await engine.dispose()
