"""Real-PostgreSQL concurrency barriers for registry subject locks."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from api.host.locks import acquire_registry_subject_locks


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for registry subject-lock tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """Do not gate pure PostgreSQL lock tests on the optional GPU verifier CLI."""

    yield


@pytest_asyncio.fixture
async def postgres_sessions():
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        yield sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    finally:
        await engine.dispose()


async def _hold_subject(
    sessions,
    *,
    server_id: str,
    launch_config_id: str,
    entered: asyncio.Event,
    release: asyncio.Event,
) -> None:
    async with sessions() as db:
        await acquire_registry_subject_locks(
            db,
            server_id=server_id,
            launch_config_id=launch_config_id,
        )
        entered.set()
        await release.wait()
        await db.commit()


async def test_distinct_registry_subjects_acquire_concurrently(postgres_sessions):
    suffix = uuid.uuid4().hex
    first_entered = asyncio.Event()
    second_entered = asyncio.Event()
    release = asyncio.Event()
    tasks = [
        asyncio.create_task(
            _hold_subject(
                postgres_sessions,
                server_id=f"server-a-{suffix}",
                launch_config_id=f"config-a-{suffix}",
                entered=first_entered,
                release=release,
            )
        ),
        asyncio.create_task(
            _hold_subject(
                postgres_sessions,
                server_id=f"server-b-{suffix}",
                launch_config_id=f"config-b-{suffix}",
                entered=second_entered,
                release=release,
            )
        ),
    ]
    try:
        await asyncio.wait_for(first_entered.wait(), timeout=2)
        await asyncio.wait_for(second_entered.wait(), timeout=2)
    finally:
        release.set()
        await asyncio.gather(*tasks)


async def test_same_registry_server_serializes_postgres_transactions(
    postgres_sessions,
):
    suffix = uuid.uuid4().hex
    first_entered = asyncio.Event()
    release_first = asyncio.Event()

    first_task = asyncio.create_task(
        _hold_subject(
            postgres_sessions,
            server_id=f"server-{suffix}",
            launch_config_id=f"config-a-{suffix}",
            entered=first_entered,
            release=release_first,
        )
    )
    await asyncio.wait_for(first_entered.wait(), timeout=2)

    try:
        async with postgres_sessions() as blocked:
            await blocked.execute(text("SET LOCAL lock_timeout = '200ms'"))
            with pytest.raises(DBAPIError) as raised:
                await acquire_registry_subject_locks(
                    blocked,
                    server_id=f"server-{suffix}",
                    launch_config_id=f"config-b-{suffix}",
                )
            assert "lock timeout" in str(raised.value).lower()
            await blocked.rollback()
    finally:
        release_first.set()
        await first_task

    async with postgres_sessions() as after_release:
        await acquire_registry_subject_locks(
            after_release,
            server_id=f"server-{suffix}",
            launch_config_id=f"config-b-{suffix}",
        )
        await after_release.commit()
