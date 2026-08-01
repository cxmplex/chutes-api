"""Execution-faithful Redis lease and PostgreSQL host-capacity barriers."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from redis.asyncio import Redis
from sqlalchemy import text

import api.cpu_scheduler as cpu_scheduler
from api.server.schemas import Host
from tests.integration import test_releases_postgres as releases_pg

pytest_plugins = ["tests.integration.test_releases_postgres"]

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
TEST_REDIS_URL = os.getenv("TEST_REDIS_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for scheduler lease tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """This DB/Redis-only module does not require the external attestation CLI."""
    yield


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
    raise AssertionError(f"backend {pid} never blocked on the Host row")


async def test_locked_capacity_refreshes_cached_host_after_concurrent_commit(
    postgres_schema,
    monkeypatch,
):
    """A stale identity-map Host must block, refresh, and observe exhausted capacity."""

    session_factory, _schema = postgres_schema

    async def no_global_lock(_session):
        return None

    # Isolate the Host-row barrier. Production acquires the lifecycle advisory lock immediately
    # before this row lock; the unit regression separately pins that ordering.
    monkeypatch.setattr(
        cpu_scheduler,
        "acquire_gpu_lifecycle_lock",
        no_global_lock,
    )
    host_id = f"scheduler-capacity-{uuid.uuid4().hex}"
    async with session_factory() as first, session_factory() as second:
        host = releases_pg._host(host_id)
        host.capacity = 1
        first.add(host)
        await first.commit()

        cached = await second.get(Host, host_id)
        assert cached is not None and cached.capacity == 1

        locked = await cpu_scheduler._lock_host_with_capacity(first, host_id)
        assert locked is not None and locked.capacity == 1
        locked.capacity = 0
        await first.flush()

        second_pid = await second.scalar(text("SELECT pg_backend_pid()"))
        contender = asyncio.create_task(cpu_scheduler._lock_host_with_capacity(second, host_id))
        await _wait_for_database_lock(first.bind, second_pid)
        assert not contender.done()

        await first.commit()
        assert await contender is None
        assert cached.capacity == 0
        await second.rollback()


@pytest.mark.skipif(
    not TEST_REDIS_URL,
    reason="TEST_REDIS_URL is required for scheduler lease tests",
)
async def test_real_redis_old_owner_cannot_release_or_renew_successor():
    """Execute the production Lua through the A-expire/B-acquire/A-release race."""

    client = Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    key = f"cpu-scheduler-lease-test:{uuid.uuid4().hex}"
    owner_a = f"owner-a-{uuid.uuid4().hex}"
    owner_b = f"owner-b-{uuid.uuid4().hex}"
    try:
        assert await client.set(key, owner_a, nx=True, px=25)
        for _ in range(200):
            if await client.get(key) is None:
                break
            await asyncio.sleep(0.01)
        assert await client.get(key) is None

        assert await client.set(key, owner_b, nx=True, ex=5)
        released = await client.eval(
            cpu_scheduler.SCHEDULER_LOCK_RELEASE_SCRIPT,
            1,
            key,
            owner_a,
        )
        assert released == 0
        assert await client.get(key) == owner_b

        stale_renewal = await client.eval(
            cpu_scheduler.SCHEDULER_LOCK_RENEW_SCRIPT,
            1,
            key,
            owner_a,
            30,
        )
        assert stale_renewal == 0
        assert await client.get(key) == owner_b

        renewed = await client.eval(
            cpu_scheduler.SCHEDULER_LOCK_RENEW_SCRIPT,
            1,
            key,
            owner_b,
            30,
        )
        assert renewed == 1
        assert 20 <= await client.ttl(key) <= 30
    finally:
        await client.delete(key)
        await client.aclose()
