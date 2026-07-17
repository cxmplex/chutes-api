"""Real-Postgres serialization tests for TEE maintenance admission."""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.chute.schemas import Chute
from api.config import settings
from api.database import Base
from api.instance.schemas import Instance
from api.metagraph import MetagraphNode
from api.server import service
from api.server.schemas import (
    ReplicaPlacement,
    Server,
    StorageObject,
    StorageVolume,
    TeeUpgradeWindow,
)
from api.user.schemas import User


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real-Postgres maintenance tests",
    ),
]

WINDOW_ID = "maintenance-concurrency-window"
TARGET_VERSION = "2.0.0"
OLD_VERSION = "1.0.0"


@pytest.fixture(autouse=True)
def nv_attest():
    """Maintenance tests do not invoke the external GPU-attestation CLI."""
    yield


@pytest_asyncio.fixture
async def postgres_schema():
    schema = f"maintenance_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        connect_args={"server_settings": {"search_path": schema}},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        yield sessions
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


def _server(
    server_id: str,
    miner_hotkey: str,
    ordinal: int,
    *,
    storage_role: bool = False,
) -> Server:
    incarnation = str(uuid.uuid4()) if storage_role else None
    cert_hash = hashlib.sha256(f"cert:{server_id}".encode()).hexdigest() if storage_role else None
    return Server(
        server_id=server_id,
        ip=f"10.40.0.{ordinal}",
        miner_hotkey=miner_hotkey,
        name=server_id,
        netuid=settings.netuid,
        is_tee=True,
        compute_type="cpu",
        tee_type="sev-snp",
        self_registered=True,
        version=OLD_VERSION,
        host_id=f"host-{server_id}" if storage_role else None,
        storage_role=storage_role,
        storage_incarnation=incarnation,
        attested_cert_pubkey_hash=cert_hash,
    )


async def _seed_window_and_servers(
    sessions,
    servers: list[Server],
    *,
    limit: int,
) -> None:
    now = datetime.now(timezone.utc)
    async with sessions() as db:
        seen_miners: set[str] = set()
        for ordinal, server in enumerate(servers, start=1):
            if server.miner_hotkey in seen_miners:
                continue
            seen_miners.add(server.miner_hotkey)
            db.add(
                MetagraphNode(
                    hotkey=server.miner_hotkey,
                    netuid=settings.netuid,
                    checksum="maintenance-test",
                    coldkey=f"coldkey-{ordinal}",
                    node_id=ordinal,
                )
            )
        db.add(
            TeeUpgradeWindow(
                id=WINDOW_ID,
                upgrade_window_start=now - timedelta(hours=1),
                upgrade_window_end=now + timedelta(hours=1),
                target_measurement_version=TARGET_VERSION,
                max_concurrent_per_miner=limit,
            )
        )
        db.add_all(servers)
        await db.commit()


async def _run_queued_confirmations(sessions, attempts: list[tuple[str, str]]):
    """Queue every contender behind the same real PostgreSQL row lock, then release them."""
    blocker = sessions()
    await blocker.begin()
    await blocker.execute(
        select(TeeUpgradeWindow).where(TeeUpgradeWindow.id == WINDOW_ID).with_for_update()
    )

    backend_pids: asyncio.Queue[int] = asyncio.Queue()

    async def attempt(server_id: str, miner_hotkey: str):
        async with sessions() as db:
            server = await db.get(Server, server_id)
            backend_pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            await backend_pids.put(int(backend_pid))
            try:
                return await service.confirm_maintenance(db, server, miner_hotkey)
            except HTTPException as exc:
                return exc

    tasks = [asyncio.create_task(attempt(server_id, miner)) for server_id, miner in attempts]
    pids = [await backend_pids.get() for _ in tasks]
    pid_list = ", ".join(str(pid) for pid in pids)
    observed_waiters = False
    try:
        for _ in range(200):
            waiting = (
                await blocker.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity "
                        f"WHERE pid IN ({pid_list}) AND wait_event_type = 'Lock'"
                    )
                )
            ).scalar_one()
            if waiting == len(tasks):
                observed_waiters = True
                break
            await asyncio.sleep(0.01)
    finally:
        await blocker.commit()
        await blocker.close()

    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert observed_waiters, "confirmation contenders did not queue on the PostgreSQL window lock"
    unexpected = [
        result
        for result in results
        if isinstance(result, BaseException) and not isinstance(result, HTTPException)
    ]
    assert unexpected == []
    return results


def _split_results(results):
    accepted = [result for result in results if not isinstance(result, HTTPException)]
    rejected = [result for result in results if isinstance(result, HTTPException)]
    return accepted, rejected


def _denial_reasons(exc: HTTPException) -> set[str]:
    return {item["reason"] for item in exc.detail["denial_reasons"]}


async def test_concurrent_confirmations_enforce_per_miner_limit(postgres_schema):
    miner = "maintenance-cap-miner"
    servers = [
        _server("maintenance-cap-a", miner, 1),
        _server("maintenance-cap-b", miner, 2),
    ]
    await _seed_window_and_servers(postgres_schema, servers, limit=1)

    results = await _run_queued_confirmations(
        postgres_schema,
        [(server.server_id, miner) for server in servers],
    )

    accepted, rejected = _split_results(results)
    assert len(accepted) == 1
    assert len(rejected) == 1
    assert rejected[0].status_code == 409
    assert "concurrency_cap" in _denial_reasons(rejected[0])
    async with postgres_schema() as db:
        pending = (
            (
                await db.execute(
                    select(Server.server_id).where(
                        Server.maintenance_pending_window_id == WINDOW_ID
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(pending) == 1


async def test_concurrent_confirmations_preserve_sole_chute_survivor(postgres_schema, monkeypatch):
    servers = [
        _server("maintenance-chute-a", "maintenance-chute-miner-a", 1),
        _server("maintenance-chute-b", "maintenance-chute-miner-b", 2),
    ]
    await _seed_window_and_servers(postgres_schema, servers, limit=2)

    user_id = "maintenance-chute-user"
    chute_id = "maintenance-shared-chute"
    async with postgres_schema() as db:
        await db.execute(
            User.__table__.insert().values(
                user_id=user_id,
                username="maintenance-chute-user",
                coldkey="maintenance-chute-coldkey",
                fingerprint_hash=uuid.uuid4().hex,
            )
        )
        await db.execute(
            Chute.__table__.insert().values(
                chute_id=chute_id,
                user_id=user_id,
                name="maintenance-shared-chute",
                cords=[],
                node_selector={},
                code="pass\n",
                filename="main.py",
                ref_str="main:chute",
            )
        )
        for ordinal, server in enumerate(servers, start=1):
            db.add(
                Instance(
                    instance_id=f"maintenance-instance-{ordinal}",
                    host=f"10.50.0.{ordinal}",
                    port=8000,
                    chute_id=chute_id,
                    version="1",
                    miner_uid=ordinal,
                    miner_hotkey=server.miner_hotkey,
                    miner_coldkey=f"coldkey-{ordinal}",
                    active=True,
                    verified=True,
                    server_id=server.server_id,
                )
            )
        await db.commit()

    async def skip_post_commit_notifications(*_args, **_kwargs):
        return None

    # Purge transport uses the application's global session. The admission, rows, locks, and
    # survivor predicate remain real PostgreSQL operations in the isolated test schema.
    monkeypatch.setattr(service, "purge_and_notify", skip_post_commit_notifications)
    results = await _run_queued_confirmations(
        postgres_schema,
        [(server.server_id, server.miner_hotkey) for server in servers],
    )

    accepted, rejected = _split_results(results)
    assert len(accepted) == 1
    assert len(rejected) == 1
    assert rejected[0].status_code == 409
    assert "sole_survivor" in _denial_reasons(rejected[0])
    async with postgres_schema() as db:
        available = (
            await db.execute(
                select(func.count())
                .select_from(Instance)
                .join(Server, Server.server_id == Instance.server_id)
                .where(
                    Instance.chute_id == chute_id,
                    Instance.active.is_(True),
                    Server.maintenance_pending_window_id.is_(None),
                )
            )
        ).scalar_one()
    assert available == 1


async def _seed_storage_object(
    sessions,
    servers: list[Server],
    *,
    replication_factor: int,
) -> None:
    user_id = "maintenance-storage-user"
    volume_id = "maintenance-storage-volume"
    object_id = "maintenance-storage-object"
    ciphertext_sha256 = "a" * 64
    ciphertext_size = 4096
    now = datetime.now(timezone.utc)

    async with sessions() as db:
        await db.execute(
            User.__table__.insert().values(
                user_id=user_id,
                username="maintenance-storage-user",
                coldkey="maintenance-storage-coldkey",
                fingerprint_hash=uuid.uuid4().hex,
            )
        )
        db.add(
            StorageVolume(
                volume_id=volume_id,
                user_id=user_id,
                name="maintenance-storage-volume",
                replication_factor=replication_factor,
                used_bytes=1,
            )
        )
        db.add(
            StorageObject(
                object_id=object_id,
                volume_id=volume_id,
                object_key="object.bin",
                lifecycle_state="committed",
                size_bytes=1,
                projected_size_bytes=1,
                ciphertext_size_bytes=ciphertext_size,
                sha256=ciphertext_sha256,
                durability_state="healthy",
                durable_replica_count=len(servers),
                committed_at=now,
            )
        )
        for ordinal, server in enumerate(servers, start=1):
            db.add(
                ReplicaPlacement(
                    placement_id=f"maintenance-placement-{ordinal}",
                    object_id=object_id,
                    server_id=server.server_id,
                    status="present",
                    confirmed_at=now,
                    storage_incarnation=server.storage_incarnation,
                    target_cert_pubkey_hash=server.attested_cert_pubkey_hash,
                    proof_sha256=ciphertext_sha256,
                    proof_size_bytes=ciphertext_size,
                    proof_mode="direct_upload",
                    proof_at=now,
                )
            )
        await db.commit()


@pytest.mark.parametrize(
    ("replication_factor", "holder_count"),
    [(1, 2), (2, 3)],
    ids=["last-replica", "required-replicas"],
)
async def test_concurrent_storage_confirmations_preserve_required_replicas(
    postgres_schema,
    replication_factor,
    holder_count,
):
    servers = [
        _server(
            f"maintenance-storage-{ordinal}",
            f"maintenance-storage-miner-{ordinal}",
            ordinal,
            storage_role=True,
        )
        for ordinal in range(1, holder_count + 1)
    ]
    await _seed_window_and_servers(postgres_schema, servers, limit=2)
    await _seed_storage_object(
        postgres_schema,
        servers,
        replication_factor=replication_factor,
    )

    results = await _run_queued_confirmations(
        postgres_schema,
        [
            (servers[0].server_id, servers[0].miner_hotkey),
            (servers[1].server_id, servers[1].miner_hotkey),
        ],
    )

    accepted, rejected = _split_results(results)
    assert len(accepted) == 1
    assert len(rejected) == 1
    assert rejected[0].status_code == 409
    assert "storage_durability" in _denial_reasons(rejected[0])
    storage_reason = next(
        item
        for item in rejected[0].detail["denial_reasons"]
        if item["reason"] == "storage_durability"
    )
    assert storage_reason["blocking"] == [
        {
            "object_id": "maintenance-storage-object",
            "volume_id": "maintenance-storage-volume",
            "remaining_replicas": replication_factor - 1,
            "required_replicas": replication_factor,
        }
    ]

    async with postgres_schema() as db:
        available_holders = (
            await db.execute(
                select(func.count())
                .select_from(Server)
                .where(
                    Server.storage_role.is_(True),
                    Server.maintenance_pending_window_id.is_(None),
                )
            )
        ).scalar_one()
    assert available_holders == replication_factor
