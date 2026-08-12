"""Real-PostgreSQL release-create request identity and crash/replay tests."""

from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.database import Base
from api.releases import service as release_service
from api.releases.schemas import (
    RELEASE_STATUS_ACTIVE,
    RELEASE_STATUS_DRAFT,
    CreateReleaseRequest,
    GuestRelease,
    ReleaseImage,
)


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
MIGRATION_NAME = "20260811120000_guest_release_request_idempotency.sql"
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for release idempotency PostgreSQL tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """Release-create tests do not invoke the external GPU verifier."""

    yield


@pytest_asyncio.fixture
async def postgres_schema():
    schema = f"release_request_{uuid.uuid4().hex}"
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
    try:
        yield sessionmaker(engine, class_=AsyncSession, expire_on_commit=False), schema
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def _apply_sql_migration(
    schema: str,
    *,
    direction: str = "up",
    expect_success: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    migration = Path(__file__).resolve().parents[2] / "api/migrations" / MIGRATION_NAME
    up_sql, down_sql = migration.read_text(encoding="utf-8").split("-- migrate:down", 1)
    sql = up_sql if direction == "up" else down_sql
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    connection_url = (
        f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    )
    process = await asyncio.create_subprocess_exec(
        "psql",
        connection_url,
        "-v",
        "ON_ERROR_STOP=1",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "PGPASSWORD": parsed.password or "",
            "PGOPTIONS": f"-c search_path={schema}",
        },
    )
    stdout, stderr = await process.communicate(sql.encode())
    completed = subprocess.CompletedProcess(
        ["psql"],
        process.returncode,
        stdout,
        stderr,
    )
    if expect_success:
        assert process.returncode == 0, (stdout + stderr).decode(errors="replace")
    else:
        assert process.returncode != 0
    return completed


def _request(
    *, activate: bool = False, notes: str | None = None
) -> CreateReleaseRequest:
    return CreateReleaseRequest(
        tee_type="sev-snp",
        compute_type="cpu",
        channel="idempotency-dev",
        chute=ReleaseImage(
            url="https://artifacts.chutes.ai/releases/idempotency-test.qcow2",
            sha256="a" * 64,
            debug=False,
            version="1.0.0",
            measurement_names=["cpu-baremetal-snp-genoa-1.0.0-1vcpu"],
            provenance_payload='{"rebuild_sha256":"' + "b" * 64 + '"}',
            provenance_signature="publisher-signature",
        ),
        notes=notes,
        activate=activate,
    )


async def test_concurrent_duplicate_requests_commit_one_exact_release(postgres_schema):
    sessions, _schema = postgres_schema
    request = _request()
    request_sha256 = request.canonical_sha256()

    async def create_once() -> str:
        async with sessions() as session:
            release = await release_service.create_release(
                session,
                request,
                request_sha256,
            )
            return release.release_id

    release_ids = await asyncio.gather(*(create_once() for _ in range(8)))
    assert len(set(release_ids)) == 1

    async with sessions() as check:
        rows = (
            (
                await check.execute(
                    select(GuestRelease).where(
                        GuestRelease.release_request_sha256 == request_sha256,
                    )
                )
            )
            .scalars()
            .all()
        )
        count = await check.scalar(select(func.count()).select_from(GuestRelease))
    assert count == 1
    assert len(rows) == 1
    assert rows[0].release_id == release_ids[0]
    assert rows[0].status == RELEASE_STATUS_DRAFT


async def test_retry_after_post_commit_crash_resumes_original_activation(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    request = _request(activate=True)
    request_sha256 = request.canonical_sha256()

    with patch.object(
        release_service,
        "activate_release",
        AsyncMock(side_effect=RuntimeError("simulated response-path crash")),
    ):
        async with sessions() as first:
            with pytest.raises(RuntimeError, match="simulated response-path crash"):
                await release_service.create_release(first, request, request_sha256)

    async with sessions() as check:
        persisted = (
            await check.execute(
                select(GuestRelease).where(
                    GuestRelease.release_request_sha256 == request_sha256,
                )
            )
        ).scalar_one()
        persisted_release_id = persisted.release_id
        assert persisted.status == RELEASE_STATUS_DRAFT

    async def finish_activation(db: AsyncSession, release_id: str) -> GuestRelease:
        release = await db.get(GuestRelease, release_id, with_for_update=True)
        assert release is not None
        release.status = RELEASE_STATUS_ACTIVE
        release.activated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(release)
        return release

    with patch.object(
        release_service, "activate_release", side_effect=finish_activation
    ) as resume:
        async with sessions() as retry:
            result = await release_service.create_release(
                retry, request, request_sha256
            )

    assert result.release_id == persisted_release_id
    assert result.status == RELEASE_STATUS_ACTIVE
    resume.assert_awaited_once_with(retry, persisted_release_id)

    # A response-loss retry after activation returns the exact row without invoking activation again.
    with patch.object(
        release_service, "activate_release", AsyncMock()
    ) as no_reactivation:
        async with sessions() as replay:
            replayed = await release_service.create_release(
                replay, request, request_sha256
            )
    assert replayed.release_id == persisted_release_id
    assert replayed.status == RELEASE_STATUS_ACTIVE
    no_reactivation.assert_not_awaited()


async def test_same_request_key_with_different_canonical_payload_fails_closed(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    original = _request(notes="first canonical request")
    request_sha256 = original.canonical_sha256()
    async with sessions() as create:
        created = await release_service.create_release(create, original, request_sha256)

    conflicting = _request(notes="different canonical request")
    async with sessions() as replay:
        with pytest.raises(
            release_service.ReleaseRequestConflict, match="does not match"
        ):
            await release_service.create_release(replay, conflicting, request_sha256)

    async with sessions() as check:
        releases = (await check.execute(select(GuestRelease))).scalars().all()
    assert [release.release_id for release in releases] == [created.release_id]


async def test_superseded_replay_never_reactivates_old_exact_release(postgres_schema):
    sessions, _schema = postgres_schema
    request = _request(activate=True)
    request_sha256 = request.canonical_sha256()
    async with sessions() as setup:
        release = GuestRelease(
            channel=request.channel,
            tee_type=request.tee_type,
            compute_type=request.compute_type,
            status="superseded",
            images={},
            release_request_sha256=request_sha256,
        )
        setup.add(release)
        await setup.commit()
        release_id = release.release_id

    with patch.object(
        release_service, "activate_release", AsyncMock()
    ) as no_reactivation:
        async with sessions() as replay:
            result = await release_service.create_release(
                replay, request, request_sha256
            )
    assert result.release_id == release_id
    assert result.status == "superseded"
    no_reactivation.assert_not_awaited()


async def test_migration_preserves_old_rows_and_enforces_unique_immutable_identity():
    schema = f"release_request_migration_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            await connection.execute(
                text(
                    f'CREATE TABLE "{schema}".guest_releases '
                    "(release_id VARCHAR PRIMARY KEY)"
                )
            )
            await connection.execute(
                text(
                    f"INSERT INTO \"{schema}\".guest_releases VALUES ('legacy-release')"
                )
            )

        await _apply_sql_migration(schema)
        await _apply_sql_migration(schema)
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )
        try:
            async with engine.begin() as connection:
                legacy_identity = await connection.scalar(
                    text(
                        "SELECT release_request_sha256 FROM guest_releases "
                        "WHERE release_id = 'legacy-release'"
                    )
                )
                assert legacy_identity is None
                await connection.execute(
                    text(
                        "INSERT INTO guest_releases (release_id, release_request_sha256) "
                        "VALUES ('qualified-release', :identity)"
                    ),
                    {"identity": "a" * 64},
                )

            with pytest.raises(IntegrityError):
                async with engine.begin() as connection:
                    await connection.execute(
                        text(
                            "INSERT INTO guest_releases (release_id, release_request_sha256) "
                            "VALUES ('duplicate-release', :identity)"
                        ),
                        {"identity": "a" * 64},
                    )
            with pytest.raises(DBAPIError, match="identity is immutable"):
                async with engine.begin() as connection:
                    await connection.execute(
                        text(
                            "UPDATE guest_releases SET release_request_sha256 = :identity "
                            "WHERE release_id = 'qualified-release'"
                        ),
                        {"identity": "b" * 64},
                    )
            with pytest.raises(IntegrityError):
                async with engine.begin() as connection:
                    await connection.execute(
                        text(
                            "INSERT INTO guest_releases (release_id, release_request_sha256) "
                            "VALUES ('malformed-release', 'ABC')"
                        )
                    )

            failed_down = await _apply_sql_migration(
                schema,
                direction="down",
                expect_success=False,
            )
            assert b"cannot downgrade" in failed_down.stderr

            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM guest_releases WHERE release_id = 'qualified-release'"
                    )
                )
            await _apply_sql_migration(schema, direction="down")
            async with engine.begin() as connection:
                column_count = await connection.scalar(
                    text(
                        "SELECT COUNT(*) FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'guest_releases' "
                        "AND column_name = 'release_request_sha256'"
                    )
                )
            assert column_count == 0
        finally:
            await engine.dispose()
    finally:
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()
