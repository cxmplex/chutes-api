"""Real-Postgres seedless Model-B migration and concurrency tests."""

from __future__ import annotations

import asyncio
import base64
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.database import Base
from api.host.reservations import (
    LaunchReservationError,
    consume_launch_reservation,
    create_launch_reservation,
    resolve_launch_reservation,
)
from api.host.schemas import (
    EnrollmentVoucherMintRequestV1,
    HostEnrollmentVoucher,
    HostKeyGeneration,
    TdLaunchReservation,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.host.service import mint_enrollment_voucher
from api.metagraph import MetagraphNode
from api.releases import service as release_service
from api.releases.schemas import GuestRelease, GuestReleaseTarget
from api.server.schemas import Host

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real-Postgres seedless tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """Seedless control-plane tests do not invoke the external GPU verifier."""
    yield


@pytest_asyncio.fixture
async def postgres_schema():
    schema = f"seedless_{uuid.uuid4().hex}"
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
        yield (
            sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
            schema,
        )
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


def _host(host_id: str) -> Host:
    return Host(
        host_id=host_id,
        name=host_id,
        miner_hotkey="owner",
        netuid=64,
        tee_type="tdx",
        capacity=2,
        storage_enabled=True,
        release_channel="seedless",
        provisioning_state="ready",
        enrollment_generation=1,
        active_key_generation=1,
        enrolled_at=datetime.now(timezone.utc),
    )


def _host_key(host_id: str) -> HostKeyGeneration:
    return HostKeyGeneration(
        host_id=host_id,
        generation=1,
        enrollment_generation=1,
        ed25519_public_key=base64.b64encode(b"e" * 32).decode(),
        ed25519_fingerprint="1" * 64,
        x25519_public_key=base64.b64encode(b"x" * 32).decode(),
        x25519_fingerprint="2" * 64,
    )


def _release(release_id: str, status: str = "active") -> GuestRelease:
    return GuestRelease(
        release_id=release_id,
        channel="seedless",
        tee_type="tdx",
        status=status,
        images={
            "chute": {
                "sha256": "a" * 64,
                "version": "1.10.0",
                "measurement_names": ["cpu-baremetal-tdx-1.10.0-2vcpu-8g"],
            }
        },
    )


async def test_seedless_schema_contains_durable_security_state(postgres_schema):
    sessions, _schema = postgres_schema
    async with sessions() as session:
        tables = {
            row[0]
            for row in (
                await session.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = current_schema()"
                    )
                )
            ).all()
        }
    assert {
        "host_enrollment_vouchers",
        "host_key_generations",
        "host_enrollment_challenges",
        "host_pcs_mailboxes",
        "td_launch_reservations",
        "registry_sessions",
    }.issubset(tables)


async def test_concurrent_release_activation_keeps_one_active(postgres_schema):
    sessions, _schema = postgres_schema
    async with sessions() as setup:
        setup.add_all([_release("release-a", "draft"), _release("release-b", "draft")])
        await setup.commit()

    async def activate(release_id: str):
        async with sessions() as session:
            with (
                patch.object(
                    release_service,
                    "_validate_l0_bootstrap",
                    AsyncMock(),
                ),
                patch.object(release_service, "_validate_image_provenance"),
            ):
                return await release_service.activate_release(session, release_id)

    await asyncio.gather(activate("release-a"), activate("release-b"))
    async with sessions() as check:
        active = (
            (await check.execute(select(GuestRelease).where(GuestRelease.status == "active")))
            .scalars()
            .all()
        )
    assert len(active) == 1


async def test_activation_captures_targets_without_legacy_bearer_tokens(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    async with sessions() as setup:
        host = _host("host-target")
        setup.add(host)
        setup.add(_release("release-target", "draft"))
        await setup.flush()
        setup.add(_host_key(host.host_id))
        await setup.commit()
    async with sessions() as session:
        with (
            patch.object(
                release_service,
                "_validate_l0_bootstrap",
                AsyncMock(),
            ),
            patch.object(release_service, "_validate_image_provenance"),
        ):
            await release_service.activate_release(session, "release-target")
    async with sessions() as check:
        targets = (
            (
                await check.execute(
                    select(GuestReleaseTarget).where(
                        GuestReleaseTarget.release_id == "release-target"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert [(target.host_id, target.role) for target in targets] == [("host-target", "chute")]
    assert targets[0].current_token_id.startswith("audit:")


async def test_launch_reservation_concurrent_replay_allows_one_consumer(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    async with sessions() as setup:
        setup.add(
            MetagraphNode(
                hotkey="owner",
                netuid=64,
                checksum="checksum",
                coldkey="coldkey",
            )
        )
        host = _host("host-reservation")
        setup.add(host)
        setup.add(_release("release-reservation"))
        await setup.flush()
        setup.add(_host_key(host.host_id))
        reservation, token = await create_launch_reservation(
            setup,
            host,
            role="chute",
            server_id="chute-process1",
            process_incarnation="process1",
            profile_id="cpu-baremetal-tdx-1.10.0-2vcpu-8g",
            chute_id="chute-1",
            container_repository="owner/image",
            container_manifest_digest=f"sha256:{'b' * 64}",
        )
        claims = reservation.claims
        await setup.commit()

    commitment = TdQuoteCommitmentV1(
        reservation_sha256=canonical_sha256(claims),
        launch_nonce=claims["launch_nonce"],
        attested_spki_sha256="3" * 64,
        release_target_sha256=claims["release_target_sha256"],
        boot_generation=claims["boot_generation"],
    )

    async def consume(attestation_id: str):
        async with sessions() as session:
            try:
                row, _claims = await resolve_launch_reservation(session, token, commitment)
                await asyncio.sleep(0.05)
                consume_launch_reservation(
                    row,
                    attestation_id=attestation_id,
                    cert_pubkey_hash="3" * 64,
                )
                await session.commit()
                return "consumed"
            except LaunchReservationError:
                await session.rollback()
                return "rejected"

    outcomes = await asyncio.gather(consume("attestation-a"), consume("attestation-b"))
    assert sorted(outcomes) == ["consumed", "rejected"]
    async with sessions() as check:
        row = await check.get(TdLaunchReservation, claims["reservation_id"])
        assert row.consumed_at is not None
        assert row.consumed_attestation_id in {"attestation-a", "attestation-b"}


async def test_concurrent_voucher_minting_uses_monotonic_generations(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    request = EnrollmentVoucherMintRequestV1(
        host_id="host-voucher",
        tee_type="tdx",
        channel="seedless",
    )

    async def mint():
        async with sessions() as session:
            return await mint_enrollment_voucher(session, "owner", request)

    first, second = await asyncio.gather(mint(), mint())
    assert {
        first.claims.enrollment_generation,
        second.claims.enrollment_generation,
    } == {1, 2}
    async with sessions() as check:
        rows = (
            (
                await check.execute(
                    select(HostEnrollmentVoucher).where(
                        HostEnrollmentVoucher.host_id == "host-voucher"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert sorted(row.enrollment_generation for row in rows) == [1, 2]


async def test_seedless_migration_sql_applies_idempotently(postgres_schema):
    _sessions, schema = postgres_schema
    migration = (
        Path(__file__).resolve().parents[2] / "api/migrations/20260720200000_seedless_model_b.sql"
    )
    up_sql = migration.read_text().split("-- migrate:down", 1)[0]
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    connection_url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    environment = {
        **os.environ,
        "PGPASSWORD": parsed.password or "",
        "PGOPTIONS": f"-c search_path={schema}",
    }
    for _ in range(2):
        process = await asyncio.create_subprocess_exec(
            "psql",
            connection_url,
            "-v",
            "ON_ERROR_STOP=1",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        stdout, stderr = await process.communicate(up_sql.encode())
        assert process.returncode == 0, (stdout + stderr).decode(errors="replace")


async def test_seedless_migration_follows_immutable_baseline():
    migrations = Path(__file__).resolve().parents[2] / "api/migrations"
    seedless = migrations / "20260720200000_seedless_model_b.sql"
    assert seedless.is_file()
    assert seedless.name > "20260715121000_image_compute_type.sql"
    payload = seedless.read_text()
    assert "CREATE TABLE IF NOT EXISTS td_launch_reservations" in payload
    assert "CREATE TABLE IF NOT EXISTS host_pcs_mailboxes" in payload
