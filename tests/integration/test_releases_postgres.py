"""Real-Postgres seedless Model-B migration and concurrency tests."""

from __future__ import annotations

import asyncio
import base64
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
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
    claim_storage_launch_intent,
    consume_launch_reservation,
    create_launch_reservation,
    resolve_launch_reservation,
)
from api.host.schemas import (
    EnrollmentVoucherMintRequestV1,
    HostEnrollmentVoucher,
    HostKeyGeneration,
    LaunchReservationResponseV1,
    StorageLaunchIntent,
    StorageLaunchIntentClaimV1,
    TdLaunchReservation,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.host.service import mint_enrollment_voucher
from api.metagraph import MetagraphNode
from api.releases import service as release_service
from api.releases.schemas import (
    GuestRelease,
    GuestReleaseTarget,
    L0BootstrapPublication,
)
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
        identity_durable_at=datetime.now(timezone.utc),
        identity_metadata_sha256="3" * 64,
        steady_config_sha256="4" * 64,
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


async def _apply_sql_migration(schema: str, migration_name: str) -> None:
    migration = Path(__file__).resolve().parents[2] / "api/migrations" / migration_name
    up_sql = migration.read_text().split("-- migrate:down", 1)[0]
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    connection_url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
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
    stdout, stderr = await process.communicate(up_sql.encode())
    assert process.returncode == 0, (stdout + stderr).decode(errors="replace")


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
        "storage_launch_intents",
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
                    AsyncMock(return_value=Mock()),
                ),
                patch.object(
                    release_service,
                    "_mark_l0_publication_active",
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
                AsyncMock(return_value=Mock()),
            ),
            patch.object(
                release_service,
                "_mark_l0_publication_active",
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


async def test_storage_intent_claim_is_server_selected_scoped_and_replay_safe(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    host = _host("host-storage-intent")
    host.storage_td_vcpus = 2
    host.storage_td_mem = "8G"
    outsider = _host("host-outside-storage-target")
    outsider.storage_td_vcpus = 2
    outsider.storage_td_mem = "8G"
    release = GuestRelease(
        release_id="release-storage-intent",
        channel=host.release_channel,
        tee_type=host.tee_type,
        status="active",
        images={
            "chute": {
                "sha256": "a" * 64,
                "version": "1.10.0",
                "measurement_names": ["cpu-baremetal-tdx-1.10.0-2vcpu-8g"],
            },
            "storage": {
                "sha256": "b" * 64,
                "version": "1.10.0",
                "measurement_names": ["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
            },
        },
        targets_captured_at=datetime.now(timezone.utc),
    )
    target = GuestReleaseTarget(
        target_id="storage-target-1",
        release_id=release.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type=host.tee_type,
        role="storage",
        current_generation=1,
        current_token_id="audit:storage-target-1",
        issued_at=datetime.now(timezone.utc),
    )
    outsider_key = _host_key(outsider.host_id)
    outsider_key.ed25519_fingerprint = "5" * 64
    outsider_key.x25519_fingerprint = "6" * 64
    async with sessions() as setup:
        setup.add_all([host, outsider, release])
        await setup.flush()
        setup.add_all(
            [
                _host_key(host.host_id),
                outsider_key,
                target,
            ]
        )
        await setup.flush()
        await release_service._ensure_storage_launch_intents(
            setup,
            release,
            [target],
        )
        unrelated, _unrelated_token = await create_launch_reservation(
            setup,
            host,
            role="chute",
            server_id="chute-unrelated",
            process_incarnation="unrelated",
            profile_id="cpu-baremetal-tdx-1.10.0-2vcpu-8g",
            chute_id="chute-1",
            container_repository="owner/image",
            container_manifest_digest=f"sha256:{'c' * 64}",
        )
        await setup.commit()
        unrelated_id = unrelated.reservation_id

    async with sessions() as first_session:
        first, first_token = await claim_storage_launch_intent(
            first_session,
            await first_session.get(Host, host.host_id),
        )
        await first_session.commit()
        first_claims = dict(first.claims)
        first_digest = first.claims_sha256
        response = LaunchReservationResponseV1(
            token=first_token,
            claims=first_claims,
            claims_sha256=first_digest,
        ).model_dump(mode="json", exclude_none=True)
        assert response["claims_sha256"] == canonical_sha256(first_claims)
        assert response["claims"]["profile_id"] == ("storage-baremetal-tdx-1.10.0-2vcpu-8g")
        assert response["claims"]["storage_intent_generation"] == 1
        assert not {
            "chute_id",
            "job_id",
            "container_repository",
            "container_manifest_digest",
        } & set(response["claims"])

    async with sessions() as second_session:
        second, _second_token = await claim_storage_launch_intent(
            second_session,
            await second_session.get(Host, host.host_id),
        )
        await second_session.commit()
        assert second.claims["storage_intent_generation"] == 2
        first_row = await second_session.get(
            TdLaunchReservation,
            first_claims["reservation_id"],
        )
        unrelated_row = await second_session.get(
            TdLaunchReservation,
            unrelated_id,
        )
        intent = await second_session.get(
            StorageLaunchIntent,
            second.claims["storage_intent_id"],
        )
        assert first_row.invalidated_at is not None
        assert unrelated_row.invalidated_at is None
        assert intent.claim_generation == 2

    commitment = TdQuoteCommitmentV1(
        reservation_sha256=first_digest,
        launch_nonce=first_claims["launch_nonce"],
        attested_spki_sha256="3" * 64,
        release_target_sha256=first_claims["release_target_sha256"],
        boot_generation=first_claims["boot_generation"],
    )
    async with sessions() as replay:
        with pytest.raises(LaunchReservationError, match="invalidated"):
            await resolve_launch_reservation(replay, first_token, commitment)
        with pytest.raises(LaunchReservationError, match="no unique"):
            await claim_storage_launch_intent(
                replay,
                await replay.get(Host, outsider.host_id),
            )

    with pytest.raises(ValueError):
        StorageLaunchIntentClaimV1.model_validate(
            {
                "schema": "chutes.storage-launch-intent-claim",
                "version": 1,
                "profile_id": "host-selected-profile",
            }
        )


async def test_returning_host_repairs_inherited_intent_without_sibling_coupling(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    host = _host("returning-storage-host")
    host.storage_td_vcpus = 2
    host.storage_td_mem = "8G"
    sibling = _host("offline-storage-sibling")
    sibling.storage_td_vcpus = 2
    sibling.storage_td_mem = "8G"
    sibling.provisioning_state = "revoked"
    image = {
        "sha256": "8" * 64,
        "version": "1.10.0",
        "measurement_names": ["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
    }
    source = GuestRelease(
        release_id="storage-source-release",
        channel=host.release_channel,
        tee_type=host.tee_type,
        status="superseded",
        images={"storage": image},
        targets_captured_at=datetime.now(timezone.utc),
    )
    active = GuestRelease(
        release_id="storage-inherited-release",
        channel=host.release_channel,
        tee_type=host.tee_type,
        status="active",
        images={"storage": {**image, "_inherited": True}},
        targets_captured_at=datetime.now(timezone.utc),
    )
    target = GuestReleaseTarget(
        target_id="returning-storage-target",
        release_id=source.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type=host.tee_type,
        role="storage",
        current_generation=1,
        current_token_id="audit:returning-storage-target",
        issued_at=datetime.now(timezone.utc),
    )
    sibling_target = GuestReleaseTarget(
        target_id="offline-sibling-target",
        release_id=source.release_id,
        host_id=sibling.host_id,
        miner_hotkey=sibling.miner_hotkey,
        tee_type=sibling.tee_type,
        role="storage",
        current_generation=1,
        current_token_id="audit:offline-sibling-target",
        issued_at=datetime.now(timezone.utc),
    )
    async with sessions() as session:
        session.add_all([host, sibling, source, active])
        await session.flush()
        session.add_all([target, sibling_target])
        await session.flush()
        intent = await release_service._ensure_storage_launch_intent_for_host(
            session,
            active,
            host,
        )
        await session.commit()

        assert intent is not None
        assert intent.target_id == target.target_id
        assert intent.release_id == source.release_id
        assert intent.profile_id == "storage-baremetal-tdx-1.10.0-2vcpu-8g"

        active.status = "superseded"
        await session.flush()
        explicit = GuestRelease(
            release_id="storage-explicit-without-target",
            channel=host.release_channel,
            tee_type=host.tee_type,
            status="active",
            images={"storage": image},
            targets_captured_at=datetime.now(timezone.utc),
        )
        session.add(explicit)
        await session.flush()
        repaired = await release_service._ensure_storage_launch_intent_for_host(
            session,
            explicit,
            host,
        )
        await session.commit()

        assert repaired is None
        assert intent.state == "superseded"


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


@pytest.mark.parametrize(
    "migration_name",
    [
        "20260722021500_l0_bootstrap_publications.sql",
        "20260722030000_host_enrollment_durability.sql",
        "20260722040000_storage_launch_intents.sql",
        "20260722050000_registry_descriptor_closure.sql",
    ],
)
async def test_followup_migrations_apply_idempotently(
    postgres_schema,
    migration_name,
):
    _sessions, schema = postgres_schema
    migration = Path(__file__).resolve().parents[2] / "api/migrations" / migration_name
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


async def test_bootstrap_publication_migration_backfills_active_release(
    postgres_schema,
):
    sessions, schema = postgres_schema
    signed = {
        "manifest": {
            "schema": "chutes.l0-bootstrap",
            "version": 1,
            "generation": 7,
        },
        "signature": "s" * 88,
    }
    release = GuestRelease(
        release_id="baseline-bootstrap-release",
        channel="stable",
        tee_type="tdx",
        status="active",
        images={
            "chute": {
                "sha256": "a" * 64,
                "version": "1.10.0",
                "measurement_names": ["cpu-baremetal-tdx-1.10.0-2vcpu-8g"],
            },
            "l0": {
                "version": "l0-1.10.0",
                "squashfs_sha256": "b" * 64,
                "bootstrap": signed,
            },
        },
        l0_manifest=signed["manifest"],
        l0_manifest_digest="c" * 64,
        l0_manifest_generation=7,
        l0_manifest_key_id="publisher-1",
        l0_manifest_key_epoch=2,
        activated_at=datetime.now(timezone.utc),
    )
    async with sessions() as setup:
        setup.add(release)
        await setup.commit()

    await _apply_sql_migration(
        schema,
        "20260722021500_l0_bootstrap_publications.sql",
    )

    async with sessions() as check:
        publication = await check.get(
            L0BootstrapPublication,
            ("tdx", "stable", 7),
        )
        assert publication is not None
        assert publication.manifest_digest == "c" * 64
        assert publication.signed_manifest == signed
        assert publication.admission_status == "active"
        assert publication.source_release_id == release.release_id


async def test_storage_intent_migration_backfills_active_target_from_reservation(
    postgres_schema,
):
    sessions, schema = postgres_schema
    host = _host("baseline-storage-host")
    host.storage_td_vcpus = None
    host.storage_td_mem = None
    release = GuestRelease(
        release_id="baseline-storage-release",
        channel=host.release_channel,
        tee_type=host.tee_type,
        status="active",
        images={
            "storage": {
                "sha256": "d" * 64,
                "version": "1.10.0",
                "measurement_names": ["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
            }
        },
        targets_captured_at=datetime.now(timezone.utc),
    )
    target = GuestReleaseTarget(
        target_id="baseline-storage-target",
        release_id=release.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type=host.tee_type,
        role="storage",
        current_generation=1,
        current_token_id="audit:baseline-storage-target",
        issued_at=datetime.now(timezone.utc),
    )
    now = datetime.now(timezone.utc)
    reservation = TdLaunchReservation(
        reservation_id="baseline-storage-reservation",
        token_id="baseline-storage-token",
        token_hash="e" * 64,
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        server_id="chute-storbaseline",
        role="storage",
        compute_type="cpu",
        tee_type=host.tee_type,
        process_incarnation="storbaseline",
        boot_generation=1,
        release_id=release.release_id,
        image_sha256="d" * 64,
        image_version="1.10.0",
        profile_id="storage-baremetal-tdx-1.10.0-2vcpu-8g",
        launch_nonce=base64.b64encode(b"n" * 32).decode(),
        release_target_sha256="f" * 64,
        claims={},
        claims_sha256=None,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        consumed_at=now,
        consumed_attestation_id="baseline-attestation",
        consumed_cert_pubkey_hash="7" * 64,
    )
    async with sessions() as setup:
        setup.add_all([host, release])
        await setup.flush()
        setup.add_all([target, reservation])
        await setup.commit()

    await _apply_sql_migration(
        schema,
        "20260722040000_storage_launch_intents.sql",
    )

    async with sessions() as check:
        stored_host = await check.get(Host, host.host_id)
        intent = (
            await check.execute(
                select(StorageLaunchIntent).where(StorageLaunchIntent.target_id == target.target_id)
            )
        ).scalar_one()
        assert stored_host.storage_td_vcpus == 2
        assert stored_host.storage_td_mem == "8G"
        assert intent.profile_id == reservation.profile_id
        assert intent.image_sha256 == reservation.image_sha256
        assert intent.state == "active"


async def test_seedless_migration_follows_immutable_baseline():
    migrations = Path(__file__).resolve().parents[2] / "api/migrations"
    seedless = migrations / "20260720200000_seedless_model_b.sql"
    assert seedless.is_file()
    assert seedless.name > "20260715121000_image_compute_type.sql"
    payload = seedless.read_text()
    assert "CREATE TABLE IF NOT EXISTS td_launch_reservations" in payload
    assert "CREATE TABLE IF NOT EXISTS host_pcs_mailboxes" in payload
