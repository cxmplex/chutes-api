"""Real-Postgres seedless Model-B migration and concurrency tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.database import Base
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.reservations import (
    LaunchReservationError,
    claim_storage_launch_intent,
    consume_launch_reservation,
    create_launch_reservation,
    resolve_launch_reservation,
)
from api.host.schemas import (
    EnrollmentKeyChallengeRequestV1,
    EnrollmentKeyChallengeRequestV2,
    EnrollmentVoucherMintRequestV1,
    EnrollmentVoucherMintRequestV2,
    HostEnrollmentRedemptionV1,
    HostEnrollmentRedemptionV2,
    HostEnrollmentVoucher,
    GpuHostStorageReadinessV1,
    HostKeyGeneration,
    LaunchReservationResponseV1,
    LaunchReservationResponseV2,
    StorageLaunchIntent,
    StorageLaunchIntentClaimV1,
    TdLaunchReservation,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.host.service import (
    create_enrollment_key_challenge,
    mint_enrollment_voucher,
    redeem_enrollment_voucher,
)
from api.metagraph import MetagraphNode
from api.releases import service as release_service
from api.releases.schemas import (
    GuestRelease,
    GuestReleaseTarget,
    GuestReleaseTargetTokenGeneration,
    GpuL0StorageClosure,
    L0BootstrapPublication,
    RoleLaunchBinaryContract,
)
from api.server.schemas import Host, HostRegistrationArgs
from api.server.service import register_host

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
        storage_requested=True,
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


async def _apply_sql_migration(
    schema: str,
    migration_name: str,
    *,
    direction: str = "up",
) -> None:
    migration = Path(__file__).resolve().parents[2] / "api/migrations" / migration_name
    up_sql, down_sql = migration.read_text().split("-- migrate:down", 1)
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


async def test_storage_capability_requires_durable_intent_in_postgres(postgres_schema):
    sessions, _schema = postgres_schema
    async with sessions() as session:
        host = _host("storage-intent-invariant")
        session.add(host)
        await session.commit()

        host.storage_requested = False
        with pytest.raises(
            IntegrityError,
            match="ck_hosts_storage_capability_requires_intent",
        ):
            await session.commit()


async def test_concurrent_release_activation_keeps_one_active(postgres_schema):
    sessions, _schema = postgres_schema
    async with sessions() as setup:
        setup.add_all([_release("release-a", "draft"), _release("release-b", "draft")])
        await setup.commit()

    async def activate(release_id: str):
        async with sessions() as session:
            return await release_service.activate_release(session, release_id)

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
        await asyncio.gather(activate("release-a"), activate("release-b"))
    async with sessions() as check:
        active = (
            (
                await check.execute(
                    select(GuestRelease).where(GuestRelease.status == "active")
                )
            )
            .scalars()
            .all()
        )
    assert len(active) == 1


async def test_concurrent_cpu_and_gpu_activation_are_independent(postgres_schema):
    sessions, _schema = postgres_schema
    cpu = _release("release-cpu", "draft")
    cpu.compute_type = "cpu"
    gpu = GuestRelease(
        release_id="release-gpu",
        channel=cpu.channel,
        tee_type="tdx",
        compute_type="gpu",
        status="draft",
        images={
            "gpu": {
                "sha256": "b" * 64,
                "measurement_names": ["gpu-lock-test"],
            }
        },
    )
    async with sessions() as setup:
        setup.add_all([cpu, gpu])
        await setup.commit()

    async def activate(release_id: str):
        async with sessions() as session:
            return await release_service.activate_release(session, release_id)

    with (
        patch.object(release_service, "_validate_image_provenance"),
        patch.object(release_service, "_validate_gpu_image_provenance"),
        patch.object(
            release_service,
            "_validate_gpu_storage_stream",
            AsyncMock(),
        ),
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
        patch.object(
            release_service,
            "_capture_release_targets",
            AsyncMock(return_value=[]),
        ),
        patch.object(
            release_service,
            "_refresh_active_gpu_storage_intents",
            AsyncMock(),
        ),
    ):
        await asyncio.wait_for(
            asyncio.gather(activate(cpu.release_id), activate(gpu.release_id)),
            timeout=10,
        )
    async with sessions() as check:
        active = (
            (
                await check.execute(
                    select(GuestRelease)
                    .where(GuestRelease.status == "active")
                    .order_by(GuestRelease.compute_type)
                )
            )
            .scalars()
            .all()
        )
    assert [(release.compute_type, release.release_id) for release in active] == [
        ("cpu", "release-cpu"),
        ("gpu", "release-gpu"),
    ]


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
    assert [(target.host_id, target.role) for target in targets] == [
        ("host-target", "chute")
    ]
    assert targets[0].current_token_id.startswith("audit:")


async def test_gpu_target_capture_excludes_cpu_host_in_same_channel_and_tdx(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    cpu_host = _host("cpu-target-host")
    cpu_host.compute_type = "cpu"
    gpu_host = _host("gpu-target-host")
    gpu_host.compute_type = "gpu"
    cpu_key = _host_key(cpu_host.host_id)
    gpu_key = _host_key(gpu_host.host_id)
    gpu_key.ed25519_fingerprint = "8" * 64
    gpu_key.x25519_fingerprint = "9" * 64
    release = GuestRelease(
        release_id="gpu-target-release",
        channel=gpu_host.release_channel,
        tee_type="tdx",
        compute_type="gpu",
        status="draft",
        images={
            "gpu": {
                "sha256": "b" * 64,
                "version": "1.11.0",
                "measurement_names": [
                    "gpu-baremetal-tdx-1.11.0-b200-8gpu-platform",
                    "gpu-baremetal-tdx-1.11.0-b200-8gpu-miner",
                ],
            }
        },
    )
    async with sessions() as session:
        session.add_all([cpu_host, gpu_host, release])
        await session.flush()
        session.add_all([cpu_key, gpu_key])
        await session.flush()
        with patch.object(
            release_service,
            "_ensure_gpu_storage_launch_intents",
            AsyncMock(),
        ):
            targets = await release_service._capture_release_targets(session, release)
        await session.commit()

    assert [
        (target.host_id, target.compute_type, target.role) for target in targets
    ] == [("gpu-target-host", "gpu", "gpu")]


async def test_gpu_release_status_ignores_subsequently_enrolled_non_targets(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    target_host = _host("gpu-status-target")
    target_host.compute_type = "gpu"
    target_host.reported_capacity = 1
    target_host.capacity = 0
    unsupported = _host("gpu-status-late-unsupported")
    unsupported.compute_type = "gpu"
    unsupported.reported_capacity = 1
    unsupported.capacity = 0
    release = GuestRelease(
        release_id="gpu-status-release",
        channel=target_host.release_channel,
        tee_type="tdx",
        compute_type="gpu",
        status="active",
        images={
            "gpu": {
                "sha256": "a" * 64,
                "measurement_names": ["gpu-baremetal-tdx-1.11.0-b200-platform"],
            }
        },
        targets_captured_at=datetime.now(timezone.utc),
    )
    target = GuestReleaseTarget(
        target_id="gpu-status-target-id",
        release_id=release.release_id,
        host_id=target_host.host_id,
        miner_hotkey=target_host.miner_hotkey,
        tee_type="tdx",
        compute_type="gpu",
        role="gpu",
        current_generation=1,
        current_token_id="audit:gpu-status-target-id",
        issued_at=datetime.now(timezone.utc),
    )
    async with sessions() as setup:
        setup.add_all([target_host, unsupported, release])
        await setup.flush()
        setup.add(target)
        await setup.commit()
    readiness = GpuHostStorageReadinessV1(
        host_id=target_host.host_id,
        trusted_storage_ready=False,
        trusted_schedulable=False,
        reason="storage_intent_missing",
    )
    with (
        patch.object(release_service, "_validate_active_release"),
        patch.object(
            release_service,
            "_gpu_storage_sibling_for_host",
            AsyncMock(side_effect=release_service.ReleaseError("incompatible closure")),
        ),
        patch(
            "api.host.reservations.gpu_host_storage_readiness",
            AsyncMock(return_value=readiness),
        ),
        patch("api.agent_channel.is_agent_online", AsyncMock(return_value=False)),
    ):
        async with sessions() as session:
            status = await release_service.release_status(
                session,
                release.release_id,
            )
    assert [row["untrusted_host_id"] for row in status["untrusted_hosts"]] == [
        target_host.host_id
    ]
    assert status["untrusted_hosts"][0]["untrusted_stage_matches_release"] is False
    assert status["gpu_storage_siblings"][0]["reason"] == (
        "gpu_l0_storage_closure_incompatible"
    )


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
                row, _claims = await resolve_launch_reservation(
                    session, token, commitment
                )
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
        assert response["claims"]["profile_id"] == (
            "storage-baremetal-tdx-1.10.0-2vcpu-8g"
        )
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


async def test_resolve_and_supersede_lock_intent_before_reservation(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    host = _host("lock-order-host")
    host.storage_td_vcpus = 2
    host.storage_td_mem = "8G"
    profile_id = "storage-baremetal-tdx-1.10.0-2vcpu-8g"
    image = {
        "sha256": "7" * 64,
        "version": "1.10.0",
        "measurement_names": [profile_id],
    }
    release = GuestRelease(
        release_id="lock-order-release",
        channel=host.release_channel,
        tee_type="tdx",
        compute_type="cpu",
        status="active",
        images={"storage": image},
    )
    target = GuestReleaseTarget(
        target_id="lock-order-target",
        release_id=release.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type="tdx",
        compute_type="cpu",
        role="storage",
        current_generation=1,
        current_token_id="audit:lock-order-target",
        issued_at=datetime.now(timezone.utc),
    )
    process_incarnation = "stor" + hashlib.sha256(host.host_id.encode()).hexdigest()[:8]
    intent = StorageLaunchIntent(
        intent_id="lock-order-intent",
        target_id=target.target_id,
        release_id=release.release_id,
        tee_type="tdx",
        channel=host.release_channel,
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        server_id=f"chute-{process_incarnation}",
        process_incarnation=process_incarnation,
        profile_id=profile_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        state="active",
        claim_generation=0,
    )
    async with sessions() as setup:
        setup.add_all([host, release])
        await setup.flush()
        setup.add_all([_host_key(host.host_id), target])
        await setup.flush()
        setup.add(intent)
        await setup.commit()
    async with sessions() as claim:
        reservation, token = await claim_storage_launch_intent(
            claim,
            await claim.get(Host, host.host_id),
        )
        await claim.commit()
    commitment = TdQuoteCommitmentV1(
        reservation_sha256=reservation.claims_sha256,
        launch_nonce=reservation.claims["launch_nonce"],
        attested_spki_sha256="e" * 64,
        release_target_sha256=reservation.claims["release_target_sha256"],
        boot_generation=reservation.claims["boot_generation"],
    )

    async with sessions() as superseder:
        await acquire_gpu_lifecycle_lock(superseder)
        await superseder.execute(
            select(StorageLaunchIntent)
            .where(StorageLaunchIntent.intent_id == intent.intent_id)
            .with_for_update()
        )
        pid_ready = asyncio.get_running_loop().create_future()

        async def resolve_while_superseding():
            async with sessions() as resolver:
                pid = (
                    await resolver.execute(text("SELECT pg_backend_pid()"))
                ).scalar_one()
                pid_ready.set_result(pid)
                with pytest.raises(LaunchReservationError, match="invalidated"):
                    await resolve_launch_reservation(resolver, token, commitment)

        resolver_task = asyncio.create_task(resolve_while_superseding())
        resolver_pid = await pid_ready
        async with sessions() as observer:
            wait_event_type = None
            for _ in range(200):
                wait_event_type = (
                    await observer.execute(
                        text(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid = :pid"
                        ),
                        {"pid": resolver_pid},
                    )
                ).scalar_one_or_none()
                if wait_event_type == "Lock":
                    break
                await asyncio.sleep(0.01)
            assert wait_event_type == "Lock"
            await observer.execute(
                select(TdLaunchReservation)
                .where(TdLaunchReservation.reservation_id == reservation.reservation_id)
                .with_for_update(nowait=True)
            )
            await observer.rollback()
        await release_service._supersede_storage_intents(
            superseder,
            StorageLaunchIntent.intent_id == intent.intent_id,
        )
        await superseder.commit()
        await asyncio.wait_for(resolver_task, timeout=5)


async def test_gpu_storage_intent_claim_replay_restart_and_cpu_target_immutability(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    profile_id = "storage-baremetal-tdx-1.10.0-2vcpu-8g"
    image = {
        "sha256": "7" * 64,
        "version": "1.10.0",
        "measurement_names": [profile_id],
        "kernel_sha256": "8" * 64,
        "initrd_sha256": "9" * 64,
        "cmdline_sha256": "a" * 64,
    }
    source = GuestRelease(
        release_id="gpu-storage-source",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status="superseded",
        images={"storage": dict(image)},
    )
    active_cpu = GuestRelease(
        release_id="gpu-storage-active-cpu",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status="active",
        images={"storage": {**image, "_inherited": True}},
    )
    gpu_release = GuestRelease(
        release_id="gpu-storage-active-gpu",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status="active",
        images={"gpu": {"sha256": "b" * 64}},
    )
    host = _host("gpu-storage-host")
    host.compute_type = "gpu"
    host.capacity = 0
    host.reported_capacity = 1
    host.release_channel = "stable"
    host.storage_td_vcpus = 2
    host.storage_td_mem = "8G"
    contract = RoleLaunchBinaryContract(
        role="storage",
        qemu_binary="qemu-system-x86_64",
        qemu_package="qemu-system-x86",
        qemu_package_version="1:10.1.0+ds-5ubuntu2.7",
        qemu_binary_sha256="c" * 64,
        machine_type="pc-q35-10.1",
        firmware_filename="OVMF.inteltdx.fd",
        firmware_sha256="d" * 64,
    )
    closure = GpuL0StorageClosure(
        source_release_id=source.release_id,
        image_version=image["version"],
        image_sha256=image["sha256"],
        kernel_sha256=image["kernel_sha256"],
        initrd_sha256=image["initrd_sha256"],
        cmdline_sha256=image["cmdline_sha256"],
        measurement_names=[profile_id],
        launch_contract=contract,
    )
    process_incarnation = "stor" + hashlib.sha256(host.host_id.encode()).hexdigest()[:8]
    intent = StorageLaunchIntent(
        intent_id="gpu-storage-intent",
        target_id=None,
        release_id=source.release_id,
        tee_type="tdx",
        channel="stable",
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        server_id=f"chute-{process_incarnation}",
        process_incarnation=process_incarnation,
        profile_id=profile_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        host_compute_type="gpu",
        gpu_release_id=gpu_release.release_id,
        active_cpu_release_id=active_cpu.release_id,
        kernel_sha256=image["kernel_sha256"],
        initrd_sha256=image["initrd_sha256"],
        cmdline_sha256=image["cmdline_sha256"],
        launch_contract=contract.model_dump(mode="json"),
        state="active",
        claim_generation=0,
    )
    async with sessions() as setup:
        setup.add_all([source, active_cpu, gpu_release, host])
        await setup.flush()
        setup.add_all([_host_key(host.host_id), intent])
        await setup.commit()

    with (
        patch.object(
            release_service,
            "_storage_launch_contract",
            return_value=contract,
        ),
        patch.object(
            release_service,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=closure)),
                "e" * 64,
            ),
        ),
    ):
        async with sessions() as first_session:
            first, first_token = await claim_storage_launch_intent(
                first_session,
                await first_session.get(Host, host.host_id),
            )
            await first_session.commit()
            response = LaunchReservationResponseV2(
                token=first_token,
                claims=first.claims,
                claims_sha256=first.claims_sha256,
            )
            assert response.claims.version == 2
            assert response.claims.release_id == source.release_id
            assert response.claims.active_cpu_release_id == active_cpu.release_id
            assert response.claims.gpu_release_id == gpu_release.release_id
            assert response.claims.host_compute_type == "gpu"
            first_id = first.reservation_id

        async with sessions() as restarted:
            second, second_token = await claim_storage_launch_intent(
                restarted,
                await restarted.get(Host, host.host_id),
            )
            await restarted.commit()
            assert second.storage_intent_id == intent.intent_id
            assert second.storage_intent_generation == 2
            prior = await restarted.get(TdLaunchReservation, first_id)
            assert prior.invalidated_at is not None
            cpu_targets = (
                (
                    await restarted.execute(
                        select(GuestReleaseTarget).where(
                            GuestReleaseTarget.release_id.in_(
                                [source.release_id, active_cpu.release_id]
                            )
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert cpu_targets == []

        second_commitment = TdQuoteCommitmentV1(
            reservation_sha256=second.claims_sha256,
            launch_nonce=second.claims["launch_nonce"],
            attested_spki_sha256="e" * 64,
            release_target_sha256=second.claims["release_target_sha256"],
            boot_generation=second.claims["boot_generation"],
        )
        async with sessions() as mutate_cpu:
            active = await mutate_cpu.get(GuestRelease, active_cpu.release_id)
            mutated = dict(active.images)
            mutated["storage"] = {
                **mutated["storage"],
                "kernel_sha256": "f" * 64,
            }
            active.images = mutated
            await mutate_cpu.commit()
        async with sessions() as stale_cpu_contract:
            with pytest.raises(LaunchReservationError, match="active exact release"):
                await resolve_launch_reservation(
                    stale_cpu_contract,
                    second_token,
                    second_commitment,
                )
        async with sessions() as restore_cpu:
            active = await restore_cpu.get(GuestRelease, active_cpu.release_id)
            restored = dict(active.images)
            restored["storage"] = {
                **restored["storage"],
                "kernel_sha256": image["kernel_sha256"],
            }
            active.images = restored
            await restore_cpu.commit()
        async with sessions() as valid_again:
            resolved, resolved_claims = await resolve_launch_reservation(
                valid_again,
                second_token,
                second_commitment,
            )
            assert resolved.reservation_id == second.reservation_id
            assert resolved_claims.storage_intent_generation == 2
            await valid_again.rollback()

        async with sessions() as supersede:
            await release_service._supersede_storage_intents(
                supersede,
                StorageLaunchIntent.intent_id == intent.intent_id,
            )
            await supersede.commit()
            stale = await supersede.get(TdLaunchReservation, second.reservation_id)
            stored_intent = await supersede.get(StorageLaunchIntent, intent.intent_id)
            assert stale.invalidated_at is not None
            assert stored_intent.state == "superseded"
        stale_commitment = second_commitment
        async with sessions() as stale_replay:
            with pytest.raises(LaunchReservationError, match="invalidated"):
                await resolve_launch_reservation(
                    stale_replay,
                    second_token,
                    stale_commitment,
                )
        async with sessions() as forged_outstanding:
            stale = await forged_outstanding.get(
                TdLaunchReservation,
                second.reservation_id,
            )
            stale.invalidated_at = None
            await forged_outstanding.commit()
            with pytest.raises(LaunchReservationError, match="intent is superseded"):
                await resolve_launch_reservation(
                    forged_outstanding,
                    second_token,
                    stale_commitment,
                )

        commitment = TdQuoteCommitmentV1(
            reservation_sha256=response.claims_sha256,
            launch_nonce=response.claims.launch_nonce,
            attested_spki_sha256="e" * 64,
            release_target_sha256=response.claims.release_target_sha256,
            boot_generation=response.claims.boot_generation,
        )
        async with sessions() as replay:
            with pytest.raises(LaunchReservationError, match="invalidated"):
                await resolve_launch_reservation(replay, first_token, commitment)


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


async def _complete_cpu_enrollment(sessions, host_id: str):
    mint_request = EnrollmentVoucherMintRequestV1(
        host_id=host_id,
        tee_type="tdx",
        channel="seedless",
    )
    ed25519 = Ed25519PrivateKey.generate()
    x25519 = X25519PrivateKey.generate()
    ed_public = base64.b64encode(
        ed25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    x_public = base64.b64encode(
        x25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()

    async with sessions() as session:
        voucher = await mint_enrollment_voucher(session, "owner", mint_request)
    challenge_request = EnrollmentKeyChallengeRequestV1(
        voucher=voucher.voucher,
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    challenge_request = challenge_request.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(challenge_request.signing_bytes())
            ).decode()
        }
    )
    async with sessions() as session:
        challenge = await create_enrollment_key_challenge(session, challenge_request)

    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(challenge.server_ephemeral_public_key)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(hashlib.sha256(voucher.voucher.encode("ascii")).hexdigest()),
        info=b"chutes/model-b/enrollment-x25519-proof/v1",
    ).derive(x25519.exchange(peer))
    signing_aad = challenge_request.signing_bytes() + challenge.challenge_id.encode(
        "ascii"
    )
    plaintext = ChaCha20Poly1305(key).decrypt(
        base64.b64decode(challenge.nonce),
        base64.b64decode(challenge.ciphertext),
        signing_aad,
    )
    redemption = HostEnrollmentRedemptionV1(
        voucher=voucher.voucher,
        challenge_id=challenge.challenge_id,
        challenge_plaintext=base64.b64encode(plaintext).decode(),
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    redemption = redemption.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(redemption.signing_bytes())
            ).decode()
        }
    )
    async with sessions() as session:
        return await redeem_enrollment_voucher(session, redemption)


async def test_cpu_reenrollment_preserves_explicit_storage_opt_in(postgres_schema):
    sessions, _schema = postgres_schema
    async with sessions() as session:
        session.add(
            MetagraphNode(
                hotkey="owner",
                netuid=64,
                checksum="cpu-storage-reenrollment",
                coldkey="coldkey",
            )
        )
        await session.commit()

    first = await _complete_cpu_enrollment(sessions, "cpu-storage-host")
    assert first.version == 1
    async with sessions() as session:
        host = await session.get(Host, "cpu-storage-host")
        assert host.storage_enabled is False
        host.storage_requested = True
        host.storage_enabled = True
        await session.commit()

    second = await _complete_cpu_enrollment(sessions, "cpu-storage-host")
    assert second.version == 1
    async with sessions() as session:
        host = await session.get(Host, "cpu-storage-host")
        assert host.compute_type == "cpu"
        assert host.storage_requested is True
        assert host.storage_enabled is False
        assert host.enrollment_generation == 2
        assert host.active_key_generation == 2
        # Model the completed durability/PCS acknowledgements before the agent opens
        # its normal registration channel; those transitions are covered separately.
        host.identity_durable_at = datetime.now(timezone.utc)
        host.identity_metadata_sha256 = "3" * 64
        host.steady_config_sha256 = "4" * 64
        host.provisioning_state = "ready"
        await session.commit()

    # A recovered/current agent can explicitly report that it has not rediscovered local intent.
    # Registration must preserve the durable opt-in and reserve exactly one slot on every retry.
    recovered_payload = HostRegistrationArgs(
        host_id="cpu-storage-host",
        capacity=2,
        tee_type="tdx",
        release_channel="seedless",
        storage_requested=False,
        storage_enabled=False,
    )
    async with sessions() as session:
        host = await session.get(Host, "cpu-storage-host")
        for _ in range(2):
            result = await register_host(session, recovered_payload, host)
            assert result["capacity"] == 1
            assert result["storage_requested"] is True
            assert result["storage_enabled"] is False
            assert host.reported_capacity == 2
            assert host.capacity == 1
            assert host.storage_requested is True
            assert host.disk_total_gb is None
            assert host.disk_free_gb is None

    # The deployed legacy producer omits storage_requested. Once it reports its storage TD healthy,
    # the omission inherits storage_enabled and its already-reserved capacity is not decremented.
    legacy_healthy_payload = HostRegistrationArgs(
        host_id="cpu-storage-host",
        capacity=1,
        tee_type="tdx",
        release_channel="seedless",
        storage_enabled=True,
        disk_total_gb=200,
        disk_free_gb=125,
    )
    assert legacy_healthy_payload.storage_requested is None
    async with sessions() as session:
        host = await session.get(Host, "cpu-storage-host")
        result = await register_host(session, legacy_healthy_payload, host)
        assert result["capacity"] == 1
        assert result["storage_requested"] is True
        assert result["storage_enabled"] is True
        assert host.reported_capacity == 1
        assert host.capacity == 1
        assert host.disk_total_gb == 200
        assert host.disk_free_gb == 125

    async with sessions() as session:
        persisted = await session.get(Host, "cpu-storage-host")
        assert persisted.storage_requested is True
        assert persisted.storage_enabled is True
        assert persisted.reported_capacity == 1
        assert persisted.capacity == 1


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


async def test_gpu_v2_enrollment_persists_compute_and_storage_identity(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    mint_request = EnrollmentVoucherMintRequestV2(
        host_id="gpu-enrollment-host",
        tee_type="tdx",
        compute_type="gpu",
        storage_enabled=True,
        channel="gpu-canary",
    )
    ed25519 = Ed25519PrivateKey.generate()
    x25519 = X25519PrivateKey.generate()
    ed_public = base64.b64encode(
        ed25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()
    x_public = base64.b64encode(
        x25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode()

    async with sessions() as session:
        session.add(
            MetagraphNode(
                hotkey="owner",
                netuid=64,
                checksum="gpu-enrollment",
                coldkey="coldkey",
            )
        )
        await session.commit()
    async with sessions() as session:
        voucher = await mint_enrollment_voucher(session, "owner", mint_request)
    challenge_request = EnrollmentKeyChallengeRequestV2(
        voucher=voucher.voucher,
        compute_type="gpu",
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    challenge_request = challenge_request.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(challenge_request.signing_bytes())
            ).decode()
        }
    )
    async with sessions() as session:
        challenge = await create_enrollment_key_challenge(session, challenge_request)

    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(challenge.server_ephemeral_public_key)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(hashlib.sha256(voucher.voucher.encode("ascii")).hexdigest()),
        info=b"chutes/model-b/enrollment-x25519-proof/v2",
    ).derive(x25519.exchange(peer))
    signing_aad = challenge_request.signing_bytes() + challenge.challenge_id.encode(
        "ascii"
    )
    plaintext = ChaCha20Poly1305(key).decrypt(
        base64.b64decode(challenge.nonce),
        base64.b64decode(challenge.ciphertext),
        signing_aad,
    )
    redemption = HostEnrollmentRedemptionV2(
        voucher=voucher.voucher,
        compute_type="gpu",
        challenge_id=challenge.challenge_id,
        challenge_plaintext=base64.b64encode(plaintext).decode(),
        ed25519_public_key=ed_public,
        x25519_public_key=x_public,
        ed25519_signature=base64.b64encode(b"x" * 64).decode(),
    )
    redemption = redemption.model_copy(
        update={
            "ed25519_signature": base64.b64encode(
                ed25519.sign(redemption.signing_bytes())
            ).decode()
        }
    )
    async with sessions() as session:
        result = await redeem_enrollment_voucher(session, redemption)

    async with sessions() as check:
        host = await check.get(Host, mint_request.host_id)
        row = (
            await check.execute(
                select(HostEnrollmentVoucher).where(
                    HostEnrollmentVoucher.voucher_id == voucher.claims.voucher_id
                )
            )
        ).scalar_one()
    assert result.version == 2
    assert result.compute_type == "gpu"
    assert result.storage_enabled is True
    assert host.compute_type == "gpu"
    assert host.tee_type == "tdx"
    assert host.storage_enabled is True
    assert host.release_channel == "gpu-canary"
    assert row.compute_type == "gpu"
    assert row.claims["compute_type"] == "gpu"
    assert row.claims["storage_enabled"] is True


async def test_attestation_identity_and_seedless_migrations_accept_create_all_and_reentry(
    postgres_schema,
):
    sessions, schema = postgres_schema
    migrations = (
        "20260714070000_release_attestation_identity.sql",
        "20260720200000_seedless_model_b.sql",
    )
    for _ in range(2):
        for migration_name in migrations:
            await _apply_sql_migration(schema, migration_name)

    async with sessions() as session:
        constraint_counts = dict(
            (
                await session.execute(
                    text(
                        "SELECT conname, count(*) FROM pg_constraint "
                        "WHERE conname IN ("
                        "'fk_server_attestations_subject', "
                        "'ck_server_attestation_attribution', "
                        "'fk_server_attestations_attribution_owner', "
                        "'fk_server_attestations_td_reservation_attribution', "
                        "'uq_td_launch_reservation_attribution') "
                        "GROUP BY conname"
                    )
                )
            ).all()
        )
        trigger_counts = dict(
            (
                await session.execute(
                    text(
                        "SELECT tgname, count(*) FROM pg_trigger "
                        "WHERE NOT tgisinternal AND tgname IN ("
                        "'preserve_server_attestation_subject_identity', "
                        "'enforce_server_attestation_subject', "
                        "'preserve_server_attestation_audit') GROUP BY tgname"
                    )
                )
            ).all()
        )
    assert constraint_counts == {
        "ck_server_attestation_attribution": 1,
        "fk_server_attestations_attribution_owner": 1,
        "fk_server_attestations_subject": 1,
        "fk_server_attestations_td_reservation_attribution": 1,
        "uq_td_launch_reservation_attribution": 1,
    }
    assert trigger_counts == {
        "enforce_server_attestation_subject": 1,
        "preserve_server_attestation_audit": 1,
        "preserve_server_attestation_subject_identity": 1,
    }


@pytest.mark.parametrize(
    ("mutation_statements", "migration_name", "expected_error"),
    [
        (
            [
                "ALTER TABLE server_attestations "
                "DROP CONSTRAINT fk_server_attestations_subject",
                "ALTER TABLE server_attestations "
                "ADD CONSTRAINT fk_server_attestations_subject "
                "FOREIGN KEY (server_id) "
                "REFERENCES server_attestation_subjects(server_id) "
                "ON DELETE CASCADE",
            ],
            "20260714070000_release_attestation_identity.sql",
            "final server attestation subject FK has invalid shape",
        ),
        (
            [
                "ALTER TABLE server_attestations "
                "ALTER COLUMN attempt_sequence DROP DEFAULT",
            ],
            "20260714070000_release_attestation_identity.sql",
            "attempt_sequence has invalid type, nullability, or default",
        ),
        (
            [
                "DROP TRIGGER enforce_server_attestation_subject "
                "ON server_attestations",
                "CREATE TRIGGER enforce_server_attestation_subject "
                "AFTER INSERT ON server_attestations FOR EACH ROW "
                "EXECUTE FUNCTION enforce_server_attestation_subject()",
            ],
            "20260714070000_release_attestation_identity.sql",
            "enforce_server_attestation_subject has invalid trigger shape",
        ),
        (
            [
                "ALTER TABLE server_attestations "
                "DROP CONSTRAINT ck_server_attestation_attribution",
                "ALTER TABLE server_attestations "
                "ADD CONSTRAINT ck_server_attestation_attribution "
                "CHECK (attribution_reservation_id IS NULL)",
            ],
            "20260720200000_seedless_model_b.sql",
            "ck_server_attestation_attribution has invalid or duplicate authority",
        ),
    ],
)
async def test_attestation_migrations_reject_partial_or_wrong_create_all_catalogs(
    postgres_schema,
    mutation_statements,
    migration_name,
    expected_error,
):
    sessions, schema = postgres_schema
    async with sessions() as session:
        for statement in mutation_statements:
            await session.execute(text(statement))
        await session.commit()

    with pytest.raises(AssertionError) as error:
        await _apply_sql_migration(schema, migration_name)
    assert expected_error in str(error.value)


@pytest.mark.parametrize(
    "migration_name",
    [
        "20260722021500_l0_bootstrap_publications.sql",
        "20260722030000_host_enrollment_durability.sql",
        "20260722040000_storage_launch_intents.sql",
        "20260722050000_registry_descriptor_closure.sql",
        "20260723030000_gpu_release_compute_type.sql",
        "20260723040000_gpu_l0_storage_sibling.sql",
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
    connection_url = (
        f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    )
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


async def test_gpu_release_migration_preserves_cpu_identity_and_signed_v1_state(
    postgres_schema,
):
    sessions, schema = postgres_schema
    host = _host("migration-cpu-host")
    host.compute_type = "cpu"
    signed_v1 = {
        "manifest": {
            "schema": "chutes.l0-bootstrap",
            "version": 1,
            "tee_type": "tdx",
            "channel": "stable",
            "generation": 9,
        },
        "signature": "v1-signature-bytes-remain-unchanged",
    }
    images = {
        "chute": {
            "sha256": "a" * 64,
            "version": "1.10.0",
            "measurement_names": ["cpu-baremetal-tdx-1.10.0-2vcpu-8g"],
            "_inherited": True,
        },
        "l0": {
            "version": "l0-1.10.0",
            "squashfs_sha256": "b" * 64,
            "bootstrap": signed_v1,
        },
    }
    release = GuestRelease(
        release_id="migration-cpu-release",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status="active",
        images=images,
        l0_manifest=signed_v1["manifest"],
        l0_manifest_digest="c" * 64,
        l0_manifest_generation=9,
        l0_manifest_key_id="publisher-v1",
        l0_manifest_key_epoch=4,
        targets_captured_at=datetime.now(timezone.utc),
    )
    publication = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        compute_type="cpu",
        generation=9,
        manifest_digest="c" * 64,
        key_id="publisher-v1",
        key_epoch=4,
        l0_version="l0-1.10.0",
        squashfs_sha256="b" * 64,
        signed_manifest=signed_v1,
        source_release_id=release.release_id,
        admission_status="active",
    )
    target = GuestReleaseTarget(
        target_id="migration-target",
        release_id=release.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type="tdx",
        compute_type="cpu",
        role="chute",
        current_generation=7,
        current_token_id="migration-current-token",
        issued_at=datetime.now(timezone.utc),
    )
    token = GuestReleaseTargetTokenGeneration(
        target_id=target.target_id,
        generation=7,
        token_id="migration-token-generation",
        issued_at=datetime.now(timezone.utc),
    )
    voucher_claims_v1 = {
        "schema": "chutes.host-enrollment",
        "version": 1,
        "voucher_id": "migration-voucher",
        "owner_hotkey": "owner",
        "host_id": host.host_id,
        "tee_type": "tdx",
        "channel": "stable",
        "enrollment_generation": 1,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "source_metadata": {},
    }
    voucher = HostEnrollmentVoucher(
        voucher_id="migration-voucher",
        voucher_hash="d" * 64,
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        tee_type="tdx",
        compute_type="cpu",
        channel="stable",
        enrollment_generation=1,
        claims=voucher_claims_v1,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    async with sessions() as setup:
        setup.add_all([host, release])
        await setup.flush()
        setup.add_all([publication, target, voucher])
        await setup.flush()
        setup.add(token)
        await setup.commit()

    migration_name = "20260723030000_gpu_release_compute_type.sql"
    await _apply_sql_migration(schema, migration_name, direction="down")
    await _apply_sql_migration(schema, migration_name)

    async with sessions() as check:
        stored_release = await check.get(GuestRelease, release.release_id)
        stored_publication = await check.get(
            L0BootstrapPublication,
            ("tdx", "stable", "cpu", 9),
        )
        stored_target = await check.get(GuestReleaseTarget, target.target_id)
        stored_token = await check.get(
            GuestReleaseTargetTokenGeneration,
            (target.target_id, 7),
        )
        stored_host = await check.get(Host, host.host_id)
        stored_voucher = await check.get(HostEnrollmentVoucher, voucher.voucher_id)
        active_index = (
            await check.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE schemaname = current_schema() "
                    "AND indexname = 'uq_guest_release_active'"
                )
            )
        ).scalar_one()

    assert stored_release.compute_type == "cpu"
    assert stored_release.status == "active"
    assert stored_release.release_id == release.release_id
    assert stored_release.images == images
    assert stored_release.images["chute"]["_inherited"] is True
    assert stored_release.l0_manifest == signed_v1["manifest"]
    assert stored_release.l0_manifest_generation == 9
    assert stored_publication.compute_type == "cpu"
    assert stored_publication.signed_manifest == signed_v1
    assert stored_target.compute_type == "cpu"
    assert stored_target.target_id == "migration-target"
    assert stored_target.current_generation == 7
    assert stored_target.current_token_id == "migration-current-token"
    assert stored_token.token_id == "migration-token-generation"
    assert stored_host.compute_type == "cpu"
    assert stored_voucher.compute_type == "cpu"
    assert stored_voucher.claims == voucher_claims_v1
    assert "(channel, tee_type, compute_type)" in active_index


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
            ("tdx", "stable", "cpu", 7),
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
                select(StorageLaunchIntent).where(
                    StorageLaunchIntent.target_id == target.target_id
                )
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
