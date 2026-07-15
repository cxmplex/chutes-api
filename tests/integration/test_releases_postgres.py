"""Real-Postgres release migration, activation serialization, and attested status tests."""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import jwt
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.database import Base
from api.database import migrations as database_migrations
from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.metagraph import MetagraphNode
from api.releases import service as release_service
from api.releases.schemas import (
    GuestRelease,
    GuestReleaseTarget,
    GuestReleaseTargetTokenGeneration,
    ReleaseStatusResponse,
)
from api.server import service as server_service
from api.server.schemas import (
    Host,
    HostRegistrationArgs,
    Server,
    ServerAttestation,
)


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
DBMATE_BIN = os.getenv("DBMATE_BIN") or shutil.which("dbmate")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real-Postgres release tests",
    ),
]
CPU_NAMES = [f"cpu-baremetal-snp-genoa-1.6.2-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)]
CPU_SHA = "688d24a5ab1af8e2174ffada8d8ea669c38280b4b0fdd6936729fe697b5930e3"
STORAGE_NAMES = [f"storage-baremetal-snp-genoa-1.6.1-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)]
STORAGE_SHA = "3121af4af5446f1dacc4a3290eba8605aa3c2a32a319d31c958c61faca5dd2da"


@pytest.fixture(autouse=True)
def nv_attest():
    """Release tests do not invoke the external GPU-attestation CLI."""
    yield


async def _create_schema_engine(prefix: str):
    schema = f"{prefix}_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        connect_args={"server_settings": {"search_path": schema}},
    )
    return schema, admin, engine


async def _drop_schema(schema, admin, engine):
    await engine.dispose()
    async with admin.begin() as connection:
        await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    await admin.dispose()


async def _run_dbmate(schema: str) -> None:
    sync_url = TEST_DATABASE_URL.replace("+asyncpg", "")
    separator = "&" if "?" in sync_url else "?"
    sync_url = f"{sync_url}{separator}search_path={schema}&sslmode=disable"
    process = await asyncio.create_subprocess_exec(
        DBMATE_BIN,
        "--url",
        sync_url,
        "--migrations-dir",
        str(Path(__file__).resolve().parents[2] / "api/migrations"),
        "--migrations-table",
        "schema_migrations",
        "--no-dump-schema",
        "migrate",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


@pytest.mark.skipif(not DBMATE_BIN, reason="dbmate is required")
@pytest.mark.parametrize("legacy_upgrade", [False, True])
async def test_clean_and_upgrade_migrations_enforce_single_active_release(
    legacy_upgrade,
):
    schema, admin, engine = await _create_schema_engine("release_migrations")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            if legacy_upgrade:
                await connection.execute(text("DROP INDEX uq_guest_release_active"))
                await connection.execute(
                    text("DROP INDEX IF EXISTS idx_server_attestations_release_identity")
                )
                for table in (
                    "servers",
                    "server_attestations",
                    "boot_attestations",
                ):
                    await connection.execute(
                        text(f"ALTER TABLE {table} DROP COLUMN IF EXISTS measurement_name")
                    )
        async with engine.connect() as connection:
            await database_migrations.record_historical_migration_baseline(connection)
        await _run_dbmate(schema)

        async with engine.connect() as connection:
            index_exists = (
                await connection.execute(
                    text(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM pg_indexes
                            WHERE schemaname = current_schema()
                              AND indexname = 'uq_guest_release_active'
                              AND indexdef LIKE 'CREATE UNIQUE INDEX%'
                        )
                        """
                    )
                )
            ).scalar_one()
            columns = set(
                (
                    await connection.execute(
                        text(
                            """
                            SELECT table_name, column_name
                            FROM information_schema.columns
                            WHERE table_schema = current_schema()
                              AND column_name = 'measurement_name'
                              AND table_name = ANY(:tables)
                            """
                        ),
                        {
                            "tables": [
                                "servers",
                                "server_attestations",
                                "boot_attestations",
                            ]
                        },
                    )
                ).all()
            )
            rollout_columns = set(
                (
                    await connection.execute(
                        text(
                            """
                            SELECT table_name, column_name
                            FROM information_schema.columns
                            WHERE table_schema = current_schema()
                              AND (
                                (table_name = 'hosts'
                                 AND column_name = ANY(:host_columns))
                                OR
                                (table_name = 'guest_releases'
                                 AND column_name = 'targets_captured_at')
                                OR
                                (table_name = 'guest_release_targets'
                                 AND column_name = ANY(:target_columns))
                              )
                            """
                        ),
                        {
                            "host_columns": [
                                "storage_enabled",
                                "release_channel",
                            ],
                            "target_columns": [
                                "current_generation",
                                "current_token_id",
                            ],
                        },
                    )
                ).all()
            )
            release_target_table = (
                await connection.execute(
                    text(
                        """
                        SELECT to_regclass(
                            current_schema() || '.guest_release_targets'
                        ) IS NOT NULL
                        """
                    )
                )
            ).scalar_one()
            release_target_token_table = (
                await connection.execute(
                    text(
                        """
                        SELECT to_regclass(
                            current_schema() || '.guest_release_target_token_generations'
                        ) IS NOT NULL
                        """
                    )
                )
            ).scalar_one()
        assert index_exists
        assert columns == {
            ("servers", "measurement_name"),
            ("server_attestations", "measurement_name"),
            ("boot_attestations", "measurement_name"),
        }
        assert rollout_columns == {
            ("hosts", "storage_enabled"),
            ("hosts", "release_channel"),
            ("guest_releases", "targets_captured_at"),
            ("guest_release_targets", "current_generation"),
            ("guest_release_targets", "current_token_id"),
        }
        assert release_target_table
        assert release_target_token_table
    finally:
        await _drop_schema(schema, admin, engine)


def _release_images(*, chute=True, storage=False):
    images = {}
    if chute:
        images["chute"] = {
            "url": (
                "http://storage.googleapis.com/ardent-stacker-232906-chutes-tee/"
                "l0/guest/snp-1.6.2-debug.qcow2"
            ),
            "sha256": CPU_SHA,
            "debug": True,
            "version": "1.6.2",
            "measurement_names": CPU_NAMES,
            "provenance_payload": None,
            "provenance_signature": None,
        }
    if storage:
        images["storage"] = {
            "url": (
                "http://storage.googleapis.com/ardent-stacker-232906-chutes-tee/"
                "l0/guest/storage-1.6.1-debug.qcow2"
            ),
            "sha256": STORAGE_SHA,
            "debug": True,
            "version": "1.6.1",
            "measurement_names": STORAGE_NAMES,
            "provenance_payload": None,
            "provenance_signature": None,
        }
    return images


async def test_concurrent_activation_is_serialized_and_leaves_one_active():
    schema, admin, engine = await _create_schema_engine("release_activation")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        release_ids = [f"release-{uuid.uuid4().hex}" for _ in range(2)]
        async with sessions() as setup:
            setup.add_all(
                [
                    GuestRelease(
                        release_id=release_id,
                        channel="stable",
                        tee_type="sev-snp",
                        status="draft",
                        images=_release_images(),
                    )
                    for release_id in release_ids
                ]
            )
            await setup.commit()

        async with sessions() as first, sessions() as second:
            await asyncio.gather(
                release_service.activate_release(first, release_ids[0]),
                release_service.activate_release(second, release_ids[1]),
            )

        async with sessions() as check:
            active = (
                (
                    await check.execute(
                        select(GuestRelease).where(
                            GuestRelease.channel == "stable",
                            GuestRelease.tee_type == "sev-snp",
                            GuestRelease.status == "active",
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(active) == 1
        assert active[0].release_id in release_ids
    finally:
        await _drop_schema(schema, admin, engine)


async def test_activation_captures_immutable_logical_role_matrix():
    schema, admin, engine = await _create_schema_engine("release_targets")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with sessions() as invalid:
            invalid.add(
                Host(
                    host_id="invalid-zero-compute",
                    name="invalid-zero-compute",
                    miner_hotkey="miner",
                    tee_type="sev-snp",
                    capacity=0,
                    storage_enabled=False,
                    release_channel="matrix",
                )
            )
            with pytest.raises(IntegrityError):
                await invalid.commit()
            await invalid.rollback()
        release = GuestRelease(
            release_id="release-role-matrix",
            channel="matrix",
            tee_type="sev-snp",
            status="draft",
            images=_release_images(chute=True, storage=True),
        )
        async with sessions() as setup:
            setup.add(release)
            setup.add_all(
                [
                    Host(
                        host_id="compute-only",
                        name="compute-only",
                        miner_hotkey="miner",
                        tee_type="sev-snp",
                        capacity=1,
                        storage_enabled=False,
                        release_channel="matrix",
                    ),
                    Host(
                        host_id="storage-only",
                        name="storage-only",
                        miner_hotkey="miner",
                        tee_type="sev-snp",
                        capacity=0,
                        storage_enabled=True,
                        release_channel="matrix",
                    ),
                    Host(
                        host_id="combined",
                        name="combined",
                        miner_hotkey="miner",
                        tee_type="sev-snp",
                        capacity=2,
                        storage_enabled=True,
                        release_channel="matrix",
                    ),
                    Host(
                        host_id="other-channel",
                        name="other-channel",
                        miner_hotkey="miner",
                        tee_type="sev-snp",
                        capacity=2,
                        storage_enabled=True,
                        release_channel="stable",
                    ),
                ]
            )
            await setup.commit()

        async with sessions() as activate:
            await release_service.activate_release(activate, release.release_id)

        async with sessions() as check:
            captured = (
                (
                    await check.execute(
                        select(GuestReleaseTarget).where(
                            GuestReleaseTarget.release_id == release.release_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert {(row.host_id, row.role) for row in captured} == {
                ("compute-only", "storage"),
                ("storage-only", "storage"),
                ("combined", "chute"),
                ("combined", "storage"),
            }
            auto_opted = await check.get(Host, "compute-only")
            assert auto_opted.storage_enabled is True
            assert auto_opted.capacity == 0
            generations = (
                (
                    await check.execute(
                        select(GuestReleaseTargetTokenGeneration).where(
                            GuestReleaseTargetTokenGeneration.target_id.in_(
                                [row.target_id for row in captured]
                            )
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert {(row.target_id, row.generation, row.token_id) for row in generations} == {
                (row.target_id, 1, row.current_token_id) for row in captured
            }
            combined_manifest = await release_service.active_manifest_for_host(
                check,
                "sev-snp",
                "matrix",
                host_id="combined",
                miner_hotkey="miner",
            )
            assert set(combined_manifest.target_tokens) == {"chute", "storage"}
            auto_manifest = await release_service.active_manifest_for_host(
                check,
                "sev-snp",
                "matrix",
                host_id="compute-only",
                miner_hotkey="miner",
            )
            assert set(auto_manifest.target_tokens) == {"storage"}
            recovered_manifest = await release_service.active_manifest_for_host(
                check,
                "sev-snp",
                "matrix",
                host_id="compute-only",
                miner_hotkey="miner",
            )
            assert recovered_manifest.target_tokens == auto_manifest.target_tokens
            reissued_manifest = await release_service.active_manifest_for_host(
                check,
                "sev-snp",
                "matrix",
                host_id="compute-only",
                miner_hotkey="miner",
                reissue_roles={"storage"},
            )
            assert set(reissued_manifest.target_tokens) == {"storage"}
            assert (
                reissued_manifest.target_tokens["storage"] != auto_manifest.target_tokens["storage"]
            )
            refreshed = await server_service.register_host(
                check,
                HostRegistrationArgs(
                    host_id="compute-only",
                    name="compute-only",
                    capacity=1,
                    storage_enabled=False,
                    tee_type="sev-snp",
                    release_channel="matrix",
                ),
                "miner",
            )
            assert refreshed["capacity"] == 0
            refreshed_host = await check.get(Host, "compute-only")
            assert refreshed_host.storage_enabled is True
            assert refreshed_host.capacity == 0
            with pytest.raises(release_service.ReleaseError, match="another miner"):
                await release_service.active_manifest_for_host(
                    check,
                    "sev-snp",
                    "matrix",
                    host_id="combined",
                    miner_hotkey="attacker",
                )
            check.add(
                Host(
                    host_id="late-extra",
                    name="late-extra",
                    miner_hotkey="miner",
                    tee_type="sev-snp",
                    capacity=2,
                    storage_enabled=True,
                    release_channel="matrix",
                )
            )
            await check.commit()

        async with sessions() as reactivate:
            await release_service.activate_release(reactivate, release.release_id)
            captured = (
                (
                    await reactivate.execute(
                        select(GuestReleaseTarget).where(
                            GuestReleaseTarget.release_id == release.release_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert "late-extra" not in {row.host_id for row in captured}
    finally:
        await _drop_schema(schema, admin, engine)


async def test_release_target_token_reissues_for_reboot_and_preserves_audit():
    schema, admin, engine = await _create_schema_engine("release_target_rotation")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        now = datetime.now(timezone.utc)
        target = GuestReleaseTarget(
            target_id="target-token",
            release_id="release-token",
            host_id="logical-token-host",
            miner_hotkey="release-miner",
            tee_type="sev-snp",
            role="chute",
            current_generation=1,
            current_token_id="target-token-generation-1",
            issued_at=now,
        )
        generation = GuestReleaseTargetTokenGeneration(
            target_id=target.target_id,
            generation=1,
            token_id=target.current_token_id,
            issued_at=now,
        )
        async with sessions() as setup:
            setup.add(
                MetagraphNode(
                    hotkey="release-miner",
                    netuid=64,
                    checksum="checksum",
                    coldkey="release-coldkey",
                )
            )
            setup.add(
                Host(
                    host_id="logical-token-host",
                    name="logical-token-host",
                    miner_hotkey="release-miner",
                    netuid=64,
                    tee_type="sev-snp",
                    capacity=1,
                    release_channel="token",
                )
            )
            setup.add(
                GuestRelease(
                    release_id="release-token",
                    channel="token",
                    tee_type="sev-snp",
                    status="active",
                    images=_release_images(chute=True, storage=False),
                    targets_captured_at=now,
                )
            )
            setup.add_all(
                [
                    _server(
                        "token-server",
                        "logical-token-host",
                        cert_hash="token-cert-1",
                    ),
                    _attestation(
                        "token-server",
                        now,
                        attestation_id="att-token-1",
                    ),
                    target,
                    generation,
                ]
            )
            await setup.commit()

        async with sessions() as first:
            target = await first.get(GuestReleaseTarget, "target-token")
            token_1 = release_service._encode_release_target_token(target)
            (
                locked,
                locked_generation,
                release,
            ) = await release_service.resolve_release_target_token(
                first,
                token_1,
                host_id="logical-token-host",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
            )
            release_service.validate_release_target_attestation(
                locked,
                release,
                storage_role=False,
                measurement_name=CPU_NAMES[1],
                tee_type="sev-snp",
            )
            release_service.consume_release_target(
                locked,
                locked_generation,
                server=await first.get(Server, "token-server"),
                attestation=await first.get(ServerAttestation, "att-token-1"),
                cert_pubkey_hash="token-cert-1",
            )
            await first.commit()

        async with sessions() as replay:
            with pytest.raises(release_service.ReleaseError, match="already been consumed"):
                await release_service.resolve_release_target_token(
                    replay,
                    token_1,
                    host_id="logical-token-host",
                    miner_hotkey="release-miner",
                    tee_type="sev-snp",
                )

        async with sessions() as rotate:
            normal = await release_service.active_manifest_for_host(
                rotate,
                "sev-snp",
                "token",
                host_id="logical-token-host",
                miner_hotkey="release-miner",
            )
            assert normal.target_tokens == {}
            rotated = await release_service.active_manifest_for_host(
                rotate,
                "sev-snp",
                "token",
                host_id="logical-token-host",
                miner_hotkey="release-miner",
                reissue_roles={"chute"},
            )
            token_2 = rotated.target_tokens["chute"]
            assert token_2 != token_1
            assert release_service._decode_release_target_token(token_2)["generation"] == 2
            await rotate.commit()

        async with sessions() as inspect_reissue:
            current = await inspect_reissue.get(GuestReleaseTarget, "target-token")
            old_generation = await inspect_reissue.get(
                GuestReleaseTargetTokenGeneration,
                ("target-token", 1),
            )
            new_generation = await inspect_reissue.get(
                GuestReleaseTargetTokenGeneration,
                ("target-token", 2),
            )
            assert current.current_generation == 2
            assert current.consumed_at is None
            assert current.consumed_cert_pubkey_hash is None
            assert old_generation.invalidated_at is not None
            assert old_generation.consumed_cert_pubkey_hash == "token-cert-1"
            assert new_generation.consumed_at is None

        async with sessions() as stale:
            with pytest.raises(release_service.ReleaseError, match="stale"):
                await release_service.resolve_release_target_token(
                    stale,
                    token_1,
                    host_id="logical-token-host",
                    miner_hotkey="release-miner",
                    tee_type="sev-snp",
                )

        payload = release_service._decode_release_target_token(token_2)
        payload["release_id"] = "another-release"
        wrong_release_token = jwt.encode(
            payload,
            release_service.settings.launch_config_key,
            algorithm="HS256",
        )
        async with sessions() as wrong_release:
            with pytest.raises(release_service.ReleaseError, match="unknown release"):
                await release_service.resolve_release_target_token(
                    wrong_release,
                    wrong_release_token,
                    host_id="logical-token-host",
                    miner_hotkey="release-miner",
                    tee_type="sev-snp",
                )

        for storage_role, measurement_name, message in (
            (True, STORAGE_NAMES[1], "role"),
            (False, "cpu-baremetal-snp-genoa-9.9.9-2vcpu", "measurement"),
        ):
            async with sessions() as wrong_identity:
                (
                    locked,
                    _generation,
                    release,
                ) = await release_service.resolve_release_target_token(
                    wrong_identity,
                    token_2,
                    host_id="logical-token-host",
                    miner_hotkey="release-miner",
                    tee_type="sev-snp",
                )
                with pytest.raises(release_service.ReleaseError, match=message):
                    release_service.validate_release_target_attestation(
                        locked,
                        release,
                        storage_role=storage_role,
                        measurement_name=measurement_name,
                        tee_type="sev-snp",
                    )
                await wrong_identity.rollback()

        async with sessions() as reboot:
            server = await reboot.get(Server, "token-server")
            server.attested_cert_pubkey_hash = "token-cert-2"
            attestation = _attestation(
                "token-server",
                now + timedelta(seconds=1),
                attestation_id="att-token-2",
            )
            reboot.add(attestation)
            await reboot.flush()
            (
                locked,
                locked_generation,
                release,
            ) = await release_service.resolve_release_target_token(
                reboot,
                token_2,
                host_id="logical-token-host",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
            )
            release_service.validate_release_target_attestation(
                locked,
                release,
                storage_role=False,
                measurement_name=CPU_NAMES[1],
                tee_type="sev-snp",
            )
            release_service.consume_release_target(
                locked,
                locked_generation,
                server=server,
                attestation=attestation,
                cert_pubkey_hash="token-cert-2",
            )
            await reboot.commit()

        async with sessions() as audit:
            generations = (
                (
                    await audit.execute(
                        select(GuestReleaseTargetTokenGeneration)
                        .where(GuestReleaseTargetTokenGeneration.target_id == "target-token")
                        .order_by(GuestReleaseTargetTokenGeneration.generation)
                    )
                )
                .scalars()
                .all()
            )
            assert [row.generation for row in generations] == [1, 2]
            assert [row.consumed_cert_pubkey_hash for row in generations] == [
                "token-cert-1",
                "token-cert-2",
            ]
            current = await audit.get(GuestReleaseTarget, "target-token")
            assert current.current_generation == 2
            assert current.consumed_attestation_id == "att-token-2"
            assert current.consumed_cert_pubkey_hash == "token-cert-2"
    finally:
        await _drop_schema(schema, admin, engine)


async def test_release_target_token_concurrent_consumption_allows_exactly_one():
    schema, admin, engine = await _create_schema_engine("release_target_concurrent")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        now = datetime.now(timezone.utc)
        target = GuestReleaseTarget(
            target_id="target-concurrent",
            release_id="release-concurrent",
            host_id="logical-concurrent",
            miner_hotkey="release-miner",
            tee_type="sev-snp",
            role="chute",
            current_generation=1,
            current_token_id="target-concurrent-generation-1",
            issued_at=now,
        )
        async with sessions() as setup:
            setup.add(
                MetagraphNode(
                    hotkey="release-miner",
                    netuid=64,
                    checksum="checksum",
                    coldkey="release-coldkey",
                )
            )
            setup.add(
                GuestRelease(
                    release_id="release-concurrent",
                    channel="concurrent",
                    tee_type="sev-snp",
                    status="active",
                    images=_release_images(chute=True, storage=False),
                    targets_captured_at=now,
                )
            )
            setup.add_all(
                [
                    target,
                    GuestReleaseTargetTokenGeneration(
                        target_id=target.target_id,
                        generation=1,
                        token_id=target.current_token_id,
                        issued_at=now,
                    ),
                    _server("concurrent-a", "logical-concurrent", cert_hash="cert-a"),
                    _server("concurrent-b", "logical-concurrent", cert_hash="cert-b"),
                    _attestation(
                        "concurrent-a",
                        now,
                        attestation_id="att-concurrent-a",
                    ),
                    _attestation(
                        "concurrent-b",
                        now,
                        attestation_id="att-concurrent-b",
                    ),
                ]
            )
            await setup.commit()

        async with sessions() as token_session:
            target = await token_session.get(GuestReleaseTarget, "target-concurrent")
            token = release_service._encode_release_target_token(target)

        async def attempt(server_id: str, attestation_id: str, cert_hash: str) -> str:
            async with sessions() as session:
                try:
                    (
                        locked,
                        generation,
                        release,
                    ) = await release_service.resolve_release_target_token(
                        session,
                        token,
                        host_id="logical-concurrent",
                        miner_hotkey="release-miner",
                        tee_type="sev-snp",
                    )
                    release_service.validate_release_target_attestation(
                        locked,
                        release,
                        storage_role=False,
                        measurement_name=CPU_NAMES[1],
                        tee_type="sev-snp",
                    )
                    release_service.consume_release_target(
                        locked,
                        generation,
                        server=await session.get(Server, server_id),
                        attestation=await session.get(ServerAttestation, attestation_id),
                        cert_pubkey_hash=cert_hash,
                    )
                    await session.commit()
                    return "consumed"
                except release_service.ReleaseError:
                    await session.rollback()
                    return "rejected"

        results = await asyncio.gather(
            attempt("concurrent-a", "att-concurrent-a", "cert-a"),
            attempt("concurrent-b", "att-concurrent-b", "cert-b"),
        )
        assert sorted(results) == ["consumed", "rejected"]

        async with sessions() as check:
            generation = await check.get(
                GuestReleaseTargetTokenGeneration,
                ("target-concurrent", 1),
            )
            assert generation.consumed_attestation_id in {
                "att-concurrent-a",
                "att-concurrent-b",
            }
    finally:
        await _drop_schema(schema, admin, engine)


async def test_same_miner_launcher_can_transfer_another_logical_hosts_token_but_never_proves_physical():
    schema, admin, engine = await _create_schema_engine("release_target_transfer")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        now = datetime.now(timezone.utc)
        target = GuestReleaseTarget(
            target_id="target-logical-a",
            release_id="release-transfer",
            host_id="logical-a",
            miner_hotkey="same-miner",
            tee_type="sev-snp",
            role="chute",
            current_generation=1,
            current_token_id="target-logical-a-generation-1",
            issued_at=now,
        )
        transferred_server = _server(
            "transferred-server",
            # An L0 physically corresponding to logical-b can inject logical-a here.
            "logical-a",
            cert_hash="transferred-cert",
        )
        transferred_server.miner_hotkey = "same-miner"
        async with sessions() as setup:
            setup.add(
                MetagraphNode(
                    hotkey="same-miner",
                    netuid=64,
                    checksum="checksum",
                    coldkey="release-coldkey",
                )
            )
            setup.add(
                GuestRelease(
                    release_id="release-transfer",
                    channel="transfer",
                    tee_type="sev-snp",
                    status="active",
                    images=_release_images(chute=True, storage=False),
                    targets_captured_at=now,
                )
            )
            setup.add_all(
                [
                    Host(
                        host_id=host_id,
                        name=host_id,
                        miner_hotkey="same-miner",
                        netuid=64,
                        tee_type="sev-snp",
                        capacity=1,
                        release_channel="transfer",
                        staged_images={
                            "chute": {"sha256": CPU_SHA},
                            "roll_outcomes": {
                                "schema_version": 1,
                                "release_id": "release-transfer",
                                "roles": {
                                    "chute": {
                                        "sha256": CPU_SHA,
                                        "old_processes_exited": True,
                                        "new_process_reachable": False,
                                    }
                                },
                            },
                        },
                    )
                    for host_id in ("logical-a", "logical-b")
                ]
            )
            setup.add_all(
                [
                    target,
                    GuestReleaseTargetTokenGeneration(
                        target_id=target.target_id,
                        generation=1,
                        token_id=target.current_token_id,
                        issued_at=now,
                    ),
                    transferred_server,
                    _attestation(
                        "transferred-server",
                        now,
                        attestation_id="att-transferred",
                    ),
                ]
            )
            await setup.commit()

        async with sessions() as consume:
            # The API can authenticate only the shared miner, not which physical L0 made this request.
            # The same-miner logical-b launcher can therefore ask for logical-a's bearer token.
            manifest = await release_service.active_manifest_for_host(
                consume,
                "sev-snp",
                "transfer",
                host_id="logical-a",
                miner_hotkey="same-miner",
            )
            token = manifest.target_tokens["chute"]
            (
                locked,
                generation,
                release,
            ) = await release_service.resolve_release_target_token(
                consume,
                token,
                host_id="logical-a",
                miner_hotkey="same-miner",
                tee_type="sev-snp",
            )
            release_service.validate_release_target_attestation(
                locked,
                release,
                storage_role=False,
                measurement_name=CPU_NAMES[1],
                tee_type="sev-snp",
            )
            release_service.consume_release_target(
                locked,
                generation,
                server=await consume.get(Server, "transferred-server"),
                attestation=await consume.get(ServerAttestation, "att-transferred"),
                cert_pubkey_hash="transferred-cert",
            )
            await consume.commit()

        async def online(host_id: str) -> bool:
            return host_id in {"logical-a", "logical-b"}

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr("api.agent_channel.is_agent_online", online)
            async with sessions() as check:
                status_payload = await release_service.release_status(check, "release-transfer")
        assert status_payload["logical_rollout_converged"] is True, status_payload[
            "logical_rollout_targets"
        ]
        assert status_payload["logical_rollout_telemetry_only"] is True
        assert status_payload["logical_target_tokens_same_miner_transferable"] is True
        assert status_payload["logical_rollout_targets"][0]["same_miner_token_transferable"]
        assert status_payload["logical_rollout_targets"][0]["physical_placement_trusted"] is False
        assert status_payload["physical_host_convergence_proven"] is False
        assert status_payload["pin_pruning_safe"] is False
    finally:
        await _drop_schema(schema, admin, engine)


def _server(
    server_id,
    host_id,
    *,
    measurement_name=None,
    version=None,
    storage_role=False,
    tee_type="sev-snp",
    cert_hash=None,
):
    measurement_name = measurement_name or (STORAGE_NAMES[1] if storage_role else CPU_NAMES[1])
    version = version or ("1.6.1-storage-snp-2vcpu" if storage_role else "1.6.2-snp-2vcpu")
    config_fingerprint, trust_set_fingerprint = _trust_identity(measurement_name)
    return Server(
        server_id=server_id,
        ip=f"192.0.2.{abs(hash(server_id)) % 200 + 1}",
        miner_hotkey="release-miner",
        name=server_id,
        netuid=64,
        is_tee=True,
        compute_type="cpu",
        tee_type=tee_type,
        host_id=host_id,
        version=version,
        measurement_name=measurement_name,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
        self_registered=True,
        storage_role=storage_role,
        attested_cert_pubkey_hash=cert_hash or f"{server_id}-cert",
        storage_incarnation=(f"incarnation-{server_id}" if storage_role else None),
        storage_incarnation_announced_at=(datetime.now(timezone.utc) if storage_role else None),
    )


def _attestation(
    server_id,
    verified_at,
    *,
    measurement_name=None,
    measurement_version=None,
    storage_role=False,
    attestation_id=None,
):
    measurement_name = measurement_name or (STORAGE_NAMES[1] if storage_role else CPU_NAMES[1])
    measurement_version = measurement_version or (
        "1.6.1-storage-snp-2vcpu" if storage_role else "1.6.2-snp-2vcpu"
    )
    config_fingerprint, trust_set_fingerprint = _trust_identity(measurement_name)
    return ServerAttestation(
        attestation_id=attestation_id or f"att-{server_id}",
        server_id=server_id,
        quote_data="real-quote-placeholder",
        measurement_name=measurement_name,
        measurement_version=measurement_version,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
        created_at=verified_at,
        verified_at=verified_at,
    )


def _trust_identity(measurement_name):
    measurements = release_service.settings.tee_measurements
    trust_set_fingerprint = measurement_trust_set_fingerprint(measurements)
    config = next(
        (measurement for measurement in measurements if measurement.name == measurement_name),
        None,
    )
    return (
        measurement_config_fingerprint(config) if config is not None else "0" * 64,
        trust_set_fingerprint,
    )


async def test_status_uses_exact_one_use_logical_targets_and_never_guest_host_id(
    monkeypatch,
):
    schema, admin, engine = await _create_schema_engine("release_status")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        now = datetime.now(timezone.utc)
        stale = now - timedelta(
            seconds=release_service.settings.release_attestation_max_age_seconds + 1
        )

        releases = [
            GuestRelease(
                release_id="release-both",
                channel="both",
                tee_type="sev-snp",
                status="active",
                images=_release_images(chute=True, storage=True),
                targets_captured_at=now,
            ),
            GuestRelease(
                release_id="release-incomplete",
                channel="incomplete",
                tee_type="sev-snp",
                status="active",
                images=_release_images(chute=True, storage=True),
                targets_captured_at=now,
            ),
            GuestRelease(
                release_id="release-chute-only",
                channel="chute-only",
                tee_type="sev-snp",
                status="active",
                images=_release_images(chute=True, storage=False),
                targets_captured_at=now,
            ),
        ]
        hosts = [
            Host(
                host_id=host_id,
                name=host_id,
                miner_hotkey="release-miner",
                netuid=64,
                tee_type="sev-snp",
                capacity=4,
                storage_enabled=True,
                release_channel=channel,
                staged_images={
                    "chute": {"sha256": CPU_SHA},
                    "storage": {"sha256": STORAGE_SHA},
                    "roll_outcomes": {
                        "schema_version": 1,
                        "release_id": f"release-{channel}",
                        "roles": {
                            "chute": {
                                "sha256": CPU_SHA,
                                "old_processes_exited": True,
                                "new_process_reachable": False,
                            },
                            **(
                                {
                                    "storage": {
                                        "sha256": STORAGE_SHA,
                                        "old_processes_exited": True,
                                        "new_process_reachable": True,
                                    }
                                }
                                if channel != "chute-only"
                                else {}
                            ),
                        },
                    },
                },
            )
            for host_id, channel in (
                ("logical-a", "both"),
                ("logical-b", "incomplete"),
                ("logical-c", "chute-only"),
            )
        ]
        servers = [
            # Consumed targets deliberately carry spoofed guest host IDs. Target rows, token
            # consumption, exact quote identity, and certificate continuity are the trusted path.
            _server("cpu-a", "spoofed-physical-a", cert_hash="cert-cpu-a"),
            _server(
                "storage-a",
                "spoofed-physical-a",
                storage_role=True,
                cert_hash="cert-storage-a",
            ),
            # Extra exact TDs cannot satisfy the two unseen logical-b targets.
            _server("duplicate-cpu", "logical-b", cert_hash="cert-duplicate-cpu"),
            _server(
                "duplicate-storage",
                "logical-b",
                storage_role=True,
                cert_hash="cert-duplicate-storage",
            ),
            _server("cpu-c", "another-spoof", cert_hash="cert-cpu-c"),
            _server(
                "old-cpu",
                "logical-a",
                measurement_name="cpu-baremetal-snp-genoa-1.5.0-2vcpu",
                version="1.5.0-snp-2vcpu",
            ),
            _server(
                "old-storage",
                "logical-c",
                measurement_name="storage-baremetal-snp-genoa-1.5.0-2vcpu",
                version="1.5.0-storage-snp-2vcpu",
                storage_role=True,
            ),
        ]
        attestations = [
            _attestation("cpu-a", now, attestation_id="att-cpu-a"),
            _attestation(
                "storage-a",
                now,
                storage_role=True,
                attestation_id="att-storage-a",
            ),
            _attestation(
                "duplicate-cpu",
                now,
                attestation_id="att-duplicate-cpu",
            ),
            _attestation(
                "duplicate-storage",
                now,
                storage_role=True,
                attestation_id="att-duplicate-storage",
            ),
            _attestation("cpu-c", now, attestation_id="att-cpu-c"),
            _attestation(
                "old-cpu",
                now,
                measurement_name="cpu-baremetal-snp-genoa-1.5.0-2vcpu",
                measurement_version="1.5.0-snp-2vcpu",
                attestation_id="att-old-cpu",
            ),
            _attestation(
                "old-storage",
                stale,
                measurement_name="storage-baremetal-snp-genoa-1.5.0-2vcpu",
                measurement_version="1.5.0-storage-snp-2vcpu",
                storage_role=True,
                attestation_id="att-old-storage",
            ),
        ]
        cpu_config_fingerprint, trust_set_fingerprint = _trust_identity(CPU_NAMES[1])
        storage_config_fingerprint, _ = _trust_identity(STORAGE_NAMES[1])
        targets = [
            GuestReleaseTarget(
                target_id="target-both-chute",
                release_id="release-both",
                host_id="logical-a",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
                role="chute",
                issued_at=now,
                consumed_at=now,
                consumed_server_id="cpu-a",
                consumed_attestation_id="att-cpu-a",
                consumed_cert_pubkey_hash="cert-cpu-a",
                consumed_measurement_name=CPU_NAMES[1],
                consumed_measurement_version="1.6.2-snp-2vcpu",
                consumed_measurement_config_fingerprint=cpu_config_fingerprint,
                consumed_trust_set_fingerprint=trust_set_fingerprint,
            ),
            GuestReleaseTarget(
                target_id="target-both-storage",
                release_id="release-both",
                host_id="logical-a",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
                role="storage",
                issued_at=now,
                consumed_at=now,
                consumed_server_id="storage-a",
                consumed_attestation_id="att-storage-a",
                consumed_cert_pubkey_hash="cert-storage-a",
                consumed_measurement_name=STORAGE_NAMES[1],
                consumed_measurement_version="1.6.1-storage-snp-2vcpu",
                consumed_measurement_config_fingerprint=storage_config_fingerprint,
                consumed_trust_set_fingerprint=trust_set_fingerprint,
            ),
            GuestReleaseTarget(
                target_id="target-incomplete-chute",
                release_id="release-incomplete",
                host_id="logical-b",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
                role="chute",
                issued_at=now,
            ),
            GuestReleaseTarget(
                target_id="target-incomplete-storage",
                release_id="release-incomplete",
                host_id="logical-b",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
                role="storage",
                issued_at=now,
            ),
            GuestReleaseTarget(
                target_id="target-chute-only",
                release_id="release-chute-only",
                host_id="logical-c",
                miner_hotkey="release-miner",
                tee_type="sev-snp",
                role="chute",
                issued_at=now,
                consumed_at=now,
                consumed_server_id="cpu-c",
                consumed_attestation_id="att-cpu-c",
                consumed_cert_pubkey_hash="cert-cpu-c",
                consumed_measurement_name=CPU_NAMES[1],
                consumed_measurement_version="1.6.2-snp-2vcpu",
                consumed_measurement_config_fingerprint=cpu_config_fingerprint,
                consumed_trust_set_fingerprint=trust_set_fingerprint,
            ),
        ]
        async with sessions() as setup:
            setup.add(
                MetagraphNode(
                    hotkey="release-miner",
                    netuid=64,
                    checksum="checksum",
                    coldkey="release-coldkey",
                )
            )
            setup.add_all(releases + hosts + servers + attestations + targets)
            await setup.commit()

        online = {"logical-a": True, "logical-b": True, "logical-c": True}
        monkeypatch.setattr(
            "api.agent_channel.is_agent_online",
            AsyncMock(side_effect=lambda host_id: online.get(host_id, False)),
        )
        async with sessions() as session:
            # A fresh old chute measurement blocks pruning even though both exact role targets are
            # token-consumed and guest host IDs are spoofed.
            blocked = await release_service.release_status(session, "release-both")
            ReleaseStatusResponse.model_validate(blocked)
            assert blocked["logical_target_counts"] == {"chute": 1, "storage": 1}
            assert blocked["logical_target_completed_counts"] == {
                "chute": 1,
                "storage": 1,
            }, blocked["logical_rollout_targets"]
            assert blocked["logical_rollout_converged"] is True
            assert blocked["fresh_relevant_attestations_not_on_release"] == 1
            assert blocked["pin_pruning_safe"] is False
            assert blocked["physical_host_convergence_proven"] is False

            old_cpu = await session.get(ServerAttestation, "att-old-cpu")
            old_cpu.created_at = stale
            old_cpu.verified_at = stale
            await session.commit()
            exact = await release_service.release_status(session, "release-both")
            assert exact["logical_rollout_converged"] is True
            assert exact["fresh_relevant_attestations_not_on_release"] == 0
            assert exact["logical_rollout_telemetry_only"] is True
            assert exact["logical_target_tokens_same_miner_transferable"] is True
            assert exact["physical_host_convergence_proven"] is False
            assert exact["pin_pruning_safe"] is False
            assert all(
                row["same_miner_token_transferable"] and not row["physical_placement_trusted"]
                for row in exact["logical_rollout_targets"]
            )
            exact_by_role = {row["role"]: row for row in exact["logical_rollout_targets"]}
            assert exact_by_role["chute"]["running_image_sha256"] == CPU_SHA
            assert exact_by_role["chute"]["running_image_version"] == "1.6.2"
            assert exact_by_role["chute"]["running_process_incarnation"] == "cert-cpu-a"
            assert exact_by_role["chute"]["running_storage_incarnation"] is None
            assert exact_by_role["storage"]["running_image_sha256"] == STORAGE_SHA
            assert exact_by_role["storage"]["running_image_version"] == "1.6.1"
            assert exact_by_role["storage"]["running_process_incarnation"] == "cert-storage-a"
            assert (
                exact_by_role["storage"]["running_storage_incarnation"] == "incarnation-storage-a"
            )
            assert all(
                row["exact_staged_digest"]
                and row["old_process_exit_confirmed"]
                and row["fresh_role_health"]
                for row in exact_by_role.values()
            )

            logical_a = await session.get(Host, "logical-a")
            original_staged = logical_a.staged_images
            logical_a.staged_images = {
                **original_staged,
                "chute": {"sha256": "0" * 64},
            }
            await session.commit()
            wrong_stage = await release_service.release_status(session, "release-both")
            assert wrong_stage["logical_rollout_converged"] is False
            assert any(
                not row["exact_staged_digest"]
                for row in wrong_stage["logical_rollout_targets"]
                if row["role"] == "chute"
            )

            logical_a.staged_images = {
                **original_staged,
                "roll_outcomes": {
                    **original_staged["roll_outcomes"],
                    "roles": {
                        **original_staged["roll_outcomes"]["roles"],
                        "chute": {
                            **original_staged["roll_outcomes"]["roles"]["chute"],
                            "old_processes_exited": False,
                        },
                    },
                },
            }
            await session.commit()
            old_still_running = await release_service.release_status(session, "release-both")
            assert old_still_running["logical_rollout_converged"] is False
            assert any(
                not row["old_process_exit_confirmed"]
                for row in old_still_running["logical_rollout_targets"]
                if row["role"] == "chute"
            )

            logical_a.staged_images = original_staged
            storage_a = await session.get(Server, "storage-a")
            original_announced_at = storage_a.storage_incarnation_announced_at
            storage_a.storage_incarnation_announced_at = now - timedelta(seconds=1)
            await session.commit()
            stale_storage_health = await release_service.release_status(session, "release-both")
            assert stale_storage_health["logical_rollout_converged"] is False
            assert any(
                not row["fresh_role_health"]
                for row in stale_storage_health["logical_rollout_targets"]
                if row["role"] == "storage"
            )
            storage_a.storage_incarnation_announced_at = original_announced_at
            await session.commit()

            # Offline captured targets remain incomplete even with fresh exact attestations.
            online["logical-a"] = False
            offline = await release_service.release_status(session, "release-both")
            assert offline["all_logical_targets_healthy"] is False
            assert offline["logical_rollout_converged"] is False
            assert offline["pin_pruning_safe"] is False
            online["logical-a"] = True

            # Two arbitrary exact duplicate TDs cannot fill the immutable unseen target rows.
            incomplete = await release_service.release_status(session, "release-incomplete")
            assert incomplete["trusted_attestations_on_release"] >= 2
            assert incomplete["logical_target_counts"] == {"chute": 1, "storage": 1}
            assert incomplete["logical_target_completed_counts"] == {
                "chute": 0,
                "storage": 0,
            }
            assert incomplete["logical_rollout_converged"] is False
            assert incomplete["pin_pruning_safe"] is False

            # Make an old storage attestation fresh. A chute-only release preserves and ignores the
            # omitted storage role, but logical completion still cannot authorize pin pruning.
            old_storage = await session.get(ServerAttestation, "att-old-storage")
            old_storage.created_at = now
            old_storage.verified_at = now
            await session.commit()
            chute_only = await release_service.release_status(session, "release-chute-only")
            assert chute_only["required_roles"] == ["chute"]
            assert chute_only["logical_target_counts"] == {"chute": 1}
            assert chute_only["logical_target_completed_counts"] == {"chute": 1}
            assert chute_only["fresh_relevant_attestations_not_on_release"] == 0
            assert chute_only["logical_rollout_converged"] is True
            assert chute_only["physical_host_convergence_proven"] is False
            assert chute_only["pin_pruning_safe"] is False
    finally:
        await _drop_schema(schema, admin, engine)
