"""Real PostgreSQL ordering proof for attributable attestation attempts."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import asyncpg
import pytest


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for attestation sequence tests",
    ),
]
MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "api/migrations/20260714070000_release_attestation_identity.sql"
)
SEEDLESS_MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "api/migrations/20260720200000_seedless_model_b.sql"
)


@pytest.fixture(autouse=True)
def nv_attest():
    yield


def _database_url() -> str:
    assert TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")


async def test_sequence_backfill_and_reverse_commit_keep_latest_attempt_authoritative():
    schema = f"attestation_sequence_{uuid.uuid4().hex}"
    admin = await asyncpg.connect(_database_url())
    first = None
    second = None
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        await admin.execute(f'SET search_path TO "{schema}"')
        await admin.execute(
            """
            CREATE TABLE guest_releases (
                release_id VARCHAR PRIMARY KEY,
                tee_type VARCHAR NOT NULL,
                channel VARCHAR NOT NULL
            );
            CREATE TABLE hosts (
                host_id VARCHAR PRIMARY KEY
            );
            CREATE TABLE servers (
                server_id VARCHAR PRIMARY KEY,
                miner_hotkey VARCHAR NOT NULL,
                compute_type VARCHAR NOT NULL,
                tee_type VARCHAR NOT NULL
            );
            CREATE TABLE server_attestations (
                attestation_id VARCHAR PRIMARY KEY,
                server_id VARCHAR NOT NULL
                    REFERENCES servers(server_id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ,
                measurement_version VARCHAR,
                verification_error VARCHAR,
                verified_at TIMESTAMPTZ
            );
            CREATE TABLE boot_attestations (
                attestation_id VARCHAR PRIMARY KEY
            );
            INSERT INTO servers(server_id, miner_hotkey, compute_type, tee_type) VALUES
                ('server-1', 'owner-1', 'cpu', 'tdx'),
                ('tie-failure', 'owner-2', 'cpu', 'sev-snp'),
                ('tie-success', 'owner-3', 'gpu', 'tdx'),
                ('null-tie', 'owner-4', 'gpu', 'tdx');
            INSERT INTO server_attestations(
                attestation_id, server_id, created_at, verification_error, verified_at
            ) VALUES
                ('legacy-old', 'server-1', '2025-01-01T00:00:00Z', NULL, now()),
                ('legacy-a', 'server-1', '2026-01-01T00:00:00Z', NULL, now()),
                ('legacy-b', 'server-1', '2026-01-01T00:00:00Z', 'failed', NULL),
                ('a-success', 'tie-failure', '2026-02-01T00:00:00Z', NULL, now()),
                ('z-failure', 'tie-failure', '2026-02-01T00:00:00Z', 'failed', NULL),
                ('a-failure', 'tie-success', '2026-03-01T00:00:00Z', 'failed', NULL),
                ('z-success', 'tie-success', '2026-03-01T00:00:00Z', NULL, now()),
                ('a-null-failure', 'null-tie', NULL, 'failed', NULL),
                ('z-null-success', 'null-tie', NULL, NULL, now());
            """
        )
        legacy_sequence_order = [
            row["attestation_id"]
            for row in await admin.fetch(
                "SELECT attestation_id FROM server_attestations "
                "ORDER BY created_at ASC NULLS LAST, attestation_id ASC"
            )
        ]
        legacy_latest = {
            server_id: await admin.fetchval(
                "SELECT attestation_id FROM server_attestations "
                "WHERE server_id = $1 "
                "ORDER BY created_at DESC NULLS FIRST, attestation_id DESC LIMIT 1",
                server_id,
            )
            for server_id in (
                "server-1",
                "tie-failure",
                "tie-success",
                "null-tie",
            )
        }

        up = MIGRATION.read_text(encoding="utf-8").split("-- migrate:down", 1)[0]
        await admin.execute(up)
        migrated_order = [
            row["attestation_id"]
            for row in await admin.fetch(
                "SELECT attestation_id FROM server_attestations "
                "ORDER BY attempt_sequence"
            )
        ]
        assert migrated_order == legacy_sequence_order
        for server_id, expected_id in legacy_latest.items():
            assert (
                await admin.fetchval(
                    "SELECT attestation_id FROM server_attestations "
                    "WHERE server_id = $1 ORDER BY attempt_sequence DESC LIMIT 1",
                    server_id,
                )
                == expected_id
            )
        assert legacy_latest == {
            "server-1": "legacy-b",
            "tie-failure": "z-failure",
            "tie-success": "z-success",
            "null-tie": "z-null-success",
        }
        subjects = await admin.fetch(
            "SELECT server_id, owner_hotkey, compute_type, tee_type, deployment_model "
            "FROM server_attestation_subjects ORDER BY server_id"
        )
        assert [tuple(row.values()) for row in subjects] == [
            ("null-tie", "owner-4", "gpu", "tdx", "gpu"),
            ("server-1", "owner-1", "cpu", "tdx", "cpu-model-a"),
            ("tie-failure", "owner-2", "cpu", "sev-snp", "cpu-model-a"),
            ("tie-success", "owner-3", "gpu", "tdx", "gpu"),
        ]

        first = await asyncpg.connect(_database_url())
        second = await asyncpg.connect(_database_url())
        await first.execute(f'SET search_path TO "{schema}"')
        await second.execute(f'SET search_path TO "{schema}"')
        first_tx = first.transaction()
        second_tx = second.transaction()
        await first_tx.start()
        first_sequence = await first.fetchval(
            "INSERT INTO server_attestations("
            "attestation_id, server_id, created_at, verification_error, verified_at"
            ") VALUES ('older-success', 'server-1', now(), NULL, now()) "
            "RETURNING attempt_sequence"
        )
        await second_tx.start()
        second_sequence = await second.fetchval(
            "INSERT INTO server_attestations("
            "attestation_id, server_id, created_at, verification_error, verified_at"
            ") VALUES ('newer-failure', 'server-1', now(), 'quote failed', NULL) "
            "RETURNING attempt_sequence"
        )
        assert first_sequence < second_sequence

        # Commit the newer failure first. Once both transactions are visible,
        # allocation order—not wall time or commit inversion—remains authoritative.
        await second_tx.commit()
        await first_tx.commit()
        latest = await admin.fetchrow(
            "SELECT attestation_id, verification_error "
            "FROM server_attestations WHERE server_id = 'server-1' "
            "ORDER BY attempt_sequence DESC LIMIT 1"
        )
        assert latest["attestation_id"] == "newer-failure"
        assert latest["verification_error"] == "quote failed"

        # Two old binaries can concurrently submit the first attestation for a newly registered
        # server. The loser of the subject INSERT waits, reselects the winner, and validates the
        # exact immutable identity instead of failing on the primary-key race.
        await admin.execute(
            "INSERT INTO servers(server_id, miner_hotkey, compute_type, tee_type) "
            "VALUES ('race-server', 'race-owner', 'cpu', 'tdx')"
        )
        race_first_tx = first.transaction()
        race_second_tx = second.transaction()
        await race_first_tx.start()
        first_race_sequence = await first.fetchval(
            "INSERT INTO server_attestations("
            "attestation_id, server_id, created_at, verification_error, verified_at"
            ") VALUES ('race-first', 'race-server', now(), NULL, now()) "
            "RETURNING attempt_sequence"
        )
        await race_second_tx.start()
        second_insert = asyncio.create_task(
            second.fetchval(
                "INSERT INTO server_attestations("
                "attestation_id, server_id, created_at, verification_error, verified_at"
                ") VALUES ('race-second', 'race-server', now(), 'failed', NULL) "
                "RETURNING attempt_sequence"
            )
        )
        await asyncio.sleep(0.05)
        assert not second_insert.done()
        await race_first_tx.commit()
        second_race_sequence = await asyncio.wait_for(second_insert, timeout=5)
        await race_second_tx.commit()
        assert first_race_sequence < second_race_sequence
        assert (
            await admin.fetchval(
                "SELECT count(*) FROM server_attestation_subjects "
                "WHERE server_id = 'race-server' AND owner_hotkey = 'race-owner'"
            )
            == 1
        )

        # Pending-to-terminal audit fields remain mutable, but the row identity and chronology do
        # not. This covers both PK-based and time-based attempts to reorder immutable history.
        await admin.execute(
            "UPDATE server_attestations SET verification_error = 'terminal failure', "
            "verified_at = NULL WHERE attestation_id = 'race-first'"
        )
        with pytest.raises(asyncpg.PostgresError, match="audit identity is immutable"):
            await admin.execute(
                "UPDATE server_attestations SET attestation_id = 'race-renamed' "
                "WHERE attestation_id = 'race-first'"
            )
        with pytest.raises(asyncpg.PostgresError, match="audit identity is immutable"):
            await admin.execute(
                "UPDATE server_attestations SET created_at = created_at + interval '1 second' "
                "WHERE attestation_id = 'race-first'"
            )

        # Legacy ORM delete-orphan behavior issues child DELETEs before deleting Server. The DB
        # keeps those immutable rows as no-ops while allowing the operational parent to disappear.
        await admin.execute(
            "DELETE FROM server_attestations WHERE attestation_id = 'legacy-old'"
        )
        assert (
            await admin.fetchval(
                "SELECT count(*) FROM server_attestations "
                "WHERE attestation_id = 'legacy-old'"
            )
            == 1
        )
        await admin.execute("DELETE FROM servers WHERE server_id = 'tie-failure'")
        assert (
            await admin.fetchval(
                "SELECT count(*) FROM server_attestations WHERE server_id = 'tie-failure'"
            )
            == 2
        )

        # The next unshipped migration accepts the legacy-upgraded catalog, and both migrations
        # accept their own exact final catalog on re-entry without duplicating authority.
        seedless_up = SEEDLESS_MIGRATION.read_text(encoding="utf-8").split(
            "-- migrate:down", 1
        )[0]
        await admin.execute(seedless_up)
        await admin.execute(up)
        await admin.execute(seedless_up)
        attribution_constraints = {
            row["conname"]: row["definition"]
            for row in await admin.fetch(
                "SELECT conname, pg_get_constraintdef(oid, true) AS definition "
                "FROM pg_constraint "
                "WHERE conrelid = 'server_attestations'::regclass "
                "AND conname IN ("
                "'ck_server_attestation_attribution', "
                "'fk_server_attestations_attribution_owner', "
                "'fk_server_attestations_td_reservation_attribution')"
            )
        }
        assert set(attribution_constraints) == {
            "ck_server_attestation_attribution",
            "fk_server_attestations_attribution_owner",
            "fk_server_attestations_td_reservation_attribution",
        }
        assert (
            await admin.fetchval(
                "SELECT count(*) FROM pg_constraint "
                "WHERE conrelid = 'td_launch_reservations'::regclass "
                "AND conname = 'uq_td_launch_reservation_attribution' "
                "AND contype = 'u'"
            )
            == 1
        )
        assert await admin.fetchval(
            "SELECT bool_and(format_type(atttypid, atttypmod) = 'character varying') "
            "FROM pg_attribute WHERE attrelid = 'server_attestations'::regclass "
            "AND attname IN ('attribution_reservation_id', 'attribution_owner_hotkey')"
        )
    finally:
        if first is not None:
            await first.close()
        if second is not None:
            await second.close()
        await admin.execute("SET search_path TO public")
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()
