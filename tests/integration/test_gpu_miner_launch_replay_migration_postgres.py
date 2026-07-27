"""Migration parity and guarded rollback for miner launch replay state."""

from __future__ import annotations

from tests.integration.test_gpu_migration_guards_postgres import (
    _apply,
    _assert_guard_rejects_without_changes,
    _create_schema,
    _drop_schema,
    _migration,
    _psql,
    nv_attest as nv_attest,
)


MIGRATION = "20260727130000_gpu_miner_launch_replay.sql"
PREDECESSOR = """
CREATE TABLE launch_configs (
    config_id TEXT PRIMARY KEY,
    miner_hotkey TEXT NOT NULL
);
"""


def test_miner_launch_replay_migration_round_trips_predecessor_schema():
    schema = _create_schema("miner_launch_replay", PREDECESSOR)
    try:
        up, down = _migration(MIGRATION)
        applied = _apply(up, schema)
        assert applied.returncode == 0, applied.stderr.decode()
        catalog = _psql(
            """
            SELECT column_name || '|' || data_type || '|' ||
                   COALESCE(character_maximum_length::text, '')
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'launch_configs'
               AND column_name LIKE 'miner_launch_request%'
             ORDER BY column_name;
            SELECT indexname
              FROM pg_indexes
             WHERE schemaname = current_schema()
               AND indexname = 'uq_launch_configs_miner_request';
            SELECT tgname
              FROM pg_trigger
             WHERE tgrelid = 'launch_configs'::regclass
               AND NOT tgisinternal
               AND tgname = 'trg_miner_launch_request_immutable';
            """,
            schema,
        )
        assert catalog.returncode == 0, catalog.stderr.decode()
        assert b"miner_launch_request_id|character varying|36" in catalog.stdout
        assert b"miner_launch_request_sha256|character varying|64" in catalog.stdout
        assert b"uq_launch_configs_miner_request" in catalog.stdout
        assert b"trg_miner_launch_request_immutable" in catalog.stdout

        rolled_back = _apply(down, schema)
        assert rolled_back.returncode == 0, rolled_back.stderr.decode()
        remaining = _psql(
            """
            SELECT COUNT(*)
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'launch_configs'
               AND column_name LIKE 'miner_launch_request%';
            """,
            schema,
        )
        assert remaining.stdout.strip() == b"0"
    finally:
        _drop_schema(schema)


def test_miner_launch_replay_down_guard_is_scoped_and_catalog_preserving():
    schema = _create_schema("miner_launch_replay_guard", PREDECESSOR)
    try:
        up, _down = _migration(MIGRATION)
        applied = _apply(up, schema)
        assert applied.returncode == 0, applied.stderr.decode()
        inserted = _psql(
            """
            INSERT INTO launch_configs(
                config_id,
                miner_hotkey,
                miner_launch_request_id,
                miner_launch_request_sha256
            ) VALUES (
                'config-1',
                'miner-1',
                '44444444-4444-4444-8444-444444444444',
                repeat('a', 64)
            );
            """,
            schema,
        )
        assert inserted.returncode == 0, inserted.stderr.decode()
        _assert_guard_rejects_without_changes(
            schema,
            MIGRATION,
            ("launch_configs",),
            b"cannot discard durable miner launch response replay state",
        )

        immutable = _psql(
            """
            UPDATE launch_configs
               SET miner_launch_request_sha256 = repeat('b', 64)
             WHERE config_id = 'config-1';
            """,
            schema,
        )
        assert immutable.returncode != 0
        assert b"miner launch request identity is immutable" in immutable.stderr
    finally:
        _drop_schema(schema)
