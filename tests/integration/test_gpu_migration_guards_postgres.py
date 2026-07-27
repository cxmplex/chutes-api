"""Real-PostgreSQL evidence for GPU migration guards and lock ordering.

These fixtures describe the deployed predecessor shape needed by each migration.
They intentionally do not use ``Base.metadata.create_all()``: that path is covered
separately, and using the current ORM here would hide predecessor-schema failures.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import uuid
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

import asyncpg
import pytest


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for GPU migration guard tests",
)
MIGRATIONS = Path(__file__).resolve().parents[2] / "api/migrations"
LIFECYCLE_PREFLIGHT = (
    Path(__file__).resolve().parents[2]
    / "scripts/preflight_gpu_lifecycle_migration.sql"
)

PLATFORM = "20260724100000_gpu_platform_scheduler.sql"
REGISTRY = "20260724100500_registry_launch_scope.sql"
CHUTEFS = "20260724234500_gpu_chutefs_default_volume.sql"
LIFECYCLE = "20260725120000_gpu_lifecycle_durability.sql"
ROTATION = "20260726121000_chutefs_session_rotation_replay.sql"


@pytest.fixture(autouse=True)
def nv_attest():
    yield


def _psql(sql: str, schema: str) -> subprocess.CompletedProcess:
    parsed = urlsplit(TEST_DATABASE_URL.replace("+asyncpg", ""))
    url = f"postgresql://{parsed.username}@{parsed.hostname}:{parsed.port}{parsed.path}"
    return subprocess.run(
        ["psql", url, "-v", "ON_ERROR_STOP=1", "-A", "-t"],
        input=sql.encode(),
        capture_output=True,
        env={
            **os.environ,
            "PGPASSWORD": parsed.password or "",
            "PGOPTIONS": f"-c search_path={schema}",
        },
        check=False,
    )


def _migration(name: str) -> tuple[str, str]:
    return (MIGRATIONS / name).read_text(encoding="utf-8").split(
        "-- migrate:down",
        1,
    )


def _create_schema(prefix: str, ddl: str) -> str:
    schema = f"{prefix}_{uuid.uuid4().hex}"
    created = _psql(f'CREATE SCHEMA "{schema}";', "public")
    assert created.returncode == 0, created.stderr.decode()
    predecessor = _psql(ddl, schema)
    if predecessor.returncode != 0:
        _drop_schema(schema)
    assert predecessor.returncode == 0, predecessor.stderr.decode()
    return schema


def _drop_schema(schema: str) -> None:
    dropped = _psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;', "public")
    assert dropped.returncode == 0, dropped.stderr.decode()


def _apply(sql: str, schema: str) -> subprocess.CompletedProcess:
    return _psql(f"BEGIN;\n{sql}\nCOMMIT;", schema)


def _snapshot(schema: str, tables: Iterable[str]) -> str:
    table_names = tuple(sorted(tables))
    quoted_tables = ", ".join(f"'{name}'" for name in table_names)
    catalog = _psql(
        f"""
        SELECT 'column|' || table_name || '|' || ordinal_position || '|' ||
               column_name || '|' || data_type || '|' || is_nullable || '|' ||
               COALESCE(column_default, '')
          FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name IN ({quoted_tables})
         ORDER BY table_name, ordinal_position;
        SELECT 'constraint|' || relation.relname || '|' || constraint_row.conname ||
               '|' || pg_get_constraintdef(constraint_row.oid, true)
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
         WHERE constraint_row.connamespace = current_schema()::regnamespace
           AND relation.relname IN ({quoted_tables})
         ORDER BY relation.relname, constraint_row.conname;
        SELECT 'index|' || tablename || '|' || indexname || '|' || indexdef
          FROM pg_indexes
         WHERE schemaname = current_schema()
           AND tablename IN ({quoted_tables})
         ORDER BY tablename, indexname;
        SELECT 'trigger|' || relation.relname || '|' || trigger_row.tgname || '|' ||
               pg_get_triggerdef(trigger_row.oid, true)
          FROM pg_trigger AS trigger_row
          JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
         WHERE NOT trigger_row.tgisinternal
           AND relation.relnamespace = current_schema()::regnamespace
           AND relation.relname IN ({quoted_tables})
         ORDER BY relation.relname, trigger_row.tgname;
        """,
        schema,
    )
    assert catalog.returncode == 0, catalog.stderr.decode()
    parts = [catalog.stdout]
    for table in table_names:
        rows = _psql(
            f"""
            SELECT COALESCE(
                jsonb_agg(to_jsonb(row_value) ORDER BY to_jsonb(row_value)::text),
                '[]'::jsonb
            )
              FROM {table} AS row_value;
            """,
            schema,
        )
        assert rows.returncode == 0, rows.stderr.decode()
        parts.append(table.encode() + b"\n" + rows.stdout)
    return hashlib.sha256(b"\n".join(parts)).hexdigest()


def _assert_guard_rejects_without_changes(
    schema: str,
    migration: str,
    tables: Iterable[str],
    expected_message: bytes,
) -> None:
    before = _snapshot(schema, tables)
    _up, down = _migration(migration)
    rejected = _apply(down, schema)
    assert rejected.returncode != 0
    assert expected_message in rejected.stderr
    assert _snapshot(schema, tables) == before


PLATFORM_PREDECESSOR = """
CREATE TABLE guest_releases (release_id TEXT PRIMARY KEY);
CREATE TABLE gpu_allocation_groups (allocation_group_id TEXT PRIMARY KEY);
CREATE TABLE gpu_launch_reservations (
    reservation_id TEXT PRIMARY KEY,
    management_mode TEXT NOT NULL,
    chute_id TEXT,
    job_id TEXT,
    state TEXT NOT NULL
);
CREATE TABLE jobs (job_id TEXT PRIMARY KEY);
CREATE TABLE launch_configs (
    config_id TEXT PRIMARY KEY,
    server_id TEXT,
    job_id TEXT REFERENCES jobs(job_id),
    failed_at TIMESTAMP,
    verification_error TEXT,
    CONSTRAINT uq_job_launch_config UNIQUE (job_id)
);
CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    server_id TEXT
);
CREATE TABLE registry_sessions (session_id TEXT PRIMARY KEY);
CREATE TABLE server_attestations (
    attestation_id TEXT PRIMARY KEY,
    verification_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE servers (
    server_id TEXT PRIMARY KEY,
    gpu_launch_reservation_id TEXT
);
"""


REGISTRY_PREDECESSOR = """
CREATE TABLE launch_configs (
    config_id TEXT PRIMARY KEY,
    server_id TEXT,
    gpu_management_mode TEXT,
    failed_at TIMESTAMP,
    verification_error TEXT,
    job_id TEXT
);
CREATE TABLE registry_sessions (
    session_id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    repository TEXT,
    manifest_digest TEXT,
    allowed_manifests JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_blobs JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_manifest_tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    descriptor_closure_sha256 TEXT,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT uq_registry_session_server UNIQUE (server_id)
);
CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    config_id TEXT,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_error TEXT,
    stop_billing_at TIMESTAMP
);
CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    finished_at TIMESTAMP,
    miner_terminated BOOLEAN
);
"""


CHUTEFS_PREDECESSOR = """
CREATE TABLE users (user_id VARCHAR PRIMARY KEY);
CREATE TABLE storage_volumes (
    volume_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(user_id),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    purged_at TIMESTAMPTZ,
    key_shredded_at TIMESTAMPTZ
);
CREATE TABLE storage_volume_keys (
    key_id VARCHAR PRIMARY KEY,
    volume_id VARCHAR NOT NULL REFERENCES storage_volumes(volume_id)
);
CREATE TABLE chutes (
    chute_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(user_id),
    node_selector JSONB
);
CREATE TABLE jobs (
    job_id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(user_id),
    finished_at TIMESTAMPTZ,
    miner_terminated BOOLEAN
);
CREATE TABLE gpu_launch_reservations (
    reservation_id VARCHAR PRIMARY KEY,
    state VARCHAR NOT NULL
);
CREATE TABLE servers (
    server_id VARCHAR PRIMARY KEY,
    gpu_retired_at TIMESTAMPTZ,
    gpu_runtime_session_attestation_id VARCHAR,
    attested_cert_pubkey_hash VARCHAR
);
CREATE TABLE launch_configs (
    config_id VARCHAR PRIMARY KEY,
    chute_id VARCHAR NOT NULL REFERENCES chutes(chute_id),
    job_id VARCHAR REFERENCES jobs(job_id),
    server_id VARCHAR REFERENCES servers(server_id),
    gpu_management_mode VARCHAR,
    gpu_launch_reservation_id VARCHAR REFERENCES gpu_launch_reservations(reservation_id),
    failed_at TIMESTAMPTZ,
    verification_error TEXT,
    registry_scope_active BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_job_launch_config_active
    ON launch_configs(job_id)
    WHERE job_id IS NOT NULL AND failed_at IS NULL;
CREATE TABLE instances (
    instance_id VARCHAR PRIMARY KEY,
    config_id VARCHAR REFERENCES launch_configs(config_id),
    active BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_error TEXT,
    stop_billing_at TIMESTAMPTZ
);
CREATE TABLE registry_sessions (
    session_id VARCHAR PRIMARY KEY,
    launch_config_id VARCHAR REFERENCES launch_configs(config_id),
    revoked_at TIMESTAMPTZ
);
"""


LIFECYCLE_PREDECESSOR = """
CREATE TABLE hosts (host_id VARCHAR PRIMARY KEY);
CREATE TABLE gpu_launch_reservations (
    reservation_id VARCHAR PRIMARY KEY,
    allocation_group_id VARCHAR,
    allocation_group_generation INTEGER,
    server_id VARCHAR,
    process_incarnation VARCHAR,
    gpu_uuids JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE TABLE gpu_inventory_reports (report_id VARCHAR PRIMARY KEY);
CREATE TABLE gpu_allocation_groups (
    allocation_group_id VARCHAR PRIMARY KEY,
    generation INTEGER NOT NULL,
    last_report_id VARCHAR NOT NULL REFERENCES gpu_inventory_reports(report_id),
    state VARCHAR NOT NULL,
    management_mode VARCHAR,
    reservation_owner VARCHAR,
    reservation_id VARCHAR,
    reservation_generation INTEGER NOT NULL DEFAULT 0,
    process_incarnation VARCHAR,
    recovery_started_at TIMESTAMPTZ
);
CREATE TABLE server_attestations (attestation_id VARCHAR PRIMARY KEY);
CREATE TABLE servers (
    server_id VARCHAR PRIMARY KEY,
    gpu_launch_reservation_id VARCHAR,
    gpu_process_incarnation VARCHAR,
    gpu_allocation_group_id VARCHAR,
    gpu_allocation_group_generation INTEGER
);
CREATE TABLE nodes (
    uuid VARCHAR PRIMARY KEY,
    server_id VARCHAR REFERENCES servers(server_id),
    gpu_allocation_group_id VARCHAR,
    gpu_allocation_group_generation INTEGER,
    gpu_retired_at TIMESTAMPTZ,
    CONSTRAINT ck_nodes_gpu_allocation_identity CHECK (
        (gpu_allocation_group_id IS NULL AND gpu_allocation_group_generation IS NULL)
        OR (gpu_allocation_group_id IS NOT NULL AND gpu_allocation_group_generation > 0)
    )
);
"""


ROTATION_PREDECESSOR = """
CREATE TABLE chutefs_launch_sessions (
    session_id VARCHAR PRIMARY KEY,
    config_id VARCHAR NOT NULL,
    instance_id VARCHAR NOT NULL,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chutefs_launch_sessions_config_id_key UNIQUE (config_id),
    CONSTRAINT chutefs_launch_sessions_instance_id_key UNIQUE (instance_id)
);
"""


@pytest.mark.parametrize(
    ("migration", "prefix", "predecessor", "seed", "tables", "message"),
    [
        (
            PLATFORM,
            "platform_down",
            PLATFORM_PREDECESSOR,
            """
            INSERT INTO jobs(job_id) VALUES ('job');
            INSERT INTO launch_configs(config_id, job_id, failed_at)
            VALUES ('active', 'job', NULL), ('history', 'job', NOW());
            """,
            (
                "gpu_launch_reservations",
                "instances",
                "jobs",
                "launch_configs",
                "registry_sessions",
                "server_attestations",
                "servers",
            ),
            b"cannot roll back GPU platform scheduler migration",
        ),
        (
            PLATFORM,
            "platform_state_down",
            PLATFORM_PREDECESSOR,
            """
            INSERT INTO registry_sessions(session_id, manifest_tag_digests)
            VALUES (
                'session',
                '{"sha256-tag.sig":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
            );
            """,
            (
                "gpu_launch_reservations",
                "launch_configs",
                "registry_sessions",
            ),
            b"cannot roll back GPU platform scheduler migration",
        ),
        (
            REGISTRY,
            "registry_down",
            REGISTRY_PREDECESSOR,
            """
            INSERT INTO registry_sessions(
                session_id, server_id, scope_id, repository, manifest_digest,
                descriptor_closure_sha256
            ) VALUES (
                'session', 'server', 'launch-config:config', 'owner/repository',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            );
            """,
            ("instances", "jobs", "launch_configs", "registry_sessions"),
            b"cannot discard non-legacy registry launch scopes",
        ),
        (
            CHUTEFS,
            "chutefs_down",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO chutes(chute_id, user_id, node_selector)
            VALUES ('chute', 'user', '{"compute_type":"cpu"}');
            INSERT INTO launch_configs(
                config_id, chute_id, user_id, compute_type,
                storage_session_exchange_allowed
            ) VALUES ('config', 'chute', 'user', 'cpu', TRUE);
            """,
            (
                "default_chutefs_volume_bindings",
                "chutefs_launch_sessions",
                "launch_configs",
                "storage_volumes",
                "users",
            ),
            b"cannot roll back default ChuteFS volumes",
        ),
        (
            CHUTEFS,
            "chutefs_unbound_volume_down",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO storage_volumes(volume_id, user_id, deleted)
            VALUES ('unbound-incomplete', 'user', FALSE);
            """,
            (
                "default_chutefs_volume_bindings",
                "chutefs_launch_sessions",
                "storage_volume_keys",
                "storage_volumes",
                "users",
            ),
            b"cannot roll back default ChuteFS volumes",
        ),
        (
            CHUTEFS,
            "chutefs_key_down",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO storage_volumes(
                volume_id, user_id, deleted, purged_at, key_shredded_at
            ) VALUES ('volume-with-key', 'user', TRUE, NOW(), NOW());
            INSERT INTO storage_volume_keys(key_id, volume_id)
            VALUES ('key', 'volume-with-key');
            """,
            (
                "default_chutefs_volume_bindings",
                "chutefs_launch_sessions",
                "storage_volume_keys",
                "storage_volumes",
                "users",
            ),
            b"cannot roll back default ChuteFS volumes",
        ),
        (
            CHUTEFS,
            "chutefs_binding_down",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO storage_volumes(volume_id, user_id, deleted)
            VALUES ('volume', 'user', FALSE);
            INSERT INTO default_chutefs_volume_bindings(
                binding_id, user_id, chute_id, volume_id
            ) VALUES ('binding', 'user', 'chute', 'volume');
            """,
            (
                "default_chutefs_volume_bindings",
                "chutefs_launch_sessions",
                "storage_volumes",
                "users",
            ),
            b"cannot roll back default ChuteFS volumes",
        ),
        (
            CHUTEFS,
            "chutefs_session_down",
            CHUTEFS_PREDECESSOR,
            f"""
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO storage_volumes(volume_id, user_id, deleted)
            VALUES ('volume', 'user', FALSE);
            INSERT INTO default_chutefs_volume_bindings(
                binding_id, user_id, chute_id, volume_id
            ) VALUES ('binding', 'user', 'chute', 'volume');
            INSERT INTO chutes(chute_id, user_id, node_selector)
            VALUES ('chute', 'user', '{{"compute_type":"cpu"}}');
            INSERT INTO launch_configs(
                config_id, chute_id, user_id, compute_type,
                default_volume_id, storage_session_exchange_allowed
            ) VALUES ('config', 'chute', 'user', 'cpu', 'volume', TRUE);
            INSERT INTO instances(instance_id, config_id)
            VALUES ('instance', 'config');
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id, binding_id, user_id,
                chute_id, compute_type, management_mode, server_id, volume_id,
                allowed_operations, access_token_hash, refresh_token_hash,
                access_expires_at, refresh_expires_at, attested_cert_pubkey_hash
            ) VALUES (
                'session', 'config', 'instance', 'binding', 'user', 'chute',
                'cpu', 'platform', 'server', 'volume',
                '["put", "get", "list", "delete"]',
                '{"a" * 64}', '{"b" * 64}',
                NOW() + INTERVAL '5 minutes', NOW() + INTERVAL '10 minutes',
                '{"c" * 64}'
            );
            """,
            (
                "default_chutefs_volume_bindings",
                "chutefs_launch_sessions",
                "launch_configs",
                "storage_volumes",
                "users",
            ),
            b"cannot roll back default ChuteFS volumes",
        ),
        (
            LIFECYCLE,
            "lifecycle_down",
            LIFECYCLE_PREDECESSOR,
            f"""
            INSERT INTO gpu_launch_reservations(reservation_id) VALUES ('reservation');
            INSERT INTO gpu_registration_nonces(
                nonce_id, client_request_id, request_generation, peer_spki_sha256,
                reservation_id, server_ip, nonce_value, nonce_hash, state, expires_at
            ) VALUES (
                'nonce', 'request', 1, '{"a" * 64}', 'reservation', '192.0.2.1',
                '{"b" * 64}', '{"c" * 64}', 'issued', NOW() + INTERVAL '5 minutes'
            );
            """,
            (
                "gpu_allocation_groups",
                "nodes",
                "gpu_hotplug_commands",
                "gpu_lifecycle_operations",
                "gpu_recovery_authorizations",
                "gpu_recovery_events",
                "gpu_registration_attempts",
                "gpu_registration_conflicts",
                "gpu_registration_nonces",
            ),
            b"cannot roll back durable GPU lifecycle state",
        ),
        (
            ROTATION,
            "rotation_down",
            ROTATION_PREDECESSOR,
            f"""
            INSERT INTO chutefs_token_key_epochs(
                key_id, state, required_replica_ids
            ) VALUES ('key-v1', 'staged', '["test-replica"]');
            INSERT INTO chutefs_token_key_replica_acks(
                replica_id, key_id, key_ids, key_fingerprints, keyring_sha256
            ) VALUES (
                'test-replica', 'key-v1', '["key-v1"]',
                '{{"key-v1":"{"a" * 64}"}}', '{"b" * 64}'
            );
            UPDATE chutefs_token_key_epochs
               SET state = 'active', activated_at = NOW()
             WHERE key_id = 'key-v1';
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id,
                access_expires_at, refresh_expires_at,
                rotation_request_sha256, token_seed, token_key_id,
                response_replay_until
            ) VALUES (
                'session', 'config', 'instance', NOW() + INTERVAL '5 minutes',
                NOW() + INTERVAL '1 hour',
                '{"d" * 64}', '{"e" * 64}', 'key-v1', NOW() + INTERVAL '15 minutes'
            );
            """,
            (
                "chutefs_launch_sessions",
                "chutefs_token_key_epochs",
                "chutefs_token_key_replica_acks",
            ),
            b"cannot remove ChuteFS rotation replay state",
        ),
        (
            ROTATION,
            "rotation_history_down",
            ROTATION_PREDECESSOR,
            """
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id,
                access_expires_at, refresh_expires_at, revoked_at
            ) VALUES
                ('old', 'config', 'old-instance', NOW() + INTERVAL '5 minutes',
                 NOW() + INTERVAL '1 hour', NOW()),
                ('active', 'config', 'active-instance', NOW() + INTERVAL '5 minutes',
                 NOW() + INTERVAL '1 hour', NULL);
            """,
            ("chutefs_launch_sessions",),
            b"cannot restore one-session uniqueness while session history exists",
        ),
    ],
)
def test_migration_specific_down_guard_preserves_catalog_and_data(
    migration: str,
    prefix: str,
    predecessor: str,
    seed: str,
    tables: tuple[str, ...],
    message: bytes,
):
    schema = _create_schema(prefix, predecessor)
    try:
        up, _down = _migration(migration)
        migrated = _apply(up, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        seeded = _psql(seed, schema)
        assert seeded.returncode == 0, seeded.stderr.decode()
        _assert_guard_rejects_without_changes(
            schema,
            migration,
            tables,
            message,
        )
    finally:
        _drop_schema(schema)


@pytest.mark.parametrize(
    ("migration", "prefix", "predecessor", "legacy_seed", "assertion"),
    [
        (
            PLATFORM,
            "platform_allowed",
            PLATFORM_PREDECESSOR,
            """
            INSERT INTO jobs(job_id) VALUES ('job');
            INSERT INTO launch_configs(config_id, job_id) VALUES ('config', 'job');
            """,
            "SELECT config_id || '|' || job_id FROM launch_configs;",
        ),
        (
            REGISTRY,
            "registry_allowed",
            REGISTRY_PREDECESSOR,
            """
            INSERT INTO registry_sessions(
                session_id, server_id, repository, manifest_digest,
                descriptor_closure_sha256
            ) VALUES (
                'legacy', 'server', 'owner/repository',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            );
            """,
            "SELECT session_id || '|' || repository || '|' || manifest_digest || '|' || "
            "descriptor_closure_sha256 FROM registry_sessions;",
        ),
        (
            CHUTEFS,
            "chutefs_allowed",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO chutes(chute_id, user_id, node_selector)
            VALUES ('chute', 'user', '{"compute_type":"cpu"}');
            INSERT INTO launch_configs(config_id, chute_id, verified_at)
            VALUES ('config', 'chute', NOW());
            """,
            "SELECT config_id || '|' || chute_id FROM launch_configs;",
        ),
        (
            LIFECYCLE,
            "lifecycle_allowed",
            LIFECYCLE_PREDECESSOR,
            "INSERT INTO gpu_launch_reservations(reservation_id) VALUES ('reservation');",
            "SELECT reservation_id FROM gpu_launch_reservations;",
        ),
        (
            ROTATION,
            "rotation_allowed",
            ROTATION_PREDECESSOR,
            """
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id,
                access_expires_at, refresh_expires_at
            ) VALUES (
                'session', 'config', 'instance', NOW() + INTERVAL '5 minutes',
                NOW() + INTERVAL '1 hour'
            );
            """,
            "SELECT session_id || '|' || config_id || '|' || instance_id "
            "FROM chutefs_launch_sessions;",
        ),
    ],
)
def test_exact_predecessor_data_survives_allowed_down(
    migration: str,
    prefix: str,
    predecessor: str,
    legacy_seed: str,
    assertion: str,
):
    schema = _create_schema(prefix, predecessor)
    try:
        seeded = _psql(legacy_seed, schema)
        assert seeded.returncode == 0, seeded.stderr.decode()
        before = _psql(assertion, schema)
        assert before.returncode == 0, before.stderr.decode()
        up, down = _migration(migration)
        migrated = _apply(up, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        reverted = _apply(down, schema)
        assert reverted.returncode == 0, reverted.stderr.decode()
        after = _psql(assertion, schema)
        assert after.returncode == 0, after.stderr.decode()
        assert after.stdout == before.stdout
    finally:
        _drop_schema(schema)


def test_lifecycle_preflight_rejects_current_reservation_from_other_custody():
    schema = _create_schema(
        "lifecycle_preflight_wrong_custody",
        """
        CREATE TABLE gpu_inventory_reports (report_id VARCHAR PRIMARY KEY);
        CREATE TABLE gpu_allocation_groups (
            allocation_group_id VARCHAR PRIMARY KEY,
            generation INTEGER NOT NULL,
            last_report_id VARCHAR NOT NULL
        );
        CREATE TABLE gpu_launch_reservations (
            reservation_id VARCHAR PRIMARY KEY,
            allocation_group_id VARCHAR NOT NULL,
            allocation_group_generation INTEGER NOT NULL,
            server_id VARCHAR NOT NULL,
            process_incarnation VARCHAR NOT NULL,
            gpu_uuids JSONB NOT NULL
        );
        CREATE TABLE servers (
            server_id VARCHAR PRIMARY KEY,
            gpu_launch_reservation_id VARCHAR,
            gpu_process_incarnation VARCHAR,
            gpu_allocation_group_id VARCHAR,
            gpu_allocation_group_generation INTEGER
        );
        CREATE TABLE nodes (
            uuid VARCHAR PRIMARY KEY,
            server_id VARCHAR,
            gpu_allocation_group_id VARCHAR,
            gpu_allocation_group_generation INTEGER,
            gpu_retired_at TIMESTAMPTZ
        );

        INSERT INTO gpu_inventory_reports(report_id) VALUES ('report-current');
        INSERT INTO gpu_allocation_groups(
            allocation_group_id, generation, last_report_id
        ) VALUES
            ('group-current', 1, 'report-current'),
            ('group-other', 1, 'report-current');
        INSERT INTO gpu_launch_reservations(
            reservation_id, allocation_group_id,
            allocation_group_generation, server_id,
            process_incarnation, gpu_uuids
        ) VALUES (
            'reservation-other', 'group-other', 1, 'server-other',
            'same-process', '["gpu-node"]'::jsonb
        );
        INSERT INTO servers(
            server_id, gpu_launch_reservation_id, gpu_process_incarnation,
            gpu_allocation_group_id, gpu_allocation_group_generation
        ) VALUES (
            'server-current', 'reservation-other', 'same-process',
            'group-current', 1
        );
        INSERT INTO nodes(
            uuid, server_id, gpu_allocation_group_id,
            gpu_allocation_group_generation, gpu_retired_at
        ) VALUES ('gpu-node', 'server-current', 'group-current', 1, NULL);
        """,
    )
    try:
        result = _psql(LIFECYCLE_PREFLIGHT.read_text(encoding="utf-8"), schema)
        assert result.returncode == 0, result.stderr.decode()
        assert b"gpu-node|server-current|group-current|1||{}|blocking_live" in result.stdout
        assert b"repairable_live" not in result.stdout
    finally:
        _drop_schema(schema)


async def _connect(schema: str, application_name: str):
    dsn = TEST_DATABASE_URL.replace("postgresql+asyncpg", "postgresql")
    return await asyncpg.connect(
        dsn,
        server_settings={
            "search_path": schema,
            "application_name": application_name,
        },
    )


async def _wait_for_lock(observer, pid: int) -> None:
    for _ in range(200):
        waiting = await observer.fetchval(
            "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = $1",
            pid,
        )
        if waiting:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"backend {pid} never waited for a relation lock")


async def _assert_writer_cannot_cross_down(
    schema: str,
    migration: str,
    blocked_table: str,
    writer_sql: str,
) -> None:
    _up, down = _migration(migration)
    blocker = await _connect(schema, "gpu-migration-blocker")
    down_connection = await _connect(schema, "gpu-migration-down")
    writer = await _connect(schema, "gpu-migration-writer")
    observer = await _connect(schema, "gpu-migration-observer")
    blocker_transaction = blocker.transaction()
    await blocker_transaction.start()
    blocker_committed = False
    await blocker.execute(f"LOCK TABLE {blocked_table} IN ROW EXCLUSIVE MODE")

    async def run_down():
        transaction = down_connection.transaction()
        await transaction.start()
        try:
            await down_connection.execute(down)
        except BaseException:
            await transaction.rollback()
            raise
        await transaction.commit()

    async def run_writer():
        try:
            await writer.execute(writer_sql)
        except Exception as exc:  # exact error varies by PostgreSQL plan invalidation point
            return exc
        return None

    try:
        down_task = asyncio.create_task(run_down())
        await _wait_for_lock(observer, down_connection.get_server_pid())
        writer_task = asyncio.create_task(run_writer())
        await _wait_for_lock(observer, writer.get_server_pid())
        await blocker_transaction.commit()
        blocker_committed = True
        await asyncio.wait_for(down_task, timeout=10)
        writer_error = await asyncio.wait_for(writer_task, timeout=10)
        assert writer_error is not None
    finally:
        if not blocker_committed:
            await blocker_transaction.rollback()
        await blocker.close()
        await down_connection.close()
        await writer.close()
        await observer.close()


async def _assert_runtime_advisory_fence_precedes_down_tables(
    schema: str,
    migration: str,
    *,
    advisory_name: str,
    before_down_sql: str,
    after_down_wait_sql: str,
) -> None:
    _up, down = _migration(migration)
    runtime = await _connect(schema, "chutefs-runtime")
    down_connection = await _connect(schema, "chutefs-down")
    observer = await _connect(schema, "chutefs-observer")
    runtime_transaction = runtime.transaction()
    await runtime_transaction.start()
    runtime_committed = False
    await runtime.execute(
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))",
        advisory_name,
    )
    await runtime.execute(before_down_sql)

    async def run_down():
        transaction = down_connection.transaction()
        await transaction.start()
        try:
            await down_connection.execute(down)
        except BaseException:
            await transaction.rollback()
            raise
        await transaction.commit()

    try:
        down_task = asyncio.create_task(run_down())
        await _wait_for_lock(observer, down_connection.get_server_pid())
        await runtime.execute(after_down_wait_sql)
        await runtime_transaction.commit()
        runtime_committed = True
        await asyncio.wait_for(down_task, timeout=10)
    finally:
        if not runtime_committed:
            await runtime_transaction.rollback()
        await runtime.close()
        await down_connection.close()
        await observer.close()


@pytest.mark.asyncio
async def test_default_volume_down_waits_on_schema_fence_before_runtime_rows():
    schema = _create_schema("chutefs_schema_fence", CHUTEFS_PREDECESSOR)
    try:
        seeded = _psql(
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO chutes(chute_id, user_id, node_selector)
            VALUES ('chute', 'user', '{"compute_type":"cpu"}');
            INSERT INTO launch_configs(config_id, chute_id, failed_at)
            VALUES ('config', 'chute', NOW());
            """,
            schema,
        )
        assert seeded.returncode == 0, seeded.stderr.decode()
        up, _down = _migration(CHUTEFS)
        migrated = _apply(up, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        await _assert_runtime_advisory_fence_precedes_down_tables(
            schema,
            CHUTEFS,
            advisory_name="chutes.chutefs-schema-fence.v1",
            before_down_sql="SELECT 1 FROM users WHERE user_id = 'user' FOR UPDATE",
            after_down_wait_sql=(
                "SELECT 1 FROM launch_configs WHERE config_id = 'config' FOR UPDATE"
            ),
        )
    finally:
        _drop_schema(schema)


@pytest.mark.asyncio
async def test_rotation_down_waits_on_epoch_fence_before_session_rows():
    schema = _create_schema("chutefs_epoch_fence", ROTATION_PREDECESSOR)
    try:
        seeded = _psql(
            """
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id,
                access_expires_at, refresh_expires_at
            ) VALUES (
                'session', 'config', 'instance', NOW() + INTERVAL '5 minutes',
                NOW() + INTERVAL '1 hour'
            );
            """,
            schema,
        )
        assert seeded.returncode == 0, seeded.stderr.decode()
        up, _down = _migration(ROTATION)
        migrated = _apply(up, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        await _assert_runtime_advisory_fence_precedes_down_tables(
            schema,
            ROTATION,
            advisory_name="chutes.chutefs-token-key-epochs.v1",
            before_down_sql="SELECT 1",
            after_down_wait_sql=(
                "SELECT 1 FROM chutefs_launch_sessions "
                "WHERE session_id = 'session' FOR UPDATE"
            ),
        )
    finally:
        _drop_schema(schema)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "migration",
        "prefix",
        "predecessor",
        "seed",
        "blocked_table",
        "writer_sql",
    ),
    [
        (
            PLATFORM,
            "platform_race",
            PLATFORM_PREDECESSOR,
            """
            INSERT INTO jobs(job_id) VALUES ('job');
            INSERT INTO launch_configs(config_id, job_id) VALUES ('active', 'job');
            """,
            "launch_configs",
            """
            INSERT INTO launch_configs(
                config_id, job_id, failed_at, gpu_management_mode
            ) VALUES ('history', 'job', NOW(), NULL)
            """,
        ),
        (
            REGISTRY,
            "registry_race",
            REGISTRY_PREDECESSOR,
            """
            INSERT INTO registry_sessions(session_id, server_id)
            VALUES ('legacy', 'server');
            """,
            "registry_sessions",
            "UPDATE registry_sessions SET scope_id = 'launch-config:config' "
            "WHERE session_id = 'legacy'",
        ),
        (
            CHUTEFS,
            "chutefs_race",
            CHUTEFS_PREDECESSOR,
            """
            INSERT INTO users(user_id) VALUES ('user');
            INSERT INTO chutes(chute_id, user_id, node_selector)
            VALUES ('chute', 'user', '{"compute_type":"cpu"}');
            INSERT INTO launch_configs(config_id, chute_id, verified_at)
            VALUES ('config', 'chute', NOW());
            """,
            "launch_configs",
            "UPDATE launch_configs SET completed_at = NOW() WHERE config_id = 'config'",
        ),
        (
            LIFECYCLE,
            "lifecycle_race",
            LIFECYCLE_PREDECESSOR,
            "INSERT INTO gpu_launch_reservations(reservation_id) VALUES ('reservation');",
            "gpu_registration_nonces",
            f"""
            INSERT INTO gpu_registration_nonces(
                nonce_id, client_request_id, request_generation, peer_spki_sha256,
                reservation_id, server_ip, nonce_value, nonce_hash, state, expires_at
            ) VALUES (
                'nonce', 'request', 1, '{"a" * 64}', 'reservation', '192.0.2.1',
                '{"b" * 64}', '{"c" * 64}', 'issued', NOW() + INTERVAL '5 minutes'
            )
            """,
        ),
        (
            ROTATION,
            "rotation_race",
            ROTATION_PREDECESSOR,
            """
            INSERT INTO chutefs_launch_sessions(
                session_id, config_id, instance_id,
                access_expires_at, refresh_expires_at
            ) VALUES (
                'session', 'config', 'instance', NOW() + INTERVAL '5 minutes',
                NOW() + INTERVAL '1 hour'
            );
            """,
            "chutefs_launch_sessions",
            f"""
            UPDATE chutefs_launch_sessions
               SET rotation_request_sha256 = '{"d" * 64}',
                   token_seed = '{"e" * 64}',
                   token_key_id = 'key-v1',
                   response_replay_until = NOW() + INTERVAL '15 minutes'
             WHERE session_id = 'session'
            """,
        ),
    ],
)
async def test_access_exclusive_down_prevents_guard_to_ddl_writer_race(
    migration: str,
    prefix: str,
    predecessor: str,
    seed: str,
    blocked_table: str,
    writer_sql: str,
):
    schema = _create_schema(prefix, predecessor)
    try:
        seeded = _psql(seed, schema)
        assert seeded.returncode == 0, seeded.stderr.decode()
        up, _down = _migration(migration)
        migrated = _apply(up, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        await _assert_writer_cannot_cross_down(
            schema,
            migration,
            blocked_table,
            writer_sql,
        )
    finally:
        _drop_schema(schema)
