"""Real-Postgres acceptance for exact registry launch lifecycle revocation."""

import os
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for registry lifecycle tests",
)


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


def test_instance_and_job_terminal_events_revoke_registry_sessions():
    schema = f"registry_lifecycle_{uuid.uuid4().hex}"
    migration = (
        Path(__file__).resolve().parents[2]
        / "api/migrations/20260724100500_registry_launch_scope.sql"
    )
    up_sql, down_sql = migration.read_text(encoding="utf-8").split(
        "-- migrate:down",
        1,
    )
    assert _psql(f'CREATE SCHEMA "{schema}";', "public").returncode == 0
    try:
        baseline = _psql(
            """
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
            """,
            schema,
        )
        assert baseline.returncode == 0, baseline.stderr.decode()
        migrated = _psql(up_sql, schema)
        assert migrated.returncode == 0, migrated.stderr.decode()

        instance_lifecycle = _psql(
            f"""
            INSERT INTO launch_configs (
                config_id, server_id, gpu_management_mode,
                container_repository, container_manifest_digest,
                registry_scope_active
            ) VALUES (
                'config-instance', 'server-instance', 'miner',
                'owner/image', 'sha256:{"a" * 64}', TRUE
            );
            INSERT INTO registry_sessions (
                session_id, server_id, scope_id, launch_config_id
            ) VALUES (
                'session-instance', 'server-instance',
                'launch-config:config-instance', 'config-instance'
            );
            INSERT INTO instances (
                instance_id, config_id, active, verified
            ) VALUES ('instance-1', 'config-instance', TRUE, TRUE);
            UPDATE instances SET active = FALSE WHERE instance_id = 'instance-1';
            SELECT registry_scope_active, registry_scope_revoked_at IS NOT NULL
            FROM launch_configs WHERE config_id = 'config-instance';
            SELECT revoked_at IS NOT NULL
            FROM registry_sessions WHERE session_id = 'session-instance';
            """,
            schema,
        )
        assert instance_lifecycle.returncode == 0, instance_lifecycle.stderr.decode()
        assert [
            line
            for line in instance_lifecycle.stdout.decode().splitlines()
            if "|" in line or line in {"t", "f"}
        ][-2:] == ["f|t", "t"]

        job_lifecycle = _psql(
            f"""
            INSERT INTO jobs (job_id) VALUES ('job-1');
            INSERT INTO launch_configs (
                config_id, server_id, gpu_management_mode, job_id,
                container_repository, container_manifest_digest,
                registry_scope_active
            ) VALUES (
                'config-job', 'server-job', 'miner', 'job-1',
                'owner/image', 'sha256:{"b" * 64}', TRUE
            );
            INSERT INTO registry_sessions (
                session_id, server_id, scope_id, launch_config_id
            ) VALUES (
                'session-job', 'server-job',
                'launch-config:config-job', 'config-job'
            );
            UPDATE jobs SET finished_at = NOW() WHERE job_id = 'job-1';
            SELECT registry_scope_active, registry_scope_revoked_at IS NOT NULL
            FROM launch_configs WHERE config_id = 'config-job';
            SELECT revoked_at IS NOT NULL
            FROM registry_sessions WHERE session_id = 'session-job';
            """,
            schema,
        )
        assert job_lifecycle.returncode == 0, job_lifecycle.stderr.decode()
        assert [
            line
            for line in job_lifecycle.stdout.decode().splitlines()
            if "|" in line or line in {"t", "f"}
        ][-2:] == ["f|t", "t"]

        cleanup = _psql(
            "DELETE FROM registry_sessions WHERE session_id = 'session-job';",
            schema,
        )
        assert cleanup.returncode == 0, cleanup.stderr.decode()
        reverted = _psql(down_sql, schema)
        assert reverted.returncode == 0, reverted.stderr.decode()
    finally:
        dropped = _psql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE;', "public")
        assert dropped.returncode == 0, dropped.stderr.decode()
