"""Startup ordering for schema migrations and per-worker storage reconciliation."""

import asyncio
import hashlib
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import make_url

from api.database import migrations


MIGRATION_MANIFEST_LINE = re.compile(
    r"^(?P<digest>[0-9a-f]{64})  (?P<filename>[0-9]{14}_[a-z0-9_]+\.sql)$"
)


class FakeConnection:
    def __init__(self):
        self.events = []

    async def execute(self, statement, parameters=None):
        self.events.append((str(statement), parameters))

    async def commit(self):
        self.events.append(("commit", None))

    async def rollback(self):
        self.events.append(("rollback", None))

    async def run_sync(self, callback):
        self.events.append(("orm-bootstrap", callback))


class ScalarRows:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def __iter__(self):
        return iter(self.values)


class ConnectionContext:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return None


class FakeEngine:
    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return ConnectionContext(self.connection)


class FakeProcess:
    def __init__(self, returncode):
        self.returncode = returncode

    async def communicate(self):
        return b"migration output", b""


class ControlledProcess:
    def __init__(self, events):
        self.events = events
        self.returncode = None
        self.communicate_started = asyncio.Event()
        self.wait_started = asyncio.Event()
        self.allow_exit = asyncio.Event()

    async def communicate(self):
        self.events.append(("dbmate-communicate", None))
        self.communicate_started.set()
        await self.allow_exit.wait()
        self.returncode = -15
        self.events.append(("dbmate-reaped", None))
        return b"", b""

    def terminate(self):
        self.events.append(("dbmate-terminate", None))
        self.wait_started.set()

    def kill(self):
        self.events.append(("dbmate-kill", None))

    async def wait(self):
        await self.communicate_started.wait()
        return self.returncode


class ExitedBeforeDrainProcess:
    def __init__(self, events):
        self.events = events
        self.returncode = None
        self.communicate_started = asyncio.Event()
        self.exited = asyncio.Event()
        self.allow_drain = asyncio.Event()

    async def communicate(self):
        self.events.append(("dbmate-communicate", None))
        self.communicate_started.set()
        self.returncode = 0
        self.exited.set()
        await self.allow_drain.wait()
        self.events.append(("dbmate-drained", None))
        return b"", b""

    def terminate(self):
        raise AssertionError("an already-exited process must not be terminated")

    def kill(self):
        raise AssertionError("an already-exited process must not be killed")


class UnsupportedPostgresConnection:
    def __init__(self, server_version_num):
        self.server_version_num = server_version_num
        self.statements = []

    async def scalar(self, statement, parameters=None):
        self.statements.append((str(statement), parameters))
        return self.server_version_num


def test_historical_baseline_is_exact_immutable_production_set():
    versions = migrations.historical_migration_versions()
    assert versions == sorted(set(versions))
    assert len(versions) == 64
    assert (
        hashlib.sha256(("\n".join(versions) + "\n").encode("ascii")).hexdigest()
        == "bbe1008b2619eb1821d40aac9fb91bc68afd2216eb5cbf2d4ebb4a1c9cea399d"
    )
    branch_added_sub_threshold = {
        "20260528120000",
        "20260529150000",
        "20260529160000",
        "20260603120000",
        "20260603170000",
        "20260604120000",
        "20260605120000",
        "20260605130000",
        "20260607120000",
        "20260610120000",
        "20260629120000",
        "20260703120000",
        "20260703130000",
        "20260703140000",
        "20260704160000",
        "20260706120000",
    }
    assert branch_added_sub_threshold.isdisjoint(versions)


@pytest.mark.asyncio
async def test_unsupported_postgres_major_fails_before_any_catalog_lookup_or_ddl():
    connection = UnsupportedPostgresConnection(160011)
    with pytest.raises(RuntimeError, match="qualified only for PostgreSQL 15"):
        await migrations._validate_production_base_postgres_major(connection)
    assert len(connection.statements) == 1
    assert "server_version_num" in connection.statements[0][0]


def test_api_migration_file_set_and_bytes_are_frozen():
    migration_dir = Path(__file__).resolve().parents[2] / "api/migrations"
    manifest_path = migration_dir / "SHA256SUMS"
    frozen = {}
    for line in manifest_path.read_text(encoding="ascii").splitlines():
        match = MIGRATION_MANIFEST_LINE.fullmatch(line)
        assert match is not None, f"invalid migration hash manifest line: {line!r}"
        filename = match.group("filename")
        assert filename not in frozen, f"duplicate migration manifest entry: {filename}"
        frozen[filename] = match.group("digest")

    migration_files = {path.name: path for path in sorted(migration_dir.glob("*.sql"))}
    assert len(frozen) == 113
    assert set(frozen) == set(migration_files), (
        "API migration file set changed; record every new migration explicitly and never "
        "rewrite migration history after its first remediation release"
    )
    actual = {
        filename: hashlib.sha256(path.read_bytes()).hexdigest()
        for filename, path in migration_files.items()
    }
    mismatches = {
        filename: (frozen[filename], actual[filename])
        for filename in frozen
        if actual[filename] != frozen[filename]
    }
    assert mismatches == {}, f"API migration bytes changed: {mismatches!r}"


def test_production_base_contract_bytes_are_pinned_separately_from_dbmate():
    source = migrations.production_base_sql()
    assert hashlib.sha256(source.encode("utf-8")).hexdigest() == (
        migrations.PRODUCTION_BASE_SQL_SHA256
    )
    assert "CREATE TABLE IF NOT EXISTS partitioned_invocations" in source
    assert "CREATE MATERIALIZED VIEW user_current_balance" in source
    assert "Preserve any legacy" in source
    assert "DROP FUNCTION report_missing_short_lived_instances" not in source
    assert migrations.PRODUCTION_BASE_CONTRACT_SHA256 == (
        migrations.production_base_contract_sha256(
            migrations.PRODUCTION_BASE_SQL_SHA256
        )
    )


def test_dbmate_url_preserves_reserved_credentials_ipv6_and_query(monkeypatch):
    source = (
        "postgresql+asyncpg://us%2Fer:p%40ss%3Aword@[2001:db8::1]:5432/"
        "db%2Fname?application_name=a%20b&options=-c%20x%3Dy"
    )
    monkeypatch.setattr(
        migrations, "settings", SimpleNamespace(sqlalchemy=source, db_ssl="verify-full")
    )
    rendered = migrations.dbmate_url()
    parsed = make_url(rendered)
    assert parsed.drivername == "postgresql"
    assert parsed.username == "us/er"
    assert parsed.password == "p@ss:word"
    assert parsed.host == "2001:db8::1"
    assert parsed.database == "db%2Fname"
    assert dict(parsed.query) == {
        "application_name": "a b",
        "options": "-c x=y",
        "sslmode": "verify-full",
    }
    assert "us%2Fer:p%40ss%3Aword@[2001:db8::1]" in rendered


def test_dbmate_url_maps_explicit_local_db_ssl_without_corrupting_query(monkeypatch):
    source = "postgresql+asyncpg://user:p%40ss@127.0.0.1:5432/db?foo=a%26b"
    monkeypatch.setattr(
        migrations, "settings", SimpleNamespace(sqlalchemy=source, db_ssl="disable")
    )
    parsed = make_url(migrations.dbmate_url())
    assert parsed.password == "p@ss"
    assert dict(parsed.query) == {"foo": "a&b", "sslmode": "disable"}


def test_dbmate_url_preserves_explicit_local_sslmode(monkeypatch):
    source = "postgresql+asyncpg://user:pass@localhost:5432/db?sslmode=require&application_name=api"
    monkeypatch.setattr(
        migrations, "settings", SimpleNamespace(sqlalchemy=source, db_ssl="disable")
    )
    parsed = make_url(migrations.dbmate_url())
    assert dict(parsed.query) == {"application_name": "api", "sslmode": "require"}


@pytest.mark.parametrize("db_ssl", ["require", "verify-full"])
def test_dbmate_url_never_uses_implicit_remote_libpq_tls_posture(monkeypatch, db_ssl):
    source = "postgresql+asyncpg://user:pass@db.example:5432/chutes"
    monkeypatch.setattr(
        migrations, "settings", SimpleNamespace(sqlalchemy=source, db_ssl=db_ssl)
    )
    assert make_url(migrations.dbmate_url()).query["sslmode"] == db_ssl


def test_server_health_has_post_remediation_forward_migration():
    """The upstream pre-baseline file is marked applied on legacy DBs; the forward copy must run."""
    versions = migrations.historical_migration_versions()
    assert "20260626120000" in versions
    assert "20260715120000" not in versions
    assert "20260715120000" > "20260714110000"

    migration_dir = Path(__file__).resolve().parents[2] / "api/migrations"
    old_up = (
        (migration_dir / "20260626120000_server_health.sql")
        .read_text()
        .split("-- migrate:up", 1)[1]
        .split("-- migrate:down", 1)[0]
    )
    forward = (migration_dir / "20260715120000_server_health_forward.sql").read_text()
    forward_up = forward.split("-- migrate:up", 1)[1].split("-- migrate:down", 1)[0]
    forward_down = forward.split("-- migrate:down", 1)[1]
    assert " ".join(old_up.split()) == " ".join(forward_up.split())
    assert "DROP " not in forward_down
    assert "20260626120000_server_health.sql" in forward_down


@pytest.mark.asyncio
async def test_final_ledger_rejects_dbmate_exit_zero_without_progress(monkeypatch):
    class LedgerConnection:
        async def execute(self, _statement):
            return ScalarRows(["20241101123129"])

    async def validate_catalog(_connection, *, required):
        assert required is True
        return True

    monkeypatch.setattr(
        migrations, "_validate_schema_migrations_catalog", validate_catalog
    )
    monkeypatch.setattr(
        migrations,
        "migration_versions_on_disk",
        lambda: {"20241101123129", "20241101150057"},
    )
    with pytest.raises(RuntimeError, match="without the exact final migration ledger"):
        await migrations._validate_final_migration_ledger(LedgerConnection())


@pytest.mark.asyncio
async def test_startup_serializes_dbmate_after_orm_bootstrap(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))
    invocation = {}

    async def bootstrap(conn):
        conn.events.append(("orm-bootstrap", migrations.create_application_tables))

    async def unlock(conn):
        conn.events.append(("pg_advisory_unlock", None))

    async def validate(conn):
        conn.events.append(("catalog-validate", None))
        return {
            "daily_revenue_summary_variant": "quota_current_activation_approximation"
        }

    async def validate_final_ledger(conn):
        conn.events.append(("ledger-validate", None))

    async def marker(conn):
        return (
            migrations.PRODUCTION_BASE_CONTRACT_SHA256,
            migrations.PRODUCTION_BASE_SQL_SHA256,
            migrations.PRODUCTION_BASE_CATALOG_SHA256,
            "quota_current_activation_approximation",
        )

    async def create_subprocess_exec(*args, **kwargs):
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return FakeProcess(0)

    monkeypatch.setattr(
        migrations.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    monkeypatch.setattr(migrations, "bootstrap_production_base", bootstrap)
    monkeypatch.setattr(migrations, "validate_production_base_catalog", validate)
    monkeypatch.setattr(
        migrations, "_validate_final_migration_ledger", validate_final_ledger
    )
    monkeypatch.setattr(migrations, "_production_base_marker", marker)
    monkeypatch.setattr(migrations, "_unlock_migration_connection", unlock)
    await migrations.run_database_migrations()

    assert "pg_advisory_lock" in connection.events[0][0]
    assert next(event[0] for event in connection.events if event[0] == "orm-bootstrap")
    assert invocation["args"][0] == "dbmate"
    assert invocation["args"][-1] == "migrate"
    assert "--url" not in invocation["args"]
    assert invocation["kwargs"]["env"]["DATABASE_URL"] == migrations.dbmate_url()
    assert migrations.dbmate_url() not in invocation["args"]
    assert set(invocation["kwargs"]["env"]) <= migrations._DBMATE_ENV_ALLOWLIST | {
        "DATABASE_URL"
    }
    assert ("catalog-validate", None) in connection.events
    assert ("ledger-validate", None) in connection.events
    assert connection.events[-1][0] == "pg_advisory_unlock"


def test_dbmate_diagnostics_log_only_count_digest_stream_and_status():
    diagnostic = (
        b"postgresql://migration-user:p@ss:word@db.example/chutes?"
        b"sslpassword=reordered-secret&token=decoded-token&sslkey=/secret/key"
    )
    evidence = migrations._dbmate_output_evidence("stderr", diagnostic, 17)
    assert evidence == (
        f"dbmate stderr: bytes={len(diagnostic)}, "
        f"sha256={hashlib.sha256(diagnostic).hexdigest()}, exit_code=17"
    )
    for secret in (
        "migration-user",
        "p@ss:word",
        "reordered-secret",
        "decoded-token",
        "/secret/key",
    ):
        assert secret not in evidence
    source = (
        Path(__file__).resolve().parents[2] / "api/database/migrations.py"
    ).read_text()
    assert "_redact_dbmate_output" not in source


@pytest.mark.asyncio
async def test_startup_fails_closed_and_releases_lock_on_migration_error(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))

    async def bootstrap(conn):
        conn.events.append(("orm-bootstrap", migrations.create_application_tables))

    async def unlock(conn):
        conn.events.append(("pg_advisory_unlock", None))

    async def validate(conn):
        conn.events.append(("catalog-validate", None))
        return {
            "daily_revenue_summary_variant": "quota_current_activation_approximation"
        }

    async def create_subprocess_exec(*_args, **_kwargs):
        return FakeProcess(17)

    monkeypatch.setattr(
        migrations.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    monkeypatch.setattr(migrations, "bootstrap_production_base", bootstrap)
    monkeypatch.setattr(migrations, "validate_production_base_catalog", validate)
    monkeypatch.setattr(migrations, "_unlock_migration_connection", unlock)
    with pytest.raises(RuntimeError, match="exit code 17"):
        await migrations.run_database_migrations()

    assert connection.events[-2:] == [("rollback", None), ("pg_advisory_unlock", None)]
    main_source = (Path(__file__).resolve().parents[2] / "api/main.py").read_text()
    assert "/tmp/api.pid" not in main_source
    assert "asyncio.create_task(storage_reconcile_loop())" in main_source


@pytest.mark.asyncio
async def test_repeated_cancellation_reaps_dbmate_before_unlock(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))
    process = ControlledProcess(connection.events)

    async def bootstrap(conn):
        conn.events.append(("orm-bootstrap", migrations.create_application_tables))

    async def unlock(conn):
        conn.events.append(("pg_advisory_unlock", None))

    async def create_subprocess_exec(*_args, **_kwargs):
        return process

    monkeypatch.setattr(
        migrations.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    monkeypatch.setattr(migrations, "bootstrap_production_base", bootstrap)
    monkeypatch.setattr(migrations, "_unlock_migration_connection", unlock)

    migration_task = asyncio.create_task(migrations.run_database_migrations())
    await process.communicate_started.wait()
    migration_task.cancel()
    await process.wait_started.wait()
    migration_task.cancel()
    await asyncio.sleep(0)
    assert ("pg_advisory_unlock", None) not in connection.events

    process.allow_exit.set()
    with pytest.raises(asyncio.CancelledError):
        await migration_task

    assert connection.events.index(
        ("dbmate-terminate", None)
    ) < connection.events.index(("dbmate-reaped", None))
    assert connection.events.index(("dbmate-reaped", None)) < connection.events.index(
        ("rollback", None)
    )
    assert connection.events.index(("rollback", None)) < connection.events.index(
        ("pg_advisory_unlock", None)
    )


@pytest.mark.asyncio
async def test_cancellation_drains_noisy_real_child_before_unlock(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))
    original_create_subprocess_exec = asyncio.create_subprocess_exec
    launched = asyncio.Event()
    holder = {}

    async def bootstrap(conn):
        conn.events.append(("orm-bootstrap", migrations.create_application_tables))

    async def unlock(conn):
        assert holder["process"].returncode is not None
        conn.events.append(("pg_advisory_unlock", None))

    async def create_noisy_process(*_args, **_kwargs):
        process = await original_create_subprocess_exec(
            sys.executable,
            "-c",
            "import os,time; os.write(1, b'x' * (2 * 1024 * 1024)); time.sleep(60)",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        holder["process"] = process
        launched.set()
        return process

    monkeypatch.setattr(migrations, "bootstrap_production_base", bootstrap)
    monkeypatch.setattr(migrations, "_unlock_migration_connection", unlock)
    monkeypatch.setattr(
        migrations.asyncio, "create_subprocess_exec", create_noisy_process
    )

    migration_task = asyncio.create_task(migrations.run_database_migrations())
    await launched.wait()
    # Give the child enough time to exceed ordinary pipe capacity while communicate drains it.
    await asyncio.sleep(0.2)
    migration_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(migration_task, timeout=5)

    assert holder["process"].returncode is not None
    assert connection.events[-2:] == [("rollback", None), ("pg_advisory_unlock", None)]


@pytest.mark.asyncio
async def test_cancellation_after_child_exit_waits_for_communicate_drain(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))
    process = ExitedBeforeDrainProcess(connection.events)

    async def bootstrap(conn):
        conn.events.append(("orm-bootstrap", migrations.create_application_tables))

    async def unlock(conn):
        assert process.returncode == 0
        assert process.allow_drain.is_set()
        assert ("dbmate-drained", None) in conn.events
        conn.events.append(("pg_advisory_unlock", None))

    async def create_subprocess_exec(*_args, **_kwargs):
        return process

    monkeypatch.setattr(
        migrations.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    monkeypatch.setattr(migrations, "bootstrap_production_base", bootstrap)
    monkeypatch.setattr(migrations, "_unlock_migration_connection", unlock)

    migration_task = asyncio.create_task(migrations.run_database_migrations())
    await process.communicate_started.wait()
    await process.exited.wait()
    migration_task.cancel()
    await asyncio.sleep(0)
    assert ("pg_advisory_unlock", None) not in connection.events

    process.allow_drain.set()
    with pytest.raises(asyncio.CancelledError):
        await migration_task

    assert connection.events.index(("dbmate-drained", None)) < connection.events.index(
        ("rollback", None)
    )
    assert connection.events.index(("rollback", None)) < connection.events.index(
        ("pg_advisory_unlock", None)
    )
