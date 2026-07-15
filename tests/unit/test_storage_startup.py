"""Startup ordering for schema migrations and per-worker storage reconciliation."""

from pathlib import Path

import pytest

from api.database import migrations


class FakeConnection:
    def __init__(self):
        self.events = []

    async def execute(self, statement, parameters=None):
        self.events.append((str(statement), parameters))

    async def commit(self):
        self.events.append(("commit", None))

    async def run_sync(self, callback):
        self.events.append(("orm-bootstrap", callback))


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


def test_historical_baseline_never_marks_enforced_storage_chain_applied():
    versions = migrations.historical_migration_versions()
    assert versions
    assert all(version < migrations.TRACKED_MIGRATION_BASELINE for version in versions)
    assert migrations.TRACKED_MIGRATION_BASELINE not in versions


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
    forward_up = (
        (migration_dir / "20260715120000_server_health_forward.sql")
        .read_text()
        .split("-- migrate:up", 1)[1]
        .split("-- migrate:down", 1)[0]
    )
    assert " ".join(old_up.split()) == " ".join(forward_up.split())


@pytest.mark.asyncio
async def test_startup_serializes_dbmate_after_orm_bootstrap(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))
    invocation = {}

    async def create_subprocess_exec(*args, **kwargs):
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return FakeProcess(0)

    monkeypatch.setattr(migrations.asyncio, "create_subprocess_exec", create_subprocess_exec)
    await migrations.run_database_migrations()

    assert "pg_advisory_lock" in connection.events[0][0]
    assert next(event[0] for event in connection.events if event[0] == "orm-bootstrap")
    assert invocation["args"][0] == "dbmate"
    assert invocation["args"][-1] == "migrate"
    assert "pg_advisory_unlock" in connection.events[-2][0]


@pytest.mark.asyncio
async def test_startup_fails_closed_and_releases_lock_on_migration_error(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(migrations, "engine", FakeEngine(connection))

    async def create_subprocess_exec(*_args, **_kwargs):
        return FakeProcess(17)

    monkeypatch.setattr(migrations.asyncio, "create_subprocess_exec", create_subprocess_exec)
    with pytest.raises(RuntimeError, match="exit code 17"):
        await migrations.run_database_migrations()

    assert any("pg_advisory_unlock" in event[0] for event in connection.events)
    main_source = (Path(__file__).resolve().parents[2] / "api/main.py").read_text()
    assert "/tmp/api.pid" not in main_source
    assert "asyncio.create_task(storage_reconcile_loop())" in main_source
