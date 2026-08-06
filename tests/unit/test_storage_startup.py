"""Startup ordering for schema migrations and per-worker storage reconciliation."""

import hashlib
import re
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
    assert len(frozen) == 110
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


def test_dbmate_url_preserves_reserved_credentials_ipv6_and_query(monkeypatch):
    source = (
        "postgresql+asyncpg://us%2Fer:p%40ss%3Aword@[2001:db8::1]:5432/"
        "db%2Fname?application_name=a%20b&options=-c%20x%3Dy"
    )
    monkeypatch.setattr(migrations, "settings", SimpleNamespace(sqlalchemy=source))
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
    }
    assert "us%2Fer:p%40ss%3Aword@[2001:db8::1]" in rendered


def test_dbmate_url_adds_local_sslmode_without_corrupting_query(monkeypatch):
    source = "postgresql+asyncpg://user:p%40ss@127.0.0.1:5432/db?foo=a%26b"
    monkeypatch.setattr(migrations, "settings", SimpleNamespace(sqlalchemy=source))
    parsed = make_url(migrations.dbmate_url())
    assert parsed.password == "p@ss"
    assert dict(parsed.query) == {"foo": "a&b", "sslmode": "disable"}


def test_dbmate_url_preserves_explicit_local_sslmode(monkeypatch):
    source = "postgresql+asyncpg://user:pass@localhost:5432/db?sslmode=require&application_name=api"
    monkeypatch.setattr(migrations, "settings", SimpleNamespace(sqlalchemy=source))
    parsed = make_url(migrations.dbmate_url())
    assert dict(parsed.query) == {"application_name": "api", "sslmode": "require"}


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
