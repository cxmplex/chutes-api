import pytest

from api.storage import reconcile as storage_reconcile


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value


class _Connection:
    def __init__(self, events, results):
        self.events = events
        self.results = iter(results)

    async def execute(self, statement, _params=None):
        sql = str(statement)
        self.events.append("leader_lock" if "pg_try_advisory_lock" in sql else "leader_unlock")
        return _ScalarResult(next(self.results))

    async def commit(self):
        self.events.append("leader_commit")


class _ConnectionContext:
    def __init__(self, connection, events):
        self.connection = connection
        self.events = events

    async def __aenter__(self):
        self.events.append("leader_enter")
        return self.connection

    async def __aexit__(self, *_args):
        self.events.append("leader_exit")


class _Engine:
    def __init__(self, connection, events):
        self.connection = connection
        self.events = events

    def connect(self):
        return _ConnectionContext(self.connection, self.events)


class _WorkSessionContext:
    def __init__(self, session, events):
        self.session = session
        self.events = events

    async def __aenter__(self):
        self.events.append("work_enter")
        return self.session

    async def __aexit__(self, *_args):
        self.events.append("work_exit")


def _install_fakes(monkeypatch, lock_results):
    events = []
    connection = _Connection(events, lock_results)
    work_session = object()
    monkeypatch.setattr(storage_reconcile, "engine", _Engine(connection, events))
    monkeypatch.setattr(
        storage_reconcile,
        "get_session",
        lambda: _WorkSessionContext(work_session, events),
    )

    async def _reconcile(session):
        assert session is work_session
        assert connection is not session
        events.append("reconcile")

    monkeypatch.setattr(storage_reconcile, "reconcile_storage", _reconcile)
    return events


@pytest.mark.asyncio
async def test_reconcile_owns_leadership_on_dedicated_connection(monkeypatch):
    events = _install_fakes(monkeypatch, [True, True])

    assert await storage_reconcile.reconcile_storage_once()
    assert events == [
        "leader_enter",
        "leader_lock",
        "leader_commit",
        "work_enter",
        "reconcile",
        "work_exit",
        "leader_unlock",
        "leader_commit",
        "leader_exit",
    ]


@pytest.mark.asyncio
async def test_reconcile_does_no_work_without_leadership(monkeypatch):
    events = _install_fakes(monkeypatch, [False])

    assert not await storage_reconcile.reconcile_storage_once()
    assert events == ["leader_enter", "leader_lock", "leader_commit", "leader_exit"]


@pytest.mark.asyncio
async def test_reconcile_asserts_successful_unlock(monkeypatch):
    events = _install_fakes(monkeypatch, [True, False])

    with pytest.raises(RuntimeError, match="unlock was not owned"):
        await storage_reconcile.reconcile_storage_once()
    assert events[-3:] == ["leader_unlock", "leader_commit", "leader_exit"]
