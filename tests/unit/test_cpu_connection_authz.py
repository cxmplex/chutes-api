"""Authorization for GET /servers/cpu/{id}/connection (owner-connect discovery + provision token).

Two roles may obtain the connection info + a single-use provision token: the miner that registered
the server, and the RENTER who owns the chute/job whose instance the scheduler placed on it. Both
must be the AUTHENTICATED principal -- a raw X-Chutes-Hotkey header must never gate this (an unsigned
request returns current_user=None while the header is attacker-supplied, so trusting it would let
anyone who knows the public miner hotkey mint a token for someone else's rental).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

import api.server.router as sr


class _Res:
    def __init__(self, all_rows=None, scalar=None):
        self._all = all_rows or []
        self._scalar = scalar

    def all(self):
        return self._all

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._all))


def _db(side_effects):
    return SimpleNamespace(execute=AsyncMock(side_effect=side_effects))


def _inst(instance_id="i1", chute_id="c1"):
    return SimpleNamespace(instance_id=instance_id, chute_id=chute_id)


# --- _caller_owns_server_workload: query order is instances -> jobs(by instance_id) -> chutes(cord only)

@pytest.mark.asyncio
async def test_cord_chute_owner_authorized():
    """A cord (job-less) instance: the chute author is the workload owner."""
    db = _db([_Res(all_rows=[_inst()]), _Res(all_rows=[]), _Res(all_rows=[("c1", "u1")])])
    assert await sr._caller_owns_server_workload(db, "srv", SimpleNamespace(user_id="u1")) is True


@pytest.mark.asyncio
async def test_job_owner_authorized_on_public_chute():
    """A job instance: the JOB owner is authorized even though they don't own the (public) chute."""
    db = _db([_Res(all_rows=[_inst()]), _Res(all_rows=[("i1", "u1")])])
    assert await sr._caller_owns_server_workload(db, "srv", SimpleNamespace(user_id="u1")) is True


@pytest.mark.asyncio
async def test_public_chute_author_NOT_authorized_for_other_users_job():
    """OVER-AUTH regression: a job instance's owner is the job user, NOT the chute author. The
    author of a public chute must NOT owner-connect to another user's running rental on it."""
    db = _db([_Res(all_rows=[_inst()]), _Res(all_rows=[("i1", "renter")])])
    # caller is the chute author, not the renter who owns the job -> rejected.
    assert await sr._caller_owns_server_workload(db, "srv", SimpleNamespace(user_id="author")) is False


@pytest.mark.asyncio
async def test_non_owner_cord_rejected():
    db = _db([_Res(all_rows=[_inst()]), _Res(all_rows=[]), _Res(all_rows=[("c1", "u1")])])
    assert await sr._caller_owns_server_workload(db, "srv", SimpleNamespace(user_id="u2")) is False


@pytest.mark.asyncio
async def test_no_user_rejected():
    assert await sr._caller_owns_server_workload(_db([]), "srv", None) is False


@pytest.mark.asyncio
async def test_no_instances_on_server_rejected():
    db = _db([_Res(all_rows=[])])
    assert await sr._caller_owns_server_workload(db, "srv", SimpleNamespace(user_id="u1")) is False


# --- endpoint-level authz (the bypass fix) ---

@pytest.mark.asyncio
async def test_unauthenticated_request_rejected_401():
    """No valid signature / API key -> current_user is None -> 401, BEFORE any header is trusted.
    Closes the bypass where an unsigned X-Chutes-Hotkey header authorized the miner-owner branch."""
    with pytest.raises(HTTPException) as exc:
        await sr.get_cpu_server_connection(server_id="srv", db=_db([]), current_user=None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_non_owner_rejected_404():
    """An authenticated user who is neither the miner owner nor the workload owner gets 404."""
    server = SimpleNamespace(
        server_id="srv", self_registered=True, compute_type="cpu", miner_hotkey="miner-hk"
    )
    # execute #1 -> the server; execute #2 -> the helper's (empty) instances query.
    db = _db([_Res(scalar=server), _Res(all_rows=[])])
    caller = SimpleNamespace(user_id="u2", hotkey="renter-hk")  # hotkey != miner-hk
    with pytest.raises(HTTPException) as exc:
        await sr.get_cpu_server_connection(server_id="srv", db=db, current_user=caller)
    assert exc.value.status_code == 404
