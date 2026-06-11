"""Unit tests for Model B (per-chute L0 host control plane).

Authentication (timestamp-nonce freshness + signature + production metagraph membership) lives in
the router's `get_current_user` dependency -- pinned here by inspecting the route dependants.
The service owns the host-specific logic (upsert, ownership pinning), tested directly.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.host.router import router as host_router
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import Host, HostRegistrationArgs
from api.server import service as svc

HOTKEY = "5C4zjxDLpaRPGSz7cMoYjexEoZubat3tRYBqKuf5LVu8ejZd"


def _args(host_id="l0-unit-1", **kw):
    return HostRegistrationArgs(host_id=host_id, capacity=4, tee_type="sev-snp", **kw)


def _mock_db(existing_host=None, existing_node=object()):
    db = AsyncMock()
    # db.get: MetagraphNode lookup then Host lookup. Return a non-None node (skip auto-create) and
    # the given existing host (None => new).
    db.get = AsyncMock(side_effect=[existing_node, existing_host])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _route_auth_dependencies(path: str, method: str) -> list:
    """Collect the get_current_user._authenticate dependants declared on a host route."""
    for route in host_router.routes:
        if route.path == path and method in route.methods:
            return [
                dep
                for dep in route.dependant.dependencies
                if getattr(dep.call, "__name__", "") == "_authenticate"
            ]
    raise AssertionError(f"route {method} {path} not found")


@pytest.mark.parametrize(
    "path,method",
    [
        ("/register", "POST"),
        ("/{host_id}/upgrade-image", "POST"),
        ("/", "GET"),
    ],
)
def test_host_routes_carry_hotkey_auth_dependency(path, method):
    """Every host endpoint (including the list) must authenticate via get_current_user."""
    assert _route_auth_dependencies(path, method), (
        f"{method} {path} does not declare the get_current_user auth dependency"
    )


@pytest.mark.asyncio
async def test_register_host_valid_upserts():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        db = _mock_db()
        res = await svc.register_host(db, _args(), HOTKEY)
        assert res == {"host_id": "l0-unit-1", "capacity": 4, "status": "registered"}
        assert db.add.called  # new Host row added


@pytest.mark.asyncio
async def test_register_host_rejects_wrong_owner():
    """A host already owned by a different miner cannot be hijacked."""
    with patch.object(svc.settings, "skip_metagraph_check", True):
        other = Host(host_id="l0-unit-1", name="x", miner_hotkey="5OTHER", capacity=1)
        with pytest.raises(ServerRegistrationError, match="different miner"):
            await svc.register_host(_mock_db(existing_host=other), _args(), HOTKEY)


@pytest.mark.asyncio
async def test_register_host_rejects_missing_hotkey():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        with pytest.raises(ServerRegistrationError, match="hotkey"):
            await svc.register_host(_mock_db(), _args(), "")
