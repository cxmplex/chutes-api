"""Unit tests for Model B (per-chute L0 host control plane): register_host auth (signature +
timestamp-nonce freshness + ownership). The scheduler dispatch + route are integration-verified."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bittensor_wallet.keypair import Keypair

from api.server.exceptions import ServerRegistrationError
from api.server.schemas import Host, HostRegistrationArgs
from api.server import service as svc

SEED = "409ac200a7c1409c9b7b318f0ff3b2357d1aa39ef132142a12898c782ae4c3b7"
_KP = Keypair.create_from_seed("0x" + SEED)
HOTKEY = _KP.ss58_address


def _sig(nonce: str) -> str:
    return _KP.sign(f"{HOTKEY}:{nonce}:host_register".encode()).hex()


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


@pytest.mark.asyncio
async def test_register_host_rejects_stale_nonce():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        stale = str(int(time.time()) - 9999)
        with pytest.raises(ServerRegistrationError, match="stale"):
            await svc.register_host(_mock_db(), _args(), HOTKEY, stale, _sig(stale))


@pytest.mark.asyncio
async def test_register_host_rejects_bad_signature():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        nonce = str(int(time.time()))
        with pytest.raises(ServerRegistrationError, match="signature"):
            await svc.register_host(_mock_db(), _args(), HOTKEY, nonce, "00" * 64)


@pytest.mark.asyncio
async def test_register_host_rejects_non_timestamp_nonce():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        with pytest.raises(ServerRegistrationError, match="unix timestamp"):
            await svc.register_host(_mock_db(), _args(), HOTKEY, "not-a-number", _sig("not-a-number"))


@pytest.mark.asyncio
async def test_register_host_valid_upserts():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        nonce = str(int(time.time()))
        db = _mock_db()
        res = await svc.register_host(db, _args(), HOTKEY, nonce, _sig(nonce))
        assert res == {"host_id": "l0-unit-1", "capacity": 4, "status": "registered"}
        assert db.add.called  # new Host row added


@pytest.mark.asyncio
async def test_register_host_rejects_wrong_owner():
    """A host already owned by a different miner cannot be hijacked."""
    with patch.object(svc.settings, "skip_metagraph_check", True):
        nonce = str(int(time.time()))
        other = Host(host_id="l0-unit-1", name="x", miner_hotkey="5OTHER", capacity=1)
        with pytest.raises(ServerRegistrationError, match="different miner"):
            await svc.register_host(_mock_db(existing_host=other), _args(), HOTKEY, nonce, _sig(nonce))
