"""Unit tests for Model B (per-chute L0 host control plane).

Authentication (timestamp-nonce freshness + signature + production metagraph membership) lives in
the router's `get_current_user` dependency -- pinned here by inspecting the route dependants.
The service owns the host-specific logic (upsert, ownership pinning), tested directly.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from pydantic import ValidationError

from api.host.router import router as host_router
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import CpuServerRegistrationArgs, Host, HostRegistrationArgs
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
        # No active release -> registration explicitly attaches release=None.
        with patch(
            "api.releases.service.active_manifest_for_host",
            AsyncMock(return_value=None),
        ):
            db = _mock_db()
            res = await svc.register_host(db, _args(), HOTKEY)
        assert res == {
            "host_id": "l0-unit-1",
            "capacity": 4,
            "status": "registered",
            "release": None,
        }
        assert db.add.called  # new Host row added


@pytest.mark.asyncio
async def test_register_host_uses_requested_release_channel_on_first_boot():
    active_manifest = AsyncMock(return_value=None)
    db = _mock_db()
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch(
            "api.releases.service.active_manifest_for_host",
            active_manifest,
        ),
    ):
        await svc.register_host(db, _args(release_channel="canary"), HOTKEY)

    active_manifest.assert_awaited_once_with(
        db,
        "sev-snp",
        "canary",
        host_id="l0-unit-1",
        miner_hotkey=HOTKEY,
    )


@pytest.mark.asyncio
async def test_register_host_propagates_desired_release_lookup_failure():
    db = _mock_db()
    lookup = AsyncMock(side_effect=RuntimeError("malformed active release"))
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch("api.releases.service.active_manifest_for_host", lookup),
        pytest.raises(RuntimeError, match="malformed active release"),
    ):
        await svc.register_host(db, _args(release_channel="canary"), HOTKEY)

    lookup.assert_awaited_once_with(
        db,
        "sev-snp",
        "canary",
        host_id="l0-unit-1",
        miner_hotkey=HOTKEY,
    )


@pytest.mark.asyncio
async def test_register_host_rejects_wrong_owner():
    """A host already owned by a different miner cannot be hijacked."""
    with patch.object(svc.settings, "skip_metagraph_check", True):
        other = Host(host_id="l0-unit-1", name="x", miner_hotkey="5OTHER", capacity=1)
        with pytest.raises(ServerRegistrationError, match="different miner"):
            await svc.register_host(_mock_db(existing_host=other), _args(), HOTKEY)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "miner_hotkey", "tee_type", "provider", "message"),
    [
        (
            Host(
                host_id="l0-unit-1",
                name="victim",
                miner_hotkey="5OTHER",
                tee_type="sev-snp",
                capacity=4,
            ),
            HOTKEY,
            "sev-snp",
            "baremetal",
            "different miner",
        ),
        (
            Host(
                host_id="l0-unit-1",
                name="owner",
                miner_hotkey=HOTKEY,
                tee_type="tdx",
                capacity=4,
            ),
            HOTKEY,
            "sev-snp",
            "baremetal",
            "launches tdx",
        ),
        (
            Host(
                host_id="l0-unit-1",
                name="owner",
                miner_hotkey=HOTKEY,
                tee_type="sev-snp",
                capacity=4,
            ),
            HOTKEY,
            "sev-snp",
            "gcp",
            "incompatible",
        ),
    ],
)
async def test_cpu_registration_rejects_untrusted_host_claim_before_accounting(
    host, miner_hotkey, tee_type, provider, message
):
    result = Mock()
    result.scalar_one_or_none.return_value = host
    db = AsyncMock()
    db.execute.return_value = result
    measurement = SimpleNamespace(provider=provider)

    with pytest.raises(ServerRegistrationError, match=message):
        await svc._validate_cpu_registration_host(
            db,
            "l0-unit-1",
            miner_hotkey,
            tee_type,
            measurement,
        )

    db.commit.assert_not_awaited()


def _cpu_registration_args(host_id=None):
    return CpuServerRegistrationArgs(
        server_id="td-unit-1",
        name="td-unit-1",
        quote="quote",
        tee_type="sev-snp",
        host_id=host_id,
        benchmark={
            "cpu_cores": 4,
            "ram_gb": 16,
            "int_score": 1.0,
            "float_score": 1.0,
            "memory_bandwidth_mb_s": 1.0,
            "hash_score": 1.0,
            "composite_score": 1.0,
            "duration_ms": 1,
        },
    )


async def _run_full_cpu_registration(args, execute_results, db, redis):
    db.execute.side_effect = execute_results
    keypair = Mock()
    keypair.verify.return_value = True
    quote = Mock()
    measurement = SimpleNamespace(
        gpu_count=0,
        name="cpu-baremetal-snp",
        provider="baremetal",
        version="1.7.0",
    )
    with (
        patch.object(svc.settings, "skip_metagraph_check", False),
        patch.object(svc.settings, "netuid", 64),
        patch.object(svc.settings, "_redis_client", redis),
        patch.object(svc, "Keypair", return_value=keypair),
        patch.object(svc, "build_runtime_quote", return_value=quote),
        patch.object(
            svc,
            "verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={}),
        ),
        patch.object(svc, "get_matching_measurement_config", return_value=measurement),
        patch.object(svc, "validate_cpu_benchmark", return_value=args.benchmark),
    ):
        await svc.register_cpu_server(
            db,
            "203.0.113.10",
            args,
            HOTKEY,
            "nonce",
            "00",
            "a" * 64,
            "certificate",
        )


@pytest.mark.asyncio
async def test_full_baremetal_registration_without_host_id_cannot_bypass_capacity_accounting():
    membership = Mock()
    membership.scalar.return_value = True
    db = AsyncMock()
    db.add = MagicMock()
    redis = AsyncMock()

    with pytest.raises(ServerRegistrationError, match="requires.*host_id"):
        await _run_full_cpu_registration(
            _cpu_registration_args(),
            [membership],
            db,
            redis,
        )

    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    redis.decr.assert_not_awaited()


@pytest.mark.asyncio
async def test_full_baremetal_registration_cannot_charge_a_victim_hosts_capacity():
    membership = Mock()
    membership.scalar.return_value = True
    victim = Host(
        host_id="victim-host",
        name="victim",
        miner_hotkey="5Victim",
        tee_type="sev-snp",
        capacity=1,
    )
    host_lookup = Mock()
    host_lookup.scalar_one_or_none.return_value = victim
    db = AsyncMock()
    db.add = MagicMock()
    redis = AsyncMock()

    with pytest.raises(ServerRegistrationError, match="different miner"):
        await _run_full_cpu_registration(
            _cpu_registration_args("victim-host"),
            [membership, host_lookup],
            db,
            redis,
        )

    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    redis.decr.assert_not_awaited()


@pytest.mark.asyncio
async def test_hostless_gcp_model_a_registration_remains_valid():
    db = AsyncMock()
    measurement = SimpleNamespace(provider="gcp")

    assert (
        await svc._validate_cpu_registration_host(
            db,
            None,
            HOTKEY,
            "sev-snp",
            measurement,
        )
        is None
    )
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_host_rejects_missing_hotkey():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        with pytest.raises(ServerRegistrationError, match="hotkey"):
            await svc.register_host(_mock_db(), _args(), "")


def test_host_registration_schema_accepts_zero_only_as_nonnegative_input():
    assert (
        HostRegistrationArgs(
            host_id="storage-only",
            capacity=0,
            storage_enabled=True,
        ).capacity
        == 0
    )
    with pytest.raises(ValidationError, match="greater than or equal"):
        HostRegistrationArgs(host_id="negative", capacity=-1, storage_enabled=True)
    with pytest.raises(ValidationError, match="enrolled ChuteFS storage"):
        HostRegistrationArgs(host_id="zero-compute", capacity=0)


@pytest.mark.parametrize(
    "values",
    [
        {"capacity": 65},
        {"default_vcpus": 0},
        {"default_vcpus": 4097},
        {"default_mem": "0G"},
        {"default_mem": f"{2**63}G"},
        {"external_host": "bad host"},
        {"disk_total_gb": -1},
        {"disk_total_gb": 1, "disk_free_gb": 2},
        {"disk_total_gb": 8_589_934_592},
    ],
)
def test_host_registration_schema_rejects_unsafe_resource_bounds(values):
    with pytest.raises(ValidationError):
        HostRegistrationArgs(host_id="unsafe", **values)


@pytest.mark.asyncio
async def test_register_host_accepts_zero_capacity_storage_enrollment():
    db = _mock_db()
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch(
            "api.releases.service.active_manifest_for_host",
            AsyncMock(return_value=None),
        ),
    ):
        result = await svc.register_host(
            db,
            HostRegistrationArgs(
                host_id="storage-only",
                capacity=0,
                storage_enabled=True,
                tee_type="sev-snp",
            ),
            HOTKEY,
        )
    enrolled = db.add.call_args.args[0]
    assert enrolled.capacity == 0
    assert enrolled.storage_enabled is True
    assert result["capacity"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "args",
    [
        HostRegistrationArgs.model_construct(
            host_id="negative",
            capacity=-1,
            storage_enabled=True,
            release_channel="stable",
        ),
        HostRegistrationArgs.model_construct(
            host_id="zero-compute",
            capacity=0,
            storage_enabled=False,
            release_channel="stable",
        ),
        HostRegistrationArgs.model_construct(
            host_id="overflow",
            capacity=65,
            storage_enabled=True,
            release_channel="stable",
        ),
    ],
)
async def test_register_host_service_rejects_invalid_zero_or_negative_capacity(args):
    db = _mock_db()
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        pytest.raises(ServerRegistrationError, match="capacity"),
    ):
        await svc.register_host(db, args, HOTKEY)
    db.commit.assert_not_awaited()
