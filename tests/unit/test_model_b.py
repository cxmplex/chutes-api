"""Unit tests for seedless Model-B logical-host control."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from api.host.router import router as host_router
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import CpuServerRegistrationArgs, Host, HostRegistrationArgs
from api.server import service as svc

HOTKEY = "5C4zjxDLpaRPGSz7cMoYjexEoZubat3tRYBqKuf5LVu8ejZd"


def _args(host_id="l0-unit-1", **kw):
    return HostRegistrationArgs(host_id=host_id, capacity=4, tee_type="sev-snp", **kw)


def _host(host_id="l0-unit-1", channel="stable", owner=HOTKEY):
    return Host(
        host_id=host_id,
        name=host_id,
        miner_hotkey=owner,
        tee_type="sev-snp",
        release_channel=channel,
        capacity=1,
        storage_enabled=False,
        provisioning_state="ready",
        enrollment_generation=1,
        active_key_generation=1,
        identity_durable_at=datetime.now(timezone.utc),
        identity_metadata_sha256="1" * 64,
        steady_config_sha256="2" * 64,
    )


def test_host_enrollment_openapi_preserves_v1_and_exposes_gpu_v2():
    app = FastAPI()
    app.include_router(host_router, prefix="/hosts")
    schemas = app.openapi()["components"]["schemas"]

    assert "compute_type" not in schemas["EnrollmentVoucherClaimsV1"]["properties"]
    assert schemas["EnrollmentVoucherClaimsV1"]["properties"]["version"]["const"] == 1
    assert schemas["EnrollmentVoucherClaimsV2"]["properties"]["compute_type"]["const"] == "gpu"
    assert schemas["EnrollmentVoucherClaimsV2"]["properties"]["storage_enabled"]["const"] is True
    assert schemas["HostEnrollmentStatusV2"]["properties"]["compute_type"]["const"] == "gpu"
    registration = schemas["HostRegistrationArgs"]
    storage_requested = registration["properties"]["storage_requested"]
    assert "storage_requested" not in registration.get("required", [])
    assert {item["type"] for item in storage_requested["anyOf"]} == {
        "boolean",
        "null",
    }


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
    """Collect direct auth dependency function names declared on a host route."""
    for route in host_router.routes:
        if route.path == path and method in route.methods:
            return [getattr(dep.call, "__name__", "") for dep in route.dependant.dependencies]
    raise AssertionError(f"route {method} {path} not found")


@pytest.mark.parametrize(
    "path,method,dependency",
    [
        ("/register", "POST", "get_ready_host"),
        ("/{host_id}/upgrade-image", "POST", "_authenticate"),
        ("/", "GET", "_authenticate"),
    ],
)
def test_host_routes_use_scoped_or_miner_auth_as_designed(path, method, dependency):
    assert dependency in _route_auth_dependencies(path, method)


@pytest.mark.asyncio
async def test_register_host_valid_updates_telemetry_only():
    with patch.object(svc.settings, "skip_metagraph_check", True):
        # No active release -> registration explicitly attaches release=None.
        with patch(
            "api.releases.service.active_manifest_for_host",
            AsyncMock(return_value=None),
        ):
            db = _mock_db()
            host = _host()
            res = await svc.register_host(db, _args(), host)
        assert res == {
            "host_id": "l0-unit-1",
            "capacity": 4,
            "storage_requested": False,
            "storage_enabled": False,
            "status": "registered",
            "release": None,
        }
        assert not db.add.called
        assert host.capacity == 4


@pytest.mark.asyncio
async def test_legacy_cpu_storage_payload_opts_in_without_double_reserving_capacity():
    host = _host()
    args = HostRegistrationArgs(
        host_id=host.host_id,
        capacity=3,
        tee_type="sev-snp",
        storage_enabled=True,
        disk_total_gb=100,
        disk_free_gb=60,
    )
    assert args.storage_requested is None
    db = _mock_db()
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch(
            "api.releases.service.active_manifest_for_host",
            AsyncMock(return_value=None),
        ),
    ):
        result = await svc.register_host(db, args, host)

    assert result["capacity"] == 3
    assert result["storage_requested"] is True
    assert result["storage_enabled"] is True
    assert host.reported_capacity == 3
    assert host.capacity == 3
    assert host.storage_requested is True
    assert host.disk_total_gb == 100
    assert host.disk_free_gb == 60


@pytest.mark.asyncio
async def test_legacy_gpu_storage_payload_omission_reaches_registration_service():
    host = _host("gpu-legacy-storage")
    host.tee_type = "tdx"
    host.compute_type = "gpu"
    host.storage_requested = True
    host.storage_enabled = True
    host.boot_generation = 1
    args = HostRegistrationArgs(
        host_id=host.host_id,
        capacity=1,
        tee_type="tdx",
        compute_type="gpu",
        release_channel="stable",
        storage_enabled=True,
        host_boot_id="11111111-1111-1111-1111-111111111111",
        untrusted_gpu_inventory={
            "configured_profile": "b200-8gpu",
            "devices": [],
            "observed_count": 0,
            "expected_count": 8,
            "profile_match": False,
        },
        untrusted_gpu_inventory_ready=True,
    )
    assert args.storage_requested is None
    readiness = SimpleNamespace(
        trusted_storage_ready=True,
        control_channel_eligible=True,
        trusted_schedulable=True,
        reason="ready",
    )
    observe = AsyncMock(return_value={"storage-server"})
    advance_boot = AsyncMock()
    db = _mock_db()
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch(
            "api.host.reservations.observe_gpu_storage_liveness",
            observe,
        ),
        patch(
            "api.host.gpu_allocations.advance_gpu_host_boot",
            advance_boot,
        ),
        patch(
            "api.releases.service.active_manifest_for_host",
            AsyncMock(return_value=None),
        ),
        patch.object(
            svc,
            "gpu_host_storage_readiness",
            AsyncMock(return_value=readiness),
        ),
    ):
        result = await svc.register_host(db, args, host)

    assert result["capacity"] == 1
    assert result["storage_requested"] is True
    assert result["storage_enabled"] is True
    observe.assert_awaited_once_with(db, host.host_id)
    advance_boot.assert_awaited_once_with(db, host, str(args.host_boot_id))


@pytest.mark.asyncio
async def test_registration_cannot_erase_reenrolled_storage_intent_or_restore_capacity():
    host = _host()
    host.storage_requested = True
    host.storage_enabled = False
    args = HostRegistrationArgs(
        host_id=host.host_id,
        capacity=4,
        tee_type="sev-snp",
        storage_requested=False,
        storage_enabled=False,
    )

    for _ in range(2):
        db = _mock_db()
        with (
            patch.object(svc.settings, "skip_metagraph_check", True),
            patch(
                "api.releases.service.active_manifest_for_host",
                AsyncMock(return_value=None),
            ),
        ):
            result = await svc.register_host(db, args, host)

        assert result["capacity"] == 3
        assert result["storage_requested"] is True
        assert result["storage_enabled"] is False
        assert host.reported_capacity == 4
        assert host.capacity == 3
        assert host.disk_total_gb is None
        assert host.disk_free_gb is None


@pytest.mark.asyncio
async def test_register_host_uses_requested_release_channel_on_first_boot():
    active_manifest = AsyncMock(return_value=None)
    db = _mock_db()
    host = _host(channel="canary")
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch(
            "api.releases.service.active_manifest_for_host",
            active_manifest,
        ),
    ):
        await svc.register_host(db, _args(release_channel="canary"), host)

    active_manifest.assert_awaited_once_with(
        db,
        "sev-snp",
        "canary",
        "cpu",
        host_id="l0-unit-1",
        miner_hotkey=HOTKEY,
    )


@pytest.mark.asyncio
async def test_register_host_propagates_desired_release_lookup_failure():
    db = _mock_db()
    host = _host(channel="canary")
    lookup = AsyncMock(side_effect=RuntimeError("malformed active release"))
    with (
        patch.object(svc.settings, "skip_metagraph_check", True),
        patch("api.releases.service.active_manifest_for_host", lookup),
        pytest.raises(RuntimeError, match="malformed active release"),
    ):
        await svc.register_host(db, _args(release_channel="canary"), host)

    lookup.assert_awaited_once_with(
        db,
        "sev-snp",
        "canary",
        "cpu",
        host_id="l0-unit-1",
        miner_hotkey=HOTKEY,
    )


@pytest.mark.asyncio
async def test_register_host_rejects_identity_field_changes():
    host = _host()
    with pytest.raises(ServerRegistrationError, match="authenticated host"):
        await svc.register_host(_mock_db(), _args(host_id="other"), host)
    with pytest.raises(ServerRegistrationError, match="TEE, compute type, or release channel"):
        await svc.register_host(
            _mock_db(),
            _args(release_channel="canary"),
            host,
        )


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


def _cpu_registration_args():
    return CpuServerRegistrationArgs(
        server_id="td-unit-1",
        name="td-unit-1",
        quote="quote",
        tee_type="sev-snp",
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

    with pytest.raises(ServerRegistrationError, match="requires.*launch reservation"):
        await _run_full_cpu_registration(
            _cpu_registration_args(),
            [membership],
            db,
            redis,
        )

    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    redis.decr.assert_not_awaited()


def test_guest_supplied_host_id_is_rejected_by_registration_schema():
    values = _cpu_registration_args().model_dump()
    values["host_id"] = "victim-host"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CpuServerRegistrationArgs.model_validate(values)


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
async def test_register_host_rejects_nonready_enrollment():
    host = _host()
    host.provisioning_state = "awaiting_pcs"
    with pytest.raises(ServerRegistrationError, match="not launch-ready"):
        await svc.register_host(_mock_db(), _args(), host)


def test_host_registration_schema_accepts_zero_only_as_nonnegative_input():
    assert (
        HostRegistrationArgs(
            host_id="storage-only",
            capacity=0,
            storage_requested=True,
        ).capacity
        == 0
    )
    with pytest.raises(ValidationError, match="greater than or equal"):
        HostRegistrationArgs(host_id="negative", capacity=-1, storage_requested=True)
    with pytest.raises(ValidationError, match="storage-requested"):
        HostRegistrationArgs(host_id="zero-compute", capacity=0)



def test_legacy_cpu_storage_payload_and_explicit_false_are_distinct():
    legacy = HostRegistrationArgs(
        host_id="legacy-cpu-storage",
        capacity=0,
        storage_enabled=True,
        disk_total_gb=100,
        disk_free_gb=50,
    )
    assert legacy.storage_requested is None
    assert legacy.storage_enabled is True

    with pytest.raises(ValidationError, match="durable storage intent"):
        HostRegistrationArgs(
            host_id="explicitly-disabled-cpu-storage",
            storage_requested=False,
            storage_enabled=True,
            disk_total_gb=100,
            disk_free_gb=50,
        )

def test_cpu_storage_capability_requires_current_disk_health():
    with pytest.raises(ValidationError, match="current disk capacity"):
        HostRegistrationArgs(
            host_id="cpu-storage-no-capacity",
            storage_requested=True,
            storage_enabled=True,
        )

    valid = HostRegistrationArgs(
        host_id="cpu-storage-healthy",
        storage_requested=True,
        storage_enabled=True,
        disk_total_gb=100,
        disk_free_gb=60,
    )
    assert valid.storage_enabled is True
    assert valid.disk_free_gb == 60

    with pytest.raises(ValidationError, match="while storage is unhealthy"):
        HostRegistrationArgs(
            host_id="cpu-storage-withdrawn",
            storage_requested=True,
            storage_enabled=False,
            disk_total_gb=100,
            disk_free_gb=60,
        )


def test_gpu_host_registration_requires_tdx_and_storage_posture():
    gpu = HostRegistrationArgs(
        host_id="gpu-host",
        tee_type="tdx",
        compute_type="gpu",
        storage_enabled=True,
        capacity=1,
        host_boot_id="11111111-1111-1111-1111-111111111111",
        untrusted_gpu_inventory={
            "configured_profile": "b200-8gpu",
            "devices": [],
            "observed_count": 0,
            "expected_count": 8,
            "profile_match": False,
        },
        untrusted_gpu_inventory_ready=True,
    )
    assert gpu.compute_type == "gpu"
    assert gpu.storage_requested is None
    with pytest.raises(ValidationError, match="GPU hosts require TDX"):
        HostRegistrationArgs(
            host_id="gpu-snp",
            tee_type="sev-snp",
            compute_type="gpu",
            storage_requested=True,
            storage_enabled=True,
            host_boot_id="11111111-1111-1111-1111-111111111111",
            untrusted_gpu_inventory={
                "configured_profile": "b200-8gpu",
                "devices": [],
                "observed_count": 0,
                "expected_count": 8,
                "profile_match": False,
            },
            untrusted_gpu_inventory_ready=False,
        )
    with pytest.raises(ValidationError, match="storage_requested/storage_enabled"):
        HostRegistrationArgs(
            host_id="gpu-explicit-storage-false",
            tee_type="tdx",
            compute_type="gpu",
            storage_requested=False,
            storage_enabled=True,
            host_boot_id="11111111-1111-1111-1111-111111111111",
            untrusted_gpu_inventory={
                "configured_profile": "b200-8gpu",
                "devices": [],
                "observed_count": 0,
                "expected_count": 8,
                "profile_match": False,
            },
            untrusted_gpu_inventory_ready=True,
        )
    with pytest.raises(ValidationError, match="storage_enabled"):
        HostRegistrationArgs(
            host_id="gpu-no-storage",
            tee_type="tdx",
            compute_type="gpu",
            storage_requested=True,
            storage_enabled=False,
            host_boot_id="11111111-1111-1111-1111-111111111111",
            untrusted_gpu_inventory={
                "configured_profile": "b200-8gpu",
                "devices": [],
                "observed_count": 0,
                "expected_count": 8,
                "profile_match": False,
            },
            untrusted_gpu_inventory_ready=False,
        )


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
                storage_requested=True,
                tee_type="sev-snp",
            ),
            _host("storage-only"),
        )
    assert not db.add.called
    assert result["capacity"] == 0
    assert result["storage_requested"] is True
    assert result["storage_enabled"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "args",
    [
        HostRegistrationArgs.model_construct(
            host_id="negative",
            capacity=-1,
            storage_enabled=True,
            tee_type="sev-snp",
            release_channel="stable",
        ),
        HostRegistrationArgs.model_construct(
            host_id="zero-compute",
            capacity=0,
            storage_enabled=False,
            tee_type="sev-snp",
            release_channel="stable",
        ),
        HostRegistrationArgs.model_construct(
            host_id="overflow",
            capacity=65,
            storage_enabled=True,
            tee_type="sev-snp",
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
        await svc.register_host(db, args, _host(args.host_id))
    db.commit.assert_not_awaited()
