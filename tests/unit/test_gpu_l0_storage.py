from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.config import measurement_trust_set_fingerprint
from api.host.reservations import gpu_host_storage_readiness
from api.host.schemas import (
    StorageLaunchIntent,
    TdLaunchReservation,
    TdLaunchReservationClaimsV1,
    TdLaunchReservationClaimsV2,
    canonical_sha256,
)
from api.releases import service as release_service
from api.releases.schemas import (
    GpuL0StorageClosure,
    GuestRelease,
    RoleLaunchBinaryContract,
)
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import Host, Server, ServerAttestation
from api.server.service import _validate_existing_model_b_server_identity


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.value)


class _ReadinessDb:
    def __init__(self, *, intent, reservation, server, attestation, releases):
        self.results = iter(
            (
                _Result(intent),
                _Result(reservation),
                _Result(attestation),
                _Result([intent.server_id]),
            )
        )
        self.server = server
        self.releases = releases

    async def execute(self, _query):
        return next(self.results)

    async def get(self, model, key):
        if model is Server:
            return self.server
        if model is GuestRelease:
            return self.releases.get(key)
        raise AssertionError(f"unexpected lookup: {model} {key}")


@pytest.mark.asyncio
async def test_composed_release_locks_are_always_cpu_then_gpu():
    empty = SimpleNamespace()
    empty.scalars = lambda: SimpleNamespace(all=lambda: [])
    db = AsyncMock()
    db.execute.return_value = empty
    await release_service._lock_release_streams(
        db,
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
    )
    release_locks = [
        call.args[1]["lock_key"]
        for call in db.execute.await_args_list
        if len(call.args) > 1 and "lock_key" in call.args[1]
    ]
    assert release_locks == [
        "guest-release:stable:tdx:cpu",
        "guest-release:stable:tdx:gpu",
    ]


def test_gpu_storage_reservation_v2_binds_both_streams_without_changing_v1():
    now = datetime.now(timezone.utc)
    common = {
        "reservation_id": "reservation-1",
        "token_id": "token-1",
        "owner_hotkey": "owner",
        "host_id": "gpu-host",
        "host_key_generation": 1,
        "server_id": "chute-stor1234",
        "role": "storage",
        "compute_type": "cpu",
        "tee_type": "tdx",
        "process_incarnation": "stor1234",
        "boot_generation": 1,
        "release_id": "cpu-storage-source",
        "image_sha256": "1" * 64,
        "image_version": "1.10.0",
        "profile_id": "storage-baremetal-tdx-1.10.0-2vcpu-8g",
        "storage_intent_id": "intent-1",
        "storage_intent_generation": 1,
        "launch_nonce": "bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4=",
        "release_target_sha256": "2" * 64,
        "issued_at": now,
        "expires_at": now + timedelta(minutes=10),
    }
    cpu = TdLaunchReservationClaimsV1(**common)
    gpu = TdLaunchReservationClaimsV2(
        **common,
        host_compute_type="gpu",
        gpu_release_id="gpu-active",
        active_cpu_release_id="cpu-active",
    )
    assert cpu.version == 1
    assert "host_compute_type" not in cpu.model_dump()
    assert gpu.version == 2
    assert gpu.release_id == "cpu-storage-source"
    assert gpu.active_cpu_release_id == "cpu-active"
    assert gpu.gpu_release_id == "gpu-active"
    assert canonical_sha256(gpu) != canonical_sha256(cpu)


def test_reported_capacity_live_and_orm_defaults_are_identical():
    assert str(Host.__table__.c.reported_capacity.server_default.arg) == "1"
    assert str(StorageLaunchIntent.__table__.c.host_compute_type.server_default.arg) == "cpu"
    assert str(TdLaunchReservation.__table__.c.claims_version.server_default.arg) == "1"
    assert str(TdLaunchReservation.__table__.c.host_compute_type.server_default.arg) == "cpu"
    migration = (
        Path(__file__).resolve().parents[2]
        / "api/migrations/20260723040000_gpu_l0_storage_sibling.sql"
    ).read_text()
    assert "ALTER COLUMN reported_capacity SET DEFAULT 1" in migration
    assert "host_compute_type TEXT NOT NULL DEFAULT 'cpu'" in migration
    assert "claims_version INTEGER NOT NULL DEFAULT 1" in migration


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("compute_type", "gpu"),
        ("storage_role", False),
        ("self_registered", False),
        ("host_id", "other-host"),
    ],
)
def test_storage_registration_never_overwrites_unrelated_same_miner_server(
    field,
    value,
):
    server = Server(
        server_id="chute-stor1234",
        miner_hotkey="owner",
        compute_type="cpu",
        storage_role=True,
        self_registered=True,
        host_id="gpu-host",
    )
    setattr(server, field, value)
    claims = SimpleNamespace(
        server_id=server.server_id,
        owner_hotkey="owner",
        role="storage",
        host_id="gpu-host",
        process_incarnation="stor1234",
    )
    prior = TdLaunchReservation(
        server_id=server.server_id,
        owner_hotkey="owner",
        host_id="gpu-host",
        role="storage",
        compute_type="cpu",
        process_incarnation="stor1234",
    )
    with pytest.raises(ServerRegistrationError, match="role lineage"):
        _validate_existing_model_b_server_identity(server, claims, prior)


def _readiness_state(*, consumed=True, announced=True):
    now = datetime.now(timezone.utc)
    profile_id = "storage-baremetal-tdx-1.10.0-2vcpu-8g"
    image = {
        "sha256": "1" * 64,
        "version": "1.10.0",
        "measurement_names": [profile_id],
        "kernel_sha256": "3" * 64,
        "initrd_sha256": "4" * 64,
        "cmdline_sha256": "5" * 64,
    }
    active_cpu = GuestRelease(
        release_id="cpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status="active",
        images={"storage": dict(image)},
    )
    source = GuestRelease(
        release_id="cpu-source",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status="superseded",
        images={"storage": dict(image)},
    )
    active_gpu = GuestRelease(
        release_id="gpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status="active",
        images={"gpu": {"sha256": "2" * 64}},
    )
    host = Host(
        host_id="gpu-host",
        name="gpu-host",
        miner_hotkey="owner",
        tee_type="tdx",
        compute_type="gpu",
        release_channel="stable",
        storage_requested=True,
        storage_enabled=True,
        capacity=0,
        reported_capacity=1,
    )
    intent = StorageLaunchIntent(
        intent_id="intent-1",
        target_id=None,
        release_id=source.release_id,
        tee_type="tdx",
        channel="stable",
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        server_id="chute-stor1234",
        process_incarnation="stor1234",
        profile_id=profile_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        host_compute_type="gpu",
        gpu_release_id=active_gpu.release_id,
        active_cpu_release_id=active_cpu.release_id,
        kernel_sha256="3" * 64,
        initrd_sha256="4" * 64,
        cmdline_sha256="5" * 64,
        launch_contract={
            "role": "storage",
            "qemu_binary": "qemu-system-x86_64",
            "qemu_package": "qemu-system-x86",
            "qemu_package_version": "1:10.1.0+ds-5ubuntu2.7",
            "qemu_binary_sha256": "8" * 64,
            "machine_type": "pc-q35-10.1",
            "firmware_filename": "OVMF.inteltdx.fd",
            "firmware_sha256": "9" * 64,
        },
        state="active",
        claim_generation=1,
    )
    reservation = TdLaunchReservation(
        reservation_id="reservation-1",
        storage_intent_id=intent.intent_id,
        storage_intent_generation=1,
        claims_version=2,
        host_compute_type="gpu",
        invalidated_at=None,
        issued_at=now - timedelta(minutes=2),
        consumed_at=now - timedelta(minutes=1) if consumed else None,
        consumed_cert_pubkey_hash="6" * 64 if consumed else None,
        boot_generation=1,
    )
    config = SimpleNamespace(
        name=profile_id,
        version="1.10.0-storage-tdx-2vcpu",
        config_fingerprint="7" * 64,
        image_sha256=image["sha256"],
    )
    trust = measurement_trust_set_fingerprint([config])
    server = Server(
        server_id=intent.server_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        compute_type="cpu",
        tee_type="tdx",
        storage_role=True,
        launch_reservation_id=reservation.reservation_id,
        launch_boot_generation=reservation.boot_generation,
        measurement_name=profile_id,
        measurement_config_fingerprint=config.config_fingerprint,
        trust_set_fingerprint=trust,
        attested_cert_pubkey_hash="6" * 64,
        storage_incarnation="incarnation-1",
        storage_incarnation_announced_at=now if announced else None,
    )
    attestation = ServerAttestation(
        server_id=server.server_id,
        verification_error=None,
        verified_at=now,
        created_at=now,
        measurement_name=profile_id,
        measurement_version=config.version,
        measurement_config_fingerprint=config.config_fingerprint,
        trust_set_fingerprint=trust,
    )
    db = _ReadinessDb(
        intent=intent,
        reservation=reservation,
        server=server,
        attestation=attestation,
        releases={
            active_cpu.release_id: active_cpu,
            source.release_id: source,
            active_gpu.release_id: active_gpu,
        },
    )
    contract = RoleLaunchBinaryContract.model_validate(intent.launch_contract)
    closure = GpuL0StorageClosure(
        source_release_id=source.release_id,
        image_version=image["version"],
        image_sha256=image["sha256"],
        kernel_sha256=image["kernel_sha256"],
        initrd_sha256=image["initrd_sha256"],
        cmdline_sha256=image["cmdline_sha256"],
        measurement_names=[profile_id],
        launch_contract=contract,
    )
    return host, db, config, server.server_id, contract, closure


@pytest.mark.asyncio
async def test_gpu_storage_gate_requires_consumed_current_reservation():
    host, db, config, _server_id, contract, closure = _readiness_state(consumed=False)
    configured = SimpleNamespace(
        tee_measurements=[config],
        release_attestation_max_age_seconds=3600,
    )
    with (
        patch("api.host.reservations.settings", configured),
        patch.object(release_service, "_storage_launch_contract", return_value=contract),
        patch.object(
            release_service,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=closure)),
                "a" * 64,
            ),
        ),
    ):
        readiness = await gpu_host_storage_readiness(db, host)
    assert readiness.trusted_storage_ready is False
    assert readiness.trusted_schedulable is False
    assert readiness.reason == "current_storage_reservation_not_consumed"


@pytest.mark.asyncio
async def test_gpu_storage_gate_ignores_stale_old_channel_intent():
    host, db, _config, _server_id, _contract, _closure = _readiness_state()
    host.release_channel = "canary"
    readiness = await gpu_host_storage_readiness(
        db,
        host,
        include_allocation=False,
    )
    assert readiness.trusted_storage_ready is False
    assert readiness.reason == "storage_intent_host_identity_stale"


@pytest.mark.asyncio
async def test_gpu_storage_gate_loses_and_recovers_on_fresh_live_health():
    host, lost_db, config, server_id, contract, closure = _readiness_state()
    configured = SimpleNamespace(
        tee_measurements=[config],
        release_attestation_max_age_seconds=3600,
    )
    with (
        patch("api.host.reservations.settings", configured),
        patch.object(release_service, "_storage_launch_contract", return_value=contract),
        patch.object(
            release_service,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=closure)),
                "a" * 64,
            ),
        ),
        patch(
            "api.storage.service._live_storage_ids",
            AsyncMock(return_value=set()),
        ),
    ):
        lost = await gpu_host_storage_readiness(lost_db, host)
    assert lost.reason == "storage_health_not_fresh"
    assert lost.trusted_schedulable is False

    host, ready_db, config, server_id, contract, closure = _readiness_state()
    configured = SimpleNamespace(
        tee_measurements=[config],
        release_attestation_max_age_seconds=3600,
    )
    with (
        patch("api.host.reservations.settings", configured),
        patch.object(release_service, "_storage_launch_contract", return_value=contract),
        patch.object(
            release_service,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=closure)),
                "a" * 64,
            ),
        ),
        patch(
            "api.storage.service._live_storage_ids",
            AsyncMock(return_value={server_id}),
        ),
    ):
        ready = await gpu_host_storage_readiness(ready_db, host)
    assert ready.reason == "storage_ready_gpu_group_unavailable"
    assert ready.allocation_group_available is False
    assert ready.trusted_storage_ready is True
    assert ready.control_channel_eligible is True
    assert ready.trusted_schedulable is False
    assert ready.physical_co_location_trusted is False


@pytest.mark.asyncio
async def test_gpu_storage_gate_fails_closed_when_cpu_sidecar_changes():
    host, db, config, _server_id, contract, closure = _readiness_state()
    source = db.releases["cpu-source"]
    source.images = {
        "storage": {
            **source.images["storage"],
            "kernel_sha256": "f" * 64,
        }
    }
    configured = SimpleNamespace(
        tee_measurements=[config],
        release_attestation_max_age_seconds=3600,
    )
    with (
        patch("api.host.reservations.settings", configured),
        patch.object(release_service, "_storage_launch_contract", return_value=contract),
        patch.object(
            release_service,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=closure)),
                "a" * 64,
            ),
        ),
    ):
        readiness = await gpu_host_storage_readiness(db, host)
    assert readiness.reason == "storage_intent_release_identity_stale"
    assert readiness.trusted_storage_ready is False
