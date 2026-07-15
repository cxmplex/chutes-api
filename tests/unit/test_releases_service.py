"""Release safety gates: exact CPU matrices, provenance, and rollout targeting."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from pydantic import ValidationError

from api.releases import service as rsvc
from api.releases.provenance import canonical_provenance_bytes
from api.releases.schemas import (
    RELEASE_STATUS_ACTIVE,
    RELEASE_STATUS_DRAFT,
    CreateReleaseRequest,
    GuestRelease,
    GuestReleaseTarget,
    ReleaseImage,
)
from api.server.schemas import Host


RELEASE_URL = (
    "http://storage.googleapis.com/ardent-stacker-232906-chutes-tee/l0/guest/snp-1.7.0-debug.qcow2"
)
VCPU_SIZES = (1, 2, 4, 8)


def _names(role="chute", version="1.7.0", tee_type="sev-snp"):
    prefix = "storage" if role == "storage" else "cpu"
    if tee_type == "sev-snp":
        return [f"{prefix}-baremetal-snp-genoa-{version}-{vcpus}vcpu" for vcpus in VCPU_SIZES]
    return [f"{prefix}-baremetal-tdx-{version}-{vcpus}vcpu" for vcpus in VCPU_SIZES]


def _pin_version(version, role, tee_type, vcpus):
    tee_slug = "snp" if tee_type == "sev-snp" else "tdx"
    return f"{version}-{'storage-' if role == 'storage' else ''}{tee_slug}-{vcpus}vcpu"


def _measurement(
    name,
    *,
    names,
    vcpus,
    role="chute",
    version="1.7.0",
    sha="a" * 64,
    debug=True,
    tee_type="sev-snp",
    provider="bare-metal",
    gpu_count=0,
    expected_gpus=None,
    value="A" * 96,
):
    return SimpleNamespace(
        name=name,
        image_sha256=sha,
        image_measurement_names=list(names),
        debug=debug,
        tee_type=tee_type,
        provider=provider,
        version=_pin_version(version, role, tee_type, vcpus),
        gpu_count=gpu_count,
        expected_gpus=[] if expected_gpus is None else expected_gpus,
        measurement=value,
        mrtd=value,
        boot_rtmrs={f"RTMR{i}": chr(ord("B") + i) * 96 for i in range(4)},
        runtime_rtmrs={f"RTMR{i}": chr(ord("F") + i) * 96 for i in range(4)},
        vtpm_pcrs=None,
    )


def _measurements(
    role="chute",
    *,
    version="1.7.0",
    sha="a" * 64,
    debug=True,
    tee_type="sev-snp",
    provider="bare-metal",
):
    names = _names(role, version, tee_type)
    return [
        _measurement(
            name,
            names=names,
            vcpus=vcpus,
            role=role,
            version=version,
            sha=sha,
            debug=debug,
            tee_type=tee_type,
            provider=provider,
            value=chr(ord("A") + index) * 96,
        )
        for index, (name, vcpus) in enumerate(zip(names, VCPU_SIZES, strict=True))
    ]


def _pinned(*measurements):
    return patch.object(
        rsvc,
        "_loaded_measurements_by_name",
        return_value={measurement.name: measurement for measurement in measurements},
    )


def _image(
    role="chute",
    *,
    version="1.7.0",
    sha="a" * 64,
    debug=True,
    tee_type="sev-snp",
    names=None,
    provenance_payload=None,
    provenance_signature=None,
):
    return {
        "url": RELEASE_URL,
        "sha256": sha,
        "debug": debug,
        "version": version,
        "measurement_names": list(names or _names(role, version, tee_type)),
        "provenance_payload": provenance_payload,
        "provenance_signature": provenance_signature,
    }


def _release(**images):
    return GuestRelease(
        release_id="rel-1",
        channel="stable",
        tee_type="sev-snp",
        status=RELEASE_STATUS_DRAFT,
        images=images,
    )


def _db(release):
    db = AsyncMock()
    db.get = AsyncMock(return_value=release)
    empty = Mock()
    empty.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=empty)
    db.add_all = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _canonical_document(measurements, *, role="chute", sha="a" * 64):
    return {
        "schema_version": 1,
        "image": {"filename": "1.7.0-debug.qcow2", "sha256": sha},
        "tee_type": "sev-snp",
        "provider": "bare-metal",
        "role": role,
        "version": "1.7.0",
        "build_flags": {"debug_build": True, "debug_logging": True},
        "gpu_count": 0,
        "expected_gpus": [],
        "required_vcpu_sizes": list(VCPU_SIZES),
        "measurements": [
            {
                "name": measurement.name,
                "vcpus": vcpus,
                "values": {"measurement": measurement.measurement},
            }
            for measurement, vcpus in zip(measurements, VCPU_SIZES, strict=True)
        ],
    }


@pytest.mark.asyncio
async def test_activate_succeeds_with_complete_cpu_only_debug_dev_matrix():
    measurements = _measurements()
    release = _release(chute=_image())
    db = _db(release)
    with _pinned(*measurements):
        result = await rsvc.activate_release(db, release.release_id)
    assert result.status == RELEASE_STATUS_ACTIVE
    assert db.commit.called


@pytest.mark.asyncio
async def test_activate_refuses_unpinned_matrix_member():
    measurements = _measurements()
    release = _release(chute=_image())
    with _pinned(*measurements[:-1]):
        with pytest.raises(rsvc.ReleaseError, match="not pinned"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_activate_refuses_empty_present_image_matrix():
    release = _release(chute=_image(names=[]))
    release.images["chute"]["measurement_names"] = []
    with pytest.raises(rsvc.ReleaseError, match="no measurement names"):
        await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda pins: setattr(pins[0], "gpu_count", 1), "CPU-only"),
        (lambda pins: setattr(pins[0], "expected_gpus", ["h100"]), "CPU-only"),
        (lambda pins: setattr(pins[0], "provider", "gcp"), "provider=bare-metal"),
        (lambda pins: setattr(pins[0], "tee_type", "tdx"), "different TEE"),
        (
            lambda pins: setattr(pins[0], "version", "1.7.1-snp-1vcpu"),
            "pin versions",
        ),
        (
            lambda pins: setattr(pins[0], "image_sha256", "b" * 64),
            "exact digest",
        ),
        (lambda pins: setattr(pins[0], "debug", False), "debug posture"),
    ],
)
@pytest.mark.asyncio
async def test_activate_refuses_wrong_pin_semantics(mutation, message):
    measurements = _measurements()
    mutation(measurements)
    release = _release(chute=_image())
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match=message):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_activate_refuses_partial_or_reordered_matrix():
    measurements = _measurements()
    partial_names = _names()[:-1]
    release = _release(chute=_image(names=partial_names))
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="required vCPU matrix"):
            await rsvc.activate_release(_db(release), release.release_id)

    reordered_names = list(reversed(_names()))
    release = _release(chute=_image(names=reordered_names))
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="required vCPU matrix"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_activate_refuses_wrong_role_matrix():
    measurements = _measurements("chute", sha="b" * 64)
    release = _release(storage=_image("chute", sha="b" * 64))
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="wrong role"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_activate_refuses_version_relabel_in_measurement_names():
    measurements = _measurements(version="1.7.1")
    release = _release(chute=_image(version="1.7.0", names=_names(version="1.7.1")))
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="image version semantics"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_activate_refuses_pin_without_digest_matrix_binding():
    measurements = _measurements()
    measurements[0].image_measurement_names = None
    release = _release(chute=_image())
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="do not bind"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_production_never_accepts_unsigned_provenance():
    measurements = _measurements(debug=False)
    release = _release(chute=_image(debug=False))
    with (
        _pinned(*measurements),
        patch.object(rsvc.settings, "allow_debug_measurements", False),
        patch.object(rsvc.settings, "skip_metagraph_check", False),
    ):
        with pytest.raises(rsvc.ReleaseError, match="Production managed releases"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_unsigned_canonical_debug_payload_still_binds_measurement_values():
    measurements = _measurements()
    document = _canonical_document(measurements)
    document["measurements"][2]["values"]["measurement"] = "F" * 96
    payload = canonical_provenance_bytes(document).decode()
    release = _release(chute=_image(provenance_payload=payload))
    with _pinned(*measurements):
        with pytest.raises(rsvc.ReleaseError, match="pin values"):
            await rsvc.activate_release(_db(release), release.release_id)


@pytest.mark.asyncio
async def test_canonical_payload_binds_role_digest_version_and_debug_flags():
    measurements = _measurements()
    for mutate, match in (
        (lambda doc: doc.update(role="storage"), "release semantics"),
        (lambda doc: doc["image"].update(sha256="b" * 64), "sha256"),
        (lambda doc: doc.update(version="1.7.1"), "release semantics"),
        (
            lambda doc: doc["build_flags"].update(debug_build=False, debug_logging=False),
            "filename and debug_build posture disagree",
        ),
    ):
        document = _canonical_document(measurements)
        mutate(document)
        payload = canonical_provenance_bytes(document).decode()
        release = _release(chute=_image(provenance_payload=payload))
        with _pinned(*measurements):
            with pytest.raises(rsvc.ReleaseError, match=match):
                await rsvc.activate_release(_db(release), release.release_id)


def test_release_image_requires_exact_version_matrix_and_debug_posture():
    base = {
        "url": RELEASE_URL,
        "sha256": "a" * 64,
        "debug": True,
        "version": "1.7.0",
        "measurement_names": _names(),
    }
    assert ReleaseImage(**base).version == "1.7.0"
    for field in ("version", "measurement_names", "debug"):
        invalid = dict(base)
        invalid.pop(field)
        with pytest.raises(ValidationError):
            ReleaseImage(**invalid)


@pytest.mark.parametrize("debug", [None, "false", 0, 1])
def test_release_image_requires_strict_debug_boolean(debug):
    kwargs = {
        "url": RELEASE_URL,
        "sha256": "a" * 64,
        "version": "1.7.0",
        "measurement_names": _names(),
    }
    if debug is not None:
        kwargs["debug"] = debug
    with pytest.raises(ValidationError):
        ReleaseImage(**kwargs)


@pytest.mark.parametrize(
    "url",
    [
        RELEASE_URL,
        "https://artifacts.chutes.ai/releases/chute-1.7.0.qcow2",
        "https://artifacts.chutes.ai:443/releases/chute-1.7.0.qcow2",
        "https://8.8.8.8/releases/chute-1.7.0.qcow2",
    ],
)
def test_release_image_accepts_direct_public_urls(url):
    image = ReleaseImage(
        url=url,
        sha256="A" * 64,
        debug=False,
        version="1.7.0",
        measurement_names=_names(),
    )
    assert image.sha256 == "a" * 64


@pytest.mark.parametrize(
    "url",
    [
        "https://artifacts.chutes.ai/releases/$(id).qcow2",
        "https://artifacts.chutes.ai/releases/`id`.qcow2",
        "https://artifacts.chutes.ai/releases/chute image.qcow2",
        "https://user:secret@artifacts.chutes.ai/releases/chute.qcow2",
        "ftp://artifacts.chutes.ai/releases/chute.qcow2",
        "file:///var/lib/chutes/chute.qcow2",
        "http://artifacts.chutes.ai/releases/chute.qcow2",
        "https://localhost/releases/chute.qcow2",
        "https://127.0.0.1/releases/chute.qcow2",
        "https://169.254.169.254/releases/chute.qcow2",
        "https://artifacts.chutes.ai:8443/releases/chute.qcow2",
        "https://bad_host.example.com/releases/chute.qcow2",
        "https://artifacts.chutes.ai/releases/chute.qcow2?redirect=evil",
        "https://artifacts.chutes.ai/releases/%24%28id%29.qcow2",
    ],
)
def test_release_image_rejects_unsafe_urls(url):
    with pytest.raises(ValidationError):
        ReleaseImage(
            url=url,
            sha256="a" * 64,
            debug=False,
            version="1.7.0",
            measurement_names=_names(),
        )


def test_release_manifest_omits_provenance_from_host_payload():
    image = _image(
        provenance_payload=json.dumps({"secret": "not-host-data"}),
        provenance_signature="signature",
    )
    release = _release(chute=image)
    manifest = rsvc.release_manifest(release)
    dumped = manifest.model_dump()
    assert dumped["chute"]["version"] == "1.7.0"
    assert "provenance_payload" not in dumped["chute"]
    assert "provenance_signature" not in dumped["chute"]


def test_storage_release_auto_opts_in_before_role_target_snapshot():
    release = _release(chute=_image(), storage=_image("storage"))
    compute = Host(capacity=1, storage_enabled=False)
    storage_only = Host(capacity=0, storage_enabled=True)
    combined = Host(capacity=2, storage_enabled=True)
    rsvc._apply_storage_auto_opt_in(release, compute)
    assert compute.storage_enabled is True
    assert compute.capacity == 0
    assert rsvc._target_roles_for_host(release, compute) == ["storage"]
    assert rsvc._target_roles_for_host(release, storage_only) == ["storage"]
    assert rsvc._target_roles_for_host(release, combined) == ["chute", "storage"]


def test_storage_auto_opt_in_reserves_exactly_once():
    release = _release(chute=_image(), storage=_image("storage"))
    host = Host(capacity=2, storage_enabled=False)
    rsvc._apply_storage_auto_opt_in(release, host)
    rsvc._apply_storage_auto_opt_in(release, host)
    assert host.capacity == 1
    assert rsvc._target_roles_for_host(release, host) == ["chute", "storage"]


def test_host_manifest_carries_signed_logical_target_token_without_physical_claim():
    issued_at = datetime.now(timezone.utc)
    target = GuestReleaseTarget(
        target_id="target-1",
        release_id="rel-1",
        host_id="logical-host",
        miner_hotkey="miner",
        tee_type="sev-snp",
        role="chute",
        current_generation=7,
        current_token_id="target-token-generation-7",
        issued_at=issued_at,
    )
    token = rsvc._encode_release_target_token(target)
    payload = rsvc._decode_release_target_token(token)
    assert payload["release_id"] == "rel-1"
    assert payload["logical_host_id"] == "logical-host"
    assert payload["generation"] == 7
    assert "physical" not in payload
    manifest = rsvc.release_manifest(_release(chute=_image()), {"chute": token})
    assert manifest.target_tokens == {"chute": token}


def test_release_target_token_changes_hardware_attestation_nonce():
    nonce = "01" * 32
    token = "header.payload.signature"
    assert rsvc.release_bound_attestation_nonce(nonce, token) != nonce
    assert rsvc.release_bound_attestation_nonce(nonce, None) == nonce


def test_release_request_accepts_each_role_matrix_and_rejects_empty():
    chute = ReleaseImage(**_image())
    storage = ReleaseImage(**_image("storage"))

    assert CreateReleaseRequest(tee_type="sev-snp", chute=chute).storage is None
    assert CreateReleaseRequest(tee_type="sev-snp", storage=storage).chute is None
    both = CreateReleaseRequest(tee_type="sev-snp", chute=chute, storage=storage)
    assert both.chute is chute
    assert both.storage is storage
    with pytest.raises(ValidationError, match="at least one"):
        CreateReleaseRequest(tee_type="sev-snp")


@pytest.mark.asyncio
async def test_actual_committed_debug_matrix_activates_only_in_dev_posture(tmp_path):
    from pathlib import Path

    from api.config import Settings

    configured = Settings()
    configured.tee_committed_measurement_config_path = (
        Path(__file__).resolve().parents[2] / "api/config/tee_measurements.committed.yaml"
    )
    configured.tee_measurement_config_path = tmp_path / "absent.yaml"
    configured.allow_debug_measurements = True
    measurements = configured._load_tee_measurements()
    cpu_names = _names(version="1.6.2")
    storage_names = _names("storage", version="1.6.1")
    release = _release(
        chute=_image(
            version="1.6.2",
            names=cpu_names,
            sha="688d24a5ab1af8e2174ffada8d8ea669c38280b4b0fdd6936729fe697b5930e3",
        ),
        storage=_image(
            "storage",
            version="1.6.1",
            names=storage_names,
            sha="3121af4af5446f1dacc4a3290eba8605aa3c2a32a319d31c958c61faca5dd2da",
        ),
    )
    with _pinned(*measurements):
        activated = await rsvc.activate_release(_db(release), release.release_id)
    assert activated.status == RELEASE_STATUS_ACTIVE


def test_guest_release_has_single_active_partial_unique_index():
    index = next(
        item for item in GuestRelease.__table__.indexes if item.name == "uq_guest_release_active"
    )
    assert index.unique is True
    assert "status = 'active'" in str(index.dialect_options["postgresql"]["where"])


@pytest.mark.asyncio
async def test_empty_canary_list_targets_zero_hosts():
    measurements = _measurements()
    release = _release(chute=_image())
    release.status = RELEASE_STATUS_ACTIVE
    db = _db(release)
    result_proxy = Mock()
    result_proxy.scalars.return_value.all.return_value = []
    db.execute.return_value = result_proxy
    with _pinned(*measurements):
        result = await rsvc.rollout_release(db, release.release_id, host_ids=[])
    assert result["dispatched"] == 0
    assert "hosts.host_id IN" in str(db.execute.await_args.args[0])


@pytest.mark.asyncio
async def test_already_active_is_revalidated_before_idempotent_return():
    measurements = _measurements()
    release = _release(chute=_image())
    release.status = RELEASE_STATUS_ACTIVE
    release.targets_captured_at = datetime.now(timezone.utc)
    db = _db(release)
    with _pinned(*measurements):
        result = await rsvc.activate_release(db, release.release_id)
    assert result is release
    assert not db.commit.called
