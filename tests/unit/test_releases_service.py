"""Release safety gates: exact CPU matrices, provenance, and rollout targeting."""

import json
import copy
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
    RELEASE_STATUS_SUPERSEDED,
    CreateReleaseRequest,
    GpuReleaseImage,
    GpuL0StorageClosure,
    GuestRelease,
    ReleaseImage,
    RoleLaunchBinaryContract,
)
from api.server.schemas import Host


RELEASE_URL = (
    "http://storage.googleapis.com/ardent-stacker-232906-chutes-tee/l0/guest/snp-1.7.0-debug.qcow2"
)
VCPU_SIZES = (1, 2, 4, 8)


@pytest.fixture(autouse=True)
def _seedless_l0_gate_is_covered_separately():
    with (
        patch.object(
            rsvc,
            "_validate_l0_bootstrap",
            AsyncMock(return_value=Mock()),
        ),
        patch.object(rsvc, "_mark_l0_publication_active", AsyncMock()),
        patch.object(rsvc, "_ensure_storage_launch_intents", AsyncMock()),
    ):
        yield


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


def test_direct_tdx_release_rejects_partial_ram_qualified_matrix():
    names = [f"cpu-baremetal-tdx-1.9.0-{vcpus}vcpu-8g" for vcpus in VCPU_SIZES]
    pins = {
        name: SimpleNamespace(
            name=name,
            gpu_count=0,
            expected_gpus=[],
            tee_type="tdx",
            provider="bare-metal",
        )
        for name in names
    }
    release = GuestRelease(
        release_id="direct-partial",
        channel="canary",
        tee_type="tdx",
        status=RELEASE_STATUS_DRAFT,
        images={
            "chute": _image(
                version="1.9.0",
                tee_type="tdx",
                names=names,
                debug=False,
            )
        },
    )

    with pytest.raises(rsvc.ReleaseError, match="complete ordered vCPU/RAM"):
        rsvc._validate_image_provenance(release, "chute", release.images["chute"], pins)


def test_partial_release_materializes_omitted_active_image_slots():
    current = _release(chute=_image(), l0={"version": "l0-old"})
    current.release_id = "current"
    current.status = RELEASE_STATUS_ACTIVE
    candidate = _release(storage=_image("storage"))
    candidate.release_id = "candidate"

    merged = rsvc._merged_release_images(candidate, current)

    assert {k: v for k, v in merged["chute"].items() if k != "_inherited"} == current.images[
        "chute"
    ]
    assert merged["chute"]["_inherited"] is True
    assert {k: v for k, v in merged["l0"].items() if k != "_inherited"} == current.images["l0"]
    assert merged["l0"]["_inherited"] is True
    assert merged["storage"] == candidate.images["storage"]


def test_inherited_l0_marker_cannot_replace_the_current_active_l0():
    current = _release(l0={"version": "l0-current"})
    current.release_id = "current"
    current.status = RELEASE_STATUS_ACTIVE
    candidate = _release(l0={"version": "l0-stale", "_inherited": True})
    candidate.release_id = "candidate"

    merged = rsvc._merged_release_images(candidate, current)

    assert merged["l0"]["version"] == "l0-current"
    assert merged["l0"]["_inherited"] is True


@pytest.mark.asyncio
async def test_idempotent_partial_activation_preserves_inherited_role_marker():
    release = _release(
        chute={**_image(sha="b" * 64), "_inherited": True},
        storage=_image("storage", sha="c" * 64),
    )
    release.status = RELEASE_STATUS_ACTIVE
    release.targets_captured_at = datetime.now(timezone.utc)
    db = _db(release)

    with (
        patch.object(
            rsvc,
            "get_active_release",
            AsyncMock(return_value=release),
        ),
        patch.object(rsvc, "_validate_image_provenance"),
    ):
        activated = await rsvc.activate_release(db, release.release_id)

    assert activated.images["chute"]["_inherited"] is True
    assert rsvc.release_manifest(activated).chute is not None
    assert rsvc._target_roles_for_host(activated, Host(capacity=2, storage_enabled=True)) == [
        "storage"
    ]
    assert db.commit.called


@pytest.mark.asyncio
async def test_rollback_partial_activation_inherits_current_role_without_promoting_it():
    release = _release(
        chute={**_image(sha="b" * 64), "_inherited": True},
        storage=_image("storage", sha="c" * 64),
    )
    release.release_id = "rollback"
    release.status = RELEASE_STATUS_SUPERSEDED
    release.targets_captured_at = datetime.now(timezone.utc)
    current = _release(chute=_image(sha="d" * 64))
    current.release_id = "current"
    current.status = RELEASE_STATUS_ACTIVE
    db = _db(release)

    with (
        patch.object(
            rsvc,
            "get_active_release",
            AsyncMock(return_value=current),
        ),
        patch.object(rsvc, "_validate_image_provenance"),
    ):
        activated = await rsvc.activate_release(db, release.release_id)

    assert activated.images["chute"]["sha256"] == "d" * 64
    assert activated.images["chute"]["_inherited"] is True
    assert activated.images["storage"]["sha256"] == "c" * 64
    assert "_inherited" not in activated.images["storage"]
    assert rsvc.release_manifest(activated).chute is not None
    assert rsvc._target_roles_for_host(activated, Host(capacity=2, storage_enabled=True)) == [
        "storage"
    ]
    assert db.commit.called


@pytest.mark.asyncio
async def test_storage_only_activation_preserves_active_chute_for_scheduler():
    current = _release(chute=_image())
    current.release_id = "current"
    current.status = RELEASE_STATUS_ACTIVE
    candidate = _release(storage=_image("storage"))
    candidate.release_id = "candidate"
    db = _db(candidate)

    with (
        patch.object(
            rsvc,
            "get_active_release",
            AsyncMock(return_value=current),
        ),
        patch.object(rsvc, "_validate_image_provenance") as validate,
    ):
        activated = await rsvc.activate_release(db, candidate.release_id)

    assert activated.images["chute"]["_inherited"] is True
    assert activated.images["storage"] == candidate.images["storage"]
    assert {call.args[1] for call in validate.call_args_list} == {
        "chute",
        "storage",
    }
    host = Host(capacity=2, storage_enabled=True)
    assert rsvc._target_roles_for_host(activated, host) == ["storage"]
    manifest = rsvc.release_manifest(activated)
    assert manifest.chute is not None
    assert manifest.storage is not None


@pytest.mark.asyncio
async def test_first_storage_only_tdx_release_is_rejected_as_unschedulable():
    candidate = _release(storage=_image("storage"))
    candidate.release_id = "candidate"
    candidate.tee_type = "tdx"

    with patch.object(rsvc, "get_active_release", AsyncMock(return_value=None)):
        with pytest.raises(rsvc.ReleaseError, match="unschedulable"):
            await rsvc.activate_release(_db(candidate), candidate.release_id)


def test_legacy_schema_v1_tdx_release_is_rejected_before_scheduling():
    measurements = _measurements(tee_type="tdx")
    image = _image(tee_type="tdx")
    release = GuestRelease(
        release_id="legacy-tdx",
        channel="canary",
        tee_type="tdx",
        status=RELEASE_STATUS_DRAFT,
        images={"chute": image},
    )

    with pytest.raises(rsvc.ReleaseError, match="schema-version 2"):
        rsvc._validate_image_provenance(
            release,
            "chute",
            image,
            {measurement.name: measurement for measurement in measurements},
        )


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


def test_host_manifest_contains_desired_state_but_no_launch_authorization():
    manifest = rsvc.release_manifest(_release(chute=_image()))
    assert manifest.chute is not None
    assert "target_tokens" not in manifest.model_dump()
    assert "launch_reservation" not in manifest.model_dump_json()


def test_release_request_accepts_each_role_matrix_and_rejects_empty():
    chute = ReleaseImage(**_image())
    storage = ReleaseImage(**_image("storage"))

    assert CreateReleaseRequest(tee_type="sev-snp", compute_type="cpu", chute=chute).storage is None
    assert (
        CreateReleaseRequest(tee_type="sev-snp", compute_type="cpu", storage=storage).chute is None
    )
    both = CreateReleaseRequest(
        tee_type="sev-snp",
        compute_type="cpu",
        chute=chute,
        storage=storage,
    )
    assert both.chute is chute
    assert both.storage is storage
    with pytest.raises(ValidationError, match="at least one"):
        CreateReleaseRequest(tee_type="sev-snp", compute_type="cpu")


def test_gpu_release_request_is_tdx_only_and_requires_exact_dual_cmdlines():
    gpu = GpuReleaseImage(
        url="https://artifacts.chutes.ai/releases/gpu-1.11.0.qcow2",
        sha256="1" * 64,
        debug=False,
        version="1.11.0",
        measurement_names=[
            "gpu-baremetal-tdx-1.11.0-b200-8gpu-platform",
            "gpu-baremetal-tdx-1.11.0-b200-8gpu-miner",
        ],
        kernel_sha256="2" * 64,
        initrd_sha256="3" * 64,
        cmdline_sha256={"platform": "4" * 64, "miner": "5" * 64},
    )

    request = CreateReleaseRequest(
        tee_type="tdx",
        compute_type="gpu",
        gpu=gpu,
    )
    assert request.gpu is gpu
    with pytest.raises(ValidationError, match="TDX-only"):
        CreateReleaseRequest(
            tee_type="sev-snp",
            compute_type="gpu",
            gpu=gpu,
        )
    with pytest.raises(ValidationError, match="cannot contain CPU"):
        CreateReleaseRequest(
            tee_type="tdx",
            compute_type="gpu",
            gpu=gpu,
            chute=ReleaseImage(**_image()),
        )
    with pytest.raises(ValidationError, match="must differ"):
        GpuReleaseImage(
            **{
                **gpu.model_dump(),
                "cmdline_sha256": {
                    "platform": "4" * 64,
                    "miner": "4" * 64,
                },
            }
        )


def test_release_inheritance_rejects_cross_compute_streams():
    cpu = _release(chute=_image())
    cpu.compute_type = "cpu"
    gpu = GuestRelease(
        release_id="gpu-release",
        channel=cpu.channel,
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_DRAFT,
        images={},
    )

    with pytest.raises(rsvc.ReleaseError, match="across compute streams"):
        rsvc._merged_release_images(gpu, cpu)


def test_persisted_release_slots_cannot_cross_compute_streams():
    cpu = _release(chute=_image())
    cpu.compute_type = "cpu"
    cpu.images["gpu"] = {"sha256": "9" * 64}
    with pytest.raises(rsvc.ReleaseError, match="opposite-stream"):
        rsvc.release_manifest(cpu)

    gpu = GuestRelease(
        release_id="malformed-gpu",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_ACTIVE,
        images={
            "gpu": {
                "url": "https://artifacts.chutes.ai/releases/gpu.qcow2",
                "sha256": "1" * 64,
            },
            "chute": _image(),
        },
    )
    with pytest.raises(rsvc.ReleaseError, match="opposite-stream"):
        rsvc.release_manifest(gpu)


def test_gpu_release_status_policy_tracks_runtime_convergence():
    import inspect
    from api.releases.schemas import ReleaseStatusResponse

    gpu = GuestRelease(
        release_id="gpu-source-only",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"gpu": {"sha256": "1" * 64}},
    )
    cpu = _release(chute=_image())
    cpu.compute_type = "cpu"

    assert rsvc._runtime_convergence_supported(gpu) is True
    assert rsvc._runtime_convergence_supported(cpu) is True
    source = inspect.getsource(rsvc.release_status)
    assert "GpuLaunchReservation" in source
    assert '"runtime_convergence_state": "tracked"' in source
    assert "guest_consumed_at" in source
    assert "gpu_evidence_sha256" in source
    assert "gpu_process_incarnation" in source
    assert "ServerAttestation.attestation_id.desc()" in source
    assert "latest.c.gpu_retired_at.is_(None)" in source
    assert "_revocation_failed" in source
    assert 'GpuLaunchReservation.state == "running"' in source
    assert "storage_sibling_ready" in source
    assert "old_process_exit_confirmed" in source
    assert '"physical_host_convergence_proven": False' in source
    assert '"pin_pruning_safe": False' in source
    assert "runtime_convergence_state" in ReleaseStatusResponse.model_fields


@pytest.mark.asyncio
async def test_gpu_storage_desired_state_keeps_exact_cpu_release_identity_without_mutation():
    profile_id = "storage-baremetal-tdx-1.10.0-2vcpu-8g"
    storage = {
        "url": "https://artifacts.chutes.ai/releases/storage-1.10.0.qcow2",
        "sha256": "7" * 64,
        "debug": False,
        "version": "1.10.0",
        "measurement_names": [profile_id],
        "kernel_sha256": "8" * 64,
        "initrd_sha256": "9" * 64,
        "cmdline_sha256": "a" * 64,
    }
    source = GuestRelease(
        release_id="cpu-storage-source",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status=RELEASE_STATUS_SUPERSEDED,
        images={"storage": dict(storage)},
    )
    active_cpu = GuestRelease(
        release_id="cpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"storage": {**storage, "_inherited": True}},
    )
    gpu = GuestRelease(
        release_id="gpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"gpu": {"sha256": "b" * 64}},
    )
    host = Host(
        host_id="gpu-host",
        miner_hotkey="owner",
        tee_type="tdx",
        compute_type="gpu",
        release_channel="stable",
        storage_enabled=True,
        storage_td_vcpus=2,
        storage_td_mem="8G",
    )
    before_active = copy.deepcopy(active_cpu.images)
    before_source = copy.deepcopy(source.images)
    contract = RoleLaunchBinaryContract(
        role="storage",
        qemu_binary="qemu-system-x86_64",
        qemu_package="qemu-system-x86",
        qemu_package_version="1:10.1.0+ds-5ubuntu2.7",
        qemu_binary_sha256="c" * 64,
        machine_type="pc-q35-10.1",
        firmware_filename="OVMF.inteltdx.fd",
        firmware_sha256="d" * 64,
    )
    closure = GpuL0StorageClosure(
        source_release_id=source.release_id,
        image_version=storage["version"],
        image_sha256=storage["sha256"],
        kernel_sha256=storage["kernel_sha256"],
        initrd_sha256=storage["initrd_sha256"],
        cmdline_sha256=storage["cmdline_sha256"],
        measurement_names=[profile_id],
        launch_contract=contract,
    )
    db = AsyncMock()
    db.get.return_value = source
    with (
        patch.object(rsvc, "get_active_release", AsyncMock(return_value=active_cpu)),
        patch.object(rsvc, "_validate_active_release"),
        patch.object(rsvc, "_storage_source_release", AsyncMock(return_value=source)),
        patch.object(rsvc, "_storage_launch_contract", return_value=contract),
        patch.object(
            rsvc,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(
                    manifest=SimpleNamespace(storage_closure=closure),
                ),
                "f" * 64,
            ),
        ),
    ):
        sibling = await rsvc._gpu_storage_sibling_for_host(
            db,
            gpu,
            host,
        )

    assert sibling.source_release_id == source.release_id
    assert sibling.active_cpu_release_id == active_cpu.release_id
    assert sibling.profile_id == profile_id
    assert sibling.image.sha256 == storage["sha256"]
    assert sibling.launch_contract == contract
    assert sibling.physical_co_location_trusted is False
    assert active_cpu.images == before_active
    assert source.images == before_source


@pytest.mark.asyncio
async def test_gpu_storage_intent_is_host_scoped_restart_idempotent_and_has_no_cpu_target():
    gpu = GuestRelease(
        release_id="gpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"gpu": {"sha256": "b" * 64}},
    )
    host = Host(
        host_id="gpu-host",
        miner_hotkey="owner",
        tee_type="tdx",
        compute_type="gpu",
        release_channel="stable",
        storage_enabled=True,
        provisioning_state="ready",
        identity_durable_at=datetime.now(timezone.utc),
    )
    sibling = SimpleNamespace(
        source_release_id="cpu-storage-source",
        active_cpu_release_id="cpu-active",
        profile_id="storage-baremetal-tdx-1.10.0-2vcpu-8g",
        image=SimpleNamespace(
            sha256="7" * 64,
            version="1.10.0",
            kernel_sha256="8" * 64,
            initrd_sha256="9" * 64,
            cmdline_sha256="a" * 64,
        ),
        launch_contract=RoleLaunchBinaryContract(
            role="storage",
            qemu_binary="qemu-system-x86_64",
            qemu_package="qemu-system-x86",
            qemu_package_version="1:10.1.0+ds-5ubuntu2.7",
            qemu_binary_sha256="c" * 64,
            machine_type="pc-q35-10.1",
            firmware_filename="OVMF.inteltdx.fd",
            firmware_sha256="d" * 64,
        ),
    )
    empty = Mock()
    empty.scalar_one_or_none.return_value = None
    first_db = AsyncMock()
    first_db.execute.return_value = empty
    first_db.add = MagicMock()
    with patch.object(
        rsvc,
        "_gpu_storage_sibling_for_host",
        AsyncMock(return_value=sibling),
    ):
        created = await rsvc._ensure_gpu_storage_launch_intent_for_host(
            first_db,
            gpu,
            host,
        )
    assert created.target_id is None
    assert created.host_compute_type == "gpu"
    assert created.release_id == sibling.source_release_id
    assert created.gpu_release_id == gpu.release_id
    assert created.active_cpu_release_id == sibling.active_cpu_release_id
    assert created.claim_generation in {None, 0}
    first_db.add.assert_called_once_with(created)

    found = Mock()
    found.scalar_one_or_none.return_value = created
    restart_db = AsyncMock()
    restart_db.execute.return_value = found
    restart_db.add = MagicMock()
    with patch.object(
        rsvc,
        "_gpu_storage_sibling_for_host",
        AsyncMock(return_value=sibling),
    ):
        recovered = await rsvc._ensure_gpu_storage_launch_intent_for_host(
            restart_db,
            gpu,
            host,
        )
    assert recovered is created
    restart_db.add.assert_not_called()


@pytest.mark.asyncio
async def test_cpu_storage_activation_invalidates_incompatible_gpu_l0_without_reissue():
    contract = RoleLaunchBinaryContract(
        role="storage",
        qemu_binary="qemu-system-x86_64",
        qemu_package="qemu-system-x86",
        qemu_package_version="1:10.1.0+ds-5ubuntu2.7",
        qemu_binary_sha256="c" * 64,
        machine_type="pc-q35-10.1",
        firmware_filename="OVMF.inteltdx.fd",
        firmware_sha256="d" * 64,
    )
    old_closure = GpuL0StorageClosure(
        source_release_id="old-storage",
        image_version="1.10.0",
        image_sha256="1" * 64,
        kernel_sha256="2" * 64,
        initrd_sha256="3" * 64,
        cmdline_sha256="4" * 64,
        measurement_names=["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
        launch_contract=contract,
    )
    new_closure = old_closure.model_copy(
        update={
            "source_release_id": "new-storage",
            "image_version": "1.11.0",
            "image_sha256": "5" * 64,
        }
    )
    cpu = GuestRelease(
        release_id="cpu-new",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"storage": {"sha256": "5" * 64}},
    )
    gpu = GuestRelease(
        release_id="gpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"gpu": {"sha256": "6" * 64}},
    )
    supersede = AsyncMock()
    ensure = AsyncMock()
    with (
        patch.object(
            rsvc,
            "_gpu_l0_storage_closure",
            AsyncMock(return_value=new_closure),
        ),
        patch.object(
            rsvc,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=old_closure)),
                "a" * 64,
            ),
        ),
        patch.object(rsvc, "_supersede_storage_intents", supersede),
        patch.object(rsvc, "_ensure_gpu_storage_launch_intents", ensure),
    ):
        await rsvc._refresh_active_gpu_storage_intents(
            AsyncMock(),
            active_cpu_release=cpu,
            gpu_release=gpu,
        )
    supersede.assert_awaited_once()
    ensure.assert_not_awaited()


@pytest.mark.asyncio
async def test_gpu_activation_rejects_l0_with_wrong_storage_artifact_closure():
    contract = RoleLaunchBinaryContract(
        role="storage",
        qemu_binary="qemu-system-x86_64",
        qemu_package="qemu-system-x86",
        qemu_package_version="1:10.1.0+ds-5ubuntu2.7",
        qemu_binary_sha256="c" * 64,
        machine_type="pc-q35-10.1",
        firmware_filename="OVMF.inteltdx.fd",
        firmware_sha256="d" * 64,
    )
    expected = GpuL0StorageClosure(
        source_release_id="storage-new",
        image_version="1.11.0",
        image_sha256="1" * 64,
        kernel_sha256="2" * 64,
        initrd_sha256="3" * 64,
        cmdline_sha256="4" * 64,
        measurement_names=["storage-baremetal-tdx-1.11.0-2vcpu-8g"],
        launch_contract=contract,
    )
    wrong = expected.model_copy(update={"image_sha256": "5" * 64})
    cpu = GuestRelease(
        release_id="cpu-active",
        channel="stable",
        tee_type="tdx",
        compute_type="cpu",
        status=RELEASE_STATUS_ACTIVE,
        images={"storage": {"sha256": "1" * 64}},
    )
    gpu = GuestRelease(
        release_id="gpu-draft",
        channel="stable",
        tee_type="tdx",
        compute_type="gpu",
        status=RELEASE_STATUS_DRAFT,
        images={"gpu": {"sha256": "6" * 64}},
    )
    with (
        patch.object(rsvc, "get_active_release", AsyncMock(return_value=cpu)),
        patch.object(rsvc, "_validate_active_release"),
        patch.object(
            rsvc,
            "_gpu_l0_storage_closure",
            AsyncMock(return_value=expected),
        ),
        patch.object(
            rsvc,
            "_verify_l0_release_contract",
            return_value=(
                SimpleNamespace(manifest=SimpleNamespace(storage_closure=wrong)),
                "a" * 64,
            ),
        ),
    ):
        with pytest.raises(rsvc.ReleaseError, match="does not match"):
            await rsvc._validate_gpu_storage_stream(AsyncMock(), gpu)


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
async def test_already_captured_rollout_commits_lifecycle_lock_before_liveness():
    measurements = _measurements()
    release = _release(chute=_image())
    release.status = RELEASE_STATUS_ACTIVE
    release.targets_captured_at = datetime.now(timezone.utc)
    host = Host(
        host_id="captured-rollout-host",
        miner_hotkey="miner",
        tee_type=release.tee_type,
        compute_type="cpu",
        release_channel=release.channel,
    )
    target = rsvc.GuestReleaseTarget(
        target_id="captured-rollout-target",
        release_id=release.release_id,
        host_id=host.host_id,
        miner_hotkey=host.miner_hotkey,
        tee_type=release.tee_type,
        compute_type="cpu",
        role="chute",
        current_generation=1,
        current_token_id="audit:captured-rollout-target",
        issued_at=datetime.now(timezone.utc),
    )
    db = _db(release)
    db.info = {}
    advisory_result = Mock()
    targets_result = Mock()
    targets_result.scalars.return_value.all.return_value = [target]
    hosts_result = Mock()
    hosts_result.scalars.return_value.all.return_value = [host]
    db.execute.side_effect = [advisory_result, targets_result, hosts_result]

    async def commit_and_release_guard():
        db.info.pop("gpu_lifecycle_lock_held", None)

    db.commit.side_effect = commit_and_release_guard

    async def assert_liveness_outside_lifecycle_lock(_host_id):
        assert db.info.get("gpu_lifecycle_lock_held") is not True
        return False

    with (
        _pinned(*measurements),
        patch(
            "api.agent_channel.is_agent_online",
            AsyncMock(side_effect=assert_liveness_outside_lifecycle_lock),
        ) as is_online,
    ):
        result = await rsvc.rollout_release(db, release.release_id)

    assert result["dispatched"] == 0
    is_online.assert_awaited_once_with(host.host_id)
    assert db.commit.await_count == 2


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
    assert db.commit.called
