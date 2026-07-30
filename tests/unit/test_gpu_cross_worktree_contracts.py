"""Producer-to-consumer contracts across all four GPU alignment worktrees."""

import base64
import hashlib
import importlib
import importlib.util
import inspect
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
import pytest

from api.host.schemas import GpuLaunchReservationClaimsV1, canonical_sha256
from api.instance.router import (
    _canonical_miner_launch_request_id,
    get_launch_config,
)
from api.registry.router import _registry_session_response
from api.releases.provenance import load_canonical_provenance
from api.releases.schemas import (
    L0ArtifactV1,
    L0BootstrapManifestV2,
    SignedL0BootstrapManifestV2,
)
from api.server.gpu_sessions import (
    GPU_PLATFORM_RUNTIME_SESSION_PURPOSES,
    GPU_RUNTIME_SESSION_PURPOSES,
)
from api.storage.schemas import (
    LaunchStorageContext,
    LaunchStorageExchangeResponse,
    LaunchStorageSessionResponse,
)
from cross_repo_tests import repository_root


def _repository(name: str) -> Path:
    return repository_root(name, start=Path(__file__))


def _import_from_path(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _storage_closure() -> dict:
    return {
        "schema": "chutes.gpu-l0-storage-closure",
        "version": 1,
        "source_release_id": "cpu-storage-release",
        "image_version": "1.10.0",
        "image_sha256": "6" * 64,
        "kernel_sha256": "7" * 64,
        "initrd_sha256": "8" * 64,
        "cmdline_sha256": "9" * 64,
        "measurement_names": ["storage-baremetal-tdx-1.10.0-2vcpu-8g"],
        "launch_contract": {
            "role": "storage",
            "qemu_binary": "qemu-system-x86_64",
            "qemu_package": "qemu-system-x86",
            "qemu_package_version": "1:10.1.0+ds-5ubuntu2.7",
            "qemu_binary_sha256": "a" * 64,
            "machine_type": "pc-q35-10.1",
            "firmware_filename": "OVMF.inteltdx.fd",
            "firmware_sha256": "b" * 64,
        },
    }


def test_cross_repo_overrides_are_strict_and_per_repo_takes_precedence(monkeypatch, tmp_path):
    empty_workspace = tmp_path / "empty"
    empty_workspace.mkdir()
    monkeypatch.setenv("CHUTES_CROSS_REPO_ROOT", str(empty_workspace))
    monkeypatch.delenv("CHUTES_SEK8S_ROOT", raising=False)
    with pytest.raises(AssertionError, match="sek8s repository is missing"):
        _repository("sek8s")

    explicit_sek8s = tmp_path / "explicit-sek8s"
    explicit_sek8s.mkdir()
    monkeypatch.setenv("CHUTES_SEK8S_ROOT", str(explicit_sek8s))
    assert _repository("sek8s") == explicit_sek8s


def test_api_l0_v2_is_accepted_exactly_by_miner_cli(monkeypatch):
    miner_src = _repository("miner") / "src/chutes-miner-cli"
    sys.path.insert(0, str(miner_src))
    try:
        miner_l0 = importlib.import_module("chutes_miner_cli.l0")
    finally:
        sys.path.remove(str(miner_src))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()

    def artifact(name: str, digit: str) -> L0ArtifactV1:
        return L0ArtifactV1(
            url=f"https://objects.example.com/gpu-l0/1/{name}",
            size=123,
            sha256=digit * 64,
        )

    manifest = L0BootstrapManifestV2(
        tee_type="tdx",
        channel="stable",
        generation=1,
        key_id="publisher-1",
        key_epoch=1,
        l0_version="1.11.0",
        kernel=artifact("vmlinuz", "1"),
        initrd=artifact("initrd.img", "2"),
        cmdline=artifact("cc-cmdline", "3"),
        squashfs=artifact("filesystem.squashfs", "4"),
        validator_ca_sha256="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        storage_closure=_storage_closure(),
        gpu_profile_id="b200-8gpu",
        gpu_qemu_sha256s=["6" * 64],
        gpu_tdvf_sha256s=["7" * 64],
        gpu_launch_public_key_id="8" * 64,
        gpu_launch_public_key_epoch=1,
        gpu_build_inputs_sha256="9" * 64,
    )
    signed = SignedL0BootstrapManifestV2(
        manifest=manifest,
        signature=base64.b64encode(private_key.sign(manifest.canonical_bytes())).decode(),
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    monkeypatch.setattr(
        miner_l0,
        "_publisher_registry",
        lambda: {
            "schema": "chutes.l0-publisher-keys",
            "version": 1,
            "keys": [
                {
                    "key_id": "publisher-1",
                    "epoch": 1,
                    "public_key": base64.b64encode(public).decode(),
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                    "enabled": True,
                }
            ],
        },
    )
    document = signed.model_dump(mode="json", exclude_none=True)
    verified = miner_l0.verify_bootstrap(
        document,
        tee_type="tdx",
        channel="stable",
        compute_type="gpu",
        now=now,
    )
    assert verified == document["manifest"]
    assert verified["gpu_profile_id"] == "b200-8gpu"


def test_api_gpu_claim_fixture_is_byte_identical_and_parses_in_sek8s():
    api_fixture = _repository("api") / "tests/fixtures/gpu_launch_claims_v1.json"
    sek8s = _repository("sek8s")
    sek8s_fixture = sek8s / "tests/fixtures/gpu_launch_claims_v1.json"
    assert api_fixture.read_bytes() == sek8s_fixture.read_bytes()
    document = json.loads(api_fixture.read_text(encoding="ascii"))
    api_claims = GpuLaunchReservationClaimsV1.model_validate(document)
    sek8s_claims = _import_from_path(
        "cross_worktree_gpu_claims",
        sek8s / "src/chutes-agent/chutes_agent/gpu_claims.py",
    )
    parsed = sek8s_claims.parse_exact_gpu_claims(document)
    assert parsed.model_dump(mode="json", exclude_none=True, by_alias=True) == document
    assert canonical_sha256(api_claims) == (
        "b3b0199bd6c87befdd682f9c847a196b19d44773d78ffd6bf131e15f77543197"
    )


def test_miner_persists_and_sends_the_api_required_launch_request_uuid():
    miner_source = (
        _repository("miner") / "src/chutes-miner/chutes_miner/gepetto.py"
    ).read_text(encoding="utf-8")
    assert "intent_id = str(uuid.uuid4())" in miner_source
    assert '"miner_launch_request_id": intent_id' in miner_source
    assert 'params["miner_launch_request_id"] = intent_id' in miner_source

    handler_source = inspect.getsource(get_launch_config)
    attested_branch = handler_source.split("if runtime_server_id is not None:", 1)[
        1
    ].split("# Resolve external demand telemetry", 1)[0]
    assert (
        "_canonical_miner_launch_request_id(miner_launch_request_id)" in attested_branch
    )
    request_id = "88888888-8888-4888-8888-888888888888"
    assert _canonical_miner_launch_request_id(request_id) == request_id
    with pytest.raises(HTTPException) as exc:
        _canonical_miner_launch_request_id(None)
    assert getattr(exc.value, "status_code", None) == 422


def test_api_registry_response_is_accepted_and_bound_by_sek8s_consumer():
    registry_contract = _import_from_path(
        "cross_worktree_registry_contract",
        _repository("sek8s") / "src/chutes-agent/chutes_agent/registry_contract.py",
    )
    root = f"sha256:{'a' * 64}"
    signature = f"sha256:{'b' * 64}"
    blob = f"sha256:{'c' * 64}"
    tag = f"sha256-{'a' * 64}.sig"
    closure = {
        "schema": "chutes.oci-descriptor-closure",
        "version": 1,
        "root_manifest": root,
        "manifests": [root, signature],
        "blobs": [blob],
        "manifest_tags": [tag],
        "manifest_tag_digests": {tag: signature},
    }
    row = SimpleNamespace(
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        launch_config_id=None,
        repository="owner/image",
        manifest_digest=root,
        descriptor_closure_sha256=canonical_sha256(closure),
        allowed_manifests=closure["manifests"],
        allowed_blobs=closure["blobs"],
        allowed_manifest_tags=closure["manifest_tags"],
        manifest_tag_digests=closure["manifest_tag_digests"],
    )
    response = _registry_session_response(row, "registry-token").model_dump(mode="json")
    assert (
        registry_contract.validate_registry_session_response(
            response,
            repository="owner/image",
            manifest_digest=root,
        )
        == "registry-token"
    )


def test_runtime_purposes_and_launch_storage_context_match_consumers(monkeypatch):
    purposes = json.loads(
        (_repository("api") / "tests/fixtures/gpu_runtime_purposes_v1.json").read_text(
            encoding="ascii"
        )
    )
    assert purposes["miner"] == list(GPU_RUNTIME_SESSION_PURPOSES)
    assert purposes["platform"] == list(GPU_PLATFORM_RUNTIME_SESSION_PURPOSES)
    monkeypatch.setenv("MINER_OWNER_SS58", "5CrossWorktreeOwner")
    miner_settings = _import_from_path(
        "cross_worktree_miner_settings",
        _repository("miner") / "src/chutes-common/chutes_common/settings.py",
    )
    assert miner_settings.GPU_MINER_RUNTIME_PURPOSES == purposes["miner"]

    context = LaunchStorageContext(
        user_id="user-1",
        chute_id="chute-1",
        config_id="config-1",
        instance_id="instance-1",
        compute_type="gpu",
        management_mode="miner",
        server_id="server-1",
        default_volume_id="volume-1",
        verified_at="2026-07-25T00:00:00+00:00",
    ).model_dump(mode="json")
    sdk_context = _import_from_path(
        "cross_worktree_launch_context",
        _repository("sdk") / "chutes/util/launch_context.py",
    )
    parsed = sdk_context._parse_context(context)
    assert parsed.default_volume_id == context["default_volume_id"]
    assert parsed.management_mode == context["management_mode"]


def test_launch_storage_exchange_is_exact_producer_to_consumer_bytes():
    context = LaunchStorageContext(
        user_id="user-1",
        chute_id="chute-1",
        config_id="config-1",
        instance_id="instance-1",
        job_id=None,
        compute_type="gpu",
        management_mode="miner",
        server_id="server-1",
        default_volume_id="volume-1",
        verified_at="2026-07-25T00:00:00+00:00",
    )
    session = LaunchStorageSessionResponse(
        access_token="access-token",
        access_expires_at="2026-07-25T00:15:00+00:00",
        refresh_token="refresh-token",
        refresh_expires_at="2026-07-26T00:00:00+00:00",
        allowed_operations=["put", "get", "list", "delete"],
        generation=1,
    )
    produced = (
        LaunchStorageExchangeResponse(
            launch_context=context,
            storage_session=session,
        ).model_dump_json()
        + "\n"
    ).encode("ascii")
    api_fixture = (
        _repository("api") / "tests/fixtures/launch_storage_exchange_v1.json"
    ).read_bytes()
    sdk_fixture = (
        _repository("sdk") / "tests/fixtures/launch_storage_exchange_v1.json"
    ).read_bytes()
    assert produced == api_fixture == sdk_fixture

    payload = json.loads(produced)
    assert list(payload["storage_session"]) == [
        "schema",
        "version",
        "access_token",
        "access_expires_at",
        "refresh_token",
        "refresh_expires_at",
        "allowed_operations",
        "generation",
    ]
    sdk_context = _import_from_path(
        "cross_worktree_launch_context_bytes",
        _repository("sdk") / "chutes/util/launch_context.py",
    )
    parsed = sdk_context.install_launch_context(payload)
    assert parsed.default_volume_id == context.default_volume_id
    assert parsed.management_mode == context.management_mode


def test_full_gpu_provenance_fixture_is_one_canonical_document():
    api_fixture = _repository("api") / "tests/fixtures/gpu_provenance_v3_complete.json"
    sek8s_fixture = _repository("sek8s") / "tests/fixtures/gpu_provenance_v3_complete.json"
    payload = api_fixture.read_bytes()
    assert payload == sek8s_fixture.read_bytes()
    document = load_canonical_provenance(payload.decode("ascii"))
    assert document["schema_version"] == 3
    assert document["compute_type"] == "gpu"
    assert document["profile_contract_sha256"] == (
        "02f00e3808054419b3d9914d269a691649c34ba33d61a7b7523548c926c6ee75"
    )
    assert (
        hashlib.sha256(payload).hexdigest()
        == hashlib.sha256(sek8s_fixture.read_bytes()).hexdigest()
    )
