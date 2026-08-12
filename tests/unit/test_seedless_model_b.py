import base64
import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.constants import HOTKEY_HEADER
from api.database import get_db_session
from api.host.schemas import (
    EnrollmentKeyChallengeRequestV1,
    EnrollmentKeyChallengeRequestV2,
    EnrollmentVoucherClaimsV1,
    EnrollmentVoucherClaimsV2,
    HostSigningEnvelopeV1,
    HostSigningEnvelopeV2,
    PcsMailboxAadV1,
    PcsMailboxAadV2,
    PcsMailboxEnvelopeV1,
    PcsMailboxEnvelopeV2,
    TdLaunchReservationClaimsV1,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.releases.bootstrap import (
    L0BootstrapVerificationError,
    parse_signed_l0_manifest,
    verify_signed_l0_manifest,
)
from api.releases.schemas import (
    CreateReleaseRequest,
    GuestRelease,
    L0ArtifactV1,
    L0BootstrapManifestV1,
    L0BootstrapManifestV2,
    L0BootstrapPublication,
    SignedL0BootstrapManifestV1,
    SignedL0BootstrapManifestV2,
)
from cross_repo_tests import repository_root
from api.releases import service as release_service
from api.releases.router import router as releases_router
from api.host.schemas import RegistrySession, RegistrySessionRequestV1
from api.registry.router import _registry_request_matches


def _publisher_registry(tmp_path, private_key, now):
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "schema": "chutes.l0-publisher-keys",
                "version": 1,
                "keys": [
                    {
                        "key_id": "release-1",
                        "epoch": 1,
                        "public_key": base64.b64encode(public).decode(),
                        "not_before": (now - timedelta(days=1)).isoformat(),
                        "not_after": (now + timedelta(days=30)).isoformat(),
                        "enabled": True,
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return path


def _signed_bootstrap(
    private_key,
    now,
    *,
    generation=1,
    key_id="release-1",
    key_epoch=1,
    squashfs_digest="4",
):
    def artifact(name, digest):
        return L0ArtifactV1(
            url=f"https://objects.example.com/l0/1/{name}",
            size=123,
            sha256=digest * 64,
        )

    manifest = L0BootstrapManifestV1(
        tee_type="tdx",
        channel="stable",
        generation=generation,
        key_id=key_id,
        key_epoch=key_epoch,
        l0_version="1.10.0",
        kernel=artifact("vmlinuz", "1"),
        initrd=artifact("initrd.img", "2"),
        cmdline=artifact("cc-cmdline", "3"),
        squashfs=artifact("filesystem.squashfs", squashfs_digest),
        validator_ca_sha256="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    signature = private_key.sign(manifest.canonical_bytes())
    return SignedL0BootstrapManifestV1(
        manifest=manifest,
        signature=base64.b64encode(signature).decode(),
    )


def _gpu_storage_closure():
    return {
        "schema": "chutes.gpu-l0-storage-closure",
        "version": 1,
        "source_release_id": "cpu-storage-release",
        "image_version": "1.10.0",
        "image_sha256": "6" * 64,
        "kernel_sha256": "7" * 64,
        "initrd_sha256": "8" * 64,
        "cmdline_sha256": "9" * 64,
        "measurement_names": [
            "storage-baremetal-tdx-1.10.0-2vcpu-8g",
        ],
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


def test_l0_bootstrap_signature_and_tamper_rejection(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)

    assert verify_signed_l0_manifest(signed, registry, now=now) == signed.manifest.digest()

    tampered = signed.model_copy(
        update={
            "manifest": signed.manifest.model_copy(
                update={"generation": signed.manifest.generation + 1}
            )
        }
    )
    with pytest.raises(L0BootstrapVerificationError, match="signature"):
        verify_signed_l0_manifest(tampered, registry, now=now)


def test_gpu_l0_v2_is_compute_bound_without_reinterpreting_cpu_v1(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    cpu = _signed_bootstrap(private_key, now)
    cpu_document = cpu.manifest.model_dump(mode="json", exclude_none=True)
    assert cpu_document["version"] == 1
    assert "compute_type" not in cpu_document

    gpu_manifest = L0BootstrapManifestV2.model_validate(
        {
            **cpu_document,
            "version": 2,
            "compute_type": "gpu",
            "storage_closure": _gpu_storage_closure(),
            "gpu_profile_id": "b200-8gpu",
            "gpu_qemu_sha256s": ["1" * 64],
            "gpu_tdvf_sha256s": ["2" * 64],
            "gpu_launch_public_key_id": "3" * 64,
            "gpu_launch_public_key_epoch": 1,
            "gpu_build_inputs_sha256": "4" * 64,
        }
    )
    gpu = SignedL0BootstrapManifestV2(
        manifest=gpu_manifest,
        signature=base64.b64encode(private_key.sign(gpu_manifest.canonical_bytes())).decode(),
    )
    assert verify_signed_l0_manifest(gpu, registry, now=now) == gpu.manifest.digest()
    assert (
        parse_signed_l0_manifest(
            gpu.model_dump(mode="json", exclude_none=True),
            compute_type="gpu",
        )
        == gpu
    )
    with pytest.raises(ValueError):
        parse_signed_l0_manifest(
            gpu.model_dump(mode="json", exclude_none=True),
            compute_type="cpu",
        )
    with pytest.raises(ValueError):
        parse_signed_l0_manifest(
            cpu.model_dump(mode="json", exclude_none=True),
            compute_type="gpu",
        )
    with pytest.raises(ValueError, match="GPU TDX"):
        L0BootstrapManifestV2.model_validate(
            {
                **gpu_manifest.model_dump(mode="json", exclude_none=True),
                "tee_type": "sev-snp",
            }
        )


def test_l0_bootstrap_expiry_rejected(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)

    with pytest.raises(L0BootstrapVerificationError, match="expired"):
        verify_signed_l0_manifest(signed, registry, now=now + timedelta(hours=2))


def test_l0_bootstrap_rejects_explicit_null_release_id():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_bootstrap(private_key, now)
    document = signed.model_dump(mode="json")
    document["manifest"]["release_id"] = None

    with pytest.raises(ValueError, match="omitted rather than null"):
        SignedL0BootstrapManifestV1.model_validate(document)


def test_release_openapi_exposes_compute_scope_gpu_slot_and_l0_v2():
    app = FastAPI()
    app.include_router(releases_router, prefix="/releases")
    schemas = app.openapi()["components"]["schemas"]

    assert schemas["CreateReleaseRequest"]["properties"]["compute_type"]["enum"] == [
        "cpu",
        "gpu",
    ]
    assert "gpu" in schemas["CreateReleaseRequest"]["properties"]
    assert "gpu" in schemas["ReleaseManifest"]["properties"]
    assert "required_gpu_measurement_names" in schemas["ReleaseStatusResponse"]["properties"]
    assert schemas["L0BootstrapManifestV2-Output"]["properties"]["compute_type"]["const"] == "gpu"
    assert "storage_closure" in schemas["L0BootstrapManifestV2-Output"]["required"]
    create_parameters = app.openapi()["paths"]["/releases"]["post"]["parameters"]
    request_identity = next(
        parameter
        for parameter in create_parameters
        if parameter["name"] == "X-Chutes-Release-Request-SHA256"
    )
    assert request_identity["in"] == "header"
    assert request_identity["required"] is True
    assert request_identity["schema"]["pattern"] == "^[0-9a-f]{64}$"


def test_release_create_route_requires_exact_identity_maps_conflict_and_echoes_identity():
    app = FastAPI()
    app.include_router(releases_router, prefix="/releases")
    database = object()
    app.dependency_overrides[get_db_session] = lambda: database
    create_route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/releases"
        and "POST" in getattr(route, "methods", set())
    )
    admin = Mock()
    admin.has_role.return_value = True
    for dependency in create_route.dependant.dependencies:
        if dependency.call is not get_db_session:
            app.dependency_overrides[dependency.call] = lambda: admin

    body = {
        "tee_type": "sev-snp",
        "compute_type": "cpu",
        "channel": "idempotency-dev",
        "chute": {
            "url": "https://artifacts.chutes.ai/releases/route-idempotency.qcow2",
            "sha256": "a" * 64,
            "debug": False,
            "version": "1.0.0",
            "measurement_names": ["cpu-baremetal-snp-genoa-1.0.0-1vcpu"],
        },
        "activate": False,
    }
    request = CreateReleaseRequest.model_validate(body)
    request_sha256 = request.canonical_sha256()

    with TestClient(app) as client:
        missing = client.post("/releases", json=body)
        malformed = client.post(
            "/releases",
            json=body,
            headers={"X-Chutes-Release-Request-SHA256": request_sha256.upper()},
        )
        conflict = client.post(
            "/releases",
            json=body,
            headers={"X-Chutes-Release-Request-SHA256": "0" * 64},
        )

        release = GuestRelease(
            release_id="route-release",
            tee_type="sev-snp",
            compute_type="cpu",
            channel="idempotency-dev",
            status="draft",
            images={},
            release_request_sha256=request_sha256,
        )
        with patch.object(
            release_service,
            "create_release",
            AsyncMock(return_value=release),
        ) as create:
            accepted = client.post(
                "/releases",
                json=body,
                headers={"X-Chutes-Release-Request-SHA256": request_sha256},
            )

    assert missing.status_code == 422
    assert malformed.status_code == 422
    assert conflict.status_code == 409
    assert accepted.status_code == 200
    assert accepted.json()["release_id"] == "route-release"
    assert accepted.json()["release_request_sha256"] == request_sha256
    create.assert_awaited_once_with(database, request, request_sha256)


@pytest.mark.asyncio
async def test_release_activation_gate_persists_verified_l0_audit(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)
    release = GuestRelease(
        release_id="release-1",
        tee_type="tdx",
        channel="stable",
        images={
            "l0": {
                "version": "1.10.0",
                "squashfs_sha256": "4" * 64,
                "bootstrap": signed.model_dump(mode="json", exclude_none=True),
            }
        },
    )
    empty = Mock()
    empty.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = empty
    db.get.return_value = None
    db.add = MagicMock()
    with patch.object(
        release_service.settings,
        "trusted_l0_publisher_keys_path",
        registry,
    ):
        await release_service._validate_l0_bootstrap(db, release)

    assert release.l0_manifest_generation == 1
    assert release.l0_manifest_key_id == "release-1"
    assert release.l0_manifest_key_epoch == 1
    assert release.l0_manifest_digest == signed.manifest.digest()
    publication = db.add.call_args.args[0]
    assert publication.source_release_id == release.release_id
    assert publication.admission_status == "staged"


@pytest.mark.asyncio
async def test_newer_staged_bootstrap_does_not_shadow_active_generation(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)
    publication = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        generation=1,
        manifest_digest=signed.manifest.digest(),
        key_id="release-1",
        key_epoch=1,
        l0_version="1.10.0",
        squashfs_sha256="4" * 64,
        signed_manifest=signed.model_dump(mode="json", exclude_none=True),
        admission_status="active",
        source_release_id="draft-bootstrap",
    )
    staged = L0BootstrapPublication(
        generation=2,
        admission_status="staged",
    )
    result = Mock()
    result.scalar_one_or_none.return_value = publication
    db = AsyncMock()
    db.execute.return_value = result
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    with (
        patch.object(
            release_service.settings,
            "trusted_l0_publisher_keys_path",
            registry,
        ),
    ):
        returned = await release_service.active_l0_bootstrap(db, "tdx", "stable")

    assert returned == signed
    query = db.execute.await_args.args[0]
    assert "active" in query.compile().params.values()
    assert staged.generation > publication.generation
    db.add.assert_not_called()
    db.flush.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_staged_only_bootstrap_is_not_served():
    result = Mock()
    result.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = result

    returned = await release_service.active_l0_bootstrap(db, "tdx", "stable")

    assert returned is None
    query = db.execute.await_args.args[0]
    assert "active" in query.compile().params.values()


@pytest.mark.asyncio
async def test_activation_switches_the_visible_l0_generation():
    release = GuestRelease(
        release_id="release-2",
        tee_type="tdx",
        channel="stable",
    )
    publication = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        compute_type="cpu",
        generation=2,
        admission_status="staged",
    )
    db = AsyncMock()
    await release_service._mark_l0_publication_active(db, release, publication)

    statement = db.execute.await_args.args[0]
    params = statement.compile().params
    assert {"active", "staged"} <= set(params.values())
    assert publication.admission_status == "active"
    assert publication.activated_at is not None


@pytest.mark.asyncio
async def test_l0_publication_rejects_equivocation_and_backward_key_epoch(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)
    release = GuestRelease(
        release_id="release-equivocation",
        tee_type="tdx",
        channel="stable",
        images={
            "l0": {
                "version": "1.10.0",
                "squashfs_sha256": "4" * 64,
                "bootstrap": signed.model_dump(mode="json", exclude_none=True),
            }
        },
    )
    existing = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        generation=1,
        manifest_digest="f" * 64,
        key_id="release-1",
        key_epoch=1,
        l0_version="other",
        squashfs_sha256="e" * 64,
        signed_manifest=signed.model_dump(mode="json", exclude_none=True),
        source_release_id="other-release",
    )
    result = Mock()
    result.scalar_one_or_none.return_value = existing
    db = AsyncMock()
    db.get.return_value = existing
    db.execute.return_value = result
    with patch.object(
        release_service.settings,
        "trusted_l0_publisher_keys_path",
        registry,
    ):
        with pytest.raises(release_service.ReleaseError, match="equivocation"):
            await release_service._admit_l0_bootstrap(db, release)

    newer = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        generation=2,
        manifest_digest="d" * 64,
        key_id="release-2",
        key_epoch=2,
        l0_version="newer",
        squashfs_sha256="c" * 64,
        signed_manifest=signed.model_dump(mode="json", exclude_none=True),
        source_release_id="newer-release",
    )
    matching_old = L0BootstrapPublication(
        tee_type="tdx",
        channel="stable",
        generation=1,
        manifest_digest=signed.manifest.digest(),
        key_id="release-1",
        key_epoch=1,
        l0_version="1.10.0",
        squashfs_sha256="4" * 64,
        signed_manifest=signed.model_dump(mode="json", exclude_none=True),
        source_release_id=release.release_id,
    )
    db = AsyncMock()
    db.get.return_value = matching_old
    result = Mock()
    result.scalar_one_or_none.return_value = newer
    db.execute.return_value = result
    with patch.object(
        release_service.settings,
        "trusted_l0_publisher_keys_path",
        registry,
    ):
        with pytest.raises(release_service.ReleaseError, match="cannot be reactivated"):
            await release_service._admit_l0_bootstrap(db, release)

    backward_signed = _signed_bootstrap(private_key, now, generation=3)
    release.images = {
        "l0": {
            "version": "1.10.0",
            "squashfs_sha256": "4" * 64,
            "bootstrap": backward_signed.model_dump(mode="json", exclude_none=True),
        }
    }
    db = AsyncMock()
    db.get.return_value = None
    result = Mock()
    result.scalar_one_or_none.return_value = newer
    db.execute.return_value = result
    with patch.object(
        release_service.settings,
        "trusted_l0_publisher_keys_path",
        registry,
    ):
        with pytest.raises(release_service.ReleaseError, match="epoch cannot move backwards"):
            await release_service._admit_l0_bootstrap(db, release)


def test_real_asgi_staged_only_404_then_active_response_verifies_in_miner_cli(
    tmp_path, monkeypatch
):
    miner_cli_source = repository_root("miner", start=Path(__file__)) / "src" / "chutes-miner-cli"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry_path = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)

    app = FastAPI()
    app.include_router(releases_router, prefix="/releases")
    app.dependency_overrides[get_db_session] = lambda: object()
    bootstrap_route = next(
        route for route in app.routes if getattr(route, "path", None) == "/releases/l0-bootstrap"
    )
    for dependency in bootstrap_route.dependant.dependencies:
        if dependency.call is not get_db_session:
            app.dependency_overrides[dependency.call] = lambda: None

    with (
        patch.object(
            release_service,
            "active_l0_bootstrap",
            AsyncMock(side_effect=[None, signed]),
        ),
        TestClient(app) as client,
    ):
        staged_only = client.get(
            "/releases/l0-bootstrap?tee_type=tdx&channel=stable",
            headers={HOTKEY_HEADER: "owner"},
        )
        response = client.get(
            "/releases/l0-bootstrap?tee_type=tdx&channel=stable",
            headers={HOTKEY_HEADER: "owner"},
        )
    assert staged_only.status_code == 404
    assert response.status_code == 200
    assert "release_id" not in response.json()["manifest"]

    monkeypatch.syspath_prepend(str(miner_cli_source))
    miner_l0 = importlib.import_module("chutes_miner_cli.l0")
    monkeypatch.setattr(
        miner_l0,
        "_publisher_registry",
        lambda: json.loads(registry_path.read_text(encoding="utf-8")),
    )
    verified = miner_l0.verify_bootstrap(
        response.json(),
        tee_type="tdx",
        channel="stable",
        now=now,
    )
    assert verified["generation"] == 1


def test_quote_commitment_binds_every_reservation_dimension():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    claims = TdLaunchReservationClaimsV1(
        reservation_id="reservation-1",
        token_id="token-1",
        owner_hotkey="owner",
        host_id="host-1",
        host_key_generation=2,
        server_id="chute-process1",
        role="chute",
        tee_type="tdx",
        process_incarnation="process1",
        boot_generation=3,
        release_id="release-1",
        image_sha256="1" * 64,
        image_version="1.10.0",
        profile_id="cpu-baremetal-tdx-1.10.0-2vcpu-8g",
        chute_id="chute-1",
        container_repository="owner/image",
        container_manifest_digest=f"sha256:{'a' * 64}",
        launch_nonce=base64.b64encode(b"n" * 32).decode(),
        release_target_sha256="2" * 64,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    commitment = TdQuoteCommitmentV1(
        reservation_sha256=canonical_sha256(claims),
        launch_nonce=claims.launch_nonce,
        attested_spki_sha256="3" * 64,
        release_target_sha256=claims.release_target_sha256,
        boot_generation=claims.boot_generation,
    )
    original = commitment.report_data_nonce()
    assert commitment.model_copy(update={"boot_generation": 4}).report_data_nonce() != original
    assert (
        commitment.model_copy(update={"attested_spki_sha256": "4" * 64}).report_data_nonce()
        != original
    )


def test_host_and_pcs_envelopes_are_strict_and_canonical():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    signing = HostSigningEnvelopeV1(
        host_id="host-1",
        key_generation=1,
        challenge_id="challenge-1",
        challenge="x" * 32,
        method="POST",
        target="/hosts/register",
        body_sha256="0" * 64,
        issued_at=now,
    )
    assert b'"schema":"chutes.host-signature"' in signing.signing_bytes()

    aad = PcsMailboxAadV1(
        owner_hotkey="owner",
        host_id="host-1",
        recipient_fingerprint="1" * 64,
        enrollment_generation=1,
        key_generation=1,
        message_id="message-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    envelope = PcsMailboxEnvelopeV1(
        sender_ephemeral_public_key=base64.b64encode(b"e" * 32).decode(),
        nonce=base64.b64encode(b"n" * 12).decode(),
        ciphertext=base64.b64encode(b"c" * 32).decode(),
        aad=aad,
        miner_signature=base64.b64encode(b"s" * 64).decode(),
    )
    assert envelope.miner_signing_bytes() == envelope.miner_signing_bytes()
    with pytest.raises(ValueError):
        PcsMailboxEnvelopeV1.model_validate({**envelope.model_dump(mode="json"), "unknown": True})

    gpu_signing = HostSigningEnvelopeV2(
        **signing.model_dump(mode="python", exclude={"version"}),
        version=2,
        compute_type="gpu",
    )
    assert b'"compute_type":"gpu"' in gpu_signing.signing_bytes()
    gpu_aad = PcsMailboxAadV2(
        **aad.model_dump(mode="python", exclude={"version"}),
        version=2,
        compute_type="gpu",
    )
    gpu_envelope = PcsMailboxEnvelopeV2(
        sender_ephemeral_public_key=envelope.sender_ephemeral_public_key,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        aad=gpu_aad,
        miner_signature=envelope.miner_signature,
    )
    assert gpu_envelope.version == 2
    assert gpu_envelope.kdf_label == "chutes/model-b/pcs-mailbox/v2"


def test_cpu_enrollment_v1_bytes_remain_unchanged_and_gpu_uses_v2():
    now = datetime(2026, 7, 23, tzinfo=timezone.utc)
    cpu_claims = EnrollmentVoucherClaimsV1(
        voucher_id="voucher-1",
        owner_hotkey="owner",
        host_id="host-1",
        tee_type="tdx",
        channel="stable",
        enrollment_generation=1,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    cpu_document = cpu_claims.model_dump(mode="json", exclude_none=True)
    assert cpu_document["version"] == 1
    assert "compute_type" not in cpu_document
    assert "storage_enabled" not in cpu_document

    gpu_claims = EnrollmentVoucherClaimsV2(
        **cpu_claims.model_dump(
            mode="python",
            exclude={"version", "tee_type"},
        ),
        version=2,
        tee_type="tdx",
        compute_type="gpu",
        storage_enabled=True,
    )
    assert gpu_claims.model_dump(mode="json")["compute_type"] == "gpu"

    public_key = base64.b64encode(b"k" * 32).decode()
    signature = base64.b64encode(b"s" * 64).decode()
    cpu_request = EnrollmentKeyChallengeRequestV1(
        voucher="voucher-1." + "a" * 64,
        ed25519_public_key=public_key,
        x25519_public_key=public_key,
        ed25519_signature=signature,
    )
    gpu_request = EnrollmentKeyChallengeRequestV2(
        voucher=cpu_request.voucher,
        compute_type="gpu",
        ed25519_public_key=public_key,
        x25519_public_key=public_key,
        ed25519_signature=signature,
    )
    assert b"compute_type" not in cpu_request.signing_bytes()
    assert b'"compute_type":"gpu"' in gpu_request.signing_bytes()


def test_registry_session_enforces_repository_action_and_exact_manifest():
    assert (
        RegistrySessionRequestV1(
            repository="owner/my--image__part",
            manifest_digest=f"sha256:{'a' * 64}",
        ).repository
        == "owner/my--image__part"
    )
    manifests = [f"sha256:{'a' * 64}", f"sha256:{'c' * 64}"]
    blobs = [f"sha256:{'b' * 64}"]
    tags = [f"sha256-{'a' * 64}.sig"]
    tag_digests = {tags[0]: manifests[1]}
    session = RegistrySession(
        repository="owner/image",
        actions=["pull"],
        manifest_digest=f"sha256:{'a' * 64}",
        allowed_manifests=manifests,
        allowed_blobs=blobs,
        allowed_manifest_tags=tags,
        manifest_tag_digests=tag_digests,
        descriptor_closure_sha256=canonical_sha256(
            {
                "schema": "chutes.oci-descriptor-closure",
                "version": 1,
                "root_manifest": f"sha256:{'a' * 64}",
                "manifests": manifests,
                "blobs": blobs,
                "manifest_tags": tags,
                "manifest_tag_digests": tag_digests,
            }
        ),
    )
    assert _registry_request_matches(session, "GET", "/v2/")
    assert _registry_request_matches(
        session,
        "GET",
        f"/v2/owner/image/manifests/sha256:{'a' * 64}",
    )
    assert _registry_request_matches(
        session,
        "GET",
        f"/v2/owner/image/manifests/sha256-{'a' * 64}.sig",
    )
    assert _registry_request_matches(
        session,
        "HEAD",
        f"/v2/owner/image/blobs/sha256:{'b' * 64}",
    )
    assert not _registry_request_matches(session, "GET", "/v2/owner/image/manifests/latest")
    assert not _registry_request_matches(
        session,
        "GET",
        f"/v2/other/image/manifests/sha256:{'a' * 64}",
    )
    assert not _registry_request_matches(
        session,
        "PUT",
        f"/v2/owner/image/manifests/sha256:{'a' * 64}",
    )
