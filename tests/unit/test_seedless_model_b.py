import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from api.host.schemas import (
    HostSigningEnvelopeV1,
    PcsMailboxAadV1,
    PcsMailboxEnvelopeV1,
    TdLaunchReservationClaimsV1,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.releases.bootstrap import (
    L0BootstrapVerificationError,
    verify_signed_l0_manifest,
)
from api.releases.schemas import (
    GuestRelease,
    L0ArtifactV1,
    L0BootstrapManifestV1,
    SignedL0BootstrapManifestV1,
)
from api.releases import service as release_service
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


def _signed_bootstrap(private_key, now):
    def artifact(name, digest):
        return L0ArtifactV1(
            url=f"https://objects.example.com/l0/1/{name}",
            size=123,
            sha256=digest * 64,
        )

    manifest = L0BootstrapManifestV1(
        tee_type="tdx",
        channel="stable",
        generation=1,
        key_id="release-1",
        key_epoch=1,
        l0_version="1.10.0",
        kernel=artifact("vmlinuz", "1"),
        initrd=artifact("initrd.img", "2"),
        cmdline=artifact("cc-cmdline", "3"),
        squashfs=artifact("filesystem.squashfs", "4"),
        validator_ca_sha256="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    signature = private_key.sign(manifest.canonical_bytes())
    return SignedL0BootstrapManifestV1(
        manifest=manifest,
        signature=base64.b64encode(signature).decode(),
    )


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


def test_l0_bootstrap_expiry_rejected(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)

    with pytest.raises(L0BootstrapVerificationError, match="expired"):
        verify_signed_l0_manifest(signed, registry, now=now + timedelta(hours=2))


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
                "bootstrap": signed.model_dump(mode="json"),
            }
        },
    )
    empty = Mock()
    empty.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = empty
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


@pytest.mark.asyncio
async def test_verified_draft_bootstrap_is_available_before_activation(tmp_path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    registry = _publisher_registry(tmp_path, private_key, now)
    signed = _signed_bootstrap(private_key, now)
    release = GuestRelease(
        release_id="draft-bootstrap",
        tee_type="tdx",
        channel="stable",
        status="draft",
        images={
            "l0": {
                "version": "1.10.0",
                "squashfs_sha256": "4" * 64,
                "bootstrap": signed.model_dump(mode="json"),
            }
        },
        created_at=now,
    )
    result = Mock()
    result.scalars.return_value.all.return_value = [release]
    db = AsyncMock()
    db.execute.return_value = result
    with (
        patch.object(
            release_service.settings,
            "trusted_l0_publisher_keys_path",
            registry,
        ),
        patch.object(
            release_service,
            "_validate_l0_bootstrap",
            AsyncMock(),
        ),
    ):
        returned = await release_service.active_l0_bootstrap(db, "tdx", "stable")

    assert returned == signed


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


def test_registry_session_enforces_repository_action_and_exact_manifest():
    assert (
        RegistrySessionRequestV1(
            repository="owner/my--image__part",
            manifest_digest=f"sha256:{'a' * 64}",
        ).repository
        == "owner/my--image__part"
    )
    session = RegistrySession(
        repository="owner/image",
        actions=["pull"],
        manifest_digest=f"sha256:{'a' * 64}",
    )
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
