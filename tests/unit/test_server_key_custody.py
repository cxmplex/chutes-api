"""Adversarial regression tests for registered-server LUKS capabilities."""

import base64
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.server.exceptions import (
    MeasurementMismatchError,
    ServerNotFoundError,
)
from api.server.schemas import (
    BootAttestationResponse,
    CpuServerRegistrationArgs,
    Host,
    LuksAttestRequest,
    LuksAttestResponse,
    LuksCapabilityContext,
    LuksCapabilityPurpose,
    LuksConfirmRequest,
    LuksVolumeInfo,
    LuksVolumeRotation,
    Server,
)
from api.server.service import (
    issue_boot_attestation_nonce,
    process_luks_attest_request,
    process_luks_confirm,
    register_cpu_server,
    require_confirm_nonce,
    require_luks_quote_nonce,
)
from api.host.schemas import TdQuoteCommitmentV1


OWNER = "5FRegisteredOwner"
ATTACKER = "5FAttacker"
SERVER_ID = "registered-server"
VM_NAME = "registered-vm"
CERT_HASH = "a" * 64
OTHER_CERT_HASH = "b" * 64
QUOTE_NONCE = "c" * 64


def _server(*, storage_role: bool = False) -> Server:
    measurement = _measurement(storage=storage_role)
    return Server(
        server_id=SERVER_ID,
        ip="203.0.113.10",
        miner_hotkey=OWNER,
        name=VM_NAME,
        is_tee=True,
        storage_role=storage_role,
        compute_type="cpu" if storage_role else "gpu",
        tee_type="tdx",
        version="1.6.1",
        measurement_name="storage-test" if storage_role else "gpu-test",
        measurement_config_fingerprint=measurement_config_fingerprint(measurement),
        trust_set_fingerprint=measurement_trust_set_fingerprint([measurement]),
        attested_cert="-----BEGIN CERTIFICATE-----\nregistered\n-----END CERTIFICATE-----",
        attested_cert_pubkey_hash=CERT_HASH,
    )


def _capability(*, storage: bool = False) -> LuksCapabilityContext:
    measurement = _measurement(storage=storage)
    return LuksCapabilityContext(
        purpose=LuksCapabilityPurpose.STORAGE if storage else LuksCapabilityPurpose.BOOT,
        server_id=SERVER_ID,
        miner_hotkey=OWNER,
        vm_name=VM_NAME,
        cert_hash=CERT_HASH,
        measurement_name="storage-test" if storage else "gpu-test",
        measurement_version="1.6.1",
        measurement_config_fingerprint=measurement_config_fingerprint(measurement),
        trust_set_fingerprint=measurement_trust_set_fingerprint([measurement]),
        tee_type="tdx",
        storage_role=storage,
        allowed_volumes=["chutefs-data"] if storage else ["storage", "tdx-cache"],
    )


def _measurement(*, storage: bool = False, name: str | None = None) -> TeeMeasurementConfig:
    measurement = TeeMeasurementConfig(
        version="1.6.1",
        mrtd="a" * 96,
        name=name or ("storage-test" if storage else "gpu-test"),
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        runtime_rtmr3="e" * 96,
        expected_gpus=[] if storage else ["h200"],
        gpu_count=0 if storage else 1,
        tee_type="tdx",
        provider="bare-metal" if storage else "gcp",
    )
    measurement.config_fingerprint = measurement_config_fingerprint(measurement)
    measurement.trust_set_fingerprint = measurement_trust_set_fingerprint([measurement])
    return measurement


def _db_with(server: Server) -> AsyncMock:
    db = AsyncMock(spec=AsyncSession)
    db.get.return_value = server
    result = Mock()
    result.scalar_one_or_none.return_value = server
    db.execute.return_value = result
    db.commit = AsyncMock()
    return db


def _benchmark() -> dict:
    return {
        "cpu_cores": 2,
        "ram_gb": 8,
        "composite_score": 100.0,
    }


@pytest.mark.asyncio
async def test_victim_server_nonce_attack_fails_before_nonce_issuance():
    """An attacker naming a victim server cannot reach quote-nonce creation."""
    db = _db_with(_server())
    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            side_effect=ServerNotFoundError(SERVER_ID),
        ),
        patch("api.server.service.create_nonce", new_callable=AsyncMock) as create_nonce,
    ):
        with pytest.raises(ServerNotFoundError):
            await issue_boot_attestation_nonce(
                db,
                "203.0.113.10",
                SERVER_ID,
                ATTACKER,
                f"{int(time.time())}.attack",
                "00",
                CERT_HASH,
            )
    create_nonce.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["role", "cert", "signature"])
async def test_boot_nonce_rejects_wrong_role_cert_or_signature_before_issue(failure):
    server = _server(storage_role=failure == "role")
    db = _db_with(server)
    keypair = Mock()
    keypair.verify.return_value = failure != "signature"
    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch("api.server.service.Keypair", return_value=keypair),
        patch("api.server.service.create_nonce", new_callable=AsyncMock) as create_nonce,
        patch("api.server.service.settings") as settings,
    ):
        settings.redis_client.set = AsyncMock(return_value=True)
        with pytest.raises(HTTPException) as exc_info:
            await issue_boot_attestation_nonce(
                db,
                server.ip,
                server.server_id,
                server.miner_hotkey,
                f"{int(time.time())}.auth",
                "00",
                OTHER_CERT_HASH if failure == "cert" else CERT_HASH,
            )
    assert exc_info.value.status_code in (401, 403)
    create_nonce.assert_not_awaited()


@pytest.mark.asyncio
async def test_boot_nonce_context_is_registered_signed_and_boot_scoped():
    server = _server()
    db = _db_with(server)
    keypair = Mock()
    keypair.verify.return_value = True
    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch("api.server.service.Keypair", return_value=keypair),
        patch(
            "api.server.service.create_nonce",
            new_callable=AsyncMock,
            return_value={"nonce": QUOTE_NONCE, "expires_at": "later"},
        ) as create_nonce,
        patch("api.server.service.settings") as settings,
    ):
        settings.redis_client.set = AsyncMock(return_value=True)
        result = await issue_boot_attestation_nonce(
            db,
            server.ip,
            server.server_id,
            server.miner_hotkey,
            f"{int(time.time())}.auth",
            "00",
            CERT_HASH,
        )

    assert result["nonce"] == QUOTE_NONCE
    context = create_nonce.await_args.kwargs["context"]
    assert context["server_id"] == SERVER_ID
    assert context["miner_hotkey"] == OWNER
    assert context["cert_hash"] == CERT_HASH
    assert context["storage_role"] is False
    assert context["allowed_volumes"] == ["storage", "tdx-cache"]


@pytest.mark.asyncio
async def test_boot_nonce_authorization_replay_cannot_mint_another_nonce():
    server = _server()
    db = _db_with(server)
    keypair = Mock()
    keypair.verify.return_value = True
    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch("api.server.service.Keypair", return_value=keypair),
        patch("api.server.service.create_nonce", new_callable=AsyncMock) as create_nonce,
        patch("api.server.service.settings") as settings,
    ):
        settings.redis_client.set = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc_info:
            await issue_boot_attestation_nonce(
                db,
                server.ip,
                server.server_id,
                server.miner_hotkey,
                f"{int(time.time())}.replayed",
                "00",
                CERT_HASH,
            )

    assert exc_info.value.status_code == 401
    create_nonce.assert_not_awaited()


@pytest.mark.asyncio
async def test_storage_registration_signature_binds_identity_cert_and_role():
    """Storage capability issuance derives owner/role from a quote-bound reservation."""
    commitment = TdQuoteCommitmentV1(
        reservation_sha256="1" * 64,
        launch_nonce=base64.b64encode(b"n" * 32).decode(),
        attested_spki_sha256=CERT_HASH,
        release_target_sha256="2" * 64,
        boot_generation=1,
    )
    args = CpuServerRegistrationArgs(
        server_id=SERVER_ID,
        name=VM_NAME,
        quote="quote",
        benchmark=_benchmark(),
        storage_role=True,
        launch_reservation="reservation.secret",
        quote_commitment=commitment,
        td_signature=base64.b64encode(b"s" * 64).decode(),
    )
    db = AsyncMock(spec=AsyncSession)
    db.get.return_value = None
    membership = Mock()
    membership.scalar.return_value = True
    server_lookup = Mock()
    server_lookup.scalar_one_or_none.return_value = None
    ip_owners = Mock()
    ip_owners.scalars.return_value.all.return_value = []
    db.execute.side_effect = [membership, server_lookup, ip_owners]
    reservation = SimpleNamespace(
        reservation_id="reservation-1",
        boot_generation=1,
        consumed_at=None,
        invalidated_at=None,
    )
    claims = SimpleNamespace(
        owner_hotkey=OWNER,
        host_id="l0-owner",
        server_id=SERVER_ID,
        tee_type="tdx",
        role="storage",
        profile_id="storage-test",
        image_sha256="d" * 64,
    )
    attestation_quote = Mock()
    measurement = _measurement(storage=True)
    measurement.image_sha256 = "d" * 64
    with (
        patch("api.server.service.settings") as settings,
        patch(
            "api.server.service.resolve_launch_reservation",
            new_callable=AsyncMock,
            return_value=(reservation, claims),
        ),
        patch("api.server.service._verify_td_registration_signature"),
        patch(
            "api.server.service._validate_cpu_registration_host",
            new_callable=AsyncMock,
            return_value=Host(
                host_id="l0-owner",
                name="l0-owner",
                miner_hotkey=OWNER,
                tee_type="tdx",
                capacity=1,
            ),
        ),
        patch("api.server.service.build_runtime_quote", return_value=attestation_quote),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={}),
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=measurement,
        ),
        patch("api.server.service.validate_cpu_benchmark", return_value=_benchmark()),
        patch(
            "api.server.service.generate_luks_quote_nonce",
            new_callable=AsyncMock,
            return_value=QUOTE_NONCE,
        ) as generate_capability,
    ):
        settings.skip_metagraph_check = False
        settings.netuid = 64
        result = await register_cpu_server(
            db,
            "203.0.113.10",
            args,
            None,
            QUOTE_NONCE,
            None,
            CERT_HASH,
            "-----BEGIN CERTIFICATE-----\nregistered\n-----END CERTIFICATE-----",
        )

    assert reservation.consumed_at is not None
    capability = generate_capability.await_args.args[0]
    assert capability.purpose == LuksCapabilityPurpose.STORAGE
    assert capability.server_id == SERVER_ID
    assert capability.cert_hash == CERT_HASH
    assert capability.measurement_name == "storage-test"
    assert capability.allowed_volumes == ["chutefs-data"]
    assert result["luks_quote_nonce"] == QUOTE_NONCE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "hotkey", "cert_hash", "volumes"),
    [
        ("owner", ATTACKER, CERT_HASH, ["storage"]),
        ("role", OWNER, CERT_HASH, ["storage"]),
        ("cert", OWNER, OTHER_CERT_HASH, ["storage"]),
        ("volume", OWNER, CERT_HASH, ["chutefs-data"]),
    ],
)
async def test_luks_attest_rejects_wrong_owner_role_cert_or_volume_without_keys(
    failure,
    hotkey,
    cert_hash,
    volumes,
):
    server = _server()
    if failure == "role":
        server.storage_role = True
    db = _db_with(server)
    body = LuksAttestRequest(quote="quote", volumes=volumes)

    with (
        patch("api.server.service.build_runtime_quote") as build_quote,
        patch("api.server.service.lease_luks_passphrases", new_callable=AsyncMock) as rotate,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await process_luks_attest_request(
                db,
                SERVER_ID,
                hotkey,
                body,
                (QUOTE_NONCE, _capability()),
                cert_hash,
            )

    assert exc_info.value.status_code == 403
    build_quote.assert_not_called()
    rotate.assert_not_awaited()


@pytest.mark.asyncio
async def test_luks_attest_rejects_measurement_switch_without_disk_key_lookup():
    server = _server(storage_role=True)
    db = _db_with(server)
    quote = Mock()
    body = LuksAttestRequest(quote="quote", volumes=["chutefs-data"])

    with (
        patch("api.server.service.build_runtime_quote", return_value=quote),
        patch("api.server.service.verify_quote", new_callable=AsyncMock),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_measurement(storage=True, name="storage-other"),
        ),
        patch("api.server.service.lease_luks_passphrases", new_callable=AsyncMock) as rotate,
    ):
        with pytest.raises(MeasurementMismatchError):
            await process_luks_attest_request(
                db,
                SERVER_ID,
                OWNER,
                body,
                (QUOTE_NONCE, _capability(storage=True)),
                CERT_HASH,
            )
    rotate.assert_not_awaited()


@pytest.mark.asyncio
async def test_victim_confirm_attack_cannot_promote_pending_disk_key():
    server = _server()
    db = _db_with(server)
    confirm_capability = _capability().model_copy(
        update={
            "issued_volumes": ["storage"],
            "issued_generations": {"storage": 1},
            "issued_lease_ids": {"storage": "lease-id"},
        }
    )
    body = LuksConfirmRequest(volumes={"storage": {"rotated": True, "generation": 1}})

    with patch(
        "api.server.service._get_vm_cache_config_for_update", new_callable=AsyncMock
    ) as get_config:
        with pytest.raises(HTTPException) as exc_info:
            await process_luks_confirm(
                db,
                SERVER_ID,
                ATTACKER,
                body,
                confirm_capability,
                CERT_HASH,
            )

    assert exc_info.value.status_code == 403
    get_config.assert_not_awaited()


@pytest.mark.asyncio
async def test_luks_quote_nonce_is_single_use_and_replay_fails():
    redis = AsyncMock()
    redis.getdel.side_effect = [_capability().model_dump_json().encode(), None]
    settings = Mock(redis_client=redis)

    with patch("api.server.service.settings", settings):
        nonce, context = await require_luks_quote_nonce(QUOTE_NONCE)
        assert nonce == QUOTE_NONCE
        assert context.server_id == SERVER_ID
        with pytest.raises(HTTPException) as exc_info:
            await require_luks_quote_nonce(QUOTE_NONCE)

    assert exc_info.value.status_code == 401
    assert redis.getdel.await_count == 2


@pytest.mark.asyncio
async def test_exact_confirm_capability_remains_queryable_for_idempotent_retry():
    capability = _capability().model_copy(
        update={
            "issued_volumes": ["storage"],
            "issued_generations": {"storage": 4},
            "issued_lease_ids": {"storage": "lease-4"},
        }
    )
    redis = AsyncMock()
    redis.get.return_value = capability.model_dump_json().encode()
    settings = Mock(redis_client=redis)

    with patch("api.server.service.settings", settings):
        first = await require_confirm_nonce("confirm-capability")
        second = await require_confirm_nonce("confirm-capability")

    assert first.issued_generations == {"storage": 4}
    assert second.issued_lease_ids == {"storage": "lease-4"}
    assert redis.get.await_count == 2
    redis.getdel.assert_not_awaited()


@pytest.mark.asyncio
async def test_storage_capability_returns_no_k3s_key():
    server = _server(storage_role=True)
    db = _db_with(server)
    quote = Mock()
    vm_config = SimpleNamespace(
        k3s_encryption_key="encrypted-unrelated-k3s-key",
    )
    rotations = {
        "chutefs-data": LuksVolumeRotation(
            current="disk-current",
            next="disk-next",
            generation=8,
            confirmed_generation=7,
            lease_id="lease-id",
            lease_reused=False,
        )
    }
    body = LuksAttestRequest(quote="quote", volumes=["chutefs-data"])

    with (
        patch("api.server.service.build_runtime_quote", return_value=quote),
        patch("api.server.service.verify_quote", new_callable=AsyncMock),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_measurement(storage=True),
        ),
        patch(
            "api.server.service.lease_luks_passphrases",
            new_callable=AsyncMock,
            return_value=(rotations, vm_config),
        ),
        patch(
            "api.server.service.generate_confirm_nonce",
            new_callable=AsyncMock,
            return_value="confirm",
        ),
        patch("api.server.service.encrypt_passphrase") as encrypt,
        patch("api.server.service.decrypt_passphrase") as decrypt,
    ):
        result = await process_luks_attest_request(
            db,
            SERVER_ID,
            OWNER,
            body,
            (QUOTE_NONCE, _capability(storage=True)),
            CERT_HASH,
        )

    assert result.k3s_encryption_key is None
    encrypt.assert_not_called()
    decrypt.assert_not_called()

    response = LuksAttestResponse(
        volumes={
            "chutefs-data": LuksVolumeInfo(
                current="disk-current",
                next="disk-next",
                generation=8,
                confirmed_generation=7,
                lease_reused=False,
            )
        },
        confirm_nonce=result.confirm_nonce,
        k3s_encryption_key=result.k3s_encryption_key,
    )
    assert "k3s_encryption_key" not in response.model_dump(exclude_none=True)


def test_boot_response_cannot_serialize_global_or_disk_key():
    response = BootAttestationResponse(luks_quote_nonce=QUOTE_NONCE)
    payload = response.model_dump(exclude_none=True)

    assert payload == {"luks_quote_nonce": QUOTE_NONCE}
    assert "key" not in BootAttestationResponse.model_fields
    assert "key" not in payload
    assert set(BootAttestationResponse.model_fields) == {"luks_quote_nonce"}


def test_legacy_ambiguous_luks_route_is_absent():
    from api.server.router import router

    paths = {route.path for route in router.routes}
    assert "/{server_id}/luks" not in paths
    assert "/{server_id}/luks/attest" in paths
    assert "/{server_id}/luks/confirm" in paths
