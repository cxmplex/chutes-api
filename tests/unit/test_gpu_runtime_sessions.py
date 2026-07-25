import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException

from api.config import settings
from api.host.gpu_allocations import gpu_reservation_token
from api.host.schemas import (
    GpuLaunchReservation,
    GpuLaunchReservationClaimsV1,
    GpuQuoteCommitmentV1,
    canonical_sha256,
)
from api.server.schemas import GpuRuntimeSessionResponse, GpuServerRegistrationArgs
from api.server.gpu_sessions import (
    GPU_RUNTIME_SESSION_PURPOSES,
    GPU_PLATFORM_RUNTIME_SESSION_PURPOSES,
    _current_attestation,
    mint_gpu_runtime_session,
    validate_gpu_runtime_session,
)
from api import socket_server
from api.server import router as server_router
from api.server.exceptions import ServerRegistrationError


def _server(mode="miner"):
    return SimpleNamespace(
        server_id="gpu-server",
        miner_hotkey="5Owner",
        compute_type="gpu",
        tee_type="tdx",
        gpu_management_mode=mode,
        gpu_launch_reservation_id="reservation",
        gpu_allocation_group_id="group",
        gpu_allocation_group_generation=1,
        gpu_process_incarnation="process",
        gpu_topology_fingerprint="d" * 64,
        gpu_runtime_session_attestation_id="attestation",
        gpu_runtime_session_expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        attested_cert_pubkey_hash="a" * 64,
        gpu_retired_at=None,
        measurement_name="gpu-measurement",
        measurement_config_fingerprint="b" * 64,
        trust_set_fingerprint="c" * 64,
        attestation_revocation_status={},
    )


def _attestation(mode="miner"):
    return SimpleNamespace(
        attestation_id="attestation",
        server_id="gpu-server",
        verification_error=None,
        verified_at=datetime.now(timezone.utc),
        gpu_retired_at=None,
        measurement_name="gpu-measurement",
        measurement_config_fingerprint="b" * 64,
        trust_set_fingerprint="c" * 64,
        revocation_status={},
        gpu_launch_reservation_id="reservation",
        gpu_allocation_group_id="group",
        gpu_allocation_group_generation=1,
        gpu_host_boot_generation=1,
        gpu_reservation_generation=1,
        gpu_management_mode=mode,
        gpu_process_incarnation="process",
        gpu_topology_fingerprint="d" * 64,
        gpu_release_id="release",
        gpu_profile_id="profile",
        gpu_chute_id=None,
        gpu_job_id=None,
        gpu_claims_sha256="e" * 64,
        gpu_evidence_sha256="f" * 64,
        gpu_evidence_certificate_sha256s=["1" * 64],
    )


def test_miner_registration_mints_short_scoped_attested_session():
    token, expires_at = mint_gpu_runtime_session(_server(), _attestation())
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert payload["purpose"] == "gpu_runtime_session"
    assert payload["owner_hotkey"] == "5Owner"
    assert payload["allowed_purposes"] == list(GPU_RUNTIME_SESSION_PURPOSES)
    assert payload["exp"] - payload["iat"] == 900
    assert int(expires_at.timestamp()) == payload["exp"]


@pytest.mark.asyncio
async def test_runtime_session_route_response_model_accepts_exact_gpu_infra_purpose():
    server = _server()
    db = AsyncMock()
    db.get.return_value = server
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    with patch.object(
        server_router,
        "latest_gpu_runtime_session",
        AsyncMock(return_value=("runtime-token", expires_at, "attestation")),
    ):
        response = await server_router.refresh_gpu_runtime_session(
            "gpu-server",
            db,
            expected_cert_hash="a" * 64,
        )
    route = next(
        item
        for item in server_router.router.routes
        if getattr(item, "path", None) == "/gpu/{server_id}/session"
    )
    assert route.response_model is GpuRuntimeSessionResponse
    validated = route.response_model.model_validate(response.model_dump())
    assert validated.allowed_purposes == list(GPU_RUNTIME_SESSION_PURPOSES)
    assert "gpu-infra" in validated.allowed_purposes


def test_platform_registration_mints_only_exact_registry_scope():
    token, _ = mint_gpu_runtime_session(_server("platform"), _attestation("platform"))
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert payload["allowed_purposes"] == list(GPU_PLATFORM_RUNTIME_SESSION_PURPOSES)
    assert "registry_repository" not in payload
    assert "registry_manifest_digest" not in payload


def test_miner_runtime_session_grants_only_registry_session_mint_scope():
    token, _ = mint_gpu_runtime_session(_server(), _attestation())
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert "registry" in payload["allowed_purposes"]
    assert "registry_repository" not in payload
    assert "registry_manifest_digest" not in payload


@pytest.mark.asyncio
async def test_newer_failed_attestation_revokes_an_already_minted_session():
    server = _server()
    successful = _attestation()
    token, _ = mint_gpu_runtime_session(server, successful)
    failed = _attestation()
    failed.attestation_id = "newer-failed-attestation"
    failed.verification_error = "NVIDIA evidence no longer verifies"
    failed.verified_at = None
    reservation = SimpleNamespace(
        state="running",
        registration_attestation_id=successful.attestation_id,
        server_id=server.server_id,
        management_mode=server.gpu_management_mode,
        allocation_group_id=server.gpu_allocation_group_id,
        allocation_group_generation=server.gpu_allocation_group_generation,
        process_incarnation=server.gpu_process_incarnation,
        topology_fingerprint=server.gpu_topology_fingerprint,
        claims_sha256=successful.gpu_claims_sha256,
        gpu_release_id=successful.gpu_release_id,
        profile_id=successful.gpu_profile_id,
        host_boot_generation=successful.gpu_host_boot_generation,
        reservation_generation=successful.gpu_reservation_generation,
        gpu_attestation_certificate_sha256s=successful.gpu_evidence_certificate_sha256s,
        container_repository=None,
        container_manifest_digest=None,
    )
    db = AsyncMock()

    async def get(model, key):
        name = model.__name__
        if name == "Server":
            return server
        if name == "ServerAttestation":
            return successful
        assert name == "GpuLaunchReservation"
        assert key == server.gpu_launch_reservation_id
        return reservation

    latest = SimpleNamespace(scalar_one_or_none=lambda: failed)
    db.get.side_effect = get
    db.execute.return_value = latest
    with pytest.raises(HTTPException, match="newer GPU attestation attempt") as exc:
        await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="miner",
        )
    assert exc.value.status_code == 401


def test_attested_socket_sessions_are_disconnected_at_token_expiry():
    import inspect

    source = inspect.getsource(socket_server.authenticate)
    assert "gpu_runtime_session_expires_at" in source
    assert "_expire_miner_session" in source


@pytest.mark.parametrize(
    "updates",
    [
        {"verification_error": "newer quote failed", "verified_at": None},
        {"revocation_status": {"tdx": "revoked"}},
        {"measurement_name": "other-measurement"},
        {"gpu_retired_at": datetime.now(timezone.utc)},
    ],
)
def test_newer_failed_or_mismatched_attempt_invalidates_prior_session(updates):
    attempt = _attestation()
    for key, value in updates.items():
        setattr(attempt, key, value)
    with pytest.raises(HTTPException, match="Latest GPU attestation attempt"):
        _current_attestation(_server(), attempt)


def test_latest_attempt_query_does_not_filter_failures():
    import inspect

    from api.server.gpu_sessions import _latest_attestation_attempt

    source = inspect.getsource(_latest_attestation_attempt)
    assert "verification_error.is_" not in source
    assert "created_at.desc()" in source


def test_non_revoked_attestation_status_is_not_misclassified():
    server = _server()
    attempt = _attestation()
    server.attestation_revocation_status = {"tdx": "not_revoked"}
    attempt.revocation_status = {"tdx": "not_revoked"}
    assert _current_attestation(server, attempt) is attempt


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_server", [True, False])
async def test_failed_nvidia_registration_attempt_is_persisted(
    existing_server,
):
    claims = GpuLaunchReservationClaimsV1.model_validate(
        json.loads(
            (Path(__file__).resolve().parents[1] / "fixtures/gpu_launch_claims_v1.json").read_text()
        )
    )
    token = gpu_reservation_token(claims.reservation_id)
    claims_sha256 = canonical_sha256(claims)
    reservation = GpuLaunchReservation(
        reservation_id=claims.reservation_id,
        token_id=claims.token_id,
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        claims_version=1,
        claims=claims.model_dump(mode="json", exclude_none=True),
        claims_sha256=claims_sha256,
        owner_hotkey=claims.owner_hotkey,
        workload_owner=claims.workload_owner,
        host_id=claims.host_id,
        host_key_generation=claims.host_key_generation,
        host_boot_generation=claims.host_boot_generation,
        allocation_group_id=claims.allocation_group_id,
        allocation_group_generation=claims.allocation_group_generation,
        reservation_generation=claims.reservation_generation,
        management_mode=claims.management_mode,
        server_id=claims.server_id,
        process_incarnation=claims.process_incarnation,
        gpu_release_id=claims.gpu_release_id,
        profile_id=claims.gpu_profile_id,
        profile_contract_sha256=claims.profile_contract_sha256,
        measurement_name=claims.measurement_name,
        kernel_measurement_mode=claims.kernel_measurement_mode,
        topology_fingerprint=claims.topology_fingerprint,
        gpu_bdfs=claims.gpu_bdfs,
        gpu_uuids=claims.gpu_uuids,
        gpu_identifiers=claims.gpu_identifiers,
        gpu_attestation_certificate_sha256s=(claims.gpu_attestation_certificate_sha256s),
        qemu_binary_sha256=claims.qemu_binary_sha256,
        qemu_package_version=claims.qemu_package_version,
        machine_type=claims.machine_type,
        tdvf_sha256=claims.tdvf_sha256,
        image_sha256=claims.image_sha256,
        image_version=claims.image_version,
        kernel_sha256=claims.kernel_sha256,
        initrd_sha256=claims.initrd_sha256,
        mode_cmdline_sha256=claims.mode_cmdline_sha256,
        release_target_sha256=claims.release_target_sha256,
        chute_id=claims.chute_id,
        job_id=claims.job_id,
        container_repository=claims.container_repository,
        container_manifest_digest=claims.container_manifest_digest,
        launch_nonce=claims.launch_nonce,
        state="running",
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )
    server = _server("platform")
    server.server_id = claims.server_id
    server.gpu_launch_reservation_id = claims.reservation_id
    server.gpu_allocation_group_id = claims.allocation_group_id
    server.gpu_allocation_group_generation = claims.allocation_group_generation
    server.gpu_process_incarnation = claims.process_incarnation
    server.gpu_topology_fingerprint = claims.topology_fingerprint
    db = AsyncMock()

    async def get(model, _key):
        if model.__name__ == "Server":
            return server if existing_server else None
        return reservation

    db.get.side_effect = get
    db.add = MagicMock()
    request = SimpleNamespace(state=SimpleNamespace(client_ip="192.0.2.10"))
    args = GpuServerRegistrationArgs(
        server_id=server.server_id,
        quote="failed-quote",
        gpu_evidence=[{"evidence": "failed"}],
        gpu_uuids=claims.gpu_uuids,
        launch_reservation=token,
        quote_commitment=GpuQuoteCommitmentV1(
            reservation_sha256=claims_sha256,
            release_target_sha256=claims.release_target_sha256,
            launch_nonce=claims.launch_nonce,
            attested_spki_sha256=server.attested_cert_pubkey_hash,
            claims=claims,
        ),
        td_signature="signature",
    )
    quarantine = AsyncMock()
    with (
        patch.object(
            server_router,
            "register_gpu_server",
            AsyncMock(side_effect=ServerRegistrationError("NVIDIA evidence failed")),
        ),
        patch(
            "api.host.gpu_allocations.quarantine_gpu_reservation_control_plane",
            quarantine,
        ),
    ):
        with pytest.raises(ServerRegistrationError, match="NVIDIA evidence failed"):
            await server_router.register_gpu_server_endpoint(
                request,
                args,
                db,
                nonce="nonce",
                expected_cert_hash=server.attested_cert_pubkey_hash,
                expected_cert_pem="certificate",
            )
    failed = db.add.call_args.args[0]
    assert failed.server_id == server.server_id
    assert failed.quote_data == "failed-quote"
    assert failed.verification_error == "NVIDIA evidence failed"
    assert failed.gpu_evidence_certificate_sha256s == []
    quarantine.assert_awaited_once()
    db.rollback.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_legacy_volume_hotplug_is_dispatched_only_after_gpu_registration():
    result = {
        "server_id": "gpu-server",
        "reservation_id": "reservation",
        "management_mode": "miner",
        "status": "registered",
    }
    reservation = SimpleNamespace(
        reservation_id="reservation",
        server_id="gpu-server",
        host_id="gpu-host",
        claims_sha256="a" * 64,
        process_incarnation="gpu-process",
        legacy_vm_name="legacy-server",
        legacy_migration_id="migration-1",
    )
    db = AsyncMock()
    db.get.side_effect = [
        reservation,
        SimpleNamespace(state="leased"),
    ]
    request = SimpleNamespace(state=SimpleNamespace(client_ip="192.0.2.10"))
    register = AsyncMock(return_value=result)
    dispatch = AsyncMock(return_value="command-id")
    with (
        patch.object(server_router, "register_gpu_server", register),
        patch.object(server_router, "send_agent_command", dispatch),
    ):
        response = await server_router.register_gpu_server_endpoint(
            request,
            SimpleNamespace(server_id="gpu-server"),
            db,
            nonce="nonce",
            expected_cert_hash="b" * 64,
            expected_cert_pem="certificate",
        )
    assert response == result
    dispatch.assert_awaited_once_with(
        "gpu-host",
        "hotplug_gpu_legacy",
        {
            "server_id": "gpu-server",
            "reservation_id": "reservation",
            "reservation_claims_sha256": "a" * 64,
            "process_incarnation": "gpu-process",
        },
    )
