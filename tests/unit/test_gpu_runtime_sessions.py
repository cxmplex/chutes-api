import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi import HTTPException

from api.config import Settings, settings
from api.server.schemas import GpuRuntimeSessionResponse, GpuServerDecommission
from api.gpu_hotplug_service import GpuHotplugError
from api.server.gpu_sessions import (
    GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS,
    GPU_RUNTIME_SESSION_PURPOSES_V1,
    GPU_RUNTIME_SESSION_PURPOSES_V2,
    GPU_RUNTIME_SESSION_VERSION_V1,
    GPU_RUNTIME_SESSION_VERSION_V2,
    GPU_PLATFORM_RUNTIME_SESSION_PURPOSES,
    _current_attestation,
    _current_attestation_identity,
    _revocation_failed,
    _gpu_selection_matches_registration,
    latest_gpu_runtime_session,
    mint_gpu_runtime_session,
    require_completed_gpu_registration,
    validate_gpu_runtime_session,
)
from api import socket_server
from api.server import router as server_router


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


def _runtime_session_authority_db(server, attestation, *, reservation_state="running"):
    reservation = SimpleNamespace(
        reservation_id=server.gpu_launch_reservation_id,
        state=reservation_state,
        reset_completed_at=(
            datetime.now(timezone.utc) if reservation_state == "released" else None
        ),
        released_at=(datetime.now(timezone.utc) if reservation_state == "released" else None),
        claimed_at=None,
        launching_at=None,
        running_at=(datetime.now(timezone.utc) if reservation_state == "running" else None),
        launch_dispatched_at=None,
        registration_attestation_id=attestation.attestation_id,
        server_id=server.server_id,
        management_mode=server.gpu_management_mode,
        allocation_group_id=server.gpu_allocation_group_id,
        allocation_group_generation=server.gpu_allocation_group_generation,
        process_incarnation=server.gpu_process_incarnation,
        topology_fingerprint=server.gpu_topology_fingerprint,
        claims_sha256=attestation.gpu_claims_sha256,
        gpu_release_id=attestation.gpu_release_id,
        profile_id=attestation.gpu_profile_id,
        host_boot_generation=attestation.gpu_host_boot_generation,
        reservation_generation=attestation.gpu_reservation_generation,
        gpu_attestation_certificate_sha256s=(attestation.gpu_evidence_certificate_sha256s),
        legacy_migration_id=None,
    )
    db = AsyncMock()

    async def get(model, key):
        if model is GpuServerDecommission:
            return None
        if model.__name__ == "Server":
            assert key == server.server_id
            return server
        if model.__name__ == "ServerAttestation":
            assert key == attestation.attestation_id
            return attestation
        assert model.__name__ == "GpuLaunchReservation"
        assert key == server.gpu_launch_reservation_id
        return reservation

    db.get.side_effect = get
    db.execute.return_value = SimpleNamespace(
        scalar_one_or_none=lambda: attestation,
    )
    return db


@pytest.mark.asyncio
async def test_completed_registration_requires_operational_attestation_before_db_access():
    db = AsyncMock()
    with pytest.raises(HTTPException, match="operational attestation is required") as exc_info:
        await require_completed_gpu_registration(
            db,
            SimpleNamespace(),
            None,
            SimpleNamespace(),
        )
    assert exc_info.value.status_code == 403
    db.execute.assert_not_awaited()


def test_miner_registration_mints_short_scoped_attested_session():
    token, expires_at = mint_gpu_runtime_session(_server(), _attestation())
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert payload["purpose"] == "gpu_runtime_session"
    assert payload["version"] == GPU_RUNTIME_SESSION_VERSION_V1
    assert payload["owner_hotkey"] == "5Owner"
    assert payload["allowed_purposes"] == list(GPU_RUNTIME_SESSION_PURPOSES_V1)
    assert "gpu-decommission" not in payload["allowed_purposes"]
    assert payload["exp"] - payload["iat"] == 900
    assert int(expires_at.timestamp()) == payload["exp"]


def test_upgraded_miner_explicitly_mints_version_two_decommission_scope():
    token, _expires_at = mint_gpu_runtime_session(
        _server(),
        _attestation(),
        version=GPU_RUNTIME_SESSION_VERSION_V2,
    )
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert payload["version"] == GPU_RUNTIME_SESSION_VERSION_V2
    assert payload["allowed_purposes"] == list(GPU_RUNTIME_SESSION_PURPOSES_V2)
    assert "gpu-decommission" in payload["allowed_purposes"]


@pytest.mark.asyncio
async def test_version_one_token_never_authorizes_gpu_decommission():
    token, _expires_at = mint_gpu_runtime_session(_server(), _attestation())
    db = AsyncMock()

    with pytest.raises(HTTPException, match="scope is invalid") as exc:
        await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="gpu-decommission",
        )

    assert exc.value.status_code == 401
    db.get.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "purposes"),
    [
        (GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V2),
        (GPU_RUNTIME_SESSION_VERSION_V2, GPU_RUNTIME_SESSION_PURPOSES_V1),
        (3, GPU_RUNTIME_SESSION_PURPOSES_V2),
        (True, GPU_RUNTIME_SESSION_PURPOSES_V1),
    ],
)
async def test_runtime_session_version_and_purposes_must_match_exactly(
    version,
    purposes,
):
    token, _expires_at = mint_gpu_runtime_session(_server(), _attestation())
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    payload["version"] = version
    payload["allowed_purposes"] = list(purposes)
    malformed = jwt.encode(payload, settings.launch_config_key, algorithm="HS256")
    db = AsyncMock()

    with pytest.raises(HTTPException, match="scope is invalid") as exc:
        await validate_gpu_runtime_session(
            db,
            malformed,
            required_purpose="miner",
        )

    assert exc.value.status_code == 401
    db.get.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version",
    [GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_VERSION_V2],
)
async def test_runtime_session_iat_accepts_explicit_bounded_future_skew(version):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    server = _server()
    attestation = _attestation()
    db = _runtime_session_authority_db(server, attestation)
    with (
        patch(
            "api.server.gpu_sessions._runtime_session_now",
            side_effect=[
                now + timedelta(seconds=GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS),
                now,
            ],
        ),
        patch(
            "api.server.gpu_sessions.acquire_gpu_lifecycle_lock",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_completed_gpu_registration",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_gpu_hotplug_runtime_ack",
            AsyncMock(),
        ),
    ):
        token, expires_at = mint_gpu_runtime_session(
            server,
            attestation,
            version=version,
        )
        server.gpu_runtime_session_expires_at = expires_at
        current, payload = await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="miner",
        )

    assert current is server
    assert payload["version"] == version
    assert payload["iat"] == (int(now.timestamp()) + GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS)


@pytest.mark.asyncio
async def test_runtime_session_iat_rejects_future_time_beyond_explicit_skew():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    server = _server()
    attestation = _attestation()
    db = AsyncMock()
    with patch(
        "api.server.gpu_sessions._runtime_session_now",
        side_effect=[
            now + timedelta(seconds=GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS + 1),
            now,
        ],
    ):
        token, _expires_at = mint_gpu_runtime_session(
            server,
            attestation,
            version=GPU_RUNTIME_SESSION_VERSION_V2,
        )
        with pytest.raises(HTTPException, match="invalid or expired") as exc:
            await validate_gpu_runtime_session(
                db,
                token,
                required_purpose="miner",
            )

    assert exc.value.status_code == 401
    db.get.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["iat", "exp"])
@pytest.mark.parametrize("value", [True, 1.5, "1"])
async def test_runtime_session_time_claims_require_exact_integers(claim, value):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    server = _server()
    attestation = _attestation()
    with patch("api.server.gpu_sessions._runtime_session_now", return_value=now):
        token, _expires_at = mint_gpu_runtime_session(
            server,
            attestation,
            version=GPU_RUNTIME_SESSION_VERSION_V2,
        )
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    payload[claim] = value
    malformed = jwt.encode(
        payload,
        settings.launch_config_key,
        algorithm="HS256",
    )
    db = AsyncMock()

    with (
        patch("api.server.gpu_sessions._runtime_session_now", return_value=now),
        pytest.raises(HTTPException, match="invalid or expired") as exc,
    ):
        await validate_gpu_runtime_session(
            db,
            malformed,
            required_purpose="miner",
        )

    assert exc.value.status_code == 401
    db.get.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_runtime_session_expiry_has_no_clock_skew_grace():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    server = _server()
    attestation = _attestation()
    with patch("api.server.gpu_sessions._runtime_session_now", return_value=now):
        token, _expires_at = mint_gpu_runtime_session(server, attestation)
    payload = jwt.decode(
        token,
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    payload["exp"] = int(now.timestamp())
    expired = jwt.encode(
        payload,
        settings.launch_config_key,
        algorithm="HS256",
    )
    db = AsyncMock()

    with (
        patch("api.server.gpu_sessions._runtime_session_now", return_value=now),
        pytest.raises(HTTPException, match="invalid or expired") as exc,
    ):
        await validate_gpu_runtime_session(
            db,
            expired,
            required_purpose="miner",
        )

    assert exc.value.status_code == 401
    db.get.assert_not_awaited()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_runtime_session_only_replays_cert_bound_decommission_audit():
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    replay_at = issued_at + timedelta(minutes=30)
    server = _server()
    attestation = _attestation()
    with patch("api.server.gpu_sessions._runtime_session_now", return_value=issued_at):
        token, _expires_at = mint_gpu_runtime_session(
            server,
            attestation,
            version=GPU_RUNTIME_SESSION_VERSION_V2,
        )

    server.gpu_management_mode = None
    server.gpu_launch_reservation_id = None
    server.attested_cert_pubkey_hash = None
    server.gpu_runtime_session_attestation_id = None
    server.gpu_runtime_session_expires_at = None
    server.gpu_retired_at = issued_at + timedelta(seconds=1)
    audit = SimpleNamespace(
        owner_hotkey=server.miner_hotkey,
        replay_attested_spki_sha256="a" * 64,
    )
    db = AsyncMock()

    async def get(model, key):
        if model.__name__ == "Server":
            return server
        if model is GpuServerDecommission:
            return audit
        return None

    db.get.side_effect = get
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: None)
    with (
        patch("api.server.gpu_sessions._runtime_session_now", return_value=replay_at),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
    ):
        replay_server, payload = await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="gpu-decommission",
        )
    assert replay_server is server
    assert payload["attested_spki_sha256"] == "a" * 64

    audit.replay_attested_spki_sha256 = "b" * 64
    with (
        patch("api.server.gpu_sessions._runtime_session_now", return_value=replay_at),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="replay identity is invalid") as wrong_cert,
    ):
        await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="gpu-decommission",
        )
    assert wrong_cert.value.status_code == 401

    audit.replay_attested_spki_sha256 = None
    with (
        patch("api.server.gpu_sessions._runtime_session_now", return_value=replay_at),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="replay identity is invalid") as unbound,
    ):
        await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="gpu-decommission",
        )
    assert unbound.value.status_code == 401


@pytest.mark.asyncio
async def test_expired_session_still_authorizes_exact_initial_terminal_decommission_only():
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    decommission_at = issued_at + timedelta(minutes=30)
    server = _server()
    attestation = _attestation()
    with patch("api.server.gpu_sessions._runtime_session_now", return_value=issued_at):
        token, _expires_at = mint_gpu_runtime_session(
            server,
            attestation,
            version=GPU_RUNTIME_SESSION_VERSION_V2,
        )

    terminal_db = _runtime_session_authority_db(
        server,
        attestation,
        reservation_state="released",
    )
    with (
        patch(
            "api.server.gpu_sessions._runtime_session_now",
            return_value=decommission_at,
        ),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
    ):
        authorized_server, payload = await validate_gpu_runtime_session(
            terminal_db,
            token,
            required_purpose="gpu-decommission",
        )
    assert authorized_server is server
    assert payload["attested_spki_sha256"] == server.attested_cert_pubkey_hash

    active_db = _runtime_session_authority_db(server, attestation)
    with (
        patch(
            "api.server.gpu_sessions._runtime_session_now",
            return_value=decommission_at,
        ),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="invalid or expired") as nonterminal,
    ):
        await validate_gpu_runtime_session(
            active_db,
            token,
            required_purpose="gpu-decommission",
        )
    assert nonterminal.value.status_code == 401

    server.attested_cert_pubkey_hash = "b" * 64
    stale_cert_db = _runtime_session_authority_db(
        server,
        attestation,
        reservation_state="released",
    )
    with (
        patch(
            "api.server.gpu_sessions._runtime_session_now",
            return_value=decommission_at,
        ),
        patch("api.server.gpu_sessions.acquire_gpu_lifecycle_lock", AsyncMock()),
        pytest.raises(HTTPException, match="no longer exact") as stale_cert,
    ):
        await validate_gpu_runtime_session(
            stale_cert_db,
            token,
            required_purpose="gpu-decommission",
        )
    assert stale_cert.value.status_code == 401


@pytest.mark.asyncio
async def test_runtime_session_database_expiry_at_validation_now_is_rejected():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    server = _server()
    attestation = _attestation()
    db = _runtime_session_authority_db(server, attestation)
    with (
        patch(
            "api.server.gpu_sessions._runtime_session_now",
            side_effect=[now, now],
        ),
        patch(
            "api.server.gpu_sessions.acquire_gpu_lifecycle_lock",
            AsyncMock(),
        ),
    ):
        token, _expires_at = mint_gpu_runtime_session(server, attestation)
        server.gpu_runtime_session_expires_at = now
        with pytest.raises(
            HTTPException,
            match="identity is no longer current",
        ) as exc:
            await validate_gpu_runtime_session(
                db,
                token,
                required_purpose="miner",
            )

    assert exc.value.status_code == 401


@pytest.mark.parametrize("value", ["future_status", "soft-pass", 7, True])
def test_unknown_revocation_status_fails_closed(value):
    assert _revocation_failed(value) is True


@pytest.mark.parametrize(
    "value",
    [None, "good", "not_revoked", "authenticated_outage_grace", {}, []],
)
def test_explicit_nonfailure_revocation_status_remains_accepted(value):
    assert _revocation_failed(value) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "requested_version",
        "v2_enabled",
        "expected_version",
        "expected_purposes",
    ),
    [
        (None, False, GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V1),
        (None, True, GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V1),
        ("1", False, GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V1),
        ("1", True, GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V1),
        ("2", False, GPU_RUNTIME_SESSION_VERSION_V1, GPU_RUNTIME_SESSION_PURPOSES_V1),
        ("2", True, GPU_RUNTIME_SESSION_VERSION_V2, GPU_RUNTIME_SESSION_PURPOSES_V2),
    ],
)
async def test_runtime_session_route_negotiates_compatible_response(
    requested_version,
    v2_enabled,
    expected_version,
    expected_purposes,
    monkeypatch,
):
    monkeypatch.setattr(settings, "gpu_runtime_session_v2_enabled", v2_enabled)
    server = _server()
    db = AsyncMock()
    db.get.return_value = server
    token, expires_at = mint_gpu_runtime_session(
        server,
        _attestation(),
        version=expected_version,
    )
    latest = AsyncMock(return_value=(token, expires_at, "attestation"))
    with patch.object(
        server_router,
        "latest_gpu_runtime_session",
        latest,
    ):
        response = await server_router.refresh_gpu_runtime_session(
            "gpu-server",
            db,
            expected_cert_hash="a" * 64,
            requested_session_version=requested_version,
        )
    route = next(
        item
        for item in server_router.router.routes
        if getattr(item, "path", None) == "/gpu/{server_id}/session"
    )
    assert route.response_model is GpuRuntimeSessionResponse
    assert route.response_model_exclude_none is True
    document = response.model_dump(exclude_none=True)
    validated = route.response_model.model_validate(document)
    expected_keys = {
        "server_id",
        "owner_hotkey",
        "runtime_session",
        "runtime_session_expires_at",
        "allowed_purposes",
    }
    if expected_version == GPU_RUNTIME_SESSION_VERSION_V2:
        expected_keys.add("session_version")
    assert set(document) == expected_keys
    token_payload = jwt.decode(
        document["runtime_session"],
        settings.launch_config_key,
        algorithms=["HS256"],
        issuer="chutes",
    )
    assert token_payload["version"] == expected_version
    assert token_payload["allowed_purposes"] == document["allowed_purposes"]
    assert validated.allowed_purposes == list(expected_purposes)
    assert "gpu-infra" in validated.allowed_purposes
    assert document.get("session_version") == (
        GPU_RUNTIME_SESSION_VERSION_V2
        if expected_version == GPU_RUNTIME_SESSION_VERSION_V2
        else None
    )
    latest.assert_awaited_once_with(db, server, version=expected_version)


@pytest.mark.asyncio
async def test_runtime_session_route_rejects_unknown_negotiated_version_before_mint():
    server = _server()
    db = AsyncMock()
    db.get.return_value = server
    latest = AsyncMock()
    with (
        patch.object(server_router, "latest_gpu_runtime_session", latest),
        pytest.raises(
            HTTPException, match="Unsupported GPU runtime session version"
        ) as exc,
    ):
        await server_router.refresh_gpu_runtime_session(
            "gpu-server",
            db,
            expected_cert_hash="a" * 64,
            requested_session_version="3",
        )
    assert exc.value.status_code == 400
    latest.assert_not_awaited()
    db.get.assert_not_awaited()


def test_gpu_runtime_session_v2_setting_is_explicit_boolean_and_defaults_off():
    field = Settings.model_fields["gpu_runtime_session_v2_enabled"]

    assert field.annotation is bool
    assert field.default is False
    assert (
        Settings(gpu_runtime_session_v2_enabled=False).gpu_runtime_session_v2_enabled
        is False
    )
    assert (
        Settings(gpu_runtime_session_v2_enabled=True).gpu_runtime_session_v2_enabled
        is True
    )


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
    with (
        patch(
            "api.server.gpu_sessions.acquire_gpu_lifecycle_lock",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_completed_gpu_registration",
            AsyncMock(),
        ),
        pytest.raises(HTTPException, match="newer GPU attestation attempt") as exc,
    ):
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


def test_latest_attempt_query_does_not_filter_failures_and_uses_db_sequence():
    import inspect

    from api.server.gpu_sessions import _latest_attestation_attempt

    source = inspect.getsource(_latest_attestation_attempt)
    assert "verification_error.is_" not in source
    assert "attempt_sequence.desc()" in source
    assert "created_at.desc()" not in source


def test_all_direct_latest_attempt_consumers_use_database_sequence():
    import inspect

    from api import cpu_scheduler
    from api.host import reservations as host_reservations
    from api.registry import router as registry_router
    from api.releases import service as releases_service
    from api.storage import service as storage_service

    consumers = (
        cpu_scheduler._current_attested_servers,
        host_reservations.gpu_host_storage_readiness,
        registry_router._locked_registry_authority,
        releases_service.release_status,
        storage_service._verified_storage_ids,
    )
    for consumer in consumers:
        source = inspect.getsource(consumer)
        assert "ServerAttestation.attempt_sequence" in source, consumer.__qualname__
        assert "ServerAttestation.created_at.desc()" not in source, consumer.__qualname__


def _cpu_server():
    return SimpleNamespace(
        server_id="cpu-server",
        compute_type="cpu",
        measurement_name="cpu-measurement",
        measurement_config_fingerprint="2" * 64,
        trust_set_fingerprint="3" * 64,
        attestation_revocation_status={},
    )


def _cpu_attestation(*, failed=False):
    return SimpleNamespace(
        attestation_id="cpu-attempt",
        server_id="cpu-server",
        verification_error="newer quote failed" if failed else None,
        verified_at=None if failed else datetime.now(timezone.utc),
        measurement_name="cpu-measurement",
        measurement_config_fingerprint="2" * 64,
        trust_set_fingerprint="3" * 64,
        revocation_status={},
    )


def test_cpu_current_identity_accepts_latest_success_and_rejects_latest_failure():
    server = _cpu_server()
    success = _cpu_attestation()
    assert _current_attestation_identity(server, success) is success
    with pytest.raises(HTTPException, match="Latest attestation attempt"):
        _current_attestation_identity(server, _cpu_attestation(failed=True))


@pytest.mark.asyncio
async def test_cpu_model_b_authority_consults_latest_attempt():
    from api.instance.util import _require_current_attestation_identity

    failed = _cpu_attestation(failed=True)
    db = AsyncMock()
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: failed)
    with (
        patch(
            "api.server.service.runtime_attestation_context_for_server_db",
            AsyncMock(),
        ),
        pytest.raises(HTTPException, match="Latest attestation attempt"),
    ):
        await _require_current_attestation_identity(db, _cpu_server())


def test_non_revoked_attestation_status_is_not_misclassified():
    server = _server()
    attempt = _attestation()
    server.attestation_revocation_status = {"tdx": "not_revoked"}
    attempt.revocation_status = {"tdx": "not_revoked"}
    assert _current_attestation(server, attempt) is attempt


@pytest.mark.asyncio
async def test_generic_session_mint_rejects_incomplete_legacy_hotplug():
    server = _server()
    reservation = SimpleNamespace(
        state="running",
        server_id=server.server_id,
        management_mode="miner",
        legacy_migration_id="migration-1",
    )
    db = AsyncMock()
    db.execute.side_effect = [
        SimpleNamespace(scalar_one_or_none=lambda: server),
        SimpleNamespace(scalar_one_or_none=lambda: reservation),
        SimpleNamespace(scalar_one_or_none=lambda: _attestation()),
    ]
    with (
        patch(
            "api.server.gpu_sessions.acquire_gpu_lifecycle_lock",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_completed_gpu_registration",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_gpu_hotplug_runtime_ack",
            AsyncMock(side_effect=GpuHotplugError("pending hotplug")),
        ),
    ):
        with pytest.raises(HTTPException, match="hotplug custody") as exc:
            await latest_gpu_runtime_session(db, server)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_existing_generic_session_rechecks_legacy_hotplug_ack():
    server = _server()
    successful = _attestation()
    token, _ = mint_gpu_runtime_session(server, successful)
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
        gpu_attestation_certificate_sha256s=(successful.gpu_evidence_certificate_sha256s),
        legacy_migration_id="migration-1",
    )
    db = AsyncMock()

    async def get(model, _key):
        if model.__name__ == "Server":
            return server
        if model.__name__ == "ServerAttestation":
            return successful
        return reservation

    db.get.side_effect = get
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: successful)
    with (
        patch(
            "api.server.gpu_sessions.acquire_gpu_lifecycle_lock",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_completed_gpu_registration",
            AsyncMock(),
        ),
        patch(
            "api.server.gpu_sessions.require_gpu_hotplug_runtime_ack",
            AsyncMock(side_effect=GpuHotplugError("hotplug ACK missing")),
        ),
    ):
        with pytest.raises(HTTPException, match="hotplug custody") as exc:
            await validate_gpu_runtime_session(db, token, required_purpose="miner")
    assert exc.value.status_code == 401


def test_four_device_mode_selection_binds_the_same_registered_two_devices():
    reservation = [f"GPU-00000000-0000-0000-0000-{index:012x}" for index in range(1, 5)]
    registered = reservation[:2]
    registered_certificates = ["1" * 64, "2" * 64]

    assert _gpu_selection_matches_registration(
        management_mode="miner",
        reservation_uuids=reservation,
        registered_uuids=registered,
        registered_certificates=registered_certificates,
        operational_certificates=list(registered_certificates),
    )
    assert not _gpu_selection_matches_registration(
        management_mode="miner",
        reservation_uuids=reservation,
        registered_uuids=registered,
        registered_certificates=registered_certificates,
        operational_certificates=[*registered_certificates, "3" * 64],
    )
    assert not _gpu_selection_matches_registration(
        management_mode="miner",
        reservation_uuids=reservation,
        registered_uuids=registered,
        registered_certificates=registered_certificates,
        operational_certificates=["1" * 64, "3" * 64],
    )
    assert not _gpu_selection_matches_registration(
        management_mode="platform",
        reservation_uuids=reservation,
        registered_uuids=registered,
        registered_certificates=registered_certificates,
        operational_certificates=list(registered_certificates),
    )


def test_api_callers_never_pass_none_to_completed_registration_check():
    api_root = Path(__file__).parents[2] / "api"
    violations = []

    for path in api_root.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else None
            )
            if name != "require_completed_gpu_registration":
                continue
            candidates = list(node.args[2:3])
            candidates.extend(
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "operational_attestation"
            )
            if any(isinstance(value, ast.Constant) and value.value is None for value in candidates):
                violations.append((str(path.relative_to(api_root)), node.lineno))

    assert not violations, f"Missing operational attestation at API call sites: {violations}"
