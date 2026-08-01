import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi import HTTPException

from api.config import settings
from api.server.schemas import GpuRuntimeSessionResponse
from api.gpu_hotplug_service import GpuHotplugError
from api.server.gpu_sessions import (
    GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS,
    GPU_RUNTIME_SESSION_PURPOSES,
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


def _runtime_session_authority_db(server, attestation):
    reservation = SimpleNamespace(
        state="running",
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
    assert payload["owner_hotkey"] == "5Owner"
    assert payload["allowed_purposes"] == list(GPU_RUNTIME_SESSION_PURPOSES)
    assert payload["exp"] - payload["iat"] == 900
    assert int(expires_at.timestamp()) == payload["exp"]


@pytest.mark.asyncio
async def test_runtime_session_iat_accepts_explicit_bounded_future_skew():
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
        token, expires_at = mint_gpu_runtime_session(server, attestation)
        server.gpu_runtime_session_expires_at = expires_at
        current, payload = await validate_gpu_runtime_session(
            db,
            token,
            required_purpose="miner",
        )

    assert current is server
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
        token, _expires_at = mint_gpu_runtime_session(server, attestation)
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
        token, _expires_at = mint_gpu_runtime_session(server, attestation)
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
