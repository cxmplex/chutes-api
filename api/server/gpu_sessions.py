"""Short-lived, current-attestation-bound GPU miner runtime sessions."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import generate_uuid
from api.gpu_hotplug_service import (
    GpuHotplugError,
    require_gpu_hotplug_runtime_ack,
)
from api.gpu_models import GpuRegistrationAttempt
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.schemas import (
    GpuLaunchReservation,
    canonical_sha256,
)
from api.server.schemas import Server, ServerAttestation

GPU_RUNTIME_SESSION_HEADER = "X-Chutes-Attested-Session"
GPU_RUNTIME_SESSION_PURPOSES = (
    "cache",
    "gpu-infra",
    "instances",
    "launch",
    "miner",
    "nodes",
    "registry",
    "sockets",
)
GPU_PLATFORM_RUNTIME_SESSION_PURPOSES = ("registry",)
GPU_RUNTIME_SESSION_LIFETIME_SECONDS = 900


def _revocation_failed(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_revocation_failed(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_revocation_failed(item) for item in value)
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in {
        "good",
        "not_revoked",
        "not-revoked",
        "unrevoked",
        "authenticated_outage_grace",
        "revocation_not_advertised",
    }:
        return False
    return any(
        marker in normalized for marker in ("revoked", "failed", "invalid", "expired")
    )


def _current_attestation(
    server: Server,
    attestation: ServerAttestation | None,
    *,
    expected_id: str | None = None,
) -> ServerAttestation:
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.release_attestation_max_age_seconds
    )
    if (
        attestation is None
        or (expected_id is not None and attestation.attestation_id != expected_id)
        or attestation.server_id != server.server_id
        or attestation.verification_error is not None
        or attestation.verified_at is None
        or attestation.verified_at < cutoff
        or attestation.gpu_retired_at is not None
        or attestation.measurement_name != server.measurement_name
        or attestation.measurement_config_fingerprint
        != server.measurement_config_fingerprint
        or attestation.trust_set_fingerprint != server.trust_set_fingerprint
        or dict(attestation.revocation_status or {})
        != dict(server.attestation_revocation_status or {})
        or _revocation_failed(attestation.revocation_status)
        or attestation.gpu_launch_reservation_id != server.gpu_launch_reservation_id
        or attestation.gpu_allocation_group_id != server.gpu_allocation_group_id
        or attestation.gpu_allocation_group_generation
        != server.gpu_allocation_group_generation
        or attestation.gpu_management_mode != server.gpu_management_mode
        or attestation.gpu_process_incarnation != server.gpu_process_incarnation
        or attestation.gpu_topology_fingerprint != server.gpu_topology_fingerprint
        or not attestation.gpu_evidence_sha256
        or not attestation.gpu_evidence_certificate_sha256s
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Latest GPU attestation attempt is not current and successful.",
        )
    return attestation


async def _latest_attestation_attempt(
    db: AsyncSession,
    server_id: str,
    *,
    for_update: bool = False,
) -> ServerAttestation | None:
    query = (
        select(ServerAttestation)
        .where(ServerAttestation.server_id == server_id)
        .order_by(
            ServerAttestation.created_at.desc(),
            ServerAttestation.attestation_id.desc(),
        )
        .limit(1)
    )
    if for_update:
        query = query.with_for_update()
    return (await db.execute(query)).scalar_one_or_none()


async def require_completed_gpu_registration(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    attestation: ServerAttestation,
    server: Server,
) -> GpuRegistrationAttempt:
    """Require the exact completed Registration V2 publication authority."""

    await acquire_gpu_lifecycle_lock(db)
    attempts = list(
        (
            await db.execute(
                select(GpuRegistrationAttempt)
                .where(
                    GpuRegistrationAttempt.reservation_id == reservation.reservation_id,
                    GpuRegistrationAttempt.state == "completed",
                )
                .order_by(
                    GpuRegistrationAttempt.completed_at,
                    GpuRegistrationAttempt.attempt_id,
                )
                .with_for_update()
            )
        ).scalars()
    )
    if len(attempts) != 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU registration attempt is not durably completed.",
        )
    attempt = attempts[0]
    stable = dict(attempt.stable_response or {})
    expected_stable_keys = {
        "server_id",
        "owner_hotkey",
        "reservation_id",
        "claims_sha256",
        "allocation_group_id",
        "allocation_group_generation",
        "process_incarnation",
        "gpu_uuids",
        "gpu_identifiers",
        "management_mode",
        "measurement_version",
        "measurement_name",
        "measurement_config_fingerprint",
        "trust_set_fingerprint",
        "attestation_id",
        "verified_at",
        "status",
        "registration_id",
    }
    stable_uuids = stable.get("gpu_uuids")
    stable_identifiers = stable.get("gpu_identifiers")
    try:
        inventory_by_uuid = dict(
            zip(reservation.gpu_uuids, reservation.gpu_identifiers, strict=True)
        )
        certificate_by_uuid = dict(
            zip(
                reservation.gpu_uuids,
                reservation.gpu_attestation_certificate_sha256s,
                strict=True,
            )
        )
        expected_evidence_certificates = [
            certificate_by_uuid[gpu_uuid] for gpu_uuid in stable_uuids
        ]
    except (KeyError, TypeError, ValueError):
        selected_matches = False
    else:
        selected_matches = bool(
            isinstance(stable_uuids, list)
            and all(isinstance(gpu_uuid, str) for gpu_uuid in stable_uuids)
            and stable_uuids
            and stable_uuids == sorted(set(stable_uuids))
            and isinstance(stable_identifiers, list)
            and len(stable_identifiers) == len(stable_uuids)
            and stable_identifiers
            == [inventory_by_uuid[gpu_uuid] for gpu_uuid in stable_uuids]
            and attestation.gpu_evidence_certificate_sha256s
            == expected_evidence_certificates
            and (
                stable_uuids == list(reservation.gpu_uuids)
                if reservation.management_mode == "platform"
                else set(stable_uuids).issubset(set(reservation.gpu_uuids))
            )
        )
    certificate_sha256 = (
        hashlib.sha256(server.attested_cert.encode("utf-8")).hexdigest()
        if server.attested_cert is not None
        else None
    )
    exact = bool(
        set(stable) == expected_stable_keys
        and selected_matches
        and attempt.attestation_id
        == attestation.attestation_id
        == reservation.registration_attestation_id
        and attempt.registration_id is not None
        and attempt.stable_response_sha256 is not None
        and secrets.compare_digest(
            attempt.stable_response_sha256, canonical_sha256(stable)
        )
        and stable.get("registration_id") == attempt.registration_id
        and stable.get("attestation_id") == attempt.attestation_id
        and stable.get("server_id") == reservation.server_id
        and stable.get("reservation_id") == reservation.reservation_id
        and stable.get("claims_sha256") == reservation.claims_sha256
        and stable.get("allocation_group_id") == reservation.allocation_group_id
        and stable.get("allocation_group_generation")
        == reservation.allocation_group_generation
        and stable.get("process_incarnation") == reservation.process_incarnation
        and stable.get("management_mode") == reservation.management_mode
        and stable.get("owner_hotkey") == reservation.owner_hotkey
        and stable.get("measurement_version") == attestation.measurement_version
        and stable.get("measurement_name") == attestation.measurement_name
        and stable.get("measurement_config_fingerprint")
        == attestation.measurement_config_fingerprint
        and stable.get("trust_set_fingerprint") == attestation.trust_set_fingerprint
        and stable.get("verified_at") == attestation.verified_at.isoformat()
        and stable.get("status") == "registered"
        and server.server_id == reservation.server_id == attestation.server_id
        and server.gpu_launch_reservation_id == reservation.reservation_id
        and server.gpu_allocation_group_id == reservation.allocation_group_id
        and server.gpu_allocation_group_generation
        == reservation.allocation_group_generation
        and server.gpu_process_incarnation == reservation.process_incarnation
        and server.gpu_management_mode == reservation.management_mode
        and attestation.gpu_launch_reservation_id == reservation.reservation_id
        and attestation.gpu_allocation_group_id == reservation.allocation_group_id
        and attestation.gpu_allocation_group_generation
        == reservation.allocation_group_generation
        and attestation.gpu_process_incarnation == reservation.process_incarnation
        and attestation.gpu_claims_sha256 == reservation.claims_sha256
        and server.attested_cert is not None
        and server.attested_cert == attempt.peer_certificate_pem
        and certificate_sha256 is not None
        and secrets.compare_digest(attempt.peer_certificate_sha256, certificate_sha256)
        and server.attested_cert_pubkey_hash is not None
        and secrets.compare_digest(
            attempt.peer_spki_sha256, server.attested_cert_pubkey_hash
        )
    )
    if not exact:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU registration completion audit is not exact.",
        )
    return attempt


def mint_gpu_runtime_session(
    server: Server,
    attestation: ServerAttestation,
) -> tuple[str, datetime]:
    mode = server.gpu_management_mode
    if (
        server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or mode not in {"miner", "platform"}
        or not server.gpu_launch_reservation_id
        or not server.attested_cert_pubkey_hash
        or attestation.server_id != server.server_id
    ):
        raise ValueError(
            "GPU runtime sessions require a current attested server and exact mode scope"
        )
    _current_attestation(server, attestation)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=GPU_RUNTIME_SESSION_LIFETIME_SECONDS)
    payload = {
        "schema": "chutes.gpu-runtime-session",
        "version": 1,
        "iss": "chutes",
        "purpose": "gpu_runtime_session",
        "jti": generate_uuid(),
        "server_id": server.server_id,
        "owner_hotkey": server.miner_hotkey,
        "reservation_id": server.gpu_launch_reservation_id,
        "attestation_id": attestation.attestation_id,
        "attested_spki_sha256": server.attested_cert_pubkey_hash.lower(),
        "management_mode": mode,
        "allowed_purposes": list(
            GPU_RUNTIME_SESSION_PURPOSES
            if mode == "miner"
            else GPU_PLATFORM_RUNTIME_SESSION_PURPOSES
        ),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return (
        jwt.encode(payload, settings.launch_config_key, algorithm="HS256"),
        expires_at,
    )


async def validate_gpu_runtime_session(
    db: AsyncSession,
    token: str,
    *,
    required_purpose: str | None,
    allow_resetting: bool = False,
) -> tuple[Server, dict[str, Any]]:
    try:
        payload = jwt.decode(
            token,
            settings.launch_config_key,
            algorithms=["HS256"],
            issuer="chutes",
            options={"require": ["exp", "iat", "iss", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session is invalid or expired.",
        ) from exc
    required_keys = {
        "schema",
        "version",
        "iss",
        "purpose",
        "jti",
        "server_id",
        "owner_hotkey",
        "reservation_id",
        "attestation_id",
        "attested_spki_sha256",
        "management_mode",
        "allowed_purposes",
        "iat",
        "exp",
    }
    mode = payload.get("management_mode") if isinstance(payload, dict) else None
    expected_purposes = (
        GPU_RUNTIME_SESSION_PURPOSES
        if mode == "miner"
        else GPU_PLATFORM_RUNTIME_SESSION_PURPOSES
        if mode == "platform"
        else ()
    )
    if (
        not isinstance(payload, dict)
        or set(payload) != required_keys
        or payload["schema"] != "chutes.gpu-runtime-session"
        or payload["version"] != 1
        or payload["purpose"] != "gpu_runtime_session"
        or payload["allowed_purposes"] != list(expected_purposes)
        or required_purpose not in expected_purposes
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session scope is invalid.",
        )
    await acquire_gpu_lifecycle_lock(db)
    server = await db.get(Server, payload["server_id"])
    attestation = await db.get(ServerAttestation, payload["attestation_id"])
    reservation = await db.get(GpuLaunchReservation, payload["reservation_id"])
    latest_attestation = (
        await _latest_attestation_attempt(db, server.server_id)
        if server is not None
        else None
    )
    if (
        server is None
        or attestation is None
        or reservation is None
        or server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or server.gpu_management_mode != mode
        or server.gpu_retired_at is not None
        or server.miner_hotkey != payload["owner_hotkey"]
        or server.gpu_launch_reservation_id != payload["reservation_id"]
        or server.attested_cert_pubkey_hash != payload["attested_spki_sha256"]
        or server.gpu_runtime_session_attestation_id != payload["attestation_id"]
        or server.gpu_runtime_session_expires_at is None
        or server.gpu_runtime_session_expires_at <= datetime.now(timezone.utc)
        or reservation.state
        not in (
            {"running", "resetting"}
            if allow_resetting and required_purpose == "gpu-infra"
            else {"running"}
        )
        or reservation.registration_attestation_id is None
        or reservation.server_id != server.server_id
        or reservation.management_mode != server.gpu_management_mode
        or reservation.allocation_group_id != server.gpu_allocation_group_id
        or reservation.allocation_group_generation
        != server.gpu_allocation_group_generation
        or reservation.process_incarnation != server.gpu_process_incarnation
        or reservation.topology_fingerprint != server.gpu_topology_fingerprint
        or attestation.gpu_claims_sha256 != reservation.claims_sha256
        or attestation.gpu_release_id != reservation.gpu_release_id
        or attestation.gpu_profile_id != reservation.profile_id
        or attestation.gpu_host_boot_generation != reservation.host_boot_generation
        or attestation.gpu_reservation_generation != reservation.reservation_generation
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session identity is no longer current.",
        )
    try:
        await require_completed_gpu_registration(db, reservation, attestation, server)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU registration is not durably completed.",
        ) from exc
    try:
        await require_gpu_hotplug_runtime_ack(db, reservation, server.server_id)
    except GpuHotplugError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Legacy GPU hotplug custody is not ready for runtime access.",
        ) from exc
    try:
        _current_attestation(
            server,
            latest_attestation,
            expected_id=payload["attestation_id"],
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A newer GPU attestation attempt invalidated this session.",
        ) from exc
    return server, payload


async def latest_gpu_runtime_session(
    db: AsyncSession,
    server: Server,
) -> tuple[str, datetime, str]:
    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == server.server_id).with_for_update()
        )
    ).scalar_one_or_none()
    reservation = (
        (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.reservation_id
                    == server.gpu_launch_reservation_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if server is not None and server.gpu_launch_reservation_id is not None
        else None
    )
    if (
        server is None
        or reservation is None
        or reservation.state != "running"
        or reservation.server_id != server.server_id
        or reservation.management_mode != server.gpu_management_mode
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU runtime session reservation is not current.",
        )
    attestation = _current_attestation(
        server,
        await _latest_attestation_attempt(db, server.server_id, for_update=True),
    )
    await require_completed_gpu_registration(db, reservation, attestation, server)
    try:
        await require_gpu_hotplug_runtime_ack(db, reservation, server.server_id)
    except GpuHotplugError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Legacy GPU hotplug custody is not ready for runtime access.",
        ) from exc
    token, expires_at = mint_gpu_runtime_session(server, attestation)
    return token, expires_at, attestation.attestation_id
