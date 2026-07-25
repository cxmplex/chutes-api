"""Short-lived, current-attestation-bound GPU miner runtime sessions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import generate_uuid
from api.host.schemas import GpuLaunchReservation
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
    return any(marker in normalized for marker in ("revoked", "failed", "invalid", "expired"))


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
        or attestation.measurement_config_fingerprint != server.measurement_config_fingerprint
        or attestation.trust_set_fingerprint != server.trust_set_fingerprint
        or dict(attestation.revocation_status or {})
        != dict(server.attestation_revocation_status or {})
        or _revocation_failed(attestation.revocation_status)
        or attestation.gpu_launch_reservation_id != server.gpu_launch_reservation_id
        or attestation.gpu_allocation_group_id != server.gpu_allocation_group_id
        or attestation.gpu_allocation_group_generation != server.gpu_allocation_group_generation
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
) -> ServerAttestation | None:
    return (
        await db.execute(
            select(ServerAttestation)
            .where(ServerAttestation.server_id == server_id)
            .order_by(
                ServerAttestation.created_at.desc(),
                ServerAttestation.attestation_id.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()


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
    server = await db.get(Server, payload["server_id"])
    attestation = await db.get(ServerAttestation, payload["attestation_id"])
    reservation = await db.get(GpuLaunchReservation, payload["reservation_id"])
    latest_attestation = (
        await _latest_attestation_attempt(db, server.server_id) if server is not None else None
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
        or reservation.allocation_group_generation != server.gpu_allocation_group_generation
        or reservation.process_incarnation != server.gpu_process_incarnation
        or reservation.topology_fingerprint != server.gpu_topology_fingerprint
        or attestation.gpu_claims_sha256 != reservation.claims_sha256
        or attestation.gpu_release_id != reservation.gpu_release_id
        or attestation.gpu_profile_id != reservation.profile_id
        or attestation.gpu_host_boot_generation != reservation.host_boot_generation
        or attestation.gpu_reservation_generation != reservation.reservation_generation
        or attestation.gpu_evidence_certificate_sha256s
        != reservation.gpu_attestation_certificate_sha256s
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session identity is no longer current.",
        )
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
    attestation = _current_attestation(
        server,
        await _latest_attestation_attempt(db, server.server_id),
    )
    token, expires_at = mint_gpu_runtime_session(server, attestation)
    return token, expires_at, attestation.attestation_id
