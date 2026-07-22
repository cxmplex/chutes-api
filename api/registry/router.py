"""Registry authorization for Model A/GPU miners and reservation-attested Model-B TDs."""

from datetime import datetime, timedelta, timezone
import re
from urllib.parse import parse_qs, urlsplit

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import (
    AUTHORIZATION_HEADER,
    HOTKEY_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
)
from api.database import generate_uuid, get_db_session
from api.host.schemas import (
    RegistrySession,
    RegistrySessionClaimsV1,
    RegistrySessionRequestV1,
    RegistrySessionResponseV1,
    TdLaunchReservation,
)
from api.server.schemas import Server, ServerAttestation
from api.server.util import extract_client_cert_hash
from api.user.service import get_current_user


router = APIRouter()
_legacy_registry_auth = get_current_user(
    purpose="registry",
    registered_to=settings.netuid,
    raise_not_found=False,
    force_hotkey_auth=True,
)


async def _current_attested_model_b_server(db: AsyncSession, cert_hash: str) -> Server:
    server = (
        await db.execute(
            select(Server).where(
                Server.attested_cert_pubkey_hash == cert_hash.lower(),
                Server.self_registered.is_(True),
                Server.is_tee.is_(True),
                Server.compute_type == "cpu",
                Server.launch_reservation_id.is_not(None),
            )
        )
    ).scalar_one_or_none()
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented certificate is not a current Model-B TD identity.",
        )
    latest = (
        await db.execute(
            select(ServerAttestation)
            .where(ServerAttestation.server_id == server.server_id)
            .order_by(
                ServerAttestation.created_at.desc(),
                ServerAttestation.attestation_id.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.release_attestation_max_age_seconds
    )
    if (
        latest is None
        or latest.verification_error is not None
        or latest.verified_at is None
        or latest.verified_at < cutoff
        or latest.measurement_name != server.measurement_name
        or latest.measurement_config_fingerprint != server.measurement_config_fingerprint
        or latest.trust_set_fingerprint != server.trust_set_fingerprint
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Model-B TD does not have a fresh exact attestation.",
        )
    return server


@router.post("/sessions", response_model=RegistrySessionResponseV1)
async def create_registry_session(
    body: RegistrySessionRequestV1,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
):
    """Mint one short current-attestation-bound repository/digest pull session."""

    cert_hash = await extract_client_cert_hash(require_proxy_verified=True)(request)
    server = await _current_attested_model_b_server(db, cert_hash)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == server.server_id).with_for_update()
        )
    ).scalar_one()
    reservation = await db.get(TdLaunchReservation, server.launch_reservation_id)
    if (
        reservation is None
        or reservation.consumed_at is None
        or reservation.invalidated_at is not None
        or reservation.server_id != server.server_id
        or reservation.role != "chute"
        or reservation.container_repository != body.repository
        or reservation.container_manifest_digest != body.manifest_digest
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry request does not match the TD's reserved chute image.",
        )
    existing = (
        await db.execute(
            select(RegistrySession).where(RegistrySession.server_id == server.server_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This TD already minted its one registry session.",
        )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=10)
    session_id = generate_uuid()
    token_id = generate_uuid()
    claims = RegistrySessionClaimsV1(
        session_id=session_id,
        server_id=server.server_id,
        attested_cert_sha256=cert_hash.lower(),
        repository=body.repository,
        actions=["pull"],
        manifest_digest=body.manifest_digest,
        issued_at=now,
        expires_at=expires_at,
    )
    token = jwt.encode(
        {
            **claims.model_dump(mode="json"),
            "iss": "chutes",
            "purpose": "registry_session",
            "jti": token_id,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        },
        settings.launch_config_key,
        algorithm="HS256",
    )
    db.add(
        RegistrySession(
            session_id=session_id,
            token_id=token_id,
            server_id=server.server_id,
            attested_cert_pubkey_hash=cert_hash.lower(),
            repository=body.repository,
            actions=["pull"],
            manifest_digest=body.manifest_digest,
            issued_at=now,
            expires_at=expires_at,
        )
    )
    await db.commit()
    return RegistrySessionResponseV1(token=token, expires_at=expires_at)


def _registry_request_matches(
    session: RegistrySession, original_method: str, original_uri: str
) -> bool:
    if original_method.upper() not in {"GET", "HEAD"}:
        return False
    parsed = urlsplit(original_uri)
    path = parsed.path
    if path == "/v2/_token":
        try:
            scopes = parse_qs(parsed.query, strict_parsing=True).get("scope") or []
        except ValueError:
            return False
        return scopes == [f"repository:{session.repository}:pull"]
    prefix = f"/v2/{session.repository}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix) :]
    if suffix.startswith("manifests/"):
        reference = suffix.removeprefix("manifests/")
        signature_tag = session.manifest_digest.removeprefix("sha256:") + ".sig"
        return reference in {
            session.manifest_digest,
            f"sha256-{signature_tag}",
        }
    if suffix.startswith("blobs/"):
        return bool(re.fullmatch(r"blobs/sha256:[0-9a-f]{64}", suffix))
    return False


async def _validate_registry_session(
    db: AsyncSession,
    token: str,
    cert_hash: str,
    original_method: str,
    original_uri: str,
) -> None:
    try:
        payload = jwt.decode(
            token,
            settings.launch_config_key,
            algorithms=["HS256"],
            issuer="chutes",
            options={
                "require": [
                    "iss",
                    "purpose",
                    "jti",
                    "iat",
                    "exp",
                    "session_id",
                    "server_id",
                    "attested_cert_sha256",
                    "repository",
                    "actions",
                    "manifest_digest",
                    "issued_at",
                    "expires_at",
                ]
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry session is invalid or expired.",
        ) from exc
    if payload.get("purpose") != "registry_session":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry session purpose is invalid.",
        )
    row = (
        await db.execute(
            select(RegistrySession)
            .where(RegistrySession.session_id == payload["session_id"])
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    expected = {
        "jti": row.token_id if row else None,
        "server_id": row.server_id if row else None,
        "attested_cert_sha256": row.attested_cert_pubkey_hash if row else None,
        "repository": row.repository if row else None,
        "actions": row.actions if row else None,
        "manifest_digest": row.manifest_digest if row else None,
    }
    if (
        row is None
        or row.revoked_at is not None
        or row.expires_at <= now
        or row.attested_cert_pubkey_hash != cert_hash.lower()
        or any(payload.get(key) != value for key, value in expected.items())
        or not _registry_request_matches(row, original_method, original_uri)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry session does not authorize this certificate/repository/action.",
        )
    server = await _current_attested_model_b_server(db, cert_hash)
    if server.server_id != row.server_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry session server identity changed.",
        )
    row.last_used_at = now
    await db.commit()


@router.get("/auth")
async def registry_auth(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    registry_session: str | None = Header(None, alias="X-Chutes-Registry-Session"),
    original_method: str | None = Header(None, alias="X-Chutes-Registry-Method"),
    original_uri: str | None = Header(None, alias="X-Chutes-Registry-Uri"),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
    nonce: str | None = Header(None, alias=NONCE_HEADER),
    authorization: str | None = Header(None, alias=AUTHORIZATION_HEADER),
    sig_version: str | None = Header(None, alias=SIG_VERSION_HEADER),
):
    """Authorize every token/manifest/blob request; session paths never fall back."""

    if registry_session:
        if not original_method or not original_uri:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Registry session request context is missing.",
            )
        cert_hash = await extract_client_cert_hash(require_proxy_verified=True)(request)
        await _validate_registry_session(
            db,
            registry_session,
            cert_hash,
            original_method,
            original_uri,
        )
        return {"authenticated": True, "auth_type": "attested_registry_session"}
    await _legacy_registry_auth(
        request,
        api_key=None,
        hotkey=hotkey,
        signature=signature,
        nonce=nonce,
        authorization=authorization,
        sig_version=sig_version,
    )
    return {"authenticated": True, "auth_type": "legacy_miner"}
