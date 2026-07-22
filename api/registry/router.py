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
    canonical_sha256,
)
from api.server.schemas import Server, ServerAttestation
from api.server.util import extract_client_cert_hash
from api.user.service import get_current_user
from api.registry.oci import (
    OciClosureError,
    resolve_oci_descriptor_closure,
)


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


def _encode_registry_session(row: RegistrySession) -> str:
    claims = RegistrySessionClaimsV1(
        session_id=row.session_id,
        server_id=row.server_id,
        attested_cert_sha256=row.attested_cert_pubkey_hash,
        repository=row.repository,
        actions=row.actions,
        manifest_digest=row.manifest_digest,
        descriptor_closure_sha256=row.descriptor_closure_sha256,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
    )
    return jwt.encode(
        {
            **claims.model_dump(mode="json"),
            "iss": "chutes",
            "purpose": "registry_session",
            "jti": row.token_id,
            "iat": int(row.issued_at.timestamp()),
            "exp": int(row.expires_at.timestamp()),
        },
        settings.launch_config_key,
        algorithm="HS256",
    )


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
            select(RegistrySession)
            .where(RegistrySession.server_id == server.server_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        existing is not None
        and existing.revoked_at is None
        and existing.expires_at > now
        and existing.attested_cert_pubkey_hash == cert_hash.lower()
        and existing.repository == body.repository
        and existing.actions == ["pull"]
        and existing.manifest_digest == body.manifest_digest
        and _registry_request_matches(
            existing,
            "GET",
            f"/v2/{existing.repository}/manifests/{existing.manifest_digest}",
        )
    ):
        return RegistrySessionResponseV1(
            token=_encode_registry_session(existing),
            expires_at=existing.expires_at,
        )
    try:
        closure = await resolve_oci_descriptor_closure(
            reservation.container_repository,
            reservation.container_manifest_digest,
        )
    except OciClosureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The reserved OCI descriptor closure could not be verified.",
        ) from exc
    expires_at = now + timedelta(minutes=10)
    token_id = generate_uuid()
    if existing is None:
        row = RegistrySession(
            session_id=generate_uuid(),
            token_id=token_id,
            server_id=server.server_id,
        )
        db.add(row)
    else:
        row = existing
        row.token_id = token_id
    row.attested_cert_pubkey_hash = cert_hash.lower()
    row.repository = body.repository
    row.actions = ["pull"]
    row.manifest_digest = body.manifest_digest
    row.allowed_manifests = list(closure.manifests)
    row.allowed_blobs = list(closure.blobs)
    row.allowed_manifest_tags = list(closure.manifest_tags)
    row.descriptor_closure_sha256 = closure.sha256
    row.issued_at = now
    row.expires_at = expires_at
    row.revoked_at = None
    row.last_used_at = None
    token = _encode_registry_session(row)
    await db.commit()
    return RegistrySessionResponseV1(
        token=token,
        expires_at=expires_at,
    )


def _registry_request_matches(
    session: RegistrySession, original_method: str, original_uri: str
) -> bool:
    method = original_method.upper()
    if method not in {"GET", "HEAD"}:
        return False
    parsed = urlsplit(original_uri)
    path = parsed.path
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    if path == "/v2/":
        return not parsed.query
    if path == "/v2/_token":
        if method != "GET":
            return False
        try:
            query = parse_qs(
                parsed.query,
                strict_parsing=True,
                keep_blank_values=True,
            )
        except ValueError:
            return False
        if not set(query).issubset({"scope", "service"}):
            return False
        scopes = query.get("scope") or []
        services = query.get("service") or []
        return bool(
            scopes == [f"repository:{session.repository}:pull"]
            and (not services or services == ["registry.chutes.ai"])
        )
    if parsed.query or not session.descriptor_closure_sha256:
        return False
    manifests = session.allowed_manifests
    blobs = session.allowed_blobs
    tags = session.allowed_manifest_tags
    if (
        not isinstance(manifests, list)
        or not isinstance(blobs, list)
        or not isinstance(tags, list)
        or not 1 <= len(manifests) <= 128
        or len(blobs) > 2048
        or len(tags) > 32
    ):
        return False
    if (
        manifests != sorted(set(manifests))
        or blobs != sorted(set(blobs))
        or tags != sorted(set(tags))
        or session.manifest_digest not in manifests
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in manifests)
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in blobs)
        or any(not re.fullmatch(r"sha256-[0-9a-f]{64}\.sig", item) for item in tags)
        or canonical_sha256(
            {
                "schema": "chutes.oci-descriptor-closure",
                "version": 1,
                "root_manifest": session.manifest_digest,
                "manifests": manifests,
                "blobs": blobs,
                "manifest_tags": tags,
            }
        )
        != session.descriptor_closure_sha256
    ):
        return False
    prefix = f"/v2/{session.repository}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix) :]
    if suffix.startswith("manifests/"):
        reference = suffix.removeprefix("manifests/")
        return "/" not in reference and (reference in manifests or reference in tags)
    if suffix.startswith("blobs/"):
        reference = suffix.removeprefix("blobs/")
        return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", reference) and reference in blobs)
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
                    "descriptor_closure_sha256",
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
        "descriptor_closure_sha256": (row.descriptor_closure_sha256 if row else None),
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
    client_verify: str | None = Header(None, alias="X-Client-Verify"),
    client_cert: str | None = Header(None, alias="X-Client-Cert"),
):
    """Authorize every token/manifest/blob request; session paths never fall back."""

    certificate_presented = bool(
        client_cert or (client_verify and client_verify.strip().upper() not in {"", "NONE"})
    )
    if registry_session or certificate_presented:
        if not registry_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Certificate-presenting registry requests require an attested session.",
            )
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
