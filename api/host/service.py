"""Seedless logical-host enrollment, authentication, and PCS mailbox services."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Depends, Header, HTTPException, Request, status
from loguru import logger
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from bittensor_wallet.keypair import Keypair

from api.config import settings
from api.database import generate_uuid, get_db_session
from api.host.schemas import (
    EnrollmentKeyChallengeRequestV1,
    EnrollmentKeyChallengeResponseV1,
    EnrollmentVoucherClaimsV1,
    EnrollmentVoucherMintRequestV1,
    EnrollmentVoucherResponseV1,
    HostAuthChallengeV1,
    HostEnrollmentChallenge,
    HostEnrollmentRedemptionV1,
    HostEnrollmentResponseV1,
    HostEnrollmentVoucher,
    HostIdentityDurabilityAckV1,
    HostKeyGeneration,
    HostPcsMailbox,
    HostProvisioningHeartbeatV1,
    HostProvisioningStatusV1,
    HostSigningEnvelopeV1,
    HostSocketAuthenticationV1,
    HostSocketChallengeV1,
    PcsMailboxAckV1,
    PcsMailboxEnvelopeV1,
    canonical_sha256,
)
from api.server.schemas import Host

HOST_ID_HEADER = "X-Chutes-Host-Id"
HOST_KEY_GENERATION_HEADER = "X-Chutes-Host-Key-Generation"
HOST_CHALLENGE_ID_HEADER = "X-Chutes-Host-Challenge-Id"
HOST_SIGNATURE_HEADER = "X-Chutes-Host-Signature"
HOST_ISSUED_AT_HEADER = "X-Chutes-Host-Issued-At"

AUTH_CHALLENGE_TTL_SECONDS = 120
ENROLLMENT_CHALLENGE_TTL_SECONDS = 300
HOST_SIGNATURE_MAX_SKEW_SECONDS = 120
PCS_MAILBOX_MAX_LIFETIME_SECONDS = 3600
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class HostAuthError(ValueError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _key_fingerprint(public_key_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(public_key_b64, validate=True)).hexdigest()


def _parse_voucher(voucher: str) -> tuple[str, str]:
    try:
        voucher_id, secret = voucher.split(".", 1)
        raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    except (ValueError, TypeError) as exc:
        raise HostAuthError("Enrollment voucher is malformed.") from exc
    if not voucher_id or len(raw) != 32:
        raise HostAuthError("Enrollment voucher is malformed.")
    return voucher_id, hashlib.sha256(voucher.encode("ascii")).hexdigest()


def _verify_ed25519(public_key_b64: str, signature_b64: str, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True)).verify(
            base64.b64decode(signature_b64, validate=True), message
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise HostAuthError("Ed25519 proof is invalid.") from exc


async def mint_enrollment_voucher(
    db: AsyncSession,
    owner_hotkey: str,
    request: EnrollmentVoucherMintRequestV1,
) -> EnrollmentVoucherResponseV1:
    """Mint a one-use miner-owned enrollment voucher; persist only its hash."""

    existing = await db.get(Host, request.host_id)
    if existing is not None and existing.miner_hotkey != owner_hotkey:
        raise HostAuthError("Logical host is owned by another miner.")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"host-enrollment:{request.host_id}"},
    )
    await db.execute(
        select(HostEnrollmentVoucher)
        .where(HostEnrollmentVoucher.host_id == request.host_id)
        .with_for_update()
    )
    latest_generation = (
        await db.execute(
            select(func.max(HostEnrollmentVoucher.enrollment_generation)).where(
                HostEnrollmentVoucher.host_id == request.host_id
            )
        )
    ).scalar_one_or_none()
    enrollment_generation = int(latest_generation or 0) + 1
    now = _utcnow()
    await db.execute(
        update(HostEnrollmentVoucher)
        .where(
            HostEnrollmentVoucher.host_id == request.host_id,
            HostEnrollmentVoucher.consumed_at.is_(None),
            HostEnrollmentVoucher.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    claims = EnrollmentVoucherClaimsV1(
        owner_hotkey=owner_hotkey,
        host_id=request.host_id,
        tee_type=request.tee_type,
        channel=request.channel,
        enrollment_generation=enrollment_generation,
        issued_at=now,
        expires_at=now + timedelta(seconds=request.expires_in_seconds),
        provider=request.provider,
        source=request.source,
        source_metadata=request.source_metadata,
    )
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    voucher = f"{claims.voucher_id}.{secret}"
    row = HostEnrollmentVoucher(
        voucher_id=claims.voucher_id,
        voucher_hash=hashlib.sha256(voucher.encode("ascii")).hexdigest(),
        owner_hotkey=owner_hotkey,
        host_id=request.host_id,
        tee_type=request.tee_type,
        channel=request.channel,
        enrollment_generation=enrollment_generation,
        claims=claims.model_dump(mode="json", exclude_none=True),
        provider=request.provider,
        source=request.source,
        issued_at=now,
        expires_at=claims.expires_at,
    )
    db.add(row)
    await db.commit()
    return EnrollmentVoucherResponseV1(voucher=voucher, claims=claims)


async def _locked_valid_voucher(
    db: AsyncSession, voucher: str, *, allow_consumed: bool = False
) -> HostEnrollmentVoucher:
    voucher_id, voucher_hash = _parse_voucher(voucher)
    row = (
        await db.execute(
            select(HostEnrollmentVoucher)
            .where(HostEnrollmentVoucher.voucher_id == voucher_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if (
        row is None
        or not secrets.compare_digest(row.voucher_hash, voucher_hash)
        or (row.consumed_at is not None and not allow_consumed)
        or row.invalidated_at is not None
        or (row.expires_at <= now and row.consumed_at is None)
    ):
        raise HostAuthError("Enrollment voucher is unknown, expired, or already consumed.")
    return row


async def create_enrollment_key_challenge(
    db: AsyncSession, request: EnrollmentKeyChallengeRequestV1
) -> EnrollmentKeyChallengeResponseV1:
    """Prove Ed25519 possession, then challenge the proposed X25519 recipient."""

    voucher = await _locked_valid_voucher(db, request.voucher, allow_consumed=True)
    _verify_ed25519(
        request.ed25519_public_key,
        request.ed25519_signature,
        request.signing_bytes(),
    )
    if voucher.consumed_at is not None:
        host = await db.get(Host, voucher.host_id)
        key = (
            await db.get(
                HostKeyGeneration,
                (voucher.host_id, voucher.consumed_key_generation),
            )
            if voucher.consumed_key_generation is not None
            else None
        )
        if (
            host is None
            or key is None
            or key.revoked_at is not None
            or host.provisioning_state == "revoked"
            or host.enrollment_generation != voucher.enrollment_generation
            or key.enrollment_generation != voucher.enrollment_generation
            or key.ed25519_public_key != request.ed25519_public_key
            or key.x25519_public_key != request.x25519_public_key
        ):
            raise HostAuthError("Consumed voucher does not match the enrolled key generation.")
    now = _utcnow()
    challenge_id = generate_uuid()
    plaintext = secrets.token_bytes(32)
    ephemeral = X25519PrivateKey.generate()
    recipient = X25519PublicKey.from_public_bytes(
        base64.b64decode(request.x25519_public_key, validate=True)
    )
    salt = bytes.fromhex(voucher.voucher_hash)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"chutes/model-b/enrollment-x25519-proof/v1",
    ).derive(ephemeral.exchange(recipient))
    nonce = secrets.token_bytes(12)
    aad = request.signing_bytes() + challenge_id.encode("ascii")
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    row = HostEnrollmentChallenge(
        challenge_id=challenge_id,
        voucher_id=voucher.voucher_id,
        ed25519_public_key=request.ed25519_public_key,
        x25519_public_key=request.x25519_public_key,
        challenge_hash=hashlib.sha256(plaintext).hexdigest(),
        issued_at=now,
        expires_at=now + timedelta(seconds=ENROLLMENT_CHALLENGE_TTL_SECONDS),
    )
    db.add(row)
    await db.commit()
    return EnrollmentKeyChallengeResponseV1(
        challenge_id=challenge_id,
        server_ephemeral_public_key=base64.b64encode(
            ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        expires_at=row.expires_at,
    )


async def redeem_enrollment_voucher(
    db: AsyncSession, request: HostEnrollmentRedemptionV1
) -> HostEnrollmentResponseV1:
    """Atomically consume a voucher after proving possession of both host keys."""

    voucher = await _locked_valid_voucher(db, request.voucher, allow_consumed=True)
    challenge = (
        await db.execute(
            select(HostEnrollmentChallenge)
            .where(
                HostEnrollmentChallenge.challenge_id == request.challenge_id,
                HostEnrollmentChallenge.voucher_id == voucher.voucher_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if (
        challenge is None
        or challenge.consumed_at is not None
        or challenge.expires_at <= now
        or challenge.ed25519_public_key != request.ed25519_public_key
        or challenge.x25519_public_key != request.x25519_public_key
    ):
        raise HostAuthError("Enrollment key challenge is invalid or expired.")
    plaintext = base64.b64decode(request.challenge_plaintext, validate=True)
    if not secrets.compare_digest(challenge.challenge_hash, hashlib.sha256(plaintext).hexdigest()):
        raise HostAuthError("X25519 key-possession proof is invalid.")
    _verify_ed25519(
        request.ed25519_public_key,
        request.ed25519_signature,
        request.signing_bytes(),
    )

    host = (
        await db.execute(select(Host).where(Host.host_id == voucher.host_id).with_for_update())
    ).scalar_one_or_none()
    if host is not None and host.miner_hotkey != voucher.owner_hotkey:
        raise HostAuthError("Logical host is owned by another miner.")
    if (
        host is not None
        and voucher.consumed_at is None
        and int(host.enrollment_generation or 0) >= voucher.enrollment_generation
    ):
        raise HostAuthError("Enrollment voucher generation is not newer than the active host.")
    if voucher.consumed_at is not None:
        key = (
            await db.get(
                HostKeyGeneration,
                (voucher.host_id, voucher.consumed_key_generation),
            )
            if voucher.consumed_key_generation is not None
            else None
        )
        if (
            host is None
            or key is None
            or key.revoked_at is not None
            or host.provisioning_state == "revoked"
            or host.enrollment_generation != voucher.enrollment_generation
            or host.active_key_generation != key.generation
            or key.ed25519_public_key != request.ed25519_public_key
            or key.x25519_public_key != request.x25519_public_key
        ):
            raise HostAuthError("Consumed voucher does not match the enrolled key generation.")
        challenge.consumed_at = now
        await db.commit()
        return HostEnrollmentResponseV1(
            host_id=host.host_id,
            owner_hotkey=host.miner_hotkey,
            enrollment_generation=host.enrollment_generation,
            key_generation=host.active_key_generation,
            provisioning_state=host.provisioning_state,
        )
    if host is None:
        host = Host(
            host_id=voucher.host_id,
            name=voucher.host_id,
            miner_hotkey=voucher.owner_hotkey,
            netuid=settings.netuid,
            tee_type=voucher.tee_type,
            release_channel=voucher.channel,
            capacity=1,
            storage_enabled=False,
        )
        db.add(host)
        await db.flush()

    previous_keys = (
        (
            await db.execute(
                select(HostKeyGeneration)
                .where(HostKeyGeneration.host_id == host.host_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    rotated_existing_credential = any(item.revoked_at is None for item in previous_keys)
    next_key_generation = max((int(key.generation) for key in previous_keys), default=0) + 1
    for key in previous_keys:
        if key.revoked_at is None:
            key.revoked_at = now
            key.revocation_reason = "superseded by enrollment generation"
    key = HostKeyGeneration(
        host_id=host.host_id,
        generation=next_key_generation,
        enrollment_generation=voucher.enrollment_generation,
        ed25519_public_key=request.ed25519_public_key,
        ed25519_fingerprint=_key_fingerprint(request.ed25519_public_key),
        x25519_public_key=request.x25519_public_key,
        x25519_fingerprint=_key_fingerprint(request.x25519_public_key),
        issued_at=now,
    )
    db.add(key)
    host.name = host.name or host.host_id
    host.miner_hotkey = voucher.owner_hotkey
    host.tee_type = voucher.tee_type
    host.release_channel = voucher.channel
    host.enrollment_generation = voucher.enrollment_generation
    host.active_key_generation = next_key_generation
    host.provisioning_state = "persisting_identity"
    host.enrolled_at = now
    host.identity_durable_at = None
    host.identity_metadata_sha256 = None
    host.steady_config_sha256 = None
    host.provisioning_heartbeat_at = None
    host.provisioning_status = None
    voucher.consumed_at = now
    voucher.consumed_key_generation = next_key_generation
    challenge.consumed_at = now

    # Re-enrollment/rotation invalidates capabilities addressed to the old key generation.
    await db.execute(
        update(HostPcsMailbox)
        .where(
            HostPcsMailbox.host_id == host.host_id,
            HostPcsMailbox.consumed_at.is_(None),
            HostPcsMailbox.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    from api.host.schemas import TdLaunchReservation

    await db.execute(
        update(TdLaunchReservation)
        .where(
            TdLaunchReservation.host_id == host.host_id,
            TdLaunchReservation.consumed_at.is_(None),
            TdLaunchReservation.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    await db.commit()
    if rotated_existing_credential:
        from api.agent_channel import send_agent_command

        try:
            await send_agent_command(
                host.host_id,
                "disconnect",
                {"reason": "host credential rotated"},
            )
        except Exception as exc:
            logger.warning(
                f"Host {host.host_id} credential rotated but live-session disconnect "
                f"dispatch failed: {exc}"
            )
    return HostEnrollmentResponseV1(
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        enrollment_generation=host.enrollment_generation,
        key_generation=host.active_key_generation,
        provisioning_state=host.provisioning_state,
    )


def _provisioning_status(host: Host, accepted_at: datetime) -> HostProvisioningStatusV1:
    return HostProvisioningStatusV1(
        host_id=host.host_id,
        enrollment_generation=host.enrollment_generation,
        key_generation=host.active_key_generation,
        provisioning_state=host.provisioning_state,
        accepted_at=accepted_at,
    )


async def acknowledge_identity_durability(
    db: AsyncSession,
    host: Host,
    acknowledgement: HostIdentityDurabilityAckV1,
) -> HostProvisioningStatusV1:
    """Advance only after the active identity and steady config are durably persisted."""

    now = _utcnow()
    if (
        host.enrollment_generation != acknowledgement.enrollment_generation
        or host.active_key_generation != acknowledgement.key_generation
        or host.provisioning_state not in {"persisting_identity", "awaiting_pcs", "ready"}
    ):
        raise HostAuthError("Identity durability acknowledgement is stale or ineligible.")
    if host.identity_durable_at is not None:
        if (
            host.identity_metadata_sha256 != acknowledgement.identity_metadata_sha256
            or host.steady_config_sha256 != acknowledgement.steady_config_sha256
        ):
            raise HostAuthError(
                "Identity durability acknowledgement conflicts with the persisted audit."
            )
        return _provisioning_status(host, now)
    host.identity_durable_at = now
    host.identity_metadata_sha256 = acknowledgement.identity_metadata_sha256
    host.steady_config_sha256 = acknowledgement.steady_config_sha256
    if host.provisioning_state == "persisting_identity":
        host.provisioning_state = "awaiting_pcs" if host.tee_type == "tdx" else "ready"
    await db.commit()
    return _provisioning_status(host, now)


async def record_provisioning_heartbeat(
    db: AsyncSession,
    host: Host,
    heartbeat: HostProvisioningHeartbeatV1,
) -> HostProvisioningStatusV1:
    """Record visibility while launch/control surfaces remain disabled."""

    now = _utcnow()
    observed_at = heartbeat.observed_at
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    if (
        host.provisioning_state not in {"persisting_identity", "awaiting_pcs"}
        or heartbeat.provisioning_state != host.provisioning_state
        or heartbeat.enrollment_generation != host.enrollment_generation
        or heartbeat.key_generation != host.active_key_generation
        or abs((now - observed_at).total_seconds()) > HOST_SIGNATURE_MAX_SKEW_SECONDS
        or (host.provisioning_state == "awaiting_pcs" and host.identity_durable_at is None)
    ):
        raise HostAuthError("Provisioning heartbeat is stale or does not match host state.")
    host.provisioning_heartbeat_at = now
    host.provisioning_status = heartbeat.model_dump(mode="json")
    await db.commit()
    return _provisioning_status(host, now)


async def create_host_auth_challenge(
    db: AsyncSession, host_id: str, key_generation: int
) -> HostAuthChallengeV1:
    host = await db.get(Host, host_id)
    key = await db.get(HostKeyGeneration, (host_id, key_generation))
    if (
        host is None
        or key is None
        or host.provisioning_state in {"legacy", "unclaimed", "revoked"}
        or host.active_key_generation != key_generation
        or key.revoked_at is not None
    ):
        raise HostAuthError("Host key generation is not active.")
    now = _utcnow()
    challenge = HostAuthChallengeV1(
        challenge_id=generate_uuid(),
        host_id=host_id,
        key_generation=key_generation,
        challenge=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="),
        expires_at=now + timedelta(seconds=AUTH_CHALLENGE_TTL_SECONDS),
    )
    redis_key = f"host:http-challenge:{challenge.challenge_id}"
    try:
        await settings.redis_client.setex(
            redis_key,
            AUTH_CHALLENGE_TTL_SECONDS,
            json.dumps(challenge.model_dump(mode="json"), separators=(",", ":")),
        )
    except Exception as exc:
        raise HostAuthError("Host challenge service is unavailable.") from exc
    return challenge


async def create_host_socket_challenge(
    db: AsyncSession,
    session_id: str,
    host_id: str,
    key_generation: int,
) -> HostSocketChallengeV1:
    host = await db.get(Host, host_id)
    key = await db.get(HostKeyGeneration, (host_id, key_generation))
    if (
        host is None
        or key is None
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.active_key_generation != key_generation
        or key.revoked_at is not None
    ):
        raise HostAuthError("Host key generation is not control-channel eligible.")
    now = _utcnow()
    challenge = HostSocketChallengeV1(
        challenge_id=generate_uuid(),
        session_id=session_id,
        host_id=host_id,
        key_generation=key_generation,
        challenge=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="),
        expires_at=now + timedelta(seconds=AUTH_CHALLENGE_TTL_SECONDS),
    )
    try:
        await settings.redis_client.setex(
            f"host:socket-challenge:{challenge.challenge_id}",
            AUTH_CHALLENGE_TTL_SECONDS,
            json.dumps(challenge.model_dump(mode="json"), separators=(",", ":")),
        )
    except Exception as exc:
        raise HostAuthError("Host socket challenge service is unavailable.") from exc
    return challenge


async def verify_host_socket_authentication(
    db: AsyncSession,
    session_id: str,
    authentication: HostSocketAuthenticationV1,
) -> Host:
    if authentication.session_id != session_id:
        raise HostAuthError("Host socket authentication names another session.")
    now = _utcnow()
    issued_at = authentication.issued_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    if abs((now - issued_at).total_seconds()) > HOST_SIGNATURE_MAX_SKEW_SECONDS:
        raise HostAuthError("Host socket authentication is stale.")
    try:
        raw = await settings.redis_client.getdel(
            f"host:socket-challenge:{authentication.challenge_id}"
        )
    except Exception as exc:
        raise HostAuthError("Host socket replay protection is unavailable.") from exc
    if not raw:
        raise HostAuthError("Host socket challenge is unknown, expired, or already consumed.")
    challenge = HostSocketChallengeV1.model_validate_json(raw)
    if (
        challenge.session_id != session_id
        or challenge.host_id != authentication.host_id
        or challenge.key_generation != authentication.key_generation
        or challenge.challenge != authentication.challenge
        or challenge.expires_at <= now
    ):
        raise HostAuthError("Host socket challenge does not match the authentication.")
    host = (
        await db.execute(
            select(Host).where(Host.host_id == authentication.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    key = (
        await db.execute(
            select(HostKeyGeneration)
            .where(
                HostKeyGeneration.host_id == authentication.host_id,
                HostKeyGeneration.generation == authentication.key_generation,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        host is None
        or key is None
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.active_key_generation != authentication.key_generation
        or key.revoked_at is not None
    ):
        raise HostAuthError("Host socket key generation is not active.")
    _verify_ed25519(
        key.ed25519_public_key,
        authentication.signature,
        authentication.signing_bytes(),
    )
    key.last_used_at = now
    await db.commit()
    return host


async def get_current_host(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    host_id_header: Optional[str] = Header(None, alias=HOST_ID_HEADER),
    key_generation_header: Optional[str] = Header(None, alias=HOST_KEY_GENERATION_HEADER),
    challenge_id: Optional[str] = Header(None, alias=HOST_CHALLENGE_ID_HEADER),
    signature: Optional[str] = Header(None, alias=HOST_SIGNATURE_HEADER),
    issued_at_header: Optional[str] = Header(None, alias=HOST_ISSUED_AT_HEADER),
) -> Host:
    """Authenticate one method/path/body-bound request from an active logical host key."""

    if not all(
        [
            host_id_header,
            key_generation_header,
            challenge_id,
            signature,
            issued_at_header,
        ]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Complete logical-host authentication headers are required.",
        )
    try:
        key_generation = int(key_generation_header)
        issued_at = datetime.fromisoformat(issued_at_header.replace("Z", "+00:00"))
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host authentication metadata is malformed.",
        ) from exc
    now = _utcnow()
    if abs((now - issued_at).total_seconds()) > HOST_SIGNATURE_MAX_SKEW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host signature is stale.",
        )
    try:
        raw = await settings.redis_client.getdel(f"host:http-challenge:{challenge_id}")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Logical-host replay protection is unavailable.",
        ) from exc
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host challenge is unknown, expired, or already consumed.",
        )
    try:
        challenge = HostAuthChallengeV1.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host challenge is malformed.",
        ) from exc
    if (
        challenge.host_id != host_id_header
        or challenge.key_generation != key_generation
        or challenge.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host challenge does not match this request.",
        )
    host = (
        await db.execute(select(Host).where(Host.host_id == host_id_header).with_for_update())
    ).scalar_one_or_none()
    key = (
        await db.execute(
            select(HostKeyGeneration)
            .where(
                HostKeyGeneration.host_id == host_id_header,
                HostKeyGeneration.generation == key_generation,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        host is None
        or key is None
        or host.active_key_generation != key_generation
        or host.provisioning_state in {"legacy", "unclaimed", "revoked"}
        or key.revoked_at is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logical-host key generation is not active.",
        )
    envelope = HostSigningEnvelopeV1(
        host_id=host_id_header,
        key_generation=key_generation,
        challenge_id=challenge_id,
        challenge=challenge.challenge,
        method=request.method.upper(),
        target=(
            f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path
        ),
        body_sha256=getattr(request.state, "body_sha256", None) or _EMPTY_SHA256,
        issued_at=issued_at,
    )
    try:
        _verify_ed25519(key.ed25519_public_key, signature, envelope.signing_bytes())
    except HostAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    key.last_used_at = now
    return host


async def get_ready_host(
    current_host: Host = Depends(get_current_host),
) -> Host:
    """Require the enrolled host to have completed every durability gate."""

    if current_host.provisioning_state != "ready" or current_host.identity_durable_at is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Logical host provisioning is not launch-ready.",
        )
    return current_host


def _pcs_window_is_valid(
    issued_at: datetime,
    expires_at: datetime,
    now: datetime,
) -> bool:
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return bool(
        issued_at < expires_at
        and issued_at <= now + timedelta(minutes=5)
        and expires_at > now
        and (expires_at - issued_at).total_seconds() <= PCS_MAILBOX_MAX_LIFETIME_SECONDS
    )


async def store_pcs_mailbox(
    db: AsyncSession,
    owner_hotkey: str,
    envelope: PcsMailboxEnvelopeV1,
) -> None:
    """Validate the complete miner-signed ciphertext envelope and store no plaintext."""

    aad = envelope.aad
    host = (
        await db.execute(select(Host).where(Host.host_id == aad.host_id).with_for_update())
    ).scalar_one_or_none()
    key = await db.get(HostKeyGeneration, (aad.host_id, aad.key_generation))
    now = _utcnow()
    if (
        host is None
        or key is None
        or host.miner_hotkey != owner_hotkey
        or aad.owner_hotkey != owner_hotkey
        or host.enrollment_generation != aad.enrollment_generation
        or host.active_key_generation != aad.key_generation
        or key.revoked_at is not None
        or key.x25519_fingerprint != aad.recipient_fingerprint
        or host.tee_type != "tdx"
        or host.provisioning_state != "awaiting_pcs"
        or host.identity_durable_at is None
        or not _pcs_window_is_valid(aad.issued_at, aad.expires_at, now)
    ):
        raise HostAuthError("PCS mailbox does not match the active enrolled TDX host.")
    try:
        if not Keypair(ss58_address=owner_hotkey).verify(
            envelope.miner_signing_bytes(),
            base64.b64decode(envelope.miner_signature, validate=True),
        ):
            raise ValueError("signature verification failed")
    except Exception as exc:
        raise HostAuthError("PCS mailbox miner signature is invalid.") from exc
    await db.execute(
        update(HostPcsMailbox)
        .where(
            HostPcsMailbox.host_id == host.host_id,
            HostPcsMailbox.consumed_at.is_(None),
            HostPcsMailbox.invalidated_at.is_(None),
            HostPcsMailbox.expires_at <= now,
        )
        .values(invalidated_at=now)
    )
    active = (
        await db.execute(
            select(HostPcsMailbox)
            .where(
                HostPcsMailbox.host_id == host.host_id,
                HostPcsMailbox.consumed_at.is_(None),
                HostPcsMailbox.invalidated_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if active is not None:
        raise HostAuthError("An unconsumed PCS mailbox already exists for this host.")
    row = HostPcsMailbox(
        message_id=aad.message_id,
        host_id=host.host_id,
        owner_hotkey=owner_hotkey,
        enrollment_generation=aad.enrollment_generation,
        key_generation=aad.key_generation,
        recipient_fingerprint=aad.recipient_fingerprint,
        envelope=envelope.model_dump(mode="json"),
        envelope_sha256=canonical_sha256(envelope),
        issued_at=aad.issued_at,
        expires_at=aad.expires_at,
    )
    db.add(row)
    await db.commit()


async def consume_pcs_mailbox(db: AsyncSession, host: Host) -> PcsMailboxEnvelopeV1:
    if host.provisioning_state != "awaiting_pcs" or host.identity_durable_at is None:
        raise HostAuthError("PCS mailbox is unavailable before identity durability.")
    row = (
        await db.execute(
            select(HostPcsMailbox)
            .where(
                HostPcsMailbox.host_id == host.host_id,
                HostPcsMailbox.enrollment_generation == host.enrollment_generation,
                HostPcsMailbox.key_generation == host.active_key_generation,
                HostPcsMailbox.consumed_at.is_(None),
                HostPcsMailbox.invalidated_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if row is None:
        raise HostAuthError("PCS mailbox is unavailable or expired.")
    if not _pcs_window_is_valid(row.issued_at, row.expires_at, now):
        row.invalidated_at = now
        await db.commit()
        raise HostAuthError("PCS mailbox is unavailable or expired.")
    envelope = PcsMailboxEnvelopeV1.model_validate(row.envelope)
    if (
        row.envelope_sha256 != canonical_sha256(envelope)
        or envelope.aad.issued_at != row.issued_at
        or envelope.aad.expires_at != row.expires_at
        or envelope.aad.message_id != row.message_id
        or not _pcs_window_is_valid(
            envelope.aad.issued_at,
            envelope.aad.expires_at,
            now,
        )
    ):
        raise HostAuthError("PCS mailbox storage integrity check failed.")
    row.delivered_at = now
    await db.commit()
    return envelope


async def acknowledge_pcs_mailbox(
    db: AsyncSession, host: Host, acknowledgement: PcsMailboxAckV1
) -> None:
    row = (
        await db.execute(
            select(HostPcsMailbox)
            .where(
                HostPcsMailbox.message_id == acknowledgement.message_id,
                HostPcsMailbox.host_id == host.host_id,
                HostPcsMailbox.enrollment_generation == host.enrollment_generation,
                HostPcsMailbox.key_generation == host.active_key_generation,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if (
        row is not None
        and row.invalidated_at is None
        and row.delivered_at is not None
        and row.consumed_at is not None
        and row.envelope_sha256 == acknowledgement.envelope_sha256
        and host.provisioning_state == "ready"
        and host.identity_durable_at is not None
    ):
        return
    if (
        row is None
        or row.invalidated_at is not None
        or row.delivered_at is None
        or row.envelope_sha256 != acknowledgement.envelope_sha256
        or host.provisioning_state != "awaiting_pcs"
        or host.identity_durable_at is None
    ):
        raise HostAuthError("PCS mailbox acknowledgement does not match its delivery.")
    if not _pcs_window_is_valid(row.issued_at, row.expires_at, now):
        row.invalidated_at = now
        await db.commit()
        raise HostAuthError("PCS mailbox expired before durable acknowledgement.")
    if row.consumed_at is None:
        row.consumed_at = now
    host.provisioning_state = "ready"
    await db.commit()


async def revoke_host_credentials(
    db: AsyncSession, host_id: str, owner_hotkey: str, reason: str
) -> None:
    host = (
        await db.execute(select(Host).where(Host.host_id == host_id).with_for_update())
    ).scalar_one_or_none()
    if host is None or host.miner_hotkey != owner_hotkey:
        raise HostAuthError("Logical host is unknown or owned by another miner.")
    now = _utcnow()
    await db.execute(
        update(HostEnrollmentVoucher)
        .where(
            HostEnrollmentVoucher.host_id == host_id,
            HostEnrollmentVoucher.consumed_at.is_(None),
            HostEnrollmentVoucher.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    await db.execute(
        update(HostKeyGeneration)
        .where(
            HostKeyGeneration.host_id == host_id,
            HostKeyGeneration.revoked_at.is_(None),
        )
        .values(revoked_at=now, revocation_reason=reason[:500])
    )
    await db.execute(
        update(HostPcsMailbox)
        .where(
            HostPcsMailbox.host_id == host_id,
            HostPcsMailbox.consumed_at.is_(None),
            HostPcsMailbox.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    from api.host.schemas import TdLaunchReservation

    await db.execute(
        update(TdLaunchReservation)
        .where(
            TdLaunchReservation.host_id == host_id,
            TdLaunchReservation.consumed_at.is_(None),
            TdLaunchReservation.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    host.provisioning_state = "revoked"
    await db.commit()
    from api.agent_channel import send_agent_command

    try:
        await send_agent_command(host_id, "disconnect", {"reason": "host credential revoked"})
    except Exception as exc:
        logger.warning(
            f"Host {host_id} credential revoked but live-session disconnect dispatch failed: {exc}"
        )
