"""Durable validator-created, one-use Model-B TD launch reservations."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import generate_uuid
from api.host.schemas import (
    HostKeyGeneration,
    StorageLaunchIntent,
    TdLaunchReservation,
    TdLaunchReservationClaimsV1,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.releases.schemas import (
    GuestRelease,
    GuestReleaseTarget,
    RELEASE_STATUS_ACTIVE,
)
from api.server.schemas import Host

RESERVATION_LIFETIME_SECONDS = 900


class LaunchReservationError(ValueError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _release_target_digest(
    release: GuestRelease,
    role: str,
    image: dict,
    profile_id: str,
) -> str:
    return canonical_sha256(
        {
            "schema": "chutes.guest-release-target",
            "version": 1,
            "release_id": release.release_id,
            "tee_type": release.tee_type,
            "channel": release.channel,
            "role": role,
            "image_sha256": image["sha256"],
            "image_version": image["version"],
            "profile_id": profile_id,
        }
    )


async def create_launch_reservation(
    db: AsyncSession,
    host: Host,
    *,
    role: str,
    server_id: str,
    process_incarnation: str,
    profile_id: str,
    chute_id: Optional[str] = None,
    job_id: Optional[str] = None,
    container_repository: Optional[str] = None,
    container_manifest_digest: Optional[str] = None,
    storage_intent_id: Optional[str] = None,
    storage_intent_generation: Optional[int] = None,
) -> tuple[TdLaunchReservation, str]:
    """Create and persist one exact reservation before host slot allocation."""

    if (
        host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.active_key_generation is None
        or host.enrollment_generation is None
    ):
        raise LaunchReservationError("Logical host is not launch-ready.")
    key = await db.get(HostKeyGeneration, (host.host_id, host.active_key_generation))
    if key is None or key.revoked_at is not None:
        raise LaunchReservationError("Logical host has no active key generation.")
    if role not in {"chute", "storage"}:
        raise LaunchReservationError("Launch reservation role is invalid.")
    if role == "storage" and (not storage_intent_id or storage_intent_generation is None):
        raise LaunchReservationError(
            "Storage launch reservation requires a validator-owned intent claim."
        )
    if role == "chute" and (storage_intent_id is not None or storage_intent_generation is not None):
        raise LaunchReservationError("Chute reservation cannot carry a storage intent.")
    if (role == "chute") != bool(chute_id) or (
        role == "chute"
        and (
            not container_repository
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                container_manifest_digest or "",
            )
        )
    ):
        raise LaunchReservationError("Launch reservation chute binding is invalid.")
    release = (
        await db.execute(
            select(GuestRelease)
            .where(
                GuestRelease.status == RELEASE_STATUS_ACTIVE,
                GuestRelease.channel == host.release_channel,
                GuestRelease.tee_type == host.tee_type,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if release is None:
        raise LaunchReservationError("Logical host has no active exact guest release.")
    image = (release.images or {}).get(role) or {}
    if (
        not image.get("sha256")
        or not image.get("version")
        or profile_id not in (image.get("measurement_names") or [])
    ):
        raise LaunchReservationError("Launch profile is not part of the active exact release role.")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"td-launch-reservation:{server_id}"},
    )
    prior_rows = (
        (
            await db.execute(
                select(TdLaunchReservation)
                .where(TdLaunchReservation.server_id == server_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    boot_generation = max((int(item.boot_generation) for item in prior_rows), default=0) + 1
    now = _utcnow()
    reservation_id = generate_uuid()
    token_id = generate_uuid()
    launch_nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    release_target_sha256 = _release_target_digest(release, role, image, profile_id)
    claims = TdLaunchReservationClaimsV1(
        reservation_id=reservation_id,
        token_id=token_id,
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        server_id=server_id,
        role=role,
        tee_type=host.tee_type,
        process_incarnation=process_incarnation,
        boot_generation=boot_generation,
        release_id=release.release_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        profile_id=profile_id,
        chute_id=chute_id,
        job_id=job_id,
        container_repository=container_repository,
        container_manifest_digest=container_manifest_digest,
        storage_intent_id=storage_intent_id,
        storage_intent_generation=storage_intent_generation,
        launch_nonce=launch_nonce,
        release_target_sha256=release_target_sha256,
        issued_at=now,
        expires_at=now + timedelta(seconds=RESERVATION_LIFETIME_SECONDS),
    )
    claims_sha256 = canonical_sha256(claims)
    token_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    token = f"{reservation_id}.{token_secret}"
    row = TdLaunchReservation(
        reservation_id=reservation_id,
        token_id=token_id,
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        server_id=server_id,
        role=role,
        compute_type="cpu",
        tee_type=host.tee_type,
        process_incarnation=process_incarnation,
        boot_generation=boot_generation,
        release_id=release.release_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        profile_id=profile_id,
        chute_id=chute_id,
        job_id=job_id,
        container_repository=container_repository,
        container_manifest_digest=container_manifest_digest,
        storage_intent_id=storage_intent_id,
        storage_intent_generation=storage_intent_generation,
        launch_nonce=launch_nonce,
        release_target_sha256=release_target_sha256,
        claims=claims.model_dump(mode="json", exclude_none=True),
        claims_sha256=claims_sha256,
        issued_at=now,
        expires_at=claims.expires_at,
    )
    db.add(row)
    await db.flush()
    return row, token


async def claim_storage_launch_intent(
    db: AsyncSession,
    host: Host,
) -> tuple[TdLaunchReservation, str]:
    """Atomically turn the one eligible validator-owned intent into a reservation."""

    if (
        host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or not host.storage_enabled
        or host.active_key_generation is None
    ):
        raise LaunchReservationError("Logical host is not storage-launch eligible.")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"storage-launch-intent:{host.host_id}"},
    )
    intents = (
        (
            await db.execute(
                select(StorageLaunchIntent)
                .where(
                    StorageLaunchIntent.host_id == host.host_id,
                    StorageLaunchIntent.owner_hotkey == host.miner_hotkey,
                    StorageLaunchIntent.tee_type == host.tee_type,
                    StorageLaunchIntent.channel == host.release_channel,
                    StorageLaunchIntent.state == "active",
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if len(intents) != 1:
        raise LaunchReservationError(
            "Logical host has no unique validator-owned storage launch intent."
        )
    intent = intents[0]
    target = await db.get(GuestReleaseTarget, intent.target_id)
    if (
        target is None
        or target.target_id != intent.target_id
        or target.release_id != intent.release_id
        or target.host_id != host.host_id
        or target.miner_hotkey != host.miner_hotkey
        or target.tee_type != host.tee_type
        or target.role != "storage"
    ):
        raise LaunchReservationError(
            "Storage launch intent no longer matches its immutable target."
        )
    release = (
        await db.execute(
            select(GuestRelease)
            .where(
                GuestRelease.status == RELEASE_STATUS_ACTIVE,
                GuestRelease.channel == host.release_channel,
                GuestRelease.tee_type == host.tee_type,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    image = (release.images or {}).get("storage") if release is not None else None
    if (
        release is None
        or not isinstance(image, dict)
        or image.get("sha256") != intent.image_sha256
        or image.get("version") != intent.image_version
        or intent.profile_id not in (image.get("measurement_names") or [])
        or (not image.get("_inherited") and target.release_id != release.release_id)
    ):
        raise LaunchReservationError(
            "Storage launch intent does not match the active desired storage image."
        )
    await db.execute(
        update(TdLaunchReservation)
        .where(
            TdLaunchReservation.storage_intent_id == intent.intent_id,
            TdLaunchReservation.consumed_at.is_(None),
            TdLaunchReservation.invalidated_at.is_(None),
        )
        .values(invalidated_at=_utcnow())
    )
    claim_generation = int(intent.claim_generation or 0) + 1
    reservation, token = await create_launch_reservation(
        db,
        host,
        role="storage",
        server_id=intent.server_id,
        process_incarnation=intent.process_incarnation,
        profile_id=intent.profile_id,
        storage_intent_id=intent.intent_id,
        storage_intent_generation=claim_generation,
    )
    now = _utcnow()
    intent.claim_generation = claim_generation
    intent.last_claimed_at = now
    reservation.handed_to_host_at = now
    await db.flush()
    return reservation, token


def _parse_token(token: str) -> tuple[str, str]:
    try:
        reservation_id, secret = token.split(".", 1)
        raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    except (TypeError, ValueError) as exc:
        raise LaunchReservationError("Launch reservation is malformed.") from exc
    if not reservation_id or len(raw) != 32:
        raise LaunchReservationError("Launch reservation is malformed.")
    return reservation_id, hashlib.sha256(token.encode("ascii")).hexdigest()


async def resolve_launch_reservation(
    db: AsyncSession,
    token: str,
    commitment: TdQuoteCommitmentV1,
) -> tuple[TdLaunchReservation, TdLaunchReservationClaimsV1]:
    reservation_id, token_hash = _parse_token(token)
    row = (
        await db.execute(
            select(TdLaunchReservation)
            .where(TdLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if (
        row is None
        or not secrets.compare_digest(row.token_hash, token_hash)
        or row.invalidated_at is not None
        or row.consumed_at is not None
        or row.expires_at <= now
    ):
        raise LaunchReservationError(
            "Launch reservation is unknown, expired, invalidated, or consumed."
        )
    claims = TdLaunchReservationClaimsV1.model_validate(row.claims)
    if (
        row.reservation_id != claims.reservation_id
        or row.token_id != claims.token_id
        or row.host_id != claims.host_id
        or row.owner_hotkey != claims.owner_hotkey
        or row.server_id != claims.server_id
        or row.boot_generation != claims.boot_generation
        or row.release_target_sha256 != claims.release_target_sha256
        or row.host_key_generation != claims.host_key_generation
        or row.image_sha256 != claims.image_sha256
        or row.profile_id != claims.profile_id
        or row.chute_id != claims.chute_id
        or row.job_id != claims.job_id
        or row.container_repository != claims.container_repository
        or row.container_manifest_digest != claims.container_manifest_digest
        or row.storage_intent_id != claims.storage_intent_id
        or row.storage_intent_generation != claims.storage_intent_generation
        or row.claims_sha256 != canonical_sha256(claims)
    ):
        raise LaunchReservationError(
            "Launch reservation durable row does not match its canonical claims."
        )
    release = (
        await db.execute(
            select(GuestRelease).where(GuestRelease.release_id == row.release_id).with_for_update()
        )
    ).scalar_one_or_none()
    image = (release.images or {}).get(row.role) if release is not None else None
    if (
        release is None
        or release.status != RELEASE_STATUS_ACTIVE
        or release.tee_type != claims.tee_type
        or not isinstance(image, dict)
        or image.get("sha256") != claims.image_sha256
        or image.get("version") != claims.image_version
        or claims.profile_id not in (image.get("measurement_names") or [])
    ):
        raise LaunchReservationError(
            "Launch reservation no longer names the active exact release target."
        )
    host = await db.get(Host, row.host_id)
    key = await db.get(HostKeyGeneration, (row.host_id, row.host_key_generation))
    if (
        host is None
        or key is None
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.release_channel != release.channel
        or host.active_key_generation != row.host_key_generation
        or key.revoked_at is not None
    ):
        raise LaunchReservationError("Launch reservation host-key generation is no longer active.")
    expected = {
        "reservation_sha256": row.claims_sha256,
        "launch_nonce": claims.launch_nonce,
        "release_target_sha256": claims.release_target_sha256,
        "boot_generation": claims.boot_generation,
    }
    if any(getattr(commitment, name) != value for name, value in expected.items()):
        raise LaunchReservationError("TD quote commitment does not match the launch reservation.")
    return row, claims


def reservation_bound_attestation_nonce(request_nonce: str, commitment: TdQuoteCommitmentV1) -> str:
    try:
        request_nonce_bytes = bytes.fromhex(request_nonce)
    except ValueError as exc:
        raise LaunchReservationError("CPU registration nonce is malformed.") from exc
    return hashlib.sha256(
        request_nonce_bytes + bytes.fromhex(commitment.report_data_nonce())
    ).hexdigest()


def consume_launch_reservation(
    reservation: TdLaunchReservation,
    *,
    attestation_id: str,
    cert_pubkey_hash: str,
) -> None:
    if reservation.consumed_at is not None or reservation.invalidated_at is not None:
        raise LaunchReservationError("Launch reservation is no longer consumable.")
    reservation.consumed_at = _utcnow()
    reservation.consumed_attestation_id = attestation_id
    reservation.consumed_cert_pubkey_hash = cert_pubkey_hash.lower()
