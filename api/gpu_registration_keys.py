"""Database authority for short-lived GPU Registration V2 recovery keys."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import get_session
from api.gpu_models import (
    GpuRegistrationAttempt,
    GpuRegistrationConflict,
    GpuRegistrationRecoveryKeyEpoch,
    GpuRegistrationRecoveryKeyEpochOperation,
    GpuRegistrationRecoveryKeyReplicaAck,
)
from api.key_authority_types import KeyAuthorityRefreshResult

RECOVERY_KEY_EPOCH_ADVISORY_LOCK = "chutes.gpu-registration-recovery-key-epochs.v1"
RECOVERY_KEY_ACK_MAX_AGE_SECONDS = 120
_RECOVERY_KEY_ACK_REFRESH_SECONDS = 30
_RECOVERY_KEY_RETRY_AFTER_SECONDS = 5
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_REPLICA_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_EPOCH_OPERATION_SCHEMA = "chutes.gpu-registration-recovery-key-epoch-operation.v1"


class GpuRegistrationRecoveryKeyUnavailable(HTTPException):
    """The durable request exists but this replica cannot decrypt it safely."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
            headers={"Retry-After": str(_RECOVERY_KEY_RETRY_AFTER_SECONDS)},
        )


def registration_recovery_key_fingerprints(
    keys: Mapping[str, str],
) -> dict[str, str]:
    """Return purpose-separated non-secret fingerprints of configured keys."""

    return {
        key_id: hashlib.sha256(
            b"chutes.gpu-registration-recovery-key-fingerprint.v1\0"
            + key_id.encode("ascii")
            + b"\0"
            + material.encode("ascii")
        ).hexdigest()
        for key_id, material in sorted(keys.items())
    }


def registration_recovery_keyset_sha256(keys: Mapping[str, str]) -> str:
    """Fingerprint the complete configured key set without storing key material."""

    fingerprints = registration_recovery_key_fingerprints(keys)
    payload = json.dumps(
        [
            {"key_id": key_id, "key_sha256": fingerprint}
            for key_id, fingerprint in fingerprints.items()
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _operation_request(
    *,
    operation: str,
    request_id: str,
    key_id: str,
    administrator_id: str,
    required_replica_ids: list[str] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": _EPOCH_OPERATION_SCHEMA,
        "operation": operation,
        "request_id": request_id,
        "key_id": key_id,
        "administrator_id": administrator_id,
    }
    if required_replica_ids is not None:
        document["required_replica_ids"] = sorted(required_replica_ids)
    if reason is not None:
        document["reason"] = reason
    return document


async def _replay_operation(
    db: AsyncSession,
    *,
    request_id: str,
    request_sha256: str,
) -> dict[str, Any] | None:
    operation = (
        await db.execute(
            select(GpuRegistrationRecoveryKeyEpochOperation)
            .where(GpuRegistrationRecoveryKeyEpochOperation.request_id == request_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if operation is None:
        return None
    if operation.request_sha256 != request_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "GPU registration recovery-key request ID is already bound to "
                "different input."
            ),
        )
    response = dict(operation.response_json)
    if operation.response_sha256 != _canonical_sha256(response):
        raise GpuRegistrationRecoveryKeyUnavailable(
            "GPU registration recovery-key operation response audit is invalid."
        )
    await db.commit()
    return response


def _record_operation(
    db: AsyncSession,
    *,
    request_id: str,
    request_sha256: str,
    operation_type: str,
    key_id: str,
    predecessor_key_id: str | None,
    administrator_id: str,
    required_replica_ids: list[str] | None,
    reason: str | None,
    response: dict[str, Any],
) -> None:
    db.add(
        GpuRegistrationRecoveryKeyEpochOperation(
            request_id=request_id,
            request_sha256=request_sha256,
            operation_type=operation_type,
            key_id=key_id,
            predecessor_key_id=predecessor_key_id,
            requested_by_user_id=administrator_id,
            required_replica_ids=required_replica_ids,
            reason=reason,
            response_json=response,
            response_sha256=_canonical_sha256(response),
        )
    )


async def _lock_epoch_stream(db: AsyncSession) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:name, 0))"),
        {"name": RECOVERY_KEY_EPOCH_ADVISORY_LOCK},
    )


async def _lock_epoch_stream_shared(db: AsyncSession) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:name, 0))"),
        {"name": RECOVERY_KEY_EPOCH_ADVISORY_LOCK},
    )


async def _locked_epochs(
    db: AsyncSession,
) -> list[GpuRegistrationRecoveryKeyEpoch]:
    return list(
        (
            await db.execute(
                select(GpuRegistrationRecoveryKeyEpoch)
                .order_by(
                    GpuRegistrationRecoveryKeyEpoch.created_at,
                    GpuRegistrationRecoveryKeyEpoch.key_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )


def _active_epoch(
    epochs: list[GpuRegistrationRecoveryKeyEpoch],
) -> GpuRegistrationRecoveryKeyEpoch:
    active = [epoch for epoch in epochs if epoch.state == "active"]
    if len(active) != 1:
        raise GpuRegistrationRecoveryKeyUnavailable(
            "GPU registration recovery-key authority does not have exactly one "
            "active epoch."
        )
    return active[0]


def _configured_keyring() -> tuple[
    dict[str, str], dict[str, Fernet], dict[str, str], str, str
]:
    materials = settings.gpu_registration_recovery_key_materials
    ciphers = settings.gpu_registration_recovery_keys
    fingerprints = registration_recovery_key_fingerprints(materials)
    return (
        materials,
        ciphers,
        fingerprints,
        registration_recovery_keyset_sha256(materials),
        settings.gpu_registration_recovery_replica_id,
    )


async def _acknowledge_configured_epochs(
    db: AsyncSession,
    *,
    epochs: list[GpuRegistrationRecoveryKeyEpoch],
    configured_key_ids: list[str],
    fingerprints: dict[str, str],
    keyring_sha256: str,
    replica_id: str,
    now: datetime,
) -> None:
    refresh_before = now - timedelta(seconds=_RECOVERY_KEY_ACK_REFRESH_SECONDS)
    acknowledgeable_key_ids = sorted(
        epoch.key_id
        for epoch in epochs
        if epoch.state in {"staged", "active", "retiring"}
        and fingerprints.get(epoch.key_id) == epoch.key_sha256
    )
    stale_acknowledgements = list(
        (
            await db.execute(
                select(GpuRegistrationRecoveryKeyReplicaAck)
                .where(
                    GpuRegistrationRecoveryKeyReplicaAck.replica_id == replica_id,
                    GpuRegistrationRecoveryKeyReplicaAck.key_id.not_in(
                        acknowledgeable_key_ids
                    ),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for acknowledgement in stale_acknowledgements:
        await db.delete(acknowledgement)
    for epoch in epochs:
        if epoch.key_id not in acknowledgeable_key_ids:
            continue
        acknowledgement = (
            await db.execute(
                select(GpuRegistrationRecoveryKeyReplicaAck)
                .where(
                    GpuRegistrationRecoveryKeyReplicaAck.replica_id == replica_id,
                    GpuRegistrationRecoveryKeyReplicaAck.key_id == epoch.key_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if acknowledgement is None:
            db.add(
                GpuRegistrationRecoveryKeyReplicaAck(
                    replica_id=replica_id,
                    key_id=epoch.key_id,
                    key_ids=configured_key_ids,
                    key_fingerprints=fingerprints,
                    keyring_sha256=keyring_sha256,
                    acknowledged_at=now,
                )
            )
        elif (
            acknowledgement.key_ids != configured_key_ids
            or acknowledgement.key_fingerprints != fingerprints
            or acknowledgement.keyring_sha256 != keyring_sha256
            or acknowledgement.acknowledged_at <= refresh_before
        ):
            acknowledgement.key_ids = configured_key_ids
            acknowledgement.key_fingerprints = fingerprints
            acknowledgement.keyring_sha256 = keyring_sha256
            acknowledgement.acknowledged_at = now
    await db.flush()


async def _nonterminal_key_references(db: AsyncSession) -> set[str]:
    attempt_ids = (
        await db.execute(
            select(GpuRegistrationAttempt.request_payload_key_id).where(
                GpuRegistrationAttempt.state == "processing",
                GpuRegistrationAttempt.request_payload_key_id.is_not(None),
            )
        )
    ).scalars()
    conflict_ids = (
        await db.execute(
            select(GpuRegistrationConflict.request_payload_key_id).where(
                GpuRegistrationConflict.state.in_(("recorded", "verifying")),
                GpuRegistrationConflict.request_payload_key_id.is_not(None),
            )
        )
    ).scalars()
    return {key_id for key_id in (*attempt_ids.all(), *conflict_ids.all()) if key_id}


async def _ensure_authority_locked(
    db: AsyncSession,
) -> tuple[GpuRegistrationRecoveryKeyEpoch, Fernet]:
    (
        materials,
        ciphers,
        fingerprints,
        keyring_sha256,
        replica_id,
    ) = _configured_keyring()
    now = datetime.now(timezone.utc)
    epochs = await _locked_epochs(db)
    if not epochs:
        key_id = settings.gpu_registration_recovery_key_id
        epoch = GpuRegistrationRecoveryKeyEpoch(
            key_id=key_id,
            key_sha256=fingerprints[key_id],
            predecessor_key_id=None,
            state="staged",
            required_replica_ids=[replica_id],
            created_at=now,
        )
        db.add(epoch)
        await db.flush()
        epochs = [epoch]
        await _acknowledge_configured_epochs(
            db,
            epochs=epochs,
            configured_key_ids=sorted(materials),
            fingerprints=fingerprints,
            keyring_sha256=keyring_sha256,
            replica_id=replica_id,
            now=now,
        )
        epoch.state = "active"
        epoch.activated_at = now
        await db.flush()

    active = _active_epoch(epochs)
    for epoch in epochs:
        configured_fingerprint = fingerprints.get(epoch.key_id)
        if (
            epoch.state in {"staged", "active"}
            and configured_fingerprint is not None
            and configured_fingerprint != epoch.key_sha256
        ):
            raise GpuRegistrationRecoveryKeyUnavailable(
                f"GPU registration recovery key {epoch.key_id!r} does not match "
                "its database fingerprint."
            )
        if epoch.state == "active" and configured_fingerprint is None:
            raise GpuRegistrationRecoveryKeyUnavailable(
                f"Database-active GPU registration recovery key {epoch.key_id!r} "
                "is absent from this replica."
            )
    await _acknowledge_configured_epochs(
        db,
        epochs=epochs,
        configured_key_ids=sorted(materials),
        fingerprints=fingerprints,
        keyring_sha256=keyring_sha256,
        replica_id=replica_id,
        now=now,
    )
    return active, ciphers[active.key_id]


async def lock_active_registration_recovery_key(
    db: AsyncSession,
) -> tuple[str, Fernet]:
    """Lock and return the database-active encryption key in the caller transaction."""

    await _lock_epoch_stream_shared(db)
    active = (
        (
            await db.execute(
                select(GpuRegistrationRecoveryKeyEpoch)
                .where(GpuRegistrationRecoveryKeyEpoch.state == "active")
                .with_for_update(read=True)
            )
        )
        .scalars()
        .all()
    )
    if len(active) != 1:
        raise GpuRegistrationRecoveryKeyUnavailable(
            "GPU registration recovery-key authority is not initialized."
        )
    epoch = active[0]
    materials = settings.gpu_registration_recovery_key_materials
    fingerprint = registration_recovery_key_fingerprints(materials).get(epoch.key_id)
    cipher = settings.gpu_registration_recovery_keys.get(epoch.key_id)
    if fingerprint != epoch.key_sha256 or cipher is None:
        raise GpuRegistrationRecoveryKeyUnavailable(
            f"Database-active GPU registration recovery key {epoch.key_id!r} is "
            "missing or does not match this replica."
        )
    return epoch.key_id, cipher


async def load_registration_recovery_cipher(
    db: AsyncSession,
    key_id: str,
) -> Fernet:
    """Validate persisted-key identity before decrypting durable request bytes."""

    epoch = await db.get(GpuRegistrationRecoveryKeyEpoch, key_id)
    try:
        materials = settings.gpu_registration_recovery_key_materials
        ciphers = settings.gpu_registration_recovery_keys
    except ValueError as exc:
        raise GpuRegistrationRecoveryKeyUnavailable(
            "GPU registration recovery-key configuration is unavailable."
        ) from exc
    fingerprint = registration_recovery_key_fingerprints(materials).get(key_id)
    cipher = ciphers.get(key_id)
    if (
        epoch is None
        or epoch.state not in {"active", "retiring"}
        or fingerprint != epoch.key_sha256
        or cipher is None
    ):
        raise GpuRegistrationRecoveryKeyUnavailable(
            f"Persisted GPU registration recovery key {key_id!r} is missing, "
            "retired, or does not match its database fingerprint."
        )
    return cipher


async def ensure_gpu_registration_recovery_key_authority(
    db: AsyncSession,
) -> tuple[str, Fernet]:
    """Bootstrap/ACK the key authority under its exclusive transaction lock."""

    await _lock_epoch_stream(db)
    active, cipher = await _ensure_authority_locked(db)
    return active.key_id, cipher


async def gpu_registration_recovery_key_retention_status(
    db: AsyncSession,
) -> KeyAuthorityRefreshResult:
    """Refresh authority state and classify unavailable persisted dependencies."""

    await ensure_gpu_registration_recovery_key_authority(db)
    epochs = await _locked_epochs(db)
    epochs_by_id = {epoch.key_id: epoch for epoch in epochs}
    references = await _nonterminal_key_references(db)
    materials = settings.gpu_registration_recovery_key_materials
    ciphers = settings.gpu_registration_recovery_keys
    fingerprints = registration_recovery_key_fingerprints(materials)
    missing = sorted(
        key_id
        for key_id in references
        if key_id not in ciphers
        or key_id not in epochs_by_id
        or epochs_by_id[key_id].state not in {"active", "retiring"}
        or fingerprints.get(key_id) != epochs_by_id[key_id].key_sha256
    )
    return KeyAuthorityRefreshResult(
        missing_referenced_key_ids=tuple(missing),
    )


async def require_gpu_registration_recovery_key_retention() -> KeyAuthorityRefreshResult:
    """Acknowledge this replica and report unavailable retained request keys.

    Active/staged authority corruption remains fatal. A missing predecessor
    used by a nonterminal attempt or conflict degrades readiness while the
    operation-specific decrypt path continues to fail closed with Retry-After.
    """

    async with get_session() as db:
        return await gpu_registration_recovery_key_retention_status(db)


async def stage_gpu_registration_recovery_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
    required_replica_ids: list[str],
) -> dict[str, Any]:
    """Stage a fingerprint-bound successor for an exact serving replica cohort."""

    required = sorted(set(required_replica_ids))
    if (
        _KEY_ID_PATTERN.fullmatch(key_id) is None
        or not required
        or any(_REPLICA_ID_PATTERN.fullmatch(item) is None for item in required)
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="GPU registration recovery-key stage input is malformed.",
        )
    request_document = _operation_request(
        operation="stage",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
        required_replica_ids=required,
    )
    request_sha256 = _canonical_sha256(request_document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay
    active, _ = await _ensure_authority_locked(db)
    materials, _, fingerprints, keyring_sha256, replica_id = _configured_keyring()
    if key_id not in materials:
        raise GpuRegistrationRecoveryKeyUnavailable(
            "The handling replica does not hold the proposed GPU registration "
            "recovery key."
        )
    if replica_id not in required:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The required replica set must include the handling API replica.",
        )
    existing = await db.get(GpuRegistrationRecoveryKeyEpoch, key_id)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU registration recovery key ID already has an epoch.",
        )
    existing_successor = (
        await db.execute(
            select(GpuRegistrationRecoveryKeyEpoch.key_id)
            .where(
                GpuRegistrationRecoveryKeyEpoch.predecessor_key_id == active.key_id,
                GpuRegistrationRecoveryKeyEpoch.state == "staged",
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing_successor is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Active GPU registration recovery key already has staged successor "
                f"{existing_successor!r}; cancel that exact epoch before staging a replacement."
            ),
        )
    epoch = GpuRegistrationRecoveryKeyEpoch(
        key_id=key_id,
        key_sha256=fingerprints[key_id],
        predecessor_key_id=active.key_id,
        state="staged",
        required_replica_ids=required,
    )
    db.add(epoch)
    await db.flush()
    await _acknowledge_configured_epochs(
        db,
        epochs=[epoch],
        configured_key_ids=sorted(materials),
        fingerprints=fingerprints,
        keyring_sha256=keyring_sha256,
        replica_id=replica_id,
        now=datetime.now(timezone.utc),
    )
    response = {
        "request_id": request_id,
        "operation": "stage",
        "key_id": epoch.key_id,
        "predecessor_key_id": active.key_id,
        "state": "staged",
        "active_key_id": active.key_id,
        "required_replica_ids": required,
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="stage",
        key_id=epoch.key_id,
        predecessor_key_id=active.key_id,
        administrator_id=administrator_id,
        required_replica_ids=required,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def activate_gpu_registration_recovery_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Activate only after every required replica ACKs one identical key set."""

    request_document = _operation_request(
        operation="activate",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
    )
    request_sha256 = _canonical_sha256(request_document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay
    active, _ = await _ensure_authority_locked(db)
    target = (
        await db.execute(
            select(GpuRegistrationRecoveryKeyEpoch)
            .where(GpuRegistrationRecoveryKeyEpoch.key_id == key_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        target is None
        or target.state != "staged"
        or target.predecessor_key_id != active.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU registration recovery key is not the active key's staged successor.",
        )
    configured_fingerprints = registration_recovery_key_fingerprints(
        settings.gpu_registration_recovery_key_materials
    )
    if configured_fingerprints.get(target.key_id) != target.key_sha256:
        raise GpuRegistrationRecoveryKeyUnavailable(
            "The handling replica does not hold the exact staged GPU registration "
            "recovery key."
        )
    acknowledgements = list(
        (
            await db.execute(
                select(GpuRegistrationRecoveryKeyReplicaAck)
                .where(GpuRegistrationRecoveryKeyReplicaAck.key_id == target.key_id)
                .order_by(GpuRegistrationRecoveryKeyReplicaAck.replica_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    by_replica = {ack.replica_id: ack for ack in acknowledgements}
    required_acks = [by_replica.get(item) for item in target.required_replica_ids]
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=RECOVERY_KEY_ACK_MAX_AGE_SECONDS
    )
    if any(ack is None or ack.acknowledged_at < cutoff for ack in required_acks):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Not every required replica has a fresh recovery-key acknowledgement.",
        )
    first = required_acks[0]
    assert first is not None
    for acknowledgement in required_acks:
        assert acknowledgement is not None
        if (
            target.key_id not in acknowledgement.key_ids
            or active.key_id not in acknowledgement.key_ids
            or acknowledgement.key_ids != first.key_ids
            or acknowledgement.key_fingerprints != first.key_fingerprints
            or acknowledgement.keyring_sha256 != first.keyring_sha256
            or acknowledgement.key_fingerprints.get(target.key_id) != target.key_sha256
            or acknowledgement.key_fingerprints.get(active.key_id) != active.key_sha256
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Serving replicas did not acknowledge one identical recovery keyring.",
            )
    now = datetime.now(timezone.utc)
    active.state = "retiring"
    active.retiring_at = now
    await db.flush()
    target.state = "active"
    target.activated_at = now
    await db.flush()
    response = {
        "request_id": request_id,
        "operation": "activate",
        "key_id": target.key_id,
        "predecessor_key_id": active.key_id,
        "state": "active",
        "active_key_id": target.key_id,
        "required_replica_ids": list(target.required_replica_ids),
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="activate",
        key_id=target.key_id,
        predecessor_key_id=active.key_id,
        administrator_id=administrator_id,
        required_replica_ids=None,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def retire_gpu_registration_recovery_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Retire an old key only after no recoverable request references it."""

    request_document = _operation_request(
        operation="retire",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
    )
    request_sha256 = _canonical_sha256(request_document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay
    active, _ = await _ensure_authority_locked(db)
    target = (
        await db.execute(
            select(GpuRegistrationRecoveryKeyEpoch)
            .where(GpuRegistrationRecoveryKeyEpoch.key_id == key_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        target is None
        or target.state != "retiring"
        or active.predecessor_key_id != target.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU registration recovery key is not the retiring predecessor.",
        )
    referenced_attempt = (
        await db.execute(
            select(GpuRegistrationAttempt.attempt_id)
            .where(
                GpuRegistrationAttempt.state == "processing",
                GpuRegistrationAttempt.request_payload_key_id == key_id,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    referenced_conflict = (
        await db.execute(
            select(GpuRegistrationConflict.conflict_id)
            .where(
                GpuRegistrationConflict.state.in_(("recorded", "verifying")),
                GpuRegistrationConflict.request_payload_key_id == key_id,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if referenced_attempt is not None or referenced_conflict is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU registration recovery key still has a nonterminal reference.",
        )
    target.state = "retired"
    target.retired_at = datetime.now(timezone.utc)
    await db.flush()
    response = {
        "request_id": request_id,
        "operation": "retire",
        "key_id": target.key_id,
        "predecessor_key_id": target.predecessor_key_id,
        "state": "retired",
        "active_key_id": active.key_id,
        "required_replica_ids": list(target.required_replica_ids),
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="retire",
        key_id=target.key_id,
        predecessor_key_id=target.predecessor_key_id,
        administrator_id=administrator_id,
        required_replica_ids=None,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def cancel_gpu_registration_recovery_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
    reason: str,
) -> dict[str, Any]:
    """Terminally cancel one exact staged successor before replacing it."""

    reason = reason.strip()
    if not reason or len(reason) > 2000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="GPU registration recovery-key cancellation reason is malformed.",
        )
    request_document = _operation_request(
        operation="cancel",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
        reason=reason,
    )
    request_sha256 = _canonical_sha256(request_document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay
    active, _ = await _ensure_authority_locked(db)
    target = (
        await db.execute(
            select(GpuRegistrationRecoveryKeyEpoch)
            .where(GpuRegistrationRecoveryKeyEpoch.key_id == key_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        target is None
        or target.state != "staged"
        or target.predecessor_key_id != active.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU registration recovery key is not the active key's staged successor.",
        )
    acknowledgements = list(
        (
            await db.execute(
                select(GpuRegistrationRecoveryKeyReplicaAck)
                .where(GpuRegistrationRecoveryKeyReplicaAck.key_id == target.key_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for acknowledgement in acknowledgements:
        await db.delete(acknowledgement)
    await db.flush()
    target.state = "cancelled"
    target.cancelled_at = datetime.now(timezone.utc)
    await db.flush()
    response = {
        "request_id": request_id,
        "operation": "cancel",
        "key_id": target.key_id,
        "predecessor_key_id": target.predecessor_key_id,
        "state": "cancelled",
        "active_key_id": active.key_id,
        "required_replica_ids": list(target.required_replica_ids),
        "reason": reason,
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="cancel",
        key_id=target.key_id,
        predecessor_key_id=target.predecessor_key_id,
        administrator_id=administrator_id,
        required_replica_ids=None,
        reason=reason,
        response=response,
    )
    await db.commit()
    return response
