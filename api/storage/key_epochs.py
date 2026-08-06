"""Administrator-controlled, idempotent ChuteFS token-key epoch transitions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.server.schemas import (
    ChuteFSLaunchSession,
    ChuteFSTokenKeyEpoch,
    ChuteFSTokenKeyEpochOperation,
    ChuteFSTokenKeyReplicaAck,
)
from api.storage.startup import (
    TOKEN_KEY_ACK_MAX_AGE_SECONDS,
    token_key_fingerprints,
)

TOKEN_KEY_EPOCH_ADVISORY_LOCK = "chutes.chutefs-token-key-epochs.v1"
_OPERATION_SCHEMA = "chutes.chutefs-token-key-epoch-operation.v1"
TOKEN_KEY_OPERATION_REPLAY_SECONDS = 24 * 60 * 60


def _canonical_sha256(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _request_document(
    *,
    operation: str,
    request_id: str,
    key_id: str,
    administrator_id: str,
    cohort_id: str | None = None,
    required_ack_count: int | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": _OPERATION_SCHEMA,
        "operation": operation,
        "request_id": request_id,
        "key_id": key_id,
        "administrator_id": administrator_id,
    }
    if cohort_id is not None:
        document["cohort_id"] = cohort_id
    if required_ack_count is not None:
        document["required_ack_count"] = required_ack_count
    if reason is not None:
        document["reason"] = reason
    return document


async def _lock_epoch_stream(db: AsyncSession) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:name, 0))"),
        {"name": TOKEN_KEY_EPOCH_ADVISORY_LOCK},
    )


async def lock_token_key_epoch_for_session(db: AsyncSession) -> None:
    """Fence one session transaction against activation and retirement."""

    await db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:name, 0))"),
        {"name": TOKEN_KEY_EPOCH_ADVISORY_LOCK},
    )


async def _replay_operation(
    db: AsyncSession,
    *,
    request_id: str,
    request_sha256: str,
) -> dict[str, Any] | None:
    operation = (
        await db.execute(
            select(ChuteFSTokenKeyEpochOperation)
            .where(ChuteFSTokenKeyEpochOperation.request_id == request_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if operation is None:
        return None
    if operation.request_sha256 != request_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key request ID is already bound to different input.",
        )
    if operation.replay_expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key operation replay window expired; use a new request ID.",
        )
    response = dict(operation.response_json)
    if operation.response_sha256 != _canonical_sha256(response):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ChuteFS token key operation replay audit is inconsistent.",
        )
    await db.commit()
    return response


async def _locked_epochs(db: AsyncSession) -> list[ChuteFSTokenKeyEpoch]:
    return list(
        (
            await db.execute(
                select(ChuteFSTokenKeyEpoch)
                .order_by(
                    ChuteFSTokenKeyEpoch.created_at,
                    ChuteFSTokenKeyEpoch.key_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )


def _active_epoch(epochs: list[ChuteFSTokenKeyEpoch]) -> ChuteFSTokenKeyEpoch:
    active = [epoch for epoch in epochs if epoch.state == "active"]
    if len(active) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key authority does not have exactly one active epoch.",
        )
    return active[0]


async def _prune_departed_replica_acks(db: AsyncSession, *, now: datetime) -> None:
    """Bound ACK history after replicas have departed a stable rollout cohort."""

    await db.execute(
        delete(ChuteFSTokenKeyReplicaAck).where(
            ChuteFSTokenKeyReplicaAck.acknowledged_at
            < now - timedelta(seconds=5 * TOKEN_KEY_ACK_MAX_AGE_SECONDS)
        )
    )


def _record_operation(
    db: AsyncSession,
    *,
    request_id: str,
    request_sha256: str,
    operation_type: str,
    key_id: str,
    predecessor_key_id: str | None,
    administrator_id: str,
    cohort_id: str | None,
    required_ack_count: int | None,
    reason: str | None,
    response: dict[str, Any],
) -> None:
    db.add(
        ChuteFSTokenKeyEpochOperation(
            request_id=request_id,
            request_sha256=request_sha256,
            operation_type=operation_type,
            key_id=key_id,
            predecessor_key_id=predecessor_key_id,
            requested_by_user_id=administrator_id,
            cohort_id=cohort_id,
            required_ack_count=required_ack_count,
            reason=reason,
            response_json=response,
            response_sha256=_canonical_sha256(response),
            replay_expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=TOKEN_KEY_OPERATION_REPLAY_SECONDS),
        )
    )


async def stage_token_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
    cohort_id: str | None = None,
    required_ack_count: int | None = None,
) -> dict[str, Any]:
    """Stage a successor for a stable serving cohort and required ACK count."""

    cohort_id = cohort_id or settings.chutefs_token_replica_cohort
    configured_ack_count = settings.chutefs_token_required_ack_count
    if required_ack_count is None:
        required_ack_count = configured_ack_count
    if not 1 <= required_ack_count <= 256:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ChuteFS token key required ACK count is malformed.",
        )
    if required_ack_count != configured_ack_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "ChuteFS token key required ACK count must exactly match the configured "
                "serving-cohort quorum."
            ),
        )
    document = _request_document(
        operation="stage",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
        cohort_id=cohort_id,
        required_ack_count=required_ack_count,
    )
    request_sha256 = _canonical_sha256(document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay

    epochs = await _locked_epochs(db)
    active = _active_epoch(epochs)
    if cohort_id != settings.chutefs_token_replica_cohort:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The handling API replica is not a member of the requested rollout cohort.",
        )
    if any(epoch.key_id == key_id for epoch in epochs):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key ID already has an epoch.",
        )
    staged_successor = next(
        (
            epoch
            for epoch in epochs
            if epoch.predecessor_key_id == active.key_id and epoch.state == "staged"
        ),
        None,
    )
    if staged_successor is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Active ChuteFS token key already has staged successor "
                f"{staged_successor.key_id!r}; cancel it before staging a replacement."
            ),
        )
    configured_fingerprints = token_key_fingerprints(settings.chutefs_token_keys)
    target_fingerprint = configured_fingerprints.get(key_id)
    if (
        target_fingerprint is None
        or configured_fingerprints.get(active.key_id) != active.key_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The handling API replica does not hold the exact ChuteFS "
                "token-key material required to stage this epoch."
            ),
        )
    epoch = ChuteFSTokenKeyEpoch(
        key_id=key_id,
        predecessor_key_id=active.key_id,
        key_sha256=target_fingerprint,
        state="staged",
        cohort_id=cohort_id,
        required_ack_count=required_ack_count,
    )
    db.add(epoch)
    response = {
        "request_id": request_id,
        "operation": "stage",
        "key_id": key_id,
        "predecessor_key_id": active.key_id,
        "state": "staged",
        "active_key_id": active.key_id,
        "cohort_id": cohort_id,
        "required_ack_count": required_ack_count,
        "retired_key_ids": [],
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="stage",
        key_id=key_id,
        predecessor_key_id=active.key_id,
        administrator_id=administrator_id,
        cohort_id=cohort_id,
        required_ack_count=required_ack_count,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def activate_token_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Atomically retire the predecessor and activate a fully acknowledged successor."""

    document = _request_document(
        operation="activate",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
    )
    request_sha256 = _canonical_sha256(document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay

    epochs = await _locked_epochs(db)
    active = _active_epoch(epochs)
    target = next((epoch for epoch in epochs if epoch.key_id == key_id), None)
    if target is None or target.state != "staged" or target.predecessor_key_id != active.key_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key epoch is not the staged successor of the active key.",
        )
    configured_fingerprints = token_key_fingerprints(settings.chutefs_token_keys)
    if (
        configured_fingerprints.get(target.key_id) != target.key_sha256
        or configured_fingerprints.get(active.key_id) != active.key_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The handling API replica does not hold the exact staged and "
                "active ChuteFS token-key material."
            ),
        )

    now = datetime.now(timezone.utc)
    await _prune_departed_replica_acks(db, now=now)
    acknowledgements = list(
        (
            await db.execute(
                select(ChuteFSTokenKeyReplicaAck)
                .where(ChuteFSTokenKeyReplicaAck.key_id == key_id)
                .order_by(ChuteFSTokenKeyReplicaAck.replica_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    freshness_cutoff = now - timedelta(seconds=TOKEN_KEY_ACK_MAX_AGE_SECONDS)
    required_acks = [
        ack
        for ack in acknowledgements
        if ack.cohort_id == target.cohort_id and ack.acknowledged_at >= freshness_cutoff
    ]
    if len(required_acks) < int(target.required_ack_count):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The stable serving cohort does not have the required number of fresh "
                "acknowledgements for the staged ChuteFS key."
            ),
        )
    first = required_acks[0]
    assert first is not None
    for acknowledgement in required_acks:
        assert acknowledgement is not None
        if (
            key_id not in acknowledgement.key_ids
            or active.key_id not in acknowledgement.key_ids
            or acknowledgement.key_fingerprints.get(key_id) != target.key_sha256
            or acknowledgement.key_fingerprints.get(active.key_id) != active.key_sha256
            or acknowledgement.key_ids != first.key_ids
            or acknowledgement.key_fingerprints != first.key_fingerprints
            or acknowledgement.keyring_sha256 != first.keyring_sha256
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Serving replicas have not acknowledged the same complete keyring.",
            )

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
        "cohort_id": target.cohort_id,
        "required_ack_count": target.required_ack_count,
        "retired_key_ids": [],
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="activate",
        key_id=target.key_id,
        predecessor_key_id=active.key_id,
        administrator_id=administrator_id,
        cohort_id=None,
        required_ack_count=None,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def retire_token_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Retire an old key only after every authority/replay reference expires."""

    document = _request_document(
        operation="retire",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
    )
    request_sha256 = _canonical_sha256(document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay

    epochs = await _locked_epochs(db)
    active = _active_epoch(epochs)
    by_key = {epoch.key_id: epoch for epoch in epochs}
    ancestors: list[ChuteFSTokenKeyEpoch] = []
    predecessor_id = active.predecessor_key_id
    while predecessor_id is not None:
        ancestor = by_key.get(predecessor_id)
        if ancestor is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="ChuteFS token key predecessor chain is incomplete.",
            )
        ancestors.append(ancestor)
        predecessor_id = ancestor.predecessor_key_id
    target = by_key.get(key_id)
    if target is None or target.state != "retiring" or target not in ancestors:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key is not a retiring ancestor of the active key.",
        )

    now = datetime.now(timezone.utc)
    retiring_ids = [epoch.key_id for epoch in ancestors if epoch.state == "retiring"]
    referenced_ids = set(
        (
            await db.execute(
                select(ChuteFSLaunchSession.token_key_id)
                .where(
                    ChuteFSLaunchSession.token_key_id.in_(retiring_ids),
                    (
                        (ChuteFSLaunchSession.access_expires_at > now)
                        | (ChuteFSLaunchSession.refresh_expires_at > now)
                        | (ChuteFSLaunchSession.response_replay_until > now)
                    ),
                )
                .order_by(ChuteFSLaunchSession.token_key_id, ChuteFSLaunchSession.session_id)
                .with_for_update()
            )
        ).scalars()
    )
    if target.key_id in referenced_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key is still referenced by unexpired session authority.",
        )

    retired_key_ids: list[str] = []
    for ancestor in reversed(ancestors):
        if ancestor.state == "retiring" and ancestor.key_id not in referenced_ids:
            ancestor.state = "retired"
            ancestor.retired_at = now
            retired_key_ids.append(ancestor.key_id)
    await db.flush()
    response = {
        "request_id": request_id,
        "operation": "retire",
        "key_id": target.key_id,
        "predecessor_key_id": target.predecessor_key_id,
        "state": "retired",
        "active_key_id": active.key_id,
        "cohort_id": target.cohort_id,
        "required_ack_count": target.required_ack_count,
        "retired_key_ids": retired_key_ids,
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="retire",
        key_id=target.key_id,
        predecessor_key_id=target.predecessor_key_id,
        administrator_id=administrator_id,
        cohort_id=None,
        required_ack_count=None,
        reason=None,
        response=response,
    )
    await db.commit()
    return response


async def cancel_token_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
    reason: str,
) -> dict[str, Any]:
    """Terminally cancel one exact staged successor before replacement."""

    reason = reason.strip()
    if not reason or len(reason) > 2000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ChuteFS token key cancellation reason is malformed.",
        )
    document = _request_document(
        operation="cancel",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
        reason=reason,
    )
    request_sha256 = _canonical_sha256(document)
    await _lock_epoch_stream(db)
    replay = await _replay_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
    )
    if replay is not None:
        return replay

    epochs = await _locked_epochs(db)
    active = _active_epoch(epochs)
    target = next((epoch for epoch in epochs if epoch.key_id == key_id), None)
    if target is None or target.state != "staged" or target.predecessor_key_id != active.key_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key is not the active key's staged successor.",
        )
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
        "cohort_id": target.cohort_id,
        "required_ack_count": target.required_ack_count,
        "retired_key_ids": [],
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="cancel",
        key_id=target.key_id,
        predecessor_key_id=target.predecessor_key_id,
        administrator_id=administrator_id,
        cohort_id=None,
        required_ack_count=None,
        reason=reason,
        response=response,
    )
    await db.commit()
    return response
