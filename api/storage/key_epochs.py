"""Administrator-controlled, idempotent ChuteFS token-key epoch transitions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.server.schemas import (
    ChuteFSLaunchSession,
    ChuteFSTokenKeyEpoch,
    ChuteFSTokenKeyEpochOperation,
    ChuteFSTokenKeyReplicaAck,
)
from api.storage.startup import TOKEN_KEY_ACK_MAX_AGE_SECONDS

_KEY_EPOCH_ADVISORY_LOCK = "chutes.chutefs-token-key-epochs.v1"
_OPERATION_SCHEMA = "chutes.chutefs-token-key-epoch-operation.v1"


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
    required_replica_ids: list[str] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": _OPERATION_SCHEMA,
        "operation": operation,
        "request_id": request_id,
        "key_id": key_id,
        "administrator_id": administrator_id,
    }
    if required_replica_ids is not None:
        document["required_replica_ids"] = sorted(required_replica_ids)
    return document


async def _lock_epoch_stream(db: AsyncSession) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:name, 0))"),
        {"name": _KEY_EPOCH_ADVISORY_LOCK},
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
    response = dict(operation.response_json)
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
            required_replica_ids=required_replica_ids,
            response_json=response,
        )
    )


async def stage_token_key_epoch(
    db: AsyncSession,
    *,
    administrator_id: str,
    request_id: str,
    key_id: str,
    required_replica_ids: list[str],
) -> dict[str, Any]:
    """Stage a successor for the exact serving replica cohort."""

    required_replica_ids = sorted(required_replica_ids)
    document = _request_document(
        operation="stage",
        request_id=request_id,
        key_id=key_id,
        administrator_id=administrator_id,
        required_replica_ids=required_replica_ids,
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
    if settings.chutefs_token_replica_id not in required_replica_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The exact serving replica set must include the handling API replica.",
        )
    if any(epoch.key_id == key_id for epoch in epochs):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key ID already has an epoch.",
        )
    epoch = ChuteFSTokenKeyEpoch(
        key_id=key_id,
        predecessor_key_id=active.key_id,
        state="staged",
        required_replica_ids=required_replica_ids,
    )
    db.add(epoch)
    response = {
        "request_id": request_id,
        "operation": "stage",
        "key_id": key_id,
        "predecessor_key_id": active.key_id,
        "state": "staged",
        "active_key_id": active.key_id,
        "required_replica_ids": required_replica_ids,
    }
    _record_operation(
        db,
        request_id=request_id,
        request_sha256=request_sha256,
        operation_type="stage",
        key_id=key_id,
        predecessor_key_id=active.key_id,
        administrator_id=administrator_id,
        required_replica_ids=required_replica_ids,
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
    if (
        target is None
        or target.state != "staged"
        or target.predecessor_key_id != active.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key epoch is not the staged successor of the active key.",
        )
    if key_id not in settings.chutefs_token_keys:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The handling API replica does not hold the staged ChuteFS token key.",
        )

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
    by_replica = {ack.replica_id: ack for ack in acknowledgements}
    required = list(target.required_replica_ids)
    required_acks = [by_replica.get(replica_id) for replica_id in required]
    freshness_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=TOKEN_KEY_ACK_MAX_AGE_SECONDS
    )
    if any(
        ack is None or ack.acknowledged_at < freshness_cutoff
        for ack in required_acks
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Not every required serving replica has a fresh acknowledgement "
                "of the staged ChuteFS key."
            ),
        )
    first = required_acks[0]
    assert first is not None
    for acknowledgement in required_acks:
        assert acknowledgement is not None
        if (
            key_id not in acknowledgement.key_ids
            or active.key_id not in acknowledgement.key_ids
            or acknowledgement.key_ids != first.key_ids
            or acknowledgement.key_fingerprints != first.key_fingerprints
            or acknowledgement.keyring_sha256 != first.keyring_sha256
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Serving replicas have not acknowledged the same complete keyring.",
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
        "required_replica_ids": required,
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
    target = next((epoch for epoch in epochs if epoch.key_id == key_id), None)
    if (
        target is None
        or target.state != "retiring"
        or active.predecessor_key_id != target.key_id
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key is not the retiring predecessor of the active key.",
        )

    now = datetime.now(timezone.utc)
    references = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession.session_id)
                .where(
                    ChuteFSLaunchSession.token_key_id == key_id,
                    (
                        (ChuteFSLaunchSession.access_expires_at > now)
                        | (ChuteFSLaunchSession.refresh_expires_at > now)
                        | (ChuteFSLaunchSession.response_replay_until.is_(None))
                        | (ChuteFSLaunchSession.response_replay_until > now)
                    ),
                )
                .order_by(ChuteFSLaunchSession.session_id)
                .limit(1)
                .with_for_update()
            )
        ).scalars()
    )
    if references:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ChuteFS token key is still referenced by unexpired session authority.",
        )

    target.state = "retired"
    target.retired_at = now
    await db.flush()
    response = {
        "request_id": request_id,
        "operation": "retire",
        "key_id": target.key_id,
        "predecessor_key_id": target.predecessor_key_id,
        "state": "retired",
        "active_key_id": active.key_id,
        "required_replica_ids": [],
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
        response=response,
    )
    await db.commit()
    return response
