"""Fail-closed startup checks for deterministic ChuteFS session replay."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable, Mapping

from sqlalchemy import text

from api.config import settings
from api.database import engine

_KEY_EPOCH_ADVISORY_LOCK = "chutes.chutefs-token-key-epochs.v1"
TOKEN_KEY_ACK_MAX_AGE_SECONDS = 120
_TOKEN_KEY_ACK_REFRESH_SECONDS = 30


def missing_retained_token_keys(
    key_expiries: Iterable[tuple[str, datetime]],
    configured_key_ids: set[str],
    *,
    now: datetime,
) -> list[str]:
    """Return unconfigured keys needed by an unexpired response window."""

    return sorted(
        key_id
        for key_id, refresh_expires_at in key_expiries
        if refresh_expires_at > now and key_id not in configured_key_ids
    )


def token_key_fingerprints(keys: Mapping[str, str]) -> dict[str, str]:
    """Return domain-separated, non-secret fingerprints of configured key bytes."""

    return {
        key_id: hashlib.sha256(
                b"chutes.chutefs-token-key-fingerprint.v1\0"
                + key_id.encode("ascii")
                + b"\0"
                + secret.encode("ascii")
            ).hexdigest()
        for key_id, secret in sorted(keys.items())
    }


def token_keyset_sha256(keys: Mapping[str, str]) -> str:
    """Fingerprint the canonical IDs and actual key bytes without persisting secrets."""

    fingerprints = token_key_fingerprints(keys)
    entries = [
        {"key_id": key_id, "key_sha256": fingerprint}
        for key_id, fingerprint in fingerprints.items()
    ]
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


async def require_chutefs_token_key_retention() -> None:
    """Acknowledge the configured key set and enforce database-active key authority."""

    configured_keys = settings.chutefs_token_keys
    configured_key_ids = sorted(configured_keys)
    replica_id = settings.chutefs_token_replica_id
    keyset_json = json.dumps(configured_key_ids, separators=(",", ":"))
    key_fingerprints = token_key_fingerprints(configured_keys)
    key_fingerprints_json = json.dumps(
        key_fingerprints,
        sort_keys=True,
        separators=(",", ":"),
    )
    keyset_sha256 = token_keyset_sha256(configured_keys)
    now = datetime.now(timezone.utc)
    refresh_before = now.timestamp() - _TOKEN_KEY_ACK_REFRESH_SECONDS

    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:name, 0))"),
            {"name": _KEY_EPOCH_ADVISORY_LOCK},
        )
        epoch_rows = (
            await connection.execute(
                text(
                    "SELECT key_id, state FROM chutefs_token_key_epochs "
                    "ORDER BY created_at, key_id"
                )
            )
        ).all()
        bootstrap = not epoch_rows
        if bootstrap:
            # The first epoch must be staged before its acknowledgement because
            # the acknowledgement has a foreign key to the epoch. Only then may
            # the transition trigger permit staged -> active.
            await connection.execute(
                text(
                    "INSERT INTO chutefs_token_key_epochs "
                    "(key_id, state, required_replica_ids) "
                    "VALUES (:key_id, 'staged', CAST(:replicas AS jsonb))"
                ),
                {
                    "key_id": settings.chutefs_token_key_id,
                    "replicas": json.dumps([replica_id], separators=(",", ":")),
                },
            )
            epoch_rows = [(settings.chutefs_token_key_id, "staged")]

        if not bootstrap:
            active_fingerprints = (
                await connection.execute(
                    text(
                        "SELECT DISTINCT ack.key_fingerprints ->> epoch.key_id "
                        "FROM chutefs_token_key_epochs epoch "
                        "JOIN chutefs_token_key_replica_acks ack "
                        "ON ack.key_id = epoch.key_id "
                        "WHERE epoch.state = 'active' "
                        "AND ack.replica_id IN ("
                        "SELECT jsonb_array_elements_text(epoch.required_replica_ids))"
                    )
                )
            ).scalars().all()
            active_key_ids = [key_id for key_id, state in epoch_rows if state == "active"]
            if (
                len(active_key_ids) != 1
                or len(active_fingerprints) != 1
                or key_fingerprints.get(active_key_ids[0]) != active_fingerprints[0]
            ):
                raise RuntimeError(
                    "ChuteFS token key activation barrier rejected this replica's "
                    "active key fingerprint"
                )

        for key_id, _state in epoch_rows:
            if key_id not in configured_keys:
                continue
            await connection.execute(
                text(
                    "INSERT INTO chutefs_token_key_replica_acks "
                    "(replica_id, key_id, key_ids, key_fingerprints, "
                    "keyring_sha256, acknowledged_at) "
                    "VALUES (:replica_id, :key_id, CAST(:key_ids AS jsonb), "
                    "CAST(:key_fingerprints AS jsonb), "
                    ":keyring_sha256, :acknowledged_at) "
                    "ON CONFLICT (replica_id, key_id) DO UPDATE SET "
                    "key_ids = EXCLUDED.key_ids, "
                    "key_fingerprints = EXCLUDED.key_fingerprints, "
                    "keyring_sha256 = EXCLUDED.keyring_sha256, "
                    "acknowledged_at = EXCLUDED.acknowledged_at "
                    "WHERE chutefs_token_key_replica_acks.key_ids "
                    "IS DISTINCT FROM EXCLUDED.key_ids "
                    "OR chutefs_token_key_replica_acks.key_fingerprints "
                    "IS DISTINCT FROM EXCLUDED.key_fingerprints "
                    "OR chutefs_token_key_replica_acks.keyring_sha256 "
                    "IS DISTINCT FROM EXCLUDED.keyring_sha256 "
                    "OR chutefs_token_key_replica_acks.acknowledged_at "
                    "<= to_timestamp(:refresh_before)"
                ),
                {
                    "replica_id": replica_id,
                    "key_id": key_id,
                    "key_ids": keyset_json,
                    "key_fingerprints": key_fingerprints_json,
                    "keyring_sha256": keyset_sha256,
                    "acknowledged_at": now,
                    "refresh_before": refresh_before,
                },
            )

        if bootstrap:
            await connection.execute(
                text(
                    "UPDATE chutefs_token_key_epochs "
                    "SET state = 'active', activated_at = :activated_at "
                    "WHERE key_id = :key_id AND state = 'staged'"
                ),
                {
                    "key_id": settings.chutefs_token_key_id,
                    "activated_at": now,
                },
            )

        active_rows = (
            await connection.execute(
                text(
                    "SELECT key_id FROM chutefs_token_key_epochs "
                    "WHERE state = 'active' ORDER BY key_id"
                )
            )
        ).scalars().all()
        if len(active_rows) != 1 or active_rows[0] not in configured_keys:
            raise RuntimeError(
                "ChuteFS token key activation barrier requires exactly one "
                "database-active key present in this replica's keyring"
            )

        rows = (
            await connection.execute(
                text(
                    "SELECT token_key_id, "
                    "MAX(GREATEST(refresh_expires_at, "
                    "COALESCE(response_replay_until, refresh_expires_at))) "
                    "FROM chutefs_launch_sessions "
                    "WHERE token_key_id IS NOT NULL "
                    "GROUP BY token_key_id"
                )
            )
        ).all()
    missing = missing_retained_token_keys(
        rows,
        set(configured_keys),
        now=now,
    )
    if missing:
        raise RuntimeError(
            "ChuteFS token key retention barrier failed for active key ids: "
            + ", ".join(missing)
        )
