"""Fail-closed startup checks for deterministic ChuteFS session replay."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Iterable, Mapping

from sqlalchemy import text

from api.config import settings
from api.database import engine
from api.key_authority_types import KeyAuthorityRefreshResult

_KEY_EPOCH_ADVISORY_LOCK = "chutes.chutefs-token-key-epochs.v1"
TOKEN_KEY_ACK_MAX_AGE_SECONDS = 120
_TOKEN_KEY_ACK_REFRESH_SECONDS = 30
_VALIDATED_TOKEN_KEY_FINGERPRINTS: dict[str, str] = {}


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


def token_key_material_is_validated(key_id: str, secret: str) -> bool:
    """Return whether configured bytes match the immutable database epoch."""

    expected = _VALIDATED_TOKEN_KEY_FINGERPRINTS.get(key_id)
    actual = token_key_fingerprints({key_id: secret})[key_id]
    return expected is not None and hmac.compare_digest(actual, expected)


def token_keyset_sha256(keys: Mapping[str, str]) -> str:
    """Fingerprint the canonical IDs and actual key bytes without persisting secrets."""

    fingerprints = token_key_fingerprints(keys)
    entries = [
        {"key_id": key_id, "key_sha256": fingerprint}
        for key_id, fingerprint in fingerprints.items()
    ]
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


async def require_chutefs_token_key_retention() -> KeyAuthorityRefreshResult:
    """Acknowledge this replica and report unavailable retained session keys.

    An absent or mismatched database-active key remains fatal. A predecessor
    key that is needed only to reconstruct a persisted session response is a
    readiness degradation instead: requests that need that exact key still fail
    closed in ``launch_sessions._token_key``.
    """

    global _VALIDATED_TOKEN_KEY_FINGERPRINTS

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
                    "SELECT key_id, state, key_sha256 FROM chutefs_token_key_epochs "
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
                    "(key_id, key_sha256, state, required_replica_ids) "
                    "VALUES (:key_id, :key_sha256, 'staged', "
                    "CAST(:replicas AS jsonb))"
                ),
                {
                    "key_id": settings.chutefs_token_key_id,
                    "key_sha256": key_fingerprints[
                        settings.chutefs_token_key_id
                    ],
                    "replicas": json.dumps([replica_id], separators=(",", ":")),
                },
            )
            epoch_rows = [
                (
                    settings.chutefs_token_key_id,
                    "staged",
                    key_fingerprints[settings.chutefs_token_key_id],
                )
            ]

        if not bootstrap:
            active_epochs = [
                (key_id, key_sha256)
                for key_id, state, key_sha256 in epoch_rows
                if state == "active"
            ]
            if (
                len(active_epochs) != 1
                or key_fingerprints.get(active_epochs[0][0])
                != active_epochs[0][1]
            ):
                raise RuntimeError(
                    "ChuteFS token key activation barrier rejected this replica's "
                    "active key fingerprint"
                )

        for key_id, _state, expected_fingerprint in epoch_rows:
            if key_fingerprints.get(key_id) != expected_fingerprint:
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
        epoch_fingerprints = {
            key_id: key_sha256
            for key_id, _state, key_sha256 in epoch_rows
        }

    validated_fingerprints = {
        key_id: expected_fingerprint
        for key_id, expected_fingerprint in epoch_fingerprints.items()
        if key_fingerprints.get(key_id) == expected_fingerprint
    }
    unavailable = missing_retained_token_keys(
        rows,
        set(validated_fingerprints),
        now=now,
    )
    _VALIDATED_TOKEN_KEY_FINGERPRINTS = validated_fingerprints
    return KeyAuthorityRefreshResult(
        missing_referenced_key_ids=tuple(unavailable),
    )
