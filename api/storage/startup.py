"""Fail-closed startup checks for deterministic ChuteFS session replay."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import text

from api.config import settings
from api.database import engine


def missing_retained_token_keys(
    key_expiries: Iterable[tuple[str, datetime]],
    configured_key_ids: set[str],
    *,
    now: datetime,
) -> list[str]:
    """Return unconfigured keys still needed by any refresh replay window."""

    return sorted(
        key_id
        for key_id, refresh_expires_at in key_expiries
        if refresh_expires_at > now and key_id not in configured_key_ids
    )


async def require_chutefs_token_key_retention() -> None:
    """Reject API startup when a live session references a removed token key."""

    async with engine.connect() as connection:
        rows = (
            await connection.execute(
                text(
                    "SELECT token_key_id, MAX(refresh_expires_at) "
                    "FROM chutefs_launch_sessions "
                    "WHERE token_key_id IS NOT NULL "
                    "GROUP BY token_key_id"
                )
            )
        ).all()
    missing = missing_retained_token_keys(
        rows,
        set(settings.chutefs_token_keys),
        now=datetime.now(timezone.utc),
    )
    if missing:
        raise RuntimeError(
            "ChuteFS token key retention barrier failed for active key ids: "
            + ", ".join(missing)
        )
