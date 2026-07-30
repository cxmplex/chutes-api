"""Shared result types for database-backed key-authority refreshes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyAuthorityRefreshResult:
    """Report unavailable persisted-key dependencies without masking ACK success."""

    missing_referenced_key_ids: tuple[str, ...] = ()
