"""Process-local health and bounded ACK refresh for database-backed key authorities."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from loguru import logger

from api.gpu_registration_keys import (
    RECOVERY_KEY_ACK_MAX_AGE_SECONDS,
    require_gpu_registration_recovery_key_retention,
)
from api.storage.startup import (
    TOKEN_KEY_ACK_MAX_AGE_SECONDS,
    require_chutefs_token_key_retention,
)

KEY_AUTHORITY_ACK_REFRESH_SECONDS = 30.0


@dataclass
class _AuthorityState:
    max_age_seconds: int
    initialized: bool = False
    last_success_monotonic: float | None = None
    last_error: str | None = None


_AUTHORITY_STATES = {
    "chutefs_token": _AuthorityState(TOKEN_KEY_ACK_MAX_AGE_SECONDS),
    "gpu_registration_recovery": _AuthorityState(RECOVERY_KEY_ACK_MAX_AGE_SECONDS),
}
_AUTHORITY_REFRESHERS: tuple[tuple[str, Callable[[], Awaitable[None]]], ...] = (
    ("chutefs_token", require_chutefs_token_key_retention),
    (
        "gpu_registration_recovery",
        require_gpu_registration_recovery_key_retention,
    ),
)


def _mark_success(authority: str) -> None:
    state = _AUTHORITY_STATES[authority]
    state.initialized = True
    state.last_success_monotonic = time.monotonic()
    state.last_error = None


def _mark_failure(authority: str, exc: Exception) -> None:
    state = _AUTHORITY_STATES[authority]
    state.last_error = f"{type(exc).__name__}: {exc}"


async def initialize_key_authorities() -> None:
    """Synchronously initialize both authorities before the process serves traffic."""

    first_error: Exception | None = None
    for authority, refresh in _AUTHORITY_REFRESHERS:
        try:
            await refresh()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _mark_failure(authority, exc)
            logger.exception(f"Failed to initialize {authority} key authority")
            if first_error is None:
                first_error = exc
        else:
            _mark_success(authority)
    if first_error is not None:
        raise first_error


async def refresh_key_authority_acks_once() -> None:
    """Refresh each authority independently so one failure cannot starve the other."""

    for authority, refresh in _AUTHORITY_REFRESHERS:
        try:
            await refresh()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _mark_failure(authority, exc)
            logger.exception(f"Failed to refresh {authority} key-authority ACK")
        else:
            _mark_success(authority)


async def key_authority_ack_refresh_loop(
    interval_seconds: float = KEY_AUTHORITY_ACK_REFRESH_SECONDS,
) -> None:
    """Rate-limit the database-backed ACK path to a single background loop."""

    if interval_seconds <= 0:
        raise ValueError("Key-authority ACK refresh interval must be positive.")
    while True:
        await asyncio.sleep(interval_seconds)
        await refresh_key_authority_acks_once()


def key_authority_health() -> dict[str, dict[str, object]]:
    """Return a read-only snapshot; this function never acquires a lock or writes."""

    now = time.monotonic()
    health: dict[str, dict[str, object]] = {}
    for authority, state in _AUTHORITY_STATES.items():
        age = (
            max(0.0, now - state.last_success_monotonic)
            if state.last_success_monotonic is not None
            else None
        )
        stale = age is not None and age > state.max_age_seconds
        ready = bool(
            state.initialized
            and state.last_error is None
            and age is not None
            and not stale
        )
        if ready:
            status = "ready"
            error = None
        elif not state.initialized:
            status = "uninitialized"
            error = state.last_error or "Key authority has not been initialized."
        elif stale:
            status = "stale"
            error = (
                f"Last successful key-authority ACK is older than "
                f"{state.max_age_seconds} seconds."
            )
        else:
            status = "degraded"
            error = state.last_error
        health[authority] = {
            "ready": ready,
            "status": status,
            "ack_age_seconds": age,
            "max_ack_age_seconds": state.max_age_seconds,
            "last_error": error,
        }
    return health


def key_authorities_ready(health: dict[str, dict[str, object]]) -> bool:
    """Require the complete fixed authority set to be locally healthy."""

    return set(health) == set(_AUTHORITY_STATES) and all(
        entry.get("ready") is True for entry in health.values()
    )
