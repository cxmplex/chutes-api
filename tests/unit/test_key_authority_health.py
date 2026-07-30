from unittest.mock import AsyncMock

import pytest

from api import key_authority_health as authority_health
from api.main import _key_authority_metrics


@pytest.fixture(autouse=True)
def _isolated_authority_state(monkeypatch):
    monkeypatch.setattr(
        authority_health,
        "_AUTHORITY_STATES",
        {
            "chutefs_token": authority_health._AuthorityState(120),
            "gpu_registration_recovery": authority_health._AuthorityState(120),
        },
    )


@pytest.mark.asyncio
async def test_startup_initializes_both_key_authorities(monkeypatch):
    chutefs = AsyncMock()
    gpu_registration = AsyncMock()
    monkeypatch.setattr(
        authority_health,
        "_AUTHORITY_REFRESHERS",
        (
            ("chutefs_token", chutefs),
            ("gpu_registration_recovery", gpu_registration),
        ),
    )
    monkeypatch.setattr(authority_health.time, "monotonic", lambda: 10.0)

    await authority_health.initialize_key_authorities()

    chutefs.assert_awaited_once_with()
    gpu_registration.assert_awaited_once_with()
    health = authority_health.key_authority_health()
    assert authority_health.key_authorities_ready(health)
    assert {entry["status"] for entry in health.values()} == {"ready"}


@pytest.mark.asyncio
async def test_startup_attempts_both_authorities_then_fails_closed(monkeypatch):
    chutefs = AsyncMock(side_effect=RuntimeError("token authority unavailable"))
    gpu_registration = AsyncMock()
    monkeypatch.setattr(
        authority_health,
        "_AUTHORITY_REFRESHERS",
        (
            ("chutefs_token", chutefs),
            ("gpu_registration_recovery", gpu_registration),
        ),
    )

    with pytest.raises(RuntimeError, match="token authority unavailable"):
        await authority_health.initialize_key_authorities()

    chutefs.assert_awaited_once_with()
    gpu_registration.assert_awaited_once_with()
    health = authority_health.key_authority_health()
    assert health["chutefs_token"]["ready"] is False
    assert health["gpu_registration_recovery"]["ready"] is True


@pytest.mark.asyncio
async def test_background_refresh_failure_isolated_and_fails_health_closed(monkeypatch):
    chutefs = AsyncMock(side_effect=RuntimeError("token authority unavailable"))
    gpu_registration = AsyncMock()
    monkeypatch.setattr(
        authority_health,
        "_AUTHORITY_REFRESHERS",
        (
            ("chutefs_token", chutefs),
            ("gpu_registration_recovery", gpu_registration),
        ),
    )

    await authority_health.refresh_key_authority_acks_once()

    chutefs.assert_awaited_once_with()
    gpu_registration.assert_awaited_once_with()
    health = authority_health.key_authority_health()
    assert health["chutefs_token"]["status"] == "uninitialized"
    assert "token authority unavailable" in health["chutefs_token"]["last_error"]
    assert health["gpu_registration_recovery"]["ready"] is True
    assert authority_health.key_authorities_ready(health) is False


def test_read_only_health_expires_when_background_ack_is_stale(monkeypatch):
    state = authority_health._AUTHORITY_STATES["chutefs_token"]
    state.initialized = True
    state.last_success_monotonic = 10.0
    state.max_age_seconds = 30
    other = authority_health._AUTHORITY_STATES["gpu_registration_recovery"]
    other.initialized = True
    other.last_success_monotonic = 39.0
    monkeypatch.setattr(authority_health.time, "monotonic", lambda: 41.0)

    health = authority_health.key_authority_health()

    assert health["chutefs_token"]["ready"] is False
    assert health["chutefs_token"]["status"] == "stale"
    assert health["chutefs_token"]["ack_age_seconds"] == 31.0
    assert health["gpu_registration_recovery"]["ready"] is True


def test_authority_metrics_are_fixed_cardinality_and_report_ack_age():
    rendered = _key_authority_metrics(
        {
            "chutefs_token": {"ready": True, "ack_age_seconds": 4.5},
            "gpu_registration_recovery": {"ready": False, "ack_age_seconds": None},
        }
    ).decode()

    assert 'chutes_key_authority_ready{authority="chutefs_token"} 1' in rendered
    assert (
        'chutes_key_authority_ready{authority="gpu_registration_recovery"} 0'
        in rendered
    )
    assert (
        'chutes_key_authority_ack_age_seconds{authority="chutefs_token"} 4.5'
        in rendered
    )
