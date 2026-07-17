from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from api.constants import ServerHealthStatus
from api.server.schemas import CpuServerRegistrationArgs, Server
from server_health_prober import probe


def _server(**overrides) -> Server:
    values = {
        "server_id": "server-1",
        "name": "server-1",
        "ip": "192.0.2.10",
        "miner_hotkey": "miner",
        "compute_type": "gpu",
        "storage_role": False,
    }
    values.update(overrides)
    return Server(**values)


def test_legacy_gpu_server_keeps_attestation_proxy_health_endpoint():
    assert _server().health_check_url == "https://192.0.2.10:30443/health"


def test_server_health_chart_enables_structured_logging():
    template = (
        Path(__file__).resolve().parents[2] / "charts/templates/server-health-cronjob.yaml"
    ).read_text()
    assert 'include "chutes.loggingEnv"' in template


@pytest.mark.parametrize(
    "server",
    [
        _server(compute_type="cpu"),
        _server(compute_type="cpu", storage_role=True),
    ],
)
def test_cpu_and_storage_rows_have_no_implicit_legacy_probe(server):
    assert server.health_check_url is None


def test_cpu_role_specific_health_endpoint_is_explicit():
    server = _server(
        compute_type="cpu",
        external_host="198.51.100.8",
        tee_endpoints={"health_port": 31997, "health_path": "/storage/health"},
    )
    assert server.health_check_url == "https://192.0.2.10:31997/storage/health"


@pytest.mark.parametrize(
    "endpoints",
    [
        {"health_port": 31997},
        {"health_path": "/health"},
        {"health_port": True, "health_path": "/health"},
        {"health_port": 31997, "health_path": "https://other.example/health"},
    ],
)
def test_registration_rejects_ambiguous_health_endpoint(endpoints):
    with pytest.raises(ValueError):
        CpuServerRegistrationArgs(
            server_id="server-1",
            quote="quote",
            benchmark={},
            endpoints=endpoints,
        )


@pytest.mark.asyncio
async def test_probe_does_not_open_client_without_role_endpoint():
    server = _server(compute_type="cpu")
    with patch("server_health_prober._httpx.AsyncClient") as client:
        assert await probe(server) is False
    client.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("storage_role", "status_value", "expected"),
    [
        (False, "healthy", True),
        (True, "ok", True),
        (True, "healthy", False),
    ],
)
async def test_probe_uses_role_specific_health_contract(storage_role, status_value, expected):
    server = _server(
        compute_type="cpu",
        storage_role=storage_role,
        tee_endpoints={"health_port": 31997, "health_path": "/storage/health"},
    )
    response = Mock(status_code=200)
    response.json.return_value = {"status": status_value}
    with patch("server_health_prober._httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        assert await probe(server) is expected


def test_health_status_is_derived_from_last_success(monkeypatch):
    monkeypatch.setattr(
        "api.server.schemas.settings.server_health_degraded_threshold_seconds",
        60,
    )
    monkeypatch.setattr(
        "api.server.schemas.settings.server_health_offline_threshold_seconds",
        120,
    )
    assert _server(last_health_at=None).health_status == ServerHealthStatus.UNKNOWN
    assert (
        _server(last_health_at=datetime.now(timezone.utc) - timedelta(seconds=90)).health_status
        == ServerHealthStatus.DEGRADED
    )
    assert (
        _server(last_health_at=datetime.now(timezone.utc) - timedelta(seconds=180)).health_status
        == ServerHealthStatus.OFFLINE
    )
