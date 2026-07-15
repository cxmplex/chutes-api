"""
Unit tests for the public GET /servers/tee/measurements endpoint.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.server.router import _manifest_for_server, get_tee_measurements
from api.server.schemas import TeeMeasurementResponse


def _make_measurement(**overrides):
    defaults = dict(
        version="1",
        name="8xh200",
        mrtd="A" * 96,
        rtmr0="B" * 96,
        rtmr1="C" * 96,
        rtmr2="D" * 96,
        runtime_rtmr3="E" * 96,
        expected_gpus=["h200"],
        gpu_count=8,
    )
    defaults.update(overrides)
    return TeeMeasurementConfig(**defaults)


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_returns_all_measurements(mock_settings):
    m1 = _make_measurement(name="8xh200", version="1", expected_gpus=["h200"], gpu_count=8)
    m2 = _make_measurement(name="8xb200", version="2", expected_gpus=["b200"], gpu_count=8)
    mock_settings.tee_measurements = [m1, m2]
    mock_settings.redis_client.get = AsyncMock(return_value=None)
    mock_settings.redis_client.set = AsyncMock()

    result = await get_tee_measurements()

    assert len(result) == 2
    assert all(isinstance(r, TeeMeasurementResponse) for r in result)


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_release_candidates_are_excluded_from_public_transparency_list(mock_settings):
    stable = _make_measurement(name="stable", rc=False)
    candidate = _make_measurement(name="candidate", version="2", rc=True)
    mock_settings.tee_measurements = [stable, candidate]

    result = await get_tee_measurements()

    assert [entry.name for entry in result] == ["stable"]
    assert result[0].trust_set_fingerprint == measurement_trust_set_fingerprint([stable, candidate])


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_measurement_fields_are_correct(mock_settings):
    m = _make_measurement()
    mock_settings.tee_measurements = [m]
    mock_settings.redis_client.get = AsyncMock(return_value=None)
    mock_settings.redis_client.set = AsyncMock()

    result = await get_tee_measurements()

    assert len(result) == 1
    r = result[0]
    assert r.version == "1"
    assert r.name == "8xh200"
    assert r.mrtd == "A" * 96
    assert r.boot_rtmrs == m.boot_rtmrs
    assert r.runtime_rtmrs == m.runtime_rtmrs
    assert r.expected_gpus == ["h200"]
    assert r.gpu_count == 8
    assert isinstance(r.gpu_count, int)
    assert r.config_fingerprint == measurement_config_fingerprint(m)
    assert r.trust_set_fingerprint == measurement_trust_set_fingerprint([m])


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_returns_empty_list_when_no_measurements(mock_settings):
    mock_settings.tee_measurements = []
    mock_settings.redis_client.get = AsyncMock(return_value=None)
    mock_settings.redis_client.set = AsyncMock()

    result = await get_tee_measurements()

    assert result == []


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_endpoint_never_reads_or_writes_a_static_redis_cache(mock_settings):
    m = _make_measurement()
    mock_settings.tee_measurements = [m]
    mock_settings.redis_client.get = AsyncMock(return_value=None)
    mock_settings.redis_client.set = AsyncMock()

    mock_settings.redis_client.get = AsyncMock()
    mock_settings.redis_client.set = AsyncMock()

    await get_tee_measurements()

    mock_settings.redis_client.get.assert_not_awaited()
    mock_settings.redis_client.set.assert_not_awaited()


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_revocation_is_visible_immediately_and_changes_trust_fingerprint(
    mock_settings,
):
    first = _make_measurement(name="cpu-first", gpu_count=0, expected_gpus=[])
    remaining = _make_measurement(
        name="cpu-remaining",
        version="2",
        gpu_count=0,
        expected_gpus=[],
    )
    mock_settings.tee_measurements = [first, remaining]
    before = await get_tee_measurements()

    mock_settings.tee_measurements = [remaining]
    after = await get_tee_measurements()

    assert [entry.name for entry in after] == ["cpu-remaining"]
    assert after[0].trust_set_fingerprint != before[0].trust_set_fingerprint


@pytest.mark.asyncio
@patch("api.server.router.settings")
async def test_gcp_snp_security_identity_fields_round_trip(mock_settings):
    measurement = _make_measurement(
        name="cpu-gcp-snp",
        tee_type="sev-snp",
        provider="gcp",
        mrtd="",
        rtmr0="",
        rtmr1="",
        rtmr2="",
        runtime_rtmr3="",
        expected_gpus=[],
        gpu_count=0,
        measurement="A" * 96,
        policy=0x30000,
        min_tcb={"bootloader": 4, "tee": 0, "snp": 29, "microcode": 222},
        processor_model="Milan",
        expected_vmpl=0,
        id_key_digest="B" * 96,
        vtpm_pcrs={"8": "C" * 64, "9": "D" * 64},
        vtpm_security_flags={"2": True, "3": False, "4": False, "5": False},
        debug=False,
        image_sha256="e" * 64,
        image_measurement_names=["cpu-gcp-snp"],
    )
    mock_settings.tee_measurements = [measurement]
    mock_settings.redis_client.get = AsyncMock(return_value=None)
    mock_settings.redis_client.set = AsyncMock()

    (result,) = await get_tee_measurements()

    assert result.provider == "gcp"
    assert result.expected_vmpl == 0
    assert result.id_key_digest == "B" * 96
    assert result.vtpm_pcrs == {"8": "C" * 64, "9": "D" * 64}
    assert result.vtpm_security_flags == {
        "2": True,
        "3": False,
        "4": False,
        "5": False,
    }
    assert result.image_sha256 == "e" * 64
    assert result.image_measurement_names == ["cpu-gcp-snp"]


@patch("api.server.router.settings")
def test_connection_manifest_uses_persisted_exact_name_and_fingerprints(
    mock_settings,
):
    measurement = _make_measurement(
        name="cpu-gcp-snp",
        version="2.0.0-snp-4vcpu",
        tee_type="sev-snp",
        provider="gcp",
        mrtd="",
        rtmr0="",
        rtmr1="",
        rtmr2="",
        runtime_rtmr3="",
        expected_gpus=[],
        gpu_count=0,
        measurement="A" * 96,
        policy=0x30000,
        min_tcb={"bootloader": 4, "tee": 0, "snp": 29, "microcode": 222},
        processor_model="Milan",
        expected_vmpl=0,
        id_key_digest="B" * 96,
        vtpm_pcrs={"8": "C" * 64, "9": "D" * 64},
        vtpm_security_flags={"2": True, "3": False, "4": False, "5": False},
        debug=False,
        image_sha256="e" * 64,
        image_measurement_names=["cpu-gcp-snp"],
    )
    config_fingerprint = measurement_config_fingerprint(measurement)
    trust_set_fingerprint = measurement_trust_set_fingerprint([measurement])
    server = SimpleNamespace(
        version=measurement.version,
        measurement_name=measurement.name,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
    )
    mock_settings.tee_measurements = [measurement]

    manifest = _manifest_for_server(server)

    assert manifest["measurement_name"] == measurement.name
    assert manifest["config_fingerprint"] == config_fingerprint
    assert manifest["trust_set_fingerprint"] == trust_set_fingerprint
    assert manifest["exact_pin"] == {
        "version": measurement.version,
        "name": measurement.name,
        "tee_type": "sev-snp",
        "provider": "gcp",
        "mrtd": "",
        "boot_rtmrs": {},
        "runtime_rtmrs": {},
        "expected_gpus": [],
        "gpu_count": 0,
        "measurement": "A" * 96,
        "policy": 0x30000,
        "min_tcb": {"bootloader": 4, "tee": 0, "snp": 29, "microcode": 222},
        "processor_model": "Milan",
        "expected_vmpl": 0,
        "id_key_digest": "B" * 96,
        "vtpm_pcrs": {"8": "C" * 64, "9": "D" * 64},
        "vtpm_security_flags": {
            "2": True,
            "3": False,
            "4": False,
            "5": False,
        },
        "debug": False,
        "image_sha256": "e" * 64,
        "image_measurement_names": ["cpu-gcp-snp"],
        "config_fingerprint": config_fingerprint,
        "trust_set_fingerprint": trust_set_fingerprint,
    }


@patch("api.server.router.settings")
def test_connection_manifest_rejects_retired_or_full_trust_mismatch(
    mock_settings,
):
    measurement = _make_measurement(name="cpu-current", gpu_count=0, expected_gpus=[])
    server = SimpleNamespace(
        version=measurement.version,
        measurement_name=measurement.name,
        measurement_config_fingerprint=measurement_config_fingerprint(measurement),
        trust_set_fingerprint=measurement_trust_set_fingerprint([measurement]),
    )

    mock_settings.tee_measurements = []
    assert _manifest_for_server(server) is None

    mock_settings.tee_measurements = [
        measurement,
        _make_measurement(name="cpu-added", gpu_count=0, expected_gpus=[]),
    ]
    assert _manifest_for_server(server) is None
