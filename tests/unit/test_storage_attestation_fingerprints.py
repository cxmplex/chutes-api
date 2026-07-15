from types import SimpleNamespace

import pytest

from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.storage import service


def _config(name, *, storage):
    return TeeMeasurementConfig(
        version="1.0.0",
        name=name,
        tee_type="tdx",
        provider="bare-metal",
        mrtd="A" * 96,
        boot_rtmrs={f"RTMR{index}": "B" * 96 for index in range(4)},
        runtime_rtmrs={f"RTMR{index}": "C" * 96 for index in range(4)},
        expected_gpus=[],
        gpu_count=0,
        debug=False,
    )


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _Session:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _statement):
        return _Result(self.rows)


@pytest.mark.asyncio
async def test_storage_freshness_uses_complete_trust_set_not_storage_subset(
    monkeypatch,
):
    storage = _config("storage-current", storage=True)
    cpu = _config("cpu-current", storage=False)
    full_trust = measurement_trust_set_fingerprint([storage, cpu])
    row = SimpleNamespace(
        server_id="storage-1",
        measurement_name=storage.name,
        measurement_version=storage.version,
        measurement_config_fingerprint=measurement_config_fingerprint(storage),
        trust_set_fingerprint=full_trust,
    )
    monkeypatch.setattr(service, "settings", SimpleNamespace(tee_measurements=[storage, cpu]))

    verified = await service._verified_storage_ids(_Session([row]), ["storage-1"])

    assert verified == {"storage-1"}
    assert full_trust != measurement_trust_set_fingerprint([storage])


@pytest.mark.asyncio
async def test_storage_freshness_rejects_stale_full_trust_fingerprint(
    monkeypatch,
):
    storage = _config("storage-current", storage=True)
    cpu = _config("cpu-current", storage=False)
    row = SimpleNamespace(
        server_id="storage-1",
        measurement_name=storage.name,
        measurement_version=storage.version,
        measurement_config_fingerprint=measurement_config_fingerprint(storage),
        trust_set_fingerprint=measurement_trust_set_fingerprint([storage]),
    )
    monkeypatch.setattr(service, "settings", SimpleNamespace(tee_measurements=[storage, cpu]))

    verified = await service._verified_storage_ids(_Session([row]), ["storage-1"])

    assert verified == set()
