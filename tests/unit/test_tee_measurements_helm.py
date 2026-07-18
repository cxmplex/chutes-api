"""Render the Helm measurement ConfigMap and parse its embedded strict source."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from api.config import Settings


CHART_DIR = Path(__file__).resolve().parents[2] / "charts"


def test_helm_renders_nested_measurements_and_revocations_for_runtime_parser(tmp_path):
    helm = os.getenv("HELM_TEST_BINARY") or shutil.which("helm")
    if not helm:
        pytest.skip("helm binary is required for render-level chart verification")

    values = {
        "teeMeasurements": {
            "measurements": [
                {
                    "version": "1.3.0",
                    "tee_type": "tdx",
                    "provider": "gcp",
                    "debug": False,
                    "rc": False,
                    "mrtd": "A" * 96,
                    "rtmr1": "C" * 96,
                    "rtmr2": "D" * 96,
                    "runtime_rtmr3": "E" * 96,
                    "hardware": [
                        {
                            "name": "cpu-gcp",
                            "rtmr0": "B" * 96,
                            "expected_gpus": [],
                            "gpu_count": 0,
                        }
                    ],
                }
            ],
            "revokedMeasurements": ["future-measurement"],
        }
    }
    values_path = tmp_path / "values.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))

    rendered = subprocess.run(
        [
            helm,
            "template",
            "tee-measurements-test",
            str(CHART_DIR),
            "--show-only",
            "templates/tee-measurements-cm.yaml",
            "--values",
            str(values_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rendered.returncode == 0, rendered.stderr

    config_map = next(yaml.safe_load_all(rendered.stdout))
    embedded = config_map["data"]["tee_measurements.yaml"]
    source = yaml.safe_load(embedded)
    assert set(source) == {"measurements", "revoked_measurements"}
    assert source["measurements"][0]["hardware"][0]["name"] == "cpu-gcp"
    assert source["revoked_measurements"] == ["future-measurement"]

    source_path = tmp_path / "tee_measurements.yaml"
    source_path.write_text(embedded)
    settings = Settings()
    settings.tee_committed_measurement_config_path = tmp_path / "no-committed.yaml"
    settings.tee_measurement_config_path = source_path

    (measurement,) = settings._load_tee_measurements()
    assert measurement.name == "cpu-gcp"
    assert measurement.rtmr0 == "B" * 96
