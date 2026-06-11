"""
Unit tests for CPU (gpu_count: 0) TEE measurement config loading in api.config.
"""

import textwrap
from pathlib import Path

import pytest

from api.config import Settings


HEX96_MRTD = "A" * 96
HEX96_RTMR0 = "B" * 96
HEX96_RTMR1 = "C" * 96
HEX96_RTMR2 = "D" * 96
HEX96_RTMR3 = "E" * 96


def _settings_for_yaml(tmp_path: Path, yaml_text: str) -> Settings:
    config_path = tmp_path / "tee_measurements.yaml"
    config_path.write_text(textwrap.dedent(yaml_text))
    settings = Settings()
    settings.tee_measurement_config_path = config_path
    return settings


def test_loads_cpu_measurement_gpu_count_zero(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "1"
        mrtd: "{HEX96_MRTD}"
        name: "cpu-gcp"
        provider: "gcp"
        boot_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        runtime_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml_text)
    measurements = settings._load_tee_measurements()
    assert len(measurements) == 1
    cpu = measurements[0]
    assert cpu.gpu_count == 0
    assert cpu.expected_gpus == []
    assert cpu.provider == "gcp"
    assert cpu.mrtd == HEX96_MRTD


def test_measurement_absent_gpu_count_rejected(tmp_path):
    """A config omitting gpu_count must hard-fail at load: silently treating it as a CPU
    config would skip GPU evidence verification for a GPU image. CPU-ness is explicit
    (gpu_count: 0)."""
    yaml_text = f"""
    measurements:
      - version: "1"
        mrtd: "{HEX96_MRTD}"
        name: "cpu-baremetal"
        provider: "bare-metal"
        boot_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        runtime_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        expected_gpus: []
    """
    settings = _settings_for_yaml(tmp_path, yaml_text)
    with pytest.raises(ValueError, match="Missing 'gpu_count'"):
        settings._load_tee_measurements()


def test_gpu_measurement_still_loads_with_provider_none(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "2"
        mrtd: "{HEX96_MRTD}"
        name: "8xh200"
        boot_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        runtime_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        expected_gpus:
          - "h200"
        gpu_count: 8
    """
    settings = _settings_for_yaml(tmp_path, yaml_text)
    measurements = settings._load_tee_measurements()
    assert len(measurements) == 1
    gpu = measurements[0]
    assert gpu.gpu_count == 8
    assert gpu.expected_gpus == ["h200"]
    assert gpu.provider is None


def test_provider_is_normalized_lowercase(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "1"
        mrtd: "{HEX96_MRTD}"
        name: "cpu-gcp"
        provider: "GCP"
        boot_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        runtime_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml_text)
    measurements = settings._load_tee_measurements()
    assert measurements[0].provider == "gcp"


def test_invalid_rtmr0_length_still_raises(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "1"
        mrtd: "{HEX96_MRTD}"
        name: "cpu-bad"
        boot_rtmrs:
          rtmr0: "TOOSHORT"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        runtime_rtmrs:
          rtmr0: "{HEX96_RTMR0}"
          rtmr1: "{HEX96_RTMR1}"
          rtmr2: "{HEX96_RTMR2}"
          rtmr3: "{HEX96_RTMR3}"
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml_text)
    with pytest.raises(ValueError, match="Invalid boot_rtmrs.rtmr0"):
        settings._load_tee_measurements()
