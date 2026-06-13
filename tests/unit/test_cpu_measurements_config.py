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


# --------------------------------------------------------------------------------------------------
# AMD SEV-SNP configs must fail closed: policy + min_tcb always; vtpm_pcrs for provider gcp.
# --------------------------------------------------------------------------------------------------

HEX96_SNP = "F" * 96
HEX64_PCR = "1" * 64


def _snp_yaml(*, policy='policy: "0x30000"', min_tcb=True, provider="baremetal", vtpm=False):
    min_tcb_block = (
        """
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72"""
        if min_tcb
        else ""
    )
    vtpm_block = (
        f"""
        vtpm_pcrs:
          "8": "{HEX64_PCR}"
          "9": "{HEX64_PCR}" """
        if vtpm
        else ""
    )
    return f"""
    measurements:
      - version: "1"
        name: "cpu-snp"
        provider: "{provider}"
        tee_type: "sev-snp"
        measurement: "{HEX96_SNP}"
        {policy}{min_tcb_block}{vtpm_block}
        expected_gpus: []
        gpu_count: 0
    """


def test_snp_config_complete_loads(tmp_path):
    settings = _settings_for_yaml(tmp_path, _snp_yaml())
    (config,) = settings._load_tee_measurements()
    assert config.tee_type == "sev-snp"
    assert config.policy == 0x30000
    assert config.min_tcb == {"bootloader": 7, "tee": 0, "snp": 23, "microcode": 72}


def test_snp_config_missing_policy_rejected(tmp_path):
    """The SNP launch measurement does not cover the policy field, so an unpinned policy lets a
    host flip non-DEBUG policy bits undetected -- the config must hard-fail at load."""
    settings = _settings_for_yaml(tmp_path, _snp_yaml(policy=""))
    with pytest.raises(ValueError, match="Missing 'policy'"):
        settings._load_tee_measurements()


def test_snp_config_missing_min_tcb_rejected(tmp_path):
    """Without a minimum reported TCB there is no anti-rollback; must hard-fail at load."""
    settings = _settings_for_yaml(tmp_path, _snp_yaml(min_tcb=False))
    with pytest.raises(ValueError, match="Missing 'min_tcb'"):
        settings._load_tee_measurements()


def test_gcp_snp_config_without_vtpm_pcrs_rejected(tmp_path):
    """A provider-gcp SNP config without vtpm_pcrs would match on Google firmware alone and never
    check image identity; must hard-fail at load (requiring PCR8 and PCR9 specifically)."""
    settings = _settings_for_yaml(tmp_path, _snp_yaml(provider="gcp", vtpm=False))
    with pytest.raises(ValueError, match="must pin vtpm_pcrs including PCR8 and PCR9"):
        settings._load_tee_measurements()


def test_gcp_snp_config_with_vtpm_pcrs_loads(tmp_path):
    settings = _settings_for_yaml(tmp_path, _snp_yaml(provider="gcp", vtpm=True))
    (config,) = settings._load_tee_measurements()
    assert config.vtpm_pcrs == {"8": HEX64_PCR, "9": HEX64_PCR}


def test_debug_measurement_rejected_without_switch(tmp_path):
    """A measurement config tagged debug: true is refused at load unless ALLOW_DEBUG_MEASUREMENTS
    is set -- a debug image forwards user logs to the host console and must not pass as production."""
    yaml = f"""
    measurements:
      - version: "1"
        name: "cpu-snp-dbg"
        provider: "bare-metal"
        tee_type: "sev-snp"
        debug: true
        measurement: "{HEX96_SNP}"
        policy: "0x30000"
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml)
    with pytest.raises(ValueError, match="ALLOW_DEBUG_MEASUREMENTS"):
        settings._load_tee_measurements()


def test_debug_measurement_allowed_with_switch(tmp_path, monkeypatch):
    """With ALLOW_DEBUG_MEASUREMENTS set (dev), a debug-tagged config loads."""
    yaml = f"""
    measurements:
      - version: "1"
        name: "cpu-snp-dbg"
        provider: "bare-metal"
        tee_type: "sev-snp"
        debug: true
        measurement: "{HEX96_SNP}"
        policy: "0x30000"
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml)
    monkeypatch.setattr(settings, "allow_debug_measurements", True)
    (config,) = settings._load_tee_measurements()
    assert config.name == "cpu-snp-dbg"


def test_snp_config_missing_provider_rejected(tmp_path):
    """SNP image identity is verified differently per provider; an unset/unknown provider would
    default the GCP vTPM image-identity check off, so it must fail closed at load."""
    settings = _settings_for_yaml(tmp_path, _snp_yaml(provider="", vtpm=False))
    with pytest.raises(ValueError, match="must set provider to 'gcp' or 'bare-metal'"):
        settings._load_tee_measurements()


def test_snp_config_baremetal_alias_normalized(tmp_path):
    """'baremetal' is accepted and normalized to 'bare-metal' (no vtpm_pcrs required there)."""
    settings = _settings_for_yaml(tmp_path, _snp_yaml(provider="baremetal", vtpm=False))
    (config,) = settings._load_tee_measurements()
    assert config.provider == "bare-metal"


def test_gcp_snp_config_with_only_pcr8_rejected(tmp_path):
    """A GCP SNP config that pins some PCRs but is missing PCR9 leaves the image unpinned (the
    listed PCR alone may be image-invariant); must fail closed."""
    yaml = f"""
    measurements:
      - version: "1"
        name: "cpu-snp"
        provider: "gcp"
        tee_type: "sev-snp"
        measurement: "{HEX96_SNP}"
        policy: "0x30000"
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        vtpm_pcrs:
          "8": "{HEX64_PCR}"
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml)
    with pytest.raises(ValueError, match="must pin vtpm_pcrs including PCR8 and PCR9"):
        settings._load_tee_measurements()
