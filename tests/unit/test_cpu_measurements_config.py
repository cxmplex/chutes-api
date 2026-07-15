"""
Unit tests for CPU (gpu_count: 0) TEE measurement config loading in api.config.
"""

import textwrap
from pathlib import Path

import pytest
import yaml

from api.config import Settings
from api.main import _tee_trust_metrics


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
    settings.tee_committed_measurement_config_path = (
        tmp_path / "no-committed-measurements.yaml"
    )
    return settings


def test_loads_cpu_measurement_gpu_count_zero(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "1"
        mrtd: "{HEX96_MRTD}"
        name: "cpu-gcp"
        provider: "gcp"
        debug: false
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
        debug: false
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


@pytest.mark.parametrize("gpu_count", [False, True, "0", -1])
def test_measurement_gpu_count_requires_nonnegative_integer(tmp_path, gpu_count):
    document = yaml.safe_load(
        textwrap.dedent(
            f"""
            measurements:
              - version: "1"
                mrtd: "{HEX96_MRTD}"
                name: "cpu-gcp"
                provider: "gcp"
                debug: false
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
        )
    )
    document["measurements"][0]["gpu_count"] = gpu_count
    settings = _settings_for_yaml(tmp_path, yaml.safe_dump(document))
    with pytest.raises(ValueError, match="gpu_count"):
        settings._load_tee_measurements()


def test_gpu_measurement_still_loads_with_provider_none(tmp_path):
    yaml_text = f"""
    measurements:
      - version: "2"
        mrtd: "{HEX96_MRTD}"
        name: "8xh200"
        debug: false
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
        debug: false
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
        debug: false
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


def _snp_yaml(
    *,
    policy='policy: "0x30000"',
    min_tcb=True,
    provider="bare-metal",
    vtpm=False,
    vtpm_flags=True,
    expected_vmpl="expected_vmpl: 0",
):
    min_tcb_block = (
        min_tcb
        if isinstance(min_tcb, str)
        else """
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
    vtpm_flags_block = (
        """
        vtpm_security_flags:
          "2": true
          "3": false
          "4": false
          "5": false"""
        if vtpm and vtpm_flags is True
        else vtpm_flags
        if isinstance(vtpm_flags, str)
        else ""
    )
    return f"""
    measurements:
      - version: "1"
        name: "cpu-snp"
        provider: "{provider}"
        tee_type: "sev-snp"
        debug: false
        measurement: "{HEX96_SNP}"
        {policy}{min_tcb_block}{vtpm_block}{vtpm_flags_block}
        {expected_vmpl}
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


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (key, value)
        for key in ("bootloader", "tee", "snp", "microcode")
        for value in (True, False, 7.0, "7", None, -1, 256)
    ],
)
def test_snp_config_requires_actual_bounded_integer_for_every_tcb_component(
    tmp_path, key, value
):
    document = yaml.safe_load(textwrap.dedent(_snp_yaml()))
    document["measurements"][0]["min_tcb"][key] = value
    settings = _settings_for_yaml(tmp_path, yaml.safe_dump(document))
    with pytest.raises(ValueError, match="min_tcb"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "min_tcb",
    [
        {"bootloader": 7},
        {
            "bootloader": 7,
            "tee": 0,
            "snp": 23,
            "microcode": 72,
            "extra": 1,
        },
        {1: 7, "tee": 0, "snp": 23, "microcode": 72},
    ],
)
def test_snp_config_requires_exact_tcb_key_set(tmp_path, min_tcb):
    document = yaml.safe_load(textwrap.dedent(_snp_yaml()))
    document["measurements"][0]["min_tcb"] = min_tcb
    settings = _settings_for_yaml(tmp_path, yaml.safe_dump(document))
    with pytest.raises(ValueError, match="min_tcb"):
        settings._load_tee_measurements()


def test_snp_config_accepts_tcb_integer_boundaries(tmp_path):
    document = yaml.safe_load(textwrap.dedent(_snp_yaml()))
    document["measurements"][0]["min_tcb"] = {
        "bootloader": 0,
        "tee": 255,
        "snp": 0,
        "microcode": 255,
    }
    settings = _settings_for_yaml(tmp_path, yaml.safe_dump(document))
    (config,) = settings._load_tee_measurements()
    assert config.min_tcb == document["measurements"][0]["min_tcb"]


def test_snp_config_rejects_exact_duplicate_yaml_tcb_key(tmp_path):
    duplicate = """
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
          bootloader: 8
    """
    settings = _settings_for_yaml(tmp_path, _snp_yaml(min_tcb=duplicate))
    with pytest.raises(ValueError, match="duplicate YAML key 'bootloader'"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "tcb_block",
    [
        """
        min_tcb:
          Bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        """,
        """
        min_tcb:
          bootloader: 7
          Bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        """,
        """
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          Microcode: 72
        """,
        """
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
          MICROCODE: 72
        """,
    ],
)
def test_snp_config_rejects_wrong_case_and_case_duplicate_tcb_keys(tmp_path, tcb_block):
    settings = _settings_for_yaml(tmp_path, _snp_yaml(min_tcb=tcb_block))
    with pytest.raises(ValueError, match="exactly lowercase"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("vmpl", ["", "expected_vmpl: -1", "expected_vmpl: 4"])
def test_snp_config_requires_observed_vmpl_pin(tmp_path, vmpl):
    settings = _settings_for_yaml(tmp_path, _snp_yaml(expected_vmpl=vmpl))
    with pytest.raises(ValueError, match="expected_vmpl"):
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
    assert config.vtpm_security_flags == {
        "2": True,
        "3": False,
        "4": False,
        "5": False,
    }


@pytest.mark.parametrize(
    "flags",
    [
        False,
        """
        vtpm_security_flags:
          "2": true
          "3": false
          "4": false
        """,
        """
        vtpm_security_flags:
          "2": true
          "3": false
          "4": false
          "5": false
          "6": false
        """,
        """
        vtpm_security_flags:
          "2": true
          "3": false
          "4": false
          "5": "false"
        """,
    ],
)
def test_gcp_snp_config_requires_exact_boolean_security_flags(tmp_path, flags):
    settings = _settings_for_yaml(
        tmp_path,
        _snp_yaml(provider="gcp", vtpm=True, vtpm_flags=flags),
    )
    with pytest.raises(ValueError, match="vtpm_security_flags"):
        settings._load_tee_measurements()


def test_gcp_security_flag_flip_changes_measurement_fingerprint(tmp_path):
    first_settings = _settings_for_yaml(
        tmp_path,
        _snp_yaml(provider="gcp", vtpm=True),
    )
    (first,) = first_settings._load_tee_measurements()
    flipped = """
        vtpm_security_flags:
          "2": false
          "3": false
          "4": false
          "5": false
    """
    second_settings = _settings_for_yaml(
        tmp_path,
        _snp_yaml(provider="gcp", vtpm=True, vtpm_flags=flipped),
    )
    (second,) = second_settings._load_tee_measurements()

    assert first.config_fingerprint != second.config_fingerprint
    assert first.trust_set_fingerprint != second.trust_set_fingerprint


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
        expected_vmpl: 0
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml)
    settings.allow_debug_measurements = False
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
        expected_vmpl: 0
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


def test_snp_config_noncanonical_baremetal_provider_rejected(tmp_path):
    settings = _settings_for_yaml(tmp_path, _snp_yaml(provider="baremetal", vtpm=False))
    with pytest.raises(ValueError, match="must set provider to 'gcp' or 'bare-metal'"):
        settings._load_tee_measurements()


def test_gcp_snp_config_with_only_pcr8_rejected(tmp_path):
    """A GCP SNP config that pins some PCRs but is missing PCR9 leaves the image unpinned (the
    listed PCR alone may be image-invariant); must fail closed."""
    yaml = f"""
    measurements:
      - version: "1"
        name: "cpu-snp"
        provider: "gcp"
        tee_type: "sev-snp"
        debug: false
        measurement: "{HEX96_SNP}"
        policy: "0x30000"
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        expected_vmpl: 0
        vtpm_pcrs:
          "8": "{HEX64_PCR}"
        expected_gpus: []
        gpu_count: 0
    """
    settings = _settings_for_yaml(tmp_path, yaml)
    with pytest.raises(ValueError, match="must pin vtpm_pcrs including PCR8 and PCR9"):
        settings._load_tee_measurements()


def _settings_for_committed_yaml(tmp_path: Path, yaml_text: str) -> Settings:
    committed_path = tmp_path / "tee_measurements.committed.yaml"
    committed_path.write_text(textwrap.dedent(yaml_text))
    settings = Settings()
    settings.tee_committed_measurement_config_path = committed_path
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    return settings


def _committed_snp_yaml(provenance: str) -> str:
    provenance_block = textwrap.indent(textwrap.dedent(provenance).strip(), "        ")
    return f"""
    measurements:
      - version: "1"
        name: "cpu-snp"
        provider: "bare-metal"
        tee_type: "sev-snp"
        debug: false
{provenance_block}
        measurement: "{HEX96_SNP}"
        policy: "0x30000"
        min_tcb:
          bootloader: 7
          tee: 0
          snp: 23
          microcode: 72
        expected_vmpl: 0
        expected_gpus: []
        gpu_count: 0
    """


def _committed_snp_matrix_yaml() -> str:
    names = [f"cpu-baremetal-snp-genoa-2.0.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)]
    measurements = []
    for index, (name, vcpus) in enumerate(zip(names, (1, 2, 4, 8), strict=True)):
        measurements.append(
            {
                "version": f"2.0.0-snp-{vcpus}vcpu",
                "name": name,
                "provider": "bare-metal",
                "tee_type": "sev-snp",
                "debug": False,
                "image_sha256": "a" * 64,
                "image_measurement_names": names,
                "measurement": f"{index + 1:X}" * 96,
                "policy": "0x30000",
                "min_tcb": {
                    "bootloader": 7,
                    "tee": 0,
                    "snp": 23,
                    "microcode": 72,
                },
                "expected_vmpl": 0,
                "expected_gpus": [],
                "gpu_count": 0,
            }
        )
    return yaml.safe_dump({"measurements": measurements}, sort_keys=False)


def test_actual_committed_debug_measurements_rejected_in_production(tmp_path):
    settings = Settings()
    settings.tee_committed_measurement_config_path = (
        Path(__file__).resolve().parents[2]
        / "api/config/tee_measurements.committed.yaml"
    )
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    settings.allow_debug_measurements = False

    with pytest.raises(ValueError, match="ALLOW_DEBUG_MEASUREMENTS"):
        settings._load_tee_measurements()


def test_debug_measurement_opt_in_is_rejected_outside_dev_posture():
    with pytest.raises(ValueError, match="permitted only in the explicit dev posture"):
        Settings(
            allow_debug_measurements=True,
            skip_metagraph_check=False,
            require_mtls_client_verify=True,
        )


def test_actual_committed_measurements_have_bound_debug_provenance(tmp_path):
    settings = Settings()
    settings.tee_committed_measurement_config_path = (
        Path(__file__).resolve().parents[2]
        / "api/config/tee_measurements.committed.yaml"
    )
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    settings.allow_debug_measurements = True

    measurements = settings._load_tee_measurements()
    by_digest = {}
    debug_by_digest = {}
    for measurement in measurements:
        assert measurement.image_sha256
        assert measurement.image_measurement_names
        by_digest.setdefault(measurement.image_sha256, set()).add(measurement.name)
        debug_by_digest.setdefault(measurement.image_sha256, set()).add(
            measurement.debug
        )

    assert by_digest == {
        "688d24a5ab1af8e2174ffada8d8ea669c38280b4b0fdd6936729fe697b5930e3": {
            f"cpu-baremetal-snp-genoa-1.6.2-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
        },
        "3121af4af5446f1dacc4a3290eba8605aa3c2a32a319d31c958c61faca5dd2da": {
            f"storage-baremetal-snp-genoa-1.6.1-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
        },
        "a20879377cb717f708fa62060bb6a0b4d5f8857c7d0185a925ba6674cd7748c5": {
            "storage-baremetal-tdx-1.6.0-4vcpu"
        },
        "2f8995ab4481e752b5ccfd10d70b311799288e6fd2a5c3a4c2fb84900b169c3c": {
            f"cpu-baremetal-snp-genoa-1.7.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
        },
        "7fb6d2bbfd2d3344618bd37b56c012e4713a9a4ebaad10b6947c6ce4f4585bb5": {
            f"storage-baremetal-snp-genoa-1.7.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
        },
        "71e26326c5a0d19060fd8fcf25f54c807f9473b44fb34667742a6d6c816854d6": {
            f"storage-baremetal-snp-genoa-1.7.1-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
        },
    }
    assert debug_by_digest == {
        digest: {
            digest
            in {
                "688d24a5ab1af8e2174ffada8d8ea669c38280b4b0fdd6936729fe697b5930e3",
                "3121af4af5446f1dacc4a3290eba8605aa3c2a32a319d31c958c61faca5dd2da",
                "a20879377cb717f708fa62060bb6a0b4d5f8857c7d0185a925ba6674cd7748c5",
            }
        }
        for digest in by_digest
    }
    for measurement in measurements:
        assert (
            set(measurement.image_measurement_names)
            == by_digest[measurement.image_sha256]
        )


@pytest.mark.parametrize("debug_value", ["false", 0, None])
def test_debug_posture_requires_explicit_yaml_boolean(tmp_path, debug_value):
    yaml = _snp_yaml().replace("debug: false", f"debug: {debug_value!r}")
    settings = _settings_for_yaml(tmp_path, yaml)
    with pytest.raises(ValueError, match="Missing or invalid 'debug' posture"):
        settings._load_tee_measurements()


def test_missing_debug_posture_rejected(tmp_path):
    settings = _settings_for_yaml(
        tmp_path, _snp_yaml().replace("        debug: false\n", "")
    )
    with pytest.raises(ValueError, match="Missing or invalid 'debug' posture"):
        settings._load_tee_measurements()


def test_missing_committed_image_provenance_rejected(tmp_path):
    settings = _settings_for_committed_yaml(tmp_path, _committed_snp_yaml(""))
    with pytest.raises(ValueError, match="Missing image provenance for committed"):
        settings._load_tee_measurements()


def test_malformed_measurement_source_fails_closed(tmp_path):
    settings = Settings()
    malformed_path = tmp_path / "tee_measurements.committed.yaml"
    malformed_path.write_text("measurements:\n  - image_sha256: [")
    settings.tee_committed_measurement_config_path = malformed_path
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    with pytest.raises(ValueError, match="Failed to load TEE measurement config"):
        settings._load_tee_measurements()


def test_required_mounted_source_cannot_silently_disappear(tmp_path):
    settings = _settings_for_committed_yaml(
        tmp_path,
        _committed_snp_yaml(
            f"""
            image_sha256: "{"a" * 64}"
            image_measurement_names: ["cpu-snp"]
            """
        ),
    )
    settings.tee_measurement_config_required = True
    with pytest.raises(ValueError, match="Required TEE measurement config"):
        settings._load_tee_measurements()


def test_revocation_tombstone_survives_failed_reload_via_last_known_good(tmp_path):
    settings = _settings_for_committed_yaml(
        tmp_path,
        _committed_snp_yaml(
            f"""
            image_sha256: "{"a" * 64}"
            image_measurement_names: ["cpu-snp"]
            """
        ),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements: []\nrevoked_measurements:\n  - cpu-snp\n")
    settings.tee_measurement_config_path = mounted

    assert settings._load_tee_measurements() == []

    mounted.write_text("measurements:\n  - invalid: [")
    assert settings._load_tee_measurements() == []
    assert settings._tee_measurements_last_error


def test_runtime_missing_expected_source_retains_last_good_and_degrades(tmp_path):
    settings = _settings_for_committed_yaml(
        tmp_path,
        _committed_snp_yaml(
            f"""
            image_sha256: "{"a" * 64}"
            image_measurement_names: ["cpu-snp"]
            """
        ),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements: []\n")
    settings.tee_measurement_config_path = mounted
    settings.tee_measurement_config_required = True

    first = settings._load_tee_measurements()
    fingerprint = settings.tee_measurements_fingerprint
    mounted.unlink()

    assert settings._load_tee_measurements() == first
    health = settings.tee_measurement_health()
    assert health["status"] == "degraded"
    assert health["ready"] is False
    assert health["fingerprint"] == fingerprint
    assert "Required TEE measurement config" in health["last_error"]


def test_restart_with_required_malformed_source_fails_closed(tmp_path):
    committed = tmp_path / "committed.yaml"
    committed.write_text(
        textwrap.dedent(
            _committed_snp_yaml(
                f"""
                image_sha256: "{"a" * 64}"
                image_measurement_names: ["cpu-snp"]
                """
            )
        )
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements:\n  - malformed: [")

    with pytest.raises(ValueError, match="Failed to load TEE measurement config"):
        Settings(
            tee_committed_measurement_config_path=committed,
            tee_measurement_config_path=mounted,
            tee_measurement_config_required=True,
        )


def test_operator_metrics_expose_trust_health_error_and_fingerprint():
    rendered = _tee_trust_metrics(
        {
            "status": "degraded",
            "ready": False,
            "last_error": 'required source "mounted"\nmissing',
            "fingerprint": "a" * 64,
            "measurement_count": 7,
        }
    ).decode()

    assert "chutes_tee_measurement_trust_ready 0" in rendered
    assert "chutes_tee_measurement_trust_entries 7" in rendered
    assert 'status="degraded"' in rendered
    assert f'fingerprint="{"a" * 64}"' in rendered
    assert 'last_error="required source \\"mounted\\"\\nmissing"' in rendered


def test_revocation_changes_trust_fingerprint_and_invalidates_config(tmp_path):
    settings = _settings_for_committed_yaml(
        tmp_path,
        _committed_snp_yaml(
            f"""
            image_sha256: "{"a" * 64}"
            image_measurement_names: ["cpu-snp"]
            """
        ),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements: []\n")
    settings.tee_measurement_config_path = mounted
    settings.tee_measurement_config_required = True

    (config,) = settings._load_tee_measurements()
    before = settings.tee_measurements_fingerprint
    assert config.config_fingerprint
    assert config.trust_set_fingerprint == before

    mounted.write_text("measurements: []\nrevoked_measurements:\n  - cpu-snp\n")
    assert settings._load_tee_measurements() == []
    after = settings.tee_measurements_fingerprint
    assert after != before
    assert settings.tee_measurement_health()["status"] == "healthy"


def test_one_matrix_tombstone_atomically_retires_real_1_2_4_8_set(tmp_path):
    settings = _settings_for_committed_yaml(tmp_path, _committed_snp_matrix_yaml())
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements: []\n")
    settings.tee_measurement_config_path = mounted
    settings.tee_measurement_config_required = True

    before_configs = settings._load_tee_measurements()
    before_fingerprint = settings.tee_measurements_fingerprint
    assert [config.name for config in before_configs] == [
        f"cpu-baremetal-snp-genoa-2.0.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)
    ]

    mounted.write_text(
        "measurements: []\nrevoked_measurements:\n  - cpu-baremetal-snp-genoa-2.0.0-2vcpu\n"
    )
    assert settings._load_tee_measurements() == []
    retired_fingerprint = settings.tee_measurements_fingerprint
    assert retired_fingerprint != before_fingerprint
    assert settings.tee_measurement_health()["status"] == "healthy"

    mounted.write_text("measurements:\n  - malformed: [")
    assert settings._load_tee_measurements() == []
    assert settings.tee_measurements_fingerprint == retired_fingerprint
    assert settings._tee_measurements_last_error


@pytest.mark.parametrize(
    ("provenance", "message"),
    [
        (
            'image_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
            "Incomplete image provenance",
        ),
        (
            """
            image_sha256: "not-a-sha"
            image_measurement_names: ["cpu-snp"]
            """,
            "Invalid image_sha256",
        ),
        (
            """
            image_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            image_measurement_names: ["cpu-snp", "cpu-snp"]
            """,
            "duplicate names",
        ),
        (
            """
            image_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            image_measurement_names: ["cpu-snp", "cpu-unknown"]
            """,
            "every declared entry",
        ),
    ],
)
def test_malformed_committed_image_provenance_rejected(tmp_path, provenance, message):
    settings = _settings_for_committed_yaml(tmp_path, _committed_snp_yaml(provenance))
    with pytest.raises(ValueError, match=message):
        settings._load_tee_measurements()
