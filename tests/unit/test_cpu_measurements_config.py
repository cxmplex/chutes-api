"""Strict nested TEE measurement source parsing and runtime identity tests."""

from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml

from api.config import (
    Settings,
    TeeMeasurementConfig,
    _expand_nested_measurement_group,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.main import _tee_trust_metrics
from cross_repo_tests import repository_root


HEX96_MRTD = "A" * 96
HEX96_RTMR0 = "B" * 96
HEX96_RTMR1 = "C" * 96
HEX96_RTMR2 = "D" * 96
HEX96_RTMR3 = "E" * 96
HEX96_SNP = "F" * 96
HEX64_PCR = "1" * 64
TRUST_FINGERPRINT = "eadf05c46cc7758c943c10f78fb65633f93f9b780f6e0b301136ff919b99cef9"
COMMITTED_TDX_FINGERPRINT = "22a6a665bb44323d386849ccb9890ebbc879b017f278e1e74af30721a516a1dd"
_ABSENT = object()


def test_sek8s_renderer_contract_flattens_exact_model_a_and_b_groups():
    fixture_path = (
        repository_root("sek8s", start=Path(__file__))
        / "tests/fixtures/tee_measurement_renderer_api_contract.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert fixture["schema_version"] == 1
    assert {case["id"] for case in fixture["cases"]} == {
        "model-a-tdx-chute",
        "model-a-tdx-storage",
        "model-a-sev-snp-chute",
        "model-a-sev-snp-storage",
        "model-b-tdx-chute",
        "model-b-tdx-storage",
        "model-b-sev-snp-chute",
        "model-b-sev-snp-storage",
    }
    for case in fixture["cases"]:
        assert _expand_nested_measurement_group(
            deepcopy(case["group"]),
            fixture_path,
        ) == [case["expected_flattened"]]


def _document(*groups: dict, revoked: list[str] | None = None) -> dict:
    return {
        "measurements": list(groups),
        "revoked_measurements": list(revoked or []),
    }


def _settings_for_yaml(tmp_path: Path, yaml_text: str) -> Settings:
    config_path = tmp_path / "tee_measurements.yaml"
    config_path.write_text(yaml_text)
    settings = Settings()
    settings.tee_measurement_config_path = config_path
    settings.tee_committed_measurement_config_path = tmp_path / "no-committed-measurements.yaml"
    return settings


def _settings_for_document(tmp_path: Path, document: dict) -> Settings:
    return _settings_for_yaml(tmp_path, yaml.safe_dump(document, sort_keys=False))


def _settings_for_committed_document(tmp_path: Path, document: dict) -> Settings:
    committed_path = tmp_path / "tee_measurements.committed.yaml"
    committed_path.write_text(yaml.safe_dump(document, sort_keys=False))
    settings = Settings()
    settings.tee_committed_measurement_config_path = committed_path
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    return settings


def _tdx_group(
    *,
    version: str = "1",
    name: str = "cpu-gcp",
    provider: str | None = "gcp",
    debug: bool = False,
    rc: bool = False,
    rtmr0: object = HEX96_RTMR0,
    expected_gpus: object = None,
    gpu_count: object = 0,
    boot_rtmr3: object = _ABSENT,
    image_sha256: object = _ABSENT,
    image_measurement_names: object = _ABSENT,
) -> dict:
    group = {
        "version": version,
        "tee_type": "tdx",
        "debug": debug,
        "rc": rc,
        "mrtd": HEX96_MRTD,
        "rtmr1": HEX96_RTMR1,
        "rtmr2": HEX96_RTMR2,
        "runtime_rtmr3": HEX96_RTMR3,
        "hardware": [
            {
                "name": name,
                "rtmr0": rtmr0,
                "expected_gpus": [] if expected_gpus is None else expected_gpus,
                "gpu_count": gpu_count,
            }
        ],
    }
    if provider is not None:
        group["provider"] = provider
    if boot_rtmr3 is not _ABSENT:
        group["boot_rtmr3"] = boot_rtmr3
    if image_sha256 is not _ABSENT:
        group["image_sha256"] = image_sha256
    if image_measurement_names is not _ABSENT:
        group["image_measurement_names"] = image_measurement_names
    return group


def _direct_tdx_group(*hardware: dict) -> dict:
    return {
        "version": "1.9.1",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "debug": False,
        "mrtd": HEX96_MRTD,
        "runtime_rtmr3": HEX96_RTMR3,
        "hardware": list(hardware),
    }


def _direct_tdx_variant(
    *,
    name: str = "cpu-baremetal-tdx-1.9.1-1vcpu-8g",
    profile_id: str = "1vcpu-8g",
    vcpus: int = 1,
    memory_mib: int = 8192,
) -> dict:
    return {
        "name": name,
        "profile_id": profile_id,
        "vcpus": vcpus,
        "memory_mib": memory_mib,
        "rtmr0": HEX96_RTMR0,
        "rtmr1": HEX96_RTMR1,
        "rtmr2": HEX96_RTMR2,
        "expected_gpus": [],
        "gpu_count": 0,
    }


def _direct_gpu_group() -> dict:
    names = [
        "gpu-baremetal-tdx-1.11.0-b200-8gpu-platform",
        "gpu-baremetal-tdx-1.11.0-b200-8gpu-miner",
    ]
    hardware = []
    for index, (name, mode) in enumerate(zip(names, ("platform", "miner"), strict=True)):
        hardware.append(
            {
                "name": name,
                "gpu_profile_id": "b200-8gpu",
                "management_mode": mode,
                "mrtd": HEX96_MRTD,
                "rtmr0": chr(ord("A") + index) * 96,
                "rtmr1": HEX96_RTMR1,
                "rtmr2": chr(ord("C") + index) * 96,
                "boot_rtmr3": "0" * 96,
                "runtime_rtmr3": HEX96_RTMR3,
                "expected_gpus": ["b200"],
                "gpu_count": 8,
                "gpu_measurement_fingerprint": str(index + 1) * 64,
            }
        )
    return {
        "version": "1.11.0",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "compute_type": "gpu",
        "role": "gpu",
        "debug": False,
        "rc": True,
        "provenance_schema_version": 3,
        "gpu_fingerprint_version": 1,
        "profile_contract_sha256": "a" * 64,
        "image_sha256": "b" * 64,
        "image_measurement_names": names,
        "hardware": hardware,
    }


def _snp_group(
    *,
    version: str = "1",
    name: str = "cpu-snp",
    provider: str = "bare-metal",
    debug: bool = False,
    rc: bool = False,
    measurement: object = HEX96_SNP,
    policy: object = "0x30000",
    min_tcb: object = None,
    expected_vmpl: object = 0,
    processor_model: object = "Genoa",
    id_key_digest: object = _ABSENT,
    expected_gpus: object = None,
    gpu_count: object = 0,
    image_sha256: object = _ABSENT,
    image_measurement_names: object = _ABSENT,
) -> dict:
    group = {
        "version": version,
        "tee_type": "sev-snp",
        "provider": provider,
        "processor_model": processor_model,
        "debug": debug,
        "rc": rc,
        "policy": policy,
        "min_tcb": (
            {
                "bootloader": 7,
                "tee": 0,
                "snp": 23,
                "microcode": 72,
            }
            if min_tcb is None
            else min_tcb
        ),
        "expected_vmpl": expected_vmpl,
        "hardware": [
            {
                "name": name,
                "measurement": measurement,
                "expected_gpus": [] if expected_gpus is None else expected_gpus,
                "gpu_count": gpu_count,
            }
        ],
    }
    if provider == "gcp":
        group["vtpm_pcrs"] = {"8": HEX64_PCR, "9": HEX64_PCR}
        group["vtpm_security_flags"] = {
            "2": True,
            "3": False,
            "4": False,
            "5": False,
        }
    if id_key_digest is not _ABSENT:
        group["id_key_digest"] = id_key_digest
    if image_sha256 is not _ABSENT:
        group["image_sha256"] = image_sha256
    if image_measurement_names is not _ABSENT:
        group["image_measurement_names"] = image_measurement_names
    return group


def _committed_snp_group(
    *,
    name: str = "cpu-snp",
    measurement: str = HEX96_SNP,
    image_names: list[str] | None = None,
) -> dict:
    names = image_names or [name]
    return _snp_group(
        name=name,
        measurement=measurement,
        image_sha256="a" * 64,
        image_measurement_names=names,
    )


def _committed_snp_matrix_document() -> dict:
    names = [f"cpu-baremetal-snp-genoa-2.0.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)]
    groups = [
        _snp_group(
            version=f"2.0.0-snp-{vcpus}vcpu",
            name=name,
            measurement=f"{index:X}" * 96,
            image_sha256="a" * 64,
            image_measurement_names=names,
        )
        for index, (name, vcpus) in enumerate(zip(names, (1, 2, 4, 8), strict=True), start=1)
    ]
    return _document(*groups)


def test_nested_tdx_flattens_hardware_into_scalar_runtime_model(tmp_path):
    group = _tdx_group()
    group["hardware"].append(
        {
            "name": "cpu-gcp-second",
            "description": "second topology",
            "rtmr0": "9" * 96,
            "expected_gpus": [],
            "gpu_count": 0,
        }
    )
    settings = _settings_for_document(tmp_path, _document(group))

    first, second = settings._load_tee_measurements()

    assert first.name == "cpu-gcp"
    assert first.mrtd == HEX96_MRTD
    assert first.rtmr0 == HEX96_RTMR0
    assert second.name == "cpu-gcp-second"
    assert second.rtmr0 == "9" * 96
    assert first.boot_rtmrs["RTMR3"] == "0" * 96
    assert first.runtime_rtmrs["RTMR3"] == HEX96_RTMR3


def test_nested_direct_tdx_profiles_bind_vcpu_ram_and_variant_rtmrs(tmp_path):
    group = {
        "version": "1.9.0",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "debug": False,
        "mrtd": HEX96_MRTD,
        "runtime_rtmr3": HEX96_RTMR3,
        "hardware": [
            {
                "name": "cpu-baremetal-tdx-1.9.0-1vcpu-8g",
                "profile_id": "1vcpu-8g",
                "vcpus": 1,
                "memory_mib": 8192,
                "rtmr0": HEX96_RTMR0,
                "rtmr1": HEX96_RTMR1,
                "rtmr2": HEX96_RTMR2,
                "expected_gpus": [],
                "gpu_count": 0,
            },
            {
                "name": "cpu-baremetal-tdx-1.9.0-2vcpu-16g",
                "profile_id": "2vcpu-16g",
                "vcpus": 2,
                "memory_mib": 16384,
                "rtmr0": "8" * 96,
                "rtmr1": "9" * 96,
                "rtmr2": "A" * 96,
                "expected_gpus": [],
                "gpu_count": 0,
            },
        ],
    }
    settings = _settings_for_document(tmp_path, _document(group))

    first, second = settings._load_tee_measurements()

    assert (first.profile_id, first.vcpus, first.memory_mib) == (
        "1vcpu-8g",
        1,
        8192,
    )
    assert (second.profile_id, second.vcpus, second.memory_mib) == (
        "2vcpu-16g",
        2,
        16384,
    )
    assert first.version == "1.9.0-tdx-1vcpu-8g"
    assert second.version == "1.9.0-tdx-2vcpu-16g"
    assert first.rtmr1 != second.rtmr1


def test_nested_direct_tdx_storage_profile_gets_role_qualified_version(tmp_path):
    group = {
        "version": "1.9.0",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "debug": False,
        "mrtd": HEX96_MRTD,
        "runtime_rtmr3": HEX96_RTMR3,
        "hardware": [
            {
                "name": "storage-baremetal-tdx-1.9.0-2vcpu-8g",
                "profile_id": "2vcpu-8g",
                "vcpus": 2,
                "memory_mib": 8192,
                "rtmr0": HEX96_RTMR0,
                "rtmr1": HEX96_RTMR1,
                "rtmr2": HEX96_RTMR2,
                "expected_gpus": [],
                "gpu_count": 0,
            }
        ],
    }
    settings = _settings_for_document(tmp_path, _document(group))

    (measurement,) = settings._load_tee_measurements()

    assert measurement.version == "1.9.0-storage-tdx-2vcpu-8g"


def test_nested_direct_gpu_matrix_loads_separate_versioned_fingerprints(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_direct_gpu_group()),
    )

    platform, miner = settings._load_tee_measurements()

    assert platform.compute_type == miner.compute_type == "gpu"
    assert platform.role == miner.role == "gpu"
    assert (platform.management_mode, miner.management_mode) == ("platform", "miner")
    assert platform.gpu_profile_id == miner.gpu_profile_id == "b200-8gpu"
    assert platform.rtmr2 != miner.rtmr2
    assert platform.gpu_measurement_fingerprint == "1" * 64
    assert miner.gpu_measurement_fingerprint == "2" * 64
    assert measurement_config_fingerprint(platform) != measurement_config_fingerprint(miner)


def test_computed_boot_floor_is_compute_scoped(tmp_path, monkeypatch):
    monkeypatch.delenv("TEE_MINIMUM_BOOT_VERSION", raising=False)
    monkeypatch.delenv("TEE_GPU_MINIMUM_BOOT_VERSION", raising=False)
    cpu = _tdx_group(version="1.10.0", name="cpu-gcp-1.10.0")
    gpu = _direct_gpu_group()
    gpu["version"] = "9.0.0"
    gpu["rc"] = False
    gpu["image_measurement_names"] = [
        name.replace("1.11.0", "9.0.0") for name in gpu["image_measurement_names"]
    ]
    for item, name in zip(
        gpu["hardware"],
        gpu["image_measurement_names"],
        strict=True,
    ):
        item["name"] = name
    settings = _settings_for_document(tmp_path, _document(cpu, gpu))

    assert settings.tee_minimum_boot_version == "1.10.0"
    assert settings.tee_minimum_boot_version_for("cpu") == "1.10.0"
    assert settings.tee_minimum_boot_version_for("gpu") == "9.0.0"


@pytest.mark.parametrize("mutation", ["missing", "unknown", "partial-mode"])
def test_nested_direct_gpu_matrix_fails_closed_on_schema_drift(
    tmp_path,
    mutation,
):
    group = _direct_gpu_group()
    if mutation == "missing":
        del group["hardware"][0]["gpu_measurement_fingerprint"]
    elif mutation == "unknown":
        group["hardware"][0]["legacy_profile"] = "b200"
    else:
        group["hardware"].pop()
        group["image_measurement_names"].pop()
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError):
        settings._load_tee_measurements()


def test_nested_direct_tdx_rejects_name_profile_contradiction(tmp_path):
    group = _direct_tdx_group(_direct_tdx_variant(name="cpu-baremetal-tdx-1.9.1-2vcpu-16g"))
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="contradicts profile"):
        settings._load_tee_measurements()


def test_nested_direct_tdx_rejects_duplicate_profile_identity(tmp_path):
    variant = _direct_tdx_variant()
    group = _direct_tdx_group(variant, deepcopy(variant))
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="duplicate direct-TDX"):
        settings._load_tee_measurements()


def test_nested_tdx_accepts_explicit_nonzero_boot_rtmr3(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(
            _tdx_group(
                name="cpu-baremetal",
                provider="bare-metal",
                boot_rtmr3=HEX96_RTMR3,
            )
        ),
    )

    (measurement,) = settings._load_tee_measurements()

    assert measurement.boot_rtmrs["RTMR3"] == HEX96_RTMR3
    assert measurement.runtime_rtmrs["RTMR3"] == HEX96_RTMR3


def test_rejects_current_flat_scalar_source_without_dual_parsing(tmp_path):
    flat = {
        "version": "1",
        "name": "cpu-gcp",
        "provider": "gcp",
        "tee_type": "tdx",
        "debug": False,
        "mrtd": HEX96_MRTD,
        "rtmr0": HEX96_RTMR0,
        "rtmr1": HEX96_RTMR1,
        "rtmr2": HEX96_RTMR2,
        "runtime_rtmr3": HEX96_RTMR3,
        "expected_gpus": [],
        "gpu_count": 0,
    }
    settings = _settings_for_document(tmp_path, _document(flat))

    with pytest.raises(ValueError, match="flat scalar"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("legacy_key", ["boot_rtmrs", "runtime_rtmrs"])
def test_rejects_old_boot_runtime_map_format(tmp_path, legacy_key):
    group = _tdx_group()
    group[legacy_key] = {"rtmr0": HEX96_RTMR0}
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="old boot/runtime map"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "yaml_text",
    [
        "measurements: []\n",
        "revoked_measurements: []\n",
        "measurements: []\nrevoked_measurements: []\nextra: true\n",
        "null\n",
    ],
)
def test_root_requires_exact_document_shape(tmp_path, yaml_text):
    settings = _settings_for_yaml(tmp_path, yaml_text)

    with pytest.raises(ValueError, match="document"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "document",
    [
        {"measurements": {}, "revoked_measurements": []},
        {"measurements": [], "revoked_measurements": None},
        {"measurements": [1], "revoked_measurements": []},
    ],
)
def test_root_members_require_explicit_types(tmp_path, document):
    settings = _settings_for_document(tmp_path, document)

    with pytest.raises(ValueError):
        settings._load_tee_measurements()


def test_duplicate_yaml_keys_are_rejected_before_overwrite(tmp_path):
    settings = _settings_for_yaml(
        tmp_path,
        "measurements: []\nmeasurements: []\nrevoked_measurements: []\n",
    )

    with pytest.raises(ValueError, match="duplicate YAML key 'measurements'"):
        settings._load_tee_measurements()


def test_empty_hardware_list_rejected(tmp_path):
    group = _tdx_group()
    group["hardware"] = []
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="non-empty 'hardware'"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("alias", ["snp", "amd-snp", "SEV-SNP", "sgx"])
def test_tee_type_aliases_and_unknown_values_rejected(tmp_path, alias):
    group = _snp_group()
    group["tee_type"] = alias
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="exactly 'tdx' or 'sev-snp'"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("version",), 1, "version"),
        (("tee_type",), None, "tee_type"),
        (("provider",), "GCP", "provider"),
        (("debug",), "false", "debug"),
        (("rc",), 0, "rc"),
        (("mrtd",), 1, "mrtd"),
        (("hardware", 0, "rtmr0"), 1, "rtmr0"),
        (("hardware", 0, "expected_gpus"), "h200", "expected_gpus"),
        (("hardware", 0, "gpu_count"), False, "gpu_count"),
    ],
)
def test_tdx_explicit_values_use_strict_yaml_types(tmp_path, path, value, message):
    group = _tdx_group()
    target = group
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match=message):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"policy": True}, "policy"),
        ({"policy": 3.0}, "policy"),
        ({"processor_model": 1}, "processor_model"),
        ({"expected_vmpl": "0"}, "expected_vmpl"),
        ({"id_key_digest": None}, "id_key_digest"),
    ],
)
def test_snp_explicit_values_use_strict_yaml_types(tmp_path, mutation, message):
    group = _snp_group()
    group.update(mutation)
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match=message):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("tee_type", "wrong_field"),
    [
        ("tdx", "measurement"),
        ("sev-snp", "rtmr0"),
    ],
)
def test_hardware_variant_rejects_other_tee_measurement_field(tmp_path, tee_type, wrong_field):
    group = _tdx_group() if tee_type == "tdx" else _snp_group()
    group["hardware"][0][wrong_field] = HEX96_RTMR0
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="unsupported"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("field", ["name", "expected_gpus", "gpu_count", "rtmr0"])
def test_tdx_hardware_requires_every_canonical_field(tmp_path, field):
    group = _tdx_group()
    del group["hardware"][0][field]
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="missing required"):
        settings._load_tee_measurements()


def test_normalized_duplicate_hardware_names_rejected_across_groups(tmp_path):
    first = _tdx_group(name="cpu-gcp")
    second = _tdx_group(name=" cpu-gcp ", version="2")
    settings = _settings_for_document(tmp_path, _document(first, second))

    with pytest.raises(ValueError, match="duplicate normalized measurement name"):
        settings._load_tee_measurements()


def test_duplicate_normalized_revocations_rejected_within_source(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(revoked=["future-pin", " future-pin "]),
    )

    with pytest.raises(ValueError, match="duplicate normalized revocation"):
        settings._load_tee_measurements()


def test_unknown_revocation_tombstone_is_preserved_without_error(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_tdx_group(), revoked=["not-loaded-yet"]),
    )

    assert [config.name for config in settings._load_tee_measurements()] == ["cpu-gcp"]


def test_release_candidate_is_attestable_but_not_minimum_version(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(
            _tdx_group(version="1.3.0", name="cpu-stable", rc=False),
            _tdx_group(version="9.0.0", name="cpu-rc", rc=True),
        ),
    )

    assert [entry.rc for entry in settings.tee_measurements] == [False, True]
    assert settings.tee_minimum_boot_version == "1.3.0"


def test_release_candidate_promotion_does_not_change_trust_identity():
    common = {
        "version": "1.3.0",
        "name": "cpu-gcp",
        "provider": "gcp",
        "tee_type": "tdx",
        "debug": False,
        "mrtd": HEX96_MRTD,
        "rtmr0": HEX96_RTMR0,
        "rtmr1": HEX96_RTMR1,
        "rtmr2": HEX96_RTMR2,
        "runtime_rtmr3": HEX96_RTMR3,
        "expected_gpus": [],
        "gpu_count": 0,
    }
    candidate = TeeMeasurementConfig(**common, rc=True)
    released = TeeMeasurementConfig(**common, rc=False)

    assert measurement_config_fingerprint(candidate) == measurement_config_fingerprint(released)
    assert measurement_trust_set_fingerprint([candidate]) == measurement_trust_set_fingerprint(
        [released]
    )


def test_gpu_tdx_group_may_omit_provider(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(
            _tdx_group(
                provider=None,
                name="8xh200",
                expected_gpus=["H200"],
                gpu_count=8,
            )
        ),
    )

    (gpu,) = settings._load_tee_measurements()

    assert gpu.provider is None
    assert gpu.expected_gpus == ["h200"]
    assert gpu.gpu_count == 8


def test_cpu_group_requires_provider(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_tdx_group(provider=None)),
    )

    with pytest.raises(ValueError, match="must set provider"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("gpu_count", "expected_gpus"),
    [
        (-1, []),
        ("0", []),
        (0, ["h200"]),
        (8, []),
        (8, ["h200", "H200"]),
    ],
)
def test_gpu_inventory_is_explicit_and_consistent(tmp_path, gpu_count, expected_gpus):
    settings = _settings_for_document(
        tmp_path,
        _document(
            _tdx_group(
                provider=None if gpu_count == 8 else "gcp",
                gpu_count=gpu_count,
                expected_gpus=expected_gpus,
            )
        ),
    )

    with pytest.raises(ValueError):
        settings._load_tee_measurements()


def test_snp_complete_group_loads(tmp_path):
    settings = _settings_for_document(tmp_path, _document(_snp_group()))

    (config,) = settings._load_tee_measurements()

    assert config.tee_type == "sev-snp"
    assert config.measurement == HEX96_SNP
    assert config.policy == 0x30000
    assert config.min_tcb == {"bootloader": 7, "tee": 0, "snp": 23, "microcode": 72}
    assert config.expected_vmpl == 0


@pytest.mark.parametrize("field", ["processor_model", "policy", "min_tcb", "expected_vmpl"])
def test_snp_requires_all_shared_security_fields(tmp_path, field):
    group = _snp_group()
    del group[field]
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="missing required"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (key, value)
        for key in ("bootloader", "tee", "snp", "microcode")
        for value in (True, False, 7.0, "7", None, -1, 256)
    ],
)
def test_snp_tcb_components_require_bounded_yaml_integers(tmp_path, key, value):
    group = _snp_group()
    group["min_tcb"][key] = value
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="min_tcb"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "min_tcb",
    [
        {"bootloader": 7},
        {"bootloader": 7, "tee": 0, "snp": 23, "microcode": 72, "extra": 1},
        {1: 7, "tee": 0, "snp": 23, "microcode": 72},
        {"Bootloader": 7, "tee": 0, "snp": 23, "microcode": 72},
    ],
)
def test_snp_tcb_requires_exact_lowercase_key_set(tmp_path, min_tcb):
    settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(min_tcb=min_tcb)),
    )

    with pytest.raises(ValueError, match="min_tcb"):
        settings._load_tee_measurements()


def test_duplicate_yaml_tcb_key_rejected(tmp_path):
    source = f"""
measurements:
  - version: "1"
    tee_type: "sev-snp"
    provider: "bare-metal"
    processor_model: "Genoa"
    debug: false
    policy: "0x30000"
    min_tcb:
      bootloader: 7
      tee: 0
      snp: 23
      microcode: 72
      bootloader: 8
    expected_vmpl: 0
    hardware:
      - name: "cpu-snp"
        measurement: "{HEX96_SNP}"
        expected_gpus: []
        gpu_count: 0
revoked_measurements: []
"""
    settings = _settings_for_yaml(tmp_path, source)

    with pytest.raises(ValueError, match="duplicate YAML key 'bootloader'"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("vmpl", [-1, 4, True, "0"])
def test_snp_vmpl_requires_observed_bounded_integer(tmp_path, vmpl):
    settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(expected_vmpl=vmpl)),
    )

    with pytest.raises(ValueError, match="expected_vmpl"):
        settings._load_tee_measurements()


def test_gcp_snp_exact_vtpm_sets_load(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(provider="gcp", processor_model="Milan")),
    )

    (config,) = settings._load_tee_measurements()

    assert config.vtpm_pcrs == {"8": HEX64_PCR, "9": HEX64_PCR}
    assert config.vtpm_security_flags == {
        "2": True,
        "3": False,
        "4": False,
        "5": False,
    }


@pytest.mark.parametrize(
    "pcrs",
    [
        {"8": HEX64_PCR},
        {"8": HEX64_PCR, "9": HEX64_PCR, "10": HEX64_PCR},
        {8: HEX64_PCR, 9: HEX64_PCR},
        {"8": 1, "9": HEX64_PCR},
        {"8": "1" * 63, "9": HEX64_PCR},
    ],
)
def test_gcp_snp_requires_exact_string_pcr8_pcr9_set(tmp_path, pcrs):
    group = _snp_group(provider="gcp")
    group["vtpm_pcrs"] = pcrs
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="vtpm_pcrs"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    "flags",
    [
        {"2": True, "3": False, "4": False},
        {"2": True, "3": False, "4": False, "5": False, "6": False},
        {2: True, 3: False, 4: False, 5: False},
        {"2": True, "3": False, "4": False, "5": "false"},
    ],
)
def test_gcp_snp_requires_exact_boolean_string_flag_set(tmp_path, flags):
    group = _snp_group(provider="gcp")
    group["vtpm_security_flags"] = flags
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="vtpm_security_flags"):
        settings._load_tee_measurements()


@pytest.mark.parametrize("field", ["vtpm_pcrs", "vtpm_security_flags"])
def test_baremetal_snp_rejects_gcp_only_fields(tmp_path, field):
    group = _snp_group()
    group[field] = (
        {"8": HEX64_PCR, "9": HEX64_PCR}
        if field == "vtpm_pcrs"
        else {"2": True, "3": False, "4": False, "5": False}
    )
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match="unsupported"):
        settings._load_tee_measurements()


def test_gcp_security_flag_flip_changes_measurement_fingerprint(tmp_path):
    first_settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(provider="gcp")),
    )
    (first,) = first_settings._load_tee_measurements()
    second_group = _snp_group(provider="gcp")
    second_group["vtpm_security_flags"]["2"] = False
    second_settings = _settings_for_document(tmp_path, _document(second_group))
    (second,) = second_settings._load_tee_measurements()

    assert first.config_fingerprint != second.config_fingerprint
    assert first.trust_set_fingerprint != second.trust_set_fingerprint


def test_debug_measurement_requires_explicit_dev_opt_in(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(debug=True)),
    )
    settings.allow_debug_measurements = False

    with pytest.raises(ValueError, match="ALLOW_DEBUG_MEASUREMENTS"):
        settings._load_tee_measurements()


def test_debug_measurement_loads_with_explicit_dev_opt_in(tmp_path):
    settings = _settings_for_document(
        tmp_path,
        _document(_snp_group(debug=True)),
    )
    settings.allow_debug_measurements = True

    assert settings._load_tee_measurements()[0].debug is True


def test_debug_measurement_opt_in_rejected_outside_dev_posture():
    with pytest.raises(ValueError, match="permitted only in the explicit dev posture"):
        Settings(
            allow_debug_measurements=True,
            skip_metagraph_check=False,
            operator_endpoint_cidrs=["127.0.0.0/8"],
            require_mtls_client_verify=True,
        )


def test_image_provenance_names_preserve_source_order(tmp_path):
    names = ["cpu-b", "cpu-a"]
    groups = [
        _tdx_group(
            version=str(index),
            name=name,
            rtmr0=str(index) * 96,
            image_sha256="a" * 64,
            image_measurement_names=names,
        )
        for index, name in enumerate(names, start=1)
    ]
    settings = _settings_for_document(tmp_path, _document(*groups))

    assert [config.image_measurement_names for config in settings._load_tee_measurements()] == [
        names,
        names,
    ]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("debug", True),
        ("rc", True),
        ("provider", "bare-metal"),
    ],
)
def test_provenance_set_requires_common_shared_fields_equal(tmp_path, field, replacement):
    names = ["cpu-a", "cpu-b"]
    first = _tdx_group(
        name=names[0],
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second = _tdx_group(
        version="2",
        name=names[1],
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second[field] = replacement
    settings = _settings_for_document(tmp_path, _document(first, second))
    settings.allow_debug_measurements = True

    with pytest.raises(ValueError, match="Inconsistent image provenance"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("mrtd", "1" * 96),
        ("rtmr1", "2" * 96),
        ("rtmr2", "3" * 96),
        ("boot_rtmr3", "4" * 96),
        ("runtime_rtmr3", "5" * 96),
    ],
)
def test_tdx_provenance_set_requires_all_shared_measurements_equal(tmp_path, field, replacement):
    names = ["cpu-a", "cpu-b"]
    first = _tdx_group(
        name=names[0],
        image_sha256="a" * 64,
        image_measurement_names=names,
        boot_rtmr3=HEX96_RTMR3,
    )
    second = _tdx_group(
        version="2",
        name=names[1],
        rtmr0="9" * 96,
        image_sha256="a" * 64,
        image_measurement_names=names,
        boot_rtmr3=HEX96_RTMR3,
    )
    second[field] = replacement
    settings = _settings_for_document(tmp_path, _document(first, second))

    with pytest.raises(ValueError, match="Inconsistent image provenance"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("processor_model", "Milan"),
        ("policy", "0x30001"),
        (
            "min_tcb",
            {"bootloader": 8, "tee": 0, "snp": 23, "microcode": 72},
        ),
        ("expected_vmpl", 1),
        ("id_key_digest", "1" * 96),
    ],
)
def test_snp_provenance_set_requires_all_shared_measurements_equal(tmp_path, field, replacement):
    names = ["cpu-a", "cpu-b"]
    first = _snp_group(
        name=names[0],
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second = _snp_group(
        version="2",
        name=names[1],
        measurement="9" * 96,
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second[field] = replacement
    settings = _settings_for_document(tmp_path, _document(first, second))

    with pytest.raises(ValueError, match="Inconsistent image provenance"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("field", "key", "replacement"),
    [
        ("vtpm_pcrs", "8", "2" * 64),
        ("vtpm_security_flags", "2", False),
    ],
)
def test_gcp_snp_provenance_set_requires_shared_vtpm_fields_equal(
    tmp_path, field, key, replacement
):
    names = ["cpu-a", "cpu-b"]
    first = _snp_group(
        provider="gcp",
        name=names[0],
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second = _snp_group(
        provider="gcp",
        version="2",
        name=names[1],
        measurement="9" * 96,
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second[field][key] = replacement
    settings = _settings_for_document(tmp_path, _document(first, second))

    with pytest.raises(ValueError, match="Inconsistent image provenance"):
        settings._load_tee_measurements()


def test_provenance_matrix_keeps_distinct_versions_and_variant_measurements(tmp_path):
    names = ["cpu-a", "cpu-b"]
    first = _snp_group(
        version="2.0.0-snp-1vcpu",
        name=names[0],
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    second = _snp_group(
        version="2.0.0-snp-2vcpu",
        name=names[1],
        measurement="9" * 96,
        image_sha256="a" * 64,
        image_measurement_names=names,
    )
    settings = _settings_for_document(tmp_path, _document(first, second))

    measurements = settings._load_tee_measurements()

    assert [config.version for config in measurements] == [
        "2.0.0-snp-1vcpu",
        "2.0.0-snp-2vcpu",
    ]
    assert [config.measurement for config in measurements] == [HEX96_SNP, "9" * 96]


def test_mounted_override_replaces_committed_entry_atomically(tmp_path):
    committed = _committed_snp_group()
    settings = _settings_for_committed_document(tmp_path, _document(committed))
    mounted_path = tmp_path / "mounted.yaml"
    override = _committed_snp_group(measurement="9" * 96)
    mounted_path.write_text(yaml.safe_dump(_document(override), sort_keys=False))
    settings.tee_measurement_config_path = mounted_path

    (config,) = settings._load_tee_measurements()

    assert config.measurement == "9" * 96


def test_mounted_override_never_inherits_missing_committed_fields(tmp_path):
    committed = _committed_snp_group()
    settings = _settings_for_committed_document(tmp_path, _document(committed))
    mounted_path = tmp_path / "mounted.yaml"
    override = _committed_snp_group(measurement="9" * 96)
    del override["min_tcb"]
    mounted_path.write_text(yaml.safe_dump(_document(override), sort_keys=False))
    settings.tee_measurement_config_path = mounted_path

    with pytest.raises(ValueError, match="missing required"):
        settings._load_tee_measurements()


def test_mounted_override_of_committed_pin_requires_complete_provenance(tmp_path):
    committed = _committed_snp_group()
    settings = _settings_for_committed_document(tmp_path, _document(committed))
    mounted_path = tmp_path / "mounted.yaml"
    mounted_path.write_text(yaml.safe_dump(_document(_snp_group()), sort_keys=False))
    settings.tee_measurement_config_path = mounted_path

    with pytest.raises(ValueError, match="Missing image provenance for committed"):
        settings._load_tee_measurements()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"image_sha256": "a" * 64}, "Incomplete image provenance"),
        (
            {
                "image_sha256": 1,
                "image_measurement_names": ["cpu-snp"],
            },
            "image_sha256",
        ),
        (
            {
                "image_sha256": "a" * 64,
                "image_measurement_names": ["cpu-snp", " cpu-snp "],
            },
            "duplicate normalized names",
        ),
        (
            {
                "image_sha256": "a" * 64,
                "image_measurement_names": ["cpu-snp", "unknown"],
            },
            "every declared entry",
        ),
    ],
)
def test_malformed_image_provenance_rejected(tmp_path, mutation, message):
    group = _snp_group()
    group.update(mutation)
    settings = _settings_for_document(tmp_path, _document(group))

    with pytest.raises(ValueError, match=message):
        settings._load_tee_measurements()


def test_actual_committed_measurements_preserve_count_values_and_fingerprints(tmp_path):
    committed_path = (
        Path(__file__).resolve().parents[2] / "api/config/tee_measurements.committed.yaml"
    )
    source = yaml.safe_load(committed_path.read_text())
    assert set(source) == {"measurements", "revoked_measurements"}
    assert len(source["measurements"]) == 21
    assert sum(len(group["hardware"]) for group in source["measurements"]) == 21
    assert source["revoked_measurements"] == []

    settings = Settings()
    settings.tee_committed_measurement_config_path = committed_path
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    settings.allow_debug_measurements = True

    measurements = settings._load_tee_measurements()
    committed_tdx = next(
        config for config in measurements if config.name == "storage-baremetal-tdx-1.6.0-4vcpu"
    )

    assert len(measurements) == 21
    assert settings.tee_measurements_fingerprint == TRUST_FINGERPRINT
    assert committed_tdx.config_fingerprint == COMMITTED_TDX_FINGERPRINT
    assert committed_tdx.boot_rtmr3 == committed_tdx.runtime_rtmr3
    assert committed_tdx.boot_rtmr3 != "0" * 96

    by_digest: dict[str, set[str]] = {}
    for measurement in measurements:
        assert measurement.image_sha256
        assert measurement.image_measurement_names
        by_digest.setdefault(measurement.image_sha256, set()).add(measurement.name)
    for measurement in measurements:
        assert list(measurement.image_measurement_names or [])
        assert set(measurement.image_measurement_names or []) == by_digest[measurement.image_sha256]


def test_actual_committed_debug_measurements_rejected_in_production(tmp_path):
    settings = Settings()
    settings.tee_committed_measurement_config_path = (
        Path(__file__).resolve().parents[2] / "api/config/tee_measurements.committed.yaml"
    )
    settings.tee_measurement_config_path = tmp_path / "no-mounted-measurements.yaml"
    settings.allow_debug_measurements = False

    with pytest.raises(ValueError, match="ALLOW_DEBUG_MEASUREMENTS"):
        settings._load_tee_measurements()


def test_malformed_measurement_source_fails_closed(tmp_path):
    settings = _settings_for_yaml(
        tmp_path,
        "measurements:\n  - image_sha256: [\nrevoked_measurements: []\n",
    )

    with pytest.raises(ValueError, match="Failed to load TEE measurement config"):
        settings._load_tee_measurements()


def test_required_mounted_source_cannot_silently_disappear(tmp_path):
    settings = _settings_for_committed_document(
        tmp_path,
        _document(_committed_snp_group()),
    )
    settings.tee_measurement_config_required = True

    with pytest.raises(ValueError, match="Required TEE measurement config"):
        settings._load_tee_measurements()


def test_revocation_tombstone_survives_failed_reload_via_last_known_good(tmp_path):
    settings = _settings_for_committed_document(
        tmp_path,
        _document(_committed_snp_group()),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text(yaml.safe_dump(_document(revoked=["cpu-snp"]), sort_keys=False))
    settings.tee_measurement_config_path = mounted

    assert settings._load_tee_measurements() == []

    mounted.write_text("measurements:\n  - invalid: [\nrevoked_measurements: []\n")
    assert settings._load_tee_measurements() == []
    assert settings._tee_measurements_last_error


def test_runtime_missing_expected_source_retains_last_good_and_degrades(tmp_path):
    settings = _settings_for_committed_document(
        tmp_path,
        _document(_committed_snp_group()),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text(yaml.safe_dump(_document(), sort_keys=False))
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
    committed.write_text(yaml.safe_dump(_document(_committed_snp_group()), sort_keys=False))
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text("measurements:\n  - malformed: [\nrevoked_measurements: []\n")

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
    settings = _settings_for_committed_document(
        tmp_path,
        _document(_committed_snp_group()),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text(yaml.safe_dump(_document(), sort_keys=False))
    settings.tee_measurement_config_path = mounted
    settings.tee_measurement_config_required = True

    (config,) = settings._load_tee_measurements()
    before = settings.tee_measurements_fingerprint
    assert config.config_fingerprint
    assert config.trust_set_fingerprint == before

    mounted.write_text(yaml.safe_dump(_document(revoked=["cpu-snp"]), sort_keys=False))
    assert settings._load_tee_measurements() == []
    assert settings.tee_measurements_fingerprint != before
    assert settings.tee_measurement_health()["status"] == "healthy"


def test_one_matrix_tombstone_atomically_retires_complete_set(tmp_path):
    settings = _settings_for_committed_document(
        tmp_path,
        _committed_snp_matrix_document(),
    )
    mounted = tmp_path / "mounted.yaml"
    mounted.write_text(yaml.safe_dump(_document(), sort_keys=False))
    settings.tee_measurement_config_path = mounted
    settings.tee_measurement_config_required = True

    before_configs = settings._load_tee_measurements()
    before_fingerprint = settings.tee_measurements_fingerprint
    expected_names = [f"cpu-baremetal-snp-genoa-2.0.0-{vcpus}vcpu" for vcpus in (1, 2, 4, 8)]
    assert [config.name for config in before_configs] == expected_names

    mounted.write_text(yaml.safe_dump(_document(revoked=[expected_names[1]]), sort_keys=False))
    assert settings._load_tee_measurements() == []
    retired_fingerprint = settings.tee_measurements_fingerprint
    assert retired_fingerprint != before_fingerprint

    mounted.write_text("measurements:\n  - malformed: [\nrevoked_measurements: []\n")
    assert settings._load_tee_measurements() == []
    assert settings.tee_measurements_fingerprint == retired_fingerprint
    assert settings._tee_measurements_last_error


def test_test_helpers_do_not_share_mutable_groups():
    first = _snp_group()
    second = _snp_group()
    first["min_tcb"]["bootloader"] = 99

    assert second == deepcopy(_snp_group())
