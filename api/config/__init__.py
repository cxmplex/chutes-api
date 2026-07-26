"""
Application-wide settings.
"""

import os
import hashlib
import ipaddress
import re
from pathlib import Path
import aioboto3
import json
import yaml
from yaml.constructor import ConstructorError
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from api.safe_redis import SafeRedis
from functools import cached_property, lru_cache
import redis.asyncio as redis
from redis.retry import Retry
from redis.backoff import ConstantBackoff
from boto3.session import Config
from typing import Annotated, Dict, List, Optional
from bittensor_wallet.keypair import Keypair
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from contextlib import asynccontextmanager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet
from loguru import logger
from api.semver_util import semcomp


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys before values are overwritten."""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate YAML key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@lru_cache(maxsize=1)
def load_launch_config_private_key():
    if (path := os.getenv("LAUNCH_CONFIG_PRIVATE_KEY_PATH")) is not None:
        with open(path, "rb") as infile:
            return infile.read()
    return None


_CHUTEFS_FRAME_PLAINTEXT_BYTES = 1024 * 1024
_CHUTEFS_FIXED_CIPHERTEXT_BYTES = 48
_CHUTEFS_PER_DATA_FRAME_BYTES = 20
MAX_SNP_CRL_OUTAGE_GRACE_SECONDS = 3600
ZERO_RTMR = "0" * 96


def _max_plaintext_for_ciphertext_limit(ciphertext_limit: int) -> int:
    """Largest v4 plaintext whose exact framed ciphertext fits the node limit."""
    low = 0
    high = max(0, ciphertext_limit)
    while low < high:
        candidate = (low + high + 1) // 2
        frames = (candidate + _CHUTEFS_FRAME_PLAINTEXT_BYTES - 1) // _CHUTEFS_FRAME_PLAINTEXT_BYTES
        sealed = (
            candidate + _CHUTEFS_FIXED_CIPHERTEXT_BYTES + frames * _CHUTEFS_PER_DATA_FRAME_BYTES
        )
        if sealed <= ciphertext_limit:
            low = candidate
        else:
            high = candidate - 1
    return low


@dataclass
class TeeMeasurementConfig:
    """One canonical, per-hardware TEE trust entry.

    TDX stores only the independent values: MRTD, RTMR0-2, boot RTMR3, and runtime
    RTMR3. Boot RTMR3 defaults to zero, but bare-metal guests that extend it in the
    initramfs pin the observed non-zero value explicitly. SNP uses its launch
    measurement and policy fields, leaving the TDX scalars empty.
    """

    version: str
    name: str
    expected_gpus: List[str]
    gpu_count: int
    provider: Optional[str] = None
    tee_type: str = "tdx"
    debug: bool = False
    rc: bool = False
    # --- Intel TDX fields (empty for SNP) ---
    mrtd: str = ""
    rtmr0: str = ""
    rtmr1: str = ""
    rtmr2: str = ""
    boot_rtmr3: str = ZERO_RTMR
    runtime_rtmr3: str = ""
    # Model-B direct-TDX resource identity. Legacy/GCP/GPU entries leave these unset.
    profile_id: Optional[str] = None
    vcpus: Optional[int] = None
    memory_mib: Optional[int] = None
    # --- AMD SEV-SNP fields (only set when tee_type == "sev-snp") ---
    measurement: Optional[str] = None  # 96 hex (48B SHA-384 launch digest)
    policy: Optional[int] = None  # guest policy bits (DEBUG bit must be off)
    min_tcb: Optional[Dict[str, int]] = None  # {bootloader,tee,snp,microcode} minimums
    id_key_digest: Optional[str] = None  # 96 hex; optional owner id-block pin
    processor_model: Optional[str] = None  # Genoa | Milan | Turin (selects KDS/ARK)
    # Pinned SNP report VMPL (privilege level the guest attests at). The observed bare-metal and GCP
    # fleets both attest at VMPL 0; it remains per-measurement so a future platform must be pinned
    # from a real quote rather than inheriting an assumption. Production SNP entries may not omit it.
    expected_vmpl: Optional[int] = None
    # GCP-only image identity: pinned GCE vTPM PCR values {pcr_index(str): sha256 hex}. On GCP the
    # SNP launch measurement is Google firmware only (no RTMR3 analog), so image identity (our
    # dm-verity rootfs) is bound via the Google-managed vTPM measured boot -- PCR8 (grub cmdline w/
    # verity.roothash) + PCR9 (kernel/initrd). When set, registration requires a verified vTPM quote
    # whose PCRs equal these. Unset for bare-metal SNP (image identity is in the SNP measurement).
    vtpm_pcrs: Optional[Dict[str, str]] = None
    # GCP-only policy for the four boolean values signed in the Google AK attestation extension.
    # Keys are the undocumented ASN.1 context tags, deliberately kept numeric rather than assigned
    # local semantic names. GCP SNP verification requires exactly tags 2, 3, 4, and 5.
    vtpm_security_flags: Optional[Dict[str, bool]] = None
    # Pin-side image binding. Managed production activation additionally requires canonical detached
    # cosign provenance and compares these fields plus the cryptographic measurement values to it.
    # Unsigned bindings are accepted only for explicit debug artifacts on an explicit dev validator.
    image_sha256: Optional[str] = None
    image_measurement_names: Optional[List[str]] = None
    # Strict direct-TDX GPU pin identity. These remain absent on every existing CPU/storage and
    # legacy GPU pin so their canonical fingerprints are unchanged.
    compute_type: Optional[str] = None
    role: Optional[str] = None
    management_mode: Optional[str] = None
    gpu_profile_id: Optional[str] = None
    gpu_profile_contract_sha256: Optional[str] = None
    gpu_measurement_fingerprint: Optional[str] = None
    gpu_fingerprint_version: Optional[int] = None
    provenance_schema_version: Optional[int] = None
    # Canonical identities assigned only after every configured source validates successfully.
    config_fingerprint: str = ""
    trust_set_fingerprint: str = ""

    @property
    def boot_rtmrs(self) -> Dict[str, str]:
        if self.tee_type != "tdx":
            return {}
        return {
            "RTMR0": self.rtmr0,
            "RTMR1": self.rtmr1,
            "RTMR2": self.rtmr2,
            "RTMR3": self.boot_rtmr3,
        }

    @property
    def runtime_rtmrs(self) -> Dict[str, str]:
        if self.tee_type != "tdx":
            return {}
        return {
            "RTMR0": self.rtmr0,
            "RTMR1": self.rtmr1,
            "RTMR2": self.rtmr2,
            "RTMR3": self.runtime_rtmr3,
        }


def measurement_config_fingerprint(config: TeeMeasurementConfig) -> str:
    """Return the stable SHA-256 identity of every security-relevant config field."""
    if getattr(config, "compute_type", None) == "gpu":
        return gpu_measurement_config_fingerprint(config)
    payload = (
        asdict(config)
        if is_dataclass(config)
        else {
            name: getattr(config, name, None) for name in TeeMeasurementConfig.__dataclass_fields__
        }
    )
    payload.pop("config_fingerprint", None)
    payload.pop("trust_set_fingerprint", None)
    # rc controls publication and minimum-version selection, not attestation identity.
    # Promoting an identical candidate must not invalidate persisted exact-pin fingerprints.
    payload.pop("rc", None)
    for profile_field in ("profile_id", "vcpus", "memory_mib"):
        if payload.get(profile_field) is None:
            payload.pop(profile_field, None)
    for gpu_field in (
        "compute_type",
        "role",
        "management_mode",
        "gpu_profile_id",
        "gpu_profile_contract_sha256",
        "gpu_measurement_fingerprint",
        "gpu_fingerprint_version",
        "provenance_schema_version",
    ):
        if payload.get(gpu_field) is None:
            payload.pop(gpu_field, None)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def gpu_measurement_config_fingerprint(config: TeeMeasurementConfig) -> str:
    """Versioned canonical identity for one strict direct-TDX GPU pin."""

    if (
        config.compute_type != "gpu"
        or config.role != "gpu"
        or config.tee_type != "tdx"
        or config.provider != "bare-metal"
        or config.gpu_fingerprint_version != 1
        or config.provenance_schema_version != 3
    ):
        raise ValueError("strict GPU measurement fingerprint metadata is incomplete")
    payload = asdict(config)
    payload.pop("config_fingerprint", None)
    payload.pop("trust_set_fingerprint", None)
    payload.pop("rc", None)
    for profile_field in ("profile_id", "vcpus", "memory_mib"):
        if payload.get(profile_field) is None:
            payload.pop(profile_field, None)
    return hashlib.sha256(
        json.dumps(
            {
                "fingerprint_version": 1,
                "config": payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def measurement_trust_set_fingerprint(
    measurements: List[TeeMeasurementConfig],
) -> str:
    """Return the stable identity of the complete active set, independent of source order."""
    trust_payload = [
        {
            "name": measurement.name,
            "config_fingerprint": (
                measurement.config_fingerprint or measurement_config_fingerprint(measurement)
            ),
        }
        for measurement in sorted(measurements, key=lambda item: item.name)
    ]
    return hashlib.sha256(
        json.dumps(trust_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


_MEASUREMENT_DOCUMENT_KEYS = {"measurements", "revoked_measurements"}
_NESTED_COMMON_GROUP_KEYS = {
    "version",
    "tee_type",
    "provider",
    "debug",
    "rc",
    "image_sha256",
    "image_measurement_names",
    "hardware",
}
_NESTED_TDX_GROUP_KEYS = {
    "mrtd",
    "rtmr1",
    "rtmr2",
    "boot_rtmr3",
    "runtime_rtmr3",
}
_NESTED_SNP_GROUP_KEYS = {
    "processor_model",
    "policy",
    "min_tcb",
    "expected_vmpl",
    "id_key_digest",
}
_NESTED_GCP_SNP_GROUP_KEYS = {"vtpm_pcrs", "vtpm_security_flags"}
_NESTED_HARDWARE_KEYS = {
    "name",
    "description",
    "expected_gpus",
    "gpu_count",
}
_NESTED_DIRECT_TDX_HARDWARE_KEYS = {
    "profile_id",
    "vcpus",
    "memory_mib",
    "rtmr1",
    "rtmr2",
    "boot_rtmr3",
    "runtime_rtmr3",
}


def _field_names(values: set[object]) -> List[str]:
    """Render possibly non-string mapping keys without relying on mixed-type sorting."""
    return sorted(repr(value) for value in values)


def _expand_nested_gpu_measurement_group(group: dict, source: object) -> List[dict]:
    """Flatten one strict schema-v3 GPU profile×mode measurement group."""

    group_keys = {
        "version",
        "tee_type",
        "provider",
        "compute_type",
        "role",
        "debug",
        "rc",
        "provenance_schema_version",
        "gpu_fingerprint_version",
        "profile_contract_sha256",
        "image_sha256",
        "image_measurement_names",
        "hardware",
    }
    if set(group) != group_keys:
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: keys must be exactly "
            f"{sorted(group_keys)} (missing={_field_names(group_keys - set(group))}, "
            f"unknown={_field_names(set(group) - group_keys)})."
        )
    if (
        group["tee_type"] != "tdx"
        or group["provider"] != "bare-metal"
        or group["compute_type"] != "gpu"
        or group["role"] != "gpu"
        or group["provenance_schema_version"] != 3
        or group["gpu_fingerprint_version"] != 1
    ):
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: expected "
            "compute_type=gpu, role=gpu, TDX/bare-metal, provenance v3, fingerprint v1."
        )
    version = group["version"]
    if not isinstance(version, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version
    ):
        raise ValueError(f"Invalid strict GPU measurement group {source}: version is invalid.")
    if not isinstance(group["debug"], bool) or not isinstance(group["rc"], bool):
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: debug and rc must be booleans."
        )
    for field in ("profile_contract_sha256", "image_sha256"):
        value = group[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(
                f"Invalid strict GPU measurement group {source}: {field} must be lowercase sha256."
            )
    names = group["image_measurement_names"]
    if (
        not isinstance(names, list)
        or not names
        or any(not isinstance(name, str) or not name for name in names)
        or names != list(dict.fromkeys(names))
    ):
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: "
            "image_measurement_names must be an ordered unique non-empty string list."
        )
    hardware = group["hardware"]
    if not isinstance(hardware, list) or not hardware:
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: hardware must be non-empty."
        )
    required_variant_keys = {
        "name",
        "gpu_profile_id",
        "management_mode",
        "mrtd",
        "rtmr0",
        "rtmr1",
        "rtmr2",
        "boot_rtmr3",
        "runtime_rtmr3",
        "expected_gpus",
        "gpu_count",
        "gpu_measurement_fingerprint",
    }
    allowed_variant_keys = required_variant_keys | {"description"}
    flattened: List[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    seen_fingerprints: set[str] = set()
    profile_inventory: Dict[str, tuple[int, tuple[str, ...]]] = {}
    profile_order: List[str] = []
    for index, variant in enumerate(hardware):
        path = f"{source}:hardware[{index}]"
        if not isinstance(variant, dict) or not required_variant_keys.issubset(variant):
            actual = set(variant) if isinstance(variant, dict) else set()
            raise ValueError(
                f"Invalid strict GPU measurement variant {path}: missing "
                f"{_field_names(required_variant_keys - actual)}."
            )
        unknown = set(variant) - allowed_variant_keys
        if unknown:
            raise ValueError(
                f"Invalid strict GPU measurement variant {path}: unknown {_field_names(unknown)}."
            )
        profile_id = variant["gpu_profile_id"]
        mode = variant["management_mode"]
        if not isinstance(profile_id, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,63}", profile_id
        ):
            raise ValueError(f"Invalid strict GPU measurement variant {path}: profile id.")
        if mode not in {"platform", "miner"}:
            raise ValueError(f"Invalid strict GPU measurement variant {path}: management mode.")
        pair = (profile_id, mode)
        if pair in seen_pairs:
            raise ValueError(f"Invalid strict GPU measurement group {source}: duplicate {pair}.")
        seen_pairs.add(pair)
        if profile_id not in profile_order:
            profile_order.append(profile_id)
        expected_name = f"gpu-baremetal-tdx-{version}-{profile_id}-{mode}"
        if variant["name"] != expected_name:
            raise ValueError(
                f"Invalid strict GPU measurement variant {path}: name contradicts profile/mode."
            )
        if (
            not isinstance(variant["gpu_count"], int)
            or isinstance(variant["gpu_count"], bool)
            or variant["gpu_count"] <= 0
            or not isinstance(variant["expected_gpus"], list)
            or not variant["expected_gpus"]
            or any(
                not isinstance(gpu, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", gpu)
                for gpu in variant["expected_gpus"]
            )
            or variant["expected_gpus"] != sorted(set(variant["expected_gpus"]))
        ):
            raise ValueError(
                f"Invalid strict GPU measurement variant {path}: GPU inventory is invalid."
            )
        fingerprint = variant["gpu_measurement_fingerprint"]
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError(
                f"Invalid strict GPU measurement variant {path}: fingerprint must be sha256."
            )
        if fingerprint in seen_fingerprints:
            raise ValueError(
                f"Invalid strict GPU measurement group {source}: duplicate measurement fingerprint."
            )
        seen_fingerprints.add(fingerprint)
        inventory = (variant["gpu_count"], tuple(variant["expected_gpus"]))
        if profile_id in profile_inventory and profile_inventory[profile_id] != inventory:
            raise ValueError(
                f"Invalid strict GPU measurement group {source}: profile {profile_id!r} "
                "changes GPU identity between management modes."
            )
        profile_inventory[profile_id] = inventory
        for field in (
            "mrtd",
            "rtmr0",
            "rtmr1",
            "rtmr2",
            "boot_rtmr3",
            "runtime_rtmr3",
        ):
            value = variant[field]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9A-F]{96}", value):
                raise ValueError(
                    f"Invalid strict GPU measurement variant {path}: {field} must be uppercase SHA-384."
                )
        flat = {key: value for key, value in group.items() if key != "hardware"}
        flat.update(variant)
        flat["gpu_profile_contract_sha256"] = flat.pop("profile_contract_sha256")
        flattened.append(flat)
    expected_pairs = [
        (profile_id, mode) for profile_id in profile_order for mode in ("platform", "miner")
    ]
    actual_pairs = [(item["gpu_profile_id"], item["management_mode"]) for item in flattened]
    if actual_pairs != expected_pairs:
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: hardware must contain the "
            "complete ordered profile by platform/miner matrix."
        )
    if [item["name"] for item in flattened] != names:
        raise ValueError(
            f"Invalid strict GPU measurement group {source}: hardware names/order must "
            "exactly match image_measurement_names."
        )
    return flattened


def _expand_nested_measurement_group(group: dict, source: object) -> List[dict]:
    """Flatten one strict source group into scalar per-hardware runtime entries."""
    if group.get("compute_type") == "gpu":
        return _expand_nested_gpu_measurement_group(group, source)
    legacy_maps = {"boot_rtmrs", "runtime_rtmrs"}.intersection(group)
    if legacy_maps:
        raise ValueError(
            f"Invalid TEE measurement config {source}: old boot/runtime map field(s) "
            f"{_field_names(legacy_maps)} are not accepted; use the strict nested scalar format."
        )

    flat_variant_fields = {
        "name",
        "description",
        "expected_gpus",
        "gpu_count",
        "rtmr0",
        "measurement",
    }.intersection(group)
    if flat_variant_fields:
        raise ValueError(
            f"Invalid TEE measurement config {source}: current flat scalar field(s) "
            f"{_field_names(flat_variant_fields)} must be nested under a non-empty 'hardware' list."
        )

    if "tee_type" not in group:
        raise ValueError(
            f"Invalid TEE measurement config {source}: every measurement group must explicitly "
            "set tee_type to 'tdx' or 'sev-snp'."
        )
    tee_type = group["tee_type"]
    if not isinstance(tee_type, str):
        raise ValueError(
            f"Invalid TEE measurement config {source}: tee_type must be an actual YAML string."
        )
    if tee_type not in {"tdx", "sev-snp"}:
        raise ValueError(
            f"Invalid TEE measurement config {source}: tee_type must be exactly 'tdx' or "
            f"'sev-snp', got {tee_type!r}; SNP aliases are not accepted."
        )

    provider = group.get("provider")
    if "provider" in group:
        if not isinstance(provider, str):
            raise ValueError(
                f"Invalid TEE measurement config {source}: provider must be an actual YAML string."
            )
        if provider not in {"gcp", "bare-metal"}:
            raise ValueError(
                f"Invalid TEE measurement config {source}: provider must be exactly 'gcp' or "
                f"'bare-metal', got {provider!r}."
            )
    if tee_type == "sev-snp" and provider not in {"gcp", "bare-metal"}:
        raise ValueError(
            f"Invalid TEE measurement config {source}: every sev-snp group must explicitly set "
            "provider to 'gcp' or 'bare-metal'."
        )
    hardware_preview = group.get("hardware")
    direct_tdx_profiles = bool(
        tee_type == "tdx"
        and isinstance(hardware_preview, list)
        and any(
            isinstance(variant, dict) and "profile_id" in variant for variant in hardware_preview
        )
    )
    if direct_tdx_profiles and provider != "bare-metal":
        raise ValueError(
            f"Invalid TEE measurement config {source}: direct TDX launch profiles "
            "require provider: bare-metal."
        )

    allowed_group_keys = _NESTED_COMMON_GROUP_KEYS | (
        _NESTED_TDX_GROUP_KEYS
        if tee_type == "tdx"
        else _NESTED_SNP_GROUP_KEYS | (_NESTED_GCP_SNP_GROUP_KEYS if provider == "gcp" else set())
    )
    unexpected_group_keys = set(group) - allowed_group_keys
    if unexpected_group_keys:
        raise ValueError(
            f"Invalid TEE measurement config {source}: unsupported {tee_type}/{provider or 'generic'} "
            f"group field(s) {_field_names(unexpected_group_keys)}."
        )

    required_group_keys = {"version", "tee_type", "debug", "hardware"} | (
        (
            {"provider", "mrtd", "runtime_rtmr3"}
            if direct_tdx_profiles
            else {"mrtd", "rtmr1", "rtmr2", "runtime_rtmr3"}
        )
        if tee_type == "tdx"
        else {"provider", "processor_model", "policy", "min_tcb", "expected_vmpl"}
        | (_NESTED_GCP_SNP_GROUP_KEYS if provider == "gcp" else set())
    )
    missing_group_keys = required_group_keys - set(group)
    if missing_group_keys:
        raise ValueError(
            f"Invalid TEE measurement config {source}: {tee_type} group is missing required "
            f"field(s) {_field_names(missing_group_keys)}."
        )

    version = group["version"]
    if not isinstance(version, str) or not version.strip():
        raise ValueError(
            f"Invalid TEE measurement config {source}: version must be a non-empty YAML string."
        )
    if not isinstance(group["debug"], bool):
        raise ValueError(
            f"Invalid TEE measurement config {source}: debug must be an actual YAML boolean."
        )
    if "rc" in group and not isinstance(group["rc"], bool):
        raise ValueError(
            f"Invalid TEE measurement config {source}: rc must be an actual YAML boolean."
        )

    hardware = group["hardware"]
    if not isinstance(hardware, list) or not hardware:
        raise ValueError(
            f"Invalid TEE measurement config {source}: measurement group {version!r} must define "
            "a non-empty 'hardware' list."
        )

    variant_key = "rtmr0" if tee_type == "tdx" else "measurement"
    allowed_hardware_keys = _NESTED_HARDWARE_KEYS | {variant_key}
    if direct_tdx_profiles:
        allowed_hardware_keys |= _NESTED_DIRECT_TDX_HARDWARE_KEYS
    required_hardware_keys = {"name", "expected_gpus", "gpu_count", variant_key}
    if direct_tdx_profiles:
        required_hardware_keys |= {
            "profile_id",
            "vcpus",
            "memory_mib",
            "rtmr1",
            "rtmr2",
        }
    flattened: List[dict] = []
    seen_direct_names: set[str] = set()
    seen_direct_profiles: set[str] = set()
    seen_direct_shapes: set[tuple[int, int]] = set()
    for index, variant in enumerate(hardware):
        if not isinstance(variant, dict):
            raise ValueError(
                f"Invalid TEE measurement config {source}: hardware item {index} in group "
                f"{version!r} must be a mapping."
            )
        unexpected_variant_keys = set(variant) - allowed_hardware_keys
        if unexpected_variant_keys:
            raise ValueError(
                f"Invalid TEE measurement config {source}: hardware item {index} in group "
                f"{version!r} has unsupported {tee_type} field(s) "
                f"{_field_names(unexpected_variant_keys)}."
            )
        missing_variant_keys = required_hardware_keys - set(variant)
        if missing_variant_keys:
            raise ValueError(
                f"Invalid TEE measurement config {source}: hardware item {index} in group "
                f"{version!r} is missing required field(s) {_field_names(missing_variant_keys)}."
            )

        raw_name = variant["name"]
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError(
                f"Invalid TEE measurement config {source}: every hardware variant requires "
                "a non-empty string name."
            )
        if direct_tdx_profiles:
            profile_id = variant["profile_id"]
            vcpus = variant["vcpus"]
            memory_mib = variant["memory_mib"]
            normalized_name = raw_name.strip()
            if (
                not isinstance(profile_id, str)
                or not re.fullmatch(r"[1-9][0-9]*vcpu-[1-9][0-9]*g", profile_id)
                or not isinstance(vcpus, int)
                or isinstance(vcpus, bool)
                or vcpus <= 0
                or not isinstance(memory_mib, int)
                or isinstance(memory_mib, bool)
                or memory_mib <= 0
                or memory_mib % 1024
                or profile_id != f"{vcpus}vcpu-{memory_mib // 1024}g"
            ):
                raise ValueError(
                    f"Invalid TEE measurement config {source}: hardware variant "
                    f"{raw_name!r} has an invalid direct-TDX launch profile."
                )
            expected_names = {
                f"cpu-baremetal-tdx-{version.strip()}-{profile_id}",
                f"storage-baremetal-tdx-{version.strip()}-{profile_id}",
            }
            if normalized_name not in expected_names:
                raise ValueError(
                    f"Invalid TEE measurement config {source}: direct-TDX name "
                    f"{normalized_name!r} contradicts profile {profile_id!r}."
                )
            shape = (vcpus, memory_mib)
            if (
                normalized_name in seen_direct_names
                or profile_id in seen_direct_profiles
                or shape in seen_direct_shapes
            ):
                raise ValueError(
                    f"Invalid TEE measurement config {source}: duplicate direct-TDX "
                    f"name/profile/shape for {normalized_name!r}."
                )
            seen_direct_names.add(normalized_name)
            seen_direct_profiles.add(profile_id)
            seen_direct_shapes.add(shape)
        if "description" in variant and (
            not isinstance(variant["description"], str) or not variant["description"].strip()
        ):
            raise ValueError(
                f"Invalid TEE measurement config {source}: hardware variant {raw_name!r} "
                "description must be a non-empty YAML string."
            )

        flat = {key: value for key, value in group.items() if key != "hardware"}
        flat.update(variant)
        if direct_tdx_profiles:
            if raw_name.startswith("storage-"):
                role_segment = "storage-"
            elif raw_name.startswith("cpu-"):
                role_segment = ""
            else:
                raise ValueError(
                    f"Invalid TEE measurement config {source}: direct-TDX hardware variant "
                    f"{raw_name!r} must use a cpu-* or storage-* measurement name."
                )
            flat["version"] = f"{version.strip()}-{role_segment}tdx-{variant['profile_id']}"
        else:
            flat["version"] = version.strip()
        flat["name"] = raw_name.strip()
        flattened.append(flat)
    return flattened


class Settings(BaseSettings):
    model_config = SettingsConfigDict(arbitrary_types_allowed=True)
    _validator_keypair: Optional[Keypair] = None
    _tee_measurements_last_good: Optional[List[TeeMeasurementConfig]] = None
    _tee_measurements_last_error: Optional[str] = None
    _tee_measurements_last_source_identity: Optional[tuple] = None
    _tee_measurements_expected_sources: Optional[tuple[str, ...]] = None
    _tee_measurements_fingerprint: Optional[str] = None
    _tee_measurements_last_loaded_at: Optional[str] = None

    def model_post_init(self, __context) -> None:
        """Validate configuration after initialization."""
        for cidr in self.trusted_proxy_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid TRUSTED_PROXY_CIDRS entry {cidr!r}") from exc
        # ALLOW_DEBUG_MEASUREMENTS is not a production escape hatch. The metagraph bypass is the
        # validator's explicit dev marker (including the dev-attested-mTLS posture); without that
        # marker, reject the opt-in itself before loading any debug pins.
        if self.allow_debug_measurements and not self.skip_metagraph_check:
            raise ValueError(
                "ALLOW_DEBUG_MEASUREMENTS=true is permitted only in the explicit dev posture "
                "(SKIP_METAGRAPH_CHECK=true). A production validator must use hardened image "
                "measurements."
            )
        if self.release_attestation_max_age_seconds <= 0:
            raise ValueError("RELEASE_ATTESTATION_MAX_AGE_SECONDS must be positive.")
        _ = self.chutefs_token_keys
        if not 0 <= self.snp_crl_outage_grace_seconds <= MAX_SNP_CRL_OUTAGE_GRACE_SECONDS:
            raise ValueError(
                "SNP_CRL_OUTAGE_GRACE_SECONDS must be between 0 and "
                f"{MAX_SNP_CRL_OUTAGE_GRACE_SECONDS}; longer revocation outages fail closed."
            )
        # Eagerly validate TEE measurement configuration when any source (committed artifact or the
        # mounted ConfigMap) is present.
        if self._measurement_source_paths():
            _ = self.tee_measurements

        # SKIP_METAGRAPH_CHECK is a dev-only bypass (it auto-creates a metagraph row so an unregistered
        # hotkey can self-register a CPU server). It must never run in the production posture, which is
        # identified by the secure mTLS-client-verify default. Fail closed on the unsafe combination;
        # the full dev posture (REQUIRE_MTLS_CLIENT_VERIFY=false) is still allowed for local bring-up.
        if self.skip_metagraph_check and self.require_mtls_client_verify:
            if not self.allow_dev_attested_mtls:
                raise ValueError(
                    "SKIP_METAGRAPH_CHECK is a dev-only bypass and must not be enabled in a production "
                    "posture (REQUIRE_MTLS_CLIENT_VERIFY=true). Set SKIP_METAGRAPH_CHECK=false, run a "
                    "full dev validator (REQUIRE_MTLS_CLIENT_VERIFY=false), or set ALLOW_DEV_ATTESTED_MTLS=true "
                    "to intentionally run a dev box with the metagraph bypass AND real attestation mTLS."
                )
            logger.warning(
                "Dev-attested-mTLS posture: SKIP_METAGRAPH_CHECK=true + REQUIRE_MTLS_CLIENT_VERIFY=true "
                "(ALLOW_DEV_ATTESTED_MTLS=true) -- dev metagraph with a REAL verifying mTLS terminator. "
                "This must NEVER be used on a production validator."
            )
        # The inverse direction must also fail closed: REQUIRE_MTLS_CLIENT_VERIFY=false disables the
        # X-Client-Verify gate AND the CPU-TEE attested-cert binding on secret-returning endpoints,
        # so flipping it alone on an otherwise-production validator would silently drop the sole
        # Model-B secret guard. Only the full dev posture (SKIP_METAGRAPH_CHECK=true, the dev-only
        # marker) may run without mTLS client verification; a non-dev validator refuses to start.
        if not self.skip_metagraph_check and not self.require_mtls_client_verify:
            raise ValueError(
                "REQUIRE_MTLS_CLIENT_VERIFY=false is a dev-only posture (no mTLS terminator) and "
                "must not be set on a non-dev validator: it would disable the attested-client-cert "
                "binding that keeps CPU-TEE chute code/secrets from unattested callers. Set "
                "REQUIRE_MTLS_CLIENT_VERIFY=true, or run the full dev posture "
                "(SKIP_METAGRAPH_CHECK=true) for local bring-up."
            )
        if not self.skip_metagraph_check and not self.tee_measurement_config_required:
            raise ValueError(
                "Production validators must set TEE_MEASUREMENT_CONFIG_REQUIRED=true and mount the "
                "environment-specific TEE measurement source. The committed artifact alone is not "
                "a production trust set."
            )

    @cached_property
    def validator_keypair(self) -> Optional[Keypair]:
        if not self._validator_keypair and os.getenv("VALIDATOR_SEED"):
            self._validator_keypair = Keypair.create_from_seed(os.environ["VALIDATOR_SEED"])
        return self._validator_keypair

    @cached_property
    def fernet_key(self) -> Optional[Fernet]:
        """Get validated Fernet cipher for cache passphrase encryption.

        Returns:
            Fernet cipher instance, or None if CACHE_PASSPHRASE_KEY not configured

        Raises:
            ValueError: If CACHE_PASSPHRASE_KEY is invalid format
        """
        key = os.getenv("CACHE_PASSPHRASE_KEY")
        if not key:
            return None

        # Fernet keys must be 32 url-safe base64-encoded bytes (44 characters)
        if len(key) != 44:
            raise ValueError(
                f"CACHE_PASSPHRASE_KEY must be 44 characters (32 bytes base64-encoded), got {len(key)} characters. "
                "Generate a valid key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )

        try:
            return Fernet(key.encode())
        except Exception as e:
            raise ValueError(f"Invalid CACHE_PASSPHRASE_KEY format: {e}")

    sqlalchemy: str = os.getenv(
        "POSTGRESQL", "postgresql+asyncpg://user:password@127.0.0.1:5432/chutes"
    )
    postgres_ro: Optional[str] = os.getenv("POSTGRESQL_RO")

    # asyncpg sslmode for the postgres connections. Defaults to "require" (prod hosted
    # postgres); set DB_SSL=disable for a local postgres that has no TLS.
    db_ssl: str = os.getenv("DB_SSL", "require")

    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "REPLACEME")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "REPLACEME")
    aws_endpoint_url: Optional[str] = os.getenv("AWS_ENDPOINT_URL", "http://minio:9000")
    aws_region: str = os.getenv("AWS_REGION", "local")
    storage_bucket: str = os.getenv("STORAGE_BUCKET", "chutes")
    s3_proxy_url: Optional[str] = os.getenv("S3_PROXY_URL")

    @property
    def s3_session(self) -> aioboto3.Session:
        session = aioboto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region,
        )
        return session

    @asynccontextmanager
    async def s3_client(self):
        session = self.s3_session
        async with session.client(
            "s3",
            endpoint_url=self.aws_endpoint_url,
            config=Config(
                signature_version="s3v4",
                proxies={"https": self.s3_proxy_url} if self.s3_proxy_url else None,
            ),
        ) as client:
            yield client

    wallet_key: Optional[str] = os.getenv(
        "WALLET_KEY", "967fcf63799171672b6b66dfe30d8cd678c8bc6fb44806f0cdba3d873b3dd60b"
    )
    pg_encryption_key: Optional[str] = os.getenv("PG_ENCRYPTION_KEY", "secret")

    validator_ss58: Optional[str] = os.getenv("VALIDATOR_SS58")

    # Base redis settings.
    redis_host: str = Field(
        default_factory=lambda: os.getenv("REDIS_HOST", "172.16.0.100"),
        validation_alias="PRIMARY_REDIS_HOST",
    )
    redis_port: int = Field(
        default_factory=lambda: int(os.getenv("REDIS_PORT", "6378")),
        validation_alias="PRIMARY_REDIS_PORT",
    )
    redis_password: str = str(os.getenv("REDIS_PASSWORD", "password"))
    redis_db: int = int(os.getenv("REDIS_DB", "0"))
    redis_max_connections: int = int(os.getenv("REDIS_MAX_CONNECTIONS", 512))
    redis_connect_timeout: float = float(os.getenv("REDIS_CONNECT_TIMEOUT", "1.5"))
    redis_socket_timeout: float = float(os.getenv("REDIS_SOCKET_TIMEOUT", "2.5"))
    redis_op_timeout: float = float(
        os.getenv("REDIS_OP_TIMEOUT", os.getenv("REDIS_SOCKET_TIMEOUT", "2.5"))
    )
    redis_cacert: Optional[str] = os.getenv("REDIS_CACERT")

    _redis_client: Optional[redis.Redis] = None
    _lite_redis_client: Optional[redis.Redis] = None
    _billing_redis_client: Optional[redis.Redis] = None
    _cm_redis_client: Optional[redis.Redis] = None

    @property
    def redis_url(self) -> str:
        scheme = "rediss" if self.redis_cacert else "redis"
        base = (
            f"{scheme}://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        )
        if self.redis_cacert:
            return f"{base}?ssl_cert_reqs=required&ssl_ca_certs={self.redis_cacert}"
        return base

    @property
    def redis_client(self) -> redis.Redis:
        if self._redis_client is None:
            self._redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
                ssl_ca_certs=self.redis_cacert,
            )
        return self._redis_client

    @property
    def lite_redis_client(self) -> redis.Redis:
        if self._lite_redis_client is None:
            self._lite_redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db + 1,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
                ssl_ca_certs=self.redis_cacert,
            )
        return self._lite_redis_client

    @property
    def billing_redis_client(self) -> redis.Redis:
        if self._billing_redis_client is None:
            self._billing_redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db + 2,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
                ssl_ca_certs=self.redis_cacert,
            )
        return self._billing_redis_client

    @property
    def cm_redis_client(self) -> redis.Redis:
        if self._cm_redis_client is None:
            self._cm_redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db + 3,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
                ssl_ca_certs=self.redis_cacert,
            )
        return self._cm_redis_client

    registry_host: str = os.getenv("REGISTRY_HOST", "registry:5000")
    registry_external_host: str = os.getenv("REGISTRY_EXTERNAL_HOST", "registry.chutes.ai")
    registry_password: str = os.getenv("REGISTRY_PASSWORD", "registrypassword")
    registry_insecure: bool = os.getenv("REGISTRY_INSECURE", "false").lower() == "true"
    build_timeout: int = int(os.getenv("BUILD_TIMEOUT", "7200"))
    push_timeout: int = int(os.getenv("PUSH_TIMEOUT", "7200"))
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT", "7200"))
    netuid: int = int(os.getenv("NETUID", "64"))
    subtensor: str = os.getenv("SUBTENSOR_ADDRESS", "wss://entrypoint-finney.opentensor.ai:443")
    mev_protection_enabled: bool = os.getenv("MEV_PROTECTION_ENABLED", "false").lower() == "true"
    payment_recovery_blocks: int = int(os.getenv("PAYMENT_RECOVERY_BLOCKS", "256"))
    device_info_challenge_count: int = int(os.getenv("DEVICE_INFO_CHALLENGE_COUNT", "20"))
    skip_gpu_verification: bool = os.getenv("SKIP_GPU_VERIFICATION", "false").lower() == "true"
    # Dev-only: bypass the requirement that a self-registering CPU server's miner hotkey already
    # exists on the metagraph. When set, a metagraph_nodes row is auto-created on registration to
    # satisfy the servers FK. NEVER enable in production.
    skip_metagraph_check: bool = os.getenv("SKIP_METAGRAPH_CHECK", "false").lower() == "true"
    # Opt-in for a dev box that runs the metagraph bypass (SKIP_METAGRAPH_CHECK=true) AND fronts a
    # REAL verifying mTLS terminator (REQUIRE_MTLS_CLIENT_VERIFY=true) -- i.e. dev metagraph with real
    # attestation mTLS, needed to exercise CPU-TEE secret delivery without a live chain. Never set in
    # production (production uses a real metagraph, so SKIP_METAGRAPH_CHECK is false there anyway).
    allow_dev_attested_mtls: bool = os.getenv("ALLOW_DEV_ATTESTED_MTLS", "false").lower() == "true"
    # Debug TEE guest images (debug_logging: chute output forwarded to the host-readable serial
    # console) produce a DISTINCT measurement, but a validator cannot otherwise tell a debug
    # measurement from a hardened one -- so a debug config shipped in a production ConfigMap would
    # let a miner boot the debug image, pass attestation, and stream user logs to the host. A
    # measurement config tagged `debug: true` is therefore REFUSED at load unless this dev-only
    # switch is set, so debug measurements cannot silently enter a production deployment.
    allow_debug_measurements: bool = (
        os.getenv("ALLOW_DEBUG_MEASUREMENTS", "false").lower() == "true"
    )
    graval_url: str = os.getenv("GRAVAL_URL", "https://graval.chutes.ai:11443")

    # mTLS client-cert trust posture. The X-Client-Cert header is honored only when the terminating
    # proxy reports that a cert was presented: SUCCESS for a CA-chained cert, or FAILED:<reason> for
    # the expected self-signed TEE cert under nginx optional_no_ca. Both prove CertificateVerify
    # possession; NONE/missing does not. The proxy must overwrite client-supplied X-Client-* and the
    # backend must not be directly reachable. This also gates the CPU-TEE attested-cert binding on
    # secret-returning /tee endpoints. Set false only for plaintext local development.
    require_mtls_client_verify: bool = (
        os.getenv("REQUIRE_MTLS_CLIENT_VERIFY", "true").lower() == "true"
    )
    # X-Resolved-IP is proxy-owned and is accepted only from these directly connected networks.
    # Standalone processes trust loopback by default. The chart always sets this environment variable
    # explicitly (including an empty value, which parses to []), so chart deployments opt into trust.
    trusted_proxy_cidrs: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"]
    )

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def _parse_trusted_proxy_cidrs(cls, value):
        if isinstance(value, str):
            return [cidr.strip() for cidr in value.split(",") if cidr.strip()]
        return value

    # Database settings.
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "16"))
    db_overflow: int = int(os.getenv("DB_OVERFLOW", "3"))

    # Debug logging.
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"

    # IP hash check salt.
    ip_check_salt: str = os.getenv("IP_CHECK_SALT", "salt")

    # User JWT salt.
    user_jwt_salt: Optional[str] = os.getenv("USER_JWT_SALT", "replaceme")

    # Flag indicating that all accounts created are free.
    all_accounts_free: bool = os.getenv("ALL_ACCOUNTS_FREE", "false").lower() == "true"

    # Consecutive failure count that triggers instance deletion.
    consecutive_failure_limit: int = int(os.getenv("CONSECUTIVE_FAILURE_LIMIT", "7"))

    # Logos CDN hostname.
    logo_cdn: Optional[str] = os.getenv("LOGO_CDN", "https://logos.chutes.ai")

    # Base domain.
    base_domain: Optional[str] = os.getenv("BASE_DOMAIN", "chutes.ai")

    # Base URL a launched chute calls back to for verification (the launch-JWT "url" claim). Defaults
    # to the public https://api.{base_domain}. A dev validator that a chute reaches over plain HTTP at
    # a raw IP:port (no api.<domain> DNS) sets LAUNCH_CONFIG_BASE_URL to its own reachable base.
    launch_config_base_url: Optional[str] = os.getenv("LAUNCH_CONFIG_BASE_URL")

    # Launch config JWT signing key.
    launch_config_key: str = hashlib.sha256(
        os.getenv("LAUNCH_CONFIG_KEY", "launch-secret").encode()
    ).hexdigest()
    chutefs_token_key_id: str = os.getenv(
        "CHUTEFS_TOKEN_KEY_ID",
        "launch-config-key-v1",
    )
    chutefs_token_keys_json: Optional[str] = os.getenv("CHUTEFS_TOKEN_KEYS_JSON")
    gpu_launch_key_epoch: int = int(os.getenv("GPU_LAUNCH_KEY_EPOCH", "1"))

    @property
    def chutefs_token_keys(self) -> Dict[str, str]:
        """Versioned response-recovery keys retained through referenced session expiry."""
        if self.chutefs_token_keys_json is None:
            keys = {"launch-config-key-v1": self.launch_config_key}
        else:

            def unique_keyring(pairs):
                result = {}
                for key_id, secret in pairs:
                    if key_id in result:
                        raise ValueError("CHUTEFS_TOKEN_KEYS_JSON contains a duplicate key ID")
                    result[key_id] = secret
                return result

            try:
                keys = json.loads(
                    self.chutefs_token_keys_json,
                    object_pairs_hook=unique_keyring,
                )
            except json.JSONDecodeError as exc:
                raise ValueError("CHUTEFS_TOKEN_KEYS_JSON must be valid JSON") from exc
        if (
            not isinstance(keys, dict)
            or not keys
            or any(
                not isinstance(key_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id) is None
                or not isinstance(secret, str)
                or not 32 <= len(secret) <= 1024
                or not secret.isascii()
                for key_id, secret in keys.items()
            )
            or self.chutefs_token_key_id not in keys
        ):
            raise ValueError(
                "ChuteFS token keys must be a non-empty ASCII keyring containing "
                "CHUTEFS_TOKEN_KEY_ID"
            )
        return dict(keys)

    # New, asymmetric launch config keys.
    launch_config_private_key_bytes: Optional[bytes] = load_launch_config_private_key()

    @cached_property
    def launch_config_private_key(self) -> Optional[ec.EllipticCurvePrivateKey]:
        if hasattr(self, "_launch_config_private_key"):
            return self._launch_config_private_key
        if (key_bytes := load_launch_config_private_key()) is not None:
            self._launch_config_private_key = serialization.load_pem_private_key(key_bytes, None)
            return self._launch_config_private_key
        return None

    # Default quotas/discounts.
    default_quotas: dict = json.loads(os.getenv("DEFAULT_QUOTAS", '{"*": 0}'))
    default_discounts: dict = json.loads(os.getenv("DEFAULT_DISCOUNTS", '{"*": 0.0}'))
    default_job_quotas: dict = json.loads(os.getenv("DEFAULT_JOB_QUOTAS", '{"*": 0}'))

    # ChuteFS account entitlements and bounded control-plane work. Volume owners never submit quota
    # values: nullable per-user fields override these defaults, and both are capped here.
    storage_default_volume_quota_bytes: int = int(
        os.getenv("STORAGE_DEFAULT_VOLUME_QUOTA_BYTES", str(10 * 1024**3))
    )
    storage_max_volume_quota_bytes: int = int(
        os.getenv("STORAGE_MAX_VOLUME_QUOTA_BYTES", str(1024**4))
    )
    storage_default_aggregate_quota_bytes: int = int(
        os.getenv("STORAGE_DEFAULT_AGGREGATE_QUOTA_BYTES", str(100 * 1024**3))
    )
    storage_max_aggregate_quota_bytes: int = int(
        os.getenv("STORAGE_MAX_AGGREGATE_QUOTA_BYTES", str(10 * 1024**4))
    )
    storage_max_volumes_per_user: int = int(os.getenv("STORAGE_MAX_VOLUMES_PER_USER", "100"))
    storage_max_ciphertext_bytes: int = int(
        os.getenv("STORAGE_MAX_CIPHERTEXT_BYTES", str(64 * 1024**3))
    )
    storage_max_object_bytes: int = int(
        os.getenv(
            "STORAGE_MAX_OBJECT_BYTES",
            str(_max_plaintext_for_ciphertext_limit(storage_max_ciphertext_bytes)),
        )
    )
    storage_volume_page_size_max: int = int(os.getenv("STORAGE_VOLUME_PAGE_SIZE_MAX", "200"))
    storage_inventory_page_size_max: int = int(os.getenv("STORAGE_INVENTORY_PAGE_SIZE_MAX", "250"))
    storage_reconcile_batch_size: int = int(os.getenv("STORAGE_RECONCILE_BATCH_SIZE", "250"))
    storage_erase_task_lease_seconds: int = int(
        os.getenv("STORAGE_ERASE_TASK_LEASE_SECONDS", "300")
    )
    storage_erase_retention_seconds: int = int(
        os.getenv("STORAGE_ERASE_RETENTION_SECONDS", str(30 * 24 * 3600))
    )
    # Retiring an unreachable holder without its physical ACK is disabled by default. Enabling this
    # setting still requires a support/billing administrator to name overdue task ids explicitly.
    storage_allow_administrative_erase_retirement: bool = (
        os.getenv("STORAGE_ALLOW_ADMINISTRATIVE_ERASE_RETIREMENT", "false").lower() == "true"
    )
    storage_model_holding_freshness_seconds: int = int(
        os.getenv("STORAGE_MODEL_HOLDING_FRESHNESS_SECONDS", "300")
    )
    storage_inventory_snapshot_retention_seconds: int = int(
        os.getenv("STORAGE_INVENTORY_SNAPSHOT_RETENTION_SECONDS", str(24 * 3600))
    )
    storage_erase_audit_retention_seconds: int = int(
        os.getenv("STORAGE_ERASE_AUDIT_RETENTION_SECONDS", str(90 * 24 * 3600))
    )

    @model_validator(mode="after")
    def validate_storage_object_limits(self) -> "Settings":
        if self.storage_max_ciphertext_bytes < _CHUTEFS_FIXED_CIPHERTEXT_BYTES:
            raise ValueError("STORAGE_MAX_CIPHERTEXT_BYTES cannot hold an empty v4 container")
        safe_plaintext_limit = _max_plaintext_for_ciphertext_limit(
            self.storage_max_ciphertext_bytes
        )
        if not 0 <= self.storage_max_object_bytes <= safe_plaintext_limit:
            raise ValueError(
                "STORAGE_MAX_OBJECT_BYTES exceeds the configured node ciphertext "
                "limit after v4 framing overhead"
            )
        return self

    # Reroll discount (i.e. duplicate prompts for re-roll in RP, or pass@k, etc.)
    reroll_multiplier: float = float(os.getenv("REROLL_MULTIPLIER", "0.1"))

    # Magic discount header: when a request includes this header with the correct value,
    # a discount is applied to both quota increment and paygo charges.
    magic_discount_header_key: Optional[str] = os.getenv("MAGIC_DISCOUNT_HEADER_KEY")
    magic_discount_header_val: Optional[str] = os.getenv("MAGIC_DISCOUNT_HEADER_VAL")
    magic_discount_amount: float = float(os.getenv("MAGIC_DISCOUNT_AMOUNT", "0.5"))

    # Chutes pinned version.
    chutes_version: str = os.getenv("CHUTES_VERSION", "0.4.46")

    # Auto stake amount when DCAing into alpha after receiving payments.
    autostake_amount: float = float(os.getenv("AUTOSTAKE_AMOUNT", "10.0"))

    # Depot.dev settings (remote image building).
    depot_token: str = os.getenv("DEPOT_TOKEN", "")
    depot_project_id: str = os.getenv("DEPOT_PROJECT_ID", "")
    depot_registry: str = os.getenv("DEPOT_REGISTRY", "")
    depot_registry_token: str = os.getenv("DEPOT_REGISTRY_TOKEN", "")
    depot_registry_rw_token: str = os.getenv("DEPOT_REGISTRY_RW_TOKEN", "")

    # Cosign Settings
    cosign_password: Optional[str] = os.getenv("COSIGN_PASSWORD")
    cosign_key: Optional[Path] = Path(os.getenv("COSIGN_KEY")) if os.getenv("COSIGN_KEY") else None
    # Managed guest-image releases use a separate provenance signing trust root. The release
    # service runs cosign verify-blob against this mounted public key on every activation/serve path;
    # a missing key therefore fails production release management closed.
    trusted_provenance_public_key_path: Path = Path(
        os.getenv(
            "TRUSTED_PROVENANCE_PUBLIC_KEY_PATH",
            "/etc/chutes/provenance/cosign.pub",
        )
    )
    # Dedicated Ed25519 trust registry for publisher-authenticated L0 bootstrap manifests.
    # This is intentionally separate from guest provenance and launch-config signing roots.
    trusted_l0_publisher_keys_path: Path = Path(
        os.getenv(
            "TRUSTED_L0_PUBLISHER_KEYS_PATH",
            "/etc/chutes/l0-publisher/keys.json",
        )
    )
    provenance_cosign_binary: str = os.getenv("PROVENANCE_COSIGN_BINARY", "cosign")
    release_attestation_max_age_seconds: int = int(
        os.getenv("RELEASE_ATTESTATION_MAX_AGE_SECONDS", "3600")
    )

    # hCaptcha
    hcaptcha_sitekey: Optional[str] = os.getenv("HCAPTCHA_SITEKEY")
    hcaptcha_secret: Optional[str] = os.getenv("HCAPTCHA_SECRET")

    # TDX Attestation settings - Measurement configuration loaded from ConfigMap
    tee_measurement_config_path: Path = Path("/etc/config/tee_measurements.yaml")
    tee_measurement_config_required: bool = (
        os.getenv("TEE_MEASUREMENT_CONFIG_REQUIRED", "false").lower() == "true"
    )
    # A signed CRL that has just crossed nextUpdate may be used only after a real KDS transport
    # outage, never after a malformed/future/bad-signature response. The extension is disabled by
    # default and hard-capped at one hour so configuration cannot turn revocation into stale trust.
    snp_crl_outage_grace_seconds: int = int(os.getenv("SNP_CRL_OUTAGE_GRACE_SECONDS", "0"))
    # A versioned (git-tracked, shipped-in-image) measurements artifact loaded ALONGSIDE the mounted
    # ConfigMap. The mounted file is environment/hardware specific and (in dev) gitignored, which
    # left the ChuteFS storage-* measurements as live-only hand-appended state -- so a from-repo
    # rebuild had no storage measurements and storage registration failed (H9). Committing the
    # storage-role measurements here makes them reproducible; the mounted file still overrides by
    # name for env-specific values.
    tee_committed_measurement_config_path: Path = (
        Path(__file__).resolve().parent / "tee_measurements.committed.yaml"
    )

    def _measurement_source_paths(self) -> List[Path]:
        """Measurement sources, failing when an explicitly required mounted source disappears."""
        sources = []
        committed = self.tee_committed_measurement_config_path
        if committed and Path(committed).exists():
            sources.append(Path(committed))
        mounted = self.tee_measurement_config_path
        mounted_explicit = bool(os.getenv("TEE_MEASUREMENT_CONFIG_PATH"))
        if mounted and Path(mounted).exists():
            sources.append(Path(mounted))
        elif mounted and (self.tee_measurement_config_required or mounted_explicit):
            raise ValueError(f"Required TEE measurement config does not exist: {mounted}")
        return sources

    @property
    def tee_measurements(self) -> List[TeeMeasurementConfig]:
        """Load TEE measurement configurations from YAML file (mounted from ConfigMap).

        Re-reads the file on every access so that ConfigMap updates propagated
        by Kubernetes are picked up without restarting the pod.
        """
        return self._load_tee_measurements()

    def _load_tee_measurements(self) -> List[TeeMeasurementConfig]:
        """Atomically reload the trust set, retaining only a previously validated set on failure."""
        source_identity = (
            str(Path(self.tee_committed_measurement_config_path).resolve())
            if self.tee_committed_measurement_config_path
            else None,
            str(Path(self.tee_measurement_config_path).resolve())
            if self.tee_measurement_config_path
            else None,
            bool(self.tee_measurement_config_required),
        )
        try:
            source_paths = self._measurement_source_paths()
            resolved_sources = tuple(str(Path(path).resolve()) for path in source_paths)
            if (
                self._tee_measurements_last_source_identity == source_identity
                and self._tee_measurements_expected_sources is not None
            ):
                missing_sources = sorted(
                    set(self._tee_measurements_expected_sources) - set(resolved_sources)
                )
                if missing_sources:
                    raise ValueError(
                        "Previously validated TEE measurement source(s) disappeared: "
                        f"{missing_sources}"
                    )
            measurements = self._parse_tee_measurements(source_paths)
            for measurement in measurements:
                measurement.config_fingerprint = measurement_config_fingerprint(measurement)
            trust_fingerprint = measurement_trust_set_fingerprint(measurements)
            for measurement in measurements:
                measurement.trust_set_fingerprint = trust_fingerprint
        except Exception as exc:
            self._tee_measurements_last_error = str(exc)
            if (
                self._tee_measurements_last_good is not None
                and self._tee_measurements_last_source_identity == source_identity
            ):
                logger.error(
                    f"TEE measurement reload failed; retaining last-known-good trust set: {exc}"
                )
                return list(self._tee_measurements_last_good)
            raise
        self._tee_measurements_last_good = list(measurements)
        self._tee_measurements_last_error = None
        self._tee_measurements_last_source_identity = source_identity
        self._tee_measurements_expected_sources = resolved_sources
        self._tee_measurements_fingerprint = trust_fingerprint
        self._tee_measurements_last_loaded_at = datetime.now(timezone.utc).isoformat()
        return measurements

    def tee_measurement_health(self) -> dict:
        """Reload and report readiness without replacing a valid set with partial input."""
        try:
            measurements = self._load_tee_measurements()
        except Exception as exc:
            return {
                "status": "unhealthy",
                "ready": False,
                "last_error": str(exc),
                "fingerprint": None,
                "measurement_count": 0,
                "last_loaded_at": self._tee_measurements_last_loaded_at,
                "expected_sources": list(self._tee_measurements_expected_sources or ()),
            }
        degraded = self._tee_measurements_last_error is not None
        return {
            "status": "degraded" if degraded else "healthy",
            "ready": not degraded,
            "last_error": self._tee_measurements_last_error,
            "fingerprint": self._tee_measurements_fingerprint,
            "measurement_count": len(measurements),
            "last_loaded_at": self._tee_measurements_last_loaded_at,
            "expected_sources": list(self._tee_measurements_expected_sources or ()),
        }

    @property
    def tee_measurements_fingerprint(self) -> str:
        """Fingerprint of the complete, currently served trust set."""
        _ = self.tee_measurements
        if not self._tee_measurements_fingerprint:
            raise ValueError("TEE measurement trust set has no validated fingerprint")
        return self._tee_measurements_fingerprint

    def _parse_tee_measurements(
        self, source_paths: Optional[List[Path]] = None
    ) -> List[TeeMeasurementConfig]:
        """Parse and validate TEE measurement configurations.

        Merges the committed (versioned) artifact with the mounted ConfigMap: entries are keyed by
        ``name`` and a mounted-file entry overrides a committed one of the same name, so
        environment-specific values win while the committed storage-role measurements stay a
        reproducible baseline.
        """
        raw_by_name: Dict[str, dict] = {}
        ordered_names: List[str] = []
        committed_names: set[str] = set()
        revoked_names: set[str] = set()
        committed_path = (
            Path(self.tee_committed_measurement_config_path).resolve()
            if self.tee_committed_measurement_config_path
            else None
        )
        for path in source_paths if source_paths is not None else self._measurement_source_paths():
            is_committed = committed_path is not None and Path(path).resolve() == committed_path
            names_in_source: set[str] = set()
            try:
                with open(path) as f:
                    doc = yaml.load(f, Loader=_UniqueKeySafeLoader)
            except Exception as e:
                error_msg = f"Failed to load TEE measurement config {path}: {e}"
                logger.error(error_msg)
                raise ValueError(error_msg) from e
            if not isinstance(doc, dict):
                raise ValueError(
                    f"Invalid TEE measurement config {path}: document root must be a mapping."
                )
            document_fields = set(doc)
            if document_fields != _MEASUREMENT_DOCUMENT_KEYS:
                missing_document_fields = _MEASUREMENT_DOCUMENT_KEYS - document_fields
                unknown_document_fields = document_fields - _MEASUREMENT_DOCUMENT_KEYS
                raise ValueError(
                    f"Invalid TEE measurement config {path}: document keys must be exactly "
                    "'measurements' and 'revoked_measurements' "
                    f"(missing={_field_names(missing_document_fields)}, "
                    f"unsupported={_field_names(unknown_document_fields)})."
                )
            raw_measurements = doc["measurements"]
            if not isinstance(raw_measurements, list):
                raise ValueError(
                    f"Invalid TEE measurement config {path}: 'measurements' must be a list."
                )
            for group in raw_measurements:
                if not isinstance(group, dict):
                    raise ValueError(
                        f"Invalid TEE measurement config {path}: each measurement group must be "
                        "a mapping."
                    )
                for measurement_config in _expand_nested_measurement_group(group, path):
                    name = measurement_config["name"]
                    if name in names_in_source:
                        raise ValueError(
                            f"Invalid TEE measurement config {path}: duplicate normalized "
                            f"measurement name {name!r} in one source."
                        )
                    names_in_source.add(name)
                    if name not in raw_by_name:
                        ordered_names.append(name)
                    # Mounted variants replace committed variants atomically by normalized name.
                    # Fields are never merged between the two source entries.
                    raw_by_name[name] = measurement_config
                    if is_committed:
                        committed_names.add(name)

            raw_revocations = doc["revoked_measurements"]
            if not isinstance(raw_revocations, list):
                raise ValueError(
                    f"Invalid TEE measurement config {path}: "
                    "'revoked_measurements' must be a list of non-empty names."
                )
            revocations_in_source: set[str] = set()
            for raw_name in raw_revocations:
                if not isinstance(raw_name, str) or not raw_name.strip():
                    raise ValueError(
                        f"Invalid TEE measurement config {path}: "
                        "'revoked_measurements' must be a list of non-empty names."
                    )
                name = raw_name.strip()
                if name in revocations_in_source:
                    raise ValueError(
                        f"Invalid TEE measurement config {path}: duplicate normalized revocation "
                        f"{name!r} in one source."
                    )
                revocations_in_source.add(name)
            # Unknown tombstones are intentionally retained: a mounted source may revoke a pin
            # before that pin appears in another source or a later deployment.
            revoked_names.update(revocations_in_source)

        if revoked_names:
            # A provenance-bound image is one atomic trust object even when it has one launch
            # measurement per vCPU class.  A tombstone naming any member retires the complete
            # declared set; otherwise set validation below would reject the partial matrix and a
            # runtime reload would fall back to an LKG that still trusts the explicitly revoked
            # member.
            expanded_revocations = set(revoked_names)
            changed = True
            while changed:
                changed = False
                for name, config in raw_by_name.items():
                    raw_image_names = config.get("image_measurement_names")
                    if not isinstance(raw_image_names, list):
                        continue
                    image_names = {
                        str(image_name).strip()
                        for image_name in raw_image_names
                        if isinstance(image_name, str) and image_name.strip()
                    }
                    if (
                        name in expanded_revocations
                        or image_names.intersection(expanded_revocations)
                    ) and not image_names.issubset(expanded_revocations):
                        expanded_revocations.update(image_names)
                        changed = True
            revoked_names = expanded_revocations
            raw_by_name = {
                name: config for name, config in raw_by_name.items() if name not in revoked_names
            }
            ordered_names = [name for name in ordered_names if name not in revoked_names]

        measurements: List[TeeMeasurementConfig] = []
        for config_name in ordered_names:
            measurement_config = raw_by_name[config_name]
            version = measurement_config.get("version")
            if not isinstance(version, str) or not version.strip():
                error_msg = (
                    f"Missing or invalid 'version' for measurement config '{config_name}'. "
                    "Each measurement group must use a non-empty YAML string."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)
            version = version.strip()

            # Never infer "hardened" from an absent or loosely typed value. A YAML string such as
            # "false" is truthy in Python, so only a real YAML boolean is accepted.
            if "debug" not in measurement_config or not isinstance(
                measurement_config["debug"], bool
            ):
                raise ValueError(
                    f"Missing or invalid 'debug' posture for measurement config '{config_name}'. "
                    "Every measurement must explicitly set debug: true or debug: false using a YAML "
                    "boolean; an omitted posture must not be treated as hardened."
                )
            is_debug = measurement_config["debug"]
            if is_debug and not self.allow_debug_measurements:
                raise ValueError(
                    f"Measurement config '{config_name}' is tagged debug: true but "
                    "ALLOW_DEBUG_MEASUREMENTS is not set. Debug images forward user logs to the "
                    "host-readable serial console and must not be accepted in production. Remove the "
                    "config from the production ConfigMap, or set ALLOW_DEBUG_MEASUREMENTS=true for a "
                    "dev validator."
                )

            # Bind committed pins to the exact qcow2 digest and complete measurement-name set. This
            # relation is cross-checked against separately signed canonical provenance at managed
            # production activation; only explicit debug dev releases may use it unsigned.
            has_image_sha = "image_sha256" in measurement_config
            has_image_names = "image_measurement_names" in measurement_config
            if has_image_sha != has_image_names:
                raise ValueError(
                    f"Incomplete image provenance for measurement config '{config_name}': "
                    "image_sha256 and image_measurement_names must be supplied together."
                )
            if config_name in committed_names and not has_image_sha:
                raise ValueError(
                    f"Missing image provenance for committed measurement config '{config_name}'. "
                    "Committed pins must bind image_sha256, image_measurement_names, and debug posture."
                )

            image_sha256 = None
            image_measurement_names = None
            if has_image_sha:
                raw_image_sha256 = measurement_config["image_sha256"]
                if not isinstance(raw_image_sha256, str):
                    raise ValueError(
                        f"Invalid image_sha256 for measurement config '{config_name}': "
                        "expected an actual YAML string."
                    )
                image_sha256 = raw_image_sha256.strip().lower()
                if len(image_sha256) != 64 or any(
                    c not in "0123456789abcdef" for c in image_sha256
                ):
                    raise ValueError(
                        f"Invalid image_sha256 for measurement config '{config_name}': "
                        "expected 64 hex characters."
                    )
                raw_image_names = measurement_config["image_measurement_names"]
                if not isinstance(raw_image_names, list) or not raw_image_names:
                    raise ValueError(
                        f"Invalid image_measurement_names for measurement config '{config_name}': "
                        "expected a non-empty list."
                    )
                if any(not isinstance(name, str) or not name.strip() for name in raw_image_names):
                    raise ValueError(
                        f"Invalid image_measurement_names for measurement config '{config_name}': "
                        "every name must be a non-empty string."
                    )
                image_measurement_names = [name.strip() for name in raw_image_names]
                if len(set(image_measurement_names)) != len(image_measurement_names):
                    raise ValueError(
                        f"Invalid image_measurement_names for measurement config '{config_name}': "
                        "duplicate normalized names are not allowed."
                    )
                if config_name not in image_measurement_names:
                    raise ValueError(
                        f"Invalid image provenance for measurement config '{config_name}': "
                        "its own name is absent from image_measurement_names."
                    )

            def _require_hex96(value: object, field: str) -> str:
                if not isinstance(value, str):
                    raise ValueError(
                        f"Invalid {field} for measurement config '{config_name}': "
                        "expected an actual YAML string containing 96 hex characters."
                    )
                text = value.upper().strip()
                if len(text) != 96 or any(c not in "0123456789ABCDEF" for c in text):
                    raise ValueError(
                        f"Invalid {field} for measurement config '{config_name}': "
                        f"expected 96 hex characters, got {len(text)}."
                    )
                return text

            # gpu_count is REQUIRED and must be explicit. 0 denotes a CPU-only (GPU-less)
            # measurement config (the validator verifies measurements only and skips GPU
            # evidence / GPU-count matching). An absent gpu_count must NOT silently become a
            # CPU config -- that would skip GPU evidence verification for a GPU image.
            gpu_count = measurement_config.get("gpu_count")
            if gpu_count is None:
                raise ValueError(
                    f"Missing 'gpu_count' for measurement config '{config_name}'. "
                    "All TEE measurement configs must specify gpu_count (use 0 for CPU-only configs)."
                )
            if not isinstance(gpu_count, int) or isinstance(gpu_count, bool):
                raise ValueError(
                    f"Invalid 'gpu_count' for measurement config '{config_name}': "
                    "expected a non-negative YAML integer."
                )
            if gpu_count < 0:
                raise ValueError(
                    f"Invalid 'gpu_count' for measurement config '{config_name}': "
                    "expected a non-negative integer."
                )
            # Optional infrastructure provider hint ("gcp" | "bare-metal").
            provider = measurement_config.get("provider")
            if provider is not None and (
                not isinstance(provider, str) or provider not in {"gcp", "bare-metal"}
            ):
                raise ValueError(
                    f"Invalid provider for measurement config '{config_name}': "
                    "expected exactly 'gcp' or 'bare-metal'."
                )
            raw_expected_gpus = measurement_config.get("expected_gpus")
            if not isinstance(raw_expected_gpus, list) or any(
                not isinstance(gpu, str) or not gpu.strip() for gpu in raw_expected_gpus
            ):
                raise ValueError(
                    f"Invalid 'expected_gpus' for measurement config '{config_name}': "
                    "expected a list of non-empty strings."
                )
            expected_gpus = [gpu.strip().lower() for gpu in raw_expected_gpus]
            if len(expected_gpus) != len(set(expected_gpus)):
                raise ValueError(
                    f"Invalid 'expected_gpus' for measurement config '{config_name}': "
                    "duplicate GPU identifiers are not allowed."
                )
            if gpu_count == 0 and expected_gpus:
                raise ValueError(
                    f"CPU-only measurement config '{config_name}' cannot declare expected_gpus."
                )
            if gpu_count > 0 and not expected_gpus:
                raise ValueError(
                    f"GPU measurement config '{config_name}' must declare expected_gpus."
                )
            tee_type = measurement_config.get("tee_type")
            if not isinstance(tee_type, str) or tee_type not in {"tdx", "sev-snp"}:
                raise ValueError(
                    f"Invalid tee_type for measurement config '{config_name}': "
                    "expected exactly 'tdx' or 'sev-snp'."
                )
            if gpu_count == 0 and provider not in {"gcp", "bare-metal"}:
                raise ValueError(
                    f"CPU-only measurement config '{config_name}' must set provider to "
                    "'gcp' or 'bare-metal'."
                )
            raw_rc = measurement_config.get("rc", False)
            if not isinstance(raw_rc, bool):
                raise ValueError(
                    f"Invalid 'rc' for measurement config '{config_name}': expected a YAML boolean."
                )
            rc = raw_rc

            common_fields = {
                "version",
                "name",
                "description",
                "provider",
                "tee_type",
                "debug",
                "rc",
                "image_sha256",
                "image_measurement_names",
                "expected_gpus",
                "gpu_count",
                "compute_type",
                "role",
                "management_mode",
                "gpu_profile_id",
                "gpu_profile_contract_sha256",
                "gpu_measurement_fingerprint",
                "gpu_fingerprint_version",
                "provenance_schema_version",
            }
            tdx_fields = {
                "mrtd",
                "rtmr0",
                "rtmr1",
                "rtmr2",
                "boot_rtmr3",
                "runtime_rtmr3",
                "profile_id",
                "vcpus",
                "memory_mib",
            }
            snp_fields = {
                "measurement",
                "policy",
                "min_tcb",
                "id_key_digest",
                "processor_model",
                "expected_vmpl",
                "vtpm_pcrs",
                "vtpm_security_flags",
            }
            allowed_fields = common_fields | (snp_fields if tee_type == "sev-snp" else tdx_fields)
            unexpected_fields = sorted(set(measurement_config) - allowed_fields)
            if unexpected_fields:
                raise ValueError(
                    f"Unsupported field(s) for canonical {tee_type} measurement config "
                    f"'{config_name}': {unexpected_fields}."
                )

            # --- AMD SEV-SNP: single launch measurement + policy + min-TCB; no MRTD/RTMRs ---
            if tee_type == "sev-snp":
                measurement_hex = _require_hex96(
                    measurement_config.get("measurement"), "measurement"
                )
                # policy is REQUIRED, not optional: the SNP launch measurement does not cover the
                # policy field, so an unpinned policy lets a host flip non-DEBUG bits (SMT,
                # MIGRATE_MA, ...) that the measurement match would never catch.
                raw_policy = measurement_config.get("policy")
                if raw_policy is None:
                    raise ValueError(
                        f"Missing 'policy' for SNP measurement config '{config_name}'. SNP configs "
                        "must pin the full guest policy (the launch measurement does not cover it)."
                    )
                if isinstance(raw_policy, bool) or not isinstance(raw_policy, (str, int)):
                    raise ValueError(
                        f"Invalid 'policy' for SNP measurement config '{config_name}': expected "
                        "an actual YAML integer or an integer string such as '0x30000'."
                    )
                try:
                    policy = int(raw_policy, 0) if isinstance(raw_policy, str) else raw_policy
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid 'policy' for SNP measurement config '{config_name}': expected "
                        "an integer string such as '0x30000'."
                    ) from exc
                if policy & (1 << 19):
                    raise ValueError(
                        f"SNP measurement config '{config_name}' sets the guest policy DEBUG "
                        "bit (0x80000); a debuggable guest offers no confidentiality. Refusing."
                    )
                # min_tcb is REQUIRED, not optional: without a minimum reported TCB there is no
                # anti-rollback -- a host could run firmware with known-vulnerable SPL levels and
                # still match the config.
                raw_min_tcb = measurement_config.get("min_tcb")
                if not raw_min_tcb:
                    raise ValueError(
                        f"Missing 'min_tcb' for SNP measurement config '{config_name}'. SNP configs "
                        "must pin minimum TCB levels ({{bootloader,tee,snp,microcode}}) for "
                        "anti-rollback."
                    )
                if not isinstance(raw_min_tcb, dict):
                    raise ValueError(
                        f"Invalid 'min_tcb' for SNP measurement config '{config_name}': "
                        "expected a mapping."
                    )
                expected_tcb_keys = {"bootloader", "tee", "snp", "microcode"}
                actual_tcb_keys = set(raw_min_tcb)
                normalized_tcb_keys = {
                    key.lower() for key in actual_tcb_keys if isinstance(key, str)
                }
                case_duplicates = sorted(
                    key
                    for key in normalized_tcb_keys
                    if sum(
                        isinstance(candidate, str) and candidate.lower() == key
                        for candidate in actual_tcb_keys
                    )
                    > 1
                )
                if actual_tcb_keys != expected_tcb_keys:
                    missing = sorted(expected_tcb_keys - normalized_tcb_keys)
                    unknown = sorted(
                        repr(key)
                        for key in actual_tcb_keys
                        if not isinstance(key, str) or key not in expected_tcb_keys
                    )
                    raise ValueError(
                        f"Invalid 'min_tcb' for SNP measurement config '{config_name}': "
                        f"keys must be exactly lowercase {sorted(expected_tcb_keys)} "
                        f"(missing={missing}, unknown_or_wrong_case={unknown}, "
                        f"case_duplicates={case_duplicates})."
                    )
                min_tcb = {}
                for key, value in raw_min_tcb.items():
                    if not isinstance(value, int) or isinstance(value, bool):
                        raise ValueError(
                            f"Invalid min_tcb.{key} for measurement config '{config_name}': "
                            "expected an actual YAML integer in 0..255 "
                            "(not bool, string, or float)."
                        )
                    if not 0 <= value <= 255:
                        raise ValueError(
                            f"Invalid min_tcb.{key} for measurement config '{config_name}': "
                            "expected an integer in 0..255."
                        )
                    min_tcb[key] = value
                id_key_digest = None
                if "id_key_digest" in measurement_config:
                    id_key_digest = _require_hex96(
                        measurement_config["id_key_digest"], "id_key_digest"
                    )
                processor_model = measurement_config.get("processor_model")
                if not isinstance(processor_model, str):
                    raise ValueError(
                        f"Invalid processor_model for SNP measurement config '{config_name}': "
                        "expected an actual YAML string."
                    )
                if processor_model not in {"Genoa", "Milan", "Turin"}:
                    raise ValueError(
                        f"Invalid processor_model for SNP measurement config '{config_name}': "
                        "expected Genoa, Milan, or Turin."
                    )
                # GCP image identity: pinned GCE vTPM PCRs (sha256, 64 hex each). REQUIRED for
                # provider 'gcp': there the SNP launch measurement is Google firmware only, so a
                # config without vtpm_pcrs would match on firmware alone and never check WHICH
                # image is running.
                # Image identity on SNP is provider-specific and MUST fail closed. On GCP the SNP
                # launch measurement is ONLY Google firmware (identical for every GCP SNP VM), so
                # image identity hangs entirely on the GCE vTPM PCRs; on bare-metal the dm-verity
                # roothash is folded into the SNP launch measurement, so the measurement IS the image
                # identity. A missing/unknown provider previously defaulted vtpm_pcrs off, which would
                # register an attacker-controlled image on real GCP SNP -- so provider is REQUIRED.
                if provider not in ("gcp", "bare-metal"):
                    raise ValueError(
                        f"SNP measurement config '{config_name}' must set provider to 'gcp' or "
                        f"'bare-metal' (got {provider!r}); image identity is verified differently per "
                        "provider, so an unset/unknown provider is rejected (fail closed)."
                    )
                vtpm_pcrs = None
                vtpm_security_flags = None
                if provider == "gcp":
                    raw_vtpm = measurement_config.get("vtpm_pcrs")
                    if not isinstance(raw_vtpm, dict):
                        raise ValueError(
                            f"Invalid vtpm_pcrs for SNP config '{config_name}': expected a mapping "
                            "containing exactly string keys '8' and '9'."
                        )
                    expected_pcrs = {"8", "9"}
                    if set(raw_vtpm) != expected_pcrs or any(
                        not isinstance(key, str) for key in raw_vtpm
                    ):
                        raise ValueError(
                            f"Invalid vtpm_pcrs for SNP config '{config_name}': keys must be "
                            "exactly the strings '8' and '9'."
                        )
                    vtpm_pcrs = {}
                    for key, value in raw_vtpm.items():
                        if not isinstance(value, str):
                            raise ValueError(
                                f"Invalid vtpm_pcrs[{key}] for SNP config '{config_name}': "
                                "expected an actual YAML string containing 64 hex characters."
                            )
                        val = value.upper().strip()
                        if len(val) != 64 or any(c not in "0123456789ABCDEF" for c in val):
                            raise ValueError(
                                f"Invalid vtpm_pcrs[{key}] for SNP config '{config_name}': "
                                f"expected 64 hex chars (sha256), got {len(val)}."
                            )
                        vtpm_pcrs[key] = val

                    raw_vtpm_security_flags = measurement_config.get("vtpm_security_flags")
                    if not isinstance(raw_vtpm_security_flags, dict):
                        raise ValueError(
                            f"Invalid vtpm_security_flags for SNP config '{config_name}': "
                            "expected a map containing exactly boolean string tags 2, 3, 4, and 5."
                        )
                    expected_flag_tags = {"2", "3", "4", "5"}
                    if set(raw_vtpm_security_flags) != expected_flag_tags or any(
                        not isinstance(tag, str) for tag in raw_vtpm_security_flags
                    ):
                        raise ValueError(
                            f"Invalid vtpm_security_flags for SNP config '{config_name}': "
                            "keys must be exactly the string tags 2, 3, 4, and 5."
                        )
                    vtpm_security_flags = {}
                    for tag, raw_value in raw_vtpm_security_flags.items():
                        if not isinstance(raw_value, bool):
                            raise ValueError(
                                f"Invalid vtpm_security_flags[{tag}] for SNP config "
                                f"'{config_name}': expected an actual YAML boolean."
                            )
                        vtpm_security_flags[tag] = raw_value
                raw_vmpl = measurement_config.get("expected_vmpl")
                if not isinstance(raw_vmpl, int) or isinstance(raw_vmpl, bool):
                    raise ValueError(
                        f"Missing or invalid 'expected_vmpl' for SNP measurement config "
                        f"'{config_name}'. Pin an actual YAML integer observed in a real "
                        "registration quote."
                    )
                expected_vmpl = raw_vmpl
                if expected_vmpl not in range(4):
                    raise ValueError(
                        f"Invalid expected_vmpl for SNP measurement config '{config_name}': "
                        "expected an integer in 0..3."
                    )
                measurements.append(
                    TeeMeasurementConfig(
                        version=version,
                        name=config_name,
                        expected_gpus=expected_gpus,
                        gpu_count=gpu_count,
                        provider=provider,
                        tee_type="sev-snp",
                        rc=rc,
                        measurement=measurement_hex,
                        policy=policy,
                        min_tcb=min_tcb,
                        id_key_digest=id_key_digest,
                        processor_model=processor_model,
                        expected_vmpl=expected_vmpl,
                        vtpm_pcrs=vtpm_pcrs,
                        vtpm_security_flags=vtpm_security_flags,
                        debug=is_debug,
                        image_sha256=image_sha256,
                        image_measurement_names=image_measurement_names,
                    )
                )
                continue

            # --- Intel TDX: canonical normalized scalars. RTMR0-2 are identical at boot/runtime.
            # Boot RTMR3 defaults to zero, while bare-metal guests that extend it before their boot
            # quote pin the observed value. Runtime RTMR3 binds the measured guest stack.
            mrtd_upper = _require_hex96(measurement_config.get("mrtd"), "mrtd")
            rtmr0 = _require_hex96(measurement_config.get("rtmr0"), "rtmr0")
            rtmr1 = _require_hex96(measurement_config.get("rtmr1"), "rtmr1")
            rtmr2 = _require_hex96(measurement_config.get("rtmr2"), "rtmr2")
            boot_rtmr3 = _require_hex96(
                measurement_config.get("boot_rtmr3", ZERO_RTMR), "boot_rtmr3"
            )
            runtime_rtmr3 = _require_hex96(measurement_config.get("runtime_rtmr3"), "runtime_rtmr3")

            measurements.append(
                TeeMeasurementConfig(
                    version=version,
                    name=config_name,
                    expected_gpus=expected_gpus,
                    gpu_count=gpu_count,
                    provider=provider,
                    tee_type="tdx",
                    debug=is_debug,
                    rc=rc,
                    mrtd=mrtd_upper,
                    rtmr0=rtmr0,
                    rtmr1=rtmr1,
                    rtmr2=rtmr2,
                    boot_rtmr3=boot_rtmr3,
                    runtime_rtmr3=runtime_rtmr3,
                    profile_id=measurement_config.get("profile_id"),
                    vcpus=measurement_config.get("vcpus"),
                    memory_mib=measurement_config.get("memory_mib"),
                    image_sha256=image_sha256,
                    image_measurement_names=image_measurement_names,
                    compute_type=measurement_config.get("compute_type"),
                    role=measurement_config.get("role"),
                    management_mode=measurement_config.get("management_mode"),
                    gpu_profile_id=measurement_config.get("gpu_profile_id"),
                    gpu_profile_contract_sha256=measurement_config.get(
                        "gpu_profile_contract_sha256"
                    ),
                    gpu_measurement_fingerprint=measurement_config.get(
                        "gpu_measurement_fingerprint"
                    ),
                    gpu_fingerprint_version=measurement_config.get("gpu_fingerprint_version"),
                    provenance_schema_version=measurement_config.get("provenance_schema_version"),
                )
            )

        # Validate the relation as a set after every source has been merged. This catches a mounted
        # override that changes one committed entry but omits/changes the rest of its provenance,
        # unknown names, mixed shared posture, and partial per-vCPU matrices. Version is deliberately
        # excluded: existing size-class matrices retain distinct audit versions per hardware variant.
        def _shared_image_fields(config: TeeMeasurementConfig) -> dict:
            shared = {
                "debug": config.debug,
                "rc": config.rc,
                "tee_type": config.tee_type,
                "provider": config.provider,
            }
            if config.compute_type == "gpu":
                shared.update(
                    {
                        "compute_type": config.compute_type,
                        "role": config.role,
                        "gpu_profile_contract_sha256": config.gpu_profile_contract_sha256,
                        "gpu_fingerprint_version": config.gpu_fingerprint_version,
                        "provenance_schema_version": config.provenance_schema_version,
                    }
                )
                return shared
            if config.tee_type == "tdx":
                shared.update(
                    {
                        "mrtd": config.mrtd,
                        "boot_rtmr3": config.boot_rtmr3,
                        "runtime_rtmr3": config.runtime_rtmr3,
                    }
                )
                if config.profile_id is None:
                    shared.update(
                        {
                            "rtmr1": config.rtmr1,
                            "rtmr2": config.rtmr2,
                        }
                    )
            else:
                shared.update(
                    {
                        "processor_model": config.processor_model,
                        "policy": config.policy,
                        "min_tcb": config.min_tcb,
                        "expected_vmpl": config.expected_vmpl,
                        "id_key_digest": config.id_key_digest,
                        "vtpm_pcrs": config.vtpm_pcrs,
                        "vtpm_security_flags": config.vtpm_security_flags,
                    }
                )
            return shared

        by_name = {config.name: config for config in measurements}
        for config in measurements:
            if not config.image_sha256:
                continue
            declared_names = set(config.image_measurement_names or [])
            for name in declared_names:
                peer = by_name.get(name)
                if (
                    peer is None
                    or peer.image_sha256 != config.image_sha256
                    or list(peer.image_measurement_names or [])
                    != list(config.image_measurement_names or [])
                    or _shared_image_fields(peer) != _shared_image_fields(config)
                    or (
                        config.compute_type != "gpu"
                        and (
                            peer.gpu_count != config.gpu_count
                            or peer.expected_gpus != config.expected_gpus
                        )
                    )
                ):
                    raise ValueError(
                        f"Inconsistent image provenance for measurement set "
                        f"{sorted(declared_names)}: every declared entry must be loaded and bind "
                        "the same image_sha256, ordered set, shared TEE/provider/attestation fields, "
                        "and CPU/GPU inventory."
                    )

        logger.info(f"Loaded {len(measurements)} TEE measurement configurations")
        return measurements

    @property
    def tee_minimum_boot_version(self) -> str:
        """CPU minimum retained for existing callers."""

        return self.tee_minimum_boot_version_for("cpu")

    def tee_minimum_boot_version_for(self, compute_type: str) -> str:
        """Minimum VM version accepted within one compute-scoped trust stream.

        Existing ``TEE_MINIMUM_BOOT_VERSION`` remains the CPU override. GPU may use
        ``TEE_GPU_MINIMUM_BOOT_VERSION`` and otherwise derives only from GPU pins.
        """
        if compute_type not in {"cpu", "gpu"}:
            raise ValueError("compute_type must be cpu or gpu")
        env_name = (
            "TEE_MINIMUM_BOOT_VERSION" if compute_type == "cpu" else "TEE_GPU_MINIMUM_BOOT_VERSION"
        )
        if pinned := os.getenv(env_name):
            return pinned
        if not self._measurement_source_paths():
            return "0.0.0"
        versions = [
            measurement.version
            for measurement in self.tee_measurements
            if measurement.version
            and not measurement.rc
            and ((measurement.gpu_count > 0) == (compute_type == "gpu"))
        ]
        if not versions:
            return "0.0.0"
        latest = versions[0]
        for v in versions[1:]:
            if semcomp(v, latest) > 0:
                latest = v
        return latest

    cache_passphrase_key: Optional[str] = os.getenv("CACHE_PASSPHRASE_KEY")

    # TDX verification service URLs (if using Intel's remote verification)
    tdx_verification_url: Optional[str] = os.getenv("TDX_VERIFICATION_URL")
    tdx_cert_chain_url: Optional[str] = os.getenv("TDX_CERT_CHAIN_URL")

    # Nonce expiration (minutes)
    attestation_nonce_expiry: int = int(os.getenv("ATTESTATION_NONCE_EXPIRY", "10"))

    # OpenRouter free usage settings.
    or_free_user_id: str = os.getenv("OR_FREE_USER_ID", "replaceme")

    # Agent registration settings.
    agent_registration_threshold: float = float(os.getenv("AGENT_REGISTRATION_THRESHOLD", "50.0"))
    agent_registration_tolerance: float = float(os.getenv("AGENT_REGISTRATION_TOLERANCE", "0.10"))
    agent_registration_ttl_hours: int = int(os.getenv("AGENT_REGISTRATION_TTL_HOURS", "24"))

    # TEE endpoint-health probe thresholds.
    server_health_degraded_threshold_seconds: int = int(
        os.getenv("SERVER_HEALTH_DEGRADED_THRESHOLD_SECONDS", str(12 * 3600))
    )
    server_health_offline_threshold_seconds: int = int(
        os.getenv("SERVER_HEALTH_OFFLINE_THRESHOLD_SECONDS", str(72 * 3600))
    )
    server_health_max_concurrent: int = int(os.getenv("SERVER_HEALTH_MAX_CONCURRENT", "32"))


# Subscription tier: quota -> monthly price in USD (canonical values only).
SUBSCRIPTION_TIERS = {
    300: 3.0,
    2000: 10.0,
    5000: 20.0,
}
SUBSCRIPTION_PAYGO_DISCOUNTS = {
    3.0: 0.03,
    10.0: 0.06,
    20.0: 0.1,
}
SUBSCRIPTION_MONTHLY_CAP_MULTIPLIER = 5.0
SUBSCRIPTION_4H_CAP_MULTIPLIER = 75.0
FOUR_HOUR_CHUNKS_PER_MONTH = 180  # 30 days * 24 hours / 4 hours


def get_subscription_tier(quota: int) -> float | None:
    """
    Get the monthly price for a subscription quota value.
    Handles off-by-one quotas (e.g., 301, 2001, 5001) used for custom subs.
    """
    if quota in SUBSCRIPTION_TIERS:
        return SUBSCRIPTION_TIERS[quota]
    if quota - 1 in SUBSCRIPTION_TIERS:
        return SUBSCRIPTION_TIERS[quota - 1]
    return None


def is_custom_subscription(quota: int) -> bool:
    """Off-by-one quotas represent custom subscriptions."""
    return quota not in SUBSCRIPTION_TIERS and quota - 1 in SUBSCRIPTION_TIERS


settings = Settings()
