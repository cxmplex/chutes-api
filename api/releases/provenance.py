"""Canonical guest-image provenance parsing and cosign verification."""

from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404 - fixed argv invokes the operator-configured cosign binary.
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
DIRECT_TDX_SCHEMA_VERSION = 2
REQUIRED_RELEASE_VCPU_SIZES = (1, 2, 4, 8)
REQUIRED_DIRECT_TDX_PROFILES = tuple(
    {
        "id": f"{vcpus}vcpu-{memory_mib // 1024}g",
        "vcpus": vcpus,
        "memory_mib": memory_mib,
    }
    for vcpus in (1, 2, 4, 8)
    for memory_mib in (8192, 16384, 32768, 65536)
)
MAX_PROVENANCE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
_HEX96_RE = re.compile(r"^[0-9A-F]{96}$")
_HEX64_RE = re.compile(r"^[0-9A-F]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class ProvenanceError(ValueError):
    """A provenance payload is malformed, non-canonical, or not trusted."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate provenance JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ProvenanceError(f"invalid provenance JSON constant: {value}")


def canonical_provenance_bytes(document: dict[str, Any]) -> bytes:
    """Serialize the one accepted provenance representation."""
    try:
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProvenanceError("provenance is not canonical JSON data") from exc
    return encoded + b"\n"


def load_canonical_provenance(payload: str) -> dict[str, Any]:
    """Load a bounded payload and require byte-for-byte canonical JSON."""
    if not isinstance(payload, str):
        raise ProvenanceError("provenance payload must be a string")
    try:
        raw = payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProvenanceError("provenance payload must contain only ASCII") from exc
    if not raw or len(raw) > MAX_PROVENANCE_BYTES:
        raise ProvenanceError("provenance payload is empty or too large")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProvenanceError("provenance payload is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ProvenanceError("provenance document root must be an object")
    if canonical_provenance_bytes(document) != raw:
        raise ProvenanceError(
            "provenance payload is not canonical JSON (sorted compact keys plus one newline required)"
        )
    validate_provenance_document(document)
    return document


def select_direct_tdx_profile(
    document: dict[str, Any],
    *,
    requested_vcpus: int,
    requested_memory_mib: int,
) -> dict[str, Any]:
    """Round a request to the least over-provisioned signed direct-TDX profile."""

    validate_provenance_document(document)
    if document["schema_version"] != DIRECT_TDX_SCHEMA_VERSION:
        raise ProvenanceError("provenance does not contain direct-TDX launch profiles")
    if (
        not isinstance(requested_vcpus, int)
        or isinstance(requested_vcpus, bool)
        or requested_vcpus <= 0
        or not isinstance(requested_memory_mib, int)
        or isinstance(requested_memory_mib, bool)
        or requested_memory_mib <= 0
    ):
        raise ProvenanceError("requested TDX resources must be positive integers")
    candidates = [
        profile
        for profile in document["required_profiles"]
        if profile["vcpus"] >= requested_vcpus and profile["memory_mib"] >= requested_memory_mib
    ]
    if not candidates:
        raise ProvenanceError(
            "no signed direct-TDX launch profile satisfies "
            f"{requested_vcpus} vCPU/{requested_memory_mib} MiB"
        )
    return min(
        candidates,
        key=lambda profile: (
            profile["vcpus"] - requested_vcpus,
            profile["memory_mib"] - requested_memory_mib,
            profile["vcpus"],
            profile["memory_mib"],
        ),
    )


def _require_exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ProvenanceError(
            f"{path} must contain exactly {sorted(expected)} "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _validate_rtmrs(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise ProvenanceError(f"{path} must be an object")
    _require_exact_keys(value, {"RTMR0", "RTMR1", "RTMR2", "RTMR3"}, path)
    for name, digest in value.items():
        if not isinstance(digest, str) or not _HEX96_RE.fullmatch(digest):
            raise ProvenanceError(f"{path}.{name} must be 96 uppercase hex characters")


def _validate_measurement_values(values: Any, *, tee_type: str, provider: str, path: str) -> None:
    if not isinstance(values, dict):
        raise ProvenanceError(f"{path} must be an object")
    if tee_type == "tdx":
        _require_exact_keys(values, {"mrtd", "boot_rtmrs", "runtime_rtmrs"}, path)
        if not isinstance(values["mrtd"], str) or not _HEX96_RE.fullmatch(values["mrtd"]):
            raise ProvenanceError(f"{path}.mrtd must be 96 uppercase hex characters")
        _validate_rtmrs(values["boot_rtmrs"], f"{path}.boot_rtmrs")
        _validate_rtmrs(values["runtime_rtmrs"], f"{path}.runtime_rtmrs")
        return

    expected = (
        {"measurement", "vtpm_pcrs", "vtpm_security_flags"}
        if provider == "gcp"
        else {"measurement"}
    )
    _require_exact_keys(values, expected, path)
    if not isinstance(values["measurement"], str) or not _HEX96_RE.fullmatch(values["measurement"]):
        raise ProvenanceError(f"{path}.measurement must be 96 uppercase hex characters")
    if provider == "gcp":
        vtpm_pcrs = values["vtpm_pcrs"]
        if not isinstance(vtpm_pcrs, dict):
            raise ProvenanceError(f"{path}.vtpm_pcrs must be an object")
        if set(vtpm_pcrs) != {"8", "9"}:
            raise ProvenanceError(f"{path}.vtpm_pcrs must contain exactly PCR8 and PCR9")
        for index, digest in vtpm_pcrs.items():
            if not isinstance(digest, str) or not _HEX64_RE.fullmatch(digest):
                raise ProvenanceError(
                    f"{path}.vtpm_pcrs.{index} must be 64 uppercase hex characters"
                )
        vtpm_security_flags = values["vtpm_security_flags"]
        if not isinstance(vtpm_security_flags, dict):
            raise ProvenanceError(f"{path}.vtpm_security_flags must be an object")
        if set(vtpm_security_flags) != {"2", "3", "4", "5"}:
            raise ProvenanceError(
                f"{path}.vtpm_security_flags must contain exactly tags 2, 3, 4, and 5"
            )
        if any(not isinstance(value, bool) for value in vtpm_security_flags.values()):
            raise ProvenanceError(f"{path}.vtpm_security_flags values must be JSON booleans")


def _validate_direct_tdx_provenance(document: dict[str, Any]) -> None:
    _require_exact_keys(
        document,
        {
            "schema_version",
            "image",
            "tee_type",
            "provider",
            "role",
            "version",
            "build_flags",
            "gpu_count",
            "expected_gpus",
            "required_profiles",
            "launch_contract",
            "measurements",
        },
        "provenance",
    )
    if document["tee_type"] != "tdx" or document["provider"] != "bare-metal":
        raise ProvenanceError("schema_version 2 is reserved for bare-metal direct-boot TDX")
    if document["role"] not in {"chute", "storage"}:
        raise ProvenanceError("provenance role must be chute or storage")
    if not isinstance(document["version"], str) or not _VERSION_RE.fullmatch(document["version"]):
        raise ProvenanceError("provenance version is missing or invalid")
    if document["gpu_count"] != 0 or isinstance(document["gpu_count"], bool):
        raise ProvenanceError("managed guest provenance must declare gpu_count=0")
    if document["expected_gpus"] != []:
        raise ProvenanceError("managed guest provenance must declare expected_gpus=[]")

    image = document["image"]
    if not isinstance(image, dict):
        raise ProvenanceError("provenance image must be an object")
    _require_exact_keys(image, {"filename", "sha256"}, "provenance.image")
    if not isinstance(image["filename"], str) or not re.fullmatch(
        r"[A-Za-z0-9._+-]+\.qcow2", image["filename"]
    ):
        raise ProvenanceError("provenance image.filename must name a simple qcow2 file")
    if not isinstance(image["sha256"], str) or not _SHA256_RE.fullmatch(image["sha256"]):
        raise ProvenanceError("provenance image.sha256 must be 64 lowercase hex characters")

    flags = document["build_flags"]
    if not isinstance(flags, dict):
        raise ProvenanceError("provenance build_flags must be an object")
    _require_exact_keys(flags, {"debug_build", "debug_logging"}, "provenance.build_flags")
    if not all(isinstance(flags[key], bool) for key in flags):
        raise ProvenanceError("provenance debug flags must be JSON booleans")
    if flags["debug_logging"] and not flags["debug_build"]:
        raise ProvenanceError("debug_logging=true requires debug_build=true")
    if image["filename"].endswith("-debug.qcow2") != flags["debug_build"]:
        raise ProvenanceError("image filename and debug_build posture disagree")

    launch_contract = document["launch_contract"]
    contract_keys = {
        "boot_mode",
        "sha256",
        "qemu_binary_sha256",
        "qemu_package_version",
        "machine_type",
        "firmware_sha256",
        "image_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "cmdline_sha256",
        "verity_roothash",
        "kernel_measurement_mode",
    }
    if not isinstance(launch_contract, dict):
        raise ProvenanceError("provenance launch_contract must be an object")
    _require_exact_keys(launch_contract, contract_keys, "provenance.launch_contract")
    if launch_contract["boot_mode"] != "direct":
        raise ProvenanceError("provenance launch_contract.boot_mode must be direct")
    if launch_contract["image_sha256"] != image["sha256"]:
        raise ProvenanceError("launch_contract image_sha256 must match provenance image")
    for key in (
        "sha256",
        "qemu_binary_sha256",
        "firmware_sha256",
        "image_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "cmdline_sha256",
        "verity_roothash",
    ):
        if not isinstance(launch_contract[key], str) or not _SHA256_RE.fullmatch(
            launch_contract[key]
        ):
            raise ProvenanceError(
                f"provenance.launch_contract.{key} must be 64 lowercase hex characters"
            )
    for key in ("qemu_package_version", "machine_type"):
        if not isinstance(launch_contract[key], str) or not launch_contract[key]:
            raise ProvenanceError(f"provenance.launch_contract.{key} must be non-empty")
    if launch_contract["kernel_measurement_mode"] not in {
        "qemu-patched",
        "efi-image-as-is",
    }:
        raise ProvenanceError("provenance launch_contract kernel mode is invalid")

    required_profiles = document["required_profiles"]
    measurements = document["measurements"]
    if (
        not isinstance(required_profiles, list)
        or not required_profiles
        or not isinstance(measurements, list)
        or len(measurements) != len(required_profiles)
    ):
        raise ProvenanceError("required_profiles and measurements must be equal non-empty lists")
    if required_profiles != list(REQUIRED_DIRECT_TDX_PROFILES):
        raise ProvenanceError(
            "direct-TDX provenance must contain the complete ordered 1/2/4/8-vCPU "
            "by 8/16/32/64-GiB launch-profile matrix"
        )
    seen_profiles: set[str] = set()
    seen_names: set[str] = set()
    seen_shapes: set[tuple[int, int]] = set()
    seen_measurement_tuples: set[tuple[str, ...]] = set()
    mrtd_values: set[str] = set()
    runtime_rtmr3_values: set[str] = set()
    normalized_profiles = []
    for index, (profile, entry) in enumerate(zip(required_profiles, measurements, strict=True)):
        profile_path = f"provenance.required_profiles[{index}]"
        entry_path = f"provenance.measurements[{index}]"
        if not isinstance(profile, dict):
            raise ProvenanceError(f"{profile_path} must be an object")
        _require_exact_keys(profile, {"id", "vcpus", "memory_mib"}, profile_path)
        if not isinstance(entry, dict):
            raise ProvenanceError(f"{entry_path} must be an object")
        _require_exact_keys(
            entry,
            {"name", "profile_id", "vcpus", "memory_mib", "values"},
            entry_path,
        )
        profile_id = profile["id"]
        vcpus = profile["vcpus"]
        memory_mib = profile["memory_mib"]
        if (
            not isinstance(profile_id, str)
            or not re.fullmatch(r"[1-9][0-9]*vcpu-[1-9][0-9]*g", profile_id)
            or profile_id in seen_profiles
            or not isinstance(vcpus, int)
            or isinstance(vcpus, bool)
            or vcpus <= 0
            or not isinstance(memory_mib, int)
            or isinstance(memory_mib, bool)
            or memory_mib <= 0
            or memory_mib % 1024
            or (vcpus, memory_mib) in seen_shapes
            or profile_id != f"{vcpus}vcpu-{memory_mib // 1024}g"
        ):
            raise ProvenanceError(f"{profile_path} is invalid or duplicated")
        if (
            entry["profile_id"] != profile_id
            or entry["vcpus"] != vcpus
            or entry["memory_mib"] != memory_mib
        ):
            raise ProvenanceError(f"{entry_path} does not match required profile")
        name = entry["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}", name)
            or name in seen_names
        ):
            raise ProvenanceError(f"{entry_path}.name is invalid or duplicated")
        _validate_measurement_values(
            entry["values"],
            tee_type="tdx",
            provider="bare-metal",
            path=f"{entry_path}.values",
        )
        boot_rtmrs = entry["values"]["boot_rtmrs"]
        runtime_rtmrs = entry["values"]["runtime_rtmrs"]
        if boot_rtmrs["RTMR3"] != "0" * 96:
            raise ProvenanceError(
                f"{entry_path}.values.boot_rtmrs.RTMR3 must be the initial zero value"
            )
        if runtime_rtmrs["RTMR3"] == "0" * 96:
            raise ProvenanceError(
                f"{entry_path}.values.runtime_rtmrs.RTMR3 must bind the runtime chain"
            )
        for register in ("RTMR0", "RTMR1", "RTMR2"):
            if boot_rtmrs[register] != runtime_rtmrs[register]:
                raise ProvenanceError(f"{entry_path}.values {register} cannot change after boot")
        measurement_tuple = (
            entry["values"]["mrtd"],
            *(runtime_rtmrs[register] for register in ("RTMR0", "RTMR1", "RTMR2", "RTMR3")),
        )
        if measurement_tuple in seen_measurement_tuples:
            raise ProvenanceError(
                f"{entry_path}.values duplicates another profile's complete TDX measurement tuple"
            )
        seen_measurement_tuples.add(measurement_tuple)
        mrtd_values.add(entry["values"]["mrtd"])
        runtime_rtmr3_values.add(runtime_rtmrs["RTMR3"])
        seen_profiles.add(profile_id)
        seen_names.add(name)
        seen_shapes.add((vcpus, memory_mib))
        normalized_profiles.append((vcpus, memory_mib))
    if normalized_profiles != sorted(normalized_profiles):
        raise ProvenanceError("direct-TDX profiles must be ordered by vCPU then memory")
    if len(mrtd_values) != 1:
        raise ProvenanceError("direct-TDX profiles for one image must share one MRTD")
    if len(runtime_rtmr3_values) != 1:
        raise ProvenanceError("direct-TDX profiles for one image must share one runtime RTMR3")


def validate_provenance_document(document: dict[str, Any]) -> None:
    """Validate the canonical schema independently of release policy."""
    if document.get("schema_version") == DIRECT_TDX_SCHEMA_VERSION:
        _validate_direct_tdx_provenance(document)
        return
    _require_exact_keys(
        document,
        {
            "schema_version",
            "image",
            "tee_type",
            "provider",
            "role",
            "version",
            "build_flags",
            "gpu_count",
            "expected_gpus",
            "required_vcpu_sizes",
            "measurements",
        },
        "provenance",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ProvenanceError("unsupported provenance schema_version")
    if document["tee_type"] not in {"sev-snp", "tdx"}:
        raise ProvenanceError("provenance tee_type must be sev-snp or tdx")
    if document["provider"] not in {"bare-metal", "gcp"}:
        raise ProvenanceError("provenance provider must be bare-metal or gcp")
    if document["role"] not in {"chute", "storage"}:
        raise ProvenanceError("provenance role must be chute or storage")
    if not isinstance(document["version"], str) or not _VERSION_RE.fullmatch(document["version"]):
        raise ProvenanceError("provenance version is missing or invalid")
    if document["gpu_count"] != 0 or isinstance(document["gpu_count"], bool):
        raise ProvenanceError("managed guest provenance must declare gpu_count=0")
    if document["expected_gpus"] != []:
        raise ProvenanceError("managed guest provenance must declare expected_gpus=[]")

    image = document["image"]
    if not isinstance(image, dict):
        raise ProvenanceError("provenance image must be an object")
    _require_exact_keys(image, {"filename", "sha256"}, "provenance.image")
    if not isinstance(image["filename"], str) or not re.fullmatch(
        r"[A-Za-z0-9._+-]+\.qcow2", image["filename"]
    ):
        raise ProvenanceError("provenance image.filename must name a simple qcow2 file")
    if not isinstance(image["sha256"], str) or not _SHA256_RE.fullmatch(image["sha256"]):
        raise ProvenanceError("provenance image.sha256 must be 64 lowercase hex characters")

    flags = document["build_flags"]
    if not isinstance(flags, dict):
        raise ProvenanceError("provenance build_flags must be an object")
    _require_exact_keys(flags, {"debug_build", "debug_logging"}, "provenance.build_flags")
    if not all(isinstance(flags[key], bool) for key in flags):
        raise ProvenanceError("provenance debug flags must be JSON booleans")
    if flags["debug_logging"] and not flags["debug_build"]:
        raise ProvenanceError("debug_logging=true requires debug_build=true")
    if image["filename"].endswith("-debug.qcow2") != flags["debug_build"]:
        raise ProvenanceError("image filename and debug_build posture disagree")

    required_sizes = document["required_vcpu_sizes"]
    if (
        not isinstance(required_sizes, list)
        or not required_sizes
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in required_sizes
        )
        or required_sizes != sorted(set(required_sizes))
    ):
        raise ProvenanceError(
            "required_vcpu_sizes must be a sorted, unique, non-empty positive integer list"
        )

    measurements = document["measurements"]
    if not isinstance(measurements, list) or not measurements:
        raise ProvenanceError("provenance measurements must be a non-empty list")
    seen_names: set[str] = set()
    seen_sizes: set[int] = set()
    for index, entry in enumerate(measurements):
        path = f"provenance.measurements[{index}]"
        if not isinstance(entry, dict):
            raise ProvenanceError(f"{path} must be an object")
        _require_exact_keys(entry, {"name", "vcpus", "values"}, path)
        name = entry["name"]
        vcpus = entry["vcpus"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}", name)
            or name in seen_names
        ):
            raise ProvenanceError(f"{path}.name is invalid or duplicated")
        if (
            not isinstance(vcpus, int)
            or isinstance(vcpus, bool)
            or vcpus <= 0
            or vcpus in seen_sizes
        ):
            raise ProvenanceError(f"{path}.vcpus is invalid or duplicated")
        _validate_measurement_values(
            entry["values"],
            tee_type=document["tee_type"],
            provider=document["provider"],
            path=f"{path}.values",
        )
        seen_names.add(name)
        seen_sizes.add(vcpus)
    if [entry["vcpus"] for entry in measurements] != required_sizes:
        raise ProvenanceError("measurement order/classes must exactly equal required_vcpu_sizes")


def verify_provenance_signature(
    payload: str,
    signature: str,
    public_key_path: Path,
    *,
    cosign_binary: str = "cosign",
) -> dict[str, Any]:
    """Verify a canonical payload with a detached cosign signature and trusted key."""
    document = load_canonical_provenance(payload)
    if not isinstance(signature, str):
        raise ProvenanceError("provenance signature must be a string")
    try:
        signature_bytes = signature.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProvenanceError("provenance signature must contain only ASCII") from exc
    if not signature_bytes.strip() or len(signature_bytes) > MAX_SIGNATURE_BYTES:
        raise ProvenanceError("provenance signature is empty or too large")

    key_path = Path(public_key_path)
    if not key_path.is_file():
        raise ProvenanceError(f"trusted provenance public key is unavailable: {key_path}")

    payload_path: str | None = None
    signature_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False) as payload_file:
            payload_file.write(payload.encode("ascii"))
            payload_file.flush()
            os.fsync(payload_file.fileno())
            payload_path = payload_file.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as signature_file:
            signature_file.write(signature_bytes)
            if not signature_bytes.endswith(b"\n"):
                signature_file.write(b"\n")
            signature_file.flush()
            os.fsync(signature_file.fileno())
            signature_path = signature_file.name
        try:
            process = subprocess.run(  # nosec B603 - no shell; paths occupy distinct argv fields.
                [
                    cosign_binary,
                    "verify-blob",
                    "--key",
                    str(key_path),
                    "--signature",
                    signature_path,
                    "--insecure-ignore-tlog",
                    payload_path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError as exc:
            raise ProvenanceError("cosign is not installed in the API image") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProvenanceError("cosign provenance verification timed out") from exc
        if process.returncode != 0:
            detail = (process.stderr or process.stdout or "").strip()
            raise ProvenanceError(
                "cosign verify-blob rejected provenance" + (f": {detail[-500:]}" if detail else "")
            )
    finally:
        for path in (payload_path, signature_path):
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
    return document


def measurement_values(config: Any) -> dict[str, Any]:
    """Canonical cryptographic measurement values for one loaded pin."""
    tee_type = (getattr(config, "tee_type", None) or "tdx").lower()
    if tee_type == "tdx":
        return {
            "mrtd": config.mrtd.upper(),
            "boot_rtmrs": {
                key.upper(): value.upper() for key, value in sorted(config.boot_rtmrs.items())
            },
            "runtime_rtmrs": {
                key.upper(): value.upper() for key, value in sorted(config.runtime_rtmrs.items())
            },
        }
    values: dict[str, Any] = {"measurement": config.measurement.upper()}
    provider = normalize_provider(getattr(config, "provider", None))
    if provider == "gcp":
        values["vtpm_pcrs"] = {
            str(key): value.upper() for key, value in sorted((config.vtpm_pcrs or {}).items())
        }
        values["vtpm_security_flags"] = {
            str(key): value for key, value in sorted((config.vtpm_security_flags or {}).items())
        }
    return values


def normalize_provider(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip().lower() or None


def expected_pin_version(
    image_version: str,
    image_role: str,
    tee_type: str,
    vcpus: int,
    memory_mib: int | None = None,
) -> str:
    tee_slug = "snp" if tee_type == "sev-snp" else "tdx"
    role_segment = "storage-" if image_role == "storage" else ""
    memory_segment = f"-{memory_mib // 1024}g" if memory_mib is not None else ""
    return f"{image_version}-{role_segment}{tee_slug}-{vcpus}vcpu{memory_segment}"
