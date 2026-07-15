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
REQUIRED_RELEASE_VCPU_SIZES = (1, 2, 4, 8)
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


def validate_provenance_document(document: dict[str, Any]) -> None:
    """Validate the canonical schema independently of release policy."""
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


def expected_pin_version(image_version: str, image_role: str, tee_type: str, vcpus: int) -> str:
    tee_slug = "snp" if tee_type == "sev-snp" else "tdx"
    role_segment = "storage-" if image_role == "storage" else ""
    return f"{image_version}-{role_segment}{tee_slug}-{vcpus}vcpu"
