"""Fleet image release service: create/activate/rollout/status + the host-facing active manifest.

Desired-state model: for each (channel, tee_type, compute_type) at most one release is ACTIVE.
Activation verifies canonical detached-cosign provenance, exact image/pin identity, and the complete
CPU size matrix or GPU profile-by-management-mode matrix before desired state can change.
"""

import hashlib
import re
import secrets
import shutil
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from loguru import logger
from sqlalchemy import and_, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.database import generate_uuid
from api.host.schemas import HostKeyGeneration
from api.host.schemas import StorageLaunchIntent
from api.host.schemas import TdLaunchReservation
from api.releases.bootstrap import (
    L0BootstrapVerificationError,
    parse_signed_l0_manifest,
    verify_signed_l0_manifest,
)
from api.releases.provenance import (
    DIRECT_TDX_GPU_SCHEMA_VERSION,
    REQUIRED_DIRECT_TDX_PROFILES,
    REQUIRED_RELEASE_VCPU_SIZES,
    ProvenanceError,
    expected_pin_version,
    gpu_measurement_fingerprint,
    load_canonical_provenance,
    measurement_values,
    normalize_provider,
    verify_provenance_signature,
)
from api.releases.schemas import (
    RELEASE_STATUS_ACTIVE,
    RELEASE_STATUS_DRAFT,
    RELEASE_STATUS_SUPERSEDED,
    CreateReleaseRequest,
    GpuL0StorageClosure,
    GpuStorageSibling,
    GpuReleaseImage,
    GuestRelease,
    GuestReleaseTarget,
    L0BootstrapPublication,
    SignedL0BootstrapManifest,
    ReleaseImage,
    ReleaseL0,
    ReleaseManifest,
    RoleLaunchBinaryContract,
)
from api.server.schemas import Host, Server, ServerAttestation
from api.host.locks import (
    GPU_LIFECYCLE_LOCK_INFO_KEY,
    acquire_gpu_lifecycle_lock,
    assert_gpu_external_work_allowed,
)


_PROVENANCE_VERIFICATION_CACHE_MAX = 256
_PROVENANCE_VERIFICATION_CACHE: OrderedDict[tuple[str, ...], dict] = OrderedDict()
_PROVENANCE_SNAPSHOT_INFO_KEY = "release_provenance_verification_snapshot_keys"


def _provenance_verifier_identity() -> str:
    configured = str(settings.provenance_cosign_binary)
    resolved = shutil.which(configured)
    if resolved is None and "/" in configured:
        resolved = str(Path(configured).resolve())
    if resolved is None:
        return f"unresolved:{configured}"
    try:
        stat = Path(resolved).stat()
    except OSError:
        return f"unavailable:{resolved}"
    return ":".join(
        str(value)
        for value in (
            resolved,
            stat.st_dev,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
        )
    )


def _provenance_verification_key(payload: str, signature: str) -> tuple[str, ...]:
    """Bind one cached cosign result to exact payload, signature, key, and verifier path."""

    key_path = Path(settings.trusted_provenance_public_key_path)
    try:
        key_sha256 = hashlib.sha256(key_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ProvenanceError(f"trusted provenance public key is unavailable: {key_path}") from exc
    return (
        hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        hashlib.sha256(signature.encode("utf-8")).hexdigest(),
        str(key_path.resolve()),
        key_sha256,
        _provenance_verifier_identity(),
    )


def _verified_provenance_document(
    db: Optional[AsyncSession],
    *,
    image_role: str,
    payload: str,
    signature: str,
) -> dict:
    """Return an exact cached verification or run cosign only outside lifecycle locks."""

    if db is None:
        return verify_provenance_signature(
            payload,
            signature,
            settings.trusted_provenance_public_key_path,
            cosign_binary=settings.provenance_cosign_binary,
        )
    key = _provenance_verification_key(payload, signature)
    snapshot_keys = db.info.setdefault(_PROVENANCE_SNAPSHOT_INFO_KEY, set())
    cached = _PROVENANCE_VERIFICATION_CACHE.get(key)
    if db.info.get(GPU_LIFECYCLE_LOCK_INFO_KEY):
        if key not in snapshot_keys or cached is None:
            raise ProvenanceError(
                "release provenance snapshot is absent or was evicted before locked refetch"
            )
        _PROVENANCE_VERIFICATION_CACHE.move_to_end(key)
        return cached
    if cached is not None:
        snapshot_keys.add(key)
        _PROVENANCE_VERIFICATION_CACHE.move_to_end(key)
        return cached
    assert_gpu_external_work_allowed(db, f"{image_role} release provenance cosign verification")
    document = verify_provenance_signature(
        payload,
        signature,
        settings.trusted_provenance_public_key_path,
        cosign_binary=settings.provenance_cosign_binary,
    )
    _PROVENANCE_VERIFICATION_CACHE[key] = document
    snapshot_keys.add(key)
    _PROVENANCE_VERIFICATION_CACHE.move_to_end(key)
    while len(_PROVENANCE_VERIFICATION_CACHE) > _PROVENANCE_VERIFICATION_CACHE_MAX:
        _PROVENANCE_VERIFICATION_CACHE.popitem(last=False)
    return document


class ReleaseError(Exception):
    """Raised for release create/activate/rollout errors (mapped to HTTP 4xx by the router)."""


class ReleaseRequestConflict(ReleaseError):
    """The supplied durable request identity does not name this exact canonical request."""


def _configured_gpu_launch_signer_identity() -> tuple[str, int]:
    private_key = getattr(settings, "launch_config_private_key", None)
    epoch = getattr(settings, "gpu_launch_key_epoch", None)
    if (
        not isinstance(private_key, ec.EllipticCurvePrivateKey)
        or not isinstance(private_key.curve, ec.SECP256R1)
        or not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 1
    ):
        raise ReleaseError(
            "GPU activation requires the current configured P-256 launch signer and epoch."
        )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest(), epoch


def _compute_type(release: GuestRelease) -> str:
    """Return the ORM/server-default compute scope for transient or persisted rows."""

    value = release.compute_type or "cpu"
    if value not in {"cpu", "gpu"}:
        raise ReleaseError(f"Release {release.release_id} has an invalid compute_type.")
    if release.compute_type is None:
        release.compute_type = value
    return value


def _runtime_convergence_supported(release: GuestRelease) -> bool:
    """Both streams have reservation-bound runtime convergence telemetry."""

    return _compute_type(release) in {"cpu", "gpu"}


def _loaded_measurements_by_name() -> dict:
    """Every loaded measurement keyed by name (committed YAML + mounted ConfigMap)."""
    return {
        measurement.name: measurement
        for measurement in settings.tee_measurements
        if measurement.name
    }


def _release_measurement_names(release: GuestRelease) -> List[str]:
    names: List[str] = []
    for key in _release_image_roles(release):
        img = (release.images or {}).get(key) or {}
        names.extend(img.get("measurement_names") or [])
    return names


def _release_image_roles(release: GuestRelease) -> tuple[str, ...]:
    return ("gpu",) if _compute_type(release) == "gpu" else ("chute", "storage")


def _validate_release_stream_slots(release: GuestRelease) -> None:
    """Reject malformed persisted JSON that crosses CPU/GPU release streams."""

    images = release.images or {}
    allowed = set(_release_image_roles(release)) | {"l0"}
    unexpected = sorted(set(images) - allowed)
    if unexpected:
        raise ReleaseError(
            f"Release {release.release_id} contains opposite-stream or unknown slots: {unexpected}."
        )
    if _compute_type(release) == "gpu":
        if release.tee_type != "tdx" or not isinstance(images.get("gpu"), dict):
            raise ReleaseError("GPU releases must contain exactly one TDX gpu image slot.")
    elif images.get("gpu") is not None:
        raise ReleaseError("CPU releases cannot contain a gpu image slot.")


def _merged_release_images(release: GuestRelease, current_active: Optional[GuestRelease]) -> dict:
    """Materialize omitted image slots without promoting inherited roles to explicit ones."""
    if current_active is not None and _compute_type(current_active) != _compute_type(release):
        raise ReleaseError("Release images cannot be inherited across compute streams.")
    if current_active is not None and current_active.release_id == release.release_id:
        return {
            role: dict(image) if isinstance(image, dict) else image
            for role, image in (release.images or {}).items()
        }

    merged: dict = {}
    if current_active is not None:
        for role, image in (current_active.images or {}).items():
            inherited = dict(image) if isinstance(image, dict) else image
            if role in {"chute", "storage", "gpu", "l0"} and isinstance(inherited, dict):
                inherited["_inherited"] = True
            merged[role] = inherited
    for role, image in (release.images or {}).items():
        replacement = dict(image) if isinstance(image, dict) else image
        if (
            role in {"chute", "storage", "gpu", "l0"}
            and isinstance(replacement, dict)
            and replacement.get("_inherited")
        ):
            continue
        if isinstance(replacement, dict):
            replacement.pop("_inherited", None)
        merged[role] = replacement
    return merged


def _image_to_dict(img: Optional[ReleaseImage]) -> Optional[dict]:
    if img is None:
        return None
    return {
        "url": img.url,
        "sha256": img.sha256,
        "debug": img.debug,
        "version": img.version,
        "measurement_names": list(img.measurement_names or []),
        "kernel_sha256": img.kernel_sha256,
        "initrd_sha256": img.initrd_sha256,
        "cmdline_sha256": img.cmdline_sha256,
        "provenance_payload": img.provenance_payload,
        "provenance_signature": img.provenance_signature,
    }


def _image_from_manifest(images: dict, key: str) -> Optional[ReleaseImage]:
    raw = (images or {}).get(key)
    if not raw:
        return None
    raw = dict(raw)
    raw.pop("_inherited", None)
    return ReleaseImage(
        url=raw["url"],
        sha256=raw["sha256"],
        debug=raw["debug"],
        version=raw.get("version"),
        measurement_names=raw.get("measurement_names") or [],
        kernel_sha256=raw.get("kernel_sha256"),
        initrd_sha256=raw.get("initrd_sha256"),
        cmdline_sha256=raw.get("cmdline_sha256"),
    )


def _gpu_image_from_manifest(images: dict) -> Optional[GpuReleaseImage]:
    raw = (images or {}).get("gpu")
    if not raw:
        return None
    raw = dict(raw)
    raw.pop("_inherited", None)
    return GpuReleaseImage(
        url=raw["url"],
        sha256=raw["sha256"],
        debug=raw["debug"],
        version=raw["version"],
        measurement_names=raw.get("measurement_names") or [],
        kernel_sha256=raw["kernel_sha256"],
        initrd_sha256=raw["initrd_sha256"],
        cmdline_sha256=raw["cmdline_sha256"],
    )


def _validate_gpu_image_provenance(
    release: GuestRelease,
    image: dict,
    loaded_by_name: dict,
    *,
    db: Optional[AsyncSession] = None,
) -> None:
    """Require one strict direct-TDX GPU provenance and complete profile/mode pin matrix."""

    if _compute_type(release) != "gpu" or release.tee_type != "tdx":
        raise ReleaseError("GPU release provenance is valid only for the TDX GPU stream.")
    names = image.get("measurement_names") or []
    if not names or len(names) != len(set(names)):
        raise ReleaseError("GPU release measurement names must be non-empty and unique.")
    missing = sorted(set(names) - set(loaded_by_name))
    if missing:
        raise ReleaseError(
            f"Refusing to activate GPU release with unpinned measurement names: {missing}."
        )
    configs = [loaded_by_name[name] for name in names]
    wrong_pin_scope = sorted(
        config.name
        for config in configs
        if config.tee_type != "tdx"
        or normalize_provider(config.provider) != "bare-metal"
        or getattr(config, "compute_type", None) != "gpu"
        or getattr(config, "role", None) != "gpu"
        or getattr(config, "provenance_schema_version", None) != DIRECT_TDX_GPU_SCHEMA_VERSION
        or getattr(config, "gpu_fingerprint_version", None) != 1
        or not isinstance(config.gpu_count, int)
        or isinstance(config.gpu_count, bool)
        or config.gpu_count <= 0
        or not list(config.expected_gpus or [])
    )
    if wrong_pin_scope:
        raise ReleaseError(
            "GPU release pins must be bare-metal TDX entries with explicit GPU identity: "
            f"{wrong_pin_scope}."
        )

    payload = image.get("provenance_payload")
    signature = image.get("provenance_signature")
    unsigned_debug_allowed = bool(
        image.get("debug") is True
        and settings.allow_debug_measurements
        and settings.skip_metagraph_check
    )
    if not payload:
        raise ReleaseError("GPU release activation requires canonical schema-version 3 provenance.")
    try:
        if signature:
            provenance = _verified_provenance_document(
                db,
                image_role="gpu",
                payload=payload,
                signature=signature,
            )
        elif unsigned_debug_allowed:
            provenance = load_canonical_provenance(payload)
        else:
            raise ProvenanceError("detached signature is missing")
    except ProvenanceError as exc:
        raise ReleaseError(f"Refusing to activate GPU image: untrusted provenance: {exc}") from exc
    if provenance["schema_version"] != DIRECT_TDX_GPU_SCHEMA_VERSION:
        raise ReleaseError("GPU releases require the separate direct-TDX GPU provenance schema.")
    signer_key_id, signer_epoch = _configured_gpu_launch_signer_identity()
    if (
        provenance["launch_public_key_id"] != signer_key_id
        or provenance["launch_public_key_epoch"] != signer_epoch
    ):
        raise ReleaseError(
            "GPU provenance launch signer does not match the currently configured signer."
        )

    expected = {
        "compute_type": "gpu",
        "role": "gpu",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "version": image.get("version"),
    }
    mismatched = {
        field: {"expected": value, "actual": provenance.get(field)}
        for field, value in expected.items()
        if provenance.get(field) != value
    }
    if mismatched:
        raise ReleaseError(f"GPU provenance does not match release semantics: {mismatched}.")
    if provenance["image"]["sha256"] != image.get("sha256"):
        raise ReleaseError("GPU release sha256 does not match signed provenance.")
    if provenance["build_flags"]["debug_build"] is not image.get("debug"):
        raise ReleaseError("GPU release debug posture does not match signed provenance.")
    raw_l0 = (release.images or {}).get("l0")
    try:
        signed_l0 = parse_signed_l0_manifest(
            (raw_l0 or {}).get("bootstrap"),
            compute_type="gpu",
        )
    except (AttributeError, L0BootstrapVerificationError, ValueError) as exc:
        raise ReleaseError("GPU activation requires its exact signed L0 launch closure.") from exc
    l0_manifest = signed_l0.manifest
    expected_qemu = sorted(
        {item["qemu_binary_sha256"] for item in provenance["launch_environments"]}
    )
    expected_tdvf = sorted({item["firmware_sha256"] for item in provenance["launch_environments"]})
    if (
        not getattr(l0_manifest, "gpu_qemu_sha256s", None)
        or len(l0_manifest.gpu_qemu_sha256s) != 1
        or not set(l0_manifest.gpu_qemu_sha256s).issubset(expected_qemu)
        or not getattr(l0_manifest, "gpu_tdvf_sha256s", None)
        or len(l0_manifest.gpu_tdvf_sha256s) != 1
        or not set(l0_manifest.gpu_tdvf_sha256s).issubset(expected_tdvf)
        or not any(
            item["profile_id"] == l0_manifest.gpu_profile_id
            and item["qemu_binary_sha256"] == l0_manifest.gpu_qemu_sha256s[0]
            and item["firmware_sha256"] == l0_manifest.gpu_tdvf_sha256s[0]
            for item in provenance["launch_environments"]
        )
        or getattr(l0_manifest, "gpu_launch_public_key_id", None)
        != provenance["launch_public_key_id"]
        or getattr(l0_manifest, "gpu_launch_public_key_epoch", None)
        != provenance["launch_public_key_epoch"]
        or getattr(l0_manifest, "gpu_build_inputs_sha256", None)
        != provenance["build_inputs_sha256"]
    ):
        raise ReleaseError("GPU provenance QEMU/TDVF/key/build closure differs from signed L0.")

    signed_names = [entry["name"] for entry in provenance["measurements"]]
    if signed_names != names:
        raise ReleaseError(
            "GPU release measurement names do not exactly match the signed profile/mode matrix."
        )
    signed_artifacts = provenance["artifacts"]
    sidecars = {
        "kernel_sha256": signed_artifacts["kernel_sha256"],
        "initrd_sha256": signed_artifacts["initrd_sha256"],
        "cmdline_sha256": signed_artifacts["cmdline_sha256"],
    }
    for field, signed_value in sidecars.items():
        supplied = image.get(field)
        if supplied is not None and supplied != signed_value:
            raise ReleaseError(f"GPU release {field} does not match signed provenance.")
        image[field] = signed_value

    profile_by_id = {
        profile["id"]: profile for profile in provenance["profile_contract"]["profiles"]
    }
    value_mismatches = []
    for config, entry in zip(configs, provenance["measurements"], strict=True):
        profile = profile_by_id[entry["profile_id"]]
        expected_gpu_fingerprint = gpu_measurement_fingerprint(provenance, entry)
        if (
            config.version != provenance["version"]
            or getattr(config, "gpu_profile_id", None) != entry["profile_id"]
            or getattr(config, "management_mode", None) != entry["management_mode"]
            or getattr(config, "gpu_profile_contract_sha256", None)
            != provenance["profile_contract_sha256"]
            or getattr(config, "gpu_measurement_fingerprint", None) != expected_gpu_fingerprint
            or config.gpu_count != profile["gpu_count"]
            or list(config.expected_gpus or []) != profile["expected_gpu_identifiers"]
            or config.image_sha256 != image.get("sha256")
            or list(config.image_measurement_names or []) != names
            or config.debug is not image.get("debug")
            or measurement_values(config) != entry["values"]
        ):
            value_mismatches.append(config.name)
    if value_mismatches:
        raise ReleaseError(
            f"Loaded GPU pin values do not match canonical provenance for {value_mismatches}."
        )


def _validate_image_provenance(
    release: GuestRelease,
    image_role: str,
    image: dict,
    loaded_by_name: dict,
    *,
    db: Optional[AsyncSession] = None,
) -> None:
    """Require one image to match signed build provenance and a complete CPU pin matrix."""
    names = image.get("measurement_names") or []
    if not names:
        raise ReleaseError(
            f"Release {image_role} image references no measurement names; refusing to activate."
        )
    if len(set(names)) != len(names):
        raise ReleaseError(
            f"Release {image_role} image contains duplicate measurement names; refusing to activate."
        )

    missing = sorted(set(names) - set(loaded_by_name))
    if missing:
        raise ReleaseError(
            "Refusing to activate: these measurement names are not pinned on the validator "
            f"(tee_measurements): {missing}. Pin them (committed yaml / ConfigMap) first, or the "
            "fleet would boot an image whose attestation cannot be verified."
        )
    configs = [loaded_by_name[name] for name in names]

    wrong_gpu = sorted(
        config.name
        for config in configs
        if config.gpu_count != 0 or list(config.expected_gpus or []) != []
    )
    if wrong_gpu:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: managed guest releases are CPU-only, "
            f"but pins {wrong_gpu} do not declare gpu_count=0 and expected_gpus=[]."
        )
    wrong_tee = sorted(config.name for config in configs if config.tee_type != release.tee_type)
    if wrong_tee:
        raise ReleaseError(
            f"Refusing to activate {image_role} image for tee_type={release.tee_type}: "
            f"measurement pins have a different TEE type: {wrong_tee}."
        )
    wrong_provider = sorted(
        config.name for config in configs if normalize_provider(config.provider) != "bare-metal"
    )
    if wrong_provider:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: L0-managed releases require "
            f"provider=bare-metal, but pins have another provider: {wrong_provider}."
        )

    expected_prefix = "storage-" if image_role == "storage" else "cpu-"
    wrong_role = sorted(
        config.name for config in configs if not config.name.startswith(expected_prefix)
    )
    if wrong_role:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: measurement pins have the wrong role: "
            f"{wrong_role}."
        )

    version = image.get("version")
    if not isinstance(version, str) or not version:
        raise ReleaseError(
            f"Refusing to activate {image_role} image without an exact image version."
        )
    if release.tee_type == "sev-snp":
        name_pattern = re.compile(
            rf"^{re.escape(expected_prefix)}baremetal-snp-[a-z0-9-]+-"
            rf"{re.escape(version)}-(\d+)vcpu$"
        )
    else:
        name_pattern = re.compile(
            rf"^{re.escape(expected_prefix)}baremetal-tdx-"
            rf"{re.escape(version)}-(\d+)vcpu(?:-(\d+)g)?$"
        )
    classes_by_name: dict[str, tuple[int, Optional[int]]] = {}
    invalid_names = []
    for name in names:
        match = name_pattern.fullmatch(name)
        if match is None:
            invalid_names.append(name)
        else:
            memory_mib = (
                int(match.group(2)) * 1024
                if release.tee_type == "tdx" and match.lastindex == 2 and match.group(2)
                else None
            )
            classes_by_name[name] = (int(match.group(1)), memory_mib)
    if invalid_names:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: measurement names do not encode the exact "
            f"role/provider/TEE/image version semantics: {sorted(invalid_names)}."
        )

    required_sizes = list(REQUIRED_RELEASE_VCPU_SIZES)
    actual_sizes = [classes_by_name[name][0] for name in names]
    memory_modes = {classes_by_name[name][1] is not None for name in names}
    if len(memory_modes) != 1:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: legacy and RAM-qualified TDX "
            "measurement names cannot be mixed."
        )
    has_memory_profiles = memory_modes == {True}
    if has_memory_profiles:
        expected_profiles = [
            (profile["vcpus"], profile["memory_mib"]) for profile in REQUIRED_DIRECT_TDX_PROFILES
        ]
        actual_profiles = [classes_by_name[name] for name in names]
        if release.tee_type != "tdx" or actual_profiles != expected_profiles:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: direct-TDX releases require the "
                f"complete ordered vCPU/RAM profile matrix {expected_profiles}, got "
                f"{actual_profiles}."
            )
    elif actual_sizes != required_sizes:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: required vCPU matrix is "
            f"{required_sizes}, got {actual_sizes}. Empty, mixed, partial, duplicate, or reordered "
            "matrices are not accepted."
        )
    wrong_pin_versions = sorted(
        config.name
        for config in configs
        if config.version
        != expected_pin_version(
            version,
            image_role,
            release.tee_type,
            classes_by_name[config.name][0],
            classes_by_name[config.name][1],
        )
    )
    if wrong_pin_versions:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: pin versions do not exactly encode image "
            f"version {version}, role, TEE, and vCPU class: {wrong_pin_versions}."
        )

    incomplete_pin_provenance = sorted(
        config.name
        for config in configs
        if not config.image_sha256
        or not config.image_measurement_names
        or config.image_sha256 != image.get("sha256")
        or list(config.image_measurement_names) != names
        or config.debug is not image.get("debug")
    )
    if incomplete_pin_provenance:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: pins {incomplete_pin_provenance} do not "
            "bind the release's exact digest, ordered complete measurement matrix, and debug posture."
        )

    payload = image.get("provenance_payload")
    signature = image.get("provenance_signature")
    unsigned_debug_allowed = bool(
        image.get("debug") is True
        and settings.allow_debug_measurements
        and settings.skip_metagraph_check
    )
    if signature and not payload:
        raise ReleaseError(
            f"Refusing to activate {image_role} image: detached signature has no canonical "
            "provenance payload."
        )
    provenance = None
    if payload:
        try:
            if signature:
                provenance = _verified_provenance_document(
                    db,
                    image_role=image_role,
                    payload=payload,
                    signature=signature,
                )
            elif unsigned_debug_allowed:
                provenance = load_canonical_provenance(payload)
            else:
                raise ProvenanceError("detached signature is missing")
        except ProvenanceError as exc:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: untrusted provenance: {exc}"
            ) from exc
    elif not unsigned_debug_allowed:
        raise ReleaseError(
            f"Refusing to activate unsigned {image_role} provenance. Production managed releases "
            "require canonical provenance verified by cosign; only explicit debug dev posture may "
            "use legacy unsigned debug artifacts."
        )

    if release.tee_type == "tdx" and (provenance is None or provenance["schema_version"] != 2):
        raise ReleaseError(
            f"Refusing to activate {image_role} image: managed bare-metal TDX releases "
            "require canonical schema-version 2 direct-boot provenance."
        )

    if provenance is not None:
        expected_document_fields = {
            "role": image_role,
            "provider": "bare-metal",
            "tee_type": release.tee_type,
            "version": version,
            "gpu_count": 0,
            "expected_gpus": [],
        }
        if provenance["schema_version"] == 1:
            expected_document_fields["required_vcpu_sizes"] = required_sizes
        elif provenance["schema_version"] == 2 and not has_memory_profiles:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: direct-TDX provenance "
                "requires RAM-qualified measurement names."
            )
        if provenance["schema_version"] == 2:
            signed_sidecars = {
                "kernel_sha256": provenance["launch_contract"]["kernel_sha256"],
                "initrd_sha256": provenance["launch_contract"]["initrd_sha256"],
                "cmdline_sha256": provenance["launch_contract"]["cmdline_sha256"],
            }
            for field, signed_digest in signed_sidecars.items():
                supplied_digest = image.get(field)
                if supplied_digest is not None and supplied_digest != signed_digest:
                    raise ReleaseError(
                        f"Refusing to activate {image_role} image: {field} does not "
                        "match signed provenance."
                    )
                image[field] = signed_digest
        mismatched = {
            field: {"expected": expected, "actual": provenance.get(field)}
            for field, expected in expected_document_fields.items()
            if provenance.get(field) != expected
        }
        if mismatched:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: canonical provenance does not match "
                f"release semantics: {mismatched}."
            )
        if provenance["image"]["sha256"] != image.get("sha256"):
            raise ReleaseError(
                f"Refusing to activate {image_role} image: release sha256 does not match "
                "signed provenance."
            )
        if provenance["build_flags"]["debug_build"] is not image.get("debug"):
            raise ReleaseError(
                f"Refusing to activate {image_role} image: release debug posture does not match "
                "signed provenance."
            )
        signed_names = [entry["name"] for entry in provenance["measurements"]]
        if signed_names != names:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: release measurement names do not "
                "exactly match signed provenance."
            )
        value_mismatches = [
            config.name
            for config, entry in zip(configs, provenance["measurements"], strict=True)
            if entry["vcpus"] != classes_by_name[config.name][0]
            or (
                provenance["schema_version"] == 2
                and entry["memory_mib"] != classes_by_name[config.name][1]
            )
            or (
                provenance["schema_version"] == 2
                and (
                    config.profile_id != entry["profile_id"]
                    or config.vcpus != entry["vcpus"]
                    or config.memory_mib != entry["memory_mib"]
                )
            )
            or entry["values"] != measurement_values(config)
        ]
        if value_mismatches:
            raise ReleaseError(
                f"Refusing to activate {image_role} image: loaded pin values do not match "
                f"canonical provenance for {value_mismatches}."
            )


def _l0_to_dict(l0: Optional[ReleaseL0]) -> Optional[dict]:
    if l0 is None:
        return None
    return {
        "version": l0.version,
        "squashfs_sha256": l0.squashfs_sha256,
        "netboot_base_url": l0.netboot_base_url,
        "bootstrap": (
            l0.bootstrap.model_dump(mode="json", exclude_none=True)
            if l0.bootstrap is not None
            else None
        ),
    }


def _l0_from_manifest(images: dict) -> Optional[ReleaseL0]:
    raw = (images or {}).get("l0")
    if not raw:
        return None
    return ReleaseL0(
        version=raw["version"],
        squashfs_sha256=raw.get("squashfs_sha256"),
        netboot_base_url=raw.get("netboot_base_url"),
        bootstrap=raw.get("bootstrap"),
    )


def _verify_l0_release_contract(
    release: GuestRelease, *, allow_expired: bool = False
) -> tuple[SignedL0BootstrapManifest, str]:
    """Purely verify one release wrapper against its publisher-signed L0 contract."""
    raw = (release.images or {}).get("l0")
    if raw is None:
        raise ReleaseError(
            "A seedless Model-B release must carry a publisher-signed L0 bootstrap manifest."
        )
    try:
        signed = parse_signed_l0_manifest(
            raw.get("bootstrap"),
            compute_type=_compute_type(release),
        )
        digest = verify_signed_l0_manifest(
            signed,
            settings.trusted_l0_publisher_keys_path,
            allow_expired=allow_expired,
        )
    except (L0BootstrapVerificationError, ValueError, TypeError) as exc:
        raise ReleaseError(f"Untrusted L0 bootstrap manifest: {exc}") from exc

    manifest = signed.manifest
    release_compute_type = _compute_type(release)
    manifest_compute_type = getattr(manifest, "compute_type", "cpu")
    if (
        manifest.tee_type != release.tee_type
        or manifest.channel != release.channel
        or manifest_compute_type != release_compute_type
    ):
        raise ReleaseError(
            "L0 bootstrap manifest TEE/channel/compute type does not match the guest release."
        )
    if (
        manifest.release_id is not None
        and manifest.release_id != release.release_id
        and not raw.get("_inherited")
    ):
        raise ReleaseError("L0 bootstrap manifest release correlation does not match this release.")
    if raw.get("version") != manifest.l0_version:
        raise ReleaseError("L0 version does not match the signed bootstrap manifest.")
    if raw.get("squashfs_sha256") != manifest.squashfs.sha256:
        raise ReleaseError(
            "Required L0 squashfs digest does not match the signed bootstrap manifest."
        )
    return signed, digest


def _stamp_release_l0_audit(
    release: GuestRelease,
    signed: SignedL0BootstrapManifest,
    digest: str,
) -> None:
    manifest = signed.manifest
    release.l0_manifest = manifest.model_dump(mode="json", exclude_none=True)
    release.l0_manifest_digest = digest
    release.l0_manifest_generation = manifest.generation
    release.l0_manifest_key_id = manifest.key_id
    release.l0_manifest_key_epoch = manifest.key_epoch


async def _admit_l0_bootstrap(
    db: AsyncSession,
    release: GuestRelease,
) -> L0BootstrapPublication:
    """Transactionally admit one monotonic publisher generation without GET-side mutation."""

    await acquire_gpu_lifecycle_lock(db)
    signed, digest = _verify_l0_release_contract(release)
    manifest = signed.manifest
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {
            "lock_key": (
                f"l0-bootstrap:{release.channel}:{release.tee_type}:{_compute_type(release)}"
            )
        },
    )
    existing = await db.get(
        L0BootstrapPublication,
        (
            release.tee_type,
            release.channel,
            _compute_type(release),
            manifest.generation,
        ),
    )
    latest = (
        await db.execute(
            select(L0BootstrapPublication)
            .where(
                L0BootstrapPublication.tee_type == release.tee_type,
                L0BootstrapPublication.channel == release.channel,
                L0BootstrapPublication.compute_type == _compute_type(release),
            )
            .order_by(L0BootstrapPublication.generation.desc())
            .limit(1)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.manifest_digest != digest:
            raise ReleaseError(
                "L0 bootstrap generation equivocation: the generation already names other bytes."
            )
        if latest is not None and manifest.generation < latest.generation:
            raise ReleaseError(
                "L0 bootstrap generation is stale; an older admitted generation cannot be reactivated."
            )
        if latest is not None and manifest.key_epoch < latest.key_epoch:
            raise ReleaseError("L0 publisher key epoch cannot move backwards.")
        publication = existing
    else:
        if latest is not None and manifest.generation <= latest.generation:
            raise ReleaseError(
                "L0 bootstrap generation is stale; new admissions must increase monotonically."
            )
        if latest is not None and manifest.key_epoch < latest.key_epoch:
            raise ReleaseError("L0 publisher key epoch cannot move backwards.")
        publication = L0BootstrapPublication(
            tee_type=release.tee_type,
            channel=release.channel,
            compute_type=_compute_type(release),
            generation=manifest.generation,
            manifest_digest=digest,
            key_id=manifest.key_id,
            key_epoch=manifest.key_epoch,
            l0_version=manifest.l0_version,
            squashfs_sha256=manifest.squashfs.sha256,
            signed_manifest=signed.model_dump(mode="json", exclude_none=True),
            source_release_id=release.release_id,
            admission_status="staged",
        )
        db.add(publication)
        await db.flush()
    _stamp_release_l0_audit(release, signed, digest)
    return publication


async def _validate_l0_bootstrap(db: AsyncSession, release: GuestRelease) -> L0BootstrapPublication:
    """Compatibility name for activation/tests; admission is explicit and idempotent."""

    return await _admit_l0_bootstrap(db, release)


async def _mark_l0_publication_active(
    db: AsyncSession,
    release: GuestRelease,
    publication: L0BootstrapPublication,
) -> None:
    """Make the release's admitted L0 generation the active publication audit row."""

    await db.execute(
        update(L0BootstrapPublication)
        .where(
            L0BootstrapPublication.tee_type == release.tee_type,
            L0BootstrapPublication.channel == release.channel,
            L0BootstrapPublication.compute_type == _compute_type(release),
            L0BootstrapPublication.admission_status == "active",
            L0BootstrapPublication.generation != publication.generation,
        )
        .values(admission_status="staged")
    )
    publication.admission_status = "active"
    if publication.activated_at is None:
        publication.activated_at = datetime.now(timezone.utc)


async def _release_for_request_sha256(
    db: AsyncSession,
    request_sha256: str,
) -> Optional[GuestRelease]:
    return (
        await db.execute(
            select(GuestRelease).where(
                GuestRelease.release_request_sha256 == request_sha256,
            )
        )
    ).scalar_one_or_none()


async def _complete_release_request(
    db: AsyncSession,
    req: CreateReleaseRequest,
    release: GuestRelease,
) -> GuestRelease:
    """Resume only the crash-safe unfinished portion of one exact create request."""

    if req.activate and release.status == RELEASE_STATUS_DRAFT:
        return await activate_release(db, release.release_id)
    return release


async def create_release(
    db: AsyncSession,
    req: CreateReleaseRequest,
    request_sha256: str,
) -> GuestRelease:
    """Create or replay one durable canonical release request.

    The client identity is the lowercase SHA-256 of ``req.canonical_document()``. The unique
    database index is the concurrency arbiter: after a lost insert race we roll back, fetch the
    committed winner, and return that exact row. ``activate=true`` is deliberately resumed only
    while that row is still a draft, closing the post-create/pre-activate crash window without ever
    reactivating an older release that was subsequently superseded.
    """

    canonical_request_sha256 = req.canonical_sha256()
    if not re.fullmatch(r"[0-9a-f]{64}", request_sha256 or ""):
        raise ReleaseRequestConflict(
            "Release request identity must be exactly 64 lowercase hexadecimal characters."
        )
    if not secrets.compare_digest(request_sha256, canonical_request_sha256):
        raise ReleaseRequestConflict(
            "Release request identity does not match the canonical release request payload."
        )

    existing = await _release_for_request_sha256(db, request_sha256)
    if existing is not None:
        return await _complete_release_request(db, req, existing)

    images: Dict[str, dict] = {}
    if req.chute is not None:
        images["chute"] = _image_to_dict(req.chute)
    if req.storage is not None:
        images["storage"] = _image_to_dict(req.storage)
    if req.gpu is not None:
        images["gpu"] = {
            **_image_to_dict(req.gpu),
            "cmdline_sha256": req.gpu.cmdline_sha256.model_dump(),
        }
    if req.l0 is not None:
        images["l0"] = _l0_to_dict(req.l0)
    release = GuestRelease(
        channel=req.channel,
        tee_type=req.tee_type,
        compute_type=req.compute_type,
        status=RELEASE_STATUS_DRAFT,
        images=images,
        notes=req.notes,
        release_request_sha256=request_sha256,
    )
    db.add(release)
    created = False
    try:
        await db.flush()
        if req.l0 is not None:
            await _admit_l0_bootstrap(db, release)
        await db.commit()
        created = True
    except IntegrityError:
        await db.rollback()
        existing = await _release_for_request_sha256(db, request_sha256)
        if existing is None:
            raise
        release = existing
    except Exception:
        await db.rollback()
        raise
    if created:
        await db.refresh(release)
        logger.success(
            f"Created draft guest release {release.release_id} (channel={release.channel} "
            f"tee_type={release.tee_type} compute_type={release.compute_type} "
            f"request_sha256={request_sha256})"
        )
    return await _complete_release_request(db, req, release)


async def _lock_release_streams(
    db: AsyncSession,
    *,
    channel: str,
    tee_type: str,
    compute_type: str,
) -> Dict[str, GuestRelease]:
    """Lock composed stream identities and active rows in deterministic CPU→GPU order."""

    await acquire_gpu_lifecycle_lock(db)
    compute_types = (
        ("cpu", "gpu") if tee_type == "tdx" and compute_type in {"cpu", "gpu"} else (compute_type,)
    )
    for locked_compute_type in compute_types:
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": (f"guest-release:{channel}:{tee_type}:{locked_compute_type}")},
        )
    active_rows = (
        (
            await db.execute(
                select(GuestRelease)
                .where(
                    GuestRelease.channel == channel,
                    GuestRelease.tee_type == tee_type,
                    GuestRelease.compute_type.in_(compute_types),
                    GuestRelease.status == RELEASE_STATUS_ACTIVE,
                )
                .order_by(GuestRelease.compute_type.asc())
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    return {row.compute_type: row for row in active_rows}


def _release_validation_view(
    release: GuestRelease,
    *,
    images: Optional[dict] = None,
) -> SimpleNamespace:
    """Detached release input used only for pre-lock provenance verification."""

    return SimpleNamespace(
        release_id=release.release_id,
        channel=release.channel,
        tee_type=release.tee_type,
        compute_type=release.compute_type or "cpu",
        images=(images if images is not None else release.images),
    )


def _preverify_release_images(
    db: AsyncSession,
    release: GuestRelease,
    *,
    current_active: Optional[GuestRelease] = None,
) -> None:
    """Verify detached signatures only; locked refetch reruns every semantic check."""

    view = _release_validation_view(release)
    view.images = _merged_release_images(view, current_active)
    for image_role in _release_image_roles(view):
        image = (view.images or {}).get(image_role)
        if not isinstance(image, dict):
            continue
        payload = image.get("provenance_payload")
        signature = image.get("provenance_signature")
        if isinstance(payload, str) and payload and isinstance(signature, str) and signature:
            try:
                _verified_provenance_document(
                    db,
                    image_role=image_role,
                    payload=payload,
                    signature=signature,
                )
            except ProvenanceError as exc:
                raise ReleaseError(
                    f"Refusing to activate {image_role} image: untrusted provenance: {exc}"
                ) from exc


async def activate_release(db: AsyncSession, release_id: str) -> GuestRelease:
    """Make a release the ACTIVE desired state for its compute-scoped stream.

    GATE: every measurement name the release references MUST already be pinned in
    settings.tee_measurements. Otherwise TDs launched from the new image would fail attestation
    fleet-wide -- so refuse activation until the measurements are pinned (committed yaml / ConfigMap).
    Supersedes the prior active release for the same (channel, tee_type, compute_type).
    """
    preflight_release = await db.get(GuestRelease, release_id)
    if preflight_release is None:
        raise ReleaseError(f"Release {release_id} not found")
    preflight_compute_type = preflight_release.compute_type or "cpu"
    preflight_current = await get_active_release(
        db,
        preflight_release.tee_type,
        preflight_release.channel,
        preflight_compute_type,
    )
    if not isinstance(preflight_current, GuestRelease):
        preflight_current = None
    _preverify_release_images(
        db,
        preflight_release,
        current_active=preflight_current,
    )
    if preflight_compute_type == "gpu":
        preflight_cpu = await get_active_release(
            db,
            "tdx",
            preflight_release.channel,
            "cpu",
        )
        if isinstance(preflight_cpu, GuestRelease):
            _validate_active_release(preflight_cpu, db)
    await db.commit()

    await acquire_gpu_lifecycle_lock(db)
    release = await db.get(
        GuestRelease,
        release_id,
        with_for_update=True,
        populate_existing=True,
    )
    if release is None:
        raise ReleaseError(f"Release {release_id} not found")
    if release.compute_type is None:
        release.compute_type = "cpu"
    active_streams = await _lock_release_streams(
        db,
        channel=release.channel,
        tee_type=release.tee_type,
        compute_type=release.compute_type,
    )
    current_active = active_streams.get(release.compute_type)
    if current_active is None:
        current_active = await get_active_release(
            db,
            release.tee_type,
            release.channel,
            release.compute_type,
            lock=True,
        )
    if not isinstance(current_active, GuestRelease):
        current_active = None
    original_images = release.images
    release.images = _merged_release_images(release, current_active)
    try:
        _validate_release_stream_slots(release)
        if _runtime_convergence_supported(release) and release.tee_type == "tdx":
            required_slot = "gpu" if _compute_type(release) == "gpu" else "chute"
            if not (release.images or {}).get(required_slot):
                raise ReleaseError(
                    f"A managed TDX {_compute_type(release)} desired state must include "
                    f"its direct-boot {required_slot} image slot; the release is unschedulable."
                )
        required = _release_measurement_names(release)
        if not required:
            raise ReleaseError(
                "Release references no measurement names; refusing to activate (a release must "
                "declare the pinned measurement its image attests as, or launched TDs cannot be "
                "verified)."
            )
        loaded_by_name = _loaded_measurements_by_name()
        for image_role in _release_image_roles(release):
            image = (release.images or {}).get(image_role)
            if image:
                if image_role == "gpu":
                    _validate_gpu_image_provenance(release, image, loaded_by_name, db=db)
                else:
                    _validate_image_provenance(release, image_role, image, loaded_by_name, db=db)
        await _validate_gpu_storage_stream(db, release)
        publication = await _validate_l0_bootstrap(db, release)
        await _mark_l0_publication_active(db, release, publication)
    except Exception:
        release.images = original_images
        raise

    # Re-validate even an already-active row so legacy/malformed manifests cannot bypass newly
    # required provenance through the idempotent activation path.
    if release.status == RELEASE_STATUS_ACTIVE:
        if release.targets_captured_at is None:
            await _capture_release_targets(db, release)
        if _compute_type(release) == "gpu":
            from api.gpu_lifecycle_service import ensure_release_rollovers_for_release

            await ensure_release_rollovers_for_release(db, release)
        if _compute_type(release) == "cpu" and release.tee_type == "tdx":
            await _refresh_active_gpu_storage_intents(
                db,
                active_cpu_release=release,
                gpu_release=active_streams.get("gpu"),
            )
        await db.commit()
        await db.refresh(release)
        return release

    # Supersede the current active release for this (channel, tee_type).
    await db.execute(
        update(GuestRelease)
        .where(
            GuestRelease.channel == release.channel,
            GuestRelease.tee_type == release.tee_type,
            GuestRelease.compute_type == release.compute_type,
            GuestRelease.status == RELEASE_STATUS_ACTIVE,
            GuestRelease.release_id != release.release_id,
        )
        .values(status=RELEASE_STATUS_SUPERSEDED)
    )
    release.status = RELEASE_STATUS_ACTIVE
    release.activated_at = datetime.now(timezone.utc)
    await _capture_release_targets(db, release)
    if _compute_type(release) == "gpu":
        from api.gpu_lifecycle_service import ensure_release_rollovers_for_release

        await ensure_release_rollovers_for_release(db, release)
    if _compute_type(release) == "cpu" and release.tee_type == "tdx":
        await _refresh_active_gpu_storage_intents(
            db,
            active_cpu_release=release,
            gpu_release=active_streams.get("gpu"),
        )
    await db.commit()
    await db.refresh(release)
    logger.success(
        f"Activated guest release {release.release_id} (channel={release.channel} "
        f"tee_type={release.tee_type} compute_type={release.compute_type}); "
        f"measurements verified pinned: {sorted(set(required))}"
    )
    return release


async def get_active_release(
    db: AsyncSession,
    tee_type: str,
    channel: str = "stable",
    compute_type: str = "cpu",
    *,
    lock: bool = False,
) -> Optional[GuestRelease]:
    query = select(GuestRelease).where(
        GuestRelease.tee_type == tee_type,
        GuestRelease.channel == channel,
        GuestRelease.compute_type == compute_type,
        GuestRelease.status == RELEASE_STATUS_ACTIVE,
    )
    if lock:
        await acquire_gpu_lifecycle_lock(db)
        query = query.with_for_update()
    return (await db.execute(query)).scalar_one_or_none()


async def active_l0_bootstrap(
    db: AsyncSession,
    tee_type: str,
    channel: str,
    compute_type: str = "cpu",
) -> Optional[SignedL0BootstrapManifest]:
    """Return the newest active bootstrap publication without mutating state."""

    normalized_tee = tee_type.strip().lower()
    publication = (
        await db.execute(
            select(L0BootstrapPublication)
            .where(
                L0BootstrapPublication.tee_type == normalized_tee,
                L0BootstrapPublication.channel == channel,
                L0BootstrapPublication.compute_type == compute_type,
                L0BootstrapPublication.admission_status == "active",
            )
            .order_by(L0BootstrapPublication.generation.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if publication is None:
        return None

    try:
        signed = parse_signed_l0_manifest(
            publication.signed_manifest,
            compute_type=compute_type,
        )
        digest = verify_signed_l0_manifest(
            signed,
            settings.trusted_l0_publisher_keys_path,
        )
    except (L0BootstrapVerificationError, ValueError, TypeError) as exc:
        raise ReleaseError(f"Admitted L0 bootstrap is no longer trusted: {exc}") from exc
    manifest = signed.manifest
    manifest_compute_type = getattr(manifest, "compute_type", "cpu")
    if (
        manifest.tee_type != normalized_tee
        or manifest.channel != channel
        or manifest_compute_type != compute_type
        or publication.tee_type != normalized_tee
        or publication.channel != channel
        or (publication.compute_type or "cpu") != compute_type
        or publication.generation != manifest.generation
        or publication.manifest_digest != digest
        or publication.key_id != manifest.key_id
        or publication.key_epoch != manifest.key_epoch
        or publication.l0_version != manifest.l0_version
        or publication.squashfs_sha256 != manifest.squashfs.sha256
    ):
        raise ReleaseError("Admitted L0 bootstrap audit fields do not match its signed manifest.")
    return signed


def release_manifest(release: GuestRelease) -> ReleaseManifest:
    """The host-facing desired state; TD launch authorization is separate and one-use."""
    _validate_release_stream_slots(release)
    return ReleaseManifest(
        release_id=release.release_id,
        channel=release.channel,
        tee_type=release.tee_type,
        compute_type=_compute_type(release),
        chute=_image_from_manifest(release.images, "chute"),
        storage=_image_from_manifest(release.images, "storage"),
        gpu=_gpu_image_from_manifest(release.images),
        l0=_l0_from_manifest(release.images),
    )


def _target_roles_for_host(release: GuestRelease, host: Host) -> List[str]:
    """Release roles this enrolled logical host can actually run."""
    images = release.images or {}
    roles: List[str] = []
    if _compute_type(release) == "gpu":
        gpu = images.get("gpu") or {}
        if gpu and not gpu.get("_inherited") and int(host.reported_capacity or 0) > 0:
            roles.append("gpu")
        return roles
    chute = images.get("chute") or {}
    storage = images.get("storage") or {}
    if chute and not chute.get("_inherited") and int(host.capacity or 0) > 0:
        roles.append("chute")
    if (
        storage
        and not storage.get("_inherited")
        and bool(getattr(host, "storage_requested", False))
    ):
        roles.append("storage")
    return roles


def _apply_storage_auto_opt_in(release: GuestRelease, host: Host) -> None:
    """Reserve storage capacity before the immutable role target snapshot is derived.

    A release carrying storage is itself the operator's opt-in intent.  Hosts that have not staged a
    storage image yet still need a storage target/token, and their advertised chute capacity must no
    longer include the TD that will become the always-on storage role.
    """

    if _compute_type(release) != "cpu":
        return
    storage = (release.images or {}).get("storage") or {}
    if not storage or storage.get("_inherited"):
        return
    if bool(getattr(host, "storage_requested", False)):
        return
    current = int(host.capacity or 0)
    host.storage_requested = True
    host.capacity = max(0, current - 1)


def _storage_profile_for_host(release: GuestRelease, host: Host) -> str:
    image = (release.images or {}).get("storage") or {}
    names = list(image.get("measurement_names") or [])
    vcpus = getattr(host, "storage_td_vcpus", None)
    memory = getattr(host, "storage_td_mem", None)
    if not isinstance(vcpus, int) or isinstance(vcpus, bool) or vcpus < 1:
        raise ReleaseError(
            f"Storage target {host.host_id} has no validator-recorded storage vCPU shape."
        )
    if not isinstance(memory, str) or not re.fullmatch(r"[1-9][0-9]*(?:G|M)", memory):
        raise ReleaseError(
            f"Storage target {host.host_id} has no validator-recorded storage memory shape."
        )
    if release.tee_type == "tdx":
        amount = int(memory[:-1])
        memory_mib = amount * 1024 if memory.endswith("G") else amount
        if memory_mib % 1024:
            raise ReleaseError(
                f"Storage target {host.host_id} memory does not map to a signed TDX profile."
            )
        suffix = f"-{vcpus}vcpu-{memory_mib // 1024}g"
    else:
        suffix = f"-{vcpus}vcpu"
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ReleaseError(
            f"Storage target {host.host_id} has no unique server-selected profile for "
            f"{vcpus} vCPU/{memory}."
        )
    return matches[0]


async def _storage_source_release(
    db: AsyncSession,
    active_cpu_release: GuestRelease,
) -> GuestRelease:
    """Resolve the immutable release row that explicitly introduced active storage bytes."""

    image = (active_cpu_release.images or {}).get("storage") or {}
    if not image.get("_inherited"):
        return active_cpu_release
    candidates = (
        (
            await db.execute(
                select(GuestRelease)
                .where(
                    GuestRelease.tee_type == active_cpu_release.tee_type,
                    GuestRelease.channel == active_cpu_release.channel,
                    GuestRelease.compute_type == "cpu",
                    GuestRelease.activated_at.is_not(None),
                )
                .order_by(
                    GuestRelease.activated_at.desc().nullslast(),
                    GuestRelease.created_at.desc(),
                    GuestRelease.release_id.desc(),
                )
            )
        )
        .scalars()
        .all()
    )
    exact = []
    for candidate in candidates:
        candidate_image = (candidate.images or {}).get("storage")
        if (
            isinstance(candidate_image, dict)
            and (
                active_cpu_release.activated_at is None
                or candidate.activated_at <= active_cpu_release.activated_at
            )
            and not candidate_image.get("_inherited")
            and candidate_image.get("sha256") == image.get("sha256")
            and candidate_image.get("version") == image.get("version")
            and candidate_image.get("kernel_sha256") == image.get("kernel_sha256")
            and candidate_image.get("initrd_sha256") == image.get("initrd_sha256")
            and candidate_image.get("cmdline_sha256") == image.get("cmdline_sha256")
            and candidate_image.get("measurement_names") == image.get("measurement_names")
        ):
            exact.append(candidate)
    if not exact:
        raise ReleaseError("Active CPU storage inheritance has no exact explicit source release.")
    return exact[0]


async def _validate_gpu_storage_stream(
    db: AsyncSession,
    gpu_release: GuestRelease,
) -> None:
    if _compute_type(gpu_release) != "gpu":
        return
    active_cpu = await get_active_release(db, "tdx", gpu_release.channel, "cpu")
    if active_cpu is None:
        raise ReleaseError(
            "GPU activation requires an independently active CPU/storage TDX release "
            f"for channel {gpu_release.channel!r}."
        )
    _validate_active_release(active_cpu, db)
    storage = (active_cpu.images or {}).get("storage")
    if not isinstance(storage, dict):
        raise ReleaseError("Active CPU TDX release has no storage role to compose with GPU L0.")
    expected = await _gpu_l0_storage_closure(db, active_cpu)
    signed, _digest = _verify_l0_release_contract(gpu_release)
    if signed.manifest.storage_closure != expected:
        raise ReleaseError(
            "GPU L0 storage closure does not match the active independent CPU/storage release."
        )


def _storage_launch_contract(image: dict) -> RoleLaunchBinaryContract:
    """Extract the signed direct-TDX QEMU/TDVF identity without changing CPU rows."""

    payload = image.get("provenance_payload")
    if not isinstance(payload, str) or not payload:
        raise ReleaseError("GPU storage composition requires signed CPU storage provenance.")
    try:
        provenance = load_canonical_provenance(payload)
    except ProvenanceError as exc:
        raise ReleaseError(f"CPU storage provenance is invalid: {exc}") from exc
    launch = provenance.get("launch_contract")
    if (
        provenance.get("schema_version") != 2
        or provenance.get("role") != "storage"
        or provenance.get("tee_type") != "tdx"
        or provenance.get("provider") != "bare-metal"
        or not isinstance(launch, dict)
        or launch.get("image_sha256") != image.get("sha256")
        or launch.get("kernel_sha256") != image.get("kernel_sha256")
        or launch.get("initrd_sha256") != image.get("initrd_sha256")
        or launch.get("cmdline_sha256") != image.get("cmdline_sha256")
    ):
        raise ReleaseError(
            "GPU storage composition requires an exact schema-v2 direct-TDX storage contract."
        )
    return RoleLaunchBinaryContract(
        role="storage",
        qemu_binary="qemu-system-x86_64",
        qemu_package="qemu-system-x86",
        qemu_package_version=launch["qemu_package_version"],
        qemu_binary_sha256=launch["qemu_binary_sha256"],
        machine_type=launch["machine_type"],
        firmware_filename="OVMF.inteltdx.fd",
        firmware_sha256=launch["firmware_sha256"],
    )


async def _gpu_l0_storage_closure(
    db: AsyncSession,
    active_cpu_release: GuestRelease,
) -> GpuL0StorageClosure:
    """Resolve the one closure a GPU L0 is publisher-authorized to launch."""

    if (
        _compute_type(active_cpu_release) != "cpu"
        or active_cpu_release.tee_type != "tdx"
        or active_cpu_release.status != RELEASE_STATUS_ACTIVE
    ):
        raise ReleaseError("GPU L0 storage closure requires an active CPU TDX release.")
    storage = (active_cpu_release.images or {}).get("storage")
    if not isinstance(storage, dict):
        raise ReleaseError("Active CPU TDX release has no storage image closure.")
    source = await _storage_source_release(db, active_cpu_release)
    source_storage = (source.images or {}).get("storage") if source is not None else None
    if not isinstance(source_storage, dict) or source_storage.get("_inherited"):
        raise ReleaseError("CPU storage source release has no explicit immutable image.")
    required = (
        "sha256",
        "version",
        "measurement_names",
        "kernel_sha256",
        "initrd_sha256",
        "cmdline_sha256",
    )
    if any(not source_storage.get(field) for field in required):
        raise ReleaseError("CPU storage source release has an incomplete artifact closure.")
    return GpuL0StorageClosure(
        source_release_id=source.release_id,
        image_version=source_storage["version"],
        image_sha256=source_storage["sha256"],
        kernel_sha256=source_storage["kernel_sha256"],
        initrd_sha256=source_storage["initrd_sha256"],
        cmdline_sha256=source_storage["cmdline_sha256"],
        measurement_names=list(source_storage["measurement_names"]),
        launch_contract=_storage_launch_contract(source_storage),
    )


async def _gpu_storage_sibling_for_host(
    db: AsyncSession,
    gpu_release: GuestRelease,
    host: Host,
) -> GpuStorageSibling:
    """Compose one GPU host with the independently active CPU/storage stream."""

    await acquire_gpu_lifecycle_lock(db)
    if (
        _compute_type(gpu_release) != "gpu"
        or gpu_release.tee_type != "tdx"
        or host.compute_type != "gpu"
        or host.tee_type != "tdx"
        or not host.storage_requested
    ):
        raise ReleaseError(
            "GPU storage sibling composition requires a storage-enabled TDX GPU host."
        )
    active_cpu = await get_active_release(
        db,
        "tdx",
        gpu_release.channel,
        "cpu",
    )
    if active_cpu is None:
        raise ReleaseError(
            "GPU desired state requires an independently active CPU/storage TDX release "
            f"for channel {gpu_release.channel!r}."
        )
    _validate_active_release(active_cpu, db)
    storage = (active_cpu.images or {}).get("storage")
    if not isinstance(storage, dict):
        raise ReleaseError("Active CPU TDX desired state has no storage image.")
    closure = await _gpu_l0_storage_closure(db, active_cpu)
    signed_l0, _l0_digest = _verify_l0_release_contract(
        gpu_release,
        allow_expired=gpu_release.status == RELEASE_STATUS_ACTIVE,
    )
    if signed_l0.manifest.storage_closure != closure:
        raise ReleaseError(
            "Active GPU L0 is incompatible with the current CPU/storage launch closure."
        )
    source = await db.get(GuestRelease, closure.source_release_id)
    source_storage = (source.images or {}).get("storage")
    if not isinstance(source_storage, dict):
        raise ReleaseError("Resolved CPU storage source release has no storage image.")
    profile_id = _storage_profile_for_host(active_cpu, host)
    image = _image_from_manifest({"storage": source_storage}, "storage")
    if image is None:
        raise ReleaseError("Resolved CPU storage source image is invalid.")
    return GpuStorageSibling(
        source_release_id=source.release_id,
        active_cpu_release_id=active_cpu.release_id,
        profile_id=profile_id,
        image=image,
        launch_contract=closure.launch_contract,
    )


async def _supersede_storage_intents(
    db: AsyncSession,
    *criteria,
) -> List[StorageLaunchIntent]:
    """Supersede intents and invalidate every unconsumed reservation in one transaction."""

    await acquire_gpu_lifecycle_lock(db)
    intents = (
        (
            await db.execute(
                select(StorageLaunchIntent)
                .where(
                    StorageLaunchIntent.state == "active",
                    *criteria,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if not intents:
        return []
    intent_ids = [intent.intent_id for intent in intents]
    now = datetime.now(timezone.utc)
    await db.execute(
        update(TdLaunchReservation)
        .where(
            TdLaunchReservation.storage_intent_id.in_(intent_ids),
            TdLaunchReservation.consumed_at.is_(None),
            TdLaunchReservation.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )
    for intent in intents:
        intent.state = "superseded"
    await db.flush()
    return intents


async def _ensure_gpu_storage_launch_intent_for_host(
    db: AsyncSession,
    gpu_release: GuestRelease,
    host: Host,
) -> StorageLaunchIntent:
    """Create or recover one GPU-host storage intent without touching CPU targets."""

    await acquire_gpu_lifecycle_lock(db)
    if (
        host.miner_hotkey is None
        or host.compute_type != "gpu"
        or host.tee_type != "tdx"
        or host.release_channel != gpu_release.channel
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or not host.storage_requested
    ):
        raise ReleaseError(
            f"GPU storage-sibling host {host.host_id} is not launch-intent eligible."
        )
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"gpu-storage-intent:{host.host_id}"},
    )
    sibling = await _gpu_storage_sibling_for_host(db, gpu_release, host)
    process_incarnation = "stor" + hashlib.sha256(host.host_id.encode()).hexdigest()[:8]
    expected = {
        "target_id": None,
        "release_id": sibling.source_release_id,
        "tee_type": "tdx",
        "channel": gpu_release.channel,
        "host_id": host.host_id,
        "owner_hotkey": host.miner_hotkey,
        "server_id": f"chute-{process_incarnation}",
        "process_incarnation": process_incarnation,
        "profile_id": sibling.profile_id,
        "image_sha256": sibling.image.sha256,
        "image_version": sibling.image.version,
        "host_compute_type": "gpu",
        "gpu_release_id": gpu_release.release_id,
        "active_cpu_release_id": sibling.active_cpu_release_id,
        "kernel_sha256": sibling.image.kernel_sha256,
        "initrd_sha256": sibling.image.initrd_sha256,
        "cmdline_sha256": sibling.image.cmdline_sha256,
        "launch_contract": sibling.launch_contract.model_dump(mode="json"),
    }
    active = (
        await db.execute(
            select(StorageLaunchIntent)
            .where(
                StorageLaunchIntent.host_id == host.host_id,
                StorageLaunchIntent.owner_hotkey == host.miner_hotkey,
                StorageLaunchIntent.tee_type == "tdx",
                StorageLaunchIntent.channel == gpu_release.channel,
                StorageLaunchIntent.state == "active",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if active is not None and all(
        getattr(active, name) == value for name, value in expected.items()
    ):
        return active
    if active is not None:
        await _supersede_storage_intents(
            db,
            StorageLaunchIntent.intent_id == active.intent_id,
        )
    stored = StorageLaunchIntent(
        intent_id=generate_uuid(),
        state="active",
        **expected,
    )
    db.add(stored)
    await db.flush()
    return stored


async def _ensure_gpu_storage_launch_intents(
    db: AsyncSession,
    gpu_release: GuestRelease,
    targets: List[GuestReleaseTarget],
) -> None:
    if _compute_type(gpu_release) != "gpu":
        return
    for host_id in sorted({target.host_id for target in targets if target.role == "gpu"}):
        host = await db.get(Host, host_id)
        if host is None:
            raise ReleaseError(f"GPU rollout target {host_id} no longer has an enrolled host.")
        await _ensure_gpu_storage_launch_intent_for_host(db, gpu_release, host)


async def _refresh_active_gpu_storage_intents(
    db: AsyncSession,
    *,
    active_cpu_release: GuestRelease,
    gpu_release: Optional[GuestRelease],
) -> None:
    if gpu_release is None:
        return
    compatible = False
    try:
        expected_closure = await _gpu_l0_storage_closure(db, active_cpu_release)
        signed_l0, _digest = _verify_l0_release_contract(
            gpu_release,
            allow_expired=True,
        )
        compatible = signed_l0.manifest.storage_closure == expected_closure
    except ReleaseError:
        compatible = False
    if not compatible:
        await _supersede_storage_intents(
            db,
            StorageLaunchIntent.gpu_release_id == gpu_release.release_id,
            StorageLaunchIntent.host_compute_type == "gpu",
        )
        logger.warning(
            f"GPU release {gpu_release.release_id} L0 cannot launch the new CPU/storage "
            "closure; sibling intents were invalidated and no replacements were issued."
        )
        return
    targets = (
        (
            await db.execute(
                select(GuestReleaseTarget).where(
                    GuestReleaseTarget.release_id == gpu_release.release_id,
                    GuestReleaseTarget.compute_type == "gpu",
                    GuestReleaseTarget.role == "gpu",
                )
            )
        )
        .scalars()
        .all()
    )
    await _ensure_gpu_storage_launch_intents(db, gpu_release, targets)


async def _ensure_storage_launch_intents(
    db: AsyncSession,
    release: GuestRelease,
    targets: List[GuestReleaseTarget],
) -> None:
    """Materialize immutable, server-selected launch authority for storage targets."""

    await acquire_gpu_lifecycle_lock(db)
    if _compute_type(release) != "cpu":
        return
    image = (release.images or {}).get("storage") or {}
    if not image or image.get("_inherited"):
        return
    await _supersede_storage_intents(
        db,
        StorageLaunchIntent.tee_type == release.tee_type,
        StorageLaunchIntent.channel == release.channel,
        StorageLaunchIntent.release_id != release.release_id,
    )
    for target in [item for item in targets if item.role == "storage"]:
        process_incarnation = "stor" + hashlib.sha256(target.host_id.encode()).hexdigest()[:8]
        existing = (
            await db.execute(
                select(StorageLaunchIntent)
                .where(StorageLaunchIntent.target_id == target.target_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if existing is not None:
            immutable_expected = {
                "release_id": release.release_id,
                "tee_type": release.tee_type,
                "channel": release.channel,
                "host_id": target.host_id,
                "owner_hotkey": target.miner_hotkey,
                "server_id": f"chute-{process_incarnation}",
                "process_incarnation": process_incarnation,
                "image_sha256": image["sha256"],
                "image_version": image["version"],
            }
            mismatched = {
                name: (getattr(existing, name), value)
                for name, value in immutable_expected.items()
                if getattr(existing, name) != value
            }
            if mismatched or existing.profile_id not in (image.get("measurement_names") or []):
                raise ReleaseError(
                    f"Stored storage launch intent conflicts with immutable target: {mismatched}."
                )
            existing.state = "active"
            continue
        host = await db.get(Host, target.host_id)
        if (
            host is None
            or host.miner_hotkey != target.miner_hotkey
            or host.tee_type != release.tee_type
            or host.compute_type != release.compute_type
            or host.release_channel != release.channel
            or host.provisioning_state != "ready"
            or host.identity_durable_at is None
            or not host.storage_requested
        ):
            raise ReleaseError(
                f"Storage target {target.host_id} is no longer eligible for launch intent."
            )
        profile_id = _storage_profile_for_host(release, host)
        expected = {
            "release_id": release.release_id,
            "tee_type": release.tee_type,
            "channel": release.channel,
            "host_id": host.host_id,
            "owner_hotkey": host.miner_hotkey,
            "server_id": f"chute-{process_incarnation}",
            "process_incarnation": process_incarnation,
            "profile_id": profile_id,
            "image_sha256": image["sha256"],
            "image_version": image["version"],
        }
        db.add(
            StorageLaunchIntent(
                intent_id=generate_uuid(),
                target_id=target.target_id,
                state="active",
                **expected,
            )
        )
    await db.flush()


async def _ensure_storage_launch_intent_for_host(
    db: AsyncSession,
    release: GuestRelease,
    host: Host,
) -> Optional[StorageLaunchIntent]:
    """Repair one returning host without coupling registration to sibling targets."""

    await acquire_gpu_lifecycle_lock(db)
    if _compute_type(release) != "cpu":
        return None
    image = (release.images or {}).get("storage") or {}
    if not image:
        return None
    inherited_storage = bool(image.get("_inherited"))
    if (
        host.miner_hotkey is None
        or host.tee_type != release.tee_type
        or host.compute_type != release.compute_type
        or host.release_channel != release.channel
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or not host.storage_requested
    ):
        raise ReleaseError(f"Storage host {host.host_id} is not eligible for launch-intent repair.")
    active = (
        await db.execute(
            select(StorageLaunchIntent)
            .where(
                StorageLaunchIntent.tee_type == release.tee_type,
                StorageLaunchIntent.channel == release.channel,
                StorageLaunchIntent.host_id == host.host_id,
                StorageLaunchIntent.owner_hotkey == host.miner_hotkey,
                StorageLaunchIntent.state == "active",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        active is not None
        and active.image_sha256 == image.get("sha256")
        and active.image_version == image.get("version")
        and active.profile_id in (image.get("measurement_names") or [])
        and (inherited_storage or active.release_id == release.release_id)
    ):
        return active
    if active is not None and not inherited_storage:
        await _supersede_storage_intents(
            db,
            StorageLaunchIntent.intent_id == active.intent_id,
        )

    candidates = (
        (
            await db.execute(
                select(GuestReleaseTarget)
                .where(
                    GuestReleaseTarget.host_id == host.host_id,
                    GuestReleaseTarget.miner_hotkey == host.miner_hotkey,
                    GuestReleaseTarget.tee_type == release.tee_type,
                    GuestReleaseTarget.compute_type == release.compute_type,
                    GuestReleaseTarget.role == "storage",
                )
                .order_by(
                    GuestReleaseTarget.issued_at.desc(),
                    GuestReleaseTarget.target_id.desc(),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    target = None
    for candidate in candidates:
        if not inherited_storage and candidate.release_id != release.release_id:
            continue
        source = await db.get(GuestRelease, candidate.release_id)
        source_image = (source.images or {}).get("storage") if source is not None else None
        if (
            source is not None
            and source.tee_type == release.tee_type
            and source.compute_type == release.compute_type
            and source.channel == release.channel
            and isinstance(source_image, dict)
            and source_image.get("sha256") == image.get("sha256")
            and source_image.get("version") == image.get("version")
        ):
            target = candidate
            break
    if target is None:
        await db.flush()
        return None

    profile_id = _storage_profile_for_host(release, host)
    process_incarnation = "stor" + hashlib.sha256(host.host_id.encode()).hexdigest()[:8]
    expected = {
        "release_id": target.release_id,
        "tee_type": release.tee_type,
        "channel": release.channel,
        "host_id": host.host_id,
        "owner_hotkey": host.miner_hotkey,
        "server_id": f"chute-{process_incarnation}",
        "process_incarnation": process_incarnation,
        "profile_id": profile_id,
        "image_sha256": image["sha256"],
        "image_version": image["version"],
    }
    await _supersede_storage_intents(
        db,
        StorageLaunchIntent.tee_type == release.tee_type,
        StorageLaunchIntent.channel == release.channel,
        StorageLaunchIntent.host_id == host.host_id,
    )
    stored = (
        await db.execute(
            select(StorageLaunchIntent)
            .where(StorageLaunchIntent.target_id == target.target_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if stored is None:
        stored = StorageLaunchIntent(
            intent_id=generate_uuid(),
            target_id=target.target_id,
            state="active",
            **expected,
        )
        db.add(stored)
    else:
        mismatched = {
            name: (getattr(stored, name), value)
            for name, value in expected.items()
            if getattr(stored, name) != value
        }
        if mismatched:
            raise ReleaseError(
                f"Stored storage launch intent conflicts with immutable target: {mismatched}."
            )
        stored.state = "active"
    await db.flush()
    return stored


async def _capture_release_targets(
    db: AsyncSession,
    release: GuestRelease,
) -> List[GuestReleaseTarget]:
    """Capture an immutable enrolled logical target set exactly once."""
    await acquire_gpu_lifecycle_lock(db)
    _compute_type(release)
    if release.targets_captured_at is not None:
        targets = (
            (
                await db.execute(
                    select(GuestReleaseTarget).where(
                        GuestReleaseTarget.release_id == release.release_id
                    )
                )
            )
            .scalars()
            .all()
        )
        await _ensure_storage_launch_intents(db, release, targets)
        await _ensure_gpu_storage_launch_intents(db, release, targets)
        return targets

    query = (
        select(Host)
        .join(
            HostKeyGeneration,
            and_(
                HostKeyGeneration.host_id == Host.host_id,
                HostKeyGeneration.generation == Host.active_key_generation,
                HostKeyGeneration.revoked_at.is_(None),
            ),
        )
        .where(
            Host.tee_type == release.tee_type,
            Host.release_channel == release.channel,
            Host.compute_type == release.compute_type,
            Host.provisioning_state == "ready",
            Host.identity_durable_at.is_not(None),
            Host.active_key_generation.is_not(None),
        )
        .with_for_update()
    )
    hosts = (await db.execute(query)).scalars().all()
    captured_at = datetime.now(timezone.utc)
    targets = []
    for host in hosts:
        _apply_storage_auto_opt_in(release, host)
        for role in _target_roles_for_host(release, host):
            target_id = generate_uuid()
            targets.append(
                GuestReleaseTarget(
                    target_id=target_id,
                    release_id=release.release_id,
                    host_id=host.host_id,
                    miner_hotkey=host.miner_hotkey,
                    tee_type=release.tee_type,
                    compute_type=release.compute_type,
                    role=role,
                    current_generation=1,
                    current_token_id=f"audit:{target_id}",
                    issued_at=captured_at,
                )
            )
    explicit_roles = {
        role
        for role in _release_image_roles(release)
        if isinstance((release.images or {}).get(role), dict)
        and not (release.images or {})[role].get("_inherited")
    }
    captured_roles = {target.role for target in targets}
    missing_roles = sorted(explicit_roles - captured_roles)
    seedless_l0 = bool((((release.images or {}).get("l0") or {}).get("bootstrap")))
    if missing_roles and seedless_l0:
        raise ReleaseError(
            "Refusing activation without an eligible ready logical-host target for roles: "
            f"{missing_roles}."
        )
    db.add_all(targets)
    release.targets_captured_at = captured_at
    await db.flush()
    await _ensure_storage_launch_intents(db, release, targets)
    await _ensure_gpu_storage_launch_intents(db, release, targets)
    return targets


async def _manifest_for_logical_host(
    db: AsyncSession,
    release: GuestRelease,
    host: Host,
    *,
    reissue_roles: Optional[set[str]] = None,
) -> ReleaseManifest:
    """Build desired state only; launch authorization is a separate reservation."""

    if reissue_roles:
        raise ReleaseError(
            "Guest release target reissue was removed; request an exact launch reservation."
        )
    manifest = release_manifest(release)
    if _compute_type(release) == "gpu":
        from api.gpu_lifecycle_service import existing_release_rollovers_for_host

        sibling = await _gpu_storage_sibling_for_host(db, release, host)
        await _ensure_gpu_storage_launch_intent_for_host(db, release, host)
        rollovers = await existing_release_rollovers_for_host(db, host.host_id, release)
        manifest = manifest.model_copy(
            update={
                "storage_sibling": sibling,
                "gpu_release_rollovers": rollovers,
            }
        )
    return manifest


def _validate_active_release(
    release: GuestRelease,
    db: Optional[AsyncSession] = None,
) -> None:
    """Revalidate desired state against the current trust set before serving or dispatching it."""
    _compute_type(release)
    _validate_release_stream_slots(release)
    raw_l0 = (release.images or {}).get("l0")
    if raw_l0 is not None:
        try:
            signed_l0 = parse_signed_l0_manifest(
                raw_l0.get("bootstrap"),
                compute_type=release.compute_type,
            )
            l0_digest = verify_signed_l0_manifest(
                signed_l0,
                settings.trusted_l0_publisher_keys_path,
                allow_expired=True,
            )
        except (L0BootstrapVerificationError, ValueError, TypeError) as exc:
            raise ReleaseError(
                f"Active release {release.release_id} has an untrusted L0 manifest: {exc}"
            ) from exc
        l0_manifest = signed_l0.manifest
        l0_compute_type = getattr(l0_manifest, "compute_type", "cpu")
        if (
            l0_manifest.tee_type != release.tee_type
            or l0_manifest.channel != release.channel
            or l0_compute_type != release.compute_type
            or (
                l0_manifest.release_id is not None
                and l0_manifest.release_id != release.release_id
                and not raw_l0.get("_inherited")
            )
            or raw_l0.get("version") != l0_manifest.l0_version
            or raw_l0.get("squashfs_sha256") != l0_manifest.squashfs.sha256
            or release.l0_manifest != l0_manifest.model_dump(mode="json", exclude_none=True)
            or release.l0_manifest_digest != l0_digest
            or release.l0_manifest_generation != l0_manifest.generation
            or release.l0_manifest_key_id != l0_manifest.key_id
            or release.l0_manifest_key_epoch != l0_manifest.key_epoch
        ):
            raise ReleaseError(
                f"Active release {release.release_id} L0 audit fields do not match its signed manifest."
            )
    elif any(
        value is not None
        for value in (
            release.l0_manifest,
            release.l0_manifest_digest,
            release.l0_manifest_generation,
            release.l0_manifest_key_id,
            release.l0_manifest_key_epoch,
        )
    ):
        raise ReleaseError(f"Active release {release.release_id} has partial L0 audit state.")
    loaded_by_name = _loaded_measurements_by_name()
    images = release.images or {}
    image_roles = _release_image_roles(release)
    if not any(images.get(role) for role in image_roles):
        raise ReleaseError(f"Active release {release.release_id} contains no guest images.")
    for role in image_roles:
        image = images.get(role)
        if image:
            if role == "gpu":
                _validate_gpu_image_provenance(release, image, loaded_by_name, db=db)
            else:
                _validate_image_provenance(release, role, image, loaded_by_name, db=db)


async def preverify_active_gpu_release_for_host(
    db: AsyncSession,
    host_id: str,
) -> None:
    """Snapshot the host stream's exact GPU signature before lifecycle acquisition."""

    identity = (
        await db.execute(
            select(Host.release_channel, Host.compute_type, Host.tee_type).where(
                Host.host_id == host_id
            )
        )
    ).one_or_none()
    if identity is None or identity.compute_type != "gpu" or identity.tee_type != "tdx":
        raise ReleaseError("GPU host has no eligible release stream identity.")
    release = await get_active_release(
        db,
        "tdx",
        identity.release_channel,
        "gpu",
    )
    if release is None:
        raise ReleaseError("GPU host has no active exact GPU release.")
    _validate_active_release(release, db)
    await db.commit()


async def _preverify_active_release_closure(
    db: AsyncSession,
    release: GuestRelease,
) -> None:
    """Prewarm exact release and composed CPU/storage signatures before any later lock."""

    _validate_active_release(release, db)
    if _compute_type(release) != "gpu":
        return
    active_cpu = await get_active_release(
        db,
        "tdx",
        release.channel,
        "cpu",
    )
    if active_cpu is None:
        raise ReleaseError(
            "GPU desired state requires an independently active CPU/storage release."
        )
    _validate_active_release(active_cpu, db)


async def active_manifest_for_host(
    db: AsyncSession,
    tee_type: str,
    channel: str = "stable",
    compute_type: str = "cpu",
    *,
    host_id: Optional[str] = None,
    miner_hotkey: Optional[str] = None,
    reissue_roles: Optional[set[str]] = None,
) -> Optional[ReleaseManifest]:
    """The manifest one authenticated logical L0 should converge to.

    ``reissue_roles`` explicitly invalidates and advances those logical token generations. This
    same-miner capability remains transferable between unattested L0s and is operational only.
    """
    if not tee_type:
        return None
    release = await get_active_release(
        db,
        tee_type.strip().lower(),
        channel,
        compute_type,
        lock=bool(reissue_roles),
    )
    if release is None:
        return None
    await _preverify_active_release_closure(db, release)
    if host_id is None:
        return release_manifest(release)
    host = await db.get(Host, host_id)
    if host is None:
        raise ReleaseError(f"Logical rollout host {host_id} is not enrolled.")
    if miner_hotkey is None or host.miner_hotkey != miner_hotkey:
        raise ReleaseError(f"Logical rollout host {host_id} is owned by another miner.")
    if (
        host.tee_type != release.tee_type
        or host.compute_type != release.compute_type
        or host.release_channel != release.channel
    ):
        raise ReleaseError(
            f"Logical rollout host {host_id} is not enrolled in "
            f"{release.channel}/{release.tee_type}/{release.compute_type}."
        )
    return await _manifest_for_logical_host(
        db,
        release,
        host,
        reissue_roles=reissue_roles,
    )


async def rollout_release(
    db: AsyncSession,
    release_id: str,
    host_ids: Optional[List[str]] = None,
    reboot_l0: bool = False,
) -> Dict:
    """Push the active release to online L0 hosts of its tee_type via the upgrade_image command.

    host_ids restricts only this immediate dispatch. It never narrows the immutable activation
    telemetry target set; a true canary uses a dedicated release channel. Offline targets are
    reported here and converge later through registration or periodic polling. Automatic status
    never authorizes pin pruning.

    reboot_l0 ALSO sends a `reboot` to apply the release's L0 slot (re-netboot). This is disruptive
    (every TD on the host restarts), so it is opt-in and best driven one host at a time via host_ids.
    """
    from api.agent_channel import is_agent_online, send_agent_command

    release = await db.get(GuestRelease, release_id)
    if release is None:
        raise ReleaseError(f"Release {release_id} not found")
    if release.status != RELEASE_STATUS_ACTIVE:
        raise ReleaseError(
            f"Release {release_id} is '{release.status}', not active; activate it before rollout."
        )
    await _preverify_active_release_closure(db, release)

    l0_spec = (release.images or {}).get("l0") or {}
    l0_version = l0_spec.get("version")
    if reboot_l0 and not l0_version:
        raise ReleaseError("reboot_l0 requested but the release carries no l0 slot.")
    targets = await _capture_release_targets(db, release)
    # Capture and intent repair both acquire lifecycle custody, including the
    # already-captured replay. Always commit it before agent liveness/dispatch.
    await db.commit()
    await db.refresh(release)
    captured_host_ids = {target.host_id for target in targets}
    if host_ids is not None:
        captured_host_ids &= set(host_ids)
    q = select(Host).where(
        Host.tee_type == release.tee_type,
        Host.compute_type == release.compute_type,
        Host.host_id.in_(captured_host_ids),
    )
    hosts = (await db.execute(q)).scalars().all()
    await db.commit()

    results = []
    dispatched = 0
    for host in hosts:
        assert_gpu_external_work_allowed(db, "release rollout agent liveness")
        if not await is_agent_online(host.host_id):
            results.append(
                {
                    "host_id": host.host_id,
                    "dispatched": False,
                    "detail": "offline (will converge via poll)",
                }
            )
            continue
        try:
            manifest = (await _manifest_for_logical_host(db, release, host)).model_dump()
            await db.commit()
            assert_gpu_external_work_allowed(db, "release rollout agent dispatch")
            command_id = await send_agent_command(
                host.host_id, "upgrade_image", {"manifest": manifest}
            )
            detail = f"upgrade_image dispatched ({command_id})"
            # Opt-in L0 re-netboot: send reboot AFTER the image nudge so the box comes up on the new
            # guest images too. target_l0_version makes an already-updated host skip the reboot.
            if reboot_l0 and (getattr(host, "l0_version", None) != l0_version):
                assert_gpu_external_work_allowed(db, "release rollout reboot dispatch")
                rid = await send_agent_command(
                    host.host_id, "reboot", {"target_l0_version": l0_version}
                )
                detail += f"; reboot dispatched ({rid}) -> l0 {l0_version}"
            dispatched += 1
            results.append({"host_id": host.host_id, "dispatched": True, "detail": detail})
        except Exception as exc:  # noqa: BLE001 - report per-host, keep rolling out the rest
            results.append(
                {
                    "host_id": host.host_id,
                    "dispatched": False,
                    "detail": f"dispatch failed: {exc}",
                }
            )
    logger.success(
        f"Rollout of release {release_id} ({release.tee_type}/{release.compute_type}): "
        f"dispatched to {dispatched}/{len(hosts)} host(s)"
        + (f" (dispatch subset: {host_ids})" if host_ids else "")
        + (" +reboot_l0" if reboot_l0 else "")
    )
    return {"release_id": release_id, "dispatched": dispatched, "hosts": results}


async def release_status(db: AsyncSession, release_id: str) -> Dict:
    """Return untrusted host telemetry plus exact logical-target attestation telemetry.

    Physical host identity remains unprovable: an unattested same-miner L0 can transfer a target
    bearer token and inject its logical ``host_id`` into any guest it launches. Logical convergence
    is useful operational telemetry, but it can never automatically authorize measurement-pin
    pruning or establish physical failure-domain convergence.
    """
    from api.agent_channel import is_agent_online

    release = await db.get(GuestRelease, release_id)
    if release is None:
        raise ReleaseError(f"Release {release_id} not found")
    await _preverify_active_release_closure(db, release)

    chute_img = (release.images or {}).get("chute") or {}
    storage_img = (release.images or {}).get("storage") or {}
    gpu_img = (release.images or {}).get("gpu") or {}
    if chute_img.get("_inherited"):
        chute_img = {}
    if storage_img.get("_inherited"):
        storage_img = {}
    if gpu_img.get("_inherited"):
        gpu_img = {}
    l0_spec = (release.images or {}).get("l0") or {}
    chute_sha = chute_img.get("sha256")
    storage_sha = storage_img.get("sha256")
    gpu_sha = gpu_img.get("sha256")
    l0_version = l0_spec.get("version")
    chute_names = list(chute_img.get("measurement_names") or [])
    storage_names = list(storage_img.get("measurement_names") or [])
    gpu_names = list(gpu_img.get("measurement_names") or [])
    names_by_role = {
        role: names
        for role, names in (
            ("chute", chute_names),
            ("storage", storage_names),
            ("gpu", gpu_names),
        )
        if names
    }
    required_roles = list(names_by_role)
    required_names = [name for names in names_by_role.values() for name in names]

    targets = (
        (
            await db.execute(
                select(GuestReleaseTarget)
                .where(GuestReleaseTarget.release_id == release.release_id)
                .order_by(
                    GuestReleaseTarget.host_id,
                    GuestReleaseTarget.role,
                    GuestReleaseTarget.target_id,
                )
            )
        )
        .scalars()
        .all()
    )
    target_host_ids = sorted({target.host_id for target in targets})
    hosts = (
        (
            await db.execute(
                select(Host).where(
                    Host.tee_type == release.tee_type,
                    Host.release_channel == release.channel,
                    Host.compute_type == release.compute_type,
                    Host.host_id.in_(target_host_ids),
                )
            )
        )
        .scalars()
        .all()
        if target_host_ids
        else []
    )
    reservations = []
    gpu_reservations = []
    if release.compute_type == "cpu":
        reservations = (
            (
                await db.execute(
                    select(TdLaunchReservation)
                    .where(
                        TdLaunchReservation.release_id == release.release_id,
                        TdLaunchReservation.consumed_at.is_not(None),
                        TdLaunchReservation.invalidated_at.is_(None),
                    )
                    .order_by(
                        TdLaunchReservation.host_id,
                        TdLaunchReservation.role,
                        TdLaunchReservation.boot_generation,
                        TdLaunchReservation.issued_at,
                    )
                )
            )
            .scalars()
            .all()
        )
    else:
        from api.host.schemas import GpuLaunchReservation

        gpu_reservations = (
            (
                await db.execute(
                    select(GpuLaunchReservation)
                    .where(
                        GpuLaunchReservation.gpu_release_id == release.release_id,
                        GpuLaunchReservation.guest_consumed_at.is_not(None),
                        GpuLaunchReservation.state == "running",
                    )
                    .order_by(
                        GpuLaunchReservation.host_id,
                        GpuLaunchReservation.reservation_generation,
                        GpuLaunchReservation.issued_at,
                    )
                )
            )
            .scalars()
            .all()
        )
    reservation_by_target = {
        (reservation.host_id, reservation.role): reservation for reservation in reservations
    }
    reservation_by_target.update(
        {(reservation.host_id, "gpu"): reservation for reservation in gpu_reservations}
    )

    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.release_attestation_max_age_seconds
    )
    latest = select(
        ServerAttestation.attestation_id.label("attestation_id"),
        ServerAttestation.server_id.label("server_id"),
        ServerAttestation.measurement_name.label("measurement_name"),
        ServerAttestation.measurement_version.label("measurement_version"),
        ServerAttestation.measurement_config_fingerprint.label("measurement_config_fingerprint"),
        ServerAttestation.trust_set_fingerprint.label("trust_set_fingerprint"),
        ServerAttestation.verification_error.label("verification_error"),
        ServerAttestation.verified_at.label("verified_at"),
        ServerAttestation.revocation_status.label("revocation_status"),
        ServerAttestation.gpu_retired_at.label("gpu_retired_at"),
        func.row_number()
        .over(
            partition_by=ServerAttestation.server_id,
            order_by=ServerAttestation.attempt_sequence.desc(),
        )
        .label("rn"),
    ).subquery()
    attested_rows = (
        await db.execute(
            select(
                Server,
                latest.c.attestation_id,
                latest.c.measurement_name,
                latest.c.measurement_version,
                latest.c.measurement_config_fingerprint,
                latest.c.trust_set_fingerprint,
                latest.c.verified_at,
                latest.c.revocation_status,
            )
            .join(latest, latest.c.server_id == Server.server_id)
            .where(
                latest.c.rn == 1,
                latest.c.verification_error.is_(None),
                latest.c.verified_at.is_not(None),
                latest.c.verified_at >= cutoff,
                latest.c.gpu_retired_at.is_(None),
                Server.self_registered.is_(True),
                Server.is_tee.is_(True),
                Server.compute_type == release.compute_type,
                Server.tee_type == release.tee_type,
                Server.gpu_retired_at.is_(None),
            )
        )
    ).all()

    loaded_by_name = _loaded_measurements_by_name()
    current_trust_set_fingerprint = measurement_trust_set_fingerprint(list(loaded_by_name.values()))
    trusted_measurement_counts = {name: 0 for name in required_names}
    trusted_role_counts = {role: 0 for role in required_roles}
    trusted_tee_counts = {release.tee_type: 0}
    trusted_server_ids: set[str] = set()
    fresh_relevant_not_on_release: set[str] = set()
    latest_by_server: dict[str, tuple] = {}

    def exact_release_identity(
        server: Server,
        measurement_name: Optional[str],
        measurement_version: Optional[str],
        measurement_config_fingerprint_value: Optional[str],
        trust_set_fingerprint: Optional[str],
        role: str,
    ) -> bool:
        expected_config = loaded_by_name.get(measurement_name)
        if expected_config is None:
            return False
        role_image = (release.images or {}).get(role) or {}
        measurement_role = (
            "storage"
            if str(measurement_name or "").startswith("storage-")
            else ("gpu" if expected_config.gpu_count > 0 else "chute")
        )
        return bool(
            role == measurement_role
            and role in names_by_role
            and measurement_name in names_by_role[role]
            and expected_config.version == measurement_version
            and (
                getattr(expected_config, "config_fingerprint", None)
                or measurement_config_fingerprint(expected_config)
            )
            == measurement_config_fingerprint_value
            and trust_set_fingerprint == current_trust_set_fingerprint
            and server.measurement_name == measurement_name
            and server.version == measurement_version
            and server.measurement_config_fingerprint == measurement_config_fingerprint_value
            and server.trust_set_fingerprint == trust_set_fingerprint
            and expected_config.tee_type == release.tee_type
            and server.tee_type == release.tee_type
            and server.compute_type == release.compute_type
            and bool(server.storage_role) == (role == "storage")
            and getattr(expected_config, "image_sha256", None) == role_image.get("sha256")
        )

    for (
        server,
        attestation_id,
        measurement_name,
        measurement_version,
        measurement_config_fingerprint_value,
        trust_set_fingerprint,
        verified_at,
        revocation_status,
    ) in attested_rows:
        from api.server.gpu_sessions import _revocation_failed

        if _revocation_failed(revocation_status) or dict(revocation_status or {}) != dict(
            server.attestation_revocation_status or {}
        ):
            continue
        latest_by_server[server.server_id] = (
            server,
            attestation_id,
            measurement_name,
            measurement_version,
            measurement_config_fingerprint_value,
            trust_set_fingerprint,
            verified_at,
        )
        server_role = (
            "storage"
            if bool(server.storage_role)
            else ("gpu" if server.compute_type == "gpu" else "chute")
        )
        expected_measurement = loaded_by_name.get(measurement_name)
        measurement_role = (
            "storage"
            if str(measurement_name or "").startswith("storage-")
            else (
                "gpu"
                if expected_measurement is not None and expected_measurement.gpu_count > 0
                else "chute"
            )
        )
        # Omitted roles are preserved and intentionally ignored. A mismatch touching a required
        # role remains relevant logical rollout telemetry, but automatic pin pruning is always false.
        if server_role not in names_by_role and measurement_role not in names_by_role:
            continue
        if not exact_release_identity(
            server,
            measurement_name,
            measurement_version,
            measurement_config_fingerprint_value,
            trust_set_fingerprint,
            server_role,
        ):
            fresh_relevant_not_on_release.add(server.server_id)
            continue

        trusted_server_ids.add(server.server_id)
        trusted_measurement_counts[measurement_name] += 1
        trusted_role_counts[server_role] += 1

    trusted_tee_counts[release.tee_type] = len(trusted_server_ids)
    host_by_id = {host.host_id: host for host in hosts}
    online_by_host = {}
    for host in hosts:
        assert_gpu_external_work_allowed(db, "release-status host liveness lookup")
        online_by_host[host.host_id] = await is_agent_online(host.host_id)
    observed_storage_by_host: dict[str, set[str]] = {}
    online_by_server: dict[str, bool] = {}
    if release.compute_type == "gpu":
        from api.host.reservations import observe_gpu_storage_liveness

        for host in hosts:
            observed_storage_by_host[host.host_id] = await observe_gpu_storage_liveness(
                db, host.host_id
            )
        for server_id in sorted(
            {
                reservation.server_id
                for reservation in gpu_reservations
                if reservation.server_id is not None
            }
        ):
            assert_gpu_external_work_allowed(db, "release-status guest liveness lookup")
            online_by_server[server_id] = await is_agent_online(server_id)
    host_rows = []
    gpu_storage_siblings = []
    for host in hosts:
        staged = host.staged_images or {}
        staged_chute = (staged.get("chute") or {}).get("sha256")
        staged_storage = (staged.get("storage") or {}).get("sha256")
        staged_gpu = (staged.get("gpu") or {}).get("sha256")
        chute_ok = (not chute_sha) or staged_chute == chute_sha
        host_storage_sha = storage_sha
        storage_contract_ok = True
        if release.compute_type == "gpu":
            try:
                sibling = await _gpu_storage_sibling_for_host(db, release, host)
                host_storage_sha = sibling.image.sha256
                from api.host.reservations import gpu_host_storage_readiness

                readiness = await gpu_host_storage_readiness(
                    db,
                    host,
                    observed_live_storage_ids=observed_storage_by_host.get(host.host_id, set()),
                )
                gpu_storage_siblings.append(readiness.model_dump(mode="json"))
            except ReleaseError:
                storage_contract_ok = False
                gpu_storage_siblings.append(
                    {
                        "schema": "chutes.gpu-host-storage-readiness",
                        "version": 1,
                        "host_id": host.host_id,
                        "trusted_storage_ready": False,
                        "control_channel_eligible": False,
                        "trusted_schedulable": False,
                        "reason": "gpu_l0_storage_closure_incompatible",
                        "physical_co_location_trusted": False,
                    }
                )
        storage_ok = storage_contract_ok and (
            (not host_storage_sha) or staged_storage == host_storage_sha
        )
        gpu_ok = (not gpu_sha) or staged_gpu == gpu_sha
        running_l0 = getattr(host, "l0_version", None)
        l0_matches = None if not l0_version else (running_l0 == l0_version)
        host_rows.append(
            {
                "untrusted_host_id": host.host_id,
                "untrusted_online": online_by_host[host.host_id],
                "untrusted_staged_chute_sha": staged_chute,
                "untrusted_staged_storage_sha": staged_storage,
                "untrusted_staged_gpu_sha": staged_gpu,
                "untrusted_stage_matches_release": bool(chute_ok and storage_ok and gpu_ok),
                "untrusted_running_l0_version": running_l0,
                "untrusted_l0_matches_release": l0_matches,
                "untrusted_gpu_inventory": host.untrusted_gpu_inventory,
                "untrusted_gpu_inventory_ready": host.untrusted_gpu_inventory_ready,
            }
        )

    logical_target_counts = {role: 0 for role in required_roles}
    logical_target_completed_counts = {role: 0 for role in required_roles}
    logical_target_rows = []
    for target in targets:
        if target.role not in logical_target_counts:
            continue
        logical_target_counts[target.role] += 1
        reservation = reservation_by_target.get((target.host_id, target.role))
        if release.compute_type == "gpu":
            from api.host.reservations import gpu_host_storage_readiness
            from api.host.schemas import GpuAllocationGroup
            from api.server.gpu_sessions import _current_attestation

            current_host = host_by_id.get(target.host_id)
            server = (
                await db.get(Server, reservation.server_id) if reservation is not None else None
            )
            group = (
                await db.get(GpuAllocationGroup, reservation.allocation_group_id)
                if reservation is not None
                else None
            )
            latest_attempt = (
                (
                    await db.execute(
                        select(ServerAttestation)
                        .where(ServerAttestation.server_id == server.server_id)
                        .order_by(ServerAttestation.attempt_sequence.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if server is not None
                else None
            )
            latest_current = False
            if server is not None:
                try:
                    _current_attestation(server, latest_attempt)
                    latest_current = True
                except HTTPException:
                    latest_current = False
            expected_config = (
                loaded_by_name.get(latest_attempt.measurement_name)
                if latest_attempt is not None
                else None
            )
            fresh_exact = bool(
                reservation is not None
                and reservation.state == "running"
                and reservation.guest_consumed_at is not None
                and reservation.gpu_release_id == release.release_id
                and reservation.image_sha256 == gpu_sha
                and reservation.measurement_name in gpu_names
                and server is not None
                and server.gpu_retired_at is None
                and server.gpu_launch_reservation_id == reservation.reservation_id
                and server.gpu_allocation_group_id == reservation.allocation_group_id
                and server.gpu_allocation_group_generation
                == reservation.allocation_group_generation
                and server.gpu_management_mode == reservation.management_mode
                and server.gpu_process_incarnation == reservation.process_incarnation
                and server.gpu_topology_fingerprint == reservation.topology_fingerprint
                and group is not None
                and group.state == "running"
                and group.reservation_id == reservation.reservation_id
                and group.generation == reservation.allocation_group_generation
                and group.reservation_generation == reservation.reservation_generation
                and latest_current
                and latest_attempt is not None
                and latest_attempt.gpu_launch_reservation_id == reservation.reservation_id
                and latest_attempt.gpu_allocation_group_id == reservation.allocation_group_id
                and latest_attempt.gpu_allocation_group_generation
                == reservation.allocation_group_generation
                and latest_attempt.gpu_host_boot_generation == reservation.host_boot_generation
                and latest_attempt.gpu_reservation_generation == reservation.reservation_generation
                and latest_attempt.gpu_management_mode == reservation.management_mode
                and latest_attempt.gpu_process_incarnation == reservation.process_incarnation
                and latest_attempt.gpu_topology_fingerprint == reservation.topology_fingerprint
                and latest_attempt.gpu_release_id == reservation.gpu_release_id
                and latest_attempt.gpu_profile_id == reservation.profile_id
                and latest_attempt.gpu_claims_sha256 == reservation.claims_sha256
                and latest_attempt.gpu_evidence_certificate_sha256s
                == reservation.gpu_attestation_certificate_sha256s
                and expected_config is not None
                and exact_release_identity(
                    server,
                    latest_attempt.measurement_name,
                    latest_attempt.measurement_version,
                    latest_attempt.measurement_config_fingerprint,
                    latest_attempt.trust_set_fingerprint,
                    "gpu",
                )
            )
            storage_ready = False
            if current_host is not None:
                readiness = await gpu_host_storage_readiness(
                    db,
                    current_host,
                    include_allocation=False,
                    observed_live_storage_ids=observed_storage_by_host.get(
                        current_host.host_id, set()
                    ),
                )
                storage_ready = bool(
                    readiness.trusted_storage_ready and readiness.control_channel_eligible
                )
            runtime_session_ready = bool(
                server is not None
                and latest_attempt is not None
                and server.gpu_runtime_session_attestation_id == latest_attempt.attestation_id
                and server.gpu_runtime_session_expires_at is not None
                and server.gpu_runtime_session_expires_at > datetime.now(timezone.utc)
            )
            server_control_ready = bool(
                server is not None
                and (
                    (
                        server.gpu_management_mode == "platform"
                        and online_by_server.get(server.server_id, False)
                    )
                    or (server.gpu_management_mode == "miner" and runtime_session_ready)
                )
            )
            logical_online = bool(
                current_host is not None
                and current_host.miner_hotkey == target.miner_hotkey
                and online_by_host.get(target.host_id, False)
                and server_control_ready
            )
            staged_for_role = (
                ((current_host.staged_images or {}).get("gpu") or {}).get("sha256")
                if current_host is not None
                else None
            )
            exact_stage = bool(gpu_sha and staged_for_role == gpu_sha)
            roll_outcomes = (
                (current_host.staged_images or {}).get("roll_outcomes") or {}
                if current_host is not None
                else {}
            )
            role_roll = (roll_outcomes.get("roles") or {}).get("gpu") or {}
            old_process_exit_confirmed = bool(
                roll_outcomes.get("release_id") == release.release_id
                and role_roll.get("sha256") == gpu_sha
                and role_roll.get("old_processes_exited") is True
            )
            fresh_role_health = bool(
                fresh_exact and logical_online and storage_ready and runtime_session_ready
            )
            target_complete = bool(fresh_role_health and exact_stage and old_process_exit_confirmed)
            if target_complete:
                logical_target_completed_counts[target.role] += 1
            logical_target_rows.append(
                {
                    "target_id": target.target_id,
                    "logical_host_id": target.host_id,
                    "role": "gpu",
                    "logical_online": logical_online,
                    "launch_boot_generation": (
                        reservation.host_boot_generation
                        if reservation is not None
                        else int(target.current_generation)
                    ),
                    "launch_reservation_consumed": bool(
                        reservation is not None and reservation.guest_consumed_at is not None
                    ),
                    "fresh_exact_attestation": fresh_exact,
                    "fresh_role_health": fresh_role_health,
                    "exact_staged_digest": exact_stage,
                    "old_process_exit_confirmed": old_process_exit_confirmed,
                    "running_image_sha256": (
                        reservation.image_sha256 if reservation is not None else None
                    ),
                    "running_image_version": (
                        reservation.image_version if reservation is not None else None
                    ),
                    "running_process_incarnation": (
                        reservation.process_incarnation if reservation is not None else None
                    ),
                    "running_storage_incarnation": None,
                    "allocation_group_id": (
                        reservation.allocation_group_id if reservation is not None else None
                    ),
                    "allocation_group_generation": (
                        reservation.allocation_group_generation if reservation is not None else None
                    ),
                    "management_mode": (
                        reservation.management_mode if reservation is not None else None
                    ),
                    "storage_sibling_ready": storage_ready,
                    "runtime_session_ready": runtime_session_ready,
                    "gpu_evidence_sha256": (
                        latest_attempt.gpu_evidence_sha256 if latest_attempt is not None else None
                    ),
                    "host_credential_cloneable": True,
                    "physical_placement_trusted": False,
                    "server_id": (reservation.server_id if reservation is not None else None),
                    "measurement_name": (
                        latest_attempt.measurement_name if latest_attempt is not None else None
                    ),
                }
            )
            continue
        if reservation is None and target.consumed_at is not None:
            historical_config = loaded_by_name.get(target.consumed_measurement_name)
            reservation = SimpleNamespace(
                server_id=target.consumed_server_id,
                profile_id=target.consumed_measurement_name,
                image_sha256=getattr(historical_config, "image_sha256", None),
                boot_generation=int(target.current_generation),
                consumed_at=target.consumed_at,
                issued_at=target.issued_at,
                consumed_cert_pubkey_hash=target.consumed_cert_pubkey_hash,
            )
        latest_row = latest_by_server.get(reservation.server_id if reservation is not None else "")
        fresh_exact = False
        running_image_sha256 = None
        running_image_version = None
        running_process_incarnation = None
        running_storage_incarnation = None
        fresh_role_health = False
        latest_measurement_name = None
        if latest_row is not None:
            (
                server,
                _attestation_id,
                measurement_name,
                measurement_version,
                measurement_config_fingerprint_value,
                trust_set_fingerprint,
                verified_at,
            ) = latest_row
            latest_measurement_name = measurement_name
            consumed_config = loaded_by_name.get(measurement_name)
            if consumed_config is not None:
                running_image_sha256 = getattr(consumed_config, "image_sha256", None)
                running_image_version = ((release.images or {}).get(target.role) or {}).get(
                    "version"
                )
            running_process_incarnation = server.attested_cert_pubkey_hash
            running_storage_incarnation = (
                getattr(server, "storage_incarnation", None) if target.role == "storage" else None
            )
            consumed_identity_matches = bool(
                reservation is not None
                and reservation.profile_id == measurement_name
                and reservation.image_sha256
                == ((release.images or {}).get(target.role) or {}).get("sha256")
                and measurement_name in names_by_role.get(target.role, [])
                and consumed_config is not None
                and (
                    getattr(consumed_config, "config_fingerprint", None)
                    or measurement_config_fingerprint(consumed_config)
                )
                == measurement_config_fingerprint_value
                and trust_set_fingerprint == current_trust_set_fingerprint
                and consumed_config.tee_type == release.tee_type
            )
            fresh_exact = bool(
                reservation is not None
                and reservation.consumed_at is not None
                and reservation.consumed_at >= reservation.issued_at
                and verified_at is not None
                and verified_at >= reservation.issued_at
                and consumed_identity_matches
                and server.miner_hotkey == target.miner_hotkey
                and (server.attested_cert_pubkey_hash or "").lower()
                == (reservation.consumed_cert_pubkey_hash or "").lower()
                and exact_release_identity(
                    server,
                    measurement_name,
                    measurement_version,
                    measurement_config_fingerprint_value,
                    trust_set_fingerprint,
                    target.role,
                )
            )
            if target.role == "storage":
                announced_at = getattr(server, "storage_incarnation_announced_at", None)
                fresh_role_health = bool(
                    fresh_exact
                    and running_process_incarnation
                    and running_storage_incarnation
                    and announced_at is not None
                    and reservation is not None
                    and reservation.consumed_at is not None
                    and announced_at >= reservation.consumed_at
                )
            else:
                # A current exact self-registration row is the chute process incarnation. Host-slot
                # heartbeat reconciliation deletes it when that exact TD disappears.
                fresh_role_health = fresh_exact
        current_host = host_by_id.get(target.host_id)
        logical_online = bool(
            current_host is not None
            and current_host.miner_hotkey == target.miner_hotkey
            and online_by_host.get(target.host_id, False)
        )
        staged_for_role = (
            ((getattr(current_host, "staged_images", None) or {}).get(target.role) or {}).get(
                "sha256"
            )
            if current_host is not None
            else None
        )
        expected_role_digest = ((release.images or {}).get(target.role) or {}).get("sha256")
        exact_stage = bool(expected_role_digest and staged_for_role == expected_role_digest)
        roll_outcomes = (
            (getattr(current_host, "staged_images", None) or {}).get("roll_outcomes") or {}
            if current_host is not None
            else {}
        )
        role_roll = (roll_outcomes.get("roles") or {}).get(target.role) or {}
        old_process_exit_confirmed = bool(
            roll_outcomes.get("release_id") == release.release_id
            and role_roll.get("sha256") == expected_role_digest
            and role_roll.get("old_processes_exited") is True
        )
        target_complete = bool(
            release.compute_type == "cpu"
            and fresh_role_health
            and logical_online
            and exact_stage
            and old_process_exit_confirmed
        )
        if target_complete:
            logical_target_completed_counts[target.role] += 1
        logical_target_rows.append(
            {
                "target_id": target.target_id,
                "logical_host_id": target.host_id,
                "role": target.role,
                "logical_online": logical_online,
                "launch_boot_generation": (
                    int(reservation.boot_generation)
                    if reservation is not None
                    else int(target.current_generation)
                ),
                "launch_reservation_consumed": (
                    reservation is not None and reservation.consumed_at is not None
                ),
                "fresh_exact_attestation": fresh_exact,
                "fresh_role_health": fresh_role_health,
                "exact_staged_digest": exact_stage,
                "old_process_exit_confirmed": old_process_exit_confirmed,
                "running_image_sha256": running_image_sha256,
                "running_image_version": running_image_version,
                "running_process_incarnation": running_process_incarnation,
                "running_storage_incarnation": running_storage_incarnation,
                "host_credential_cloneable": True,
                "physical_placement_trusted": False,
                "server_id": reservation.server_id if reservation is not None else None,
                "measurement_name": latest_measurement_name,
            }
        )

    required_roles_have_targets = bool(required_roles) and all(
        logical_target_counts[role] > 0 for role in required_roles
    )
    all_logical_targets_healthy = (
        _runtime_convergence_supported(release)
        and bool(targets)
        and len(logical_target_rows) == len(targets)
        and all(
            row["fresh_exact_attestation"]
            and row["fresh_role_health"]
            and row["exact_staged_digest"]
            and row["old_process_exit_confirmed"]
            and row["logical_online"]
            for row in logical_target_rows
        )
    )
    logical_rollout_converged = bool(
        release.targets_captured_at is not None
        and required_roles_have_targets
        and all_logical_targets_healthy
    )
    target_roles_observed = {
        role: logical_target_counts[role] > 0
        and logical_target_completed_counts[role] == logical_target_counts[role]
        for role in required_roles
    }

    return {
        "release_id": release.release_id,
        "status": release.status,
        "tee_type": release.tee_type,
        "compute_type": release.compute_type,
        "required_roles": required_roles,
        "required_chute_measurement_names": chute_names,
        "required_storage_measurement_names": storage_names,
        "required_gpu_measurement_names": gpu_names,
        "gpu_storage_siblings": gpu_storage_siblings,
        "all_gpu_storage_siblings_ready": bool(gpu_storage_siblings)
        and all(
            item["trusted_storage_ready"] and item["control_channel_eligible"]
            for item in gpu_storage_siblings
        ),
        "runtime_convergence_supported": _runtime_convergence_supported(release),
        "source_staged_only": not _runtime_convergence_supported(release),
        "runtime_convergence_state": "tracked",
        "attestation_max_age_seconds": settings.release_attestation_max_age_seconds,
        "untrusted_hosts": host_rows,
        "trusted_measurement_counts": trusted_measurement_counts,
        "trusted_role_counts": trusted_role_counts,
        "trusted_tee_counts": trusted_tee_counts,
        "trusted_roles_observed": target_roles_observed,
        "all_required_roles_observed": bool(target_roles_observed)
        and all(target_roles_observed.values()),
        "trusted_attestations_on_release": len(trusted_server_ids),
        "fresh_relevant_attestations_not_on_release": len(fresh_relevant_not_on_release),
        "targets_captured_at": (
            release.targets_captured_at.isoformat()
            if release.targets_captured_at is not None
            else None
        ),
        "logical_rollout_targets": logical_target_rows,
        "logical_target_counts": logical_target_counts,
        "logical_target_completed_counts": logical_target_completed_counts,
        "all_logical_targets_healthy": all_logical_targets_healthy,
        "logical_rollout_converged": logical_rollout_converged,
        "logical_rollout_telemetry_only": True,
        "logical_host_credentials_cloneable": True,
        "physical_host_convergence_proven": False,
        # Model-B physical placement is outside the attested evidence. Automatic status must never
        # authorize pin removal; an operator must validate physical failure-domain convergence
        # through an explicit external process.
        "pin_pruning_safe": False,
    }


def to_response(release: GuestRelease) -> Dict:
    return {
        "release_id": release.release_id,
        "channel": release.channel,
        "tee_type": release.tee_type,
        "compute_type": release.compute_type,
        "status": release.status,
        "images": release.images or {},
        "notes": release.notes,
        "created_at": release.created_at.isoformat() if release.created_at else None,
        "activated_at": release.activated_at.isoformat() if release.activated_at else None,
        "release_request_sha256": release.release_request_sha256,
    }
