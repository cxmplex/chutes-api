"""Fleet image release service: create/activate/rollout/status + the host-facing active manifest.

Desired-state model: for each (channel, tee_type) at most one release is ACTIVE. L0 node-agents
converge to the active release for their tee_type. Activation verifies canonical detached-cosign
provenance, exact image/pin identity, and complete CPU-only size matrices before desired state can
change. Unsigned provenance exists only for explicit debug artifacts in explicit dev posture.
"""

import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Dict, List, Optional

from loguru import logger
from sqlalchemy import and_, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.database import generate_uuid
from api.host.schemas import HostKeyGeneration
from api.host.schemas import TdLaunchReservation
from api.releases.bootstrap import (
    L0BootstrapVerificationError,
    verify_signed_l0_manifest,
)
from api.releases.provenance import (
    REQUIRED_DIRECT_TDX_PROFILES,
    REQUIRED_RELEASE_VCPU_SIZES,
    ProvenanceError,
    expected_pin_version,
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
    GuestRelease,
    GuestReleaseTarget,
    SignedL0BootstrapManifestV1,
    ReleaseImage,
    ReleaseL0,
    ReleaseManifest,
)
from api.server.schemas import Host, Server, ServerAttestation


class ReleaseError(Exception):
    """Raised for release create/activate/rollout errors (mapped to HTTP 4xx by the router)."""


def _loaded_measurements_by_name() -> dict:
    """Every loaded measurement keyed by name (committed YAML + mounted ConfigMap)."""
    return {
        measurement.name: measurement
        for measurement in settings.tee_measurements
        if measurement.name
    }


def _release_measurement_names(release: GuestRelease) -> List[str]:
    names: List[str] = []
    for key in ("chute", "storage"):
        img = (release.images or {}).get(key) or {}
        names.extend(img.get("measurement_names") or [])
    return names


def _merged_release_images(release: GuestRelease, current_active: Optional[GuestRelease]) -> dict:
    """Materialize omitted image slots without promoting inherited roles to explicit ones."""
    if current_active is not None and current_active.release_id == release.release_id:
        return {
            role: dict(image) if isinstance(image, dict) else image
            for role, image in (release.images or {}).items()
        }

    merged: dict = {}
    if current_active is not None:
        for role, image in (current_active.images or {}).items():
            inherited = dict(image) if isinstance(image, dict) else image
            if role in {"chute", "storage"} and isinstance(inherited, dict):
                inherited["_inherited"] = True
            merged[role] = inherited
    for role, image in (release.images or {}).items():
        replacement = dict(image) if isinstance(image, dict) else image
        if (
            role in {"chute", "storage"}
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


def _validate_image_provenance(
    release: GuestRelease,
    image_role: str,
    image: dict,
    loaded_by_name: dict,
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
                provenance = verify_provenance_signature(
                    payload,
                    signature,
                    settings.trusted_provenance_public_key_path,
                    cosign_binary=settings.provenance_cosign_binary,
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


async def _validate_l0_bootstrap(db: AsyncSession, release: GuestRelease) -> None:
    """Verify and audit the exact publisher-signed L0 contract before activation."""

    raw = (release.images or {}).get("l0")
    if raw is None:
        raise ReleaseError(
            "A seedless Model-B release must carry a publisher-signed L0 bootstrap manifest."
        )
    try:
        signed = SignedL0BootstrapManifestV1.model_validate(raw.get("bootstrap"))
        digest = verify_signed_l0_manifest(signed, settings.trusted_l0_publisher_keys_path)
    except (L0BootstrapVerificationError, ValueError, TypeError) as exc:
        raise ReleaseError(f"Refusing to activate untrusted L0 bootstrap manifest: {exc}") from exc

    manifest = signed.manifest
    if manifest.tee_type != release.tee_type or manifest.channel != release.channel:
        raise ReleaseError("L0 bootstrap manifest TEE/channel does not match the guest release.")
    if manifest.release_id is not None and manifest.release_id != release.release_id:
        raise ReleaseError("L0 bootstrap manifest release correlation does not match this release.")
    if raw.get("version") != manifest.l0_version:
        raise ReleaseError("L0 version does not match the signed bootstrap manifest.")
    if raw.get("squashfs_sha256") != manifest.squashfs.sha256:
        raise ReleaseError(
            "Required L0 squashfs digest does not match the signed bootstrap manifest."
        )

    latest_generation = (
        await db.execute(
            select(func.max(GuestRelease.l0_manifest_generation)).where(
                GuestRelease.tee_type == release.tee_type,
                GuestRelease.channel == release.channel,
                GuestRelease.release_id != release.release_id,
            )
        )
    ).scalar_one_or_none()
    if latest_generation is not None and manifest.generation <= int(latest_generation):
        raise ReleaseError(
            "L0 bootstrap generation is stale; generations must increase monotonically."
        )
    latest_key_epoch = (
        await db.execute(
            select(func.max(GuestRelease.l0_manifest_key_epoch)).where(
                GuestRelease.tee_type == release.tee_type,
                GuestRelease.channel == release.channel,
                GuestRelease.release_id != release.release_id,
            )
        )
    ).scalar_one_or_none()
    if latest_key_epoch is not None and manifest.key_epoch < int(latest_key_epoch):
        raise ReleaseError("L0 publisher key epoch cannot move backwards.")

    release.l0_manifest = manifest.model_dump(mode="json", exclude_none=True)
    release.l0_manifest_digest = digest
    release.l0_manifest_generation = manifest.generation
    release.l0_manifest_key_id = manifest.key_id
    release.l0_manifest_key_epoch = manifest.key_epoch


async def create_release(db: AsyncSession, req: CreateReleaseRequest) -> GuestRelease:
    """Create a draft release. If req.activate, activate it immediately (subject to the gate)."""
    images: Dict[str, dict] = {}
    if req.chute is not None:
        images["chute"] = _image_to_dict(req.chute)
    if req.storage is not None:
        images["storage"] = _image_to_dict(req.storage)
    if req.l0 is not None:
        images["l0"] = _l0_to_dict(req.l0)
    release = GuestRelease(
        channel=req.channel,
        tee_type=req.tee_type,
        status=RELEASE_STATUS_DRAFT,
        images=images,
        notes=req.notes,
    )
    db.add(release)
    await db.commit()
    await db.refresh(release)
    logger.success(
        f"Created draft guest release {release.release_id} (channel={release.channel} "
        f"tee_type={release.tee_type})"
    )
    if req.activate:
        await activate_release(db, release.release_id)
        await db.refresh(release)
    return release


async def activate_release(db: AsyncSession, release_id: str) -> GuestRelease:
    """Make a release the ACTIVE desired state for its (channel, tee_type).

    GATE: every measurement name the release references MUST already be pinned in
    settings.tee_measurements. Otherwise TDs launched from the new image would fail attestation
    fleet-wide -- so refuse activation until the measurements are pinned (committed yaml / ConfigMap).
    Supersedes the prior active release for the same (channel, tee_type).
    """
    release = await db.get(GuestRelease, release_id)
    if release is None:
        raise ReleaseError(f"Release {release_id} not found")
    # Serialize the supersede/activate transaction for one desired-state slot. The partial unique
    # index is the final invariant; this lock makes concurrent activations deterministic instead of
    # surfacing a late IntegrityError after both callers supersede the prior row.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": f"guest-release:{release.channel}:{release.tee_type}"},
    )
    current_active = await get_active_release(db, release.tee_type, release.channel, lock=True)
    if not isinstance(current_active, GuestRelease):
        current_active = None
    original_images = release.images
    release.images = _merged_release_images(release, current_active)
    try:
        await _validate_l0_bootstrap(db, release)
        if release.tee_type == "tdx" and not (release.images or {}).get("chute"):
            raise ReleaseError(
                "A managed TDX desired state must include a schema-v2 direct-boot chute image; "
                "a first or legacy-partial storage-only release is unschedulable."
            )
        required = _release_measurement_names(release)
        if not required:
            raise ReleaseError(
                "Release references no measurement names; refusing to activate (a release must "
                "declare the pinned measurement its image attests as, or launched TDs cannot be "
                "verified)."
            )
        loaded_by_name = _loaded_measurements_by_name()
        for image_role in ("chute", "storage"):
            image = (release.images or {}).get(image_role)
            if image:
                _validate_image_provenance(release, image_role, image, loaded_by_name)
    except Exception:
        release.images = original_images
        raise

    # Re-validate even an already-active row so legacy/malformed manifests cannot bypass newly
    # required provenance through the idempotent activation path.
    if release.status == RELEASE_STATUS_ACTIVE:
        if release.targets_captured_at is None:
            await _capture_release_targets(db, release)
            await db.commit()
            await db.refresh(release)
        return release

    # Supersede the current active release for this (channel, tee_type).
    await db.execute(
        update(GuestRelease)
        .where(
            GuestRelease.channel == release.channel,
            GuestRelease.tee_type == release.tee_type,
            GuestRelease.status == RELEASE_STATUS_ACTIVE,
            GuestRelease.release_id != release.release_id,
        )
        .values(status=RELEASE_STATUS_SUPERSEDED)
    )
    release.status = RELEASE_STATUS_ACTIVE
    release.activated_at = datetime.now(timezone.utc)
    await _capture_release_targets(db, release)
    await db.commit()
    await db.refresh(release)
    logger.success(
        f"Activated guest release {release.release_id} (channel={release.channel} "
        f"tee_type={release.tee_type}); measurements verified pinned: {sorted(set(required))}"
    )
    return release


async def get_active_release(
    db: AsyncSession,
    tee_type: str,
    channel: str = "stable",
    *,
    lock: bool = False,
) -> Optional[GuestRelease]:
    query = select(GuestRelease).where(
        GuestRelease.tee_type == tee_type,
        GuestRelease.channel == channel,
        GuestRelease.status == RELEASE_STATUS_ACTIVE,
    )
    if lock:
        query = query.with_for_update()
    return (await db.execute(query)).scalar_one_or_none()


async def active_l0_bootstrap(
    db: AsyncSession,
    tee_type: str,
    channel: str,
) -> Optional[SignedL0BootstrapManifestV1]:
    """Return the newest verified bootstrap, including a pre-activation draft.

    Miner tooling must be able to enroll the initial ready host set before guest-release activation
    captures immutable rollout targets.
    """

    releases = (
        (
            await db.execute(
                select(GuestRelease).where(
                    GuestRelease.tee_type == tee_type.strip().lower(),
                    GuestRelease.channel == channel,
                    GuestRelease.status.in_([RELEASE_STATUS_ACTIVE, RELEASE_STATUS_DRAFT]),
                )
            )
        )
        .scalars()
        .all()
    )
    candidates: list[tuple[int, GuestRelease, SignedL0BootstrapManifestV1]] = []
    for release in releases:
        raw = ((release.images or {}).get("l0") or {}).get("bootstrap")
        if raw is None:
            continue
        await _validate_l0_bootstrap(db, release)
        signed = SignedL0BootstrapManifestV1.model_validate(raw)
        candidates.append((signed.manifest.generation, release, signed))
    if not candidates:
        return None
    _generation, _release, signed = max(
        candidates,
        key=lambda item: (item[0], item[1].created_at or datetime.min.replace(tzinfo=timezone.utc)),
    )
    if signed.manifest.tee_type != tee_type.strip().lower() or signed.manifest.channel != channel:
        raise ReleaseError("Draft L0 bootstrap targets another release slot.")
    verify_signed_l0_manifest(
        signed,
        settings.trusted_l0_publisher_keys_path,
    )
    return signed


def release_manifest(release: GuestRelease) -> ReleaseManifest:
    """The host-facing desired state; TD launch authorization is separate and one-use."""
    return ReleaseManifest(
        release_id=release.release_id,
        channel=release.channel,
        tee_type=release.tee_type,
        chute=_image_from_manifest(release.images, "chute"),
        storage=_image_from_manifest(release.images, "storage"),
        l0=_l0_from_manifest(release.images),
    )


def _target_roles_for_host(release: GuestRelease, host: Host) -> List[str]:
    """Release roles this enrolled logical host can actually run."""
    images = release.images or {}
    roles: List[str] = []
    chute = images.get("chute") or {}
    storage = images.get("storage") or {}
    if chute and not chute.get("_inherited") and int(host.capacity or 0) > 0:
        roles.append("chute")
    if storage and not storage.get("_inherited") and bool(getattr(host, "storage_enabled", False)):
        roles.append("storage")
    return roles


def _apply_storage_auto_opt_in(release: GuestRelease, host: Host) -> None:
    """Reserve storage capacity before the immutable role target snapshot is derived.

    A release carrying storage is itself the operator's opt-in intent.  Hosts that have not staged a
    storage image yet still need a storage target/token, and their advertised chute capacity must no
    longer include the TD that will become the always-on storage role.
    """

    storage = (release.images or {}).get("storage") or {}
    if not storage or storage.get("_inherited"):
        return
    if bool(getattr(host, "storage_enabled", False)):
        return
    current = int(host.capacity or 0)
    host.storage_enabled = True
    host.capacity = max(0, current - 1)


async def _capture_release_targets(
    db: AsyncSession,
    release: GuestRelease,
) -> List[GuestReleaseTarget]:
    """Capture an immutable enrolled logical target set exactly once."""
    if release.targets_captured_at is not None:
        return (
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
            Host.provisioning_state == "ready",
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
                    role=role,
                    current_generation=1,
                    current_token_id=f"audit:{target_id}",
                    issued_at=captured_at,
                )
            )
    explicit_roles = {
        role
        for role in ("chute", "storage")
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
    return release_manifest(release)


def _validate_active_release(release: GuestRelease) -> None:
    """Revalidate desired state against the current trust set before serving or dispatching it."""
    raw_l0 = (release.images or {}).get("l0")
    if raw_l0 is not None:
        try:
            signed_l0 = SignedL0BootstrapManifestV1.model_validate(raw_l0.get("bootstrap"))
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
        if (
            l0_manifest.tee_type != release.tee_type
            or l0_manifest.channel != release.channel
            or (l0_manifest.release_id is not None and l0_manifest.release_id != release.release_id)
            or raw_l0.get("version") != l0_manifest.l0_version
            or raw_l0.get("squashfs_sha256") != l0_manifest.squashfs.sha256
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
    if not any(images.get(role) for role in ("chute", "storage")):
        raise ReleaseError(f"Active release {release.release_id} contains no guest images.")
    for role in ("chute", "storage"):
        image = images.get(role)
        if image:
            _validate_image_provenance(release, role, image, loaded_by_name)


async def active_manifest_for_host(
    db: AsyncSession,
    tee_type: str,
    channel: str = "stable",
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
        lock=bool(reissue_roles),
    )
    if release is None:
        return None
    _validate_active_release(release)
    if host_id is None:
        return release_manifest(release)
    host = await db.get(Host, host_id)
    if host is None:
        raise ReleaseError(f"Logical rollout host {host_id} is not enrolled.")
    if miner_hotkey is None or host.miner_hotkey != miner_hotkey:
        raise ReleaseError(f"Logical rollout host {host_id} is owned by another miner.")
    if host.tee_type != release.tee_type or host.release_channel != release.channel:
        raise ReleaseError(
            f"Logical rollout host {host_id} is not enrolled in "
            f"{release.channel}/{release.tee_type}."
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
    _validate_active_release(release)

    l0_spec = (release.images or {}).get("l0") or {}
    l0_version = l0_spec.get("version")
    if reboot_l0 and not l0_version:
        raise ReleaseError("reboot_l0 requested but the release carries no l0 slot.")
    capture_needed = release.targets_captured_at is None
    targets = await _capture_release_targets(db, release)
    if capture_needed:
        await db.commit()
        await db.refresh(release)
    captured_host_ids = {target.host_id for target in targets}
    if host_ids is not None:
        captured_host_ids &= set(host_ids)
    q = select(Host).where(
        Host.tee_type == release.tee_type,
        Host.host_id.in_(captured_host_ids),
    )
    hosts = (await db.execute(q)).scalars().all()

    results = []
    dispatched = 0
    for host in hosts:
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
            command_id = await send_agent_command(
                host.host_id, "upgrade_image", {"manifest": manifest}
            )
            detail = f"upgrade_image dispatched ({command_id})"
            # Opt-in L0 re-netboot: send reboot AFTER the image nudge so the box comes up on the new
            # guest images too. target_l0_version makes an already-updated host skip the reboot.
            if reboot_l0 and (getattr(host, "l0_version", None) != l0_version):
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
        f"Rollout of release {release_id} ({release.tee_type}): dispatched to {dispatched}/{len(hosts)} host(s)"
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
    _validate_active_release(release)

    chute_img = (release.images or {}).get("chute") or {}
    storage_img = (release.images or {}).get("storage") or {}
    if chute_img.get("_inherited"):
        chute_img = {}
    if storage_img.get("_inherited"):
        storage_img = {}
    l0_spec = (release.images or {}).get("l0") or {}
    chute_sha = chute_img.get("sha256")
    storage_sha = storage_img.get("sha256")
    l0_version = l0_spec.get("version")
    chute_names = list(chute_img.get("measurement_names") or [])
    storage_names = list(storage_img.get("measurement_names") or [])
    names_by_role = {
        role: names for role, names in (("chute", chute_names), ("storage", storage_names)) if names
    }
    required_roles = list(names_by_role)
    required_names = [name for names in names_by_role.values() for name in names]

    hosts = (
        (
            await db.execute(
                select(Host).where(
                    Host.tee_type == release.tee_type,
                    Host.release_channel == release.channel,
                )
            )
        )
        .scalars()
        .all()
    )
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
    reservation_by_target = {
        (reservation.host_id, reservation.role): reservation for reservation in reservations
    }

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
        func.row_number()
        .over(
            partition_by=ServerAttestation.server_id,
            order_by=(
                ServerAttestation.created_at.desc(),
                ServerAttestation.attestation_id.desc(),
            ),
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
            )
            .join(latest, latest.c.server_id == Server.server_id)
            .where(
                latest.c.rn == 1,
                latest.c.verification_error.is_(None),
                latest.c.verified_at.is_not(None),
                latest.c.verified_at >= cutoff,
                Server.self_registered.is_(True),
                Server.is_tee.is_(True),
                Server.compute_type == "cpu",
                Server.tee_type == release.tee_type,
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
            "storage" if str(measurement_name or "").startswith("storage-") else "chute"
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
    ) in attested_rows:
        latest_by_server[server.server_id] = (
            server,
            attestation_id,
            measurement_name,
            measurement_version,
            measurement_config_fingerprint_value,
            trust_set_fingerprint,
            verified_at,
        )
        server_role = "storage" if bool(server.storage_role) else "chute"
        measurement_role = (
            "storage" if str(measurement_name or "").startswith("storage-") else "chute"
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
    online_by_host = {host.host_id: await is_agent_online(host.host_id) for host in hosts}
    host_rows = []
    for host in hosts:
        staged = host.staged_images or {}
        staged_chute = (staged.get("chute") or {}).get("sha256")
        staged_storage = (staged.get("storage") or {}).get("sha256")
        chute_ok = (not chute_sha) or staged_chute == chute_sha
        storage_ok = (not storage_sha) or staged_storage == storage_sha
        running_l0 = getattr(host, "l0_version", None)
        l0_matches = None if not l0_version else (running_l0 == l0_version)
        host_rows.append(
            {
                "untrusted_host_id": host.host_id,
                "untrusted_online": online_by_host[host.host_id],
                "untrusted_staged_chute_sha": staged_chute,
                "untrusted_staged_storage_sha": staged_storage,
                "untrusted_stage_matches_release": bool(chute_ok and storage_ok),
                "untrusted_running_l0_version": running_l0,
                "untrusted_l0_matches_release": l0_matches,
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
            fresh_role_health and logical_online and exact_stage and old_process_exit_confirmed
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
        bool(targets)
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
        "required_roles": required_roles,
        "required_chute_measurement_names": chute_names,
        "required_storage_measurement_names": storage_names,
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
        "status": release.status,
        "images": release.images or {},
        "notes": release.notes,
        "created_at": release.created_at.isoformat() if release.created_at else None,
        "activated_at": release.activated_at.isoformat() if release.activated_at else None,
    }
