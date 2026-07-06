"""Fleet image release service: create/activate/rollout/status + the host-facing active manifest.

Desired-state model: for each (channel, tee_type) at most one release is ACTIVE. L0 node-agents
converge to the active release for their tee_type. Activation is gated on the referenced measurement
names already being loaded in settings.tee_measurements, so a release can never point the fleet at an
image whose attestation the validator can't verify.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.releases.schemas import (
    RELEASE_STATUS_ACTIVE,
    RELEASE_STATUS_DRAFT,
    RELEASE_STATUS_SUPERSEDED,
    CreateReleaseRequest,
    GuestRelease,
    ReleaseImage,
    ReleaseL0,
    ReleaseManifest,
)
from api.server.schemas import Host, Server


class ReleaseError(Exception):
    """Raised for release create/activate/rollout errors (mapped to HTTP 4xx by the router)."""


def _loaded_measurement_names() -> set:
    """Names of every measurement currently pinned on the validator (committed yaml + ConfigMap)."""
    return {m.name for m in settings.tee_measurements if m.name}


def _measurement_versions(names: List[str]) -> set:
    """The measurement `version`s for the given pinned measurement `name`s (for convergence counting)."""
    by_name = {m.name: m.version for m in settings.tee_measurements if m.name}
    return {by_name[n] for n in names if n in by_name}


def _release_measurement_names(release: GuestRelease) -> List[str]:
    names: List[str] = []
    for key in ("chute", "storage"):
        img = (release.images or {}).get(key) or {}
        names.extend(img.get("measurement_names") or [])
    return names


def _image_to_dict(img: Optional[ReleaseImage]) -> Optional[dict]:
    if img is None:
        return None
    return {
        "url": img.url,
        "sha256": img.sha256,
        "version": img.version,
        "measurement_names": list(img.measurement_names or []),
    }


def _image_from_manifest(images: dict, key: str) -> Optional[ReleaseImage]:
    raw = (images or {}).get(key)
    if not raw:
        return None
    return ReleaseImage(
        url=raw["url"],
        sha256=raw["sha256"],
        version=raw.get("version"),
        measurement_names=raw.get("measurement_names") or [],
    )


def _l0_to_dict(l0: Optional[ReleaseL0]) -> Optional[dict]:
    if l0 is None:
        return None
    return {"version": l0.version, "squashfs_sha256": l0.squashfs_sha256, "netboot_base_url": l0.netboot_base_url}


def _l0_from_manifest(images: dict) -> Optional[ReleaseL0]:
    raw = (images or {}).get("l0")
    if not raw:
        return None
    return ReleaseL0(
        version=raw["version"],
        squashfs_sha256=raw.get("squashfs_sha256"),
        netboot_base_url=raw.get("netboot_base_url"),
    )


async def create_release(db: AsyncSession, req: CreateReleaseRequest) -> GuestRelease:
    """Create a draft release. If req.activate, activate it immediately (subject to the gate)."""
    images: Dict[str, dict] = {"chute": _image_to_dict(req.chute)}
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
    if release.status == RELEASE_STATUS_ACTIVE:
        return release

    required = _release_measurement_names(release)
    if not required:
        raise ReleaseError(
            "Release references no measurement names; refusing to activate (a release must declare "
            "the pinned measurement its image attests as, or launched TDs cannot be verified)."
        )
    loaded = _loaded_measurement_names()
    missing = sorted(set(required) - loaded)
    if missing:
        raise ReleaseError(
            "Refusing to activate: these measurement names are not pinned on the validator "
            f"(tee_measurements): {missing}. Pin them (committed yaml / ConfigMap) first, or the "
            "fleet would boot an image whose attestation cannot be verified."
        )

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
    await db.commit()
    await db.refresh(release)
    logger.success(
        f"Activated guest release {release.release_id} (channel={release.channel} "
        f"tee_type={release.tee_type}); measurements verified pinned: {sorted(set(required))}"
    )
    return release


async def get_active_release(db: AsyncSession, tee_type: str, channel: str = "stable") -> Optional[GuestRelease]:
    return (
        await db.execute(
            select(GuestRelease).where(
                GuestRelease.tee_type == tee_type,
                GuestRelease.channel == channel,
                GuestRelease.status == RELEASE_STATUS_ACTIVE,
            )
        )
    ).scalar_one_or_none()


def release_manifest(release: GuestRelease) -> ReleaseManifest:
    """The host-facing manifest (release id + chute/storage image entries + optional L0 set)."""
    return ReleaseManifest(
        release_id=release.release_id,
        channel=release.channel,
        tee_type=release.tee_type,
        chute=_image_from_manifest(release.images, "chute"),
        storage=_image_from_manifest(release.images, "storage"),
        l0=_l0_from_manifest(release.images),
    )


async def active_manifest_for_host(
    db: AsyncSession, tee_type: str, channel: str = "stable"
) -> Optional[ReleaseManifest]:
    """The manifest an L0 host of ``tee_type`` should converge to (None if no active release)."""
    if not tee_type:
        return None
    release = await get_active_release(db, tee_type.strip().lower(), channel)
    return release_manifest(release) if release else None


async def rollout_release(
    db: AsyncSession,
    release_id: str,
    host_ids: Optional[List[str]] = None,
    reboot_l0: bool = False,
) -> Dict:
    """Push the active release to online L0 hosts of its tee_type via the upgrade_image command.

    host_ids restricts the rollout to a canary subset. Only hosts of the release's tee_type are
    targeted (a chute/storage image for one TEE is meaningless on the other). Offline hosts are
    skipped here -- they converge on their own via the registration response + periodic poll.

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

    manifest = release_manifest(release).model_dump()
    l0_spec = (release.images or {}).get("l0") or {}
    l0_version = l0_spec.get("version")
    if reboot_l0 and not l0_version:
        raise ReleaseError("reboot_l0 requested but the release carries no l0 slot.")
    q = select(Host).where(Host.tee_type == release.tee_type)
    if host_ids:
        q = q.where(Host.host_id.in_(host_ids))
    hosts = (await db.execute(q)).scalars().all()

    results = []
    dispatched = 0
    for host in hosts:
        if not await is_agent_online(host.host_id):
            results.append({"host_id": host.host_id, "dispatched": False, "detail": "offline (will converge via poll)"})
            continue
        try:
            command_id = await send_agent_command(host.host_id, "upgrade_image", {"manifest": manifest})
            detail = f"upgrade_image dispatched ({command_id})"
            # Opt-in L0 re-netboot: send reboot AFTER the image nudge so the box comes up on the new
            # guest images too. target_l0_version makes an already-updated host skip the reboot.
            if reboot_l0 and (getattr(host, "l0_version", None) != l0_version):
                rid = await send_agent_command(host.host_id, "reboot", {"target_l0_version": l0_version})
                detail += f"; reboot dispatched ({rid}) -> l0 {l0_version}"
            dispatched += 1
            results.append({"host_id": host.host_id, "dispatched": True, "detail": detail})
        except Exception as exc:  # noqa: BLE001 - report per-host, keep rolling out the rest
            results.append({"host_id": host.host_id, "dispatched": False, "detail": f"dispatch failed: {exc}"})
    logger.success(
        f"Rollout of release {release_id} ({release.tee_type}): dispatched to {dispatched}/{len(hosts)} host(s)"
        + (f" (canary: {host_ids})" if host_ids else "")
        + (" +reboot_l0" if reboot_l0 else "")
    )
    return {"release_id": release_id, "dispatched": dispatched, "hosts": results}


async def release_status(db: AsyncSession, release_id: str) -> Dict:
    """Convergence report for a release: per-host staged digests vs the release + servers on it."""
    from api.agent_channel import is_agent_online

    release = await db.get(GuestRelease, release_id)
    if release is None:
        raise ReleaseError(f"Release {release_id} not found")

    chute_img = (release.images or {}).get("chute") or {}
    storage_img = (release.images or {}).get("storage") or {}
    l0_spec = (release.images or {}).get("l0") or {}
    chute_sha = chute_img.get("sha256")
    storage_sha = storage_img.get("sha256")
    l0_version = l0_spec.get("version")

    hosts = (
        await db.execute(select(Host).where(Host.tee_type == release.tee_type))
    ).scalars().all()
    host_rows = []
    for host in hosts:
        staged = host.staged_images or {}
        staged_chute = (staged.get("chute") or {}).get("sha256")
        staged_storage = (staged.get("storage") or {}).get("sha256")
        chute_ok = (not chute_sha) or staged_chute == chute_sha
        storage_ok = (not storage_sha) or staged_storage == storage_sha
        # L0 convergence: the host reports its running /etc/chutes/l0-version; converged when it
        # equals the release's L0 version (None when the release carries no L0 slot).
        running_l0 = getattr(host, "l0_version", None)
        l0_conv = None if not l0_version else (running_l0 == l0_version)
        host_rows.append(
            {
                "host_id": host.host_id,
                "online": await is_agent_online(host.host_id),
                "converged": bool(chute_ok and storage_ok),
                "staged_chute_sha": staged_chute,
                "staged_storage_sha": staged_storage,
                "running_l0_version": running_l0,
                "l0_converged": l0_conv,
            }
        )

    versions = _measurement_versions(_release_measurement_names(release))
    servers_on_release = 0
    if versions:
        servers_on_release = int(
            (
                await db.execute(
                    select(Server)
                    .where(Server.self_registered.is_(True), Server.version.in_(versions))
                )
            )
            .scalars()
            .all()
            .__len__()
        )

    return {
        "release_id": release.release_id,
        "status": release.status,
        "tee_type": release.tee_type,
        "chute_sha": chute_sha,
        "storage_sha": storage_sha,
        "l0_version": l0_version,
        "hosts": host_rows,
        "servers_on_release": servers_on_release,
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
