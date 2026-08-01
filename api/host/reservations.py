"""Durable validator-created, one-use Model-B TD launch reservations."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.database import generate_uuid
from api.host.schemas import (
    GpuHostStorageReadinessV1,
    HostKeyGeneration,
    StorageLaunchIntent,
    TdLaunchReservation,
    TdLaunchReservationClaimsV1,
    TdLaunchReservationClaimsV2,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.releases.schemas import (
    GuestRelease,
    GuestReleaseTarget,
    RELEASE_STATUS_ACTIVE,
)
from api.host.locks import acquire_gpu_lifecycle_lock
from api.server.schemas import Host, Server, ServerAttestation

RESERVATION_LIFETIME_SECONDS = 900


class LaunchReservationError(ValueError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _release_target_digest(
    release: GuestRelease,
    role: str,
    image: dict,
    profile_id: str,
    *,
    host_compute_type: str = "cpu",
    gpu_release_id: Optional[str] = None,
    active_cpu_release_id: Optional[str] = None,
) -> str:
    document = {
        "schema": "chutes.guest-release-target",
        "version": 1,
        "release_id": release.release_id,
        "tee_type": release.tee_type,
        "channel": release.channel,
        "role": role,
        "image_sha256": image["sha256"],
        "image_version": image["version"],
        "profile_id": profile_id,
    }
    if host_compute_type == "gpu":
        document.update(
            {
                "version": 2,
                "host_compute_type": "gpu",
                "gpu_release_id": gpu_release_id,
                "active_cpu_release_id": active_cpu_release_id,
            }
        )
    return canonical_sha256(document)


async def create_launch_reservation(
    db: AsyncSession,
    host: Host,
    *,
    role: str,
    server_id: str,
    process_incarnation: str,
    profile_id: str,
    chute_id: Optional[str] = None,
    job_id: Optional[str] = None,
    container_repository: Optional[str] = None,
    container_manifest_digest: Optional[str] = None,
    storage_intent_id: Optional[str] = None,
    storage_intent_generation: Optional[int] = None,
    source_release_id: Optional[str] = None,
    gpu_release_id: Optional[str] = None,
    active_cpu_release_id: Optional[str] = None,
) -> tuple[TdLaunchReservation, str]:
    """Create and persist one exact reservation before host slot allocation."""

    await acquire_gpu_lifecycle_lock(db)
    if (
        host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.active_key_generation is None
        or host.enrollment_generation is None
        or (
            host.compute_type != "cpu"
            and not (
                host.compute_type == "gpu"
                and role == "storage"
                and source_release_id
                and gpu_release_id
                and active_cpu_release_id
            )
        )
    ):
        raise LaunchReservationError("Logical host is not launch-ready.")
    key = await db.get(HostKeyGeneration, (host.host_id, host.active_key_generation))
    if key is None or key.revoked_at is not None:
        raise LaunchReservationError("Logical host has no active key generation.")
    if role not in {"chute", "storage"}:
        raise LaunchReservationError("Launch reservation role is invalid.")
    if role == "storage" and (not storage_intent_id or storage_intent_generation is None):
        raise LaunchReservationError(
            "Storage launch reservation requires a validator-owned intent claim."
        )
    if role == "chute" and (storage_intent_id is not None or storage_intent_generation is not None):
        raise LaunchReservationError("Chute reservation cannot carry a storage intent.")
    if (role == "chute") != bool(chute_id) or (
        role == "chute"
        and (
            not container_repository
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                container_manifest_digest or "",
            )
        )
    ):
        raise LaunchReservationError("Launch reservation chute binding is invalid.")
    release_query = select(GuestRelease).where(
        GuestRelease.channel == host.release_channel,
        GuestRelease.tee_type == host.tee_type,
        GuestRelease.compute_type == "cpu",
    )
    if host.compute_type == "gpu":
        release_query = release_query.where(GuestRelease.release_id == source_release_id)
    else:
        release_query = release_query.where(GuestRelease.status == RELEASE_STATUS_ACTIVE)
    release = (await db.execute(release_query.with_for_update())).scalar_one_or_none()
    if release is None:
        raise LaunchReservationError("Logical host has no active exact guest release.")
    image = (release.images or {}).get(role) or {}
    if (
        not image.get("sha256")
        or not image.get("version")
        or profile_id not in (image.get("measurement_names") or [])
    ):
        raise LaunchReservationError("Launch profile is not part of the active exact release role.")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"td-launch-reservation:{server_id}"},
    )
    prior_rows = (
        (
            await db.execute(
                select(TdLaunchReservation)
                .where(TdLaunchReservation.server_id == server_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    boot_generation = max((int(item.boot_generation) for item in prior_rows), default=0) + 1
    now = _utcnow()
    reservation_id = generate_uuid()
    token_id = generate_uuid()
    launch_nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    release_target_sha256 = _release_target_digest(
        release,
        role,
        image,
        profile_id,
        host_compute_type=host.compute_type,
        gpu_release_id=gpu_release_id,
        active_cpu_release_id=active_cpu_release_id,
    )
    claims_type = (
        TdLaunchReservationClaimsV2 if host.compute_type == "gpu" else TdLaunchReservationClaimsV1
    )
    claims_kwargs = {}
    if host.compute_type == "gpu":
        claims_kwargs = {
            "host_compute_type": "gpu",
            "gpu_release_id": gpu_release_id,
            "active_cpu_release_id": active_cpu_release_id,
        }
    claims = claims_type(
        reservation_id=reservation_id,
        token_id=token_id,
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        server_id=server_id,
        role=role,
        tee_type=host.tee_type,
        process_incarnation=process_incarnation,
        boot_generation=boot_generation,
        release_id=release.release_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        profile_id=profile_id,
        chute_id=chute_id,
        job_id=job_id,
        container_repository=container_repository,
        container_manifest_digest=container_manifest_digest,
        storage_intent_id=storage_intent_id,
        storage_intent_generation=storage_intent_generation,
        launch_nonce=launch_nonce,
        release_target_sha256=release_target_sha256,
        issued_at=now,
        expires_at=now + timedelta(seconds=RESERVATION_LIFETIME_SECONDS),
        **claims_kwargs,
    )
    claims_sha256 = canonical_sha256(claims)
    token_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    token = f"{reservation_id}.{token_secret}"
    row = TdLaunchReservation(
        reservation_id=reservation_id,
        token_id=token_id,
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        owner_hotkey=host.miner_hotkey,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        server_id=server_id,
        role=role,
        compute_type="cpu",
        claims_version=claims.version,
        host_compute_type=host.compute_type,
        gpu_release_id=gpu_release_id,
        active_cpu_release_id=active_cpu_release_id,
        tee_type=host.tee_type,
        process_incarnation=process_incarnation,
        boot_generation=boot_generation,
        release_id=release.release_id,
        image_sha256=image["sha256"],
        image_version=image["version"],
        profile_id=profile_id,
        chute_id=chute_id,
        job_id=job_id,
        container_repository=container_repository,
        container_manifest_digest=container_manifest_digest,
        storage_intent_id=storage_intent_id,
        storage_intent_generation=storage_intent_generation,
        launch_nonce=launch_nonce,
        release_target_sha256=release_target_sha256,
        claims=claims.model_dump(mode="json", exclude_none=True),
        claims_sha256=claims_sha256,
        issued_at=now,
        expires_at=claims.expires_at,
    )
    db.add(row)
    await db.flush()
    return row, token


async def claim_storage_launch_intent(
    db: AsyncSession,
    host: Host,
) -> tuple[TdLaunchReservation, str]:
    """Atomically turn the one eligible validator-owned intent into a reservation."""

    await acquire_gpu_lifecycle_lock(db)
    if (
        host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or not host.storage_requested
        or host.active_key_generation is None
        or host.compute_type not in {"cpu", "gpu"}
        or (host.compute_type == "gpu" and host.tee_type != "tdx")
    ):
        raise LaunchReservationError("Logical host is not storage-launch eligible.")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"storage-launch-intent:{host.host_id}"},
    )
    intents = (
        (
            await db.execute(
                select(StorageLaunchIntent)
                .where(
                    StorageLaunchIntent.host_id == host.host_id,
                    StorageLaunchIntent.owner_hotkey == host.miner_hotkey,
                    StorageLaunchIntent.tee_type == host.tee_type,
                    StorageLaunchIntent.channel == host.release_channel,
                    StorageLaunchIntent.host_compute_type == host.compute_type,
                    StorageLaunchIntent.state == "active",
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if len(intents) != 1:
        raise LaunchReservationError(
            "Logical host has no unique validator-owned storage launch intent."
        )
    intent = intents[0]
    if host.compute_type == "cpu":
        target = await db.get(GuestReleaseTarget, intent.target_id)
        if (
            target is None
            or target.target_id != intent.target_id
            or target.release_id != intent.release_id
            or target.host_id != host.host_id
            or target.miner_hotkey != host.miner_hotkey
            or target.tee_type != host.tee_type
            or target.compute_type != "cpu"
            or target.role != "storage"
        ):
            raise LaunchReservationError(
                "Storage launch intent no longer matches its immutable target."
            )
    elif (
        intent.target_id is not None
        or not intent.gpu_release_id
        or not intent.active_cpu_release_id
        or not intent.kernel_sha256
        or not intent.initrd_sha256
        or not intent.cmdline_sha256
        or not isinstance(intent.launch_contract, dict)
    ):
        raise LaunchReservationError(
            "GPU-host storage launch intent has incomplete cross-stream identity."
        )
    release = (
        await db.execute(
            select(GuestRelease)
            .where(
                GuestRelease.status == RELEASE_STATUS_ACTIVE,
                GuestRelease.channel == host.release_channel,
                GuestRelease.tee_type == host.tee_type,
                GuestRelease.compute_type == "cpu",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    image = (release.images or {}).get("storage") if release is not None else None
    source_release = (
        await db.get(GuestRelease, intent.release_id) if host.compute_type == "gpu" else release
    )
    source_image = (
        (source_release.images or {}).get("storage") if source_release is not None else None
    )
    active_gpu = None
    source_launch_contract = None
    if host.compute_type == "gpu":
        from api.releases.service import _storage_launch_contract

        if isinstance(source_image, dict):
            try:
                source_launch_contract = _storage_launch_contract(source_image).model_dump(
                    mode="json"
                )
            except Exception as exc:  # release helper normalizes provenance failures
                raise LaunchReservationError(
                    "GPU storage source launch contract is no longer valid."
                ) from exc
        active_gpu = (
            await db.execute(
                select(GuestRelease)
                .where(
                    GuestRelease.status == RELEASE_STATUS_ACTIVE,
                    GuestRelease.channel == host.release_channel,
                    GuestRelease.tee_type == "tdx",
                    GuestRelease.compute_type == "gpu",
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
    if (
        release is None
        or not isinstance(image, dict)
        or image.get("sha256") != intent.image_sha256
        or image.get("version") != intent.image_version
        or intent.profile_id not in (image.get("measurement_names") or [])
        or (
            host.compute_type == "cpu"
            and not image.get("_inherited")
            and target.release_id != release.release_id
        )
        or (
            host.compute_type == "gpu"
            and (
                active_gpu is None
                or active_gpu.release_id != intent.gpu_release_id
                or release.release_id != intent.active_cpu_release_id
                or source_release is None
                or not isinstance(source_image, dict)
                or source_image.get("_inherited")
                or source_image.get("sha256") != intent.image_sha256
                or source_image.get("version") != intent.image_version
                or source_image.get("kernel_sha256") != intent.kernel_sha256
                or source_image.get("initrd_sha256") != intent.initrd_sha256
                or source_image.get("cmdline_sha256") != intent.cmdline_sha256
                or intent.profile_id not in (source_image.get("measurement_names") or [])
                or source_launch_contract != intent.launch_contract
            )
        )
    ):
        raise LaunchReservationError(
            "Storage launch intent does not match the active desired storage image."
        )
    await db.execute(
        update(TdLaunchReservation)
        .where(
            TdLaunchReservation.storage_intent_id == intent.intent_id,
            TdLaunchReservation.consumed_at.is_(None),
            TdLaunchReservation.invalidated_at.is_(None),
        )
        .values(invalidated_at=_utcnow())
    )
    claim_generation = int(intent.claim_generation or 0) + 1
    reservation, token = await create_launch_reservation(
        db,
        host,
        role="storage",
        server_id=intent.server_id,
        process_incarnation=intent.process_incarnation,
        profile_id=intent.profile_id,
        storage_intent_id=intent.intent_id,
        storage_intent_generation=claim_generation,
        source_release_id=(intent.release_id if host.compute_type == "gpu" else None),
        gpu_release_id=(intent.gpu_release_id if host.compute_type == "gpu" else None),
        active_cpu_release_id=(
            intent.active_cpu_release_id if host.compute_type == "gpu" else None
        ),
    )
    now = _utcnow()
    intent.claim_generation = claim_generation
    intent.last_claimed_at = now
    reservation.handed_to_host_at = now
    await db.flush()
    return reservation, token


async def observe_gpu_storage_liveness(
    db: AsyncSession,
    host_id: str,
) -> set[str]:
    """Observe untrusted Redis health before lifecycle authority is locked."""

    server_ids = list(
        (
            await db.execute(
                select(StorageLaunchIntent.server_id).where(
                    StorageLaunchIntent.host_id == host_id,
                    StorageLaunchIntent.host_compute_type == "gpu",
                    StorageLaunchIntent.state == "active",
                )
            )
        )
        .scalars()
        .all()
    )
    from api.storage.service import _live_storage_ids

    return await _live_storage_ids(db, sorted(set(server_ids)))


async def gpu_host_storage_readiness(
    db: AsyncSession,
    host: Host,
    *,
    include_allocation: bool = True,
    observed_live_storage_ids: Optional[set[str]] = None,
) -> GpuHostStorageReadinessV1:
    """Derive schedulability from current storage authority, quote, incarnation, and liveness."""

    if host.compute_type != "gpu" or host.tee_type != "tdx" or not host.storage_enabled:
        return GpuHostStorageReadinessV1(
            host_id=host.host_id,
            trusted_storage_ready=False,
            trusted_schedulable=False,
            reason="host_is_not_a_storage_enabled_tdx_gpu_launcher",
        )

    intent = (
        await db.execute(
            select(StorageLaunchIntent).where(
                StorageLaunchIntent.host_id == host.host_id,
                StorageLaunchIntent.owner_hotkey == host.miner_hotkey,
                StorageLaunchIntent.tee_type == host.tee_type,
                StorageLaunchIntent.channel == host.release_channel,
                StorageLaunchIntent.host_compute_type == "gpu",
                StorageLaunchIntent.state == "active",
            )
        )
    ).scalar_one_or_none()
    base = {
        "host_id": host.host_id,
        "trusted_storage_ready": False,
        "trusted_schedulable": False,
        "gpu_release_id": getattr(intent, "gpu_release_id", None),
        "active_cpu_release_id": getattr(intent, "active_cpu_release_id", None),
        "source_storage_release_id": getattr(intent, "release_id", None),
        "storage_intent_id": getattr(intent, "intent_id", None),
        "storage_intent_generation": getattr(intent, "claim_generation", None),
        "storage_server_id": getattr(intent, "server_id", None),
    }
    if intent is None:
        return GpuHostStorageReadinessV1(
            **base,
            reason="storage_intent_missing",
        )
    if (
        intent.owner_hotkey != host.miner_hotkey
        or intent.tee_type != host.tee_type
        or intent.channel != host.release_channel
        or intent.host_compute_type != host.compute_type
    ):
        return GpuHostStorageReadinessV1(
            **base,
            reason="storage_intent_host_identity_stale",
        )

    active_cpu = await db.get(GuestRelease, intent.active_cpu_release_id)
    active_gpu = await db.get(GuestRelease, intent.gpu_release_id)
    source = await db.get(GuestRelease, intent.release_id)
    active_storage = (active_cpu.images or {}).get("storage") if active_cpu is not None else None
    source_storage = (source.images or {}).get("storage") if source is not None else None
    source_launch_contract = None
    gpu_l0_closure = None
    if isinstance(source_storage, dict) and active_gpu is not None:
        from api.releases.service import (
            _storage_launch_contract,
            _verify_l0_release_contract,
        )

        try:
            source_launch_contract = _storage_launch_contract(source_storage).model_dump(
                mode="json"
            )
            signed_l0, _digest = _verify_l0_release_contract(
                active_gpu,
                allow_expired=True,
            )
            gpu_l0_closure = signed_l0.manifest.storage_closure
        except Exception:
            source_launch_contract = None
            gpu_l0_closure = None
    if (
        active_cpu is None
        or active_cpu.status != RELEASE_STATUS_ACTIVE
        or active_cpu.compute_type != "cpu"
        or active_cpu.tee_type != "tdx"
        or active_cpu.channel != host.release_channel
        or active_gpu is None
        or active_gpu.status != RELEASE_STATUS_ACTIVE
        or active_gpu.compute_type != "gpu"
        or active_gpu.tee_type != "tdx"
        or active_gpu.channel != host.release_channel
        or source is None
        or source.compute_type != "cpu"
        or not isinstance(active_storage, dict)
        or not isinstance(source_storage, dict)
        or source_storage.get("_inherited")
        or active_storage.get("sha256") != intent.image_sha256
        or active_storage.get("version") != intent.image_version
        or source_storage.get("sha256") != intent.image_sha256
        or source_storage.get("version") != intent.image_version
        or source_storage.get("kernel_sha256") != intent.kernel_sha256
        or source_storage.get("initrd_sha256") != intent.initrd_sha256
        or source_storage.get("cmdline_sha256") != intent.cmdline_sha256
        or active_storage.get("kernel_sha256") != intent.kernel_sha256
        or active_storage.get("initrd_sha256") != intent.initrd_sha256
        or active_storage.get("cmdline_sha256") != intent.cmdline_sha256
        or source_launch_contract != intent.launch_contract
        or gpu_l0_closure is None
        or gpu_l0_closure.source_release_id != intent.release_id
        or gpu_l0_closure.image_sha256 != intent.image_sha256
        or gpu_l0_closure.image_version != intent.image_version
        or gpu_l0_closure.kernel_sha256 != intent.kernel_sha256
        or gpu_l0_closure.initrd_sha256 != intent.initrd_sha256
        or gpu_l0_closure.cmdline_sha256 != intent.cmdline_sha256
        or gpu_l0_closure.launch_contract.model_dump(mode="json") != intent.launch_contract
        or intent.profile_id not in (source_storage.get("measurement_names") or [])
        or intent.profile_id not in gpu_l0_closure.measurement_names
    ):
        return GpuHostStorageReadinessV1(
            **base,
            reason="storage_intent_release_identity_stale",
        )

    reservation = (
        await db.execute(
            select(TdLaunchReservation)
            .where(
                TdLaunchReservation.storage_intent_id == intent.intent_id,
                TdLaunchReservation.storage_intent_generation == intent.claim_generation,
                TdLaunchReservation.claims_version == 2,
                TdLaunchReservation.host_compute_type == "gpu",
                TdLaunchReservation.invalidated_at.is_(None),
            )
            .order_by(
                TdLaunchReservation.issued_at.desc(),
                TdLaunchReservation.reservation_id.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if reservation is None or reservation.consumed_at is None:
        return GpuHostStorageReadinessV1(
            **base,
            storage_reservation_id=(
                reservation.reservation_id if reservation is not None else None
            ),
            reason="current_storage_reservation_not_consumed",
        )

    server = await db.get(Server, intent.server_id)
    latest = (
        await db.execute(
            select(ServerAttestation)
            .where(ServerAttestation.server_id == intent.server_id)
            .order_by(ServerAttestation.attempt_sequence.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    try:
        measurements = settings.tee_measurements
        config = next(item for item in measurements if item.name == intent.profile_id)
        config_fingerprint = getattr(
            config, "config_fingerprint", None
        ) or measurement_config_fingerprint(config)
        trust_fingerprint = measurement_trust_set_fingerprint(measurements)
    except (StopIteration, ValueError, TypeError):
        config = None
        config_fingerprint = None
        trust_fingerprint = None
    cutoff = _utcnow() - timedelta(seconds=settings.release_attestation_max_age_seconds)
    exact_attestation = bool(
        server is not None
        and latest is not None
        and config is not None
        and latest.verification_error is None
        and latest.verified_at is not None
        and latest.verified_at >= cutoff
        and latest.verified_at >= reservation.issued_at
        and latest.measurement_name == intent.profile_id
        and latest.measurement_version == config.version
        and latest.measurement_config_fingerprint == config_fingerprint
        and latest.trust_set_fingerprint == trust_fingerprint
        and server.server_id == intent.server_id
        and server.host_id == host.host_id
        and server.miner_hotkey == host.miner_hotkey
        and server.compute_type == "cpu"
        and server.tee_type == "tdx"
        and server.storage_role is True
        and server.launch_reservation_id == reservation.reservation_id
        and server.launch_boot_generation == reservation.boot_generation
        and server.measurement_name == intent.profile_id
        and server.measurement_config_fingerprint == config_fingerprint
        and server.trust_set_fingerprint == trust_fingerprint
        and getattr(config, "image_sha256", None) == intent.image_sha256
        and (server.attested_cert_pubkey_hash or "").lower()
        == (reservation.consumed_cert_pubkey_hash or "").lower()
    )
    if not exact_attestation:
        return GpuHostStorageReadinessV1(
            **base,
            storage_reservation_id=reservation.reservation_id,
            storage_incarnation=getattr(server, "storage_incarnation", None),
            reason="fresh_exact_storage_attestation_missing",
        )

    incarnation_current = bool(
        server.storage_incarnation
        and server.storage_incarnation_announced_at is not None
        and server.storage_incarnation_announced_at >= reservation.consumed_at
    )
    if not incarnation_current:
        return GpuHostStorageReadinessV1(
            **base,
            storage_reservation_id=reservation.reservation_id,
            storage_incarnation=server.storage_incarnation,
            reason="storage_incarnation_not_current",
        )

    if observed_live_storage_ids is None:
        observed_live_storage_ids = await observe_gpu_storage_liveness(
            db,
            host.host_id,
        )
    live = intent.server_id in observed_live_storage_ids
    if not live:
        return GpuHostStorageReadinessV1(
            **base,
            storage_reservation_id=reservation.reservation_id,
            storage_incarnation=server.storage_incarnation,
            reason="storage_health_not_fresh",
        )
    allocation_available = False
    if include_allocation:
        from api.host.gpu_allocations import gpu_group_available

        allocation_available = await gpu_group_available(db, host)
    return GpuHostStorageReadinessV1(
        **{
            **base,
            "trusted_storage_ready": True,
            "control_channel_eligible": True,
            # Allocation is validator-owned, but initial topology still originates as
            # logical-host telemetry. Runtime TDX/NVIDIA evidence is a later gate.
            "trusted_schedulable": False,
            "allocation_group_available": allocation_available,
        },
        storage_reservation_id=reservation.reservation_id,
        storage_incarnation=server.storage_incarnation,
        reason=(
            "storage_ready_gpu_group_available_evidence_pending"
            if allocation_available
            else "storage_ready_gpu_group_unavailable"
        ),
    )


def _parse_token(token: str) -> tuple[str, str]:
    try:
        reservation_id, secret = token.split(".", 1)
        raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    except (TypeError, ValueError) as exc:
        raise LaunchReservationError("Launch reservation is malformed.") from exc
    if not reservation_id or len(raw) != 32:
        raise LaunchReservationError("Launch reservation is malformed.")
    return reservation_id, hashlib.sha256(token.encode("ascii")).hexdigest()


async def resolve_launch_reservation(
    db: AsyncSession,
    token: str,
    commitment: TdQuoteCommitmentV1,
    *,
    allow_consumed_for_publication: bool = False,
) -> tuple[TdLaunchReservation, TdLaunchReservationClaimsV1]:
    await acquire_gpu_lifecycle_lock(db)
    reservation_id, token_hash = _parse_token(token)
    identity = (
        await db.execute(
            select(
                TdLaunchReservation.storage_intent_id,
                TdLaunchReservation.release_id,
            ).where(
                TdLaunchReservation.reservation_id == reservation_id,
            )
        )
    ).one_or_none()
    if identity is None:
        raise LaunchReservationError("Launch reservation is unknown.")
    release = (
        await db.execute(
            select(GuestRelease)
            .where(GuestRelease.release_id == identity.release_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    storage_intent_id = identity.storage_intent_id
    intent = None
    if storage_intent_id is not None:
        intent = (
            await db.execute(
                select(StorageLaunchIntent)
                .where(StorageLaunchIntent.intent_id == storage_intent_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
    row = (
        await db.execute(
            select(TdLaunchReservation)
            .where(TdLaunchReservation.reservation_id == reservation_id)
            .execution_options(populate_existing=True)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _utcnow()
    if row is None or not secrets.compare_digest(row.token_hash, token_hash):
        raise LaunchReservationError(
            "Launch reservation is unknown, expired, invalidated, or consumed."
        )
    if row.consumed_at is not None and not allow_consumed_for_publication:
        raise LaunchReservationError(
            "Launch reservation is unknown, expired, invalidated, or consumed."
        )
    if row.consumed_at is None and (row.invalidated_at is not None or row.expires_at <= now):
        raise LaunchReservationError(
            "Launch reservation is unknown, expired, invalidated, or consumed."
        )
    claims_type = (
        TdLaunchReservationClaimsV2
        if int(row.claims_version or 1) == 2
        else TdLaunchReservationClaimsV1
    )
    claims = claims_type.model_validate(row.claims)
    if (
        row.reservation_id != claims.reservation_id
        or row.token_id != claims.token_id
        or row.host_id != claims.host_id
        or row.owner_hotkey != claims.owner_hotkey
        or row.server_id != claims.server_id
        or row.boot_generation != claims.boot_generation
        or row.release_target_sha256 != claims.release_target_sha256
        or row.host_key_generation != claims.host_key_generation
        or row.image_sha256 != claims.image_sha256
        or row.profile_id != claims.profile_id
        or row.chute_id != claims.chute_id
        or row.job_id != claims.job_id
        or row.container_repository != claims.container_repository
        or row.container_manifest_digest != claims.container_manifest_digest
        or row.storage_intent_id != claims.storage_intent_id
        or row.storage_intent_generation != claims.storage_intent_generation
        or int(row.claims_version or 1) != claims.version
        or (row.host_compute_type or "cpu") != getattr(claims, "host_compute_type", "cpu")
        or row.gpu_release_id != getattr(claims, "gpu_release_id", None)
        or row.active_cpu_release_id != getattr(claims, "active_cpu_release_id", None)
        or row.claims_sha256 != canonical_sha256(claims)
    ):
        raise LaunchReservationError(
            "Launch reservation durable row does not match its canonical claims."
        )
    expected = {
        "reservation_sha256": row.claims_sha256,
        "launch_nonce": claims.launch_nonce,
        "release_target_sha256": claims.release_target_sha256,
        "boot_generation": claims.boot_generation,
    }
    if any(getattr(commitment, name) != value for name, value in expected.items()):
        raise LaunchReservationError("TD quote commitment does not match the launch reservation.")
    if row.consumed_at is not None:
        # Exact committed response replay authenticates immutable reservation/token/commitment
        # identity above. Later release, host-key, intent, expiry, or revocation transitions must
        # not strand a registration whose success transaction already committed.
        return row, claims
    if claims.storage_intent_id is not None:
        if (
            intent is None
            or storage_intent_id != claims.storage_intent_id
            or intent.state != "active"
            or intent.claim_generation != claims.storage_intent_generation
            or intent.host_id != claims.host_id
            or intent.owner_hotkey != claims.owner_hotkey
            or intent.server_id != claims.server_id
            or intent.process_incarnation != claims.process_incarnation
            or intent.release_id != claims.release_id
            or intent.profile_id != claims.profile_id
            or intent.image_sha256 != claims.image_sha256
            or intent.image_version != claims.image_version
        ):
            raise LaunchReservationError(
                "Storage launch intent is superseded, stale, or no longer matches its claim generation."
            )
        if isinstance(claims, TdLaunchReservationClaimsV2) and (
            intent.host_compute_type != "gpu"
            or intent.gpu_release_id != claims.gpu_release_id
            or intent.active_cpu_release_id != claims.active_cpu_release_id
        ):
            raise LaunchReservationError(
                "GPU storage launch intent no longer matches its composed release identities."
            )
    image = (release.images or {}).get(row.role) if release is not None else None
    release_valid = bool(
        release is not None
        and release.tee_type == claims.tee_type
        and not isinstance(image, type(None))
        and isinstance(image, dict)
        and image.get("sha256") == claims.image_sha256
        and image.get("version") == claims.image_version
        and claims.profile_id in (image.get("measurement_names") or [])
    )
    if isinstance(claims, TdLaunchReservationClaimsV2):
        active_cpu = await db.get(GuestRelease, claims.active_cpu_release_id)
        active_gpu = await db.get(GuestRelease, claims.gpu_release_id)
        active_storage = (
            (active_cpu.images or {}).get("storage") if active_cpu is not None else None
        )
        source_contract = None
        gpu_l0_closure = None
        if isinstance(image, dict):
            from api.releases.service import (
                _storage_launch_contract,
                _verify_l0_release_contract,
            )

            try:
                source_contract = _storage_launch_contract(image).model_dump(mode="json")
                if active_gpu is not None:
                    signed_l0, _digest = _verify_l0_release_contract(
                        active_gpu,
                        allow_expired=True,
                    )
                    gpu_l0_closure = signed_l0.manifest.storage_closure
            except Exception:
                source_contract = None
                gpu_l0_closure = None
        release_valid = bool(
            release_valid
            and release.release_id == claims.release_id
            and release.compute_type == "cpu"
            and active_cpu is not None
            and active_cpu.status == RELEASE_STATUS_ACTIVE
            and active_cpu.channel == release.channel
            and active_cpu.tee_type == "tdx"
            and active_cpu.compute_type == "cpu"
            and isinstance(active_storage, dict)
            and active_storage.get("sha256") == claims.image_sha256
            and active_storage.get("version") == claims.image_version
            and claims.profile_id in (active_storage.get("measurement_names") or [])
            and intent is not None
            and image.get("kernel_sha256") == intent.kernel_sha256
            and image.get("initrd_sha256") == intent.initrd_sha256
            and image.get("cmdline_sha256") == intent.cmdline_sha256
            and active_storage.get("kernel_sha256") == intent.kernel_sha256
            and active_storage.get("initrd_sha256") == intent.initrd_sha256
            and active_storage.get("cmdline_sha256") == intent.cmdline_sha256
            and source_contract == intent.launch_contract
            and gpu_l0_closure is not None
            and gpu_l0_closure.source_release_id == claims.release_id
            and gpu_l0_closure.image_sha256 == claims.image_sha256
            and gpu_l0_closure.image_version == claims.image_version
            and gpu_l0_closure.kernel_sha256 == intent.kernel_sha256
            and gpu_l0_closure.initrd_sha256 == intent.initrd_sha256
            and gpu_l0_closure.cmdline_sha256 == intent.cmdline_sha256
            and claims.profile_id in gpu_l0_closure.measurement_names
            and gpu_l0_closure.launch_contract.model_dump(mode="json") == intent.launch_contract
            and active_gpu is not None
            and active_gpu.status == RELEASE_STATUS_ACTIVE
            and active_gpu.channel == release.channel
            and active_gpu.tee_type == "tdx"
            and active_gpu.compute_type == "gpu"
        )
    else:
        release_valid = bool(release_valid and release.status == RELEASE_STATUS_ACTIVE)
    if not release_valid:
        raise LaunchReservationError(
            "Launch reservation no longer names the active exact release target."
        )
    host = await db.get(Host, row.host_id)
    key = await db.get(HostKeyGeneration, (row.host_id, row.host_key_generation))
    if (
        host is None
        or key is None
        or host.provisioning_state != "ready"
        or host.identity_durable_at is None
        or host.release_channel != release.channel
        or host.compute_type != row.host_compute_type
        or host.active_key_generation != row.host_key_generation
        or key.revoked_at is not None
    ):
        raise LaunchReservationError("Launch reservation host-key generation is no longer active.")
    return row, claims


def reservation_bound_attestation_nonce(request_nonce: str, commitment: TdQuoteCommitmentV1) -> str:
    try:
        request_nonce_bytes = bytes.fromhex(request_nonce)
    except ValueError as exc:
        raise LaunchReservationError("CPU registration nonce is malformed.") from exc
    return hashlib.sha256(
        request_nonce_bytes + bytes.fromhex(commitment.report_data_nonce())
    ).hexdigest()


def consume_launch_reservation(
    reservation: TdLaunchReservation,
    *,
    attestation_id: str,
    cert_pubkey_hash: str,
    registration_response_bytes: str,
    registration_response_sha256: str,
) -> None:
    if reservation.consumed_at is not None or reservation.invalidated_at is not None:
        raise LaunchReservationError("Launch reservation is no longer consumable.")
    try:
        encoded_response = registration_response_bytes.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise LaunchReservationError(
            "CPU registration response bytes are not canonical ASCII."
        ) from exc
    if (
        not encoded_response
        or not re.fullmatch(r"[0-9a-f]{64}", registration_response_sha256 or "")
        or not secrets.compare_digest(
            hashlib.sha256(encoded_response).hexdigest(),
            registration_response_sha256,
        )
    ):
        raise LaunchReservationError(
            "CPU registration response bytes failed their integrity commitment."
        )
    reservation.consumed_at = _utcnow()
    reservation.consumed_attestation_id = attestation_id
    reservation.consumed_cert_pubkey_hash = cert_pubkey_hash.lower()
    reservation.registration_response_bytes = registration_response_bytes
    reservation.registration_response_sha256 = registration_response_sha256
