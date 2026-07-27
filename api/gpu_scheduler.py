"""Validator-owned scheduler for reservation-attested platform GPU workloads."""

from __future__ import annotations

import api.logging_bootstrap  # noqa: F401

import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException
from loguru import logger
from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.orm import joinedload

import api.database.orms  # noqa: F401
from api.agent_channel import (
    is_agent_online,
    send_agent_command,
    send_gpu_reservation_teardown,
)
from api.chute.schemas import Chute, NodeSelector
from api.config import settings
from api.database import engine, get_session
from api.host.gpu_allocations import (
    GpuAllocationError,
    _latest_gpu_inventory_matches_group,
    _preverify_active_gpu_release,
    _expire_locked_reservations,
    _locked_reservation_group,
    gpu_reservation_token,
    quarantine_gpu_reservation_control_plane,
    record_gpu_command_dispatch,
    reserve_gpu_group,
    _trusted_platform_workload,
)
from api.host.locks import (
    acquire_gpu_lifecycle_lock,
    assert_gpu_external_work_allowed,
)
from api.host.reservations import (
    gpu_host_storage_readiness,
    observe_gpu_storage_liveness,
)
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    GpuPlatformReservationRequestV1,
)
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import create_launch_jwt_v2
from api.job.schemas import Job
from api.log import install_asyncio_exception_handler
from api.metagraph import MetagraphNode
from api.releases.schemas import GuestRelease, RELEASE_STATUS_ACTIVE
from api.server.gpu_sessions import (
    _current_attestation,
    _latest_attestation_attempt,
    require_completed_gpu_registration,
)
from api.server.schemas import Host, Server
from api.storage.service import ensure_default_volume_binding
from api.util import semcomp

REQUIRED_GPU_SCHEMA_VERSION = "20260726121000"
SCHEMA_WAIT_SECONDS = 2
SCHEDULER_INTERVAL_SECONDS = 15
SCHEDULER_LOCK_KEY = "gpu_platform_scheduler:lock"
SCHEDULER_LOCK_TTL_SECONDS = 120
_COMPARE_AND_DELETE_LOCK = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)
GPU_INVENTORY_MAX_AGE_SECONDS = 180
LAUNCH_RETRY_SECONDS = 45
TEARDOWN_RETRY_SECONDS = 45
HOST_LOSS_GRACE_SECONDS = 180
ACTIVATION_TIMEOUT_SECONDS = 900
CLAIMED_LAUNCH_TIMEOUT_SECONDS = 900
DEFAULT_GPU_DISK_GB = 10
_ACTIVE_RESERVATION_STATES = {
    "reserved",
    "claimed",
    "launching",
    "running",
    "resetting",
    "quarantined",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _chute_image_ref(chute: Chute) -> str:
    image = f"{chute.image.user.username}/{chute.image.name}:{chute.image.tag}".lower()
    if chute.image.patch_version not in (None, "initial"):
        image += f"-{chute.image.patch_version}"
    return image


async def _container_intent(session, chute: Chute) -> tuple[str, str] | None:
    assert_gpu_external_work_allowed(session, "registry image digest resolution")
    repository = _chute_image_ref(chute).rsplit(":", 1)[0]
    try:
        from api.image.forge import get_image_digest

        digest = await get_image_digest(
            f"{settings.registry_host}/{_chute_image_ref(chute)}"
        )
    except Exception as exc:  # noqa: BLE001 - placement fails closed
        logger.warning(
            f"Could not resolve exact GPU container intent for {chute.chute_id}: {exc}"
        )
        return None
    return repository, digest


async def _target_count(session, chute_id: str) -> int:
    assert_gpu_external_work_allowed(session, "GPU target scale Redis lookup")
    value = await settings.redis_client.get(f"scale:{chute_id}")
    return max(int(value) if value else 0, 1)


def _job_ports(chute: Chute, method: str) -> list[dict]:
    for definition in chute.jobs or []:
        if definition.get("name") == method:
            return [
                {
                    "port": int(port["port"]),
                    "proto": str(port.get("proto") or "tcp"),
                }
                for port in (definition.get("ports") or [])
                if port.get("port")
            ]
    return []


async def acquire_gpu_workload_lock(
    session,
    chute_id: str,
    job_id: Optional[str],
) -> None:
    """Serialize platform and miner selection for one logical demand slot."""

    await acquire_gpu_lifecycle_lock(session)
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"gpu-workload:{chute_id}:{job_id or 'cord'}"},
    )


def _platform_gpu_selector(chute: Chute, job: Optional[Job] = None) -> NodeSelector:
    selector = NodeSelector(
        **(
            job.node_selector
            if job is not None and job.node_selector
            else chute.node_selector
        )
    )
    if (
        not chute.tee
        or chute.disabled
        or selector.compute_type != "gpu"
        or chute.image is None
        or chute.image.compute_type != "gpu"
    ):
        raise GpuAllocationError("Workload is not an enabled TEE GPU chute.")
    if not selector.supported_gpus:
        raise GpuAllocationError("GPU selector has no supported device identity.")
    return selector


def group_matches_selector(
    group: GpuAllocationGroup,
    selector: NodeSelector,
) -> bool:
    """Match only one exact homogeneous signed-profile allocation group."""

    allowed = set(selector.supported_gpus)
    identifiers = set(group.gpu_identifiers or [])
    requested_profile = getattr(selector, "gpu_profile_id", None)
    requested_topology = getattr(selector, "gpu_topology_fingerprint", None)
    return bool(
        group.state == "available"
        and group.management_mode is None
        and group.reservation_id is None
        and group.gpu_count == selector.gpu_count
        and group.vram_mib >= int(selector.min_vram_gb_per_gpu or 0) * 1024
        and len(identifiers) == 1
        and identifiers.issubset(allowed)
        and not any(identifier.startswith("b300") for identifier in identifiers)
        and not str(group.model or "").upper().startswith("B300")
        and (requested_profile is None or group.profile_id == requested_profile)
        and (
            requested_topology is None
            or group.topology_fingerprint == requested_topology
        )
    )


def inventory_budget_matches(
    report: GpuInventoryReportV1,
    *,
    required_disk_mib: int,
) -> bool:
    resources = report.resources
    return bool(
        resources.gpu_scratch_disk_mib >= required_disk_mib
        and resources.disk_allocation_shortfall_mib <= resources.data_disk_free_mib
        and resources.storage_vcpus + resources.l0_reserved_vcpus
        < resources.logical_cpus
        and resources.storage_memory_mib
        + resources.storage_overhead_mib
        + resources.gpu_overhead_mib
        + resources.l0_reserved_memory_mib
        < resources.memory_mib
    )


async def _demand_count(
    session,
    chute: Chute,
    job: Optional[Job],
) -> int:
    job_condition = (
        LaunchConfig.job_id == job.job_id
        if job is not None
        else LaunchConfig.job_id.is_(None)
    )
    instance_job_condition = (
        LaunchConfig.job_id == job.job_id
        if job is not None
        else LaunchConfig.job_id.is_(None)
    )
    instance_count = int(
        (
            await session.execute(
                select(func.count(Instance.instance_id))
                .join(LaunchConfig, LaunchConfig.config_id == Instance.config_id)
                .where(
                    Instance.chute_id == chute.chute_id,
                    Instance.version == chute.version,
                    instance_job_condition,
                    or_(
                        Instance.gpu_management_mode.is_(None),
                        Instance.gpu_management_mode != "platform",
                        Instance.stop_billing_at.is_(None),
                        Instance.stop_billing_at > func.now(),
                    ),
                )
            )
        ).scalar()
        or 0
    )
    pending_config_count = int(
        (
            await session.execute(
                select(func.count(LaunchConfig.config_id)).where(
                    LaunchConfig.chute_id == chute.chute_id,
                    job_condition,
                    LaunchConfig.failed_at.is_(None),
                    LaunchConfig.completed_at.is_(None),
                    LaunchConfig.verification_error.is_(None),
                    ~exists(
                        select(GpuLaunchReservation.reservation_id).where(
                            GpuLaunchReservation.reservation_id
                            == LaunchConfig.gpu_launch_reservation_id,
                            GpuLaunchReservation.state.in_(
                                {"quarantined", "resetting"}
                            ),
                        )
                    ),
                    ~exists(
                        select(Instance.instance_id).where(
                            Instance.config_id == LaunchConfig.config_id
                        )
                    ),
                )
            )
        ).scalar()
        or 0
    )
    reservation_job_condition = (
        GpuLaunchReservation.job_id == job.job_id
        if job is not None
        else GpuLaunchReservation.job_id.is_(None)
    )
    reservation_count = int(
        (
            await session.execute(
                select(func.count(GpuLaunchReservation.reservation_id)).where(
                    GpuLaunchReservation.management_mode == "platform",
                    GpuLaunchReservation.chute_id == chute.chute_id,
                    reservation_job_condition,
                    GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                    or_(
                        GpuLaunchReservation.state.in_({"quarantined", "resetting"}),
                        ~exists(
                            select(LaunchConfig.config_id).where(
                                LaunchConfig.gpu_launch_reservation_id
                                == GpuLaunchReservation.reservation_id
                            )
                        ),
                    ),
                )
            )
        ).scalar()
        or 0
    )
    return instance_count + pending_config_count + reservation_count


async def _candidate_groups(
    session,
    selector: NodeSelector,
    *,
    required_disk_mib: int,
):
    cutoff = _utcnow() - timedelta(seconds=GPU_INVENTORY_MAX_AGE_SECONDS)
    rows = (
        await session.execute(
            select(GpuAllocationGroup, Host, GpuInventoryReport)
            .join(Host, Host.host_id == GpuAllocationGroup.host_id)
            .join(
                GpuInventoryReport,
                and_(
                    GpuInventoryReport.host_id == Host.host_id,
                    GpuInventoryReport.host_key_generation
                    == Host.active_key_generation,
                    GpuInventoryReport.host_boot_generation
                    == Host.boot_generation,
                    GpuInventoryReport.report_generation
                    == Host.gpu_inventory_report_generation,
                ),
            )
            .where(
                GpuAllocationGroup.state == "available",
                GpuAllocationGroup.management_mode.is_(None),
                GpuAllocationGroup.reservation_id.is_(None),
                GpuAllocationGroup.gpu_count == selector.gpu_count,
                GpuAllocationGroup.vram_mib
                >= int(selector.min_vram_gb_per_gpu or 0) * 1024,
                Host.compute_type == "gpu",
                Host.tee_type == "tdx",
                Host.provisioning_state == "ready",
                Host.identity_durable_at.is_not(None),
                Host.storage_enabled.is_(True),
                Host.boot_generation > 0,
                Host.gpu_inventory_reconciled_at.is_not(None),
                Host.gpu_inventory_reconciled_at >= cutoff,
                Host.active_key_generation == GpuAllocationGroup.host_key_generation,
                Host.boot_generation == GpuAllocationGroup.host_boot_generation,
            )
            .order_by(
                GpuAllocationGroup.vram_mib,
                GpuAllocationGroup.profile_id,
                GpuAllocationGroup.allocation_group_id,
            )
        )
    ).all()
    candidates = []
    for group, host, report in rows:
        if not group_matches_selector(group, selector):
            continue
        if not _latest_gpu_inventory_matches_group(
            host,
            group,
            report,
            require_group_report_link=False,
        ):
            continue
        try:
            report_claims = GpuInventoryReportV1.model_validate(report.claims)
        except ValueError:
            report_claims = None
        if report_claims is None or not inventory_budget_matches(
            report_claims,
            required_disk_mib=required_disk_mib,
        ):
            continue
        candidates.append((group, host, report))
    return candidates


async def _place_workload(
    chute: Chute,
    *,
    job: Optional[Job] = None,
) -> bool:
    # Scale, registry closure, agent liveness, and storage liveness are all
    # preflight observations. The lifecycle transaction below revalidates the
    # authoritative database rows before reserving anything.
    async with get_session(readonly=True) as scale_session:
        target = (
            1 if job is not None else await _target_count(scale_session, chute.chute_id)
        )
    try:
        preflight_selector = _platform_gpu_selector(chute, job)
    except (GpuAllocationError, ValueError):
        return False
    preflight_disk_mib = (
        int((job.job_args or {}).get("_disk_gb") or DEFAULT_GPU_DISK_GB) * 1024
        if job is not None
        else DEFAULT_GPU_DISK_GB * 1024
    )
    async with get_session(readonly=True) as preflight_session:
        preflight_candidates = await _candidate_groups(
            preflight_session,
            preflight_selector,
            required_disk_mib=preflight_disk_mib,
        )
        identifiers = sorted(
            {
                identifier
                for group, _host, _report in preflight_candidates
                for identifier in set(group.gpu_identifiers or [])
            }
        )
        if not identifiers:
            return False
        preflight_request = GpuPlatformReservationRequestV1(
            server_id="gpu-preflight",
            process_incarnation="gpu-preflight",
            gpu_identifier=identifiers[0],
            gpu_count=int(preflight_selector.gpu_count or 0),
            minimum_vram_mib=int(preflight_selector.min_vram_gb_per_gpu or 0) * 1024,
            chute_id=chute.chute_id,
            job_id=job.job_id if job is not None else None,
        )
        trusted_workload = await _trusted_platform_workload(
            preflight_session, preflight_request
        )
        observed_storage_by_host = {
            host.host_id: await observe_gpu_storage_liveness(
                preflight_session, host.host_id
            )
            for _group, host, _report in preflight_candidates
        }
    online_host_ids = set()
    for host_id in sorted(
        {host.host_id for _group, host, _report in preflight_candidates}
    ):
        assert_gpu_external_work_allowed(
            preflight_session, "GPU placement agent liveness preflight"
        )
        if await is_agent_online(host_id):
            online_host_ids.add(host_id)
    if not online_host_ids:
        return False
    async with get_session() as session:
        preverified_host_ids = set()
        for host_id in sorted(online_host_ids):
            try:
                await _preverify_active_gpu_release(session, host_id)
            except GpuAllocationError as exc:
                logger.info(
                    f"GPU host {host_id} failed release provenance preflight: {exc}"
                )
                continue
            preverified_host_ids.add(host_id)
        if not preverified_host_ids:
            return False
        await acquire_gpu_workload_lock(
            session,
            chute.chute_id,
            job.job_id if job is not None else None,
        )
        locked_chute = (
            (
                await session.execute(
                    select(Chute)
                    .options(joinedload(Chute.image))
                    .where(Chute.chute_id == chute.chute_id)
                    .with_for_update()
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if locked_chute is None:
            return False
        locked_job = None
        if job is not None:
            locked_job = (
                await session.execute(
                    select(Job).where(Job.job_id == job.job_id).with_for_update()
                )
            ).scalar_one_or_none()
            if (
                locked_job is None
                or locked_job.finished_at is not None
                or locked_job.instance_id is not None
                or locked_job.gpu_management_mode not in {None, "platform"}
            ):
                return False
        try:
            selector = _platform_gpu_selector(locked_chute, locked_job)
        except (GpuAllocationError, ValueError) as exc:
            logger.warning(
                f"GPU platform placement rejected {locked_chute.chute_id}: {exc}"
            )
            return False
        if await _demand_count(session, locked_chute, locked_job) >= target:
            return False
        required_disk_mib = (
            int((locked_job.job_args or {}).get("_disk_gb") or DEFAULT_GPU_DISK_GB)
            * 1024
            if locked_job is not None
            else DEFAULT_GPU_DISK_GB * 1024
        )
        for group, host, report in await _candidate_groups(
            session,
            selector,
            required_disk_mib=required_disk_mib,
        ):
            if host.host_id not in preverified_host_ids:
                continue
            readiness = await gpu_host_storage_readiness(
                session,
                host,
                include_allocation=False,
                observed_live_storage_ids=observed_storage_by_host.get(
                    host.host_id, set()
                ),
            )
            if not (
                readiness.trusted_storage_ready and readiness.control_channel_eligible
            ):
                continue
            identifiers = sorted(set(group.gpu_identifiers))
            if len(identifiers) != 1:
                continue
            process_incarnation = uuid.uuid4().hex
            request = GpuPlatformReservationRequestV1(
                server_id=f"gpu-{process_incarnation}",
                process_incarnation=process_incarnation,
                gpu_identifier=identifiers[0],
                gpu_count=int(selector.gpu_count or 0),
                minimum_vram_mib=int(selector.min_vram_gb_per_gpu or 0) * 1024,
                chute_id=locked_chute.chute_id,
                job_id=locked_job.job_id if locked_job is not None else None,
            )
            try:
                response = await reserve_gpu_group(
                    session,
                    host.host_id,
                    request,
                    expected_allocation_group_id=group.allocation_group_id,
                    expected_profile_id=group.profile_id,
                    expected_topology_fingerprint=group.topology_fingerprint,
                    expected_inventory_report_id=report.report_id,
                    expected_inventory_report_sha256=report.claims_sha256,
                    observed_live_storage_ids=observed_storage_by_host.get(
                        host.host_id, set()
                    ),
                    trusted_platform_workload=trusted_workload,
                )
            except GpuAllocationError as exc:
                logger.info(
                    f"GPU group {group.allocation_group_id} lost placement arbitration: {exc}"
                )
                await session.rollback()
                return False
            if locked_job is not None:
                locked_job.gpu_management_mode = "platform"
                locked_job.gpu_launch_reservation_id = response.claims.reservation_id
            await session.commit()
            logger.success(
                f"Reserved platform GPU group {response.claims.allocation_group_id} "
                f"for {'job ' + locked_job.job_id if locked_job else 'chute ' + locked_chute.chute_id}"
            )
            return True
    return False


async def _dispatch_launch(reservation_id: str) -> bool:
    async with get_session() as session:
        await acquire_gpu_lifecycle_lock(session)
        reservation = (
            await session.execute(
                select(GpuLaunchReservation)
                .where(GpuLaunchReservation.reservation_id == reservation_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            reservation is None
            or reservation.management_mode not in {"platform", "miner"}
            or reservation.state != "reserved"
            or reservation.claimed_at is not None
            or reservation.expires_at <= _utcnow()
        ):
            return False
        if (
            reservation.launch_dispatched_at is not None
            and reservation.launch_ack_at is None
            and reservation.launch_dispatched_at
            > _utcnow() - timedelta(seconds=LAUNCH_RETRY_SECONDS)
        ):
            return False
        host_id = reservation.host_id
        token = gpu_reservation_token(
            reservation.reservation_id,
            reservation.token_hash,
        )
        claims_sha256 = reservation.claims_sha256
        command_id = reservation.launch_command_id or str(uuid.uuid4())
        await record_gpu_command_dispatch(
            session,
            reservation_id,
            command="launch_gpu",
            command_id=command_id,
        )
        await session.commit()
        assert_gpu_external_work_allowed(session, "GPU launch liveness preflight")
    assert_gpu_external_work_allowed(session, "GPU launch agent liveness preflight")
    if not await is_agent_online(host_id):
        return False
    assert_gpu_external_work_allowed(session, "GPU launch command dispatch")
    command_id = await send_agent_command(
        host_id,
        "launch_gpu",
        {
            "reservation_id": reservation_id,
            "launch_reservation": token,
            "reservation_claims_sha256": claims_sha256,
        },
        command_id=command_id,
    )
    return True


async def _latest_current_gpu_attestation(session, server: Server) -> bool:
    try:
        latest = await _latest_attestation_attempt(session, server.server_id)
        current = _current_attestation(
            server,
            latest,
        )
        reservation = await session.get(
            GpuLaunchReservation, server.gpu_launch_reservation_id
        )
        if reservation is None:
            return False
        await require_completed_gpu_registration(session, reservation, current, server)
        return bool(
            latest is not None
            and server.gpu_runtime_session_attestation_id == latest.attestation_id
            and server.gpu_runtime_session_expires_at is not None
            and server.gpu_runtime_session_expires_at > _utcnow()
        )
    except (HTTPException, AttributeError):
        return False


async def _create_platform_launch_config(
    session,
    reservation: GpuLaunchReservation,
    server: Server,
    chute: Chute,
    job: Optional[Job],
    default_volume,
) -> tuple[LaunchConfig, str]:
    if (
        server.gpu_management_mode != "platform"
        or server.gpu_launch_reservation_id != reservation.reservation_id
        or server.gpu_allocation_group_id != reservation.allocation_group_id
        or server.gpu_allocation_group_generation
        != reservation.allocation_group_generation
        or server.gpu_process_incarnation != reservation.process_incarnation
        or server.gpu_retired_at is not None
    ):
        raise GpuAllocationError(
            "Platform scheduler rejected a miner-managed or stale GPU server."
        )
    existing = (
        (
            await session.execute(
                select(LaunchConfig)
                .where(
                    LaunchConfig.gpu_launch_reservation_id == reservation.reservation_id
                )
                .with_for_update()
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if existing is not None:
        raise GpuAllocationError(
            "Platform GPU reservation already has a launch config."
        )
    miner = (
        await session.execute(
            select(MetagraphNode).where(
                MetagraphNode.hotkey == server.miner_hotkey,
                MetagraphNode.netuid == settings.netuid,
            )
        )
    ).scalar_one_or_none()
    if miner is None:
        raise GpuAllocationError(
            "GPU server owner is absent from the current metagraph."
        )
    launch_owner_id = job.user_id if job is not None else chute.user_id
    if (
        default_volume.user_id != launch_owner_id
        or default_volume.deleted
        or default_volume.purged_at is not None
    ):
        raise GpuAllocationError(
            "Platform GPU default volume changed before launch-config CAS."
        )
    config = LaunchConfig(
        config_id=str(uuid.uuid4()),
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=launch_owner_id,
        compute_type="gpu",
        default_volume_id=default_volume.volume_id,
        storage_session_exchange_allowed=True,
        job_id=job.job_id if job is not None else None,
        miner_hotkey=server.miner_hotkey,
        miner_uid=miner.node_id,
        miner_coldkey=miner.coldkey,
        env_type="tee",
        seed=0,
        nonce=None,
        server_id=server.server_id,
        container_repository=reservation.container_repository,
        container_manifest_digest=reservation.container_manifest_digest,
        gpu_management_mode="platform",
        gpu_launch_reservation_id=reservation.reservation_id,
    )
    session.add(config)
    await session.flush()
    return config, _platform_launch_token(config, chute, job)


def _platform_launch_token(
    config: LaunchConfig,
    chute: Chute,
    job: Optional[Job],
) -> str:
    return create_launch_jwt_v2(
        config,
        egress=chute.allow_external_egress,
        lock_modules=(
            True
            if chute.standard_template
            else (chute.lock_modules if chute.lock_modules is not None else False)
        ),
        disk_gb=(
            int((job.job_args or {}).get("_disk_gb") or DEFAULT_GPU_DISK_GB)
            if job is not None
            else DEFAULT_GPU_DISK_GB
        ),
    )


async def _dispatch_workload(reservation_id: str) -> bool:
    async with get_session() as session:
        # Non-authoritative lookup discovers only the ChuteFS owner/chute pair.
        # Bind User -> default binding/volume before any GPU lifecycle/workload lock.
        launch_hint = (
            await session.execute(
                select(
                    GpuLaunchReservation.chute_id,
                    GpuLaunchReservation.job_id,
                ).where(GpuLaunchReservation.reservation_id == reservation_id)
            )
        ).one_or_none()
        if launch_hint is None or launch_hint.chute_id is None:
            return False
        chute_owner_hint = (
            await session.execute(
                select(Chute.user_id).where(Chute.chute_id == launch_hint.chute_id)
            )
        ).scalar_one_or_none()
        job_owner_hint = (
            (
                await session.execute(
                    select(Job.user_id).where(Job.job_id == launch_hint.job_id)
                )
            ).scalar_one_or_none()
            if launch_hint.job_id is not None
            else None
        )
        launch_owner_hint = job_owner_hint or chute_owner_hint
        if launch_owner_hint is None:
            return False
        _, default_volume, _ = await ensure_default_volume_binding(
            session,
            launch_owner_hint,
            launch_hint.chute_id,
        )

        await acquire_gpu_lifecycle_lock(session)
        reservation = (
            await session.execute(
                select(GpuLaunchReservation)
                .where(GpuLaunchReservation.reservation_id == reservation_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            reservation is None
            or reservation.management_mode != "platform"
            or reservation.state != "running"
            or reservation.teardown_requested_at is not None
        ):
            return False
        await acquire_gpu_workload_lock(
            session,
            reservation.chute_id,
            reservation.job_id,
        )
        server = (
            await session.execute(
                select(Server)
                .where(Server.server_id == reservation.server_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        chute = (
            (
                await session.execute(
                    select(Chute)
                    .options(joinedload(Chute.image))
                    .where(Chute.chute_id == reservation.chute_id)
                    .with_for_update()
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        job = (
            (
                await session.execute(
                    select(Job)
                    .where(Job.job_id == reservation.job_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if reservation.job_id
            else None
        )
        if (
            server is None
            or chute is None
            or chute.disabled
            or not chute.tee
            or chute.image.compute_type != "gpu"
            or reservation.chute_id != launch_hint.chute_id
            or reservation.job_id != launch_hint.job_id
            or (reservation.job_id is not None and job is None)
            or (job is not None and job.finished_at is not None)
            or (job.user_id if job is not None else chute.user_id) != launch_owner_hint
            or not await _latest_current_gpu_attestation(session, server)
        ):
            raise GpuAllocationError(
                "Platform GPU workload owner, server, or attestation lineage disappeared."
            )
        config = (
            (
                await session.execute(
                    select(LaunchConfig)
                    .where(
                        LaunchConfig.gpu_launch_reservation_id
                        == reservation.reservation_id
                    )
                    .with_for_update()
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if config is None:
            config, token = await _create_platform_launch_config(
                session,
                reservation,
                server,
                chute,
                job,
                default_volume,
            )
        else:
            if (
                config.gpu_management_mode != "platform"
                or config.server_id != server.server_id
                or config.chute_id != reservation.chute_id
                or config.job_id != reservation.job_id
                or config.container_repository != reservation.container_repository
                or config.container_manifest_digest
                != reservation.container_manifest_digest
                or config.failed_at is not None
                or config.verification_error is not None
            ):
                raise GpuAllocationError(
                    "Platform GPU launch config no longer matches its reservation."
                )
            token = _platform_launch_token(config, chute, job)
        reservation.workload_dispatched_at = _utcnow()
        command_id = reservation.workload_command_id or str(uuid.uuid4())
        reservation.workload_command_id = command_id
        await session.commit()
        config_id = config.config_id
        server_id = server.server_id
        external_ports = server.external_ports
    assert_gpu_external_work_allowed(session, "GPU workload agent liveness preflight")
    if not await is_agent_online(server_id):
        return False
    ports = {"primary": 8000, "logging": 8001}
    if semcomp(chute.chutes_version or "0.0.0", "0.6.0") >= 0:
        ports["attestation"] = 8002
    disk_gb = (
        int((job.job_args or {}).get("_disk_gb") or DEFAULT_GPU_DISK_GB)
        if job is not None
        else DEFAULT_GPU_DISK_GB
    )
    assert_gpu_external_work_allowed(session, "GPU workload command dispatch")
    await send_agent_command(
        server_id,
        "deploy_chute",
        {
            "reservation_id": reservation_id,
            "gpu_launch_reservation_id": reservation_id,
            "server_id": server_id,
            "chute_id": chute.chute_id,
            "job_id": job.job_id if job is not None else None,
            "version": chute.version,
            "config_id": config_id,
            "token": token,
            "image": _chute_image_ref(chute),
            "image_digest": reservation.container_manifest_digest,
            "registry": settings.registry_external_host,
            "registry_insecure": settings.registry_insecure,
            "ref_str": chute.ref_str,
            "chutes_version": chute.chutes_version,
            "validator": settings.validator_ss58,
            "tee": True,
            "compute_type": "gpu",
            "env_type": "tee",
            "ports": ports,
            "external_ports": external_ports,
            "disk_gb": disk_gb,
            "job_ports": _job_ports(chute, job.method) if job is not None else [],
        },
        command_id=command_id,
    )
    return True


async def _dispatch_workload_or_teardown(reservation_id: str) -> None:
    try:
        await _dispatch_workload(reservation_id)
    except GpuAllocationError as exc:
        await send_gpu_reservation_teardown(
            reservation_id,
            reason=f"platform workload dispatch became impossible: {exc}",
        )


async def _reservation_still_desired(
    session,
    reservation: GpuLaunchReservation,
    *,
    resolved_image_ref: Optional[str],
    resolved_container_intent: tuple[str, str] | None,
) -> tuple[bool, str]:
    chute = (
        (
            await session.execute(
                select(Chute)
                .options(joinedload(Chute.image))
                .where(Chute.chute_id == reservation.chute_id)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if chute is None:
        return False, "chute deleted"
    if chute.disabled or not chute.tee or chute.image.compute_type != "gpu":
        return False, "chute no longer an enabled TEE GPU workload"
    if reservation.job_id is not None:
        job = await session.get(Job, reservation.job_id)
        if (
            job is None
            or job.finished_at is not None
            or job.user_id != reservation.workload_owner
            or job.gpu_management_mode != "platform"
            or job.gpu_launch_reservation_id != reservation.reservation_id
        ):
            return False, "job completed, failed, or was deleted"
        if job.version != reservation.chute_version:
            return False, "job chute version changed"
    elif chute.version != reservation.chute_version:
        return False, "chute version changed"
    elif chute.user_id != reservation.workload_owner:
        return False, "chute owner changed"
    active_release = (
        await session.execute(
            select(GuestRelease).where(
                GuestRelease.status == RELEASE_STATUS_ACTIVE,
                GuestRelease.channel
                == select(Host.release_channel)
                .where(Host.host_id == reservation.host_id)
                .scalar_subquery(),
                GuestRelease.tee_type == "tdx",
                GuestRelease.compute_type == "gpu",
            )
        )
    ).scalar_one_or_none()
    if (
        active_release is None
        or active_release.release_id != reservation.gpu_release_id
    ):
        return False, "GPU release rolled"
    if resolved_image_ref != _chute_image_ref(chute):
        return True, "container identity changed during external resolution"
    intent = resolved_container_intent
    if intent is None:
        # Existing guests remain bound to the already-reserved descriptor closure.
        # A transient registry outage blocks new placement, not safe running work.
        return True, "container digest resolution temporarily unavailable"
    if intent != (
        reservation.container_repository,
        reservation.container_manifest_digest,
    ):
        return False, "chute image digest changed"
    return True, "current"


async def _reconcile_reservation(reservation_id: str) -> None:
    resolved_image_ref: Optional[str] = None
    resolved_container_intent: tuple[str, str] | None = None
    async with get_session(readonly=True) as preflight_session:
        preflight_reservation = await preflight_session.get(
            GpuLaunchReservation,
            reservation_id,
        )
        if (
            preflight_reservation is None
            or preflight_reservation.management_mode not in {"platform", "miner"}
        ):
            return
        preflight_host_id = preflight_reservation.host_id
        if preflight_reservation.management_mode == "platform":
            preflight_chute = (
                (
                    await preflight_session.execute(
                        select(Chute)
                        .options(joinedload(Chute.image))
                        .where(Chute.chute_id == preflight_reservation.chute_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if preflight_chute is not None:
                resolved_image_ref = _chute_image_ref(preflight_chute)
                resolved_container_intent = await _container_intent(
                    preflight_session,
                    preflight_chute,
                )
    assert_gpu_external_work_allowed(
        preflight_session, "GPU reconciliation agent liveness preflight"
    )
    online = await is_agent_online(preflight_host_id)
    async with get_session() as session:
        await acquire_gpu_lifecycle_lock(session)
        identity = (
            await session.execute(
                select(
                    GpuLaunchReservation.host_id,
                    GpuLaunchReservation.management_mode,
                ).where(GpuLaunchReservation.reservation_id == reservation_id)
            )
        ).one_or_none()
        if identity is None or identity.management_mode not in {"platform", "miner"}:
            return
        management_mode = identity.management_mode
        await _expire_locked_reservations(session, identity.host_id)
        reservation, _group = await _locked_reservation_group(
            session,
            reservation_id,
        )
        if reservation.state in {"released", "expired"}:
            await session.commit()
            return
        if reservation.state == "quarantined":
            code = reservation.failure_code or "gpu_reservation_quarantined"
            failure_reason = (
                reservation.failure_reason
                or "GPU reservation remains quarantined pending explicit recovery."
            )
            host_online = online
            reset_retry_due = bool(
                reservation.teardown_dispatched_at is None
                or reservation.teardown_dispatched_at
                <= _utcnow() - timedelta(seconds=TEARDOWN_RETRY_SECONDS)
            )
            await session.rollback()
            async with get_session() as fence_session:
                await quarantine_gpu_reservation_control_plane(
                    fence_session,
                    reservation_id,
                    code=code,
                    reason=failure_reason,
                    metadata=reservation.failure_metadata,
                )
                await fence_session.commit()
            if host_online and reset_retry_due:
                await send_gpu_reservation_teardown(
                    reservation_id,
                    reason=f"quarantine reset: {failure_reason}",
                )
            return
        if management_mode == "platform":
            desired, reason = await _reservation_still_desired(
                session,
                reservation,
                resolved_image_ref=resolved_image_ref,
                resolved_container_intent=resolved_container_intent,
            )
        else:
            desired, reason = True, "current miner whole-fabric reservation"
        now = _utcnow()
        if online:
            reservation.last_reconciled_at = now
        elif reservation.last_reconciled_at is None:
            reservation.last_reconciled_at = now
        elif now - reservation.last_reconciled_at > timedelta(
            seconds=HOST_LOSS_GRACE_SECONDS
        ):
            await session.rollback()
            async with get_session() as fence_session:
                await quarantine_gpu_reservation_control_plane(
                    fence_session,
                    reservation_id,
                    code="gpu_host_control_channel_lost",
                    reason="GPU host disappeared before exact process absence and reset proof.",
                )
                await fence_session.commit()
            return
        if not desired and reservation.teardown_requested_at is None:
            reservation.teardown_requested_at = now
            reservation.teardown_reason = reason
        state = reservation.state
        teardown_requested = reservation.teardown_requested_at is not None
        teardown_reason = reservation.teardown_reason or reason
        teardown_retry_due = (
            reservation.teardown_command_id is None
            or reservation.teardown_dispatched_at is None
            or reservation.teardown_dispatched_at
            <= now - timedelta(seconds=TEARDOWN_RETRY_SECONDS)
        )
        await session.commit()
    if teardown_requested:
        if online and teardown_retry_due and state not in {"released", "expired"}:
            await send_gpu_reservation_teardown(
                reservation_id,
                reason=teardown_reason,
                operation_type=(
                    "release_rollover"
                    if teardown_reason == "GPU release rolled"
                    else None
                ),
            )
        return
    if state == "reserved":
        await _dispatch_launch(reservation_id)
        return
    if state in {"claimed", "launching"}:
        async with get_session() as session:
            row = await session.get(GpuLaunchReservation, reservation_id)
            started = row.claimed_at or row.launching_at or row.issued_at
        if started and started < _utcnow() - timedelta(
            seconds=CLAIMED_LAUNCH_TIMEOUT_SECONDS
        ):
            await send_gpu_reservation_teardown(
                reservation_id,
                reason="GPU guest failed to register before its launch deadline",
            )
        return
    if state == "running":
        async with get_session() as session:
            row = await session.get(GpuLaunchReservation, reservation_id)
            server = await session.get(Server, row.server_id) if row else None
            config = (
                (
                    await session.execute(
                        select(LaunchConfig).where(
                            LaunchConfig.gpu_launch_reservation_id == reservation_id
                        )
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            instance = (
                (
                    await session.execute(
                        select(Instance).where(
                            Instance.gpu_launch_reservation_id == reservation_id
                        )
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            current = bool(
                server is not None
                and server.gpu_management_mode == management_mode
                and await _latest_current_gpu_attestation(session, server)
            )
        if not current:
            await send_gpu_reservation_teardown(
                reservation_id,
                reason=(
                    "Latest GPU TDX/NVIDIA evidence or runtime session is "
                    "failed, revoked, or stale."
                ),
            )
        elif management_mode == "miner":
            return
        elif config is None:
            await _dispatch_workload_or_teardown(reservation_id)
        elif config.failed_at is not None or config.verification_error is not None:
            await send_gpu_reservation_teardown(
                reservation_id,
                reason="platform launch-config verification failed",
            )
        elif (
            instance is None
            and config.retrieved_at is None
            and row is not None
            and row.workload_dispatched_at is not None
            and row.workload_dispatched_at
            <= _utcnow() - timedelta(seconds=LAUNCH_RETRY_SECONDS)
            and config.created_at
            >= (
                _utcnow().replace(tzinfo=None)
                - timedelta(seconds=ACTIVATION_TIMEOUT_SECONDS)
            )
        ):
            await _dispatch_workload_or_teardown(reservation_id)
        elif (
            instance is None
            and config.created_at
            and config.created_at
            < (
                _utcnow().replace(tzinfo=None)
                - timedelta(seconds=ACTIVATION_TIMEOUT_SECONDS)
            )
        ):
            await send_gpu_reservation_teardown(
                reservation_id,
                reason="platform workload failed to create an instance",
            )
        elif (
            instance is not None
            and not instance.active
            and instance.created_at
            and instance.created_at
            < (_utcnow() - timedelta(seconds=ACTIVATION_TIMEOUT_SECONDS))
        ):
            await send_gpu_reservation_teardown(
                reservation_id,
                reason="platform workload failed serving-health activation",
            )


async def reconcile_platform_reservations() -> None:
    async with get_session() as session:
        reservation_ids = list(
            (
                await session.execute(
                    select(GpuLaunchReservation.reservation_id).where(
                        GpuLaunchReservation.management_mode == "platform",
                        GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                    )
                )
            )
            .scalars()
            .all()
        )
    for reservation_id in reservation_ids:
        try:
            await _reconcile_reservation(reservation_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"GPU platform reservation reconcile failed for {reservation_id}: {exc}"
            )


async def reconcile_miner_reservations() -> None:
    async with get_session() as session:
        reservation_ids = list(
            (
                await session.execute(
                    select(GpuLaunchReservation.reservation_id).where(
                        GpuLaunchReservation.management_mode == "miner",
                        GpuLaunchReservation.state.in_(_ACTIVE_RESERVATION_STATES),
                    )
                )
            )
            .scalars()
            .all()
        )
    for reservation_id in reservation_ids:
        try:
            await _reconcile_reservation(reservation_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"GPU miner reservation reconcile failed for {reservation_id}: {exc}"
            )


async def place_platform_demand() -> None:
    async with get_session() as session:
        chutes = (
            (
                await session.execute(
                    select(Chute)
                    .options(joinedload(Chute.image))
                    .where(
                        Chute.tee.is_(True),
                        Chute.disabled.is_(False),
                        Chute.node_selector["compute_type"].astext == "gpu",
                    )
                )
            )
            .unique()
            .scalars()
            .all()
        )
        chute_map = {chute.chute_id: chute for chute in chutes}
        jobs = (
            (
                await session.execute(
                    select(Job).where(
                        Job.chute_id.in_(list(chute_map)),
                        Job.instance_id.is_(None),
                        Job.finished_at.is_(None),
                        Job.miner_hotkey.is_(None),
                        or_(
                            Job.gpu_management_mode.is_(None),
                            Job.gpu_management_mode == "platform",
                        ),
                    )
                )
            )
            .scalars()
            .all()
            if chute_map
            else []
        )
    for chute in chutes:
        if chute.cords:
            await _place_workload(chute)
    for job in jobs:
        chute = chute_map.get(job.chute_id)
        if chute is not None:
            await _place_workload(chute, job=job)


async def schedule_once() -> None:
    from api.gpu_hotplug_service import retry_due_gpu_hotplug_commands
    from api.gpu_registration_service import (
        cleanup_expired_gpu_registration_nonces,
    )

    async with get_session() as session:
        await cleanup_expired_gpu_registration_nonces(session)
        await session.commit()
    await retry_due_gpu_hotplug_commands()
    await reconcile_miner_reservations()
    await reconcile_platform_reservations()
    await place_platform_demand()


async def _tick_with_lock() -> None:
    lock_id = str(uuid.uuid4())
    acquired = await settings.redis_client.set(
        SCHEDULER_LOCK_KEY,
        lock_id,
        nx=True,
        ex=SCHEDULER_LOCK_TTL_SECONDS,
    )
    if not acquired:
        return
    try:
        await schedule_once()
    finally:
        await settings.redis_client.eval(
            _COMPARE_AND_DELETE_LOCK,
            1,
            SCHEDULER_LOCK_KEY,
            lock_id,
        )


async def required_gpu_schema_present() -> bool:
    """Check the exact migration row without running ORM scheduling queries."""

    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT 1 FROM schema_migrations WHERE version = :required_version"
                ),
                {"required_version": REQUIRED_GPU_SCHEMA_VERSION},
            )
            return result.scalar_one_or_none() == 1
    except Exception as exc:  # table absence and blocked migration both mean not ready
        logger.warning(
            "Platform GPU scheduler schema barrier is not ready for "
            f"{REQUIRED_GPU_SCHEMA_VERSION}: {exc}"
        )
        return False


async def wait_for_required_gpu_schema() -> None:
    """Wait before Redis election or any ORM scheduling query can execute."""

    while not await required_gpu_schema_present():
        await asyncio.sleep(SCHEMA_WAIT_SECONDS)


def scheduler_liveness_healthy() -> bool:
    """The waiting process is live even while the exact schema barrier is closed."""

    return True


async def main() -> None:
    install_asyncio_exception_handler()
    logger.info(
        "Platform GPU scheduler waiting for exact schema version "
        f"{REQUIRED_GPU_SCHEMA_VERSION}"
    )
    await wait_for_required_gpu_schema()
    logger.info("Platform GPU scheduler starting")
    while True:
        try:
            await _tick_with_lock()
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Platform GPU scheduler iteration failed: {exc}")
        await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)


if __name__ == "__main__":
    if sys.argv[1:] == ["--schema-ready"]:
        ready = asyncio.run(required_gpu_schema_present())
        raise SystemExit(0 if ready else 1)
    if sys.argv[1:] == ["--live"]:
        raise SystemExit(0 if scheduler_liveness_healthy() else 1)
    if sys.argv[1:]:
        raise SystemExit("usage: python -m api.gpu_scheduler [--schema-ready|--live]")
    asyncio.run(main())
