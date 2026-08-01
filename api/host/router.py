"""Seedless Model-B logical-host enrollment and scoped control-plane routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.agent_channel import (
    send_agent_command,
    send_gpu_reservation_teardown,
    wait_for_agent_command_ack,
)
from api.constants import HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.gpu_contracts import (
    GpuHotplugCommandAckV1,
    GpuHotplugCommandV1,
    GpuLifecycleOperationV1,
    GpuLocalReleaseAckV1,
    GpuPhysicalResultV1,
    GpuRecoveryAuthorizationEnvelopeV1,
    GpuRecoveryReclaimRequestV1,
    GpuResetReceiptV1,
)
from api.gpu_hotplug_service import (
    GpuHotplugError,
    GpuHotplugGoneError,
    get_gpu_hotplug_command,
    record_gpu_hotplug_ack,
)
from api.gpu_registration_keys import (
    activate_gpu_registration_recovery_key_epoch,
    cancel_gpu_registration_recovery_key_epoch,
    retire_gpu_registration_recovery_key_epoch,
    stage_gpu_registration_recovery_key_epoch,
)
from api.gpu_lifecycle_service import (
    GpuLifecycleError,
    authorize_gpu_recovery,
    create_gpu_lifecycle_operation,
    get_gpu_lifecycle_operation,
    gpu_recovery_authorization_document,
    finalize_gpu_host_loss,
    record_gpu_local_release_ack,
    record_gpu_physical_result,
    start_gpu_recovery,
)
from api.host import service as host_service
from api.host.locks import assert_gpu_external_work_allowed
from api.host.reservations import (
    LaunchReservationError,
    claim_storage_launch_intent,
    gpu_host_storage_readiness,
    observe_gpu_storage_liveness,
)
from api.host.gpu_allocations import (
    GpuAllocationError,
    GpuAllocationQuarantinedError,
    _preverify_active_gpu_release,
    _trusted_platform_workload,
    claim_gpu_reservation,
    mark_gpu_launching,
    quarantine_gpu_reservation,
    reconcile_gpu_inventory,
    request_gpu_teardown,
    reserve_gpu_group,
    sign_gpu_launch_claims,
)
from api.host.schemas import (
    EnrollmentKeyChallengeRequestV1,
    EnrollmentKeyChallengeRequestV2,
    EnrollmentKeyChallengeResponseV1,
    EnrollmentKeyChallengeResponseV2,
    EnrollmentVoucherMintRequestV1,
    EnrollmentVoucherMintRequestV2,
    EnrollmentVoucherResponseV1,
    EnrollmentVoucherResponseV2,
    HostAuthChallengeV1,
    HostEnrollmentRedemptionV1,
    HostEnrollmentRedemptionV2,
    HostEnrollmentResponseV1,
    HostEnrollmentResponseV2,
    HostEnrollmentStatusV1,
    HostEnrollmentStatusV2,
    HostIdentityDurabilityAckV1,
    GpuHostLossFinalizeRequestV1,
    GpuHostStorageReadinessV1,
    HostKeyGeneration,
    HostProvisioningHeartbeatV1,
    HostProvisioningStatusV1,
    HostRevocationRequestV1,
    LaunchReservationResponseV1,
    LaunchReservationResponseV2,
    PcsMailboxAckV1,
    PcsMailboxEnvelopeV1,
    PcsMailboxEnvelopeV2,
    StorageLaunchIntentClaimV1,
    GpuInventoryReconcileResponseV1,
    GpuInventoryReportV1,
    GpuLaunchReservationResponseV1,
    GpuMinerReservationRequestV1,
    GpuMinerStopRequestV1,
    GpuMinerStopResponseV1,
    GpuPlatformReservationRequestV1,
    GpuReservationClaimRequestV1,
    GpuReservationQuarantineRequestV1,
    GpuReservationStateRequestV1,
    GpuSignedLaunchClaimsEnvelopeV1,
    GpuRecoveryAuthorizeRequestV1,
    GpuRegistrationRecoveryKeyCancelRequest,
    GpuRegistrationRecoveryKeyEpochResponse,
    GpuRegistrationRecoveryKeyStageRequest,
    GpuRegistrationRecoveryKeyTransitionRequest,
)
from api.server.gpu_infra import (
    authorize_legacy_gpu_cutover,
    confirm_legacy_sources_unowned,
)
from api.server.schemas import (
    GpuLegacyCutoverAuthorizeRequestV1,
    GpuLegacyCutoverAuthorizeResponseV1,
    GpuLegacyMigration,
    GpuLegacyHostConfirmRequestV1,
    GpuLegacyHostConfirmResponseV1,
    GpuMinerIdentity,
)
from api.miner.util import is_miner_blacklisted
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import (
    Host,
    HostRegistrationArgs,
    HostRegistrationResponse,
    Server,
)
from api.server.service import (
    register_host,
    request_host_image_upgrade,
    request_host_reboot,
)
from api.user.schemas import User
from api.user.service import get_current_user
from api.permissions import Permissioning

router = APIRouter()

_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


def _require_hotkey(hotkey: Optional[str]) -> str:
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    return hotkey


def _require_admin(current_user: Optional[User]) -> User:
    if current_user is None or not current_user.has_role(Permissioning.chutes_support):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU platform allocation requires a Chutes admin account.",
        )
    return current_user


@router.post(
    "/enrollment-vouchers",
    response_model=EnrollmentVoucherResponseV1 | EnrollmentVoucherResponseV2,
)
async def mint_enrollment_voucher_endpoint(
    body: EnrollmentVoucherMintRequestV1 | EnrollmentVoucherMintRequestV2,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_ENROLLMENT.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    if not settings.skip_metagraph_check:
        reason = await is_miner_blacklisted(db, owner)
        if reason:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
    try:
        return await host_service.mint_enrollment_voucher(db, owner, body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/enrollment/challenge",
    response_model=EnrollmentKeyChallengeResponseV1 | EnrollmentKeyChallengeResponseV2,
)
async def enrollment_key_challenge_endpoint(
    body: EnrollmentKeyChallengeRequestV1 | EnrollmentKeyChallengeRequestV2,
    db: AsyncSession = Depends(get_db_session),
):
    try:
        return await host_service.create_enrollment_key_challenge(db, body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/enroll",
    response_model=HostEnrollmentResponseV1 | HostEnrollmentResponseV2,
)
async def redeem_enrollment_voucher_endpoint(
    body: HostEnrollmentRedemptionV1 | HostEnrollmentRedemptionV2,
    db: AsyncSession = Depends(get_db_session),
):
    try:
        return await host_service.redeem_enrollment_voucher(db, body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/{host_id}/identity-durable",
    response_model=HostProvisioningStatusV1,
)
async def acknowledge_identity_durability_endpoint(
    host_id: str,
    body: HostIdentityDurabilityAckV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the durability path.",
        )
    try:
        return await host_service.acknowledge_identity_durability(
            db,
            current_host,
            body,
        )
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/provisioning-heartbeat",
    response_model=HostProvisioningStatusV1,
)
async def provisioning_heartbeat_endpoint(
    host_id: str,
    body: HostProvisioningHeartbeatV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the provisioning path.",
        )
    try:
        return await host_service.record_provisioning_heartbeat(
            db,
            current_host,
            body,
        )
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "/enrollment-status",
    response_model=HostEnrollmentStatusV1 | HostEnrollmentStatusV2,
)
async def enrollment_status_endpoint(
    host_id: str = Query(..., min_length=1, max_length=256),
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_ENROLLMENT.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    host = await db.get(Host, host_id)
    if (
        host is None
        or host.miner_hotkey != owner
        or host.enrollment_generation is None
        or host.active_key_generation is None
        or host.enrolled_at is None
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not enrolled.")
    key = await db.get(HostKeyGeneration, (host.host_id, host.active_key_generation))
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Host enrollment has no active key generation.",
        )
    if (host.compute_type or "cpu") == "gpu":
        return HostEnrollmentStatusV2(
            host_id=host.host_id,
            owner_hotkey=host.miner_hotkey,
            tee_type="tdx",
            compute_type="gpu",
            storage_enabled=True,
            channel=host.release_channel,
            enrollment_generation=host.enrollment_generation,
            key_generation=host.active_key_generation,
            provisioning_state=host.provisioning_state,
            x25519_public_key=key.x25519_public_key,
            x25519_fingerprint=key.x25519_fingerprint,
            enrolled_at=host.enrolled_at,
        )
    return HostEnrollmentStatusV1(
        host_id=host.host_id,
        owner_hotkey=host.miner_hotkey,
        tee_type=host.tee_type,
        channel=host.release_channel,
        enrollment_generation=host.enrollment_generation,
        key_generation=host.active_key_generation,
        provisioning_state=host.provisioning_state,
        x25519_public_key=key.x25519_public_key,
        x25519_fingerprint=key.x25519_fingerprint,
        enrolled_at=host.enrolled_at,
    )


@router.get("/{host_id}/auth/challenge", response_model=HostAuthChallengeV1)
async def host_auth_challenge_endpoint(
    host_id: str,
    key_generation: int = Query(..., ge=1),
    db: AsyncSession = Depends(get_db_session),
):
    try:
        return await host_service.create_host_auth_challenge(db, host_id, key_generation)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.post("/pcs-mailbox", status_code=status.HTTP_204_NO_CONTENT)
async def provision_pcs_mailbox_endpoint(
    body: PcsMailboxEnvelopeV1 | PcsMailboxEnvelopeV2,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_PCS_MAILBOX.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    try:
        await host_service.store_pcs_mailbox(db, _require_hotkey(hotkey), body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/{host_id}/pcs-mailbox/consume",
    response_model=PcsMailboxEnvelopeV1 | PcsMailboxEnvelopeV2,
)
async def consume_pcs_mailbox_endpoint(
    host_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the mailbox path.",
        )
    try:
        return await host_service.consume_pcs_mailbox(db, current_host)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/{host_id}/pcs-mailbox/ack", status_code=status.HTTP_204_NO_CONTENT)
async def acknowledge_pcs_mailbox_endpoint(
    host_id: str,
    body: PcsMailboxAckV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the mailbox path.",
        )
    try:
        await host_service.acknowledge_pcs_mailbox(db, current_host, body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/launch-reservations/storage",
    response_model=LaunchReservationResponseV1 | LaunchReservationResponseV2,
    response_model_exclude_none=True,
)
async def create_storage_launch_reservation_endpoint(
    host_id: str,
    body: StorageLaunchIntentClaimV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the reservation path.",
        )
    try:
        reservation, token = await claim_storage_launch_intent(
            db,
            current_host,
        )
        await db.commit()
        response_type = (
            LaunchReservationResponseV2
            if int(reservation.claims_version or 1) == 2
            else LaunchReservationResponseV1
        )
        return response_type(
            token=token,
            claims=reservation.claims,
            claims_sha256=reservation.claims_sha256,
        )
    except LaunchReservationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "/{host_id}/storage-readiness",
    response_model=GpuHostStorageReadinessV1,
)
async def gpu_storage_readiness_endpoint(
    host_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the readiness path.",
        )
    readiness = await gpu_host_storage_readiness(db, current_host)
    desired_capacity = (
        int(current_host.reported_capacity or 0) if readiness.trusted_schedulable else 0
    )
    if current_host.capacity != desired_capacity:
        current_host.capacity = desired_capacity
        await db.commit()
    return readiness


@router.post(
    "/{host_id}/gpu/migrations/{migration_id}/source-closed",
    response_model=GpuLegacyHostConfirmResponseV1,
)
async def confirm_legacy_gpu_sources_endpoint(
    host_id: str,
    migration_id: str,
    body: GpuLegacyHostConfirmRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the migration path.",
        )
    try:
        result = await confirm_legacy_sources_unowned(
            db,
            current_host,
            migration_id,
            body,
        )
        await db.commit()
        return result
    except HTTPException:
        await db.rollback()
        raise


@router.post(
    "/{host_id}/gpu/inventory",
    response_model=GpuInventoryReconcileResponseV1,
)
async def reconcile_gpu_inventory_endpoint(
    host_id: str,
    body: GpuInventoryReportV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU inventory path.",
        )
    try:
        result = await reconcile_gpu_inventory(db, current_host, body)
        await db.commit()
        return result
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/reservations/platform",
    response_model=GpuLaunchReservationResponseV1,
    response_model_exclude_none=True,
)
async def create_platform_gpu_reservation_endpoint(
    host_id: str,
    body: GpuPlatformReservationRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    _require_admin(current_user)
    try:
        from api.chute.schemas import Chute
        from api.gpu_scheduler import (
            _demand_count,
            _target_count,
            acquire_gpu_workload_lock,
        )
        from api.job.schemas import Job

        # Resolve registry closure and Redis liveness/scale observations before
        # the workload/lifecycle transaction. The locked phase refetches and
        # compares the database lineage before creating authority.
        trusted_workload = await _trusted_platform_workload(db, body)
        observed_live_storage_ids = await observe_gpu_storage_liveness(db, host_id)
        target = 1 if body.job_id is not None else await _target_count(db, body.chute_id)
        await _preverify_active_gpu_release(db, host_id)
        await acquire_gpu_workload_lock(db, body.chute_id, body.job_id)
        chute = await db.get(Chute, body.chute_id)
        job = await db.get(Job, body.job_id) if body.job_id else None
        if chute is None or (body.job_id is not None and job is None):
            raise GpuAllocationError("Platform GPU workload no longer exists.")
        if await _demand_count(db, chute, job) >= target:
            raise GpuAllocationError(
                "GPU workload demand was already claimed by a platform or miner manager."
            )
        result = await reserve_gpu_group(
            db,
            host_id,
            body,
            observed_live_storage_ids=observed_live_storage_ids,
            trusted_platform_workload=trusted_workload,
        )
        await db.commit()
        return result
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/migrations/legacy/authorize",
    response_model=GpuLegacyCutoverAuthorizeResponseV1,
)
async def authorize_legacy_gpu_cutover_endpoint(
    host_id: str,
    body: GpuLegacyCutoverAuthorizeRequestV1,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.GPU_RESERVATION.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    try:
        result = await authorize_legacy_gpu_cutover(
            db,
            host_id,
            owner,
            body,
        )
        await db.commit()
        return result
    except (GpuAllocationError, HTTPException):
        await db.rollback()
        raise


@router.post(
    "/{host_id}/gpu/reservations/miner",
    response_model=GpuLaunchReservationResponseV1,
    response_model_exclude_none=True,
)
async def create_miner_gpu_reservation_endpoint(
    host_id: str,
    body: GpuMinerReservationRequestV1,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.GPU_RESERVATION.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    try:
        if body.legacy_vm_name is not None:
            identity = await db.get(GpuMinerIdentity, host_id)
            migration = (
                (
                    await db.execute(
                        select(GpuLegacyMigration).where(
                            GpuLegacyMigration.host_id == host_id,
                            GpuLegacyMigration.legacy_vm_name == body.legacy_vm_name,
                        )
                    )
                ).scalar_one_or_none()
                if identity is not None
                else None
            )
            if identity is None or identity.owner_hotkey != owner or migration is None:
                raise GpuAllocationError("Legacy migration closure has not been established.")
            if migration.state == "guest_closed":
                await db.rollback()
                command = "confirm_gpu_legacy_sources"
                command_id = f"gpu-legacy-confirm-{migration.migration_id}"
                command_data = {
                    "migration_id": migration.migration_id,
                    "legacy_server_id": migration.legacy_server_id,
                    "storage_luks_uuid": migration.storage_luks_uuid,
                    "cache_luks_uuid": migration.cache_luks_uuid,
                }
                acknowledgement = None
                for _attempt in range(2):
                    assert_gpu_external_work_allowed(db, "legacy source-confirm command dispatch")
                    await send_agent_command(
                        host_id,
                        command,
                        command_data,
                        command_id=command_id,
                    )
                    assert_gpu_external_work_allowed(db, "legacy source-confirm ACK wait")
                    acknowledgement = await wait_for_agent_command_ack(
                        host_id,
                        command,
                        command_id,
                        timeout_seconds=15,
                    )
                    if acknowledgement is not None:
                        break
                if acknowledgement is None or acknowledgement.get("status") != "ok":
                    raise GpuAllocationError(
                        "Legacy source ownership is not yet closed on the target host."
                    )
        observed_live_storage_ids = await observe_gpu_storage_liveness(db, host_id)
        result = await reserve_gpu_group(
            db,
            host_id,
            body,
            expected_owner_hotkey=owner,
            observed_live_storage_ids=observed_live_storage_ids,
        )
        await db.commit()
        from api.gpu_scheduler import _dispatch_launch

        await _dispatch_launch(result.claims.reservation_id)
        return result
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/recovery/{authorization_id}/reclaim",
    response_model=GpuLaunchReservationResponseV1,
    response_model_exclude_none=True,
)
async def reclaim_recovered_gpu_group_endpoint(
    host_id: str,
    authorization_id: str,
    body: GpuRecoveryReclaimRequestV1,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.GPU_RESERVATION.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    if body.authorization_id != authorization_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU recovery authorization differs from its path.",
        )
    try:
        observed_live_storage_ids = await observe_gpu_storage_liveness(db, host_id)
        result = await reserve_gpu_group(
            db,
            host_id,
            body.reservation,
            expected_owner_hotkey=owner,
            recovery_authorization_id=authorization_id,
            observed_live_storage_ids=observed_live_storage_ids,
        )
        await db.commit()
        from api.gpu_scheduler import _dispatch_launch

        await _dispatch_launch(result.claims.reservation_id)
        return result
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/gpu/miner/{server_id}/stop",
    response_model=GpuMinerStopResponseV1,
)
async def stop_miner_gpu_server_endpoint(
    server_id: str,
    body: GpuMinerStopRequestV1,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.GPU_RESERVATION.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    owner = _require_hotkey(hotkey)
    server = await db.get(Server, server_id)
    if (
        server is None
        or server.miner_hotkey != owner
        or server.compute_type != "gpu"
        or server.gpu_management_mode != "miner"
        or not server.gpu_launch_reservation_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="GPU server not found.")
    try:
        reservation = await request_gpu_teardown(
            db,
            server.gpu_launch_reservation_id,
            reason=body.reason,
        )
        await db.commit()
        if reservation.state not in {"released", "expired"}:
            await send_gpu_reservation_teardown(
                reservation.reservation_id,
                reason=body.reason,
            )
        return GpuMinerStopResponseV1(
            server_id=server.server_id,
            reservation_id=reservation.reservation_id,
            status=(
                "released" if reservation.state in {"released", "expired"} else "teardown_requested"
            ),
        )
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/reservations/claim",
    response_model=GpuSignedLaunchClaimsEnvelopeV1,
    response_model_exclude_none=True,
)
async def claim_gpu_reservation_endpoint(
    host_id: str,
    body: GpuReservationClaimRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU claim path.",
        )
    try:
        claims = await claim_gpu_reservation(db, current_host, body)
        signed_claims = sign_gpu_launch_claims(claims)
        await db.commit()
        return signed_claims
    except GpuAllocationQuarantinedError as exc:
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/reservations/launching",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def mark_gpu_launching_endpoint(
    host_id: str,
    body: GpuReservationStateRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU launch path.",
        )
    try:
        await mark_gpu_launching(db, current_host, body)
        await db.commit()
    except GpuAllocationQuarantinedError as exc:
        await db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/reservations/quarantine",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def quarantine_gpu_reservation_endpoint(
    host_id: str,
    body: GpuReservationQuarantineRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU quarantine path.",
        )
    try:
        await quarantine_gpu_reservation(
            db,
            current_host,
            GpuReservationStateRequestV1(
                reservation_id=body.reservation_id,
                claims_sha256=body.claims_sha256,
                process_incarnation=body.process_incarnation,
            ),
            code=body.failure_code,
            reason=body.failure_reason,
            metadata=body.evidence,
        )
        await db.commit()
    except GpuAllocationError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/lifecycle/operations",
    response_model=GpuLifecycleOperationV1,
    response_model_exclude_none=True,
)
async def create_gpu_lifecycle_operation_endpoint(
    host_id: str,
    body: GpuLifecycleOperationV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU lifecycle path.",
        )
    try:
        result = await create_gpu_lifecycle_operation(db, current_host, body)
        await db.commit()
        return result
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "/{host_id}/gpu/lifecycle/operations/{operation_id}",
    response_model=GpuLifecycleOperationV1,
    response_model_exclude_none=True,
)
async def get_gpu_lifecycle_operation_endpoint(
    host_id: str,
    operation_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU lifecycle path.",
        )
    try:
        return await get_gpu_lifecycle_operation(db, current_host, operation_id)
    except GpuLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{host_id}/gpu/lifecycle/operations/{operation_id}/recovery-start",
    response_model=GpuLifecycleOperationV1,
    response_model_exclude_none=True,
)
async def start_gpu_recovery_endpoint(
    host_id: str,
    operation_id: str,
    body: GpuRecoveryAuthorizationEnvelopeV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU lifecycle path.",
        )
    try:
        result = await start_gpu_recovery(
            db,
            current_host,
            operation_id,
            body,
        )
        await db.commit()
        return result
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/lifecycle/operations/{operation_id}/physical-result",
    response_model=GpuResetReceiptV1,
)
async def record_gpu_physical_result_endpoint(
    host_id: str,
    operation_id: str,
    body: GpuPhysicalResultV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU lifecycle path.",
        )
    if body.operation_id != operation_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU physical result operation id differs from its path.",
        )
    try:
        return await record_gpu_physical_result(
            db,
            current_host,
            operation_id,
            body,
        )
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/{host_id}/gpu/lifecycle/operations/{operation_id}/local-release-ack",
    response_model=GpuLifecycleOperationV1,
    response_model_exclude_none=True,
)
async def record_gpu_local_release_ack_endpoint(
    host_id: str,
    operation_id: str,
    body: GpuLocalReleaseAckV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU lifecycle path.",
        )
    if body.operation_id != operation_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU local-release ACK operation id differs from its path.",
        )
    try:
        return await record_gpu_local_release_ack(
            db,
            current_host,
            operation_id,
            body,
        )
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "/{host_id}/gpu/hotplug/{command_id}",
    response_model=GpuHotplugCommandV1,
)
async def get_gpu_hotplug_command_endpoint(
    host_id: str,
    command_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU hotplug path.",
        )
    try:
        return await get_gpu_hotplug_command(db, current_host, command_id)
    except GpuHotplugGoneError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"code": exc.code, "message": str(exc)},
        )
    except GpuHotplugError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{host_id}/gpu/hotplug/{command_id}/ack",
    response_model=GpuHotplugCommandV1,
)
async def record_gpu_hotplug_ack_endpoint(
    host_id: str,
    command_id: str,
    body: GpuHotplugCommandAckV1,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_current_host),
):
    if current_host.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated host does not match the GPU hotplug path.",
        )
    if body.command_id != command_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU hotplug ACK command id differs from its path.",
        )
    try:
        result = await record_gpu_hotplug_ack(
            db,
            current_host,
            command_id,
            body,
        )
        await db.commit()
        return result
    except GpuHotplugError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/gpu/groups/{allocation_group_id}/recovery/authorize",
    response_model=GpuRecoveryAuthorizationEnvelopeV1,
    response_model_exclude_none=True,
)
async def authorize_gpu_group_recovery_endpoint(
    allocation_group_id: str,
    body: GpuRecoveryAuthorizeRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    _require_admin(current_user)
    try:
        result = await authorize_gpu_recovery(
            db,
            allocation_group_id,
            body,
            authorized_by=str(current_user.user_id),
        )
        authorization_document = gpu_recovery_authorization_document(result)
        await db.commit()
        payload = {
            "authorization": authorization_document,
            "lifecycle_operation": authorization_document["operation"],
        }
        try:
            assert_gpu_external_work_allowed(db, "GPU recovery command dispatch")
            await send_agent_command(
                result.operation.host_id,
                "recover_gpu_group",
                payload,
                command_id=result.operation.operation_id,
            )
        except Exception as dispatch_exc:  # noqa: BLE001
            logger.error(
                "GPU recovery authorization was persisted but host command "
                f"dispatch failed for {allocation_group_id}: {dispatch_exc}"
            )
        return result
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post(
    "/admin/gpu/registration/recovery-keys/stage",
    response_model=GpuRegistrationRecoveryKeyEpochResponse,
)
async def stage_gpu_registration_recovery_key_endpoint(
    body: GpuRegistrationRecoveryKeyStageRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    administrator = _require_admin(current_user)
    return GpuRegistrationRecoveryKeyEpochResponse(
        **(
            await stage_gpu_registration_recovery_key_epoch(
                db,
                administrator_id=str(administrator.user_id),
                request_id=body.request_id,
                key_id=body.key_id,
                required_replica_ids=body.required_replica_ids,
            )
        )
    )


@router.post(
    "/admin/gpu/registration/recovery-keys/cancel",
    response_model=GpuRegistrationRecoveryKeyEpochResponse,
)
async def cancel_gpu_registration_recovery_key_endpoint(
    body: GpuRegistrationRecoveryKeyCancelRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    administrator = _require_admin(current_user)
    return GpuRegistrationRecoveryKeyEpochResponse(
        **(
            await cancel_gpu_registration_recovery_key_epoch(
                db,
                administrator_id=str(administrator.user_id),
                request_id=body.request_id,
                key_id=body.key_id,
                reason=body.reason,
            )
        )
    )


@router.post(
    "/admin/gpu/registration/recovery-keys/activate",
    response_model=GpuRegistrationRecoveryKeyEpochResponse,
)
async def activate_gpu_registration_recovery_key_endpoint(
    body: GpuRegistrationRecoveryKeyTransitionRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    administrator = _require_admin(current_user)
    return GpuRegistrationRecoveryKeyEpochResponse(
        **(
            await activate_gpu_registration_recovery_key_epoch(
                db,
                administrator_id=str(administrator.user_id),
                request_id=body.request_id,
                key_id=body.key_id,
            )
        )
    )


@router.post(
    "/admin/gpu/registration/recovery-keys/retire",
    response_model=GpuRegistrationRecoveryKeyEpochResponse,
)
async def retire_gpu_registration_recovery_key_endpoint(
    body: GpuRegistrationRecoveryKeyTransitionRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    administrator = _require_admin(current_user)
    return GpuRegistrationRecoveryKeyEpochResponse(
        **(
            await retire_gpu_registration_recovery_key_epoch(
                db,
                administrator_id=str(administrator.user_id),
                request_id=body.request_id,
                key_id=body.key_id,
            )
        )
    )


@router.post(
    "/gpu/groups/{allocation_group_id}/lifecycle/operations/{operation_id}/host-lost",
    response_model=GpuLifecycleOperationV1,
    response_model_exclude_none=True,
)
async def finalize_gpu_host_loss_endpoint(
    allocation_group_id: str,
    operation_id: str,
    body: GpuHostLossFinalizeRequestV1,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Permanently fence a phase-two group whose original L0 cannot return."""

    _require_admin(current_user)
    if body.operation_id != operation_id or body.allocation_group_id != allocation_group_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GPU host-loss request identity differs from its path.",
        )
    try:
        result = await finalize_gpu_host_loss(
            db,
            operation_id,
            body,
            authorized_by=str(current_user.user_id),
        )
        await db.commit()
        return result
    except GpuLifecycleError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post("/{host_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_host_endpoint(
    host_id: str,
    body: HostRevocationRequestV1,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_REVOCATION.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    try:
        await host_service.revoke_host_credentials(
            db, host_id, _require_hotkey(hotkey), body.reason
        )
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/register", response_model=HostRegistrationResponse)
async def register_host_endpoint(
    args: HostRegistrationArgs,
    db: AsyncSession = Depends(get_db_session),
    current_host: Host = Depends(host_service.get_ready_host),
):
    """Refresh untrusted launcher telemetry under its scoped persistent host key."""
    try:
        return await register_host(db, args, current_host)
    except ServerRegistrationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error in host registration: host_id={args.host_id} error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Host registration failed due to an unexpected error.",
        )


@router.post("/{host_id}/upgrade-image")
async def upgrade_host_image_endpoint(
    host_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_UPGRADE.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    """Tell an online L0 host to refresh its chute guest image (sends the node-agent upgrade_image).

    The host re-fetches the published guest image and rolls its per-chute TDs onto it. Pin the new
    image's attestation measurement on the validator in lockstep.
    """
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    try:
        return await request_host_image_upgrade(db, host_id, hotkey)
    except ServerRegistrationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error in host image upgrade: host_id={host_id} error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Host image upgrade failed due to an unexpected error.",
        )


@router.post("/{host_id}/reboot")
async def reboot_host_endpoint(
    host_id: str,
    target_l0_version: str | None = None,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_REBOOT.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    """Tell an online L0 host to reboot so it re-netboots into the current L0 squashfs.

    This is how the node-agent + L0 host image itself are updated: publish a new netboot set, then
    reboot. The RAM-root box re-fetches it; the data disk (ChuteFS volume + staged guest images)
    survives (unlike a provider reinstall). Optional target_l0_version makes it idempotent. All the
    host's TDs go down for the ~2-4 min re-netboot -- reboot one box at a time.
    """
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    try:
        return await request_host_reboot(db, host_id, hotkey, target_l0_version=target_l0_version)
    except ServerRegistrationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error in host reboot: host_id={host_id} error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Host reboot failed due to an unexpected error.",
        )


@router.get("/")
async def list_hosts(
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose="tee",
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
            force_hotkey_auth=True,
        )
    ),
):
    """List the caller miner's registered L0 hosts + their capacity/usage (per-host TD counts)."""
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing hotkey header."
        )
    hosts = (await db.execute(select(Host).where(Host.miner_hotkey == hotkey))).scalars().all()
    # Per-host TD usage in one grouped query (mirrors api/cpu_scheduler.py _launch_on_host) rather
    # than a COUNT per host.
    used_rows = (
        await db.execute(
            select(Server.host_id, func.count(Server.server_id))
            .where(
                Server.host_id.isnot(None),
                Server.self_registered.is_(True),
                # ChuteFS storage TDs are not user-chute slots (reserved out of capacity already).
                Server.storage_role.is_(False),
                Server.miner_hotkey == hotkey,
            )
            .group_by(Server.host_id)
        )
    ).all()
    used_by_host = {host_id: count for host_id, count in used_rows}
    observed_storage_by_host = {
        host.host_id: await observe_gpu_storage_liveness(db, host.host_id)
        for host in sorted(hosts, key=lambda item: item.host_id)
        if host.compute_type == "gpu"
    }
    out = []
    for h in hosts:
        readiness = (
            await gpu_host_storage_readiness(
                db,
                h,
                observed_live_storage_ids=observed_storage_by_host.get(h.host_id, set()),
            )
            if h.compute_type == "gpu"
            else None
        )
        out.append(
            {
                "host_id": h.host_id,
                "name": h.name,
                "tee_type": h.tee_type,
                "compute_type": h.compute_type,
                "capacity": h.capacity,
                "reported_capacity": h.reported_capacity,
                "used": used_by_host.get(h.host_id, 0),
                "external_host": h.external_host,
                "cpu_cores": h.cpu_cores,
                "ram_gb": h.ram_gb,
                "specs": h.specs,
                "storage_enabled": h.storage_enabled,
                "storage_requested": h.storage_requested,
                "trusted_storage_ready": (
                    readiness.trusted_storage_ready if readiness is not None else None
                ),
                "control_channel_eligible": (
                    readiness.control_channel_eligible if readiness is not None else None
                ),
                "trusted_schedulable": (
                    readiness.trusted_schedulable if readiness is not None else None
                ),
                "trusted_storage_reason": (readiness.reason if readiness is not None else None),
                "untrusted_gpu_inventory": h.untrusted_gpu_inventory,
                "untrusted_gpu_inventory_ready": h.untrusted_gpu_inventory_ready,
            }
        )
    return out
