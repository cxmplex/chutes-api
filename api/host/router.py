"""Seedless Model-B logical-host enrollment and scoped control-plane routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.host import service as host_service
from api.host.reservations import (
    LaunchReservationError,
    claim_storage_launch_intent,
)
from api.host.schemas import (
    EnrollmentKeyChallengeRequestV1,
    EnrollmentKeyChallengeResponseV1,
    EnrollmentVoucherMintRequestV1,
    EnrollmentVoucherResponseV1,
    HostAuthChallengeV1,
    HostEnrollmentRedemptionV1,
    HostEnrollmentResponseV1,
    HostEnrollmentStatusV1,
    HostIdentityDurabilityAckV1,
    HostKeyGeneration,
    HostProvisioningHeartbeatV1,
    HostProvisioningStatusV1,
    HostRevocationRequestV1,
    LaunchReservationResponseV1,
    PcsMailboxAckV1,
    PcsMailboxEnvelopeV1,
    StorageLaunchIntentClaimV1,
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

router = APIRouter()

_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


def _require_hotkey(hotkey: Optional[str]) -> str:
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    return hotkey


@router.post("/enrollment-vouchers", response_model=EnrollmentVoucherResponseV1)
async def mint_enrollment_voucher_endpoint(
    body: EnrollmentVoucherMintRequestV1,
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


@router.post("/enrollment/challenge", response_model=EnrollmentKeyChallengeResponseV1)
async def enrollment_key_challenge_endpoint(
    body: EnrollmentKeyChallengeRequestV1,
    db: AsyncSession = Depends(get_db_session),
):
    try:
        return await host_service.create_enrollment_key_challenge(db, body)
    except host_service.HostAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post("/enroll", response_model=HostEnrollmentResponseV1)
async def redeem_enrollment_voucher_endpoint(
    body: HostEnrollmentRedemptionV1,
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


@router.get("/enrollment-status", response_model=HostEnrollmentStatusV1)
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
    body: PcsMailboxEnvelopeV1,
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


@router.post("/{host_id}/pcs-mailbox/consume", response_model=PcsMailboxEnvelopeV1)
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
    response_model=LaunchReservationResponseV1,
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
        return LaunchReservationResponseV1(
            token=token,
            claims=reservation.claims,
            claims_sha256=reservation.claims_sha256,
        )
    except LaunchReservationError as exc:
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
    out = []
    for h in hosts:
        out.append(
            {
                "host_id": h.host_id,
                "name": h.name,
                "tee_type": h.tee_type,
                "capacity": h.capacity,
                "used": used_by_host.get(h.host_id, 0),
                "external_host": h.external_host,
                "cpu_cores": h.cpu_cores,
                "ram_gb": h.ram_gb,
                "specs": h.specs,
            }
        )
    return out
