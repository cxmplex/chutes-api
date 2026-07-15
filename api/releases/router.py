"""Fleet image release API.

Endpoint groups + auth:
  - release management (create / activate / rollout / status / list): a Chutes admin
    (Permissioning.chutes_support) via the standard API-key / JWT `get_current_user`.
  - GET /releases/current and POST /releases/current/reissue: host-facing desired state and explicit
    logical-token rotation, authenticated by the owning miner's hotkey signature.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.permissions import Permissioning
from api.releases import service
from api.releases.schemas import (
    CreateReleaseRequest,
    GuestRelease,
    ReissueReleaseTargetTokensRequest,
    ReleaseManifest,
    ReleaseResponse,
    ReleaseStatusResponse,
    RolloutRequest,
    RolloutResponse,
)
from api.user.schemas import User
from api.user.service import get_current_user

router = APIRouter()

_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


def _require_admin(current_user: Optional[User]) -> User:
    if current_user is None or not current_user.has_role(Permissioning.chutes_support):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Fleet release management requires a Chutes admin account.",
        )
    return current_user


@router.post("", response_model=ReleaseResponse)
@router.post("/", response_model=ReleaseResponse)
async def create_release_endpoint(
    req: CreateReleaseRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Create a draft release (optionally activate it). Admin only."""
    _require_admin(current_user)
    try:
        release = await service.create_release(db, req)
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return service.to_response(release)


@router.post("/{release_id}/activate", response_model=ReleaseResponse)
async def activate_release_endpoint(
    release_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Activate a release (gated on its measurements being pinned). Admin only."""
    _require_admin(current_user)
    try:
        release = await service.activate_release(db, release_id)
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return service.to_response(release)


@router.post("/{release_id}/rollout", response_model=RolloutResponse)
async def rollout_release_endpoint(
    release_id: str,
    body: RolloutRequest | None = None,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Nudge online logical targets (host_ids scopes dispatch, not the captured target set). Admin only.

    reboot_l0=true also re-netboots the hosts to apply the release's L0 slot (disruptive; opt-in).
    """
    _require_admin(current_user)
    host_ids = body.host_ids if body else None
    reboot_l0 = body.reboot_l0 if body else False
    try:
        result = await service.rollout_release(
            db, release_id, host_ids=host_ids, reboot_l0=reboot_l0
        )
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return result


@router.get("/{release_id}/status", response_model=ReleaseStatusResponse)
async def release_status_endpoint(
    release_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Untrusted host data plus quote-backed, same-miner-transferable logical telemetry. Admin only.

    It never proves physical convergence or automatically authorizes measurement-pin pruning.
    """
    _require_admin(current_user)
    try:
        return await service.release_status(db, release_id)
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get("", response_model=List[ReleaseResponse])
@router.get("/", response_model=List[ReleaseResponse])
async def list_releases_endpoint(
    tee_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """List releases (optionally filter by tee_type / status). Admin only."""
    _require_admin(current_user)
    q = select(GuestRelease).order_by(GuestRelease.created_at.desc())
    if tee_type:
        q = q.where(GuestRelease.tee_type == tee_type.strip().lower())
    if status_filter:
        q = q.where(GuestRelease.status == status_filter)
    rows = (await db.execute(q)).scalars().all()
    return [service.to_response(r) for r in rows]


@router.get("/current", response_model=ReleaseManifest)
async def current_release_endpoint(
    tee_type: str = Query(..., description="The polling host's launcher tee_type: sev-snp | tdx"),
    channel: str = Query("stable"),
    host_id: str = Query(..., description="Enrolled logical L0 launcher requesting its tokens"),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    db: AsyncSession = Depends(get_db_session),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.RELEASE_FETCH.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
        )
    ),
):
    """The active manifest an L0 node-agent should converge to (miner-hotkey signed).

    Returns 404 when no release is active for this (channel, tee_type) so the agent keeps its
    current image. Host-specific one-use rollout tokens make the signed ownership check mandatory.
    """
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    try:
        manifest = await service.active_manifest_for_host(
            db,
            tee_type,
            channel,
            host_id=host_id,
            miner_hotkey=hotkey,
        )
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active release for channel={channel} tee_type={tee_type}",
        )
    return manifest


@router.post("/current/reissue", response_model=ReleaseManifest)
async def reissue_current_release_target_tokens_endpoint(
    body: ReissueReleaseTargetTokensRequest,
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    db: AsyncSession = Depends(get_db_session),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.RELEASE_FETCH.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
            require_v2=True,
        )
    ),
):
    """Rotate selected one-use logical token generations before a role representative relaunch.

    The side effect requires a method/path/body-bound v2 signature with a single-use nonce. The
    caller is miner-authenticated, but the Model-B L0 remains unattested. Reissued bearer tokens are
    therefore transferable among that miner's launchers and provide no physical-host proof.
    """
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    try:
        manifest = await service.active_manifest_for_host(
            db,
            body.tee_type,
            body.channel,
            host_id=body.host_id,
            miner_hotkey=hotkey,
            reissue_roles=set(body.roles),
        )
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(f"No active release for channel={body.channel} tee_type={body.tee_type}"),
        )
    return manifest
