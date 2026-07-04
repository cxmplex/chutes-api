"""Fleet image release API.

Endpoint groups + auth:
  - release management (create / activate / rollout / status / list): a Chutes admin
    (Permissioning.chutes_support) via the standard API-key / JWT `get_current_user`.
  - GET /releases/current: the host-facing active manifest an L0 node-agent polls, authenticated by
    the owning miner's hotkey signature (same style as /hosts/register); the manifest is non-secret.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from loguru import logger
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
    """Dispatch upgrade_image to online hosts of the release's tee_type (host_ids = canary). Admin only."""
    _require_admin(current_user)
    host_ids = body.host_ids if body else None
    try:
        result = await service.rollout_release(db, release_id, host_ids=host_ids)
    except service.ReleaseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return result


@router.get("/{release_id}/status", response_model=ReleaseStatusResponse)
async def release_status_endpoint(
    release_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(raise_not_found=False)),
):
    """Convergence report: which hosts have staged the release's images, and servers on it. Admin only."""
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
    current image. The manifest is non-secret (public image URLs + sha256); the signature scopes the
    poll to miners and prevents anonymous enumeration.
    """
    if not hotkey:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing miner hotkey header.")
    manifest = await service.active_manifest_for_host(db, tee_type, channel)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active release for channel={channel} tee_type={tee_type}",
        )
    return manifest
