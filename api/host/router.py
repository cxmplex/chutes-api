"""Model B: bare-metal L0 launcher host registration (the per-chute control plane).

An L0 host (the one-click-miner appliance / node-agent) registers here so the CPU scheduler can
dispatch per-chute TD launches to it over the control channel. The host is a launcher only and is
NOT attested -- it authenticates purely by the owning miner's hotkey signature. All workload trust
comes from each launched per-chute TD attesting itself, never from the host.

Auth: the standard `get_current_user` hotkey dependency (signature over
"{hotkey}:{nonce}:<purpose>" with a recent unix-timestamp nonce + metagraph membership in
production). Dev (skip_metagraph_check) drops only the membership requirement; signatures are
verified either way.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.miner.util import is_miner_blacklisted
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import Host, HostRegistrationArgs, HostRegistrationResponse, Server
from api.server.service import register_host, request_host_image_upgrade
from api.user.schemas import User
from api.user.service import get_current_user

router = APIRouter()

# Dev (skip_metagraph_check): drop the metagraph-membership requirement from the auth dependency;
# register_host auto-creates a dev metagraph row instead. Signatures are verified either way.
_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


@router.post("/register", response_model=HostRegistrationResponse)
async def register_host_endpoint(
    args: HostRegistrationArgs,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(
            purpose=NoncePurpose.HOST_REGISTER.value,
            registered_to=_REGISTERED_TO,
            raise_not_found=False,
        )
    ),
):
    """Register (or refresh) a Model-B L0 launcher host."""
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    try:
        if not settings.skip_metagraph_check:
            reason = await is_miner_blacklisted(db, hotkey)
            if reason:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
        return await register_host(db, args, hotkey)
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


@router.get("/")
async def list_hosts(
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        get_current_user(purpose="tee", registered_to=_REGISTERED_TO, raise_not_found=False)
    ),
):
    """List the caller miner's registered L0 hosts + their capacity/usage (per-host TD counts)."""
    if not hotkey:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing hotkey header.")
    hosts = (
        (await db.execute(select(Host).where(Host.miner_hotkey == hotkey))).scalars().all()
    )
    out = []
    for h in hosts:
        used = (
            await db.execute(
                select(Server.server_id).where(
                    Server.host_id == h.host_id, Server.self_registered.is_(True)
                )
            )
        ).scalars().all()
        out.append(
            {
                "host_id": h.host_id,
                "name": h.name,
                "tee_type": h.tee_type,
                "capacity": h.capacity,
                "used": len(used),
                "external_host": h.external_host,
                "cpu_cores": h.cpu_cores,
                "ram_gb": h.ram_gb,
                "specs": h.specs,
            }
        )
    return out
