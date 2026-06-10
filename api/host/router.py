"""Model B: bare-metal L0 launcher host registration (the per-chute control plane).

An L0 host (the one-click-miner appliance / node-agent) registers here so the CPU scheduler can
dispatch per-chute TD launches to it over the control channel. The host is a launcher only and is
NOT attested -- it authenticates purely by the owning miner's hotkey signature. All workload trust
comes from each launched per-chute TD attesting itself, never from the host.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import HOTKEY_HEADER, NONCE_HEADER, SIGNATURE_HEADER
from api.database import get_db_session
from api.miner.util import is_miner_blacklisted
from api.server.exceptions import ServerRegistrationError
from api.server.schemas import Host, HostRegistrationArgs, HostRegistrationResponse
from api.server.service import register_host, request_host_image_upgrade

router = APIRouter()


@router.post("/register", response_model=HostRegistrationResponse)
async def register_host_endpoint(
    args: HostRegistrationArgs,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
    nonce: str | None = Header(None, alias=NONCE_HEADER),
):
    """Register (or refresh) a Model-B L0 launcher host.

    Auth: the owning miner's signature over "{hotkey}:{nonce}:host_register" with a recent
    unix-timestamp nonce (X-Chutes-Nonce); the host is not yet known, so there is no server-issued
    nonce. The signature + freshness window + (prod) metagraph membership authenticate the host.
    """
    if not hotkey or not signature or not nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey/signature/nonce headers.",
        )
    try:
        if not settings.skip_metagraph_check:
            reason = await is_miner_blacklisted(db, hotkey)
            if reason:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
        return await register_host(db, args, hotkey, nonce, signature)
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
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
    nonce: str | None = Header(None, alias=NONCE_HEADER),
):
    """Tell an online L0 host to refresh its chute guest image (sends the node-agent upgrade_image).

    Auth: the owning miner's signature over "{hotkey}:{nonce}:host_upgrade" with a recent
    unix-timestamp nonce. The host re-fetches the published guest image and rolls its per-chute TDs
    onto it. Pin the new image's attestation measurement on the validator in lockstep.
    """
    if not hotkey or not signature or not nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey/signature/nonce headers.",
        )
    try:
        return await request_host_image_upgrade(db, host_id, hotkey, nonce, signature)
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
):
    """List the caller miner's registered L0 hosts + their capacity/usage (per-host TD counts)."""
    if not hotkey:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing hotkey header.")
    from api.server.schemas import Server

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
