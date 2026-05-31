"""
CPU chute scheduler for 1-click self-registered TEE servers.

This is the validator-side placement brain for the 1-click model (it replaces the miner's gepetto
for CPU chutes). On an interval it:

  1. finds CPU chutes (node_selector.compute_type == "cpu") that need more instances,
  2. matches each to an online, self-registered CPU server that is idle and meets the chute's
     cores/RAM/benchmark requirements (single-tenant: one chute per CPU server),
  3. mints a launch config + JWT bound to that server, and
  4. pushes a deploy_chute command to the server's agent over the control channel.

Run as its own process (e.g. `python -m api.cpu_scheduler`), like chute_autoscaler.
"""

import asyncio
import secrets
import uuid

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

import api.database.orms  # noqa
from api.agent_channel import is_agent_online, send_agent_command
from api.chute.schemas import Chute
from api.config import settings
from api.database import get_session
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import create_launch_jwt_v2
from api.metagraph import MetagraphNode
from api.server.schemas import Server
from api.util import semcomp

SCHEDULER_INTERVAL_SECONDS = 15
DEFAULT_CPU_DISK_GB = 10


def _chute_image_ref(chute: Chute) -> str:
    """Pullable image repo path (registry host is supplied by the agent's own config)."""
    image = f"{chute.image.user.username}/{chute.image.name}:{chute.image.tag}".lower()
    if chute.image.patch_version not in (None, "initial"):
        image += f"-{chute.image.patch_version}"
    return image


async def _target_count(chute_id: str) -> int:
    """Desired instance count from the autoscaler; CPU chutes default to 1."""
    value = await settings.redis_client.get(f"scale:{chute_id}")
    target = int(value) if value else 0
    return max(target, 1)


async def _dispatch_deploy(session, chute: Chute, server: Server) -> None:
    miner = (
        await session.execute(
            select(MetagraphNode).where(
                MetagraphNode.hotkey == server.miner_hotkey,
                MetagraphNode.netuid == settings.netuid,
            )
        )
    ).scalar_one_or_none()
    if miner is None:
        logger.warning(f"No metagraph node for {server.miner_hotkey}; skipping {server.server_id}")
        return

    config_id = str(uuid.uuid4())
    rint_nonce = None
    if semcomp(chute.chutes_version or "0.0.0", "0.4.9") >= 0:
        rint_nonce = secrets.token_hex(16)
        await settings.redis_client.set(f"rint_nonce:{config_id}", rint_nonce, ex=7200)

    launch_config = LaunchConfig(
        config_id=config_id,
        env_key=secrets.token_bytes(16).hex(),
        chute_id=chute.chute_id,
        miner_hotkey=server.miner_hotkey,
        miner_uid=miner.node_id,
        miner_coldkey=miner.coldkey,
        env_type="tee",
        seed=0,
        nonce=rint_nonce,
        server_id=server.server_id,
    )
    session.add(launch_config)
    await session.commit()
    await session.refresh(launch_config)

    token = create_launch_jwt_v2(
        launch_config,
        egress=chute.allow_external_egress,
        lock_modules=(
            True
            if chute.standard_template
            else (chute.lock_modules if chute.lock_modules is not None else False)
        ),
        disk_gb=DEFAULT_CPU_DISK_GB,
    )

    ports = {"primary": 8000, "logging": 8001}
    if semcomp(chute.chutes_version or "0.0.0", "0.6.0") >= 0:
        ports["attestation"] = 8002

    await send_agent_command(
        server.server_id,
        "deploy_chute",
        {
            "chute_id": chute.chute_id,
            "version": chute.version,
            "config_id": config_id,
            "token": token,
            "image": _chute_image_ref(chute),
            "registry": settings.registry_external_host,
            "registry_insecure": settings.registry_insecure,
            "ref_str": chute.ref_str,
            "chutes_version": chute.chutes_version,
            "validator": settings.validator_ss58,
            "tee": chute.tee,
            "ports": ports,
            "disk_gb": DEFAULT_CPU_DISK_GB,
        },
    )
    logger.success(
        f"Dispatched deploy of chute {chute.chute_id} (config {config_id}) to server {server.server_id}"
    )


async def schedule_once() -> None:
    async with get_session() as session:
        cpu_chutes = (
            (
                await session.execute(
                    select(Chute)
                    .options(joinedload(Chute.image))
                    .where(Chute.node_selector["compute_type"].astext == "cpu")
                )
            )
            .unique()
            .scalars()
            .all()
        )
        if not cpu_chutes:
            return

        servers = (
            (
                await session.execute(
                    select(Server).where(
                        Server.compute_type == "cpu",
                        Server.self_registered.is_(True),
                        Server.is_tee.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not servers:
            return

        # A server is unavailable if it already runs an instance or has a deploy in flight
        # (an unverified, unfailed launch config). Single-tenant per CPU server.
        occupied = set(
            (
                await session.execute(
                    select(Instance.server_id).where(Instance.server_id.isnot(None))
                )
            )
            .scalars()
            .all()
        )
        occupied |= set(
            (
                await session.execute(
                    select(LaunchConfig.server_id).where(
                        LaunchConfig.server_id.isnot(None),
                        LaunchConfig.verified_at.is_(None),
                        LaunchConfig.failed_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

        for chute in cpu_chutes:
            if chute.disabled:
                continue
            ns = chute.node_selector or {}
            min_score = ns.get("min_benchmark_score") or 0
            req_cores = ns.get("cpu_cores") or 1
            req_ram = ns.get("ram_gb") or 1

            current = (
                await session.execute(
                    select(func.count(Instance.instance_id)).where(
                        Instance.chute_id == chute.chute_id
                    )
                )
            ).scalar() or 0
            if current >= await _target_count(chute.chute_id):
                continue

            for server in servers:
                if server.server_id in occupied:
                    continue
                if (server.benchmark_score or 0) < min_score:
                    continue
                if (server.cpu_cores or 0) < req_cores or (server.ram_gb or 0) < req_ram:
                    continue
                if not await is_agent_online(server.server_id):
                    continue
                await _dispatch_deploy(session, chute, server)
                occupied.add(server.server_id)
                break


async def main() -> None:
    logger.info("CPU chute scheduler starting")
    while True:
        try:
            await schedule_once()
        except Exception as exc:
            logger.error(f"CPU scheduler iteration failed: {exc}")
        await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
