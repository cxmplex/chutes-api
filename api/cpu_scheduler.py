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
from api.server.schemas import Host, Server
from api.util import semcomp

SCHEDULER_INTERVAL_SECONDS = 15
DEFAULT_CPU_DISK_GB = 10
# Model B: how long to consider a per-chute TD launch "in flight" (boot + self-register window),
# so the scheduler does not re-launch the same chute on another host while its TD comes up.
MB_LAUNCH_INFLIGHT_TTL = 300
# Model B: a per-chute TD is a full confidential VM -- the guest OS (systemd, docker/podman, the
# attestation service + agent) needs headroom ON TOP of the chute's own RAM request, or the chute
# container is OOM-killed inside the TD. Size the TD = chute RAM + this overhead (mirrors Model-A
# single-VM servers, which run ~8G for a 4G chute).
MB_TD_MEM_OVERHEAD_GB = 4


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

    # Resolve the chute image's content digest validator-side (from the internal registry where the
    # forge signed it) so the agent pulls + cosign-verifies BY DIGEST -- a tag/registry swap then
    # cannot substitute a different image between schedule and run. Best-effort: a non-resolvable
    # image (not signed/pushed to the chutes registry) deploys with cosign-only verification rather
    # than being blocked; cosign against the baked key remains the primary anchor either way.
    image_digest = None
    try:
        from api.image.forge import get_image_digest

        image_digest = await get_image_digest(f"{settings.registry_host}/{_chute_image_ref(chute)}")
    except Exception as exc:
        logger.warning(
            f"Could not resolve image digest for chute {chute.chute_id}; "
            f"deploying with cosign-only verification: {exc}"
        )

    await send_agent_command(
        server.server_id,
        "deploy_chute",
        {
            "chute_id": chute.chute_id,
            "version": chute.version,
            "config_id": config_id,
            "token": token,
            "image": _chute_image_ref(chute),
            "image_digest": image_digest,
            "registry": settings.registry_external_host,
            "registry_insecure": settings.registry_insecure,
            "ref_str": chute.ref_str,
            "chutes_version": chute.chutes_version,
            "validator": settings.validator_ss58,
            "tee": chute.tee,
            "ports": ports,
            # Model B: when the TD is reached via the L0 host's DNAT, advertise the externally
            # reachable ports (the container still publishes + the chute still binds the internal
            # ports above). None for standalone single-VM servers (external == internal).
            "external_ports": server.external_ports,
            "disk_gb": DEFAULT_CPU_DISK_GB,
        },
    )
    logger.success(
        f"Dispatched deploy of chute {chute.chute_id} (config {config_id}) to server {server.server_id}"
    )


async def _launch_on_host(session, chute: Chute, req_cores: int, req_ram: int) -> bool:
    """Model B: ask an online L0 host with free capacity to launch a per-chute TD for ``chute``.

    The host's node-agent launches a fresh confidential VM; that TD self-registers as a CPU server
    (stamped with the host_id) and a subsequent scheduler tick places the chute on it via the normal
    deploy path. Returns True if a launch was dispatched. Per-chute in-flight is tracked in redis so
    we launch exactly one TD per unmet demand while it boots; per-host capacity = host.capacity minus
    the self-registered TDs already stamped with that host_id minus its in-flight launches.
    """
    inflight_key = f"mb:launch:{chute.chute_id}"
    if await settings.redis_client.exists(inflight_key):
        return False  # a TD for this chute is already booting/registering

    hosts = (
        (await session.execute(select(Host))).scalars().all()
    )
    if not hosts:
        return False

    # Self-registered TDs already attributed to each host (durable per-host usage).
    used_rows = (
        await session.execute(
            select(Server.host_id, func.count(Server.server_id))
            .where(Server.host_id.isnot(None), Server.self_registered.is_(True))
            .group_by(Server.host_id)
        )
    ).all()
    used_by_host = {hid: cnt for hid, cnt in used_rows}

    for host in hosts:
        host_inflight = int(await settings.redis_client.get(f"mb:host_inflight:{host.host_id}") or 0)
        available = (host.capacity or 0) - used_by_host.get(host.host_id, 0) - host_inflight
        if available <= 0:
            continue
        if not await is_agent_online(host.host_id):
            continue
        mem = f"{req_ram + MB_TD_MEM_OVERHEAD_GB}G" if req_ram else (host.default_mem or "8G")
        vcpus = req_cores or host.default_vcpus or 4
        await send_agent_command(
            host.host_id,
            "deploy_chute",
            {"chute_id": chute.chute_id, "mem": mem, "vcpus": vcpus},
        )
        # Mark the chute launch + bump the host's in-flight count for the boot window.
        await settings.redis_client.set(inflight_key, host.host_id, ex=MB_LAUNCH_INFLIGHT_TTL)
        await settings.redis_client.incr(f"mb:host_inflight:{host.host_id}")
        await settings.redis_client.expire(f"mb:host_inflight:{host.host_id}", MB_LAUNCH_INFLIGHT_TTL)
        logger.success(
            f"Model B: dispatched per-chute TD launch for {chute.chute_id} to host {host.host_id} "
            f"({mem}/{vcpus}vcpu; host avail was {available})"
        )
        return True
    return False


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
        # Note: do NOT bail on empty servers -- Model B can still launch per-chute TDs on L0 hosts.

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

            placed = False
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
                placed = True
                break

            # Model B: no free attested CPU server for this chute -> ask an L0 host to launch a fresh
            # per-chute TD. It self-registers (stamped with host_id) and a later tick places the chute.
            if not placed:
                await _launch_on_host(session, chute, req_cores, req_ram)


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
