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
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy import and_, func, select, text
from sqlalchemy.orm import joinedload

import api.database.orms  # noqa
from api.agent_channel import is_agent_online, send_agent_command
from api.chute.schemas import Chute
from api.config import settings
from api.database import get_session
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import create_launch_jwt_v2, purge_and_notify
from api.job.schemas import Job
from api.metagraph import MetagraphNode
from api.server.schemas import Host, Server
from api.util import semcomp

SCHEDULER_INTERVAL_SECONDS = 15
DEFAULT_CPU_DISK_GB = 10
# Distributed lock (mirrors chute_autoscaler's AUTOSCALER_LOCK_KEY pattern): two scheduler
# replicas double-dispatch deploys, so each tick runs under a redis SET NX lock and a replica
# that loses the race just skips its tick.
SCHEDULER_LOCK_KEY = "cpu_scheduler:lock"
SCHEDULER_LOCK_TTL = 120
# Age out scheduler-minted launch configs that were never verified: a TD that never boots, an
# image pull that hangs, or an agent that disconnected between the online check and pub/sub
# delivery would otherwise hold the chute at "pending >= target" and occupy its server forever.
# Generous enough for a cold TD boot + multi-GB image pull; failures normally resolve much
# sooner via the agent's deploy ack (see api.agent_channel.handle_agent_command_ack).
LAUNCH_CONFIG_EXPIRY_SECONDS = 900
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


def _server_fits(server: Server, req_cores: int, req_ram: int) -> bool:
    """Whether a CPU server satisfies a chute's cores/RAM request.

    Host-launched per-chute TDs (Model B, ``server.host_id`` set) are sized to the chute at launch,
    so require an EXACT vCPU match -- a small chute must not grab a larger chute's right-sized TD
    (which both wastes the big TD and starves the big chute). Standalone servers (Model A, e.g. a
    GCP Confidential VM whose vCPU count is fixed/miner-chosen) use ``>=`` so a chute requesting N
    cores can land on an idle >=N-core VM instead of being stranded forever waiting for an exact
    match that never appears (the in-VM benchmark reports the VM's real os.cpu_count()).
    """
    cores = server.cpu_cores or 0
    if server.host_id is not None:
        if cores != req_cores:
            return False
    elif cores < req_cores:
        return False
    return (server.ram_gb or 0) >= req_ram


def _job_ports(chute: Chute, method: str) -> list[dict]:
    """Ports a job declares (`@chute.job(ports=[...])`), as {port, proto}. The agent publishes each on
    the TD AND advertises it to the chute harness (CHUTES_PORT_<PROTO>_<port>) so the harness reports
    it in its activation port_mappings -- the validator checks those against the job's declared ports."""
    for job_def in chute.jobs or []:
        if job_def.get("name") == method:
            return [
                {"port": int(p["port"]), "proto": str(p.get("proto") or "tcp")}
                for p in (job_def.get("ports") or [])
                if p.get("port")
            ]
    return []


async def _dispatch_deploy(session, chute: Chute, server: Server, job: "Job" = None) -> None:
    """Place a chute (job=None) or a one-off job (job set) onto an attested CPU server.

    Jobs ride the SAME launch-config flow as cords via ``LaunchConfig.job_id``: the in-guest harness
    runs the job (not the cord server) because the activation response carries the job's
    method/data, and we forward the job's declared ports so the agent publishes them for owner-connect.
    """
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
        job_id=job.job_id if job else None,
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

    disk_gb = (
        int((job.job_args or {}).get("_disk_gb") or DEFAULT_CPU_DISK_GB)
        if job
        else DEFAULT_CPU_DISK_GB
    )
    token = create_launch_jwt_v2(
        launch_config,
        egress=chute.allow_external_egress,
        lock_modules=(
            True
            if chute.standard_template
            else (chute.lock_modules if chute.lock_modules is not None else False)
        ),
        disk_gb=disk_gb,
    )

    ports = {"primary": 8000, "logging": 8001}
    if semcomp(chute.chutes_version or "0.0.0", "0.6.0") >= 0:
        ports["attestation"] = 8002

    # Resolve the chute image's content digest validator-side (from the internal registry where the
    # forge signed it) so the agent pulls + cosign-verifies BY DIGEST -- a tag/registry swap then
    # cannot substitute a different image between schedule and run.
    image_digest = None
    try:
        from api.image.forge import get_image_digest

        image_digest = await get_image_digest(f"{settings.registry_host}/{_chute_image_ref(chute)}")
    except Exception as exc:
        logger.warning(f"Could not resolve image digest for chute {chute.chute_id}: {exc}")

    # TEE chutes MUST be digest-pinned: confidentiality relies on running exactly the measured/signed
    # image, so refuse to dispatch a TEE deploy we cannot pin (the agent also rejects an unpinned TEE
    # image, runner.py). Fail the just-minted launch config immediately -- left pending it would
    # occupy the server and count toward the chute's target for the whole expiry window.
    if chute.tee and not image_digest:
        logger.error(
            f"Refusing to deploy TEE chute {chute.chute_id} on {server.server_id}: could not "
            f"resolve an image_digest to pin (image {_chute_image_ref(chute)} not signed/pushed to "
            "the chutes registry?). Fix the image publish so the digest resolves, then retry."
        )
        await session.execute(
            text(
                "UPDATE launch_configs SET failed_at = NOW(), "
                "verification_error = 'TEE deploy refused: image digest could not be resolved' "
                "WHERE config_id = :config_id"
            ),
            {"config_id": config_id},
        )
        await session.commit()
        return

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
            "disk_gb": disk_gb,
            # CPU jobs only: container ports the agent must publish on the TD so the owner can reach
            # the job's services (e.g. JupyterLab :8888) over owner-connect. Empty for cord chutes.
            "job_ports": _job_ports(chute, job.method) if job else [],
        },
    )
    logger.success(
        f"Dispatched {'job ' + job.job_id if job else 'chute ' + chute.chute_id} "
        f"(config {config_id}) to server {server.server_id}"
    )


async def _hosts_running_chute(session, chute_id: str) -> set:
    """host_ids that already run (or are assigned) a TD for this chute. The node-agent keys TD
    slots by chute_id (one TD per chute per host), so additional instances/jobs of the same chute
    MUST land on different hosts -- re-dispatching to one of these hosts is a guaranteed
    "already deployed" no-op."""
    assigned = set(
        (
            await session.execute(
                select(Server.host_id)
                .join(Instance, Instance.server_id == Server.server_id)
                .where(Instance.chute_id == chute_id, Server.host_id.isnot(None))
            )
        )
        .scalars()
        .all()
    )
    assigned |= set(
        (
            await session.execute(
                select(Server.host_id)
                .join(LaunchConfig, LaunchConfig.server_id == Server.server_id)
                .where(
                    LaunchConfig.chute_id == chute_id,
                    LaunchConfig.verified_at.is_(None),
                    LaunchConfig.failed_at.is_(None),
                    Server.host_id.isnot(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return assigned


async def _launch_on_host(session, chute: Chute, req_cores: int, req_ram: int) -> bool:
    """Model B: ask an online L0 host with free capacity to launch a per-chute TD for ``chute``.

    The host's node-agent launches a fresh confidential VM; that TD self-registers as a CPU server
    (stamped with the host_id) and a subsequent scheduler tick places the chute on it via the normal
    deploy path. Returns True if a launch was dispatched.

    Host selection: skips hosts that already run/boot a TD for this chute (slots are keyed by
    chute_id host-side, so a duplicate dispatch is a no-op there -- multi-instance and multi-job
    demand for one chute MUST spread across hosts). In-flight launches are tracked per
    (chute, host) in redis so a booting TD isn't double-launched, while a second TD for the same
    chute can still boot concurrently on a different host. Per-host capacity = host.capacity
    minus the self-registered TDs stamped with that host_id minus its in-flight launches.
    """
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
    hosts_with_chute = await _hosts_running_chute(session, chute.chute_id)

    for host in hosts:
        if host.host_id in hosts_with_chute:
            continue
        inflight_key = f"mb:launch:{chute.chute_id}:{host.host_id}"
        if await settings.redis_client.exists(inflight_key):
            continue  # a TD for this chute is already booting on this host
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
        # Mark the (chute, host) launch + bump the host's in-flight count for the boot window.
        await settings.redis_client.set(inflight_key, host.host_id, ex=MB_LAUNCH_INFLIGHT_TTL)
        await settings.redis_client.incr(f"mb:host_inflight:{host.host_id}")
        await settings.redis_client.expire(f"mb:host_inflight:{host.host_id}", MB_LAUNCH_INFLIGHT_TTL)
        logger.success(
            f"Model B: dispatched per-chute TD launch for {chute.chute_id} to host {host.host_id} "
            f"({mem}/{vcpus}vcpu; host avail was {available})"
        )
        return True
    return False


async def expire_stale_launch_configs() -> None:
    """Fail scheduler-minted (server_id-stamped) launch configs that never verified.

    Never-claimed configs (agent vanished between dispatch and claim) expire after the base
    window; claimed-but-unverified configs (retrieved_at set: the TD is actively pulling/booting,
    possibly a multi-GB cold pull) get a doubled window before being declared dead so an
    in-flight verification isn't yanked out from under the agent. Scoped to server_id IS NOT
    NULL so the GPU launch-config flow (miner-side bookkeeping, its own JWT expiry) is untouched.
    """
    async with get_session() as session:
        result = await session.execute(
            text(
                "UPDATE launch_configs SET failed_at = NOW(), "
                "verification_error = 'expired: never verified within the scheduler window' "
                "WHERE server_id IS NOT NULL AND verified_at IS NULL AND failed_at IS NULL "
                "AND created_at < NOW() - make_interval(secs => :ttl) "
                "AND (retrieved_at IS NULL "
                "     OR created_at < NOW() - make_interval(secs => :claimed_ttl)) "
                "RETURNING config_id, chute_id, server_id"
            ),
            {
                "ttl": LAUNCH_CONFIG_EXPIRY_SECONDS,
                "claimed_ttl": LAUNCH_CONFIG_EXPIRY_SECONDS * 2,
            },
        )
        expired = result.all()
        await session.commit()
    for row in expired:
        logger.warning(
            f"Expired stale launch config {row.config_id} (chute={row.chute_id}, "
            f"server={row.server_id}): never verified within the scheduler window"
        )


async def schedule_once() -> None:
    async with get_session() as session:
        cpu_chutes = (
            (
                await session.execute(
                    select(Chute)
                    .options(joinedload(Chute.image))
                    .where(
                        Chute.node_selector["compute_type"].astext == "cpu",
                        # The 1-click path only runs confidential workloads: every config is
                        # minted env_type="tee" and the claim handler rejects a non-TEE chute
                        # (400), so placing one would just churn deploy -> reject -> expire.
                        Chute.tee.is_(True),
                    )
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
                        # Maintenance-mode servers (in_maintenance == pending window set) reject
                        # claims at the launch-config handler -- dispatching to them only
                        # manufactures failed configs.
                        Server.maintenance_pending_window_id.is_(None),
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
            # Job-only chutes (no cords) are NOT kept as always-on cord instances; they are launched
            # on demand by the job pass below (one per-job TD when a user creates a job).
            if not chute.cords:
                continue
            ns = chute.node_selector or {}
            min_score = ns.get("min_benchmark_score") or 0
            req_cores = ns.get("cpu_cores") or 1
            req_ram = ns.get("ram_gb") or 1

            # Version-aware placement (rolling updates): only current-version instances count
            # toward target, so `chutes deploy` of a new version places fresh instances instead of
            # letting the old version serve forever. Stale instances are retired once a
            # current-version instance is live (see below).
            chute_instances = (
                (
                    await session.execute(
                        select(Instance).where(Instance.chute_id == chute.chute_id)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
            current_instances = [i for i in chute_instances if i.version == chute.version]
            stale_instances = [i for i in chute_instances if i.version != chute.version]

            # Rolling retire: a live current-version instance exists -> the stale ones are
            # superseded; purging them dispatches their agent/TD teardown and frees the servers.
            if stale_instances and any(i.active and i.verified for i in current_instances):
                for inst in stale_instances:
                    logger.info(
                        f"Rolling update: retiring stale instance {inst.instance_id} of chute "
                        f"{chute.chute_id} (version {inst.version} -> {chute.version})"
                    )
                    await purge_and_notify(
                        inst, reason="rolling update - new chute version is live"
                    )
                stale_instances = []

            current = len(current_instances)
            # Count in-flight launch configs (placed on a TD but not yet verified/activated) toward
            # target too -- otherwise, while a TD is still pulling+booting the chute, the chute looks
            # under-target and we re-place/re-launch it, producing a duplicate TD (same server_id) whose
            # agent then fights the first one (flapping) and the chute never activates. Scoped to
            # scheduler-minted configs (server_id stamped): tokens minted via the public launch-config
            # endpoint must never block validator-owned placement.
            pending = (
                await session.execute(
                    select(func.count(LaunchConfig.config_id)).where(
                        LaunchConfig.chute_id == chute.chute_id,
                        LaunchConfig.server_id.isnot(None),
                        LaunchConfig.verified_at.is_(None),
                        LaunchConfig.failed_at.is_(None),
                    )
                )
            ).scalar() or 0
            if current + pending >= await _target_count(chute.chute_id):
                continue

            placed = False
            for server in servers:
                if server.server_id in occupied:
                    continue
                if (server.benchmark_score or 0) < min_score:
                    continue
                # Exact vCPU match for host-launched per-chute TDs (Model B), >= for standalone
                # servers (Model A / GCP) -- see _server_fits. This keeps a small chute from stealing
                # a larger right-sized TD while not stranding a chute on an idle larger GCP VM.
                if not _server_fits(server, req_cores, req_ram):
                    continue
                if not await is_agent_online(server.server_id):
                    continue
                await _dispatch_deploy(session, chute, server)
                occupied.add(server.server_id)
                placed = True
                break

            # Model B: no free attested CPU server for this chute -> ask an L0 host to launch a fresh
            # per-chute TD. It self-registers (stamped with host_id) and a later tick places the chute.
            launched = False
            if not placed:
                launched = await _launch_on_host(session, chute, req_cores, req_ram)

            # Rolling update with NO spare capacity anywhere: a new version can never place while
            # the stale instance holds the only server/TD. Replace in place, one instance per tick:
            # purge the oldest stale instance so its server frees and the next tick places the new
            # version there (bounded downtime instead of being stuck on the old version forever).
            if (
                not placed
                and not launched
                and stale_instances
                and not current_instances
                and pending == 0
            ):
                epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
                inst = min(stale_instances, key=lambda i: i.created_at or epoch)
                logger.warning(
                    f"Rolling update: no spare capacity for chute {chute.chute_id}; replacing "
                    f"stale instance {inst.instance_id} (version {inst.version} -> {chute.version}) in place"
                )
                await purge_and_notify(
                    inst, reason="rolling update - replacing outdated instance (no spare capacity)"
                )

        # --- CPU jobs: validator-scheduled (WE place them onto hosts; miners do NOT choose, unlike
        # the GPU job_created/miner_broadcast path). A job is a one-off workload that runs in its own
        # per-job TD. Place each pending job (unclaimed, no instance, no launch config yet) onto a free
        # attested server; else launch a fresh TD for it and a later tick places it. Shares the cord
        # pass's `occupied` set so a given TD runs exactly one workload.
        chute_map = {c.chute_id: c for c in cpu_chutes}
        pending_jobs = (
            (
                await session.execute(
                    select(Job)
                    # Only LIVE (non-failed) configs block a job: a config the ack handler /
                    # expiry sweep / TD reap marked failed must NOT strand the job forever --
                    # the scheduler is the only config minter for CPU jobs (no other miner can
                    # retry it, unlike the GPU launch-config flow), so failed attempts retry here.
                    .outerjoin(
                        LaunchConfig,
                        and_(
                            LaunchConfig.job_id == Job.job_id,
                            LaunchConfig.failed_at.is_(None),
                        ),
                    )
                    .where(
                        Job.chute_id.in_(list(chute_map.keys())),
                        Job.miner_hotkey.is_(None),
                        Job.instance_id.is_(None),
                        Job.finished_at.is_(None),
                        LaunchConfig.config_id.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        for job in pending_jobs:
            chute = chute_map.get(job.chute_id)
            if chute is None or chute.disabled:
                continue
            ns = chute.node_selector or {}
            min_score = ns.get("min_benchmark_score") or 0
            req_cores = ns.get("cpu_cores") or 1
            req_ram = ns.get("ram_gb") or 1
            placed = False
            for server in servers:
                if server.server_id in occupied:
                    continue
                if (server.benchmark_score or 0) < min_score:
                    continue
                # Exact vCPU match for host-launched per-chute TDs (Model B), >= for standalone
                # servers (Model A / GCP) -- see _server_fits. This keeps a small chute from stealing
                # a larger right-sized TD while not stranding a chute on an idle larger GCP VM.
                if not _server_fits(server, req_cores, req_ram):
                    continue
                if not await is_agent_online(server.server_id):
                    continue
                await _dispatch_deploy(session, chute, server, job=job)
                occupied.add(server.server_id)
                placed = True
                break
            if not placed:
                await _launch_on_host(session, chute, req_cores, req_ram)


async def _tick_with_lock() -> None:
    """Run one scheduler tick under the distributed lock (autoscaler_lock pattern: SET NX with
    TTL + value-checked release). A replica that loses the race skips its tick -- without this,
    two replicas double-dispatch every deploy."""
    lock_id = str(uuid.uuid4())
    acquired = await settings.redis_client.set(
        SCHEDULER_LOCK_KEY, lock_id, nx=True, ex=SCHEDULER_LOCK_TTL
    )
    if not acquired:
        logger.debug("CPU scheduler lock held by another replica; skipping tick")
        return
    try:
        await expire_stale_launch_configs()
        await schedule_once()
    finally:
        current = await settings.redis_client.get(SCHEDULER_LOCK_KEY)
        if current and (current.decode() if isinstance(current, bytes) else current) == lock_id:
            await settings.redis_client.delete(SCHEDULER_LOCK_KEY)


async def main() -> None:
    logger.info("CPU chute scheduler starting")
    while True:
        try:
            await _tick_with_lock()
        except Exception as exc:
            logger.error(f"CPU scheduler iteration failed: {exc}")
        await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
