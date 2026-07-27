"""
Server-side helpers for the 1-click CPU TEE agent control channel.

The validator pushes explicit, per-server commands (deploy/stop/scale) to a connected agent by
publishing to the ``agent_commands`` redis channel; the socket server (api/socket_server.py)
routes each command to the agent session keyed by ``server_id``. Agent liveness is tracked with a
short-TTL redis key refreshed by the agent's heartbeats, so the scheduler only assigns work to
servers that are currently connected.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from time import monotonic
from typing import Optional

import orjson as json
from loguru import logger
from sqlalchemy import select, text

from api.config import settings
from api.constants import AGENT_COMMAND_CHANNEL

_AGENT_ONLINE_KEY = "agent:online:{server_id}"
AGENT_ONLINE_TTL_SECONDS = 120
# command_id -> dispatch context (config_id etc.), so an agent's ack can be correlated back to
# the launch config it was deploying. TTL bounds growth if an agent never acks.
_AGENT_COMMAND_KEY = "agent:cmd:{command_id}"
_AGENT_COMMAND_STATUS_KEY = "agent:cmd-status:{command_id}"
AGENT_COMMAND_TTL_SECONDS = 7200
# Ack statuses that mean the command terminally failed agent-side (deploy never happened /
# launch failed / slot rejected), as emitted by chutes-agent/chutes-node-agent handlers.
FAILED_ACK_STATUSES = {"error", "rejected", "failed", "unhandled", "unknown_command"}


def _online_key(server_id: str) -> str:
    return _AGENT_ONLINE_KEY.format(server_id=server_id)


async def mark_agent_online(server_id: str, ttl: int = AGENT_ONLINE_TTL_SECONDS) -> None:
    """Refresh the liveness marker for a connected agent (called on auth + each heartbeat)."""
    await settings.redis_client.setex(_online_key(server_id), ttl, "1")


async def mark_agent_offline(server_id: str) -> None:
    """Clear the liveness marker (called on disconnect)."""
    await settings.redis_client.delete(_online_key(server_id))


async def is_agent_online(server_id: str) -> bool:
    """Whether an agent for this server is currently connected (within the heartbeat TTL)."""
    return bool(await settings.redis_client.exists(_online_key(server_id)))


async def send_agent_command(
    server_id: str,
    command: str,
    data: Optional[dict] = None,
    *,
    command_id: Optional[str] = None,
) -> str:
    """Publish an explicit command to a connected agent. Returns the generated command_id.

    The command is fanned out via redis pubsub; whichever socket-server replica holds the
    agent's session emits it to that session, others ignore it.
    """
    command_id = command_id or str(uuid.uuid4())
    payload = {
        "server_id": server_id,
        "command": command,
        "command_id": command_id,
        "data": data or {},
    }
    # Record the dispatch context so the agent's ack (which only carries command_id) can be
    # correlated back to the launch config -- a failed deploy ack marks it failed immediately
    # instead of waiting out the age-based expiry sweep.
    config_id = (data or {}).get("config_id")
    reservation_id = (data or {}).get("reservation_id") or (
        ((data or {}).get("reservation_claims") or {}).get("reservation_id")
        if isinstance((data or {}).get("reservation_claims"), dict)
        else None
    )
    context = {
        "server_id": server_id,
        "command": command,
    }
    if config_id:
        context["config_id"] = config_id
    if reservation_id:
        context["reservation_id"] = reservation_id
    status_key = _AGENT_COMMAND_STATUS_KEY.format(command_id=command_id)
    existing_status = await settings.redis_client.get(status_key)
    if existing_status:
        status_document = json.loads(existing_status)
        if (
            status_document.get("command_id") != command_id
            or status_document.get("server_id") != server_id
            or status_document.get("command") != command
        ):
            raise RuntimeError("agent command id is already bound to another command")
    else:
        await settings.redis_client.setex(
            status_key,
            AGENT_COMMAND_TTL_SECONDS,
            json.dumps(
                {
                    "command_id": command_id,
                    "server_id": server_id,
                    "command": command,
                    "status": "pending",
                    "detail": None,
                }
            ),
        )
    await settings.redis_client.setex(
        _AGENT_COMMAND_KEY.format(command_id=command_id),
        AGENT_COMMAND_TTL_SECONDS,
        json.dumps(context),
    )
    await settings.redis_client.publish(AGENT_COMMAND_CHANNEL, json.dumps(payload))
    return command_id


async def get_agent_command_status(
    server_id: str,
    command: str,
    command_id: str,
) -> Optional[dict]:
    raw = await settings.redis_client.get(_AGENT_COMMAND_STATUS_KEY.format(command_id=command_id))
    if not raw:
        return None
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or set(document) != {"command_id", "server_id", "command", "status", "detail"}
        or document.get("command_id") != command_id
        or document.get("server_id") != server_id
        or document.get("command") != command
        or not isinstance(document.get("status"), str)
        or not document["status"]
        or (document.get("detail") is not None and not isinstance(document.get("detail"), str))
    ):
        raise RuntimeError("agent command status is malformed or bound to another command")
    return document


async def wait_for_agent_command_ack(
    server_id: str,
    command: str,
    command_id: str,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.25,
) -> Optional[dict]:
    deadline = monotonic() + timeout_seconds
    while True:
        document = await get_agent_command_status(server_id, command, command_id)
        if document is not None and document["status"] != "pending":
            return document
        remaining = deadline - monotonic()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(poll_interval_seconds, remaining))


async def handle_agent_command_ack(server_id: str, ack: dict) -> None:
    """Process an agent's command acknowledgement (called by the socket server).

    A terminally-failed ack for a command that carried a config_id (deploy_chute) marks the
    launch config failed so the scheduler immediately stops counting it toward the chute's
    pending target and frees the server's occupancy, rather than waiting for the age-based
    expiry sweep. Successful acks just clear the correlation key.
    """
    command_id = (ack or {}).get("command_id")
    if not command_id:
        return
    key = _AGENT_COMMAND_KEY.format(command_id=command_id)
    try:
        raw = await settings.redis_client.get(key)
        if not raw:
            return
        context = json.loads(raw)
        # Bind the ack to the channel the command was dispatched to (the agent's server_id for
        # Model A, the host channel for Model B): only that session may consume the correlation
        # and fail the config.
        if server_id != context.get("server_id"):
            logger.warning(
                f"Ignoring ack for command {command_id} from {server_id}; it was "
                f"dispatched to {context.get('server_id')}"
            )
            return
        status = str((ack or {}).get("status") or "").lower()
        detail = (ack or {}).get("detail") or f"agent ack status={status}"
        await settings.redis_client.setex(
            _AGENT_COMMAND_STATUS_KEY.format(command_id=command_id),
            AGENT_COMMAND_TTL_SECONDS,
            json.dumps(
                {
                    "command_id": command_id,
                    "server_id": server_id,
                    "command": context.get("command"),
                    "status": status or "unknown",
                    "detail": str(detail),
                }
            ),
        )
        await settings.redis_client.delete(key)
        reservation_id = context.get("reservation_id")
        if reservation_id and context.get("command") in {"launch_gpu", "delete_gpu"}:
            from api.database import get_session
            from api.host.gpu_allocations import record_gpu_command_ack

            async with get_session() as session:
                await record_gpu_command_ack(
                    session,
                    reservation_id,
                    command=context["command"],
                    command_id=command_id,
                    status=status or "unknown",
                    detail=str(detail),
                )
                await session.commit()
            return
        if status not in FAILED_ACK_STATUSES:
            return
        config_id = context.get("config_id")
        from api.database import get_session
        from api.host.schemas import TdLaunchReservation
        from api.server.schemas import Server

        teardown = None
        async with get_session() as session:
            result = None
            if config_id:
                result = await session.execute(
                    text(
                        "UPDATE launch_configs SET failed_at = NOW(), verification_error = :error "
                        "WHERE config_id = :config_id AND verified_at IS NULL AND failed_at IS NULL"
                    ),
                    {
                        "config_id": config_id,
                        "error": f"agent deploy failed: {detail}"[:500],
                    },
                )
            reservation_id = context.get("reservation_id")
            if reservation_id:
                await session.execute(
                    text(
                        "UPDATE td_launch_reservations SET invalidated_at = NOW() "
                        "WHERE reservation_id = :reservation_id "
                        "AND consumed_at IS NULL AND invalidated_at IS NULL"
                    ),
                    {"reservation_id": reservation_id},
                )
            if config_id:
                server = await session.get(Server, server_id)
                if server is not None and server.host_id and server.launch_reservation_id:
                    reservation = await session.get(
                        TdLaunchReservation, server.launch_reservation_id
                    )
                    if reservation is not None:
                        teardown = (
                            server.host_id,
                            reservation.chute_id,
                            server.server_id,
                        )
            await session.commit()
        if teardown is not None:
            host_id, chute_id, td_server_id = teardown
            await send_agent_command(
                host_id,
                "delete_chute",
                {
                    "chute_id": chute_id,
                    "server_id": td_server_id,
                    "reason": "terminal in-TD deploy failure",
                },
            )
        if result is not None and result.rowcount:
            logger.warning(
                f"Marked launch config {config_id} failed from agent ack "
                f"(server_id={server_id}, command={context.get('command')}, detail={detail})"
            )
    except Exception as exc:
        logger.error(f"Failed to process agent command ack {command_id}: {exc}")


async def send_instance_teardown(
    chute_id: str,
    instance_id: Optional[str] = None,
    server_id: Optional[str] = None,
    config_id: Optional[str] = None,
) -> Optional[str]:
    """Tear down the agent-run workload behind a deleted CPU TEE instance.

    Only 1-click CPU instances carry a ``server_id`` (GPU instances link via Node rows and are
    undeployed by the miner control plane on miner_broadcast), so a missing server_id is a no-op.

    Targeting by model:
      * Model A (standalone VM, ``server.host_id`` is NULL): the agent session is keyed by
        server_id -> ``stop_instance`` stops the chute container (keyed by config_id).
      * Model B (per-chute TD on an L0 host): the node-agent session is keyed by host_id ->
        ``delete_chute`` tears down the whole TD and frees the slot.
      * Server row already reaped: best-effort ``stop_instance`` on the server_id channel (the
        reconcile loop cleans up anything left behind).

    Best-effort by design: callers sit on deletion paths that must never fail because an agent
    is offline, so errors are logged and swallowed. Returns the command_id or None.
    """
    if not server_id:
        return None
    try:
        from api.database import get_session
        from api.server.schemas import Server

        async with get_session() as session:
            server = (
                await session.execute(select(Server).where(Server.server_id == server_id))
            ).scalar_one_or_none()
        if server is not None and not getattr(server, "self_registered", False):
            return None
        if (
            server is not None
            and getattr(server, "compute_type", None) == "gpu"
            and getattr(server, "gpu_management_mode", None) == "platform"
            and getattr(server, "gpu_launch_reservation_id", None)
        ):
            return await send_gpu_reservation_teardown(
                server.gpu_launch_reservation_id,
                reason=f"instance teardown: {instance_id or config_id or chute_id}",
            )
        if server is not None and getattr(server, "compute_type", None) == "gpu":
            # Miner-managed GPU workloads retain the existing Gepetto event lifecycle.
            return None
        host_id = getattr(server, "host_id", None) if server is not None else None
        if host_id:
            command_id = await send_agent_command(
                host_id,
                "delete_chute",
                {
                    "chute_id": chute_id,
                    "instance_id": instance_id,
                    "server_id": server_id,
                },
            )
        else:
            command_id = await send_agent_command(
                server_id,
                "stop_instance",
                {
                    "chute_id": chute_id,
                    "instance_id": instance_id,
                    "config_id": config_id,
                },
            )
        logger.info(
            f"Dispatched teardown for instance {instance_id} of chute {chute_id} "
            f"(server_id={server_id}, host_id={host_id}, command_id={command_id})"
        )
        return command_id
    except Exception as exc:
        logger.warning(
            f"Failed to dispatch teardown for instance {instance_id} of chute {chute_id} "
            f"(server_id={server_id}): {exc}"
        )
        return None


async def send_gpu_reservation_teardown(
    reservation_id: str,
    *,
    reason: str,
    operation_type: Optional[str] = None,
) -> Optional[str]:
    """Request and retry one exact platform GPU reset command safely."""

    try:
        from api.database import get_session
        from api.gpu_lifecycle_service import (
            ensure_reservation_lifecycle_operation,
        )
        from api.host.gpu_allocations import (
            record_gpu_command_dispatch,
            request_gpu_teardown,
        )
        from api.host.locks import assert_gpu_external_work_allowed

        async with get_session() as session:
            reservation = await request_gpu_teardown(
                session,
                reservation_id,
                reason=reason,
                operation_type=operation_type,
            )
            host_id = reservation.host_id
            state = reservation.state
            if state in {"released", "expired"}:
                await session.commit()
                return None
            operation = await ensure_reservation_lifecycle_operation(
                session,
                reservation_id,
                operation_type=operation_type,
            )
            if operation.phase != "intent":
                await session.commit()
                return None
            command_id = reservation.teardown_command_id or str(uuid.uuid4())
            await record_gpu_command_dispatch(
                session,
                reservation_id,
                command="delete_gpu",
                command_id=command_id,
            )
            await session.commit()
            assert_gpu_external_work_allowed(
                session,
                "durable GPU lifecycle command dispatch",
            )
        command_id = await send_agent_command(
            host_id,
            "delete_gpu",
            {
                "reservation_id": reservation_id,
                "lifecycle_operation": operation.model_dump(
                    mode="json", exclude_none=True
                ),
                "reason": reason,
            },
            command_id=command_id,
        )
        logger.info(
            f"Dispatched exact GPU teardown reservation={reservation_id} "
            f"host={host_id} command_id={command_id}"
        )
        return command_id
    except Exception as exc:
        logger.warning(f"Failed to dispatch GPU reservation teardown {reservation_id}: {exc}")
        return None


# Reconcile grace periods: never act on rows/workloads younger than these, so the 30s heartbeat
# cadence cannot race a dispatch (deploy sent, container/TD not yet up) or a TD's boot+register
# window into a false teardown/reap.
INSTANCE_MISSING_GRACE_SECONDS = 120
SERVER_REAP_GRACE_SECONDS = 300


async def handle_agent_status(server_id: str, data) -> None:
    """Reconcile validator state against an agent heartbeat (gepetto's reconcile, validator-side).

    Model A heartbeats carry ``containers`` (running chute container config_ids, from podman);
    Model B heartbeats carry ``slots`` (active per-chute TD slots on the L0 host). Either
    direction of drift is corrected:
      * validator thinks a workload exists but the agent no longer runs it -> purge the instance
        (and for Model B, reap the dead TD's Server row so host capacity frees);
      * the agent still runs a workload the validator no longer knows -> dispatch its teardown.

    Older agents send bare liveness heartbeats (no inventory) -- those reconcile nothing.
    Best-effort: a reconcile failure must never take down the socket server's event handler.
    """
    if not isinstance(data, dict):
        return
    try:
        if "slots" in data:
            await _reconcile_host_slots(server_id, data.get("slots") or [])
            # Fleet releases: record the guest-image digests + running L0 version the host reports
            # (for the release convergence status). Best-effort; never let it break the reconcile.
            if "staged_images" in data or "l0_version" in data:
                await _persist_host_staged_images(
                    server_id, data.get("staged_images"), data.get("l0_version")
                )
        elif "containers" in data:
            await _reconcile_server_containers(server_id, data.get("containers") or [])
    except Exception as exc:
        logger.error(f"Heartbeat reconcile failed for {server_id}: {exc}")


async def _persist_host_staged_images(host_id: str, staged, l0_version=None) -> None:
    """Persist the host's reported staged guest-image digests + running L0 version (release status)."""
    if not isinstance(staged, dict) and not l0_version:
        return
    from api.database import get_session
    from api.server.schemas import Host

    async with get_session() as session:
        host = await session.get(Host, host_id)
        if host is None:
            return
        changed = False
        if isinstance(staged, dict) and host.staged_images != staged:
            host.staged_images = staged
            changed = True
        if l0_version and host.l0_version != l0_version:
            host.l0_version = l0_version
            changed = True
        if changed:
            await session.commit()


def _older_than(created_at, seconds: int) -> bool:
    """True when a timestamped row is old enough to act on (unknown ages are NOT acted on)."""
    if created_at is None:
        return False
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return (now - created_at).total_seconds() > seconds


async def _reconcile_server_containers(server_id: str, containers: list) -> None:
    """Model A: reconcile a standalone VM's running chute containers against validator state."""
    from api.database import get_session
    from api.instance.schemas import Instance, LaunchConfig
    from api.instance.util import purge_and_notify

    reported = {str(c) for c in containers if c}
    async with get_session() as session:
        instances = (
            (await session.execute(select(Instance).where(Instance.server_id == server_id)))
            .unique()
            .scalars()
            .all()
        )
        pending_config_ids = set(
            (
                await session.execute(
                    select(LaunchConfig.config_id).where(
                        LaunchConfig.server_id == server_id,
                        LaunchConfig.verified_at.is_(None),
                        LaunchConfig.failed_at.is_(None),
                        LaunchConfig.completed_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

    # Validator -> agent drift: an instance whose container is gone (crashed/stopped) is dead --
    # purge it so traffic stops routing there and the server frees for re-placement.
    for instance in instances:
        if instance.config_id in reported:
            continue
        if not _older_than(instance.created_at, INSTANCE_MISSING_GRACE_SECONDS):
            continue
        logger.warning(
            f"Reconcile: agent {server_id} no longer runs container for instance "
            f"{instance.instance_id} (config {instance.config_id}); purging"
        )
        await purge_and_notify(instance, reason="reconcile - agent reports chute container gone")

    # Agent -> validator drift: a running container with neither an instance nor a live launch
    # config (purged while the agent was offline, or its config expired) is an orphan -- stop it.
    known = {i.config_id for i in instances} | pending_config_ids
    for config_id in reported - known:
        logger.warning(
            f"Reconcile: agent {server_id} runs orphan container chute-{config_id}; stopping"
        )
        await send_agent_command(server_id, "stop_instance", {"config_id": config_id})


async def _reconcile_host_slots(host_id: str, slots: list) -> None:
    """Model B: reconcile an L0 host's active TD slots against validator state."""
    from api.chute.schemas import Chute
    from api.database import get_session
    from api.instance.schemas import Instance
    from api.instance.util import purge_and_notify
    from api.server.schemas import Server

    reported = {
        str(s.get("server_id")): dict(s)
        for s in slots
        if isinstance(s, dict) and s.get("server_id")
    }

    async with get_session() as session:
        servers = (
            (
                await session.execute(
                    select(Server).where(
                        Server.host_id == host_id,
                        Server.self_registered.is_(True),
                        # ChuteFS: the always-on storage TD is launched by the node-agent at boot and
                        # is NOT a scheduled chute slot, so it never appears in the slot heartbeat.
                        # Exempt it from reaping or the reconcile loop would tear it down every tick.
                        Server.storage_role.is_(False),
                        Server.gpu_retired_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

    # Validator -> host drift: a Server row whose TD the host no longer runs (upgrade_image
    # teardown, host reboot, manual stop) would otherwise count against host capacity forever.
    for server in servers:
        if server.server_id in reported:
            slot = reported[server.server_id]
            if getattr(server, "compute_type", None) == "gpu" and (
                slot.get("compute_type") != "gpu"
                or slot.get("management_mode") != server.gpu_management_mode
                or slot.get("reservation_id") != server.gpu_launch_reservation_id
                or slot.get("allocation_group_id") != server.gpu_allocation_group_id
                or slot.get("allocation_group_generation") != server.gpu_allocation_group_generation
                or slot.get("process_incarnation") != server.gpu_process_incarnation
                or slot.get("topology_fingerprint") != server.gpu_topology_fingerprint
            ):
                from api.host.gpu_allocations import (
                    quarantine_gpu_reservation_control_plane,
                )

                async with get_session() as session:
                    await quarantine_gpu_reservation_control_plane(
                        session,
                        server.gpu_launch_reservation_id,
                        code="gpu_slot_heartbeat_lineage_mismatch",
                        reason="GPU slot heartbeat differs from its attested reservation lineage.",
                        metadata={"slot": slot},
                    )
                    await session.commit()
            continue
        if not _older_than(server.created_at, SERVER_REAP_GRACE_SECONDS):
            continue
        if getattr(server, "compute_type", None) == "gpu" and getattr(
            server, "gpu_launch_reservation_id", None
        ):
            from api.host.gpu_allocations import (
                quarantine_gpu_reservation_control_plane,
            )

            async with get_session() as session:
                await quarantine_gpu_reservation_control_plane(
                    session,
                    server.gpu_launch_reservation_id,
                    code="gpu_process_missing_without_reset",
                    reason=(
                        "GPU host heartbeat omitted a reservation-owned process without "
                        "exact reset proof."
                    ),
                )
                await session.commit()
            continue
        logger.warning(
            f"Reconcile: host {host_id} no longer runs TD {server.server_id}; reaping its "
            "server row (+ purging its instances / failing its pending launch configs)"
        )
        async with get_session() as session:
            instances = (
                (
                    await session.execute(
                        select(Instance).where(Instance.server_id == server.server_id)
                    )
                )
                .unique()
                .scalars()
                .all()
            )
        for instance in instances:
            await purge_and_notify(
                instance,
                reason="reconcile - backing per-chute TD no longer exists on host",
            )
        async with get_session() as session:
            from api.server.service import delete_server

            await delete_server(session, server.server_id, server.miner_hotkey)

    # Host -> validator drift: a TD still running for a chute the validator no longer wants
    # (chute deleted while the host was offline / TD never registered within its boot window).
    for slot_server_id, slot_data in reported.items():
        slot_chute_id = str(slot_data.get("chute_id") or "")
        slot_compute_type = slot_data.get("compute_type")
        slot_reservation_id = slot_data.get("reservation_id")
        async with get_session() as session:
            server_exists = (
                await session.execute(
                    select(Server.server_id).where(Server.server_id == slot_server_id)
                )
            ).scalar_one_or_none()
            chute_exists = (
                (
                    await session.execute(
                        select(Chute.chute_id).where(Chute.chute_id == slot_chute_id)
                    )
                ).scalar_one_or_none()
                if slot_chute_id
                and not (slot_compute_type == "gpu" and slot_data.get("management_mode") == "miner")
                else None
            )
            if slot_compute_type == "gpu" and slot_data.get("management_mode") == "miner":
                chute_exists = slot_chute_id
        if slot_chute_id and chute_exists is None:
            logger.warning(
                f"Reconcile: host {host_id} runs TD {slot_server_id} for deleted chute "
                f"{slot_chute_id}; tearing down"
            )
            if slot_compute_type == "gpu":
                if slot_reservation_id:
                    await send_gpu_reservation_teardown(
                        slot_reservation_id,
                        reason="slot references a deleted GPU chute",
                    )
                else:
                    logger.error(
                        f"Refusing ownerless raw GPU delete for slot {slot_server_id}; "
                        "explicit inventory-bound recovery is required"
                    )
            else:
                await send_agent_command(
                    host_id,
                    "delete_chute",
                    {"chute_id": slot_chute_id, "server_id": slot_server_id},
                )
            continue
        if server_exists is None and slot_chute_id:
            # No Server row: either the TD is still booting/registering (launch in-flight, keyed
            # per chute+host by the scheduler) or it failed to register within the launch window
            # and will never be schedulable.
            from api.host.schemas import GpuLaunchReservation, TdLaunchReservation

            async with get_session() as reservation_session:
                if slot_compute_type == "gpu":
                    active_reservation = (
                        await reservation_session.execute(
                            select(GpuLaunchReservation.reservation_id).where(
                                GpuLaunchReservation.reservation_id == slot_reservation_id,
                                GpuLaunchReservation.host_id == host_id,
                                GpuLaunchReservation.server_id == slot_server_id,
                                GpuLaunchReservation.state.in_(
                                    {"claimed", "launching", "running", "resetting"}
                                ),
                            )
                        )
                    ).scalar_one_or_none()
                else:
                    active_reservation = (
                        await reservation_session.execute(
                            select(TdLaunchReservation.reservation_id).where(
                                TdLaunchReservation.host_id == host_id,
                                TdLaunchReservation.chute_id == slot_chute_id,
                                TdLaunchReservation.server_id == slot_server_id,
                                TdLaunchReservation.consumed_at.is_(None),
                                TdLaunchReservation.invalidated_at.is_(None),
                                TdLaunchReservation.expires_at > datetime.now(timezone.utc),
                            )
                        )
                    ).scalar_one_or_none()
            if active_reservation is not None:
                continue
            logger.warning(
                f"Reconcile: host {host_id} TD {slot_server_id} (chute {slot_chute_id}) never "
                "self-registered within the launch window; tearing down"
            )
            if slot_compute_type == "gpu":
                if slot_reservation_id:
                    await send_gpu_reservation_teardown(
                        slot_reservation_id,
                        reason="GPU guest never established validator server lineage",
                    )
                else:
                    logger.error(
                        f"Refusing ownerless raw GPU delete for slot {slot_server_id}; "
                        "explicit inventory-bound recovery is required"
                    )
            else:
                await send_agent_command(
                    host_id,
                    "delete_chute",
                    {"chute_id": slot_chute_id, "server_id": slot_server_id},
                )


async def send_job_instance_teardown(instance_id: Optional[str]) -> Optional[str]:
    """Dispatch a teardown for a job's instance, resolving the (possibly already purged) row.

    Used on job deletion. A missing instance row is a no-op (the instance purge path already
    dispatched its teardown). When a purge and a job deletion overlap -- purge() notifies
    before committing its instance DELETE, so this helper's fresh session can still see the
    row -- both paths may dispatch; that is harmless by design, because the agents treat
    stop/delete for an absent workload as a no-op ack.
    """
    if not instance_id:
        return None
    try:
        from api.database import get_session
        from api.instance.schemas import Instance

        async with get_session() as session:
            instance = (
                await session.execute(
                    select(Instance.chute_id, Instance.server_id, Instance.config_id).where(
                        Instance.instance_id == instance_id
                    )
                )
            ).first()
        if instance is None:
            return None
        return await send_instance_teardown(
            instance.chute_id,
            instance_id=instance_id,
            server_id=instance.server_id,
            config_id=instance.config_id,
        )
    except Exception as exc:
        logger.warning(f"Failed to dispatch job-instance teardown for {instance_id}: {exc}")
        return None
