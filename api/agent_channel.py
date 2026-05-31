"""
Server-side helpers for the 1-click CPU TEE agent control channel.

The validator pushes explicit, per-server commands (deploy/stop/scale) to a connected agent by
publishing to the ``agent_commands`` redis channel; the socket server (api/socket_server.py)
routes each command to the agent session keyed by ``server_id``. Agent liveness is tracked with a
short-TTL redis key refreshed by the agent's heartbeats, so the scheduler only assigns work to
servers that are currently connected.
"""

import uuid
from typing import Optional

import orjson as json

from api.config import settings

AGENT_COMMAND_CHANNEL = "agent_commands"
_AGENT_ONLINE_KEY = "agent:online:{server_id}"
AGENT_ONLINE_TTL_SECONDS = 120


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
    server_id: str, command: str, data: Optional[dict] = None
) -> str:
    """Publish an explicit command to a connected agent. Returns the generated command_id.

    The command is fanned out via redis pubsub; whichever socket-server replica holds the
    agent's session emits it to that session, others ignore it.
    """
    command_id = str(uuid.uuid4())
    payload = {
        "server_id": server_id,
        "command": command,
        "command_id": command_id,
        "data": data or {},
    }
    await settings.redis_client.publish(AGENT_COMMAND_CHANNEL, json.dumps(payload))
    return command_id
