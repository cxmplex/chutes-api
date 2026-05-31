"""
Socket.IO poowered websocket server for continuous bi-directional vali/miner comms.
"""

import asyncio
import socketio
import orjson
import api.constants as cst
from typing import Dict
from loguru import logger
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select
import api.database.orms  # noqa
from api.config import settings
from api.database import get_session
from api.server.schemas import Server
from api.user.router import get_current_user
from api.socket_shared import SyntheticRequest
from api.redis_pubsub import RedisListener, AgentCommandListener
from api.agent_channel import mark_agent_online, mark_agent_offline

SERVER_ID_HEADER = "X-Chutes-Server-Id"

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
fastapi_app = FastAPI()
app = socketio.ASGIApp(sio, fastapi_app)
sio.session_map = {}
sio.reverse_map = {}
# 1-click CPU TEE agent sessions: server_id -> session_id, and session_id -> {hotkey, server_id}.
sio.agent_sessions = {}
sio.agent_meta = {}


@fastapi_app.on_event("startup")
async def initialize_socket_app():
    """
    Start our redis subscriber when the server starts.
    """
    fastapi_app.state.redis_listener = RedisListener(sio, "miner_broadcast")
    asyncio.create_task(fastapi_app.state.redis_listener.start())
    fastapi_app.state.agent_listener = AgentCommandListener(sio, "agent_commands")
    asyncio.create_task(fastapi_app.state.agent_listener.start())


@fastapi_app.on_event("shutdown")
async def shutdown():
    """
    Shut down the redis listeners when the app shuts down.
    """
    if hasattr(fastapi_app.state, "redis_listener"):
        await fastapi_app.state.redis_listener.stop()
    if hasattr(fastapi_app.state, "agent_listener"):
        await fastapi_app.state.agent_listener.stop()


@sio.event
async def connect(session_id: str, _):
    """
    New connection established.
    """
    logger.info(f"New socket.io connection from {session_id=}")


@sio.event
async def disconnect(session_id):
    """
    Client disconnect.
    """
    if (hotkey := sio.session_map.pop(session_id, None)) is not None:
        sio.reverse_map.pop(hotkey, None)
        logger.info(f"Disconnected authenticated miner: {hotkey}")
    if (meta := sio.agent_meta.pop(session_id, None)) is not None:
        server_id = meta["server_id"]
        if sio.agent_sessions.get(server_id) == session_id:
            sio.agent_sessions.pop(server_id, None)
        await mark_agent_offline(server_id)
        logger.info(f"Disconnected 1-click agent: server_id={server_id}")


@sio.event
async def authenticate(session_id: str, headers: Dict[str, str]) -> bool:
    """
    Authentication request from a client (miner).  Headers here aren't
    really headers since this is socket.io, but we'll treat them as such.
    """
    try:
        request = SyntheticRequest(headers)
        _ = await get_current_user(
            raise_not_found=False, registered_to=settings.netuid, purpose="sockets"
        )(
            request=request,
            hotkey=headers.get(cst.HOTKEY_HEADER),
            signature=headers.get(cst.SIGNATURE_HEADER),
            nonce=headers.get(cst.NONCE_HEADER),
        )
        hotkey = headers.get(cst.HOTKEY_HEADER)
        logger.info(f"Successfully authenticated miner {hotkey=}, {session_id=}")
        sio.session_map[session_id] = hotkey
        sio.reverse_map[hotkey] = session_id
        await sio.emit("auth_success", {"message": "Authenticated"}, to=session_id)
        return True
    except HTTPException as e:
        error_msg = f"Authentication failed: {e.detail}"
        logger.warning(error_msg)
        await sio.emit("auth_failed", {"error": error_msg}, to=session_id)
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        await sio.emit("auth_failed", {"error": error_msg}, to=session_id)
    await sio.disconnect(session_id)
    return False


@sio.event
async def miner_message(session_id, data):
    """
    Placeholder for miner originated messages, not really used (yet).
    """
    if (hotkey := sio.session_map.get(session_id)) is None:
        logger.warning(f"Unauthenticated message from {session_id}")
        await sio.disconnect(session_id)
        return
    logger.debug(f"Received message from miner {hotkey=}: {data=}")


@sio.event
async def agent_authenticate(session_id: str, headers: Dict[str, str]) -> bool:
    """
    Authentication for a 1-click CPU TEE server agent.

    Verifies the owning miner's hotkey signature (purpose "sockets", same scheme as miners) and
    that the supplied server id is a self-registered server belonging to that miner, then binds
    this socket session to the server id so the validator can push commands to it.
    """
    try:
        request = SyntheticRequest(headers)
        await get_current_user(
            raise_not_found=False, registered_to=settings.netuid, purpose="sockets"
        )(
            request=request,
            hotkey=headers.get(cst.HOTKEY_HEADER),
            signature=headers.get(cst.SIGNATURE_HEADER),
            nonce=headers.get(cst.NONCE_HEADER),
        )
        hotkey = headers.get(cst.HOTKEY_HEADER)
        server_id = headers.get(SERVER_ID_HEADER)
        if not server_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Missing server id header"
            )
        async with get_session() as session:
            server = (
                await session.execute(
                    select(Server).where(
                        Server.server_id == server_id,
                        Server.miner_hotkey == hotkey,
                        Server.self_registered.is_(True),
                    )
                )
            ).scalar_one_or_none()
        if server is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Server {server_id} is not a self-registered server for {hotkey}",
            )
        sio.agent_sessions[server_id] = session_id
        sio.agent_meta[session_id] = {"hotkey": hotkey, "server_id": server_id}
        await mark_agent_online(server_id)
        logger.success(
            f"Authenticated 1-click agent: server_id={server_id} hotkey={hotkey} session={session_id}"
        )
        await sio.emit(
            "auth_success", {"message": "Authenticated", "server_id": server_id}, to=session_id
        )
        return True
    except HTTPException as e:
        logger.warning(f"Agent authentication failed: {e.detail}")
        await sio.emit("auth_failed", {"error": f"Authentication failed: {e.detail}"}, to=session_id)
    except Exception as e:
        logger.error(f"Unexpected error authenticating agent: {e}")
        await sio.emit("auth_failed", {"error": f"Unexpected error: {e}"}, to=session_id)
    await sio.disconnect(session_id)
    return False


@sio.event
async def agent_status(session_id: str, data) -> None:
    """
    Heartbeat / status update from a connected agent. Refreshes the liveness marker so the
    scheduler keeps treating the server as online; capacity/instance status rides along for
    later phases.
    """
    meta = sio.agent_meta.get(session_id)
    if meta is None:
        logger.warning(f"agent_status from unauthenticated session {session_id}")
        await sio.disconnect(session_id)
        return
    await mark_agent_online(meta["server_id"])
    logger.debug(f"agent_status server_id={meta['server_id']}: {data}")


@sio.event
async def agent_command_ack(session_id: str, data) -> None:
    """
    Acknowledgement from an agent that it received/processed a pushed command. Republished onto
    the local 'agent_acks' redis channel so the scheduler can correlate by command_id.
    """
    meta = sio.agent_meta.get(session_id)
    if meta is None:
        logger.warning(f"agent_command_ack from unauthenticated session {session_id}")
        await sio.disconnect(session_id)
        return
    payload = {"server_id": meta["server_id"], **(data if isinstance(data, dict) else {"data": data})}
    logger.info(f"agent_command_ack server_id={meta['server_id']}: {data}")
    try:
        await settings.redis_client.publish("agent_acks", orjson.dumps(payload))
    except Exception as exc:
        logger.error(f"Failed to publish agent ack: {exc}")
