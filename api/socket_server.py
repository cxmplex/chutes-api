"""
Socket.IO poowered websocket server for continuous bi-directional vali/miner comms.
"""

import api.logging_bootstrap  # noqa: F401  # configure structured logging before imports log
import asyncio
import base64
import secrets
import socketio
import api.constants as cst
from datetime import datetime, timedelta, timezone
from typing import Dict
from loguru import logger
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import or_, select
import api.database.orms  # noqa
from api.config import settings
from api.database import get_session
from api.server.schemas import Host, Server
from api.host import service as host_service
from api.host.schemas import (
    HostSocketAuthenticationV1,
    HostSocketAuthenticationV2,
    HostKeyGeneration,
    GpuLaunchReservation,
    TdSocketAuthenticationV1,
    TdSocketChallengeV1,
)
from api.user.router import get_current_user
from api.socket_shared import SyntheticRequest
from api.redis_pubsub import RedisListener, AgentCommandListener
from api.log import install_asyncio_exception_handler
from api.agent_channel import (
    handle_agent_command_ack,
    handle_agent_status,
    mark_agent_online,
    mark_agent_offline,
)

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
fastapi_app = FastAPI()
app = socketio.ASGIApp(sio, fastapi_app)
sio.session_map = {}
sio.reverse_map = {}
sio.miner_expiry_tasks = {}
# 1-click CPU TEE agent sessions: server_id -> session_id, and session_id -> {hotkey, server_id}.
sio.agent_sessions = {}
sio.agent_meta = {}


async def _require_current_server_attestation(session, server: Server):
    """Require the latest completed attempt for every attested TD control channel."""

    from api.server.gpu_sessions import (
        _current_attestation,
        _current_attestation_identity,
        _latest_attestation_attempt,
    )

    latest = await _latest_attestation_attempt(session, server.server_id)
    if server.compute_type == "gpu":
        return _current_attestation(server, latest)
    return _current_attestation_identity(server, latest)


async def _validate_agent_session(session_id: str) -> bool:
    meta = sio.agent_meta.get(session_id)
    if meta is None:
        return False
    generation = meta.get("host_key_generation")
    attested_spki = meta.get("attested_spki_sha256")
    async with get_session() as session:
        if generation is not None:
            host = await session.get(Host, meta["server_id"])
            key = await session.get(HostKeyGeneration, (meta["server_id"], generation))
            valid = bool(
                host is not None
                and key is not None
                and host.provisioning_state == "ready"
                and host.identity_durable_at is not None
                and host.active_key_generation == generation
                and key.revoked_at is None
            )
            if valid and host.compute_type == "gpu":
                from api.host.reservations import gpu_host_storage_readiness

                readiness = await gpu_host_storage_readiness(session, host)
                desired_capacity = (
                    int(host.reported_capacity or 0) if readiness.trusted_schedulable else 0
                )
                if host.capacity != desired_capacity:
                    host.capacity = desired_capacity
                    await session.commit()
                valid = readiness.control_channel_eligible
        elif attested_spki:
            server = await session.get(Server, meta["server_id"])
            valid = bool(
                server is not None
                and server.attested_cert_pubkey_hash == attested_spki
            )
            if valid:
                try:
                    await _require_current_server_attestation(session, server)
                except HTTPException:
                    valid = False
        else:
            # Session state is process-local and cannot survive a rolling restart. Any metadata
            # without a generation/SPKI binding was created by legacy code and must reauthenticate.
            valid = False
    if not valid:
        sio.agent_meta.pop(session_id, None)
        if sio.agent_sessions.get(meta["server_id"]) == session_id:
            sio.agent_sessions.pop(meta["server_id"], None)
        await sio.disconnect(session_id)
    return valid


sio.validate_agent_session = _validate_agent_session


@fastapi_app.on_event("startup")
async def initialize_socket_app():
    """
    Start our redis subscriber when the server starts.
    """
    install_asyncio_exception_handler()
    fastapi_app.state.redis_listener = RedisListener(sio, "miner_broadcast")
    asyncio.create_task(fastapi_app.state.redis_listener.start())
    fastapi_app.state.agent_listener = AgentCommandListener(sio, cst.AGENT_COMMAND_CHANNEL)
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
        expiry_task = sio.miner_expiry_tasks.pop(session_id, None)
        if expiry_task is not None and expiry_task is not asyncio.current_task():
            expiry_task.cancel()
        logger.info(f"Disconnected authenticated miner: {hotkey}")
    if (meta := sio.agent_meta.pop(session_id, None)) is not None:
        server_id = meta["server_id"]
        if sio.agent_sessions.get(server_id) == session_id:
            sio.agent_sessions.pop(server_id, None)
        await mark_agent_offline(server_id)
        logger.info(f"Disconnected 1-click agent: server_id={server_id}")


async def _expire_miner_session(session_id: str, expires_at: int) -> None:
    delay = max(
        0.0,
        expires_at - datetime.now(timezone.utc).timestamp(),
    )
    await asyncio.sleep(delay)
    if session_id in sio.session_map:
        logger.info(f"Disconnecting expired attested miner session: {session_id}")
        await sio.disconnect(session_id)


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
            authorization=None,
            api_key=None,
            sig_version=headers.get(cst.SIG_VERSION_HEADER),
            attested_session=headers.get("X-Chutes-Attested-Session"),
        )
        hotkey = headers.get(cst.HOTKEY_HEADER)
        logger.info(f"Successfully authenticated miner {hotkey=}, {session_id=}")
        sio.session_map[session_id] = hotkey
        sio.reverse_map[hotkey] = session_id
        expires_at = getattr(
            request.state,
            "gpu_runtime_session_expires_at",
            None,
        )
        if isinstance(expires_at, int):
            sio.miner_expiry_tasks[session_id] = asyncio.create_task(
                _expire_miner_session(session_id, expires_at)
            )
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


def _verify_attested_socket_signature(
    attested_cert_pem: str, message: str, signature_hex: str
) -> bool:
    """Verify an attested-key socket-auth signature against the server's registration-bound cert.

    The cert's pubkey hash is committed in the server's registration quote report_data, and the
    matching private key lives only inside the attested TD (generated in-TEE at boot, never
    host-supplied), so a valid signature here proves the socket session is held by the TD itself,
    not merely by a holder of the miner hotkey. RSA today (the in-TEE cert is RSA-4096); EC is
    tolerated for forward-compat. Fail closed on any error.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        cert = x509.load_pem_x509_certificate(attested_cert_pem.encode())
        pub = cert.public_key()
        sig = bytes.fromhex(signature_hex)
        data = message.encode()
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
            return True
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        return False
    except Exception:  # noqa: BLE001 - any failure => signature not valid (fail closed)
        return False


def _verify_attested_socket_signature_b64(
    attested_cert_pem: str, message: bytes, signature_b64: str
) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        cert = x509.load_pem_x509_certificate(attested_cert_pem.encode())
        public_key = cert.public_key()
        signature = base64.b64decode(signature_b64, validate=True)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        return False
    except Exception:
        return False


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
        server_id = headers.get(cst.SERVER_ID_HEADER)
        nonce = headers.get(cst.NONCE_HEADER)
        if not server_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing server id header",
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
            if server is not None:
                await _require_current_server_attestation(session, server)
        if server is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{server_id} is not a self-registered server for {hotkey}",
            )
        # Self-registered CPU-TEE server: the miner-hotkey signature alone does NOT bind this
        # command channel to the TD. Require the registration-bound in-TEE key as well.
        attest_sig = headers.get(cst.ATTEST_SIGNATURE_HEADER)
        if not server.attested_cert or not server.attested_cert_pubkey_hash:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Server {server_id} has no complete attestation-bound certificate identity; "
                    "re-register (POST /servers/cpu/register) before opening its command channel."
                ),
            )
        if not attest_sig or not _verify_attested_socket_signature(
            server.attested_cert, f"{server_id}:{nonce}:sockets-attest", attest_sig
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Missing or invalid attestation-bound socket signature for self-registered "
                    f"server {server_id}; only the in-TEE attested key may hold its command channel."
                ),
            )
        previous = sio.agent_sessions.get(server_id)
        if previous is not None and previous != session_id:
            # Remove authority before requesting transport teardown so an in-flight event from
            # the replaced socket cannot pass validation while disconnect is being delivered.
            sio.agent_meta.pop(previous, None)
            await sio.disconnect(previous)
        sio.agent_sessions[server_id] = session_id
        agent_meta = {
            "hotkey": hotkey,
            "server_id": server_id,
            "attested_spki_sha256": server.attested_cert_pubkey_hash.lower(),
        }
        sio.agent_meta[session_id] = agent_meta
        await mark_agent_online(server_id)
        logger.success(
            f"Authenticated 1-click agent: server_id={server_id} hotkey={hotkey} session={session_id}"
        )
        await sio.emit(
            "auth_success",
            {"message": "Authenticated", "server_id": server_id},
            to=session_id,
        )
        return True
    except HTTPException as e:
        logger.warning(f"Agent authentication failed: {e.detail}")
        await sio.emit(
            "auth_failed",
            {"error": f"Authentication failed: {e.detail}"},
            to=session_id,
        )
    except Exception as e:
        logger.error(f"Unexpected error authenticating agent: {e}")
        await sio.emit("auth_failed", {"error": f"Unexpected error: {e}"}, to=session_id)
    await sio.disconnect(session_id)
    return False


@sio.event
async def td_challenge(session_id: str, data: Dict[str, object]) -> bool:
    """Issue a one-use challenge for a current reservation-attested Model-B TD."""

    try:
        server_id = str((data or {}).get("server_id") or "")
        async with get_session() as session:
            server = (
                await session.execute(
                    select(Server).where(
                        Server.server_id == server_id,
                        Server.self_registered.is_(True),
                        or_(
                            Server.launch_reservation_id.is_not(None),
                            Server.gpu_launch_reservation_id.is_not(None),
                        ),
                    )
                )
            ).scalar_one_or_none()
            if server is None or not server.attested_cert or not server.attested_cert_pubkey_hash:
                raise ValueError("server has no current reservation-attested identity")
            await _require_current_server_attestation(session, server)
            reservation_identity = {}
            if server.compute_type == "gpu":
                reservation = await session.get(
                    GpuLaunchReservation,
                    server.gpu_launch_reservation_id,
                )
                if (
                    reservation is None
                    or reservation.state != "running"
                    or reservation.server_id != server.server_id
                    or reservation.reservation_id != server.gpu_launch_reservation_id
                    or reservation.allocation_group_id != server.gpu_allocation_group_id
                    or reservation.allocation_group_generation
                    != server.gpu_allocation_group_generation
                    or reservation.process_incarnation != server.gpu_process_incarnation
                ):
                    raise ValueError("GPU socket reservation lineage is not current")
                reservation_identity = {
                    "gpu_launch_reservation_id": reservation.reservation_id,
                    "gpu_claims_sha256": reservation.claims_sha256,
                    "gpu_allocation_group_id": reservation.allocation_group_id,
                    "gpu_allocation_group_generation": (reservation.allocation_group_generation),
                    "gpu_process_incarnation": reservation.process_incarnation,
                }
            else:
                reservation_identity = {
                    "launch_reservation_id": server.launch_reservation_id,
                }
        now = datetime.now(timezone.utc)
        challenge = TdSocketChallengeV1(
            challenge_id=secrets.token_hex(32),
            session_id=session_id,
            server_id=server.server_id,
            attested_spki_sha256=server.attested_cert_pubkey_hash.lower(),
            challenge=secrets.token_urlsafe(32),
            expires_at=now + timedelta(seconds=120),
            **reservation_identity,
        )
        await settings.redis_client.setex(
            f"td:socket-challenge:{challenge.challenge_id}",
            120,
            challenge.model_dump_json(),
        )
        await sio.emit(
            "td_challenge",
            challenge.model_dump(mode="json", exclude_none=True),
            to=session_id,
        )
        return True
    except Exception as exc:
        logger.warning(f"TD socket challenge rejected: {exc}")
        await sio.emit("auth_failed", {"error": str(exc)}, to=session_id)
        await sio.disconnect(session_id)
        return False


@sio.event
async def td_authenticate(session_id: str, data: Dict[str, object]) -> bool:
    """Bind a control channel to the current reservation-attested serving key."""

    try:
        authentication = TdSocketAuthenticationV1.model_validate(data)
        if authentication.session_id != session_id:
            raise ValueError("TD socket authentication names another session")
        now = datetime.now(timezone.utc)
        issued_at = authentication.issued_at
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
        if abs((now - issued_at).total_seconds()) > 120:
            raise ValueError("TD socket authentication is stale")
        raw = await settings.redis_client.getdel(
            f"td:socket-challenge:{authentication.challenge_id}"
        )
        if not raw:
            raise ValueError("TD socket challenge is expired or consumed")
        challenge = TdSocketChallengeV1.model_validate_json(raw)
        if (
            challenge.session_id != session_id
            or challenge.server_id != authentication.server_id
            or challenge.attested_spki_sha256 != authentication.attested_spki_sha256
            or challenge.challenge != authentication.challenge
            or challenge.expires_at <= now
        ):
            raise ValueError("TD socket authentication does not match its challenge")
        async with get_session() as session:
            server = (
                await session.execute(
                    select(Server).where(
                        Server.server_id == authentication.server_id,
                        Server.self_registered.is_(True),
                        or_(
                            Server.launch_reservation_id.is_not(None),
                            Server.gpu_launch_reservation_id.is_not(None),
                        ),
                        Server.attested_cert_pubkey_hash == authentication.attested_spki_sha256,
                    )
                )
            ).scalar_one_or_none()
            if server is None or not server.attested_cert:
                raise ValueError("TD attested identity is no longer current")
            await _require_current_server_attestation(session, server)
            reservation_fields = (
                "launch_reservation_id",
                "gpu_launch_reservation_id",
                "gpu_claims_sha256",
                "gpu_allocation_group_id",
                "gpu_allocation_group_generation",
                "gpu_process_incarnation",
            )
            if any(
                getattr(authentication, field) != getattr(challenge, field)
                for field in reservation_fields
            ):
                raise ValueError("TD socket authentication changed reservation lineage")
            if server.compute_type == "gpu":
                reservation = await session.get(
                    GpuLaunchReservation,
                    server.gpu_launch_reservation_id,
                )
                if (
                    reservation is None
                    or reservation.state != "running"
                    or reservation.server_id != server.server_id
                    or reservation.reservation_id != authentication.gpu_launch_reservation_id
                    or reservation.claims_sha256 != authentication.gpu_claims_sha256
                    or reservation.allocation_group_id != authentication.gpu_allocation_group_id
                    or reservation.allocation_group_generation
                    != authentication.gpu_allocation_group_generation
                    or reservation.process_incarnation != authentication.gpu_process_incarnation
                ):
                    raise ValueError("GPU socket authentication reservation is stale")
            elif server.launch_reservation_id != authentication.launch_reservation_id:
                raise ValueError("TD socket launch reservation changed")
        if not _verify_attested_socket_signature_b64(
            server.attested_cert,
            authentication.signing_bytes(),
            authentication.signature,
        ):
            raise ValueError("TD socket signature is invalid")
        previous = sio.agent_sessions.get(server.server_id)
        if previous is not None and previous != session_id:
            await sio.disconnect(previous)
        sio.agent_sessions[server.server_id] = session_id
        sio.agent_meta[session_id] = {
            "hotkey": server.miner_hotkey,
            "server_id": server.server_id,
            "attested_spki_sha256": authentication.attested_spki_sha256,
        }
        await mark_agent_online(server.server_id)
        await sio.emit(
            "auth_success",
            {
                "message": "Authenticated",
                "server_id": server.server_id,
                "attested_spki_sha256": authentication.attested_spki_sha256,
            },
            to=session_id,
        )
        return True
    except Exception as exc:
        logger.warning(f"TD socket authentication failed: {exc}")
        await sio.emit("auth_failed", {"error": str(exc)}, to=session_id)
        await sio.disconnect(session_id)
        return False


@sio.event
async def host_challenge(session_id: str, data: Dict[str, object]) -> bool:
    """Issue a server challenge for one active logical-host key generation."""

    try:
        host_id = str((data or {}).get("host_id") or "")
        key_generation = int((data or {}).get("key_generation") or 0)
        async with get_session() as session:
            challenge = await host_service.create_host_socket_challenge(
                session, session_id, host_id, key_generation
            )
        await sio.emit(
            "host_challenge",
            challenge.model_dump(mode="json"),
            to=session_id,
        )
        return True
    except Exception as exc:
        logger.warning(f"Host socket challenge rejected: {exc}")
        await sio.emit("auth_failed", {"error": str(exc)}, to=session_id)
        await sio.disconnect(session_id)
        return False


@sio.event
async def host_authenticate(session_id: str, data: Dict[str, object]) -> bool:
    """Authenticate an L0 control channel with its persistent Ed25519 host key."""

    try:
        authentication = (
            HostSocketAuthenticationV2.model_validate(data)
            if isinstance(data, dict) and data.get("version") == 2
            else HostSocketAuthenticationV1.model_validate(data)
        )
        async with get_session() as session:
            host = await host_service.verify_host_socket_authentication(
                session, session_id, authentication
            )
        previous = sio.agent_sessions.get(host.host_id)
        if previous is not None and previous != session_id:
            await sio.disconnect(previous)
        sio.agent_sessions[host.host_id] = session_id
        sio.agent_meta[session_id] = {
            "hotkey": host.miner_hotkey,
            "server_id": host.host_id,
            "host_key_generation": authentication.key_generation,
        }
        await mark_agent_online(host.host_id)
        await sio.emit(
            "auth_success",
            {
                "message": "Authenticated",
                "server_id": host.host_id,
                "key_generation": authentication.key_generation,
            },
            to=session_id,
        )
        logger.success(
            f"Authenticated logical host: host_id={host.host_id} "
            f"key_generation={authentication.key_generation} session={session_id}"
        )
        return True
    except Exception as exc:
        logger.warning(f"Host socket authentication failed: {exc}")
        await sio.emit("auth_failed", {"error": str(exc)}, to=session_id)
        await sio.disconnect(session_id)
        return False


@sio.event
async def agent_status(session_id: str, data) -> None:
    """
    Heartbeat / status update from a connected agent. Refreshes the liveness marker so the
    scheduler keeps treating the server as online, then reconciles validator state against the
    heartbeat's running-workload inventory (containers for Model A, TD slots for Model B).
    """
    meta = sio.agent_meta.get(session_id)
    if meta is None or not await _validate_agent_session(session_id):
        logger.warning(f"agent_status from unauthenticated session {session_id}")
        await sio.disconnect(session_id)
        return
    await mark_agent_online(meta["server_id"])
    logger.debug(f"agent_status server_id={meta['server_id']}: {data}")
    await handle_agent_status(meta["server_id"], data)


@sio.event
async def agent_command_ack(session_id: str, data) -> None:
    """
    Acknowledgement from an agent that it received/processed a pushed command. A terminally
    failed deploy ack marks its launch config failed (by command_id correlation) so the
    scheduler immediately frees the chute's pending slot + the server's occupancy.
    """
    meta = sio.agent_meta.get(session_id)
    if meta is None or not await _validate_agent_session(session_id):
        logger.warning(f"agent_command_ack from unauthenticated session {session_id}")
        await sio.disconnect(session_id)
        return
    logger.info(f"agent_command_ack server_id={meta['server_id']}: {data}")
    await handle_agent_command_ack(
        meta["server_id"], data if isinstance(data, dict) else {"data": data}
    )
