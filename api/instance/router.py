"""
Routes for instances.
"""

import csv
import hashlib
from io import StringIO
import os
import re
import uuid
import ctypes
import traceback
import random
import socket
import secrets
import asyncio
import orjson as json  # noqa
from api.image.util import get_inspecto_hash
import api.miner_client as miner_client
from loguru import logger
from typing import Optional, Tuple
from datetime import datetime, timedelta, timezone
from fastapi.responses import PlainTextResponse
from fastapi import APIRouter, Depends, HTTPException, Response, status, Header, Request
from sqlalchemy import select, text, func, update, and_, desc, true
from sqlalchemy.orm import joinedload, lazyload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import insert
from api.gpu import SUPPORTED_GPUS, COMPUTE_MULTIPLIER
from api.database import get_db_session, generate_uuid, get_session
from api.config import settings
from api.metrics.warmup import (
    track_warmup_seconds,
    track_warmup_seconds_since,
    WarmupTrigger,
)
from api.constants import (
    TEE_BONUS,
    HOTKEY_HEADER,
    AUTHORIZATION_HEADER,
    PRIVATE_INSTANCE_BONUS,
    TEE_PRIVATE_INSTANCE_BONUS,
    INTEGRATED_SUBNETS,
    INTEGRATED_SUBNET_BONUS,
    NoncePurpose,
)
from api.node.schemas import Node
from api.permissions import Permissioning
from api.payment.util import decrypt_secret
from api.node.util import get_node_by_id
from api.chute.schemas import Chute, NodeSelector
from api.chute.util import get_manual_boost, is_shared
from api.bounty.util import claim_bounty, calculate_bounty_boost
from api.secret.schemas import Secret
from api.image.schemas import Image  # noqa
from api.instance.schemas import (
    LaunchConfigArgs,
    LaunchConfigResponse,
    LegacyTeeLaunchConfigArgs,
    TeeLaunchConfigArgs,
    Instance,
    instance_nodes,
    LaunchConfig,
)
from api.job.schemas import Job
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    canonical_sha256,
)
from api.gpu_models import GpuLifecycleOperation
from api.host.locks import (
    acquire_gpu_lifecycle_lock,
    assert_gpu_external_work_allowed,
)
from api.instance.util import (
    _decode_chutes_jwt,
    create_launch_jwt_v2,
    generate_fs_key,
    get_instance_by_chute_and_id,
    get_server_for_gpus,
    get_cpu_server_for_host,
    create_job_jwt,
    load_launch_config_from_jwt,
    invalidate_instance_cache,
    verify_tee_chute,
    require_attested_client_cert,
)
from api.server.service import (
    validate_request_nonce,
    create_nonce,
    get_instance_evidence,
    verify_gpu_evidence,
)
from api.server.gpu_sessions import _current_attestation, _latest_attestation_attempt
from api.server.schemas import (
    TeeInstanceEvidence,
    BootAttestation,
    DefaultChuteFSVolumeBinding,
    Server,
    StorageVolume,
    StorageVolumeKey,
)
from api.storage.service import ensure_default_volume_binding
from api.rate_limit import rate_limit
from api.server.exceptions import (
    AttestationError,
    InstanceNotFoundError,
    ChuteNotTeeError,
    NonceError,
    GetEvidenceError,
)
from api.user.schemas import User
from api.user.service import get_current_user, chutes_user_id, subnet_role_accessible
from api.metagraph import get_miner_by_hotkey
from api.util import (
    semcomp,
    is_valid_host,
    generate_ip_token,
    aes_decrypt,
    derive_ecdh_session_key,
    derive_x25519_session_key,
    decrypt_instance_response,
    notify_created,
    notify_deleted,
    notify_verified,
    notify_activated,
    notify_disabled,
    load_shared_object,
    has_legacy_private_billing,
)
from api.encrypted_logs.capture import start_encrypted_log_capture
from api.metrics.launch_config import track_failure as track_launch_config_failure
from api.log import instance_logger, LifecycleEvent, update_log_context
from api.bounty.util import check_bounty_exists
from starlette.responses import StreamingResponse
from api.graval_worker import graval_encrypt, verify_proof, generate_fs_hash
from taskiq import TaskiqResultTimeoutError
from watchtower import is_kubernetes_env, verify_expected_command, verify_fs_hash
from api.request_context import bind_request_context

router = APIRouter(dependencies=[Depends(bind_request_context)])

_EXTERNAL_VALUE_UNSET = object()
_ACTIVATION_ATTEMPT_EXTRA_KEY = "_launch_activation_attempt_v1"
_ACTIVATION_REPLAY_TTL_SECONDS = 24 * 60 * 60

_CONSUME_WARMUP_REPLAY_LUA = """
local warmup_key = KEYS[1]
local replay_key = KEYS[2]
local attempt_id = ARGV[1]
local replay_ttl = ARGV[2]
local chute_id = ARGV[3]

local cached = redis.call('GET', replay_key)
if cached then
    return cached
end

local requested_at = redis.call('GET', warmup_key)
local now = redis.call('TIME')
local consumed_at = tonumber(now[1]) + (tonumber(now[2]) / 1000000)
local envelope
if requested_at then
    envelope = cjson.encode({
        schema = 'chutes.activation-warmup-result.v1',
        attempt_id = attempt_id,
        chute_id = chute_id,
        consumed_at = consumed_at,
        requested_at = requested_at
    })
    redis.call('DEL', warmup_key)
else
    envelope = cjson.encode({
        schema = 'chutes.activation-warmup-result.v1',
        attempt_id = attempt_id,
        chute_id = chute_id,
        consumed_at = consumed_at,
        requested_at = cjson.null
    })
end
redis.call('SET', replay_key, envelope, 'EX', replay_ttl)
return envelope
"""


async def _maybe_start_log_capture(instance, config_id: str):
    """Start encrypted startup log capture for private chute instances."""
    try:
        async with get_session(readonly=True) as session:
            chute = (
                (
                    await session.execute(
                        select(Chute).where(Chute.chute_id == instance.chute_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if not chute or chute.public:
                return
            user = (
                (
                    await session.execute(
                        select(User).where(User.user_id == chute.user_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if not user or not user.hotkey:
                return
        # Find the log port from port_mappings
        if not instance.port_mappings:
            return
        try:
            log_port = next(
                p for p in instance.port_mappings if p["internal_port"] == 8001
            )["external_port"]
        except (StopIteration, TypeError, KeyError):
            return
        asyncio.create_task(
            start_encrypted_log_capture(
                instance_id=instance.instance_id,
                config_id=config_id,
                chute_id=instance.chute_id,
                owner_ss58=user.hotkey,
                host=instance.host,
                log_port=log_port,
                miner_hotkey=instance.miner_hotkey,
                # TEE instances serve the logging port over TLS with the attested cert; pin to it so
                # the host-routed (DNAT'd) log stream cannot be read/tampered in transit.
                cacert=instance.cacert,
            )
        )
    except Exception as exc:
        logger.debug(f"Failed to start encrypted log capture: {exc}")


INSPECTO = load_shared_object("chutes", "chutes-inspecto.so")
INSPECTO.verify_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
INSPECTO.verify_hash.restype = ctypes.c_char_p

NETNANNY = ctypes.CDLL(
    os.getenv("CHUTES_NNVERIFY_PATH", "/usr/local/lib/chutes-nnverify.so")
)
NETNANNY.verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint8]
NETNANNY.verify.restype = ctypes.c_int

# Aegis v4 verification library is required.
import chutes as _chutes_pkg  # noqa: E402

_aegis_verify_path = os.path.join(
    os.path.dirname(_chutes_pkg.__file__), "chutes-aegis-verify.so"
)
AEGIS_VERIFY = ctypes.CDLL(_aegis_verify_path)
AEGIS_VERIFY.verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint8]
AEGIS_VERIFY.verify.restype = ctypes.c_int
AEGIS_VERIFY.decrypt_session_key.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
AEGIS_VERIFY.decrypt_session_key.restype = ctypes.c_int
logger.info(f"Loaded chutes-aegis-verify.so from {_aegis_verify_path}")


def _decrypt_cllmv_session_key(blob_hex: str, x25519_priv_hex: str) -> str | None:
    """Decrypt miner's ephemeral HMAC key from the CLLMV V2 init blob."""
    key_buf = ctypes.create_string_buffer(65)
    ret = AEGIS_VERIFY.decrypt_session_key(
        blob_hex.encode(),
        x25519_priv_hex.encode(),
        key_buf,
        65,
    )
    if ret != 0:
        return None
    return key_buf.value.decode()


def _verify_rint_commitment_v4(commitment_hex: str) -> bool:
    """Verify a v4 runtime integrity commitment (aegis/Ed25519)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if len(commitment_hex) != 292:
            logger.error(
                f"RUNINT v4: commitment length mismatch: {len(commitment_hex)} != 292"
            )
            return False

        commitment_bytes = bytes.fromhex(commitment_hex)
        if len(commitment_bytes) != 146:
            logger.error(
                f"RUNINT v4: decoded commitment length mismatch: {len(commitment_bytes)} != 146"
            )
            return False

        prefix = commitment_bytes[0]
        if prefix != 0x04:
            logger.error(f"RUNINT v4: invalid prefix: {prefix} != 0x04")
            return False

        version = commitment_bytes[1]
        if version != 0x04:
            logger.error(f"RUNINT v4: invalid version: {version} != 0x04")
            return False

        pubkey_bytes = commitment_bytes[2:34]  # Ed25519 pubkey (32 bytes)
        nonce_bytes = commitment_bytes[34:50]  # nonce (16 bytes)
        lib_proof_bytes = commitment_bytes[50:82]  # lib_proof HMAC-SHA256 (32 bytes)
        sig_bytes = commitment_bytes[82:146]  # Ed25519 signature (64 bytes)

        # Verify: Ed25519_verify(pubkey, version||pubkey||nonce||lib_proof, signature)
        msg_to_verify = bytes([version]) + pubkey_bytes + nonce_bytes + lib_proof_bytes
        pk = Ed25519PublicKey.from_public_bytes(pubkey_bytes)

        try:
            pk.verify(sig_bytes, msg_to_verify)
            logger.info("RUNINT v4: commitment verification successful")
            return True
        except Exception:
            logger.error("RUNINT v4: signature verification failed")
            return False

    except Exception as e:
        logger.error(f"RUNINT v4: commitment verification error: {e}")
        return False


def _verify_rint_commitment(commitment_hex: str, expected_nonce: str) -> bool:
    """Verify the runtime integrity commitment (mini-cert). Auto-detects v3/v4."""
    # v4 commitments start with "04" prefix
    if commitment_hex[:2] == "04":
        return _verify_rint_commitment_v4(commitment_hex)

    # v3 (SECP256k1) path
    try:
        from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
        import hashlib

        if len(commitment_hex) != 324:
            logger.error(
                f"RUNINT: commitment length mismatch: {len(commitment_hex)} != 324"
            )
            return False

        commitment_bytes = bytes.fromhex(commitment_hex)
        if len(commitment_bytes) != 162:
            logger.error(
                f"RUNINT: decoded commitment length mismatch: {len(commitment_bytes)} != 162"
            )
            return False

        prefix = commitment_bytes[0]
        if prefix != 0x03:
            logger.error(f"RUNINT: invalid prefix: {prefix} != 0x03")
            return False

        version = commitment_bytes[1]
        if version != 0x03:
            logger.error(f"RUNINT: invalid version: {version} != 0x03")
            return False

        pubkey_bytes = commitment_bytes[2:66]
        nonce_bytes = commitment_bytes[66:82]
        lib_fp_bytes = commitment_bytes[82:98]
        sig_bytes = commitment_bytes[98:162]

        nonce_tag = b"rint-nonce-v3"
        expected_nonce_value = hashlib.sha256(
            nonce_tag + lib_fp_bytes + expected_nonce.encode()
        ).digest()[:16]
        if nonce_bytes != expected_nonce_value:
            logger.error(
                f"RUNINT: nonce mismatch: {nonce_bytes.hex()} != {expected_nonce_value.hex()}"
            )
            return False

        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        msg_to_verify = bytes([version]) + pubkey_bytes + nonce_bytes + lib_fp_bytes
        msg_hash = hashlib.sha256(msg_to_verify).digest()

        try:
            vk.verify_digest(sig_bytes, msg_hash)
            logger.info("RUNINT: commitment verification successful")
            return True
        except BadSignatureError:
            logger.error("RUNINT: signature verification failed")
            return False

    except Exception as e:
        logger.error(f"RUNINT: commitment verification error: {e}")
        return False


def _verify_e2e_pubkey_sig(
    attested_cert_pem: str, e2e_pubkey: str, sig_hex: str, config_id: str
) -> bool:
    """Verify a CPU-TEE chute's e2e_pubkey is attestation-bound.

    The chute signs ``f"{e2e_pubkey}:{config_id}"`` with the in-TD attested cert key (whose public-key
    hash is committed in the server's registration quote report_data). We verify that signature with
    the server's persisted attested cert, proving the ML-KEM public key was generated inside the
    attested TD -- so neither the untrusted host nor the validator can substitute it before it is
    published via /e2e/instances (the CPU-TEE analog of the GPU report_data e2e_pubkey binding).
    Returns True iff the signature is valid.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    try:
        cert = x509.load_pem_x509_certificate(attested_cert_pem.encode())
        pub = cert.public_key()
        sig = bytes.fromhex(sig_hex)
        data = f"{e2e_pubkey}:{config_id}".encode()
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, data)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            logger.error(
                f"e2e_pubkey sig: unsupported attested cert key type {type(pub).__name__}"
            )
            return False
        return True
    except InvalidSignature:
        logger.error("e2e_pubkey signature does not match the attested cert")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error(f"e2e_pubkey signature verification error: {exc}")
        return False


def _validate_tls_cert(
    tls_cert_pem: str,
    tls_cert_sig_hex: str,
    rint_commitment_hex: str,
    nonce: str | None = None,
) -> bool:
    """Validate TLS cert signature against the aegis Ed25519 key from rint_commitment.

    For v4 commitments, verifies sign(cert_pem || nonce) using the Ed25519 pubkey
    embedded at bytes 2:34 of the commitment. Also verifies the nonce is embedded
    in the cert as an X.509 extension if present.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography import x509

    try:
        commitment_bytes = bytes.fromhex(rint_commitment_hex)
        if commitment_bytes[0] != 0x04:
            logger.error("TLS cert validation: not a v4 commitment")
            return False
        pubkey_bytes = commitment_bytes[2:34]

        pk = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        sig_bytes = bytes.fromhex(tls_cert_sig_hex)

        # Verify signature over cert_pem || nonce (nonce-bound) or just cert_pem (legacy).
        signed_data = tls_cert_pem.encode()
        if nonce:
            signed_data += nonce.encode()
        pk.verify(sig_bytes, signed_data)

        # If nonce provided, verify it's embedded in the cert as X.509 extension.
        if nonce:
            CHUTES_NONCE_OID = x509.ObjectIdentifier("1.3.6.1.4.1.59888.1")
            cert = x509.load_pem_x509_certificate(tls_cert_pem.encode())
            try:
                ext = cert.extensions.get_extension_for_oid(CHUTES_NONCE_OID)
                raw = ext.value.value
                # Extension value is DER: UTF8String(nonce). Parse tag+length.
                if raw[0] == 0x0C:  # UTF8String tag
                    # Short form length
                    if raw[1] < 0x80:
                        cert_nonce = raw[2 : 2 + raw[1]].decode()
                    elif raw[1] == 0x81:
                        cert_nonce = raw[3 : 3 + raw[2]].decode()
                    else:
                        cert_nonce = raw.decode()  # fallback
                else:
                    cert_nonce = raw.decode()  # fallback for raw OCTET STRING
                if cert_nonce != nonce:
                    logger.error(
                        f"TLS cert nonce mismatch: cert={cert_nonce} expected={nonce}"
                    )
                    return False
            except x509.ExtensionNotFound:
                # Legacy cert without nonce extension — allow if sig verified.
                logger.warning(
                    "TLS cert has no nonce extension, skipping nonce embedding check"
                )

        logger.info("TLS cert signature validation successful")
        return True
    except Exception as e:
        logger.error(f"TLS cert validation failed: {e}")
        return False


async def _verify_instance_tls_live(
    host: str, port: int, expected_cert_pem: str
) -> bool:
    """Connect to the instance's logging port and verify the served cert matches expected."""
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    try:
        expected_cert = x509.load_pem_x509_certificate(expected_cert_pem.encode())
        expected_fingerprint = expected_cert.fingerprint(hashes.SHA256())

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=10.0,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        served_der = ssl_object.getpeercert(binary_form=True)
        served_cert = x509.load_der_x509_certificate(served_der)
        served_fingerprint = served_cert.fingerprint(hashes.SHA256())
        writer.close()
        await writer.wait_closed()

        if served_fingerprint != expected_fingerprint:
            logger.warning(
                f"TLS cert mismatch: served {served_fingerprint.hex()} != expected {expected_fingerprint.hex()}"
            )
            return False
        logger.info(f"Live TLS cert verification passed for {host}:{port}")
        return True
    except Exception as e:
        logger.warning(f"Failed to verify TLS cert live at {host}:{port}: {e}")
        return False


async def _load_chute(db, chute_id: str) -> Chute:
    chute = (
        (await db.execute(select(Chute).where(Chute.chute_id == chute_id)))
        .unique()
        .scalar_one_or_none()
    )
    if not chute:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Chute {chute_id} not found",
        )
    return chute


async def _check_blacklisted(db, hotkey):
    mgnode = await get_miner_by_hotkey(hotkey, db)
    if not mgnode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Miner with hotkey {hotkey} not found in metagraph",
        )
    if mgnode.blacklist_reason:
        logger.warning(f"MINERBLACKLIST: {hotkey=} reason={mgnode.blacklist_reason}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Your hotkey has been blacklisted: {mgnode.blacklist_reason}",
        )
    return mgnode


async def _get_instance_counts_and_target(
    db,
    chute_id,
    hotkey,
    *,
    scale_value=_EXTERNAL_VALUE_UNSET,
):
    """Shared helper to get instance counts and target for a chute."""
    query = text("""
        SELECT
            COUNT(*) AS total_count,
            COUNT(CASE WHEN active IS true AND verified IS true THEN 1 ELSE NULL END) AS active_count,
            COUNT(CASE WHEN NOT (active IS false AND activated_at IS NOT NULL) THEN 1 ELSE NULL END) AS live_count,
            COUNT(CASE WHEN miner_hotkey = :hotkey THEN 1 ELSE NULL END) AS hotkey_count
        FROM instances
        WHERE chute_id = :chute_id
    """)
    count_result = (
        (await db.execute(query, {"chute_id": chute_id, "hotkey": hotkey}))
        .mappings()
        .first()
    )
    current_count = count_result["total_count"]
    active_count = count_result["active_count"]
    live_count = count_result["live_count"]
    hotkey_count = count_result["hotkey_count"]

    # Redis is external telemetry. Launch paths resolve it after releasing the
    # lifecycle transaction and pass the exact result back into the locked
    # count/CAS phase. Other callers retain the historical standalone behavior.
    if scale_value is _EXTERNAL_VALUE_UNSET:
        assert_gpu_external_work_allowed(db, "instance scale telemetry lookup")
        scale_value = await settings.redis_client.get(f"scale:{chute_id}")
    if scale_value:
        target_count = int(scale_value)
    else:
        # Fallback to database.
        capacity_query = text("""
            SELECT target_count
            FROM capacity_log
            WHERE chute_id = :chute_id
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        capacity_result = await db.execute(capacity_query, {"chute_id": chute_id})
        capacity_row = capacity_result.first()
        if capacity_row and capacity_row.target_count is not None:
            target_count = capacity_row.target_count
            logger.info(
                f"Retrieved target_count from CapacityLog for {chute_id}: {target_count}"
            )
        else:
            target_count = current_count
            logger.warning(
                f"No target_count in Redis or CapacityLog for {chute_id}, "
                f"using conservative current count as default: {target_count}"
            )

    return current_count, active_count, live_count, hotkey_count, target_count


async def _check_scalable(
    db,
    chute,
    hotkey,
    *,
    scale_value=_EXTERNAL_VALUE_UNSET,
):
    """Creation path: gate on live_count to prevent over-launching."""
    chute_id = chute.chute_id
    (
        current_count,
        active_count,
        live_count,
        hotkey_count,
        target_count,
    ) = await _get_instance_counts_and_target(
        db,
        chute_id,
        hotkey,
        scale_value=scale_value,
    )

    # For TEE chutes, gate on live instance count (active + pending, excludes disabled).
    # TEE instances take a long time to spin up, so allowing many more live instances
    # than the target wastes miner time. Allow target + 1 to permit one racer.
    if chute.tee and live_count >= target_count + 1:
        logger.warning(
            f"SCALELOCK (TEE live): chute {chute_id=} {chute.name} has too many live instances: "
            f"{live_count=}, {active_count=}, {target_count=}, {hotkey_count=}"
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"TEE chute {chute_id} already has {live_count} live instances (target: {target_count}).",
        )

    # Non-TEE: gate on active_count only, allowing miners to race with pending instances.
    # TEE creation is already gated above on live_count, so active_count here is a fallback
    # that only matters for non-TEE chutes.
    if active_count >= target_count:
        logger.warning(
            f"SCALELOCK: chute {chute_id=} {chute.name} has reached target capacity: "
            f"{current_count=}, {active_count=}, {live_count=}, {target_count=}, {hotkey_count=}"
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Chute {chute_id} has reached its target capacity of {target_count} instances.",
        )


async def _check_scalable_activation(
    db,
    chute,
    hotkey,
    *,
    scale_value=_EXTERNAL_VALUE_UNSET,
):
    """Activation path: gate on active_count only, since the instance already exists."""
    # Public TEE instances always pass activation — they were scalable when created,
    # and the autoscaler TEE limit may have changed since then.
    if chute.tee and chute.public:
        return

    chute_id = chute.chute_id
    (
        current_count,
        active_count,
        live_count,
        hotkey_count,
        target_count,
    ) = await _get_instance_counts_and_target(
        db,
        chute_id,
        hotkey,
        scale_value=scale_value,
    )

    if active_count >= target_count:
        logger.warning(
            f"SCALELOCK (activation): chute {chute_id=} {chute.name} active instances at target: "
            f"{active_count=}, {target_count=}, {live_count=}, {hotkey_count=}"
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Chute {chute_id} already has {active_count} active instances (target: {target_count}).",
        )


async def _check_scalable_private(
    db,
    chute,
    miner,
    *,
    inventory_history=_EXTERNAL_VALUE_UNSET,
    scale_value=_EXTERNAL_VALUE_UNSET,
    bounty_exists=_EXTERNAL_VALUE_UNSET,
):
    """
    Special scaling logic for private chutes (without legacy billing).
    """
    chute_id = chute.chute_id

    ## Prevent highly unstable miners from deploying private chutes.
    # unstable_query = text("""
    #    SELECT
    #      COUNT(*) FILTER (
    #        WHERE valid_termination IS TRUE
    #           OR deletion_reason IN (
    #                'job has been terminated due to insufficient user balance',
    #                'user-defined/private chute instance has not been used since shutdown_after_seconds',
    #                'user has zero/negative balance (private chute)'
    #              )
    #           OR deletion_reason LIKE '%%has an old version%%'
    #           OR deleted_at IS NULL
    #      ) AS valid_terminations,
    #      COUNT(*) FILTER (
    #        WHERE valid_termination IS NOT TRUE
    #          AND deletion_reason NOT IN (
    #                'job has been terminated due to insufficient user balance',
    #                'user-defined/private chute instance has not been used since shutdown_after_seconds',
    #                'user has zero/negative balance (private chute)'
    #              )
    #          AND deletion_reason NOT LIKE '%%has an old version%%'
    #          AND deleted_at IS NOT NULL
    #      ) AS invalid_terminations,
    #      ROUND(
    #        COUNT(*) FILTER (
    #          WHERE valid_termination IS NOT TRUE
    #            AND deletion_reason NOT IN (
    #                  'job has been terminated due to insufficient user balance',
    #                  'user-defined/private chute instance has not been used since shutdown_after_seconds',
    #                  'user has zero/negative balance (private chute)'
    #                )
    #            AND deletion_reason NOT LIKE '%%has an old version%%'
    #            AND deleted_at IS NOT NULL
    #        )::numeric
    #        / NULLIF(COUNT(*), 0),
    #        4
    #      ) AS invalid_ratio
    #    FROM instance_audit
    #    WHERE billed_to IS NOT NULL
    #      AND activated_at IS NOT NULL
    #      AND activated_at >= NOW() - INTERVAL '7 days'
    #      AND miner_hotkey = :hotkey
    # """)
    # result = await db.execute(unstable_query, {"hotkey": miner.hotkey})
    # row = result.mappings().one()
    # if (
    #    row["valid_terminations"] + row["invalid_terminations"] >= 10
    #    and row["invalid_ratio"] >= 0.5
    # ):
    #    message = f"UNSTABLE MINER: miner {miner.hotkey} denied private chute {chute_id} due to instability: {row}"
    #    logger.warning(message)
    #    raise HTTPException(
    #        status_code=status.HTTP_403_FORBIDDEN,
    #        detail=message,
    #    )

    # TEE chutes skip all history/inventory gates entirely.
    # Miners with an active TEE instance also bypass.
    skip_gates = chute.tee
    if not skip_gates:
        has_tee = (
            await db.execute(
                text("""
                SELECT 1 FROM instances i
                JOIN chutes c ON c.chute_id = i.chute_id
                WHERE i.miner_hotkey = :hotkey
                  AND i.active = TRUE
                  AND i.verified = TRUE
                  AND c.tee = TRUE
                LIMIT 1
            """),
                {"hotkey": miner.hotkey},
            )
        ).scalar_one_or_none()
        skip_gates = has_tee is not None

    if not skip_gates:
        # Require some public chute history.
        public_history_query = text("""
            SELECT COUNT(*) AS public_count
            FROM instance_audit ia
            JOIN chutes c ON c.chute_id = ia.chute_id
            WHERE ia.miner_hotkey = :hotkey
              AND c.public IS TRUE
              AND ia.activated_at IS NOT NULL
              AND ia.activated_at <= NOW() - INTERVAL '3 days'
         """)
        public_result = (
            (await db.execute(public_history_query, {"hotkey": miner.hotkey}))
            .mappings()
            .first()
        )
        if not public_result or public_result["public_count"] == 0:
            logger.warning(
                f"PRIVATE_GATE: miner {miner.hotkey} denied private chute {chute_id}: "
                f"no public chute instance activated >= 3 days ago"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "You must have at least one public chute instance >= one week old creation timestamp to deploy private chutes"
                ),
            )

        # Require minimum active public inventory right now.
        active_public_query = text("""
            SELECT
                COUNT(DISTINCT i.instance_id) AS active_instance_count,
                COUNT(inodes.node_id) AS total_gpus
            FROM instances i
            JOIN instance_nodes inodes ON inodes.instance_id = i.instance_id
            WHERE i.miner_hotkey = :hotkey
              AND i.active = TRUE
              AND i.billed_to IS NULL
        """)
        active_public_result = (
            (await db.execute(active_public_query, {"hotkey": miner.hotkey}))
            .mappings()
            .first()
        )
        instance_count = (
            active_public_result["active_instance_count"] if active_public_result else 0
        )
        total_gpus = active_public_result["total_gpus"] if active_public_result else 0
        if instance_count < 4 or total_gpus < 12:
            logger.warning(
                f"PRIVATE_GATE: miner {miner.hotkey} denied private chute {chute_id}: "
                f"{instance_count} active public instances with {total_gpus} GPUs "
                f"(minimum 4 instances and 12 GPUs required)"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"You must have at least 4 active public (non-private) chute instances "
                    f"with a total of at least 12 GPUs to deploy private chutes "
                    f"(currently have {instance_count} instances with {total_gpus} GPUs)"
                ),
            )

        # Require average GPU inventory of at least 16 over the entire 7-day scoring period.
        # Try cached value first, fall back to a single-miner DB query on cache miss.
        if inventory_history is _EXTERNAL_VALUE_UNSET:
            inventory_history = None
            assert_gpu_external_work_allowed(
                db, "private instance inventory telemetry lookup"
            )
            inventory_raw = await settings.redis_client.get(f"uqhist:{miner.hotkey}")
            if inventory_raw:
                inventory_history = json.loads(inventory_raw)
        if not inventory_history:
            miner_inventory_result = await db.execute(
                text("""
                    WITH time_series AS (
                        SELECT generate_series(
                            date_trunc('hour', now() - INTERVAL '7 days'),
                            date_trunc('hour', now()),
                            INTERVAL '1 hour'
                        ) AS time_point
                    ),
                    latest_chute_config AS (
                        SELECT DISTINCT ON (chute_id)
                            chute_id,
                            (node_selector->>'gpu_count')::integer AS gpu_count
                        FROM chute_history
                        ORDER BY chute_id, updated_at DESC
                    ),
                    active_instances AS (
                        SELECT
                            ts.time_point,
                            ia.chute_id,
                            COALESCE(lcc.gpu_count, 1) AS gpu_count
                        FROM time_series ts
                        JOIN instance_audit ia
                            ON ia.miner_hotkey = :hotkey
                            AND ia.activated_at <= ts.time_point
                            AND (ia.deleted_at IS NULL OR ia.deleted_at >= ts.time_point)
                            AND ia.activated_at IS NOT NULL
                            AND (
                                ia.billed_to IS NOT NULL
                                OR (COALESCE(ia.deleted_at, ts.time_point) - ia.activated_at >= interval '1 hour')
                            )
                        LEFT JOIN latest_chute_config lcc ON ia.chute_id = lcc.chute_id
                    )
                    SELECT
                        ts.time_point::text AS time,
                        COALESCE(SUM(ai.gpu_count), 0) AS total_count
                    FROM time_series ts
                    LEFT JOIN active_instances ai ON ai.time_point = ts.time_point
                    GROUP BY ts.time_point
                    ORDER BY ts.time_point
                """),
                {"hotkey": miner.hotkey},
            )
            rows = miner_inventory_result.mappings().all()
            if rows:
                inventory_history = [
                    {"total_count": int(r["total_count"])} for r in rows
                ]
        if not inventory_history:
            logger.warning(
                f"PRIVATE_GATE: miner {miner.hotkey} denied private chute {chute_id}: no inventory history found"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No inventory history found; you must have an average of at least 16 GPUs over the 7-day scoring period to deploy private chutes.",
            )
        avg_gpus = sum(
            entry.get("total_count", 0) for entry in inventory_history
        ) / len(inventory_history)
        if avg_gpus < 16:
            logger.warning(
                f"PRIVATE_GATE: miner {miner.hotkey} denied private chute {chute_id}: "
                f"average GPU inventory {avg_gpus:.1f} < 16 over 7-day scoring period"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"You must have an average of at least 16 GPUs over the 7-day scoring period "
                    f"to deploy private chutes (currently {avg_gpus:.1f} average GPUs)"
                ),
            )

    query = text("""
        SELECT
            COUNT(*) AS total_count,
            COUNT(CASE WHEN active IS true AND verified IS true THEN 1 ELSE NULL END) AS active_count
        FROM instances
        WHERE chute_id = :chute_id
    """)
    count_result = (await db.execute(query, {"chute_id": chute_id})).mappings().first()
    active_count = count_result["active_count"]
    if scale_value is _EXTERNAL_VALUE_UNSET:
        assert_gpu_external_work_allowed(db, "private instance scale telemetry lookup")
        scale_value = await settings.redis_client.get(f"scale:{chute_id}")
    target_count = int(scale_value) if scale_value else 0
    if bounty_exists is _EXTERNAL_VALUE_UNSET:
        assert_gpu_external_work_allowed(db, "private instance bounty lookup")
        bounty_exists = await check_bounty_exists(chute_id)
    if active_count == 0 and not bounty_exists:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Private chute {chute_id} has no active bounty and cannot be scaled.",
        )
    if active_count >= target_count and target_count > 0:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Private chute {chute_id} has reached its target capacity of {target_count} instances.",
        )


async def _validate_node(
    db,
    chute,
    node_id: str,
    hotkey: str,
    node_selector: NodeSelector,
) -> Node:
    node = await get_node_by_id(node_id, db, hotkey)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id} not found",
        )

    # Not verified?
    if not node.verified_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"GPU {node_id} is not yet verified, and cannot be associated with an instance",
        )

    # Already associated with an instance?
    result = await db.execute(
        select(instance_nodes.c.instance_id).where(instance_nodes.c.node_id == node_id)
    )
    existing_instance_id = result.scalar()
    if existing_instance_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"GPU {node_id} is already assigned to instance: {existing_instance_id}",
        )

    # Valid GPU for this chute?
    if node.gpu_identifier not in node_selector.supported_gpus:
        logger.warning(
            f"INSTANCEFAIL: attempt to post incompatible GPUs: {node.name} for {chute.node_selector} {hotkey=}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Node {node_id} is not compatible with chute node selector!",
        )
    return node


async def _validate_nodes(
    db,
    chute,
    node_ids: list[str],
    hotkey: str,
    instance: Instance,
    node_selector: NodeSelector,
) -> list[Node]:
    host = instance.host
    # CPU (GPU-less) chutes have no GPU Node rows; the instance<->server linkage is by
    # host + miner_hotkey (see verify_tee_chute), so there is no node count to enforce or
    # instance_nodes association to create.
    if node_selector.compute_type == "cpu":
        return []
    gpu_count = node_selector.gpu_count or 0
    if len(set(node_ids)) != gpu_count:
        logger.warning(
            f"INSTANCEFAIL: Attempt to post incorrect GPU count: {len(node_ids)} vs {gpu_count} from {hotkey=}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{chute.chute_id=} {chute.name=} requires exactly {gpu_count} GPUs.",
        )

    node_hosts = set()
    nodes = []
    for node_id in set(node_ids):
        node = await _validate_node(db, chute, node_id, hotkey, node_selector)
        nodes.append(node)
        node_hosts.add(node.verification_host)

        # Create the association record, handling dupes.
        stmt = (
            insert(instance_nodes)
            .values(instance_id=instance.instance_id, node_id=node_id)
            .on_conflict_do_nothing(index_elements=["node_id"])
        )
        result = await db.execute(stmt)
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Node {node_id} is already assigned to another instance",
            )

    # The hostname used in verifying the node must match the hostname of the instance.
    if len(node_hosts) > 1 or list(node_hosts)[0].lower() != host.lower():
        logger.warning(
            "INSTANCEFAIL: Instance hostname mismatch: {node_hosts=} {host=}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Instance hostname does not match the node verification hostname: {host=} vs {node_hosts=}",
        )
    return nodes


async def _validate_host_port(db, host, port):
    existing = (
        (
            await db.execute(
                select(Instance)
                .where(Instance.host == host, Instance.port == port)
                .limit(1)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Host/port {host}:{port} is already in use by another instance.",
        )

    if not await is_valid_host(host):
        logger.warning(f"INSTANCEFAIL: Attempt to post bad host: {host}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid instance host: {host}",
        )


@router.get("/reconciliation_csv")
async def get_instance_reconciliation_csv(
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get all instance audit instance_id, deleted_at records to help reconcile audit data.
    """
    query = """
        SELECT
            instance_id,
            deleted_at
        FROM instance_audit
        WHERE (deleted_at IS NULL OR deleted_at >= NOW() - INTERVAL '7 days 1 hour')
          AND activated_at IS NOT NULL
    """
    output = StringIO()
    writer = csv.writer(output)
    result = await db.execute(text(query))
    writer.writerow([col for col in result.keys()])
    writer.writerows(result)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="audit-reconciliation.csv"'
        },
    )


@router.get("/compute_history_csv")
async def get_instance_compute_history_csv(
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get instance_compute_history records for the scoring period (last 7 days + buffer).
    Used by the auditor to reconcile compute history data on startup.
    """
    query = """
        SELECT
            instance_id,
            compute_multiplier,
            started_at,
            ended_at
        FROM instance_compute_history
        WHERE ended_at IS NULL
           OR ended_at >= NOW() - INTERVAL '8 days'
        ORDER BY instance_id, started_at
    """
    output = StringIO()
    writer = csv.writer(output)
    result = await db.execute(text(query))
    writer.writerow([col for col in result.keys()])
    writer.writerows(result)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="compute-history.csv"'},
    )


def _require_non_cpu_tee_claim_fields(
    chute: Chute,
    args: LaunchConfigArgs,
    launch_config: LaunchConfig,
) -> None:
    """`gpus` and `env` were schema-required before CPU-TEE made them Optional. Only CPU-TEE
    chutes (no aegis envdump, no GPU nodes) may omit them; every other claim must still provide
    both, otherwise omitting `env` silently skips envdump verification and omitting `gpus`
    crashes node validation. Reject with the same 422 the old pydantic contract produced
    (no failed_at: the miner may re-claim with a corrected payload, exactly as before)."""
    cpu_tee = bool(chute.tee) and (
        str((chute.node_selector or {}).get("compute_type", "gpu")).lower() == "cpu"
    )
    if cpu_tee:
        return
    fields = (
        ("gpus",)
        if launch_config.gpu_management_mode == "platform"
        else ("gpus", "env")
    )
    missing = [field for field in fields if getattr(args, field) is None]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Missing required field(s) for a non-CPU-TEE launch config claim: {', '.join(missing)}"
            ),
        )


async def _validate_launch_config_env(
    db: AsyncSession,
    launch_config: LaunchConfig,
    chute: Chute,
    args: LaunchConfigArgs,
    log_prefix: str,
):
    from chutes.envdump import DUMPER

    # Verify, decrypt, parse the envdump payload. CPU-TEE chutes send no envdump (no aegis), so there
    # is nothing to decrypt -- their integrity is anchored by TD attestation + cosign image verification.
    if "ENVDUMP_UNLOCK" in os.environ and args.env:
        try:
            dump = await asyncio.to_thread(
                DUMPER.decrypt, launch_config.env_key, args.env
            )
        except Exception as exc:
            logger.error(
                f"Attempt to claim {launch_config.config_id=} failed, invalid envdump payload received: {exc}"
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = f"Unable to verify: {exc=} {args=}"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )

        # Check the environment.
        try:
            await verify_expected_command(
                dump,
                chute,
                miner_hotkey=launch_config.miner_hotkey,
            )
        except AssertionError as exc:
            logger.error(
                f"Attempt to claim {launch_config.config_id=} failed, invalid command: {exc}"
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = f"Invalid command: {exc}"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You are not running the correct command, sneaky devil: {exc}",
            )

        # K8S check.
        if not is_kubernetes_env(
            chute,
            dump,
            log_prefix=log_prefix,
            standard_template=chute.standard_template,
        ):
            logger.error(f"{log_prefix} is not running a valid kubernetes environment")
            launch_config.failed_at = func.now()
            launch_config.verification_error = "Failed kubernetes environment check."
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )

        # Ensure lmcache/vllm/sglang env can't be set outside of user's code.
        if semcomp(chute.chutes_version or "0.0.0", "0.4.0") >= 0:
            banned_keys = [
                key
                for key in dump["env"]
                if key.lower().startswith(
                    (
                        "lmcache",
                        "hf_token",
                        "huggingface_hub_token",
                        "hugging_face_hub_token",
                        "requests_ca_bundle",
                        "curl_ca_bundle",
                        "ssl_cert_file",
                    )
                )
                and key.lower()
                not in (
                    "hf_home",
                    "lmcache_use_experimental",
                )
            ]
            if banned_keys:
                logger.error(
                    f"{log_prefix} has LLM engine/HF/ssl/cache/etc. overrides: {banned_keys=}"
                )
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "Failed kubernetes environment check (llm/hf/sec/etc. envs)."
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )
    else:
        logger.warning("Unable to perform extended validation, skipping...")


async def _validate_launch_config_inspecto(
    db: AsyncSession,
    launch_config: LaunchConfig,
    chute: Chute,
    args: LaunchConfigArgs,
    log_prefix: str,
    *,
    inspecto_hash=_EXTERNAL_VALUE_UNSET,
):
    if semcomp(chute.chutes_version, "0.3.50") >= 0:
        # Inspecto
        if not args.inspecto:
            logger.error(f"{log_prefix} no inspecto hash provided")
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "Failed inspecto environment/lib verification."
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )

        check_inspecto = "PS_OP" in os.environ
        enforce_inspecto = check_inspecto and semcomp(chute.chutes_version, "0.5.5") < 0
        inspecto_valid = True
        fail_reason = None
        if check_inspecto:
            if inspecto_hash is _EXTERNAL_VALUE_UNSET:
                assert_gpu_external_work_allowed(db, "launch Inspecto hash lookup")
                inspecto_hash = await get_inspecto_hash(chute.image_id)
            if not inspecto_hash:
                logger.info(
                    f"INSPECTO: image_id={chute.image_id} has no inspecto hash; allowing."
                )
                inspecto_valid = True
            else:
                if not args.inspecto:
                    inspecto_valid = False
                    fail_reason = "missing args.inspecto hash!"
                else:
                    seed = launch_config.config_id
                    if semcomp(chute.chutes_version, "0.4.9") >= 0:
                        seed = args.rint_nonce + seed
                    raw = INSPECTO.verify_hash(
                        inspecto_hash.encode("utf-8"),
                        seed.encode("utf-8"),
                        args.inspecto.encode("utf-8"),
                    )
                    logger.info(
                        f"INSPECTO: verify_hash({inspecto_hash=}, {seed=}, {args.inspecto=}) -> {raw=}",
                    )
                    if not raw:
                        inspecto_valid = False
                        fail_reason = "inspecto returned NULL"
                    else:
                        try:
                            payload = json.loads(raw.decode("utf-8"))
                        except Exception as e:
                            inspecto_valid = False
                            fail_reason = f"inspecto returned non-JSON: {e}"
                        else:
                            if not payload.get("verified"):
                                inspecto_valid = False
                                fail_reason = f"inspecto verification failed: {payload}"
        if not inspecto_valid:
            if enforce_inspecto:
                logger.error(
                    f"{log_prefix} has invalid inspecto verification: {fail_reason}"
                )
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "Failed inspecto environment/lib verification."
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )
            else:
                logger.warning(
                    f"{log_prefix} inspecto mismatch (not enforced, chutes_version={chute.chutes_version}): {fail_reason}"
                )


FS_HASH_RESULT_TIMEOUT = 600.0


async def _await_fs_hash(task, config_id: str, miner_hotkey: str):
    """Bound worker waits so a stalled hash task cannot pin a request DB session."""
    try:
        return await task.wait_result(timeout=FS_HASH_RESULT_TIMEOUT)
    except TaskiqResultTimeoutError as exc:
        logger.error(
            f"FSHASH: task timed out after {FS_HASH_RESULT_TIMEOUT}s {config_id=} {miner_hotkey=}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Filesystem verification timed out; retry the launch claim.",
        ) from exc


def _launch_external_input_document(
    launch_config: LaunchConfig,
    chute: Chute,
    launch_job: Job | None,
    node_selector: NodeSelector,
    args: LaunchConfigArgs,
    *,
    is_private: bool,
) -> dict:
    """Canonical authority/request snapshot for bounded launch adapters."""

    job_document = None
    if launch_job is not None:
        job_document = {
            "job_id": launch_job.job_id,
            "user_id": launch_job.user_id,
            "chute_id": launch_job.chute_id,
            "version": launch_job.version,
            "method": launch_job.method,
            "finished": launch_job.finished_at is not None,
            "miner_hotkey": launch_job.miner_hotkey,
            "instance_id": launch_job.instance_id,
            "gpu_management_mode": launch_job.gpu_management_mode,
            "gpu_launch_reservation_id": launch_job.gpu_launch_reservation_id,
            "node_selector": launch_job.node_selector,
        }
    return {
        "schema": "chutes.launch-external-input.v1",
        "launch_config": {
            "config_id": launch_config.config_id,
            "chute_id": launch_config.chute_id,
            "user_id": launch_config.user_id,
            "compute_type": launch_config.compute_type,
            "job_id": launch_config.job_id,
            "host": launch_config.host,
            "port": launch_config.port,
            "env_type": launch_config.env_type,
            "miner_uid": launch_config.miner_uid,
            "miner_hotkey": launch_config.miner_hotkey,
            "miner_coldkey": launch_config.miner_coldkey,
            "server_id": launch_config.server_id,
            "gpu_management_mode": launch_config.gpu_management_mode,
            "gpu_launch_reservation_id": launch_config.gpu_launch_reservation_id,
            "container_repository": launch_config.container_repository,
            "container_manifest_digest": launch_config.container_manifest_digest,
            "nonce": launch_config.nonce,
            "failed": launch_config.failed_at is not None,
            "verified": launch_config.verified_at is not None,
            "completed": launch_config.completed_at is not None,
        },
        "chute": {
            "chute_id": chute.chute_id,
            "user_id": chute.user_id,
            "version": chute.version,
            "image_id": chute.image_id,
            "image_patch_version": getattr(chute.image, "patch_version", None),
            "chutes_version": chute.chutes_version,
            "node_selector": chute.node_selector,
            "public": bool(chute.public),
            "tee": bool(chute.tee),
            "disabled": bool(chute.disabled),
            "allow_external_egress": bool(chute.allow_external_egress),
            "filename": chute.filename,
            "standard_template": chute.standard_template,
            "boost": chute.boost,
        },
        "job": job_document,
        "node_selector": node_selector.model_dump(mode="json"),
        # Do not retain request secrets in the snapshot; the digest still binds every byte.
        "request_sha256": canonical_sha256(
            args.model_dump(mode="json", exclude_none=False)
        ),
        "private_launch": is_private,
    }


def _normalized_external_scalar(value):
    if isinstance(value, bytes):
        return value.decode()
    return value


async def _collect_launch_external_work(
    db: AsyncSession,
    input_document: dict,
    launch_config: LaunchConfig,
    chute: Chute,
    node_selector: NodeSelector,
    *,
    is_private: bool,
    managed_tee: bool,
) -> dict:
    """Run launch adapters only after the lifecycle transaction has committed."""

    assert_gpu_external_work_allowed(db, "launch pricing lookup")
    price = await node_selector.current_estimated_price()
    if not price or price.get("usd", {}).get("hour") is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Launch pricing is temporarily unavailable.",
        )

    assert_gpu_external_work_allowed(db, "launch manual boost lookup")
    manual_boost = await get_manual_boost(chute.chute_id)

    inspecto_hash = None
    if semcomp(chute.chutes_version, "0.3.50") >= 0 and "PS_OP" in os.environ:
        assert_gpu_external_work_allowed(db, "launch Inspecto hash lookup")
        inspecto_hash = await get_inspecto_hash(chute.image_id)

    scale_value = None
    inventory_history = None
    bounty_exists = None
    if launch_config.job_id is None:
        assert_gpu_external_work_allowed(db, "launch scale telemetry lookup")
        scale_value = _normalized_external_scalar(
            await settings.redis_client.get(f"scale:{chute.chute_id}")
        )
        if is_private:
            if not chute.tee:
                assert_gpu_external_work_allowed(
                    db, "private launch inventory telemetry lookup"
                )
                inventory_raw = await settings.redis_client.get(
                    f"uqhist:{launch_config.miner_hotkey}"
                )
                inventory_history = json.loads(inventory_raw) if inventory_raw else None
            assert_gpu_external_work_allowed(db, "private launch bounty lookup")
            bounty_exists = await check_bounty_exists(chute.chute_id)

    filesystem_hash = None
    if (
        not managed_tee
        and semcomp(chute.chutes_version, "0.3.1") >= 0
        and "CFSV_OP" in os.environ
    ):
        assert_gpu_external_work_allowed(db, "launch filesystem hash dispatch")
        task = await generate_fs_hash.kiq(
            chute.image_id,
            chute.image.patch_version,
            launch_config.config_id,
            sparse=False,
            exclude_path=f"/app/{chute.filename}",
        )
        assert_gpu_external_work_allowed(db, "launch filesystem hash wait")
        result = await _await_fs_hash(
            task,
            launch_config.config_id,
            launch_config.miner_hotkey,
        )
        filesystem_hash = result.return_value

    result_document = {
        "input_sha256": canonical_sha256(input_document),
        "hourly_price_usd": price["usd"]["hour"],
        "manual_boost": manual_boost,
        "inspecto_hash": inspecto_hash,
        "scale_value": scale_value,
        "inventory_history": inventory_history,
        "bounty_exists": bounty_exists,
        "filesystem_hash": filesystem_hash,
    }
    return {
        **result_document,
        "result_sha256": canonical_sha256(result_document),
    }


def _validate_launch_external_snapshot(snapshot: dict, input_document: dict) -> None:
    expected_input_hash = canonical_sha256(input_document)
    result_document = {
        key: snapshot.get(key)
        for key in (
            "input_sha256",
            "hourly_price_usd",
            "manual_boost",
            "inspecto_hash",
            "scale_value",
            "inventory_history",
            "bounty_exists",
            "filesystem_hash",
        )
    }
    if snapshot.get("input_sha256") != expected_input_hash or snapshot.get(
        "result_sha256"
    ) != canonical_sha256(result_document):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch authority changed while external validation was in progress.",
        )


async def _validate_launch_config_filesystem(
    db: AsyncSession,
    launch_config: LaunchConfig,
    chute: Chute,
    args: LaunchConfigArgs,
    *,
    expected_hash=_EXTERNAL_VALUE_UNSET,
):
    # Valid filesystem/integrity?
    if semcomp(chute.chutes_version, "0.3.1") >= 0:
        image_id = chute.image_id
        patch_version = chute.image.patch_version
        if "CFSV_OP" in os.environ:
            if expected_hash is _EXTERNAL_VALUE_UNSET:
                assert_gpu_external_work_allowed(db, "launch filesystem hash dispatch")
                task = await generate_fs_hash.kiq(
                    image_id,
                    patch_version,
                    launch_config.config_id,
                    sparse=False,
                    exclude_path=f"/app/{chute.filename}",
                )
                assert_gpu_external_work_allowed(db, "launch filesystem hash wait")
                result = await _await_fs_hash(
                    task, launch_config.config_id, launch_config.miner_hotkey
                )
                expected_hash = result.return_value
            if expected_hash != args.fsv:
                logger.error(
                    f"Filesystem challenge failed for {launch_config.config_id=} {launch_config.miner_hotkey=}, "
                    f"{expected_hash=} for {chute.image_id=} {patch_version=} but received {args.fsv}"
                )
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "File system verification failure, mismatched hash"
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )
        else:
            logger.warning("Extended filesystem verification disabled, skipping...")


async def _validate_launch_config_instance(
    db: AsyncSession,
    request: Request,
    args: LaunchConfigArgs,
    launch_config: LaunchConfig,
    chute: Chute,
    log_prefix: str,
    *,
    chutes_owner_id: str,
    external_snapshot: dict | None = None,
) -> Tuple[LaunchConfig, list[Node], Instance, Optional[str]]:
    await acquire_gpu_lifecycle_lock(db)
    config_id = launch_config.config_id
    launch_config = (
        await db.execute(
            select(LaunchConfig)
            .where(LaunchConfig.config_id == config_id)
            .with_for_update(of=LaunchConfig)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    chute = (
        (
            await db.execute(
                select(Chute)
                .where(Chute.chute_id == getattr(launch_config, "chute_id", None))
                .options(lazyload("*"), joinedload(Chute.image))
                .with_for_update(of=Chute)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if launch_config is None or chute is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch config or chute authority disappeared.",
        )
    miner = await _check_blacklisted(db, launch_config.miner_hotkey)
    launch_job = (
        (
            await db.execute(
                select(Job)
                .where(Job.job_id == launch_config.job_id)
                .with_for_update(of=Job)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if launch_config.job_id
        else None
    )
    if launch_config.job_id and (
        launch_job is None
        or launch_job.chute_id != chute.chute_id
        or launch_job.version != chute.version
        or launch_job.finished_at is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Job launch selector or workload lineage is no longer current.",
        )
    node_selector = NodeSelector(
        **(
            launch_job.node_selector
            if launch_job is not None and launch_job.node_selector
            else chute.node_selector
        )
    )

    # CPU-TEE chutes ship NO aegis/netnanny, so the validator cannot (and must not) require aegis
    # evidence from them: netnanny_hash, runtime-integrity commitment/nonce/pubkey, mTLS cert, cfsv
    # filesystem hash, and the cllmv session blob are all skipped below. Their integrity is anchored in
    # the TD attestation (dm-verity + RTMR), verified at server registration and by verify_tee_chute
    # (which also short-circuits self-registered servers). Every other launch check (IP match,
    # scalability, run_path tampering, job claim, instance pricing) still applies.
    cpu_tee = bool(chute.tee) and (node_selector.compute_type == "cpu")
    platform_gpu = bool(chute.tee) and launch_config.gpu_management_mode == "platform"
    managed_tee = cpu_tee or platform_gpu
    platform_reservation = None
    platform_server = None
    if platform_gpu:
        if not launch_config.gpu_launch_reservation_id or not launch_config.server_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Platform GPU launch config has no exact reservation/server binding.",
            )
        platform_reservation = (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.reservation_id
                    == launch_config.gpu_launch_reservation_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        platform_server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == launch_config.server_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            platform_reservation is None
            or platform_server is None
            or platform_reservation.state != "running"
            or platform_reservation.management_mode != "platform"
            or platform_reservation.server_id != platform_server.server_id
            or platform_reservation.reservation_id
            != platform_server.gpu_launch_reservation_id
            or platform_reservation.chute_id != launch_config.chute_id
            or platform_reservation.job_id != launch_config.job_id
            or platform_reservation.container_repository
            != launch_config.container_repository
            or platform_reservation.container_manifest_digest
            != launch_config.container_manifest_digest
            or platform_server.gpu_management_mode != "platform"
            or platform_server.gpu_retired_at is not None
            or platform_server.in_maintenance
            or platform_server.gpu_allocation_group_id
            != platform_reservation.allocation_group_id
            or platform_server.gpu_allocation_group_generation
            != platform_reservation.allocation_group_generation
            or platform_server.gpu_process_incarnation
            != platform_reservation.process_incarnation
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Platform GPU launch config lineage is stale or miner-managed.",
            )
        try:
            _current_attestation(
                platform_server,
                await _latest_attestation_attempt(db, platform_server.server_id),
            )
        except HTTPException as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Platform GPU server has no current successful evidence.",
            ) from exc
    gpu_lineage_reservation = platform_reservation
    if launch_config.gpu_management_mode == "miner":
        gpu_lineage_reservation = (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.reservation_id
                    == launch_config.gpu_launch_reservation_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        miner_server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == launch_config.server_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            gpu_lineage_reservation is None
            or miner_server is None
            or gpu_lineage_reservation.state != "running"
            or gpu_lineage_reservation.management_mode != "miner"
            or gpu_lineage_reservation.server_id != launch_config.server_id
            or miner_server.gpu_management_mode != "miner"
            or miner_server.gpu_launch_reservation_id
            != gpu_lineage_reservation.reservation_id
            or miner_server.gpu_retired_at is not None
            or miner_server.in_maintenance
            or miner_server.gpu_allocation_group_id
            != gpu_lineage_reservation.allocation_group_id
            or miner_server.gpu_allocation_group_generation
            != gpu_lineage_reservation.allocation_group_generation
            or miner_server.gpu_process_incarnation
            != gpu_lineage_reservation.process_incarnation
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Miner GPU launch config lineage is no longer current.",
            )
    if launch_job is not None:
        expected_mode = launch_config.gpu_management_mode
        if expected_mode in {"platform", "miner"} and (
            launch_job.gpu_management_mode != expected_mode
            or launch_job.gpu_launch_reservation_id
            != launch_config.gpu_launch_reservation_id
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Job is owned by a different GPU manager or reservation.",
            )
        if expected_mode is None and launch_job.gpu_management_mode is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Legacy launch config cannot claim a managed GPU job.",
            )

    is_private = bool(
        not chute.public
        and not has_legacy_private_billing(chute)
        and chute.user_id != chutes_owner_id
    )
    external_input = _launch_external_input_document(
        launch_config,
        chute,
        launch_job,
        node_selector,
        args,
        is_private=is_private,
    )
    if external_snapshot is None:
        # Environment decryption/validation is local-only. It must precede the
        # durable external-work intent, but performs no network/Redis/subprocess I/O.
        await _validate_launch_config_env(db, launch_config, chute, args, log_prefix)
        # `retrieved_at` plus the exact current authority form the durable intent.
        # Commit before Redis, pricing, task dispatch, or task result waits.
        await db.commit()
        external_snapshot = await _collect_launch_external_work(
            db,
            external_input,
            launch_config,
            chute,
            node_selector,
            is_private=is_private,
            managed_tee=managed_tee,
        )

        await acquire_gpu_lifecycle_lock(db)
        current_config = (
            await db.execute(
                select(LaunchConfig)
                .where(LaunchConfig.config_id == launch_config.config_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        current_chute = (
            (
                await db.execute(
                    select(Chute)
                    .where(Chute.chute_id == launch_config.chute_id)
                    .options(lazyload("*"), joinedload(Chute.image))
                    .with_for_update(of=Chute)
                    .execution_options(populate_existing=True)
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        existing_instance = await db.scalar(
            select(Instance.instance_id).where(
                Instance.config_id == launch_config.config_id
            )
        )
        if (
            current_config is None
            or current_chute is None
            or current_config.failed_at is not None
            or current_config.verified_at is not None
            or current_config.completed_at is not None
            or existing_instance is not None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Launch authority changed while external validation was in progress.",
            )
        return await _validate_launch_config_instance(
            db,
            request,
            args,
            current_config,
            current_chute,
            log_prefix,
            chutes_owner_id=chutes_owner_id,
            external_snapshot=external_snapshot,
        )

    _validate_launch_external_snapshot(external_snapshot, external_input)
    await _validate_launch_config_inspecto(
        db,
        launch_config,
        chute,
        args,
        log_prefix,
        inspecto_hash=external_snapshot["inspecto_hash"],
    )

    # Generate a tentative instance ID only after the external snapshot has
    # been rebound to the exact locked launch/chute/job authority.
    new_instance_id = generate_uuid()

    # Re-check scalable...
    if not launch_config.job_id:
        try:
            if is_private:
                await _check_scalable_private(
                    db,
                    chute,
                    miner,
                    inventory_history=external_snapshot["inventory_history"],
                    scale_value=external_snapshot["scale_value"],
                    bounty_exists=external_snapshot["bounty_exists"],
                )
            else:
                await _check_scalable(
                    db,
                    chute,
                    launch_config.miner_hotkey,
                    scale_value=external_snapshot["scale_value"],
                )
        except HTTPException as exc:
            launch_config.failed_at = func.now()
            detail = exc.detail
            launch_config.verification_error = (
                detail if isinstance(detail, str) else str(detail)
            )
            await db.commit()
            raise

    # IP matches?
    actual_ip = request.state.client_ip
    if actual_ip != args.host:
        logger.warning(
            f"Instance with {launch_config.config_id=} {launch_config.miner_hotkey=} EGRESS INGRESS mismatch!: {actual_ip=} {args.host=}"
        )
        if launch_config.job_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Egress and ingress IPs much match for jobs: {actual_ip} vs {args.host}",
            )

    # Uniqueness of host/miner_hotkey.
    result = await db.scalar(
        select(Instance).where(
            and_(
                Instance.host == launch_config.host,
                Instance.miner_hotkey != launch_config.miner_hotkey,
            )
        )
    )
    if result:
        logger.warning(
            f"{launch_config.config_id=} {launch_config.miner_hotkey=} attempted to use host already used by another miner!"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Host {launch_config.host} is already assigned to at least one other miner_hotkey.",
        )

    if semcomp(chute.chutes_version, "0.3.50") >= 0:
        if not args.run_path or (
            chute.standard_template == "vllm"
            and os.path.dirname(args.run_path)
            != "/usr/local/lib/python3.12/dist-packages/chutes/entrypoint"
        ):
            logger.error(f"{log_prefix} has tampered with paths!")
            launch_config.failed_at = func.now()
            launch_config.verification_error = "Env tampering detected!"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )

        # NetNanny / Aegis verification (match egress config and hash).
        nn_valid = True
        if managed_tee:
            # CPU-TEE: no in-image netnanny/aegis; the TD attestation is the integrity proof.
            pass
        elif semcomp(chute.chutes_version or "0.0.0", "0.5.5") >= 0:
            # v4 (aegis): netnanny_hash comes from aegis-verify; also verify egress config.
            if chute.allow_external_egress != args.egress:
                logger.error(
                    f"{log_prefix} egress mismatch for v4 instance: {chute.allow_external_egress=} vs {args.egress=}"
                )
                nn_valid = False
            elif not args.netnanny_hash:
                nn_valid = False
            elif AEGIS_VERIFY is not None:
                if not AEGIS_VERIFY.verify(
                    launch_config.config_id.encode(),
                    args.netnanny_hash.encode(),
                    1,
                ):
                    logger.error(
                        f"{log_prefix} aegis-verify hash mismatch for {launch_config.config_id=}"
                    )
                    nn_valid = False
                else:
                    logger.success(
                        f"{log_prefix} aegis-verify hash challenge success: {launch_config.config_id=} {args.netnanny_hash=}"
                    )
            else:
                # aegis-verify .so must be deployed for v4 instances — hard fail.
                logger.error(
                    f"{log_prefix} aegis-verify library not available, cannot verify v4 instance"
                )
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "aegis-verify library not available for v4 verification"
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="aegis-verify library not available, cannot verify v4 instances",
                )
        elif chute.allow_external_egress != args.egress or not args.netnanny_hash:
            nn_valid = False
        else:
            if not NETNANNY.verify(
                launch_config.config_id.encode(),
                args.netnanny_hash.encode(),
                1,
            ):
                logger.error(
                    f"{log_prefix} netnanny hash mismatch for {launch_config.config_id=} and {chute.allow_external_egress=}"
                )
                nn_valid = False
            else:
                logger.success(
                    f"{log_prefix} netnanny hash challenge success: for {launch_config.config_id=} and {chute.allow_external_egress=} {args.netnanny_hash=}"
                )
        if not nn_valid:
            logger.error(
                f"{log_prefix} has tampered with netnanny? {args.netnanny_hash=} {args.egress=} {chute.allow_external_egress=}"
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = "Failed aegis validation."
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )

    # Runtime integrity (runint) verification for version >= 0.4.9 (aegis-backed; skipped for CPU-TEE).
    if not managed_tee and semcomp(chute.chutes_version, "0.4.9") >= 0:
        if not launch_config.nonce or not args.rint_nonce:
            logger.error(f"{log_prefix} missing runint nonce in launch config")
            launch_config.failed_at = func.now()
            launch_config.verification_error = "Missing runtime integrity nonce"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )
        if semcomp(chute.chutes_version, "0.5.0") >= 0:
            if not args.rint_commitment:
                logger.error(f"{log_prefix} missing runint commitment")
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "Missing runtime integrity commitment"
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )
            if not _verify_rint_commitment(args.rint_commitment, launch_config.nonce):
                logger.error(f"{log_prefix} invalid runint commitment")
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "Invalid runtime integrity commitment"
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )

    # Filesystem (cfsv) verification is aegis-backed; CPU-TEE has no cfsv index to verify.
    if not managed_tee:
        await _validate_launch_config_filesystem(
            db,
            launch_config,
            chute,
            args,
            expected_hash=external_snapshot["filesystem_hash"],
        )

    # Assign the job to this launch config.
    if launch_config.job_id:
        job_claim_conditions = [
            Job.job_id == launch_config.job_id,
            Job.miner_hotkey.is_(None),
        ]
        if launch_config.gpu_management_mode in {"platform", "miner"}:
            job_claim_conditions.extend(
                [
                    Job.gpu_management_mode == launch_config.gpu_management_mode,
                    Job.gpu_launch_reservation_id
                    == launch_config.gpu_launch_reservation_id,
                ]
            )
        else:
            job_claim_conditions.extend(
                [
                    Job.gpu_management_mode.is_(None),
                    Job.gpu_launch_reservation_id.is_(None),
                ]
            )
        stmt = (
            update(Job)
            .where(*job_claim_conditions)
            .values(
                miner_uid=launch_config.miner_uid,
                miner_hotkey=launch_config.miner_hotkey,
                miner_coldkey=launch_config.miner_coldkey,
            )
        )
        result = await db.execute(stmt)
        if result.rowcount == 0:
            # Job was already claimed by another miner
            logger.warning(
                f"Job {launch_config.job_id=} via {launch_config.config_id=} was already "
                f"claimed when miner {launch_config.miner_hotkey=} tried to claim it."
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "Job was already claimed by another miner"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Job {launch_config.job_id} has already been claimed by another miner!",
            )

    # Validate TLS certificate for v4 instances (>= 0.5.5).
    validated_cacert = None
    is_v4 = semcomp(chute.chutes_version or "0.0.0", "0.5.5") >= 0
    tls_cert = getattr(args, "tls_cert", None)
    tls_cert_sig = getattr(args, "tls_cert_sig", None)
    rint_commitment = getattr(args, "rint_commitment", None)

    if is_v4 and not managed_tee:
        if not rint_commitment or rint_commitment[:2] != "04":
            logger.error(
                f"{log_prefix} v4 instance (>= 0.5.5) must provide v4 (04-prefix) rint_commitment"
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "v4 instance must provide v4 rint_commitment"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="chutes >= 0.5.5 must provide a v4 runtime integrity commitment",
            )
        if not tls_cert or not tls_cert_sig:
            logger.error(f"{log_prefix} v4 instance missing tls_cert or tls_cert_sig")
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "v4 instance must provide TLS certificate"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="v4 instances must provide a TLS certificate and signature",
            )
        if not _validate_tls_cert(
            tls_cert, tls_cert_sig, rint_commitment, launch_config.nonce
        ):
            logger.error(f"{log_prefix} TLS cert signature validation failed")
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "TLS certificate signature validation failed"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="TLS certificate signature validation failed",
            )
        validated_cacert = tls_cert

    # CPU-TEE: pin the server's attestation-bound serving cert so the validator<->chute user-data
    # transport is TLS terminated INSIDE the attested TD. The cert's pubkey hash is bound into the
    # server's registration TDX quote (verify_quote at /servers/cpu/register), so a host-forged cert
    # cannot match and the untrusted host (which routes the TD's traffic) cannot MITM/read/tamper it.
    # Fail closed: no attested cert on record => no provably-private channel, so refuse to launch.
    if managed_tee:
        server_row = None
        if getattr(launch_config, "server_id", None):
            server_row = (
                await db.execute(
                    select(Server).where(Server.server_id == launch_config.server_id)
                )
            ).scalar_one_or_none()
        attested_cert = getattr(server_row, "attested_cert", None)
        if server_row is not None and server_row.in_maintenance:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Server {server_row.name} is in TEE maintenance mode and cannot accept new instances.",
            )
        if not attested_cert:
            logger.error(
                f"{log_prefix} CPU-TEE server {getattr(launch_config, 'server_id', None)} has no "
                "attestation-bound TLS cert on record"
            )
            launch_config.failed_at = func.now()
            launch_config.verification_error = (
                "CPU-TEE server has no attestation-bound TLS cert on record; re-register the server "
                "(POST /servers/cpu/register) so the validator can pin its attested transport cert."
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=launch_config.verification_error,
            )
        validated_cacert = attested_cert

        # Attestation-bind the e2e public key: a CPU-TEE chute that advertises an ML-KEM e2e_pubkey
        # must prove it was generated inside the attested TD by signing it with the attested cert key
        # (verified against the cert just pinned above). Without this, the host/validator could publish
        # a substituted key via /e2e/instances and break the validator-blind e2e guarantee. Fail closed
        # on a present-but-unsigned or mis-signed key; an absent key just opts this chute out of e2e
        # (it will not be returned by /e2e/instances).
        cpu_e2e_pubkey = getattr(args, "e2e_pubkey", None)
        if cpu_e2e_pubkey:
            cpu_e2e_pubkey_sig = getattr(args, "e2e_pubkey_sig", None)
            if not cpu_e2e_pubkey_sig or not _verify_e2e_pubkey_sig(
                attested_cert,
                cpu_e2e_pubkey,
                cpu_e2e_pubkey_sig,
                launch_config.config_id,
            ):
                logger.error(
                    f"{log_prefix} CPU-TEE e2e_pubkey attestation-binding failed"
                )
                launch_config.failed_at = func.now()
                launch_config.verification_error = (
                    "CPU-TEE e2e_pubkey is not attestation-bound (missing or invalid signature by the "
                    "server's attested cert key)"
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )

    # Create the instance now that we've verified the envdump/k8s env.
    is_cpu = node_selector.compute_type == "cpu"
    extra_fields = {
        "e2e_pubkey": getattr(args, "e2e_pubkey", None),
    }
    # CPU-TEE instances carry no aegis session key; mark them so the API sends plaintext (no cipher)
    # over the TD-secured transport instead of raising on a missing rint_session_key.
    if managed_tee:
        extra_fields["cpu_tee"] = True
    # Store CA cert for SSL verification (separate from server cert in cacert).
    tls_ca_cert = getattr(args, "tls_ca_cert", None)
    if tls_ca_cert:
        extra_fields["ca_cert"] = tls_ca_cert
    # Store mTLS client cert + key for API-to-instance connections.
    # Client key is unencrypted (no passphrase).
    tls_client_cert = getattr(args, "tls_client_cert", None)
    if tls_client_cert:
        extra_fields["client_cert"] = tls_client_cert
        extra_fields["client_key"] = getattr(args, "tls_client_key", None)

    instance = Instance(
        instance_id=new_instance_id,
        host=args.host,
        port=args.port_mappings[0].external_port,
        chute_id=launch_config.chute_id,
        version=chute.version,
        miner_uid=launch_config.miner_uid,
        miner_hotkey=launch_config.miner_hotkey,
        miner_coldkey=launch_config.miner_coldkey,
        region="n/a",
        active=False,
        verified=False,
        chutes_version=chute.chutes_version,
        symmetric_key=secrets.token_bytes(16).hex(),
        config_id=launch_config.config_id,
        # Model B: stamp the exact server. Co-tenant TDs on one L0 host share its public IP, so the
        # later instance<->server resolution (verify_tee_chute) must key off server_id, not host IP,
        # or it 409s on the shared IP. NULL for the legacy miner-run path (resolved by IP/GPUs).
        server_id=launch_config.server_id,
        gpu_management_mode=launch_config.gpu_management_mode,
        gpu_launch_reservation_id=(
            gpu_lineage_reservation.reservation_id
            if gpu_lineage_reservation is not None
            else None
        ),
        gpu_allocation_group_id=(
            gpu_lineage_reservation.allocation_group_id
            if gpu_lineage_reservation is not None
            else None
        ),
        gpu_allocation_group_generation=(
            gpu_lineage_reservation.allocation_group_generation
            if gpu_lineage_reservation is not None
            else None
        ),
        gpu_process_incarnation=(
            gpu_lineage_reservation.process_incarnation
            if gpu_lineage_reservation is not None
            else None
        ),
        port_mappings=[item.model_dump() for item in args.port_mappings],
        compute_multiplier=node_selector.compute_multiplier,
        billed_to=None,
        hourly_rate=external_snapshot["hourly_price_usd"],
        inspecto=getattr(args, "inspecto", None),
        env_creation=args.model_dump(),
        rint_commitment=rint_commitment,
        rint_nonce=getattr(args, "rint_nonce", None),
        rint_pubkey=getattr(args, "rint_pubkey", None),
        cacert=validated_cacert,
        extra={k: v for k, v in extra_fields.items() if v is not None} or None,
    )
    if launch_config.job_id or is_private:
        # Integrated subnet?
        integrated = False
        for config in INTEGRATED_SUBNETS.values():
            if config["model_substring"] in chute.name.lower():
                integrated = True
                break
        if chute.tee:
            bonus = TEE_PRIVATE_INSTANCE_BONUS
        elif integrated:
            bonus = INTEGRATED_SUBNET_BONUS
        else:
            bonus = PRIVATE_INSTANCE_BONUS
        instance.compute_multiplier *= bonus
        logger.info(
            f"Adding private instance bonus value {bonus=} to {instance.instance_id} "
            f"for total {instance.compute_multiplier=} for {chute.name=} {chute.chute_id=} {integrated=}"
        )
        instance.billed_to = (
            launch_job.user_id if launch_job is not None else chute.user_id
        )

    # Track the warmup (base) multiplier separately — this is node_selector + private/tee bonus
    # + manual boost + TEE bonus, but WITHOUT urgency (chute.boost) or bounty.
    # Used at activation time for the startup period compute history record.
    warmup_compute_multiplier = instance.compute_multiplier

    # Add chute boost (urgency boost from autoscaler).
    # Skip for private instances — their multiplier stays at the base GPU calculation.
    # Use DB NOW() via None param since launch_config.created_at
    # can be created hours before the instance is actually created.
    if (
        instance.billed_to is None
        and chute.boost is not None
        and chute.boost > 0
        and chute.boost <= 20
    ):
        instance.compute_multiplier *= chute.boost
        logger.info(
            f"Adding chute boost {chute.boost=} to {instance.instance_id} "
            f"for total {instance.compute_multiplier=} for {chute.name=} {chute.chute_id=}"
        )

    # Add manual boost (optional fine-tuning).
    manual_boost = external_snapshot["manual_boost"]
    if manual_boost != 1.0:
        instance.compute_multiplier *= manual_boost
        warmup_compute_multiplier *= manual_boost
        logger.info(
            f"Adding manual boost {manual_boost=} to {instance.instance_id} "
            f"for total {instance.compute_multiplier=} for {chute.name=} {chute.chute_id=}"
        )

    # Add TEE boost.
    if chute.tee:
        instance.compute_multiplier *= TEE_BONUS
        warmup_compute_multiplier *= TEE_BONUS
        logger.info(
            f"Adding TEE instance bonus value {TEE_BONUS} to {instance.instance_id} "
            f"for total {instance.compute_multiplier=} for {chute.name=} {chute.chute_id=}"
        )

    # 1-click CPU servers: carry the scheduler-stamped target server onto the instance so it can
    # be linked back to its self-registered server (no GPU nodes / host+hotkey inference needed).
    if getattr(launch_config, "server_id", None):
        instance.server_id = launch_config.server_id

    db.add(instance)

    # Mark the job as associated with this instance.
    if launch_config.job_id:
        job = launch_job
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {launch_config.job_id} no longer exists!",
            )
        job.instance_id = instance.instance_id
        job.port_mappings = [item.model_dump() for item in args.port_mappings]

        # Verify port mappings are correct.
        job_obj = next(j for j in chute.jobs if j["name"] == job.method)
        expected = set([f"{p['proto']}:{p['port']}".lower() for p in job_obj["ports"]])
        received = set(
            [
                f"{p.proto}:{p.internal_port}".lower()
                for p in args.port_mappings
                if p.internal_port not in [8000, 8001]
            ]
        )
        if expected != received:
            logger.error(
                f"{instance.instance_id=} from {config_id=} posted invalid ports: {expected=} vs {received=}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Invalid port mappings provided: {expected=} {received=}",
            )

    # Verify the GPUs are suitable. CPU (GPU-less) chutes have no GPU nodes; their pricing
    # stays at the node-selector CPU estimate (no actual-GPU re-pricing).
    if is_cpu:
        node_ids = []
    else:
        if len(set([node["uuid"] for node in args.gpus])) != len(args.gpus):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate GPUs in request!",
            )
        node_ids = [node["uuid"] for node in args.gpus]

    # Capture chute_id before the try/except: db.rollback() expires ORM attributes, so
    # accessing launch_config.chute_id afterwards could trigger sync IO in this async flow
    # and mask the original validation failure with MissingGreenlet.
    chute_id = launch_config.chute_id
    try:
        nodes = await _validate_nodes(
            db,
            chute,
            node_ids,
            launch_config.miner_hotkey,
            instance,
            node_selector,
        )
        if gpu_lineage_reservation is not None:
            lineage_group = (
                await db.execute(
                    select(GpuAllocationGroup)
                    .where(
                        GpuAllocationGroup.allocation_group_id
                        == gpu_lineage_reservation.allocation_group_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            lineage_report = (
                await db.execute(
                    select(GpuInventoryReport)
                    .where(
                        GpuInventoryReport.report_id
                        == getattr(lineage_group, "last_report_id", None)
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            try:
                lineage_report_claims = (
                    GpuInventoryReportV1.model_validate(lineage_report.claims)
                    if lineage_report is not None
                    else None
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current GPU inventory report is malformed.",
                ) from exc
            matching_inventory_groups = [
                item
                for item in (
                    lineage_report_claims.groups
                    if lineage_report_claims is not None
                    else []
                )
                if item.topology_fingerprint
                == gpu_lineage_reservation.topology_fingerprint
                and [device.bdf for device in item.devices]
                == list(gpu_lineage_reservation.gpu_bdfs)
                and [device.uuid for device in item.devices]
                == list(gpu_lineage_reservation.gpu_uuids)
            ]
            if (
                lineage_group is None
                or lineage_report is None
                or lineage_report_claims is None
                or len(matching_inventory_groups) != 1
                or lineage_group.state != "running"
                or lineage_group.reservation_id
                != gpu_lineage_reservation.reservation_id
                or lineage_group.generation
                != gpu_lineage_reservation.allocation_group_generation
                or lineage_group.reservation_generation
                != gpu_lineage_reservation.reservation_generation
                or lineage_group.process_incarnation
                != gpu_lineage_reservation.process_incarnation
                or lineage_report.reconciliation_status != "accepted"
                or lineage_report.host_id != gpu_lineage_reservation.host_id
                or lineage_report.host_key_generation
                != gpu_lineage_reservation.host_key_generation
                or lineage_report.host_boot_generation
                != gpu_lineage_reservation.host_boot_generation
                or lineage_report.claims_sha256
                != canonical_sha256(lineage_report_claims)
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="GPU workload inventory lineage is no longer current.",
                )
            inventory_by_uuid = {
                item.uuid: item for item in matching_inventory_groups[0].devices
            }
            selected_uuids = {node.uuid for node in nodes}
            reserved_uuids = set(gpu_lineage_reservation.gpu_uuids)
            mismatched_lineage = any(
                node.server_id != launch_config.server_id
                or node.gpu_allocation_group_id
                != gpu_lineage_reservation.allocation_group_id
                or node.gpu_allocation_group_generation
                != gpu_lineage_reservation.allocation_group_generation
                or node.gpu_launch_reservation_id
                != gpu_lineage_reservation.reservation_id
                or node.gpu_process_incarnation
                != gpu_lineage_reservation.process_incarnation
                or node.gpu_inventory_report_id != lineage_report.report_id
                or node.gpu_retired_at is not None
                or node.uuid not in inventory_by_uuid
                or node.gpu_identifier != inventory_by_uuid[node.uuid].gpu_identifier
                for node in nodes
            )
            if launch_config.gpu_management_mode == "platform" and (
                selected_uuids != reserved_uuids or mismatched_lineage
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Platform workload requires the exact reserved GPU UUID set "
                        "and server/group generation lineage."
                    ),
                )
            if launch_config.gpu_management_mode == "miner" and (
                not selected_uuids
                or not selected_uuids.issubset(reserved_uuids)
                or mismatched_lineage
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "Miner workload GPUs must be a nonempty subset of its exact "
                        "server/group generation reservation lineage."
                    ),
                )
    except Exception:
        await db.rollback()
        async with get_session() as error_session:
            await error_session.execute(
                text(
                    "UPDATE launch_configs SET failed_at = NOW(), "
                    "verification_error = 'invalid GPU/nodes configuration provided' "
                    "WHERE config_id = :config_id"
                ),
                {"config_id": config_id},
            )
            await error_session.commit()
        # Raw SQL bypasses the LaunchConfig verification_error listener, so account for
        # this failure explicitly using the pre-rollback chute identity.
        track_launch_config_failure(
            chute_id, "invalid GPU/nodes configuration provided"
        )
        raise

    if not is_cpu:
        # Use the actual GPU's rate/multiplier instead of the
        # minimum across all supported GPUs in the node selector.
        actual_gpu = nodes[0].gpu_identifier
        gpu_count = node_selector.gpu_count or 0
        actual_base = gpu_count * COMPUTE_MULTIPLIER[actual_gpu]
        ns_min_compute = node_selector.compute_multiplier
        ns_min_hourly = instance.hourly_rate
        if ns_min_compute > 0 and actual_base != ns_min_compute:
            ratio = actual_base / ns_min_compute
            instance.compute_multiplier *= ratio
            warmup_compute_multiplier *= ratio
        instance.hourly_rate = SUPPORTED_GPUS[actual_gpu]["hourly_rate"] * gpu_count
        logger.info(
            f"Adjusted instance {instance.instance_id} for "
            f"chute_id={chute.chute_id} name={chute.name!r} to actual GPU {actual_gpu}: "
            f"hourly_rate={ns_min_hourly:.4f}->{instance.hourly_rate:.4f} "
            f"(delta={instance.hourly_rate - ns_min_hourly:+.4f}, ratio={instance.hourly_rate / ns_min_hourly if ns_min_hourly else 0:.2f}x), "
            f"compute_multiplier={ns_min_compute:.4f}->{actual_base:.4f} "
            f"(delta={actual_base - ns_min_compute:+.4f}, ratio={actual_base / ns_min_compute if ns_min_compute else 0:.2f}x)"
        )

    # Store the warmup (base) compute multiplier for use at activation time.
    if instance.extra is None:
        instance.extra = {}
    instance.extra["warmup_compute_multiplier"] = warmup_compute_multiplier

    # Enforce rint_pubkey for chutes >= 0.5.1 (aegis-backed; skipped for CPU-TEE).
    if not managed_tee and semcomp(instance.chutes_version or "0.0.0", "0.5.1") >= 0:
        if not instance.rint_pubkey or not instance.rint_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="rint_pubkey and rint_nonce required for chutes >= 0.5.1",
            )

    # Generate session key if miner provided rint_pubkey
    validator_pubkey = None
    if instance.rint_pubkey and instance.rint_nonce:
        try:
            if semcomp(instance.chutes_version or "0.0.0", "0.5.5") >= 0:
                validator_pubkey, session_key = derive_x25519_session_key(
                    instance.rint_pubkey, instance.rint_nonce
                )
            else:
                validator_pubkey, session_key = derive_ecdh_session_key(
                    instance.rint_pubkey, instance.rint_nonce
                )
            instance.rint_session_key = session_key
            logger.info(
                f"Derived session key for {instance.instance_id} validator_pubkey={validator_pubkey[:16]}..."
            )
        except Exception as exc:
            logger.error(f"Session key derivation failed: {exc}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Session key derivation failed: {exc}",
            )

    # CLLMV V2: decrypt miner's ephemeral HMAC session key from init blob
    cllmv_init = getattr(args, "cllmv_session_init", None)
    is_v4_instance = semcomp(instance.chutes_version or "0.0.0", "0.5.5") >= 0
    if is_v4_instance and not managed_tee:
        if not cllmv_init:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cllmv_session_init required for chutes >= 0.5.5",
            )
        x25519_priv = os.environ.get("CLLMV_X25519_PRIVATE_KEY")
        if not x25519_priv:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CLLMV V2 not configured on validator",
            )
        try:
            cllmv_session_key = _decrypt_cllmv_session_key(cllmv_init, x25519_priv)
            if not cllmv_session_key:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="CLLMV V2 session key decryption failed (invalid init blob or signature)",
                )
            if instance.extra is None:
                instance.extra = {}
            instance.extra = {**instance.extra, "cllmv_session_key": cllmv_session_key}
            logger.info(f"CLLMV V2 session key decrypted for {instance.instance_id}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"CLLMV V2 session key decryption error: {exc}",
            )
    elif cllmv_init:
        # Pre-0.5.5 instance sent cllmv_init anyway — best-effort decrypt
        x25519_priv = os.environ.get("CLLMV_X25519_PRIVATE_KEY")
        if x25519_priv:
            try:
                cllmv_session_key = _decrypt_cllmv_session_key(cllmv_init, x25519_priv)
                if cllmv_session_key:
                    if instance.extra is None:
                        instance.extra = {}
                    instance.extra = {
                        **instance.extra,
                        "cllmv_session_key": cllmv_session_key,
                    }
                    logger.info(
                        f"CLLMV V2 session key decrypted for {instance.instance_id}"
                    )
            except Exception as exc:
                logger.warning(
                    f"CLLMV V2 session key decryption error (pre-0.5.5): {exc}"
                )

    # Instance resolve point shared by TEE and non-TEE launch flows: bind the full
    # identity set so downstream attestation failures remain correlatable.
    update_log_context(
        instance_id=instance.instance_id,
        config_id=launch_config.config_id,
        chute_id=launch_config.chute_id,
        miner_hotkey=launch_config.miner_hotkey,
    )

    return launch_config, nodes, instance, validator_pubkey


async def _validate_graval_launch_config_instance(
    config_id: str,
    args: LaunchConfigArgs,
    request: Request,
    db: AsyncSession,
    authorization: str,
) -> Tuple[LaunchConfig, list[Node], Instance, Optional[str]]:
    chutes_owner_id = await chutes_user_id()
    await acquire_gpu_lifecycle_lock(db)
    token = authorization.strip().split(" ")[-1]
    launch_config = await load_launch_config_from_jwt(db, config_id, token)
    chute = await _load_chute(db, launch_config.chute_id)
    _require_secure_source_delivery(chute)
    log_prefix = f"ENVDUMP: {launch_config.config_id=} {chute.chute_id=}"

    if chute.disabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Chute {chute.chute_id} is currently disabled",
        )

    if chute.tee:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can not claim a graval launch config for a TEE chute.",
        )

    _require_non_cpu_tee_claim_fields(chute, args, launch_config)

    return await _validate_launch_config_instance(
        db,
        request,
        args,
        launch_config,
        chute,
        log_prefix,
        chutes_owner_id=chutes_owner_id,
    )


async def _validate_tee_launch_config_instance(
    config_id: str,
    args: TeeLaunchConfigArgs,
    request: Request,
    db: AsyncSession,
    authorization: str,
) -> Tuple[LaunchConfig, list[Node], Instance, Optional[str]]:
    chutes_owner_id = await chutes_user_id()
    await acquire_gpu_lifecycle_lock(db)
    token = authorization.strip().split(" ")[-1]
    launch_config = await load_launch_config_from_jwt(db, config_id, token)
    chute = await _load_chute(db, launch_config.chute_id)
    _require_secure_source_delivery(chute)
    log_prefix = f"ENVDUMP: {launch_config.config_id=} {chute.chute_id=}"

    if chute.disabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Chute {chute.chute_id} is currently disabled",
        )

    if not chute.tee:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can not claim a TEE launch config for a non-TEE chute.",
        )

    _require_non_cpu_tee_claim_fields(chute, args, launch_config)

    # Deny launches on servers in TEE maintenance mode before creating any instance/node records.
    # CPU (GPU-less) chutes have no GPU nodes, so the server is resolved by host + miner_hotkey.
    is_cpu = (
        str((chute.node_selector or {}).get("compute_type", "gpu")).lower() == "cpu"
    )
    if is_cpu or launch_config.gpu_management_mode == "platform":
        server = await get_cpu_server_for_host(
            db, args.host, launch_config.miner_hotkey, server_id=launch_config.server_id
        )
    else:
        server = await get_server_for_gpus(db, [g["uuid"] for g in args.gpus])
    if server and server.in_maintenance:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Server {server.name} is in TEE maintenance mode and cannot accept new instances.",
        )

    (
        launch_config,
        nodes,
        instance,
        validator_pubkey,
    ) = await _validate_launch_config_instance(
        db,
        request,
        args,
        launch_config,
        chute,
        log_prefix,
        chutes_owner_id=chutes_owner_id,
    )

    # Reject new chutes (>= 0.6.0) on old VMs (latest boot attestation measurement_version < 0.2.0).
    # Newer 0.2.0+ VMs can run both old and new chutes.
    # TODO: Remove this once TEE servers are upgraded to 0.2.0 or later
    if semcomp(instance.chutes_version or "0.0.0", "0.6.0") >= 0:
        # Self-registered CPU-TEE servers attest via the CPU-register flow (recording the matched
        # measurement version on server.version) and never run the boot/LUKS BootAttestation flow, so
        # they have no BootAttestation row -- use the server's attested measurement version for them.
        server = None
        if getattr(instance, "server_id", None):
            server = (
                await db.execute(
                    select(Server).where(Server.server_id == instance.server_id)
                )
            ).scalar_one_or_none()
        if server is not None and getattr(server, "self_registered", False):
            measurement_version = server.version
        else:
            stmt = (
                select(BootAttestation)
                .where(BootAttestation.server_ip == instance.host)
                .order_by(desc(BootAttestation.created_at))
                .limit(1)
            )
            latest_boot = (await db.execute(stmt)).scalar_one_or_none()
            measurement_version = (
                latest_boot.measurement_version if latest_boot else None
            )
        if measurement_version is None or semcomp(measurement_version, "0.2.0") < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Chutes version >= 0.6.0 requires VM measurement version >= 0.2.0. "
                    "Upgrade the VM image to run this chute."
                ),
            )

    return launch_config, nodes, instance, validator_pubkey


async def _verify_tee_version_support(
    db: AsyncSession, chute: Chute, hotkey: str | None
) -> None:
    """
    Reject launch config for TEE chutes (>= 0.6.0) when miner has legacy TEE servers (< 0.2.1).
    Raises HTTPException with server names if any TEE servers need upgrading.
    """
    if (
        not chute.tee
        or not hotkey
        or semcomp(chute.chutes_version or "0.0.0", "0.6.0") < 0
    ):
        return

    latest_boot = (
        select(BootAttestation.measurement_version)
        .where(BootAttestation.server_ip == Server.ip)
        .order_by(desc(BootAttestation.created_at))
        .limit(1)
        .lateral()
    )
    stmt = (
        select(Server.name, latest_boot.c.measurement_version)
        .select_from(Server)
        .outerjoin(latest_boot, true())
        .where(Server.miner_hotkey == hotkey, Server.is_tee.is_(True))
    )
    result = await db.execute(stmt)
    legacy_server_names = [
        row[0] for row in result.all() if row[1] is None or semcomp(row[1], "0.2.1") < 0
    ]
    if legacy_server_names:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Launch config rejected: you have legacy TEE infrastructure which does not "
                "support chutes lib version >= 0.6.0. Upgrade these servers first: "
                f"{', '.join(legacy_server_names)}"
            ),
        )


MIN_SECURE_SOURCE_RUNTIME_VERSION = "0.3.61"


def _require_secure_source_delivery(chute: Chute) -> None:
    version = chute.chutes_version
    if not version or semcomp(version, MIN_SECURE_SOURCE_RUNTIME_VERSION) < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported chutes runtime version {version!r} for chute {chute.chute_id}; "
                f"minimum supported version is {MIN_SECURE_SOURCE_RUNTIME_VERSION}. "
                "Legacy miner-mounted source delivery has been removed; rebuild the chute image."
            ),
        )


def _launch_demand_input_document(
    chute: Chute,
    *,
    hotkey: str | None,
    job_id: str | None,
    launch_owner_id: str,
    runtime_server_id: str | None,
) -> dict:
    return {
        "schema": "chutes.launch-demand-external-input.v1",
        "hotkey": hotkey,
        "job_id": job_id,
        "launch_owner_id": launch_owner_id,
        "runtime_server_id": runtime_server_id,
        "chute": {
            "chute_id": chute.chute_id,
            "user_id": chute.user_id,
            "name": chute.name,
            "version": chute.version,
            "revision": chute.revision,
            "image_id": chute.image_id,
            "image_compute_type": getattr(chute.image, "compute_type", None),
            "chutes_version": chute.chutes_version,
            "node_selector": chute.node_selector,
            "public": bool(chute.public),
            "tee": bool(chute.tee),
            "disabled": bool(chute.disabled),
        },
    }


async def _collect_launch_demand_external_work(
    db: AsyncSession,
    chute: Chute,
    *,
    hotkey: str | None,
    job_id: str | None,
    runtime_server_id: str | None,
    is_private: bool,
) -> dict:
    scale_value = None
    inventory_history = None
    bounty_exists = None
    if job_id is None:
        assert_gpu_external_work_allowed(db, "launch demand scale telemetry lookup")
        scale_value = _normalized_external_scalar(
            await settings.redis_client.get(f"scale:{chute.chute_id}")
        )
        if is_private:
            if not chute.tee:
                assert_gpu_external_work_allowed(
                    db, "launch demand inventory telemetry lookup"
                )
                inventory_raw = await settings.redis_client.get(f"uqhist:{hotkey}")
                inventory_history = json.loads(inventory_raw) if inventory_raw else None
            assert_gpu_external_work_allowed(db, "launch demand bounty lookup")
            bounty_exists = await check_bounty_exists(chute.chute_id)

    registry_repository = None
    registry_manifest_digest = None
    if runtime_server_id is not None:
        from api.cpu_scheduler import _container_intent

        assert_gpu_external_work_allowed(db, "launch registry descriptor resolution")
        registry_intent = await _container_intent(chute)
        if registry_intent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Validator could not resolve the launch image descriptor.",
            )
        registry_repository, registry_manifest_digest = registry_intent
    return {
        "scale_value": scale_value,
        "inventory_history": inventory_history,
        "bounty_exists": bounty_exists,
        "registry_repository": registry_repository,
        "registry_manifest_digest": registry_manifest_digest,
    }


async def _lock_default_volume_before_gpu_workload(
    db: AsyncSession,
    *,
    launch_owner_id: str,
    chute_id: str,
    job_id: str | None,
):
    # User/binding/volume custody must precede the global GPU workload lock.
    # Holding the user row serializes all ChuteFS paths for this owner, so the
    # later forced job/chute refetch cannot invert against session rotation.
    _, default_volume, _ = await ensure_default_volume_binding(
        db,
        launch_owner_id,
        chute_id,
    )
    from api.gpu_scheduler import acquire_gpu_workload_lock

    await acquire_gpu_workload_lock(db, chute_id, job_id)
    return default_volume


def _canonical_miner_launch_request_id(value: str | None) -> str:
    if not isinstance(value, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Attested GPU miner launches require miner_launch_request_id.",
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="miner_launch_request_id must be a canonical UUID.",
        ) from exc
    if str(parsed) != value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="miner_launch_request_id must be a canonical lowercase UUID.",
        )
    return value


def _miner_launch_replay_conflict(detail: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Durable miner launch replay rejected: {detail}",
    )


def _miner_launch_jwt_policy(chute: Chute, job: Job | None) -> dict:
    disk_gb = None
    if job is not None:
        if not isinstance(job.job_args, dict) or "_disk_gb" not in job.job_args:
            _miner_launch_replay_conflict("job disk policy is unavailable")
        disk_gb = job.job_args["_disk_gb"]
    return {
        "egress": chute.allow_external_egress,
        "lock_modules": (
            True
            if chute.standard_template
            else (chute.lock_modules if chute.lock_modules is not None else False)
        ),
        "disk_gb": disk_gb,
        "launch_config_base_url": (
            settings.launch_config_base_url or f"https://api.{settings.base_domain}"
        ).rstrip("/"),
    }


def _miner_launch_demand_posture(
    chute: Chute,
    *,
    chutes_owner_id: str | None,
) -> dict:
    legacy_private_billing = has_legacy_private_billing(chute)
    platform_owned = chute.user_id == chutes_owner_id
    return {
        "public": bool(chute.public),
        "legacy_private_billing": legacy_private_billing,
        "platform_owned": platform_owned,
        "private_launch": bool(
            not chute.public and not legacy_private_billing and not platform_owned
        ),
    }


def _miner_launch_secret_sha256(label: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        _miner_launch_replay_conflict(f"launch config {label} secret is unavailable")
    return hashlib.sha256(
        b"chutes.miner-launch-config-request.v1\x00"
        + label.encode("ascii")
        + b"\x00"
        + value.encode("utf-8")
    ).hexdigest()


def _miner_launch_request_document(
    *,
    request_id: str,
    config: LaunchConfig,
    miner,
    chute: Chute,
    job: Job | None,
    server: Server,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
    binding: DefaultChuteFSVolumeBinding,
    volume: StorageVolume,
    policy: dict,
    demand_posture: dict,
) -> dict:
    """Canonical authority accepted for one miner launch response.

    All mutable values which can change a fresh launch JWT or transfer custody are
    represented here.  Replay recomputes this document from locked current rows;
    the stored digest is not trusted as a substitute for those checks.
    """

    return {
        "schema": "chutes.miner-launch-config-request",
        "version": 1,
        "miner_launch_request_id": request_id,
        "miner": {
            "hotkey": config.miner_hotkey,
            "uid": config.miner_uid,
            "coldkey": config.miner_coldkey,
            "current_uid": miner.node_id,
            "current_coldkey": miner.coldkey,
        },
        "chute": {
            "chute_id": chute.chute_id,
            "user_id": chute.user_id,
            "version": chute.version,
            "revision": chute.revision,
            "image_id": chute.image_id,
            "image_compute_type": getattr(chute.image, "compute_type", None),
            "chutes_version": chute.chutes_version,
            "node_selector": chute.node_selector,
            "tee": bool(chute.tee),
            "disabled": bool(chute.disabled),
        },
        "job": (
            {
                "job_id": job.job_id,
                "user_id": job.user_id,
                "chute_id": job.chute_id,
                "version": job.version,
                "chutes_version": job.chutes_version,
                "status": job.status,
                "node_selector": job.node_selector,
                "finished": job.finished_at is not None,
                "miner_terminated": bool(job.miner_terminated),
                "gpu_management_mode": job.gpu_management_mode,
                "gpu_launch_reservation_id": job.gpu_launch_reservation_id,
            }
            if job is not None
            else None
        ),
        "server": {
            "server_id": server.server_id,
            "miner_hotkey": server.miner_hotkey,
            "compute_type": server.compute_type,
            "tee_type": server.tee_type,
            "gpu_launch_reservation_id": server.gpu_launch_reservation_id,
            "gpu_allocation_group_id": server.gpu_allocation_group_id,
            "gpu_allocation_group_generation": (server.gpu_allocation_group_generation),
            "gpu_management_mode": server.gpu_management_mode,
            "gpu_process_incarnation": server.gpu_process_incarnation,
            "gpu_topology_fingerprint": server.gpu_topology_fingerprint,
            "attested_cert_pubkey_hash": server.attested_cert_pubkey_hash,
        },
        "reservation": {
            "reservation_id": reservation.reservation_id,
            "claims_sha256": reservation.claims_sha256,
            "owner_hotkey": reservation.owner_hotkey,
            "workload_owner": reservation.workload_owner,
            "host_id": reservation.host_id,
            "host_key_generation": reservation.host_key_generation,
            "host_boot_generation": reservation.host_boot_generation,
            "allocation_group_id": reservation.allocation_group_id,
            "allocation_group_generation": (reservation.allocation_group_generation),
            "reservation_generation": reservation.reservation_generation,
            "management_mode": reservation.management_mode,
            "server_id": reservation.server_id,
            "process_incarnation": reservation.process_incarnation,
            "topology_fingerprint": reservation.topology_fingerprint,
            "state": reservation.state,
        },
        "group": {
            "allocation_group_id": group.allocation_group_id,
            "host_id": group.host_id,
            "host_key_generation": group.host_key_generation,
            "host_boot_generation": group.host_boot_generation,
            "generation": group.generation,
            "topology_fingerprint": group.topology_fingerprint,
            "state": group.state,
            "management_mode": group.management_mode,
            "reservation_owner": group.reservation_owner,
            "reservation_id": group.reservation_id,
            "reservation_generation": group.reservation_generation,
            "process_incarnation": group.process_incarnation,
        },
        "storage": {
            "user_id": binding.user_id,
            "chute_id": binding.chute_id,
            "binding_id": binding.binding_id,
            "volume_id": volume.volume_id,
            "lifecycle_state": binding.lifecycle_state,
            "volume_deleted": bool(volume.deleted),
        },
        "registry": {
            "active": bool(config.registry_scope_active),
            "repository": config.container_repository,
            "manifest_digest": config.container_manifest_digest,
        },
        "launch": {
            "config_id": config.config_id,
            "user_id": config.user_id,
            "compute_type": config.compute_type,
            "job_id": config.job_id,
            "server_id": config.server_id,
            "gpu_management_mode": config.gpu_management_mode,
            "gpu_launch_reservation_id": config.gpu_launch_reservation_id,
            "default_volume_id": config.default_volume_id,
            "storage_session_exchange_allowed": bool(
                config.storage_session_exchange_allowed
            ),
            "env_type": config.env_type,
            "env_key_sha256": _miner_launch_secret_sha256("env-key", config.env_key),
            "runtime_nonce_sha256": _miner_launch_secret_sha256(
                "runtime-nonce", config.nonce
            ),
        },
        "jwt_policy": policy,
        "demand_posture": demand_posture,
    }


async def _lock_current_miner_launch_custody(
    db: AsyncSession,
    *,
    server: Server,
    hotkey: str,
) -> tuple[GpuLaunchReservation, GpuAllocationGroup]:
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(
                GpuLaunchReservation.reservation_id == server.gpu_launch_reservation_id
            )
            .with_for_update(of=GpuLaunchReservation)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(
                GpuAllocationGroup.allocation_group_id == server.gpu_allocation_group_id
            )
            .with_for_update(of=GpuAllocationGroup)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    active_operation = (
        (
            await db.execute(
                select(GpuLifecycleOperation)
                .where(
                    GpuLifecycleOperation.allocation_group_id
                    == group.allocation_group_id,
                    GpuLifecycleOperation.allocation_group_generation
                    == group.generation,
                    GpuLifecycleOperation.phase.not_in(
                        ("finalized", "quarantined")
                    ),
                )
                .with_for_update(of=GpuLifecycleOperation)
            )
        )
        .unique()
        .scalar_one_or_none()
        if group is not None
        else None
    )
    runtime_expiry = server.gpu_runtime_session_expires_at
    if runtime_expiry is not None and runtime_expiry.tzinfo is None:
        runtime_expiry = runtime_expiry.replace(tzinfo=timezone.utc)
    if (
        reservation is None
        or group is None
        or server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or server.gpu_management_mode != "miner"
        or server.gpu_retired_at is not None
        or server.miner_hotkey != hotkey
        or not server.gpu_runtime_session_attestation_id
        or runtime_expiry is None
        or runtime_expiry <= datetime.now(timezone.utc)
        or reservation.state != "running"
        or reservation.teardown_requested_at is not None
        or reservation.teardown_command_id is not None
        or active_operation is not None
        or reservation.management_mode != "miner"
        or reservation.owner_hotkey != hotkey
        or reservation.workload_owner != hotkey
        or reservation.server_id != server.server_id
        or reservation.allocation_group_id != server.gpu_allocation_group_id
        or reservation.allocation_group_generation
        != server.gpu_allocation_group_generation
        or reservation.process_incarnation != server.gpu_process_incarnation
        or reservation.topology_fingerprint != server.gpu_topology_fingerprint
        or group.state != "running"
        or group.management_mode != "miner"
        or group.reservation_owner != hotkey
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.generation != reservation.allocation_group_generation
        or group.host_id != reservation.host_id
        or group.host_key_generation != reservation.host_key_generation
        or group.host_boot_generation != reservation.host_boot_generation
        or group.process_incarnation != reservation.process_incarnation
        or group.topology_fingerprint != reservation.topology_fingerprint
    ):
        _miner_launch_replay_conflict(
            "GPU server, reservation, or allocation-group custody is no longer current"
        )
    return reservation, group


async def _preflight_current_miner_launch_custody(
    db: AsyncSession,
    *,
    server_id: str,
    hotkey: str,
) -> None:
    """Reject already-fenced custody before demand or registry external work."""

    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == server_id)
            .options(lazyload("*"))
            .with_for_update(of=Server)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if server is None:
        _miner_launch_replay_conflict("GPU server custody is no longer current")
    await _lock_current_miner_launch_custody(
        db,
        server=server,
        hotkey=hotkey,
    )
    await db.commit()


async def _existing_miner_launch_identity(
    db: AsyncSession,
    *,
    hotkey: str,
    request_id: str,
):
    return (
        await db.execute(
            select(
                LaunchConfig.config_id,
                LaunchConfig.user_id,
                LaunchConfig.chute_id,
                LaunchConfig.job_id,
                LaunchConfig.server_id,
            ).where(
                LaunchConfig.miner_hotkey == hotkey,
                LaunchConfig.miner_launch_request_id == request_id,
            )
        )
    ).one_or_none()


async def _lock_existing_miner_launch_storage(
    db: AsyncSession,
    *,
    user_id: str,
    chute_id: str,
    hotkey: str,
    request_id: str,
) -> tuple[LaunchConfig, DefaultChuteFSVolumeBinding, StorageVolume]:
    user = (
        await db.execute(
            select(User)
            .where(User.user_id == user_id)
            .options(lazyload("*"))
            .with_for_update(of=User)
        )
    ).scalar_one_or_none()
    if user is None:
        _miner_launch_replay_conflict("launch owner no longer exists")
    await acquire_gpu_lifecycle_lock(db)
    config = (
        (
            await db.execute(
                select(LaunchConfig)
                .where(
                    LaunchConfig.miner_hotkey == hotkey,
                    LaunchConfig.miner_launch_request_id == request_id,
                )
                .options(lazyload("*"))
                .with_for_update(of=LaunchConfig)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if config is None or config.user_id != user_id or config.chute_id != chute_id:
        _miner_launch_replay_conflict(
            "the persisted request changed before its configuration lock"
        )
    binding = (
        await db.execute(
            select(DefaultChuteFSVolumeBinding)
            .where(
                DefaultChuteFSVolumeBinding.user_id == user_id,
                DefaultChuteFSVolumeBinding.chute_id == chute_id,
                DefaultChuteFSVolumeBinding.lifecycle_state == "active",
            )
            .with_for_update(of=DefaultChuteFSVolumeBinding)
        )
    ).scalar_one_or_none()
    volume = (
        (
            await db.execute(
                select(StorageVolume)
                .where(StorageVolume.volume_id == binding.volume_id)
                .with_for_update(of=StorageVolume)
            )
        ).scalar_one_or_none()
        if binding is not None
        else None
    )
    key = (
        await db.get(StorageVolumeKey, binding.volume_id, with_for_update=True)
        if binding is not None and volume is not None
        else None
    )
    if (
        binding is None
        or volume is None
        or key is None
        or volume.user_id != user_id
        or volume.deleted
    ):
        _miner_launch_replay_conflict(
            "the exact active ChuteFS binding or volume is unavailable"
        )
    return config, binding, volume


async def _lock_new_miner_launch_storage_before_gpu_workload(
    db: AsyncSession,
    *,
    launch_owner_id: str,
    chute_id: str,
    job_id: str | None,
    hotkey: str,
    request_id: str,
) -> tuple[StorageVolume, LaunchConfig | None]:
    # ChuteFS rotation uses User -> LaunchConfig -> Binding -> Volume.  Preserve
    # that order even when another request publishes this UUID while external
    # launch resolution is in flight.
    user = (
        await db.execute(
            select(User)
            .where(User.user_id == launch_owner_id)
            .options(lazyload("*"))
            .with_for_update(of=User)
        )
    ).scalar_one_or_none()
    if user is None:
        _miner_launch_replay_conflict("launch owner no longer exists")
    await acquire_gpu_lifecycle_lock(db)
    existing = (
        (
            await db.execute(
                select(LaunchConfig)
                .where(
                    LaunchConfig.miner_hotkey == hotkey,
                    LaunchConfig.miner_launch_request_id == request_id,
                )
                .options(lazyload("*"))
                .with_for_update(of=LaunchConfig)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    _, default_volume, _ = await ensure_default_volume_binding(
        db,
        launch_owner_id,
        chute_id,
    )
    from api.gpu_scheduler import acquire_gpu_workload_lock

    await acquire_gpu_workload_lock(db, chute_id, job_id)
    return default_volume, existing


async def _locked_binding_for_new_launch(
    db: AsyncSession,
    *,
    user_id: str,
    chute_id: str,
    volume_id: str,
) -> DefaultChuteFSVolumeBinding:
    binding = (
        await db.execute(
            select(DefaultChuteFSVolumeBinding)
            .where(
                DefaultChuteFSVolumeBinding.user_id == user_id,
                DefaultChuteFSVolumeBinding.chute_id == chute_id,
                DefaultChuteFSVolumeBinding.volume_id == volume_id,
                DefaultChuteFSVolumeBinding.lifecycle_state == "active",
            )
            .with_for_update(of=DefaultChuteFSVolumeBinding)
        )
    ).scalar_one_or_none()
    if binding is None:
        _miner_launch_replay_conflict(
            "the locked default ChuteFS binding changed before launch creation"
        )
    return binding


async def _render_replayed_miner_launch_response(
    db: AsyncSession,
    *,
    config: LaunchConfig,
    policy: dict,
) -> dict:
    repository = config.container_repository
    manifest_digest = config.container_manifest_digest
    await db.commit()
    if config.nonce is not None:
        assert_gpu_external_work_allowed(
            db, "replayed launch runtime-integrity nonce publish"
        )
        await settings.redis_client.set(
            f"rint_nonce:{config.config_id}", config.nonce, ex=7200
        )
    result = {
        "token": create_launch_jwt_v2(
            config,
            egress=policy["egress"],
            lock_modules=policy["lock_modules"],
            disk_gb=policy["disk_gb"],
        ),
        "config_id": config.config_id,
        "registry": {
            "repository": repository,
            "manifest_digest": manifest_digest,
        },
    }
    return result


async def _validate_locked_miner_launch_replay(
    db: AsyncSession,
    *,
    miner,
    hotkey: str,
    request_id: str,
    requested_chute_id: str,
    requested_job_id: str | None,
    requested_server_id: str,
    binding: DefaultChuteFSVolumeBinding,
    volume: StorageVolume,
    chutes_owner_id: str | None,
) -> dict:
    config = (
        (
            await db.execute(
                select(LaunchConfig)
                .where(
                    LaunchConfig.miner_hotkey == hotkey,
                    LaunchConfig.miner_launch_request_id == request_id,
                )
                .options(lazyload("*"))
                .with_for_update(of=LaunchConfig)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if config is None:
        _miner_launch_replay_conflict("the persisted request disappeared")
    chute = (
        (
            await db.execute(
                select(Chute)
                .where(Chute.chute_id == config.chute_id)
                .options(lazyload("*"), joinedload(Chute.image))
                .with_for_update(of=Chute)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    job = (
        (
            await db.execute(
                select(Job)
                .where(Job.job_id == config.job_id)
                .options(lazyload("*"))
                .with_for_update(of=Job)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if config.job_id is not None
        else None
    )
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == config.server_id)
            .options(lazyload("*"))
            .with_for_update(of=Server)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if chute is None or server is None:
        _miner_launch_replay_conflict("chute or server no longer exists")
    _require_secure_source_delivery(chute)
    if (
        config.chute_id != requested_chute_id
        or config.job_id != requested_job_id
        or config.server_id != requested_server_id
        or config.user_id != binding.user_id
        or config.default_volume_id != binding.volume_id
        or config.default_volume_id != volume.volume_id
        or config.compute_type != "gpu"
        or config.gpu_management_mode != "miner"
        or not config.storage_session_exchange_allowed
        or config.miner_uid != miner.node_id
        or config.miner_coldkey != miner.coldkey
        or chute.chute_id != config.chute_id
        or chute.user_id != config.user_id
        or chute.image is None
        or chute.image.compute_type != "gpu"
        or chute.disabled
        or config.retrieved_at is not None
        or config.verified_at is not None
        or config.failed_at is not None
        or config.completed_at is not None
        or config.verification_error is not None
        or config.registry_scope_active is not True
        or config.registry_scope_revoked_at is not None
        or not isinstance(config.container_repository, str)
        or not config.container_repository
        or not isinstance(config.container_manifest_digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", config.container_manifest_digest)
    ):
        _miner_launch_replay_conflict(
            "request, workload, storage, or registry authority changed"
        )
    if (
        await db.execute(
            select(Instance.instance_id)
            .where(Instance.config_id == config.config_id)
            .limit(1)
        )
    ).scalar_one_or_none() is not None:
        _miner_launch_replay_conflict("launch config has already been consumed")
    if config.job_id is not None and (
        job is None
        or job.user_id != config.user_id
        or job.chute_id != config.chute_id
        or job.finished_at is not None
        or bool(job.miner_terminated)
        or job.gpu_management_mode != "miner"
        or job.gpu_launch_reservation_id != config.gpu_launch_reservation_id
        or hotkey not in (job.miner_history or [])
    ):
        _miner_launch_replay_conflict("job authority is no longer current")
    reservation, group = await _lock_current_miner_launch_custody(
        db,
        server=server,
        hotkey=hotkey,
    )
    if config.gpu_launch_reservation_id != reservation.reservation_id:
        _miner_launch_replay_conflict("launch config reservation is no longer current")
    policy = _miner_launch_jwt_policy(chute, job)
    demand_posture = _miner_launch_demand_posture(
        chute,
        chutes_owner_id=chutes_owner_id,
    )
    expected_sha256 = canonical_sha256(
        _miner_launch_request_document(
            request_id=request_id,
            config=config,
            miner=miner,
            chute=chute,
            job=job,
            server=server,
            reservation=reservation,
            group=group,
            binding=binding,
            volume=volume,
            policy=policy,
            demand_posture=demand_posture,
        )
    )
    if not isinstance(
        config.miner_launch_request_sha256, str
    ) or not secrets.compare_digest(
        config.miner_launch_request_sha256,
        expected_sha256,
    ):
        _miner_launch_replay_conflict(
            "canonical request or response-shaping JWT policy changed"
        )
    return await _render_replayed_miner_launch_response(
        db,
        config=config,
        policy=policy,
    )


async def _try_replay_miner_launch_config(
    db: AsyncSession,
    *,
    miner,
    hotkey: str,
    request_id: str,
    chute_id: str,
    job_id: str | None,
    server_id: str,
    chutes_owner_id: str | None,
) -> dict | None:
    identity = await _existing_miner_launch_identity(
        db,
        hotkey=hotkey,
        request_id=request_id,
    )
    if identity is None:
        return None
    if (
        identity.chute_id != chute_id
        or identity.job_id != job_id
        or identity.server_id != server_id
    ):
        _miner_launch_replay_conflict(
            "request UUID is already bound to different launch parameters"
        )
    _config, binding, volume = await _lock_existing_miner_launch_storage(
        db,
        user_id=identity.user_id,
        chute_id=identity.chute_id,
        hotkey=hotkey,
        request_id=request_id,
    )
    from api.gpu_scheduler import acquire_gpu_workload_lock

    await acquire_gpu_workload_lock(db, identity.chute_id, identity.job_id)
    return await _validate_locked_miner_launch_replay(
        db,
        miner=miner,
        hotkey=hotkey,
        request_id=request_id,
        requested_chute_id=chute_id,
        requested_job_id=job_id,
        requested_server_id=server_id,
        binding=binding,
        volume=volume,
        chutes_owner_id=chutes_owner_id,
    )


@router.get(
    "/launch_config",
    response_model=LaunchConfigResponse,
    response_model_exclude_none=True,
)
async def get_launch_config(
    chute_id: str,
    request: Request,
    server_id: Optional[str] = None,
    job_id: Optional[str] = None,
    miner_launch_request_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(
            raise_not_found=False, registered_to=settings.netuid, purpose="launch"
        )
    ),
):
    miner = await _check_blacklisted(db, hotkey)
    chutes_owner_id = await db.scalar(
        select(User.user_id).where(User.username == "chutes")
    )
    runtime_server_id = getattr(request.state, "gpu_runtime_server_id", None)
    durable_request_id = None
    if runtime_server_id is not None:
        if server_id != runtime_server_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Launch config server differs from the attested GPU session.",
            )
        durable_request_id = _canonical_miner_launch_request_id(miner_launch_request_id)
        replay = await _try_replay_miner_launch_config(
            db,
            miner=miner,
            hotkey=hotkey,
            request_id=durable_request_id,
            chute_id=chute_id,
            job_id=job_id,
            server_id=runtime_server_id,
            chutes_owner_id=chutes_owner_id,
        )
        if replay is not None:
            return replay
        await _preflight_current_miner_launch_custody(
            db,
            server_id=runtime_server_id,
            hotkey=hotkey,
        )

    # Resolve external demand telemetry and registry intent before acquiring the
    # global/workload lifecycle locks, then bind the results to an exact chute snapshot.
    chute = await _load_chute(db, chute_id)
    _require_secure_source_delivery(chute)
    gpu_selector = (
        str((chute.node_selector or {}).get("compute_type", "gpu")).lower() == "gpu"
    )
    if not gpu_selector:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CPU chutes are scheduled by the validator; miners cannot request launch configs for them.",
        )
    if job_id is None:
        launch_owner_id = chute.user_id
    else:
        launch_owner_id = (
            await db.execute(
                select(Job.user_id).where(
                    Job.job_id == job_id,
                    Job.chute_id == chute_id,
                )
            )
        ).scalar_one_or_none()
        if launch_owner_id is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} for chute {chute_id} not found",
            )
    is_private = bool(
        not chute.public
        and not has_legacy_private_billing(chute)
        and chute.user_id != chutes_owner_id
    )
    demand_input = _launch_demand_input_document(
        chute,
        hotkey=hotkey,
        job_id=job_id,
        launch_owner_id=launch_owner_id,
        runtime_server_id=runtime_server_id,
    )
    demand_input_sha256 = canonical_sha256(demand_input)
    await db.commit()
    demand_external = await _collect_launch_demand_external_work(
        db,
        chute,
        hotkey=hotkey,
        job_id=job_id,
        runtime_server_id=runtime_server_id,
        is_private=is_private,
    )
    demand_result_sha256 = canonical_sha256(demand_external)

    concurrent = None
    if durable_request_id is not None:
        (
            default_volume,
            concurrent,
        ) = await _lock_new_miner_launch_storage_before_gpu_workload(
            db,
            launch_owner_id=launch_owner_id,
            chute_id=chute_id,
            job_id=job_id,
            hotkey=hotkey,
            request_id=durable_request_id,
        )
    else:
        default_volume = await _lock_default_volume_before_gpu_workload(
            db,
            launch_owner_id=launch_owner_id,
            chute_id=chute_id,
            job_id=job_id,
        )
    default_binding = await _locked_binding_for_new_launch(
        db,
        user_id=launch_owner_id,
        chute_id=chute_id,
        volume_id=default_volume.volume_id,
    )
    if durable_request_id is not None and concurrent is not None:
        if (
            concurrent.user_id != launch_owner_id
            or concurrent.chute_id != chute_id
            or concurrent.job_id != job_id
            or concurrent.server_id != runtime_server_id
        ):
            _miner_launch_replay_conflict(
                "request UUID was concurrently bound to different launch parameters"
            )
        return await _validate_locked_miner_launch_replay(
            db,
            miner=miner,
            hotkey=hotkey,
            request_id=durable_request_id,
            requested_chute_id=chute_id,
            requested_job_id=job_id,
            requested_server_id=runtime_server_id,
            binding=default_binding,
            volume=default_volume,
            chutes_owner_id=chutes_owner_id,
        )
    chute = (
        (
            await db.execute(
                select(Chute)
                .where(Chute.chute_id == chute_id)
                .options(lazyload("*"), joinedload(Chute.image))
                .with_for_update(of=Chute)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if (
        chute is None
        or canonical_sha256(
            _launch_demand_input_document(
                chute,
                hotkey=hotkey,
                job_id=job_id,
                launch_owner_id=launch_owner_id,
                runtime_server_id=runtime_server_id,
            )
        )
        != demand_input_sha256
        or canonical_sha256(demand_external) != demand_result_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch demand authority changed during external resolution.",
        )
    if not job_id:
        platform_active = (
            await db.execute(
                select(GpuLaunchReservation.reservation_id)
                .where(
                    GpuLaunchReservation.management_mode == "platform",
                    GpuLaunchReservation.chute_id == chute_id,
                    GpuLaunchReservation.job_id.is_(None),
                    GpuLaunchReservation.state.in_(
                        {
                            "reserved",
                            "claimed",
                            "launching",
                            "running",
                            "resetting",
                            "quarantined",
                        }
                    ),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if platform_active is not None:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="TEE GPU chute demand is already platform-managed.",
            )
    registry_repository = demand_external["registry_repository"]
    registry_manifest_digest = demand_external["registry_manifest_digest"]
    runtime_reservation = None
    runtime_group = None
    if runtime_server_id is not None:
        runtime_server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == runtime_server_id)
                .with_for_update(of=Server)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if (
            runtime_server is None
            or runtime_server.compute_type != "gpu"
            or runtime_server.gpu_management_mode != "miner"
            or runtime_server.gpu_retired_at is not None
            or runtime_server.miner_hotkey != hotkey
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Launch config requires the current attested miner GPU server.",
            )
        runtime_reservation, runtime_group = await _lock_current_miner_launch_custody(
            db,
            server=runtime_server,
            hotkey=hotkey,
        )
    elif server_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Server-bound launch configs require an attested GPU session.",
        )

    # Check if chute is disabled
    if chute.disabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Chute {chute_id} is currently disabled",
        )
    if not job_id:
        if is_private:
            await _check_scalable_private(
                db,
                chute,
                miner,
                inventory_history=demand_external["inventory_history"],
                scale_value=demand_external["scale_value"],
                bounty_exists=demand_external["bounty_exists"],
            )
        else:
            await _check_scalable(
                db,
                chute,
                hotkey,
                scale_value=demand_external["scale_value"],
            )

    await _verify_tee_version_support(db, chute, hotkey)

    # Associated with a job?
    job = None
    if job_id:
        job = (
            (
                await db.execute(
                    select(Job)
                    .where(Job.chute_id == chute_id, Job.job_id == job_id)
                    .with_for_update(of=Job)
                    .execution_options(populate_existing=True)
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if not job or job.user_id != launch_owner_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} for chute {chute_id} not found",
            )
        if job.gpu_management_mode == "platform":
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Job {job_id} is already platform-managed.",
            )

        # Don't allow too many miners to try to claim the job...
        if len(job.miner_history) >= 15:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Job {job_id} for chute {chute_id} is already in a race between {len(job.miner_history)} miners",
            )

        # Don't allow miners to try claiming a job more than once.
        if hotkey in job.miner_history:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Your hotkey has already attempted to claim {job_id=}",
            )

        # Track this miner in the job history.
        await db.execute(
            text(
                "UPDATE jobs SET miner_history = miner_history || jsonb_build_array(CAST(:hotkey AS TEXT))"
                "WHERE job_id = :job_id"
            ),
            {"job_id": job_id, "hotkey": hotkey},
        )
        if runtime_server_id is not None:
            job.gpu_management_mode = "miner"
            job.gpu_launch_reservation_id = runtime_server.gpu_launch_reservation_id
    jwt_policy = _miner_launch_jwt_policy(chute, job)

    # Create the launch config and JWT.
    config_id = str(uuid.uuid4())

    # Generate runtime integrity nonce.
    rint_nonce = None
    if semcomp(chute.chutes_version or "0.0.0", "0.4.9") >= 0:
        rint_nonce = secrets.token_hex(16)
        # Redis is transport only; publish after the authoritative config commits.

    try:
        launch_config = LaunchConfig(
            config_id=config_id,
            env_key=secrets.token_bytes(16).hex(),
            chute_id=chute_id,
            user_id=launch_owner_id,
            compute_type=chute.image.compute_type,
            default_volume_id=default_volume.volume_id,
            storage_session_exchange_allowed=runtime_server_id is not None,
            job_id=job_id,
            miner_hotkey=hotkey,
            miner_uid=miner.node_id,
            miner_coldkey=miner.coldkey,
            miner_launch_request_id=durable_request_id,
            env_type="tee" if chute.tee else "graval",
            seed=0,
            nonce=rint_nonce,
            server_id=runtime_server_id,
            container_repository=registry_repository,
            container_manifest_digest=registry_manifest_digest,
            registry_scope_active=runtime_server_id is not None,
            gpu_management_mode=("miner" if runtime_server_id is not None else None),
            gpu_launch_reservation_id=(
                runtime_server.gpu_launch_reservation_id
                if runtime_server_id is not None
                else None
            ),
        )
        if durable_request_id is not None:
            if runtime_reservation is None or runtime_group is None:
                _miner_launch_replay_conflict(
                    "attested GPU launch custody was not locked"
                )
            launch_config.miner_launch_request_sha256 = canonical_sha256(
                _miner_launch_request_document(
                    request_id=durable_request_id,
                    config=launch_config,
                    miner=miner,
                    chute=chute,
                    job=job,
                    server=runtime_server,
                    reservation=runtime_reservation,
                    group=runtime_group,
                    binding=default_binding,
                    volume=default_volume,
                    policy=jwt_policy,
                    demand_posture=_miner_launch_demand_posture(
                        chute,
                        chutes_owner_id=chutes_owner_id,
                    ),
                )
            )
        db.add(launch_config)
        await db.commit()
        await db.refresh(launch_config)
        if rint_nonce is not None:
            assert_gpu_external_work_allowed(
                db, "launch runtime-integrity nonce publish"
            )
            await settings.redis_client.set(
                f"rint_nonce:{config_id}", rint_nonce, ex=7200
            )
    except IntegrityError as exc:
        await db.rollback()
        if durable_request_id is not None:
            # The failed flush expires ORM state in this session.  Refetch the
            # miner after rollback so replay validates current metagraph
            # identity instead of dereferencing the expired pre-race object.
            replay_miner = await _check_blacklisted(db, hotkey)
            replay = await _try_replay_miner_launch_config(
                db,
                miner=replay_miner,
                hotkey=hotkey,
                request_id=durable_request_id,
                chute_id=chute_id,
                job_id=job_id,
                server_id=runtime_server_id,
                chutes_owner_id=chutes_owner_id,
            )
            if replay is not None:
                return replay
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Launch config conflict/unique constraint error: {exc}",
        )

    # Broadcast launch token created event after lifecycle commit.
    try:
        ns = chute.node_selector or {}
        assert_gpu_external_work_allowed(db, "launch event publish")
        await settings.redis_client.publish(
            "events",
            json.dumps(
                {
                    "reason": "launch_token_created",
                    "message": f"Launch token created for chute {chute_id} by miner {hotkey}",
                    "data": {
                        "chute_id": chute_id,
                        "miner_hotkey": hotkey,
                        "gpu_count": ns.get("gpu_count", 1),
                        "include_gpus": ns.get("include"),
                        "min_vram_gb": ns.get("min_vram_gb_per_gpu"),
                    },
                }
            ).decode(),
        )
    except Exception:
        ...

    # Generate the JWT.
    token = create_launch_jwt_v2(
        launch_config,
        egress=jwt_policy["egress"],
        lock_modules=jwt_policy["lock_modules"],
        disk_gb=jwt_policy["disk_gb"],
    )

    result = {
        "token": token,
        "config_id": launch_config.config_id,
    }
    if registry_repository is not None:
        result["registry"] = {
            "repository": registry_repository,
            "manifest_digest": registry_manifest_digest,
        }
    return result


@router.get("/launch_config/{config_id}/nonce")
async def get_rint_nonce(
    config_id: str,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    """
    Get runtime integrity nonce for a launch config.

    This endpoint consumes the nonce from Redis (one-time use).
    Only available for chutes_version >= 0.4.9.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )

    token = authorization.strip().split(" ")[-1]

    # Decode and verify the JWT signature
    try:
        payload = _decode_chutes_jwt(token, require_exp=True)
        req_config_id = payload.get("sub")
        if not req_config_id or req_config_id != config_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or missing token, expected launch JWT",
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid token: {exc}",
        )

    # Load the launch config
    launch_config = (
        (
            await db.execute(
                select(LaunchConfig).where(LaunchConfig.config_id == config_id)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if not launch_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Launch config {config_id} not found",
        )

    redis_key = f"rint_nonce:{config_id}"
    nonce = await settings.redis_client.getdel(redis_key)
    if not nonce:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nonce for config {config_id} not found or already consumed",
        )

    return PlainTextResponse(nonce.decode() if isinstance(nonce, bytes) else nonce)


def _claim_node_document(node: Node) -> dict:
    return {
        "uuid": node.uuid,
        "graval": node.graval_dict(),
        "gpu_identifier": node.gpu_identifier,
        "seed": str(node.seed),
        "miner_hotkey": node.miner_hotkey,
        "server_id": node.server_id,
        "verification_host": node.verification_host,
        "verification_port": node.verification_port,
        "verified": node.verified_at is not None,
        "allocation_group_id": node.gpu_allocation_group_id,
        "allocation_group_generation": node.gpu_allocation_group_generation,
        "reservation_id": node.gpu_launch_reservation_id,
        "process_incarnation": node.gpu_process_incarnation,
        "inventory_report_id": node.gpu_inventory_report_id,
        "retired": node.gpu_retired_at is not None,
    }


def _claim_lineage_snapshot(
    launch_config: LaunchConfig,
    instance: Instance,
    nodes: list[Node],
) -> dict:
    return {
        "config_id": launch_config.config_id,
        "seed": str(launch_config.seed),
        "instance_id": instance.instance_id,
        "chute_id": launch_config.chute_id,
        "job_id": launch_config.job_id,
        "user_id": launch_config.user_id,
        "server_id": launch_config.server_id,
        "compute_type": launch_config.compute_type,
        "management_mode": launch_config.gpu_management_mode,
        "reservation_id": launch_config.gpu_launch_reservation_id,
        "allocation_group_id": instance.gpu_allocation_group_id,
        "allocation_group_generation": instance.gpu_allocation_group_generation,
        "process_incarnation": instance.gpu_process_incarnation,
        "miner_hotkey": launch_config.miner_hotkey,
        "host": instance.host,
        "port": instance.port,
        "deployment_id": instance.deployment_id,
        "symmetric_key_sha256": canonical_sha256(
            {"symmetric_key": instance.symmetric_key}
        ),
        "nodes": sorted(
            (_claim_node_document(node) for node in nodes),
            key=lambda item: item["uuid"],
        ),
    }


async def _locked_current_claim_lineage(
    db: AsyncSession,
    snapshot: dict,
) -> tuple[LaunchConfig, Instance, list[Node]]:
    """Refetch exact launch, nodes, and GPU custody after bounded external work."""

    await acquire_gpu_lifecycle_lock(db)
    launch_config = (
        await db.execute(
            select(LaunchConfig)
            .where(LaunchConfig.config_id == snapshot["config_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    instance = (
        await db.execute(
            select(Instance)
            .where(Instance.instance_id == snapshot["instance_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    nodes = (
        (
            await db.execute(
                select(Node)
                .join(instance_nodes, instance_nodes.c.node_id == Node.uuid)
                .where(instance_nodes.c.instance_id == snapshot["instance_id"])
                .options(lazyload("*"))
                .with_for_update(of=Node)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalars()
        .all()
    )
    node_document = sorted(
        (_claim_node_document(node) for node in nodes),
        key=lambda item: item["uuid"],
    )
    if (
        launch_config is None
        or instance is None
        or launch_config.failed_at is not None
        or launch_config.completed_at is not None
        or launch_config.verified_at is not None
        or instance.verified
        or instance.deployment_id != snapshot["deployment_id"]
        or launch_config.config_id != snapshot["config_id"]
        or str(launch_config.seed) != snapshot["seed"]
        or instance.config_id != snapshot["config_id"]
        or instance.instance_id != snapshot["instance_id"]
        or launch_config.chute_id != snapshot["chute_id"]
        or instance.chute_id != snapshot["chute_id"]
        or launch_config.job_id != snapshot["job_id"]
        or launch_config.user_id != snapshot["user_id"]
        or launch_config.server_id != snapshot["server_id"]
        or instance.server_id != snapshot["server_id"]
        or launch_config.compute_type != snapshot["compute_type"]
        or launch_config.gpu_management_mode != snapshot["management_mode"]
        or instance.gpu_management_mode != snapshot["management_mode"]
        or launch_config.gpu_launch_reservation_id != snapshot["reservation_id"]
        or instance.gpu_launch_reservation_id != snapshot["reservation_id"]
        or instance.gpu_allocation_group_id != snapshot["allocation_group_id"]
        or instance.gpu_allocation_group_generation
        != snapshot["allocation_group_generation"]
        or instance.gpu_process_incarnation != snapshot["process_incarnation"]
        or launch_config.miner_hotkey != snapshot["miner_hotkey"]
        or instance.miner_hotkey != snapshot["miner_hotkey"]
        or instance.host != snapshot["host"]
        or instance.port != snapshot["port"]
        or canonical_sha256({"symmetric_key": instance.symmetric_key})
        != snapshot["symmetric_key_sha256"]
        or node_document != snapshot["nodes"]
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch claim lineage changed during external verification.",
        )

    server = None
    if snapshot["server_id"] is not None:
        server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == snapshot["server_id"])
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if (
            server is None
            or server.server_id != snapshot["server_id"]
            or server.compute_type != snapshot["compute_type"]
            or server.miner_hotkey != snapshot["miner_hotkey"]
            or server.in_maintenance
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Launch server lineage changed during external verification.",
            )

    if snapshot["reservation_id"] is not None:
        reservation = (
            await db.execute(
                select(GpuLaunchReservation)
                .where(
                    GpuLaunchReservation.reservation_id == snapshot["reservation_id"]
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        group = (
            (
                await db.execute(
                    select(GpuAllocationGroup)
                    .where(
                        GpuAllocationGroup.allocation_group_id
                        == snapshot["allocation_group_id"]
                    )
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).scalar_one_or_none()
            if reservation is not None
            else None
        )
        latest = (
            await _latest_attestation_attempt(
                db,
                server.server_id,
                for_update=True,
            )
            if server is not None
            else None
        )
        try:
            _current_attestation(
                server,
                latest,
                expected_id=server.gpu_runtime_session_attestation_id,
            )
        except (AttributeError, HTTPException) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="GPU operational attestation changed during launch verification.",
            ) from exc
        mode = snapshot["management_mode"]
        if (
            mode not in {"platform", "miner"}
            or reservation is None
            or group is None
            or reservation.state != "running"
            or group.state != "running"
            or reservation.management_mode != mode
            or group.management_mode != mode
            or reservation.server_id != server.server_id
            or reservation.reservation_id != server.gpu_launch_reservation_id
            or reservation.allocation_group_id != snapshot["allocation_group_id"]
            or reservation.allocation_group_generation
            != snapshot["allocation_group_generation"]
            or reservation.process_incarnation != snapshot["process_incarnation"]
            or group.allocation_group_id != reservation.allocation_group_id
            or group.generation != reservation.allocation_group_generation
            or group.reservation_id != reservation.reservation_id
            or group.process_incarnation != reservation.process_incarnation
            or server.gpu_management_mode != mode
            or server.gpu_retired_at is not None
            or server.gpu_runtime_session_expires_at is None
            or server.gpu_runtime_session_expires_at <= datetime.now(timezone.utc)
            or server.gpu_allocation_group_id != reservation.allocation_group_id
            or server.gpu_allocation_group_generation
            != reservation.allocation_group_generation
            or server.gpu_process_incarnation != reservation.process_incarnation
            or (
                mode == "platform"
                and (
                    reservation.chute_id != snapshot["chute_id"]
                    or reservation.job_id != snapshot["job_id"]
                    or reservation.workload_owner != snapshot["user_id"]
                )
            )
            or (
                mode == "miner"
                and (reservation.chute_id is not None or reservation.job_id is not None)
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="GPU reservation changed during launch external verification.",
            )
    elif (
        snapshot["management_mode"] is not None
        or snapshot["allocation_group_id"] is not None
        or snapshot["allocation_group_generation"] is not None
        or snapshot["process_incarnation"] is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Legacy launch acquired managed GPU lineage during external verification.",
        )
    return launch_config, instance, nodes


@router.post("/launch_config/{config_id}/tee")
async def claim_tee_launch_config(
    config_id: str,
    args: TeeLaunchConfigArgs,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
    expected_nonce: str = Depends(
        validate_request_nonce(NoncePurpose.INSTANCE_VERIFICATION)
    ),
):
    """Claim a TEE launch config, verify attestation, and receive symmetric key."""
    (
        launch_config,
        nodes,
        instance,
        validator_pubkey,
    ) = await _validate_tee_launch_config_instance(
        config_id, args, request, db, authorization
    )

    _validate_launch_config_not_expired(launch_config)

    # CPU-TEE: bind the symmetric-key handout to the attested TD. Only the in-TEE key can complete
    # the mTLS handshake against the pinned attested_cert, so an operator holding only the launch
    # JWT cannot claim the instance and obtain its key. Fail closed (no-op for GPU-TEE).
    await require_attested_client_cert(db, request, instance)

    # Commit durable claim intent and release every lifecycle row lock before
    # evidence retrieval, quote verification, or NVIDIA verification.
    claim_snapshot = _claim_lineage_snapshot(launch_config, instance, nodes)
    await db.commit()
    await db.refresh(launch_config)

    await _mark_launch_config_retrieved(config_id)

    # Send event. CPU (GPU-less) chutes have no GPU nodes (nodes == []).
    await db.refresh(instance)
    gpu_count = len(nodes)
    gpu_type = nodes[0].gpu_identifier if nodes else None
    asyncio.create_task(
        notify_created(instance, gpu_count=gpu_count, gpu_type=gpu_type)
    )
    asyncio.create_task(_maybe_start_log_capture(instance, config_id))

    # Verify TEE attestation evidence. CPU chutes have no GPU nodes; skip GPU evidence.
    compute_type = "cpu" if not nodes else "gpu"
    try:
        await verify_tee_chute(
            db,
            instance,
            launch_config,
            args.deployment_id,
            expected_nonce,
            compute_type=compute_type,
        )
        await db.commit()
        launch_config, instance, nodes = await _locked_current_claim_lineage(
            db, claim_snapshot
        )
    except Exception as exc:
        chute_id = launch_config.chute_id
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        reason = detail if isinstance(detail, str) else str(detail)
        await db.rollback()
        async with get_session() as error_session:
            await acquire_gpu_lifecycle_lock(error_session)
            await error_session.execute(
                text(
                    "UPDATE launch_configs SET failed_at = NOW(), "
                    "verification_error = :reason WHERE config_id = :config_id"
                ),
                {"config_id": config_id, "reason": reason},
            )
        track_launch_config_failure(chute_id, reason)
        raise

    instance.deployment_id = args.deployment_id
    await db.commit()
    await acquire_gpu_lifecycle_lock(db)
    await db.refresh(instance)

    response = {"symmetric_key": instance.symmetric_key}

    if validator_pubkey:
        response["validator_pubkey"] = validator_pubkey

    return response


def _reject_cpu_tee_on_legacy_endpoint(instance) -> None:
    """The /attest and /graval launch-config endpoints build the verified response (chute code +
    fs_key) and are the GPU/graval path. CPU-TEE (self-registered) instances MUST verify via
    POST/PUT /launch_config/{config_id}/tee, which binds the secret response to the in-TEE attested
    client cert (require_attested_client_cert). Reject a CPU-TEE instance here (defense-in-depth):
    today these endpoints also crash on the missing GPU nodes, but this makes the exclusion
    explicit + fail-closed so a future refactor cannot hand a CPU-TEE chute's code/secrets out
    without the attested-cert binding. Only CPU-TEE instances carry a server_id."""
    if getattr(instance, "server_id", None) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "CPU-TEE instances must verify via /instances/launch_config/{config_id}/tee "
                "(attested-cert bound); the graval/attest endpoints are GPU-only."
            ),
        )


async def _mark_launch_config_retrieved(config_id: str) -> None:
    async with get_session() as session:
        await acquire_gpu_lifecycle_lock(session)
        await session.execute(
            text(
                "UPDATE launch_configs SET retrieved_at = NOW() WHERE config_id = :config_id"
            ),
            {"config_id": config_id},
        )


@router.post("/launch_config/{config_id}/attest")
async def validate_tee_launch_config_instance(
    config_id: str,
    args: LegacyTeeLaunchConfigArgs,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
    expected_nonce: str = Depends(validate_request_nonce(NoncePurpose.BOOT)),
):
    # TODO: Remove endpoint once all TEE VMs are upgraded to 0.2.0
    # and once all TEE chutes are upgraded to 0.6.0
    (
        launch_config,
        nodes,
        instance,
        validator_pubkey,
    ) = await _validate_tee_launch_config_instance(
        config_id, args, request, db, authorization
    )
    _reject_cpu_tee_on_legacy_endpoint(instance)

    _validate_launch_config_not_expired(launch_config)

    # Enforce rint_pubkey for chutes >= 0.5.1
    if semcomp(instance.chutes_version or "0.0.0", "0.5.1") >= 0:
        if not instance.rint_pubkey or not instance.rint_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="rint_pubkey and rint_nonce required for chutes >= 0.5.1",
            )

    # Persist the tentative instance, then release lifecycle custody before
    # direct NVIDIA evidence verification and any legacy filesystem worker.
    claim_snapshot = _claim_lineage_snapshot(launch_config, instance, nodes)
    await db.commit()
    await db.refresh(launch_config)

    await _mark_launch_config_retrieved(config_id)

    # Send event.
    await db.refresh(instance)
    gpu_count = len(nodes)
    gpu_type = nodes[0].gpu_identifier
    asyncio.create_task(
        notify_created(instance, gpu_count=gpu_count, gpu_type=gpu_type)
    )
    asyncio.create_task(_maybe_start_log_capture(instance, config_id))

    assert_gpu_external_work_allowed(db, "legacy chute NVIDIA evidence verification")
    try:
        await verify_gpu_evidence(args.gpu_evidence, expected_nonce)
    except AttestationError as exc:
        # The verifier logged the private reason; expose only its safe domain response.
        raise HTTPException(status_code=exc.http_status, detail=exc.message)

    request_body = await request.json()

    # Reload instance with chute relationship for filesystem validation
    # Lazy load fails
    stmt = (
        select(Instance)
        .where(Instance.instance_id == instance.instance_id)
        .options(
            joinedload(Instance.chute).joinedload(Chute.image),
            joinedload(Instance.job),
        )
    )
    instance = (await db.execute(stmt)).scalar_one()

    external_input_sha256 = canonical_sha256(
        _verification_external_input_document(
            launch_config,
            instance,
            nodes,
            request_body,
        )
    )
    filesystem_hash = await _collect_legacy_filesystem_hash(db, instance, launch_config)
    port_results = await _collect_job_port_results(db, instance)
    await db.commit()

    launch_config, instance, nodes = await _locked_current_claim_lineage(
        db, claim_snapshot
    )
    instance = await _reload_verification_context(db, instance.instance_id)
    if (
        canonical_sha256(
            _verification_external_input_document(
                launch_config,
                instance,
                nodes,
                request_body,
            )
        )
        != external_input_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Legacy TEE verification authority changed during external work.",
        )
    await _validate_legacy_filesystem(
        db,
        instance,
        launch_config,
        request_body,
        expected_hash=filesystem_hash,
    )

    await _verify_job_ports(db, instance, port_results=port_results)
    # Everything checks out.
    launch_config.verified_at = func.now()
    await _mark_instance_verified(db, instance, launch_config)
    return_value = await _build_launch_config_verified_response(
        db, instance, launch_config, request
    )
    return_value["symmetric_key"] = instance.symmetric_key

    # Include validator pubkey if ECDH was used (for miner to derive session key)
    if validator_pubkey:
        return_value["validator_pubkey"] = validator_pubkey

    await db.refresh(instance)
    _gpu_count = len(nodes) if nodes else None
    _gpu_type = nodes[0].gpu_identifier if nodes else None
    asyncio.create_task(
        notify_verified(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
    )
    return return_value


@router.post("/launch_config/{config_id}")
async def claim_launch_config(
    config_id: str,
    args: LaunchConfigArgs,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    # Backwards compatibility for older client libs; delegates to graval endpoint.
    # TODO: Remove this once all chutes are upgraded to 0.6.0 or later
    return await claim_graval_launch_config(config_id, args, request, db, authorization)


@router.post("/launch_config/{config_id}/graval")
async def claim_graval_launch_config(
    config_id: str,
    args: LaunchConfigArgs,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    """Claim a Graval launch config and receive PoVW challenge."""
    (
        launch_config,
        nodes,
        instance,
        validator_pubkey,
    ) = await _validate_graval_launch_config_instance(
        config_id, args, request, db, authorization
    )
    _reject_cpu_tee_on_legacy_endpoint(instance)

    # Persist the exact tentative instance/node claim before invoking Graval.
    node = random.choice(nodes)
    selected_node = _claim_node_document(node)
    claim_snapshot = _claim_lineage_snapshot(launch_config, instance, nodes)
    iterations = SUPPORTED_GPUS[node.gpu_identifier]["graval"]["iterations"]
    symmetric_key = instance.symmetric_key
    job_id = launch_config.job_id
    await db.commit()

    assert_gpu_external_work_allowed(db, "Graval challenge encryption")
    encrypted_payload = await graval_encrypt(
        node,
        symmetric_key,
        iterations=iterations,
        seed=None,
    )
    try:
        seed_text, ciphertext = encrypted_payload.split("|", 1)
        seed = int(seed_text)
        if not ciphertext:
            raise ValueError("empty Graval ciphertext")
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Graval returned an invalid challenge payload.",
        ) from exc

    launch_config, instance, current_nodes = await _locked_current_claim_lineage(
        db, claim_snapshot
    )
    current_node = next(
        (item for item in current_nodes if item.uuid == selected_node["uuid"]),
        None,
    )
    if current_node is None or _claim_node_document(current_node) != selected_node:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Selected Graval node changed during challenge encryption.",
        )
    launch_config.seed = seed
    await db.commit()

    # Start the PoVW response window only after the exact challenge is durable.
    await _mark_launch_config_retrieved(config_id)
    logger.success(
        f"Generated Graval challenge for {selected_node['uuid']} with seed={seed} "
        f"instance_id={instance.instance_id}"
    )

    gpu_count = len(current_nodes)
    gpu_type = current_nodes[0].gpu_identifier
    asyncio.create_task(
        notify_created(instance, gpu_count=gpu_count, gpu_type=gpu_type)
    )
    asyncio.create_task(_maybe_start_log_capture(instance, config_id))

    # The miner must decrypt the proposed symmetric key from this response payload,
    # then encrypt something using this symmetric key within the expected graval timeout.
    response = {
        "seed": seed,
        "iterations": iterations,
        "job_id": job_id,
        "symmetric_key": {
            "ciphertext": ciphertext,
            "uuid": selected_node["uuid"],
            "response_plaintext": f"secret is {config_id} {seed}",
        },
    }

    # Include validator pubkey if ECDH was used
    if validator_pubkey:
        response["validator_pubkey"] = validator_pubkey

    return response


async def delayed_instance_tls_check(instance_id: str):
    """Verify the chute port serves the expected TLS cert after activation."""
    for attempt in range(4):
        await asyncio.sleep(7)
        async with get_session() as session:
            instance = (
                (
                    await session.execute(
                        select(Instance).where(Instance.instance_id == instance_id)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if not instance or not instance.active:
                return
            if not instance.cacert:
                return
            live_ok = await _verify_instance_tls_live(
                instance.host, instance.port, instance.cacert
            )
            if not live_ok:
                reason = (
                    "Live TLS cert verification failed: "
                    f"{instance.instance_id=} {instance.miner_hotkey=} {instance.chute_id=} (attempt {attempt + 1} of 4)"
                )
                if attempt == 3:
                    logger.error(reason)
                    await session.delete(instance)
                    await session.execute(
                        text(
                            "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
                        ),
                        {"instance_id": instance.instance_id, "reason": reason},
                    )
                    await session.commit()
                    await invalidate_instance_cache(
                        instance.chute_id, instance_id=instance.instance_id
                    )
                    asyncio.create_task(notify_deleted(instance))
                else:
                    logger.warning(reason)
            else:
                logger.success(
                    f"Live TLS cert verification passed: {instance.instance_id=} on {instance.host}:{instance.port}"
                )
                await invalidate_instance_cache(
                    instance.chute_id, instance_id=instance.instance_id
                )
                asyncio.create_task(notify_activated(instance))
                return


async def delayed_instance_fs_check(instance_id: str):
    await asyncio.sleep(10)  # XXX wait for uvicorn to be listening.

    async with get_session() as session:
        instance = (
            (
                await session.execute(
                    select(Instance).where(Instance.instance_id == instance_id)
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if not instance:
            return
        if not await verify_fs_hash(instance):
            reason = (
                "Instance has failed filesystem verification: "
                f"{instance.instance_id=} {instance.miner_hotkey=} {instance.chute_id=}"
            )
            logger.warning(reason)
            await session.delete(instance)
            await session.execute(
                text(
                    "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
                ),
                {"instance_id": instance.instance_id, "reason": reason},
            )
            await session.commit()
            asyncio.create_task(notify_deleted(instance))
        else:
            logger.success(
                f"Successfully verified FS hash {instance.instance_id=} {instance.miner_hotkey=} {instance.chute_id=}"
            )


def _activation_extra_without_attempt(instance: Instance) -> dict:
    extra = dict(instance.extra or {})
    extra.pop(_ACTIVATION_ATTEMPT_EXTRA_KEY, None)
    return extra


def _activation_input_document(
    launch_config: LaunchConfig,
    instance: Instance,
    chute: Chute,
) -> dict:
    return {
        "schema": "chutes.launch-activation-input.v1",
        "launch_config": {
            "config_id": launch_config.config_id,
            "chute_id": launch_config.chute_id,
            "job_id": launch_config.job_id,
            "user_id": launch_config.user_id,
            "miner_hotkey": launch_config.miner_hotkey,
            "compute_type": launch_config.compute_type,
            "server_id": launch_config.server_id,
            "management_mode": launch_config.gpu_management_mode,
            "reservation_id": launch_config.gpu_launch_reservation_id,
            "verified_at": launch_config.verified_at.isoformat()
            if launch_config.verified_at
            else None,
            "failed_at": launch_config.failed_at.isoformat()
            if launch_config.failed_at
            else None,
            "completed_at": launch_config.completed_at.isoformat()
            if launch_config.completed_at
            else None,
        },
        "instance": {
            "instance_id": instance.instance_id,
            "config_id": instance.config_id,
            "chute_id": instance.chute_id,
            "server_id": instance.server_id,
            "management_mode": instance.gpu_management_mode,
            "reservation_id": instance.gpu_launch_reservation_id,
            "allocation_group_id": instance.gpu_allocation_group_id,
            "allocation_group_generation": instance.gpu_allocation_group_generation,
            "process_incarnation": instance.gpu_process_incarnation,
            "miner_hotkey": instance.miner_hotkey,
            "deployment_id": instance.deployment_id,
            "host": instance.host,
            "port": instance.port,
            "cacert_sha256": canonical_sha256(instance.cacert)
            if instance.cacert
            else None,
            "active": bool(instance.active),
            "verified": bool(instance.verified),
            "activated": instance.activated_at is not None,
            "bounty": bool(instance.bounty),
            "compute_multiplier": instance.compute_multiplier,
            "created_at": instance.created_at.isoformat()
            if instance.created_at
            else None,
            "extra_sha256": canonical_sha256(
                _activation_extra_without_attempt(instance)
            ),
        },
        "chute": {
            "chute_id": chute.chute_id,
            "user_id": chute.user_id,
            "name": chute.name,
            "public": bool(chute.public),
            "tee": bool(chute.tee),
            "disabled": bool(chute.disabled),
            "shutdown_after_seconds": chute.shutdown_after_seconds,
            "created_at": chute.created_at.isoformat() if chute.created_at else None,
        },
    }


def _activation_attempt_identity(config_id: str, instance_id: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"https://chutes.ai/launch-activation/{config_id}/{instance_id}",
        )
    )


def _activation_attempt(
    launch_config: LaunchConfig,
    instance: Instance,
    chute: Chute,
    *,
    create: bool,
) -> tuple[dict, str]:
    input_sha256 = canonical_sha256(
        _activation_input_document(launch_config, instance, chute)
    )
    attempt_id = _activation_attempt_identity(
        launch_config.config_id,
        instance.instance_id,
    )
    extra = dict(instance.extra or {})
    attempt = extra.get(_ACTIVATION_ATTEMPT_EXTRA_KEY)
    if attempt is None and create:
        attempt = {
            "schema": "chutes.launch-activation-attempt.v1",
            "attempt_id": attempt_id,
            "config_id": launch_config.config_id,
            "instance_id": instance.instance_id,
            "input_sha256": input_sha256,
            "state": "processing",
            "result": None,
            "result_sha256": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
        }
        extra[_ACTIVATION_ATTEMPT_EXTRA_KEY] = attempt
        instance.extra = extra
    if not isinstance(attempt, dict):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch activation attempt state is missing or malformed.",
        )
    if (
        attempt.get("schema") != "chutes.launch-activation-attempt.v1"
        or attempt.get("attempt_id") != attempt_id
        or attempt.get("config_id") != launch_config.config_id
        or attempt.get("instance_id") != instance.instance_id
        or attempt.get("input_sha256") != input_sha256
        or attempt.get("state") not in {"processing", "completed"}
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch activation attempt authority changed.",
        )
    if attempt["state"] == "processing" and (
        attempt.get("result") is not None
        or attempt.get("result_sha256") is not None
        or attempt.get("completed_at") is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Processing launch activation attempt has terminal result state.",
        )
    if attempt["state"] == "completed":
        result = attempt.get("result")
        if (
            not isinstance(result, dict)
            or attempt.get("result_sha256") != canonical_sha256(result)
            or attempt.get("completed_at") is None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Completed launch activation attempt result is invalid.",
            )
    return attempt, input_sha256


def _validate_completed_activation_attempt(
    launch_config: LaunchConfig,
    instance: Instance,
    *,
    expected_result: dict | None = None,
    expected_result_sha256: str | None = None,
    allow_missing: bool = False,
) -> None:
    attempt = (instance.extra or {}).get(_ACTIVATION_ATTEMPT_EXTRA_KEY)
    if attempt is None and allow_missing:
        return
    expected_attempt_id = _activation_attempt_identity(
        launch_config.config_id,
        instance.instance_id,
    )
    if (
        not isinstance(attempt, dict)
        or attempt.get("schema") != "chutes.launch-activation-attempt.v1"
        or attempt.get("attempt_id") != expected_attempt_id
        or attempt.get("config_id") != launch_config.config_id
        or attempt.get("instance_id") != instance.instance_id
        or attempt.get("state") != "completed"
        or not isinstance(attempt.get("result"), dict)
        or attempt.get("result", {}).get("schema")
        != "chutes.launch-activation-result.v1"
        or attempt.get("result", {}).get("attempt_id") != expected_attempt_id
        or attempt.get("result_sha256") != canonical_sha256(attempt.get("result"))
        or attempt.get("completed_at") is None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active instance has invalid launch activation result state.",
        )
    if expected_result is not None and (
        attempt.get("result") != expected_result
        or attempt.get("result_sha256") != expected_result_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active instance has conflicting launch activation result state.",
        )


def _activation_external_result(
    attempt_id: str,
    chute_id: str,
    bounty_result: dict,
    warmup_result: dict,
) -> tuple[dict, str]:
    if (
        not isinstance(bounty_result, dict)
        or bounty_result.get("schema") != "chutes.activation-bounty-result.v1"
        or bounty_result.get("attempt_id") != attempt_id
        or bounty_result.get("chute_id") != chute_id
        or "bounty" not in bounty_result
    ):
        raise RuntimeError("Activation bounty replay identity mismatch")
    if (
        not isinstance(warmup_result, dict)
        or warmup_result.get("schema") != "chutes.activation-warmup-result.v1"
        or warmup_result.get("attempt_id") != attempt_id
        or warmup_result.get("chute_id") != chute_id
        or "requested_at" not in warmup_result
    ):
        raise RuntimeError("Activation warmup replay identity mismatch")
    result = {
        "schema": "chutes.launch-activation-result.v1",
        "attempt_id": attempt_id,
        "bounty_result": bounty_result,
        "warmup_result": warmup_result,
    }
    return result, canonical_sha256(result)


def _parse_activation_warmup_envelope(data, attempt_id: str, chute_id: str) -> dict:
    if data is None:
        raise RuntimeError(
            "Activation warmup consume returned no durable result; retry the same attempt"
        )
    try:
        envelope = json.loads(data)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            "Activation warmup consume returned an invalid envelope"
        ) from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != "chutes.activation-warmup-result.v1"
        or envelope.get("attempt_id") != attempt_id
        or envelope.get("chute_id") != chute_id
        or "requested_at" not in envelope
        or not isinstance(envelope.get("consumed_at"), (int, float))
    ):
        raise RuntimeError("Activation warmup consume envelope identity mismatch")
    requested_at = envelope["requested_at"]
    if requested_at is not None and not isinstance(requested_at, (str, int, float)):
        raise RuntimeError("Activation warmup consume timestamp is invalid")
    return envelope


async def _consume_activation_warmup(
    db: AsyncSession,
    chute_id: str,
    attempt_id: str,
) -> dict:
    assert_gpu_external_work_allowed(db, "activation warmup telemetry consume")
    data = await settings.redis_client.eval(
        _CONSUME_WARMUP_REPLAY_LUA,
        2,
        f"warmup_requested_at:{chute_id}",
        f"activation_warmup_result:{attempt_id}",
        attempt_id,
        _ACTIVATION_REPLAY_TTL_SECONDS,
        chute_id,
    )
    return _parse_activation_warmup_envelope(data, attempt_id, chute_id)


async def _locked_activation_context(
    db: AsyncSession,
    config_id: str,
) -> tuple[LaunchConfig, Instance, Chute]:
    await acquire_gpu_lifecycle_lock(db)
    launch_config = (
        await db.execute(
            select(LaunchConfig)
            .where(LaunchConfig.config_id == config_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    instance = (
        await db.execute(
            select(Instance)
            .where(Instance.config_id == config_id)
            .options(lazyload("*"))
            .with_for_update(of=Instance)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    chute = (
        (
            await db.execute(
                select(Chute)
                .where(Chute.chute_id == getattr(instance, "chute_id", None))
                .options(lazyload("*"))
                .with_for_update(of=Chute)
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if launch_config is None or instance is None or chute is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Instance has disappeared for launch config {config_id}.",
        )
    return launch_config, instance, chute


@router.get("/launch_config/{config_id}/activate")
async def activate_launch_config_instance(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    token = authorization.strip().split(" ")[-1]
    launch_config = await load_launch_config_from_jwt(
        db,
        config_id,
        token,
        allow_retrieved=True,
        acquire_lifecycle_lock=False,
    )
    if not launch_config.verified_at:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Launch config has not been verified.",
        )

    # This helper may open a separate database session on its first call. Resolve
    # it before acquiring the lifecycle advisory lock.
    platform_user_id = await chutes_user_id()
    launch_config, instance, chute = await _locked_activation_context(db, config_id)
    if instance.active:
        _validate_completed_activation_attempt(
            launch_config,
            instance,
            allow_missing=True,
        )
        await db.commit()
        return {"ok": True}
    if not instance.verified or launch_config.failed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch verification lineage is no longer activatable.",
        )

    max_startup_seconds = 3.5 * 60 * 60
    if instance.created_at:
        startup_seconds = (
            datetime.utcnow() - instance.created_at.replace(tzinfo=None)
        ).total_seconds()
        if startup_seconds > max_startup_seconds:
            reason = (
                f"Instance took too long to activate ({startup_seconds:.0f}s > "
                f"{max_startup_seconds}s max)"
            )
            await db.delete(instance)
            await db.execute(
                text(
                    "UPDATE instance_audit SET deletion_reason = :reason "
                    "WHERE instance_id = :instance_id"
                ),
                {"instance_id": instance.instance_id, "reason": reason},
            )
            await db.commit()
            asyncio.create_task(notify_deleted(instance))
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=reason,
            )

    is_private = bool(
        not chute.public
        and not has_legacy_private_billing(chute)
        and chute.user_id != platform_user_id
    )
    activation_attempt, activation_input_sha256 = _activation_attempt(
        launch_config,
        instance,
        chute,
        create=True,
    )
    if activation_attempt["state"] != "processing":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Inactive instance has a completed launch activation attempt.",
        )
    activation_attempt_id = activation_attempt["attempt_id"]

    # The attempt identity is durable before Redis can consume either signal.
    await db.commit()

    scale_value = None
    bounty_exists = False
    if is_private or (chute.public and not chute.tee):
        assert_gpu_external_work_allowed(db, "activation scale telemetry lookup")
        scale_value = _normalized_external_scalar(
            await settings.redis_client.get(f"scale:{chute.chute_id}")
        )
    if is_private:
        assert_gpu_external_work_allowed(db, "activation bounty lookup")
        bounty_exists = await check_bounty_exists(chute.chute_id)

    launch_config, instance, chute = await _locked_activation_context(db, config_id)
    if instance.active:
        _validate_completed_activation_attempt(launch_config, instance)
        await db.commit()
        return {"ok": True}
    activation_attempt, current_input_sha256 = _activation_attempt(
        launch_config,
        instance,
        chute,
        create=False,
    )
    if (
        activation_attempt["state"] != "processing"
        or activation_attempt["attempt_id"] != activation_attempt_id
        or current_input_sha256 != activation_input_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch activation authority changed during scale resolution.",
        )

    if is_private:
        count_result = (
            (
                await db.execute(
                    text(
                        "SELECT COUNT(CASE WHEN active IS true AND verified IS true "
                        "THEN 1 ELSE NULL END) AS active_count FROM instances "
                        "WHERE chute_id = :chute_id"
                    ),
                    {"chute_id": chute.chute_id},
                )
            )
            .mappings()
            .first()
        )
        active_count = count_result["active_count"]
        target_count = int(scale_value) if scale_value else 0
        can_scale = (not active_count and bounty_exists) or active_count < target_count
        if not can_scale:
            reason = (
                f"Private chute chute_id={chute.chute_id} name={chute.name} "
                f"already has >= target_count={target_count} active instances"
            )
            await db.delete(instance)
            await db.execute(
                text(
                    "UPDATE instance_audit SET deletion_reason = :reason "
                    "WHERE instance_id = :instance_id"
                ),
                {"instance_id": instance.instance_id, "reason": reason},
            )
            await db.commit()
            asyncio.create_task(notify_deleted(instance))
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=reason,
            )
    elif chute.public:
        await _check_scalable_activation(
            db,
            chute,
            launch_config.miner_hotkey,
            scale_value=scale_value,
        )

    # Release all lifecycle and instance row locks before consuming Redis state.
    await db.commit()
    try:
        assert_gpu_external_work_allowed(db, "activation bounty claim")
        bounty_result = await claim_bounty(
            instance.chute_id,
            attempt_id=activation_attempt_id,
        )
        warmup_result = await _consume_activation_warmup(
            db,
            chute.chute_id,
            activation_attempt_id,
        )
        activation_result, activation_result_sha256 = _activation_external_result(
            activation_attempt_id,
            chute.chute_id,
            bounty_result,
            warmup_result,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Activation telemetry result is unavailable; retry the same activation.",
        ) from exc

    launch_config, instance, chute = await _locked_activation_context(db, config_id)
    if instance.active:
        _validate_completed_activation_attempt(
            launch_config,
            instance,
            expected_result=activation_result,
            expected_result_sha256=activation_result_sha256,
        )
        await db.commit()
        return {"ok": True}

    activation_attempt, current_input_sha256 = _activation_attempt(
        launch_config,
        instance,
        chute,
        create=False,
    )
    if (
        activation_attempt["state"] != "processing"
        or activation_attempt["attempt_id"] != activation_attempt_id
        or current_input_sha256 != activation_input_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch activation authority changed during Redis work.",
        )

    bounty = bounty_result["bounty"]
    warmup_requested_at = warmup_result["requested_at"]
    if bounty:
        instance.bounty = True
        bounty_boost = calculate_bounty_boost(bounty["age_seconds"])
        instance.compute_multiplier *= bounty_boost
        instance_logger(
            instance,
            event=LifecycleEvent.BOUNTY_CLAIM,
            bounty_age_seconds=bounty["age_seconds"],
            bounty_boost=round(bounty_boost, 2),
            compute_multiplier=instance.compute_multiplier,
        ).info(
            f"Claimed bounty for {instance.chute_id}: age={bounty['age_seconds']}s, "
            f"bounty_boost={bounty_boost:.2f}x, "
            f"total compute_multiplier={instance.compute_multiplier}"
        )

    warmup_multiplier = (instance.extra or {}).get(
        "warmup_compute_multiplier", instance.compute_multiplier
    )
    if warmup_multiplier is not None and instance.created_at is not None:
        await db.execute(
            text(
                "INSERT INTO instance_compute_history "
                "(instance_id, compute_multiplier, started_at, ended_at) "
                "VALUES (:instance_id, :multiplier, :started_at, NOW())"
            ),
            {
                "instance_id": instance.instance_id,
                "multiplier": warmup_multiplier,
                "started_at": instance.created_at.replace(tzinfo=None),
            },
        )

    completed_attempt = dict(activation_attempt)
    completed_attempt.update(
        {
            "state": "completed",
            "result": activation_result,
            "result_sha256": activation_result_sha256,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    instance_extra = dict(instance.extra or {})
    instance_extra[_ACTIVATION_ATTEMPT_EXTRA_KEY] = completed_attempt
    instance.extra = instance_extra
    instance.active = True
    instance.activated_at = func.now()
    if launch_config.job_id or is_private:
        instance.stop_billing_at = func.now() + timedelta(
            seconds=chute.shutdown_after_seconds or 300
        )
    await db.commit()

    track_warmup_seconds(
        chute.chute_id,
        WarmupTrigger.BOUNTY,
        bounty["age_seconds"] if bounty else None,
    )
    track_warmup_seconds_since(
        chute.chute_id,
        WarmupTrigger.EXPLICIT,
        warmup_requested_at,
    )
    if instance.cacert:
        asyncio.create_task(delayed_instance_tls_check(instance.instance_id))
    else:
        await invalidate_instance_cache(
            instance.chute_id, instance_id=instance.instance_id
        )
        asyncio.create_task(notify_activated(instance))
    return {"ok": True}


async def verify_port_map(instance, port_map):
    """
    Verify a port is open on the remote chute pod.
    """
    logger.info(f"Attempting to verify {port_map=} on {instance.instance_id=}")
    try:
        if port_map["proto"].lower() in ["tcp", "http"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((instance.host, port_map["external_port"]))
            logger.info(f"Connected to {instance.instance_id=} on {port_map=}")
            sock.send(b"test")
            logger.info(f"Sent a packet to {instance.instance_id=} on {port_map=}")
            response = sock.recv(1024).decode()
            logger.success(
                f"Received a response from {instance.instance_id=} on {port_map=}"
            )
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            sock.sendto(b"test", (instance.host, port_map["external_port"]))
            logger.info(f"Sent a packet to {instance.instance_id=} on {port_map=}")
            response, _ = sock.recvfrom(1024)
            response = response.decode()
            logger.success(
                f"Received a response from {instance.instance_id=} on {port_map=}"
            )
            sock.close()
        if "|" not in response:
            logger.error(f"Invalid socket response for {port_map=} {response=}")
            return False

        iv_hex, encrypted_response = response.split("|", 1)
        decrypted = await asyncio.to_thread(
            aes_decrypt, encrypted_response, instance.symmetric_key, iv_hex
        )
        expected = (
            f"response from {port_map['proto'].lower()} {port_map['internal_port']}"
        )
        return decrypted.decode() == expected
    except Exception as e:
        logger.error(f"Port verification failed for {port_map}: {e}")
        return False


def _validate_launch_config_not_expired(launch_config):
    # Validate the launch config.
    config_id = launch_config.config_id
    if launch_config.verified_at:
        logger.warning(f"Launch config {config_id} has already been verified!")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Launch config has already been verified: {config_id}",
        )
    if launch_config.failed_at:
        logger.warning(
            f"Launch config {config_id} has non-null failed_at: {launch_config.failed_at}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Launch config failed verification: {launch_config.failed_at=} {launch_config.verification_error=}",
        )


def _verification_external_input_document(
    launch_config: LaunchConfig,
    instance: Instance,
    nodes: list[Node],
    response_body: dict,
) -> dict:
    job = instance.job
    return {
        "schema": "chutes.launch-verification-external-input.v1",
        "claim": _claim_lineage_snapshot(launch_config, instance, nodes),
        "chute": {
            "chute_id": instance.chute.chute_id,
            "version": instance.chute.version,
            "chutes_version": instance.chute.chutes_version,
            "image_id": instance.chute.image_id,
            "image_patch_version": getattr(instance.chute.image, "patch_version", None),
            "filename": instance.chute.filename,
            "tee": bool(instance.chute.tee),
            "disabled": bool(instance.chute.disabled),
        },
        "job": (
            {
                "job_id": job.job_id,
                "chute_id": job.chute_id,
                "version": job.version,
                "instance_id": job.instance_id,
                "miner_hotkey": job.miner_hotkey,
                "gpu_management_mode": job.gpu_management_mode,
                "gpu_launch_reservation_id": job.gpu_launch_reservation_id,
                "started": job.started_at is not None,
                "finished": job.finished_at is not None,
                "port_mappings": job.port_mappings,
            }
            if job is not None
            else None
        ),
        "instance_port_mappings": instance.port_mappings,
        "response_sha256": canonical_sha256(response_body),
    }


async def _collect_legacy_filesystem_hash(
    db: AsyncSession,
    instance: Instance,
    launch_config: LaunchConfig,
):
    if semcomp(instance.chute.chutes_version, "0.3.1") < 0 and "CFSV_OP" in os.environ:
        assert_gpu_external_work_allowed(db, "legacy filesystem hash dispatch")
        task = await generate_fs_hash.kiq(
            instance.chute.image_id,
            instance.chute.image.patch_version,
            launch_config.seed,
            sparse=False,
            exclude_path=f"/app/{instance.chute.filename}",
        )
        assert_gpu_external_work_allowed(db, "legacy filesystem hash wait")
        result = await _await_fs_hash(
            task,
            launch_config.config_id,
            instance.miner_hotkey,
        )
        return result.return_value
    return None


async def _reload_verification_context(
    db: AsyncSession,
    instance_id: str,
) -> Instance:
    return (
        (
            await db.execute(
                select(Instance)
                .where(Instance.instance_id == instance_id)
                .options(
                    joinedload(Instance.nodes),
                    joinedload(Instance.job),
                    joinedload(Instance.chute).joinedload(Chute.image),
                )
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalar_one()
    )


async def _validate_legacy_filesystem(
    db: AsyncSession,
    instance: Instance,
    launch_config: LaunchConfig,
    response_body,
    *,
    expected_hash=_EXTERNAL_VALUE_UNSET,
):
    config_id = launch_config.config_id
    # Valid filesystem/integrity?
    if semcomp(instance.chute.chutes_version, "0.3.1") < 0:
        image_id = instance.chute.image_id
        patch_version = instance.chute.image.patch_version
        if "CFSV_OP" in os.environ:
            if expected_hash is _EXTERNAL_VALUE_UNSET:
                assert_gpu_external_work_allowed(db, "legacy filesystem hash dispatch")
                task = await generate_fs_hash.kiq(
                    image_id,
                    patch_version,
                    launch_config.seed,
                    sparse=False,
                    exclude_path=f"/app/{instance.chute.filename}",
                )
                assert_gpu_external_work_allowed(db, "legacy filesystem hash wait")
                result = await _await_fs_hash(task, config_id, instance.miner_hotkey)
                expected_hash = result.return_value
            if expected_hash != response_body["fsv"]:
                reason = (
                    f"Filesystem challenge failed for {config_id=} and {instance.instance_id=} {instance.miner_hotkey=}, "
                    f"{expected_hash=} for {image_id=} {patch_version=} but received {response_body['fsv']}"
                )
                logger.error(reason)
                launch_config.failed_at = func.now()
                launch_config.verification_error = reason
                await db.delete(instance)
                await db.execute(
                    text(
                        "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
                    ),
                    {"instance_id": instance.instance_id, "reason": reason},
                )
                await db.commit()
                asyncio.create_task(notify_deleted(instance))
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=launch_config.verification_error,
                )
        else:
            logger.warning("Extended filesystem verification disabled, skipping...")


async def _collect_job_port_results(
    db: AsyncSession, instance: Instance
) -> dict[str, bool]:
    job = instance.job
    results = {}
    if job and instance.server_id is None:
        for port_map in instance.port_mappings:
            if port_map["internal_port"] in (8000, 8001):
                continue
            key = canonical_sha256(port_map)
            assert_gpu_external_work_allowed(db, "launch job port socket verification")
            results[key] = await verify_port_map(instance, port_map)
    return results


async def _verify_job_ports(
    db: AsyncSession,
    instance: Instance,
    *,
    port_results=_EXTERNAL_VALUE_UNSET,
):
    job = instance.job
    if job:
        # Model B / TEE job chutes expose their declared (non-default) ports ONLY over the attested
        # owner-connect wireguard tunnel, never a host DNAT -- the validator has no direct path to
        # probe them (a directly-exposed port could only be MITM'd by the untrusted host). The TEE
        # attestation already binds the measured image + launch config that runs the job, so the
        # symmetric-key port handshake is redundant here; the owner confirms reachability on
        # `chutes connect`. Legacy (non-server_id) pod instances keep the direct probe.
        probe_ports = instance.server_id is None
        # Test the ports are open.
        for port_map in instance.port_mappings:
            if port_map["internal_port"] in (8000, 8001):
                continue
            if probe_ports:
                if port_results is _EXTERNAL_VALUE_UNSET:
                    assert_gpu_external_work_allowed(
                        db, "launch job port socket verification"
                    )
                    port_ok = await verify_port_map(instance, port_map)
                else:
                    port_ok = port_results.get(canonical_sha256(port_map), False)
            else:
                port_ok = True
            if not port_ok:
                reason = f"Failed port verification on {port_map=} for {instance.instance_id=} {instance.miner_hotkey=}"
                logger.error(reason)
                await db.execute(
                    text(
                        "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
                    ),
                    {"instance_id": instance.instance_id, "reason": reason},
                )
                # Persist the deletion reason and release any lifecycle/row
                # locks before publishing the failure notification. The
                # notifier is Redis-backed and must not race a rollback of
                # the state it announces.
                await db.commit()
                asyncio.create_task(notify_deleted(instance))
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Failed port verification on {port_map=}",
                )

        # All good!
        job.started_at = func.now()
        await db.refresh(job)


async def _mark_instance_verified(
    db: AsyncSession, instance: Instance, launch_config: LaunchConfig
):
    # Can't do this via the instance attrs directly, circular dependency :/
    await db.execute(
        text(
            "UPDATE instances SET verified = true, verification_error = null, last_verified_at = now() WHERE instance_id = :instance_id"
        ),
        {"instance_id": instance.instance_id},
    )

    await db.commit()
    await db.refresh(launch_config)
    instance_logger(instance, event=LifecycleEvent.INSTANCE_VERIFY).success(
        f"instance verified: {instance.instance_id} (chute {instance.chute_id})"
    )


async def _build_launch_config_verified_response(
    db: AsyncSession,
    instance: Instance,
    launch_config: LaunchConfig,
    request: Request,
):
    _require_secure_source_delivery(instance.chute)
    return_value = {
        "chute_id": launch_config.chute_id,
        "instance_id": instance.instance_id,
        "verified_at": launch_config.verified_at.isoformat(),
        "code": instance.chute.code,
        "fs_key": generate_fs_key(launch_config),
    }
    if instance.chute.encrypted_fs:
        return_value["efs"] = True
    if instance.job:
        job_token = create_job_jwt(instance.job.job_id)
        return_value.update(
            {
                "job_id": instance.job.job_id,
                "job_method": instance.job.method,
                "job_data": instance.job.job_args,
                "job_status_url": f"https://api.{settings.base_domain}/jobs/{instance.job.job_id}?token={job_token}",
            }
        )

    # Secrets, e.g. private HF tokens etc.
    secrets = (
        (
            await db.execute(
                select(Secret).where(Secret.purpose == launch_config.chute_id)
            )
        )
        .unique()
        .scalars()
        .all()
    )
    return_value["secrets"] = {}
    if secrets:
        for secret in secrets:
            value = await decrypt_secret(secret.value)
            return_value["secrets"][secret.key] = value

    return_value["secrets"]["PYTHONDONTWRITEBYTECODE"] = "1"
    return_value["secrets"]["SGLANG_DISABLE_CUDNN_CHECK"] = "1"
    # if semcomp(instance.chutes_version or "0.0.0", "0.5.11") >= 0:
    #    return_value["secrets"]["HF_HUB_DISABLE_XET"] = "1"
    #    return_value["secrets"]["HF_HUB_ENABLE_HF_TRANSFER"] = "1"
    return_value["activation_url"] = (
        f"{(settings.launch_config_base_url or f'https://api.{settings.base_domain}').rstrip('/')}"
        f"/instances/launch_config/{launch_config.config_id}/activate"
    )
    if launch_config.storage_session_exchange_allowed:
        from api.storage.launch_sessions import issue_launch_storage_session

        storage_config_id = launch_config.config_id
        storage_instance_id = instance.instance_id
        try:
            launch_context, storage_session = await issue_launch_storage_session(
                db,
                storage_config_id,
                request,
            )
        except Exception as exc:
            await db.rollback()
            await db.execute(
                text(
                    "UPDATE launch_configs "
                    "SET failed_at = NOW(), verification_error = :reason "
                    "WHERE config_id = :config_id"
                ),
                {
                    "config_id": storage_config_id,
                    "reason": f"Launch-bound ChuteFS session issuance failed: {exc}"[
                        :2000
                    ],
                },
            )
            await db.execute(
                text(
                    "UPDATE instances SET verified = false, active = false "
                    "WHERE instance_id = :instance_id"
                ),
                {"instance_id": storage_instance_id},
            )
            await db.commit()
            raise
        return_value["launch_context"] = launch_context.model_dump()
        return_value["storage_session"] = storage_session.model_dump()

    return return_value


@router.put("/launch_config/{config_id}")
async def verify_launch_config_instance(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    # Backwards compatibility for older client libs; delegates to graval endpoint.
    # TODO: Remove this once all chutes are upgraded to 0.6.0 or later
    return await verify_graval_launch_config_instance(
        config_id, request, db, authorization
    )


@router.put("/launch_config/{config_id}/graval")
async def verify_graval_launch_config_instance(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    """Verify Graval launch config instance by validating PoVW proof and symmetric key usage."""
    token = authorization.strip().split(" ")[-1]
    launch_config = await load_launch_config_from_jwt(
        db, config_id, token, allow_retrieved=True
    )

    _validate_launch_config_not_expired(launch_config)

    # Check decryption time.
    now = (await db.scalar(select(func.now()))).replace(tzinfo=None)
    start = launch_config.retrieved_at.replace(tzinfo=None)
    query = (
        select(Instance)
        .where(Instance.config_id == launch_config.config_id)
        .options(
            joinedload(Instance.nodes),
            joinedload(Instance.job),
            joinedload(Instance.chute),
        )
    )
    instance = (await db.execute(query)).unique().scalar_one_or_none()
    if not instance:
        logger.error(
            f"Instance associated with lauch config has been deleted! {launch_config.config_id=}"
        )
        launch_config.failed_at = func.now()
        launch_config.verification_error = "Instance was deleted"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instance disappeared (did you update gepetto reconcile?)",
        )
    _reject_cpu_tee_on_legacy_endpoint(instance)
    # Cache GPU info while nodes are eagerly loaded (before any commit/refresh expires them).
    _gpu_count = len(instance.nodes) if instance.nodes else None
    _gpu_type = instance.nodes[0].gpu_identifier if instance.nodes else None

    estimate = SUPPORTED_GPUS[instance.nodes[0].gpu_identifier]["graval"]["estimate"]
    max_duration = estimate * 2.15
    if (delta := (now - start).total_seconds()) >= max_duration:
        reason = (
            f"PoVW encrypted response for {config_id=} and {instance.instance_id=} "
            f"{instance.miner_hotkey=} took {delta} seconds, exceeding maximum estimate of {max_duration}"
        )
        logger.error(reason)
        launch_config.failed_at = func.now()
        launch_config.verification_error = reason
        await db.delete(instance)
        await db.execute(
            text(
                "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
            ),
            {"instance_id": instance.instance_id, "reason": reason},
        )
        await db.commit()
        asyncio.create_task(
            notify_deleted(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=launch_config.verification_error,
        )

    # Valid response cipher?
    response_body = await request.json()
    try:
        ciphertext = response_body["response"]
        iv = response_body.get("iv")  # Only used for legacy AES-CBC
        # PoVW always uses legacy AES-CBC with symmetric_key (graval decrypts it client-side)
        response = await asyncio.to_thread(
            decrypt_instance_response, ciphertext, instance, iv, force_legacy=True
        )
        assert (
            response
            == f"secret is {launch_config.config_id} {launch_config.seed}".encode()
        )
    except Exception as exc:
        reason = (
            f"PoVW encrypted response for {config_id=} and {instance.instance_id=} "
            f"{instance.miner_hotkey=} was invalid: {exc}\n{traceback.format_exc()}"
        )
        logger.error(reason)
        launch_config.failed_at = func.now()
        launch_config.verification_error = reason
        await db.delete(instance)
        await db.execute(
            text(
                "UPDATE instance_audit SET deletion_reason = :reason WHERE instance_id = :instance_id"
            ),
            {"instance_id": instance.instance_id, "reason": reason},
        )
        await db.commit()
        asyncio.create_task(
            notify_deleted(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=launch_config.verification_error,
        )

    # Bind the exact request, chute/job, instance, and node set before network,
    # worker, or socket adapters. The tentative claim is already durable.
    node_idx = random.randint(0, len(instance.nodes) - 1)
    node = instance.nodes[node_idx]
    try:
        work_product = response_body["proof"][node.uuid]["work_product"]
    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Graval proof for selected GPU.",
        ) from exc
    claim_snapshot = _claim_lineage_snapshot(
        launch_config, instance, list(instance.nodes)
    )
    external_input = _verification_external_input_document(
        launch_config,
        instance,
        list(instance.nodes),
        response_body,
    )
    external_input_sha256 = canonical_sha256(external_input)
    await db.commit()

    proof_error = None
    assert_gpu_external_work_allowed(db, "Graval proof verification")
    try:
        proof_valid = bool(await verify_proof(node, launch_config.seed, work_product))
    except Exception as exc:
        proof_valid = False
        proof_error = str(exc)
    filesystem_hash = await _collect_legacy_filesystem_hash(db, instance, launch_config)
    port_results = await _collect_job_port_results(db, instance)

    launch_config, instance, current_nodes = await _locked_current_claim_lineage(
        db, claim_snapshot
    )
    instance = await _reload_verification_context(db, instance.instance_id)
    current_input = _verification_external_input_document(
        launch_config,
        instance,
        current_nodes,
        response_body,
    )
    if canonical_sha256(current_input) != external_input_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Launch verification authority changed during external work.",
        )

    if not proof_valid:
        reason = (
            f"PoVW proof failed for config_id={config_id} and "
            f"instance_id={instance.instance_id} miner_hotkey={instance.miner_hotkey}: "
            f"{proof_error or 'proof rejected'}"
        )
        launch_config.failed_at = func.now()
        launch_config.verification_error = reason
        await db.delete(instance)
        await db.execute(
            text(
                "UPDATE instance_audit SET deletion_reason = :reason "
                "WHERE instance_id = :instance_id"
            ),
            {"instance_id": instance.instance_id, "reason": reason},
        )
        await db.commit()
        asyncio.create_task(
            notify_deleted(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=reason,
        )

    await _validate_legacy_filesystem(
        db,
        instance,
        launch_config,
        response_body,
        expected_hash=filesystem_hash,
    )

    await _verify_job_ports(db, instance, port_results=port_results)
    # Everything checks out; apply external results only to the exact CAS rows.
    launch_config.verified_at = func.now()
    await _mark_instance_verified(db, instance, launch_config)
    return_value = await _build_launch_config_verified_response(
        db, instance, launch_config, request
    )

    await db.refresh(instance)
    asyncio.create_task(
        notify_verified(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
    )
    return return_value


@router.put("/launch_config/{config_id}/tee")
async def verify_tee_launch_config_instance(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
):
    """Verify TEE launch config instance by validating symmetric key usage via dummy ports."""
    token = authorization.strip().split(" ")[-1]
    launch_config = await load_launch_config_from_jwt(
        db, config_id, token, allow_retrieved=True
    )

    _validate_launch_config_not_expired(launch_config)

    # Load instance with relationships
    query = (
        select(Instance)
        .where(Instance.config_id == launch_config.config_id)
        .options(
            joinedload(Instance.nodes),
            joinedload(Instance.job),
            joinedload(Instance.chute),
        )
    )
    instance = (await db.execute(query)).unique().scalar_one_or_none()
    if not instance:
        logger.error(
            f"Instance associated with launch config has been deleted! {launch_config.config_id=}"
        )
        launch_config.failed_at = func.now()
        launch_config.verification_error = "Instance was deleted"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instance disappeared (did you update gepetto reconcile?)",
        )

    # Cache GPU info while nodes are eagerly loaded (before any commit/refresh expires them).
    _gpu_count = len(instance.nodes) if instance.nodes else None
    _gpu_type = instance.nodes[0].gpu_identifier if instance.nodes else None

    # CPU-TEE: this response carries the chute code + decrypted secrets, so bind it to the attested
    # TD. Only the in-TEE key completes the mTLS handshake against the pinned attested_cert; an
    # operator with just the launch JWT cannot pull them. Fail closed (no-op for GPU-TEE).
    await require_attested_client_cert(db, request, instance)

    # TEE instances skip PoVW; legacy job port probes are still sockets and
    # must run after the exact claim is durable and every lifecycle lock is released.
    tee_response_document = {"operation": "tee-launch-verification"}
    claim_snapshot = _claim_lineage_snapshot(
        launch_config, instance, list(instance.nodes)
    )
    external_input_sha256 = canonical_sha256(
        _verification_external_input_document(
            launch_config,
            instance,
            list(instance.nodes),
            tee_response_document,
        )
    )
    await db.commit()
    port_results = await _collect_job_port_results(db, instance)

    launch_config, instance, current_nodes = await _locked_current_claim_lineage(
        db, claim_snapshot
    )
    instance = await _reload_verification_context(db, instance.instance_id)
    if (
        canonical_sha256(
            _verification_external_input_document(
                launch_config,
                instance,
                current_nodes,
                tee_response_document,
            )
        )
        != external_input_sha256
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="TEE launch verification authority changed during socket checks.",
        )

    await _verify_job_ports(db, instance, port_results=port_results)
    launch_config.verified_at = func.now()
    await _mark_instance_verified(db, instance, launch_config)
    return_value = await _build_launch_config_verified_response(
        db, instance, launch_config, request
    )

    await db.refresh(instance)
    asyncio.create_task(
        notify_verified(instance, gpu_count=_gpu_count, gpu_type=_gpu_type)
    )
    return return_value


@router.get("/nonce")
async def get_instance_nonce(request: Request):
    """
    Generate a nonce for TEE instance verification.

    This endpoint is called by chute instances during TEE verification (Phase 1).
    The nonce is used to bind the attestation evidence to this specific verification request.
    """
    try:
        server_ip = request.state.client_ip
        nonce_info = await create_nonce(
            server_ip, purpose=NoncePurpose.INSTANCE_VERIFICATION
        )

        # Return just the nonce string as JSON (library expects this format)
        # The library will use this nonce in the X-Chutes-Nonce header
        return nonce_info["nonce"]
    except Exception as e:
        logger.error(f"Failed to generate instance nonce: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate nonce",
        )


@router.get("/token_check")
async def get_token(salt: str = None, request: Request = None):
    origin_ip = request.state.client_ip
    return {"token": generate_ip_token(origin_ip, extra_salt=salt)}


@router.get("/{instance_id}/evidence", response_model=TeeInstanceEvidence)
async def get_tee_instance_evidence(
    instance_id: str,
    nonce: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(purpose="chutes")),
    _: None = Depends(rate_limit("tee_evidence", 60)),
):
    """
    Get TEE evidence for a specific instance (TDX quote, GPU evidence, certificate).

    Args:
        instance_id: Instance ID
        nonce: User-provided nonce (64 hex characters, 32 bytes)

    Returns:
        TeeInstanceEvidence with quote, gpu_evidence, and certificate

    Raises:
        404: Instance not found
        400: Invalid nonce format or instance not TEE-enabled
        403: User cannot access instance
        429: Rate limit exceeded
        500: Server attestation failures
    """
    # Load instance with chute for authorization check
    instance = (
        (
            await db.execute(
                select(Instance)
                .where(Instance.instance_id == instance_id)
                .options(joinedload(Instance.chute))
            )
        )
        .unique()
        .scalar_one_or_none()
    )

    if not instance:
        raise InstanceNotFoundError(instance_id)

    # Check authorization: user must own chute, have it shared, or chute must be public
    if (
        instance.chute.user_id != current_user.user_id
        and not await is_shared(instance.chute.chute_id, current_user.user_id)
        and not instance.chute.public
    ):
        if not subnet_role_accessible(instance.chute, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this instance",
            )

    try:
        evidence = await get_instance_evidence(db, instance_id, nonce)
        return evidence
    except (InstanceNotFoundError, ChuteNotTeeError, NonceError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except GetEvidenceError as e:
        logger.error(f"Failed to get evidence for instance {instance_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Attestation service unavailable. The attestation proxy could not be reached or returned an error.",
        )


@router.get("/{instance_id}/logs")
async def stream_logs(
    instance_id: str,
    request: Request,
    backfill: Optional[int] = 100,
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    current_user: User = Depends(get_current_user(purpose="logs")),
):
    """
    Fetch raw kubernetes pod logs.

    NOTE: These are pod logs, not request data/etc., so it will never
    include prompts, responses, etc. Used for troubleshooting and checking
    status of warmup, etc.
    """
    # Load and authorize in a short-lived session, then snapshot the scalar stream inputs.
    # A request-scoped yield dependency would otherwise retain its transaction until the
    # StreamingResponse finishes, leaving a connection idle in transaction for the full stream.
    async with get_session(readonly=True) as session:
        instance = (
            (
                await session.execute(
                    select(Instance)
                    .where(Instance.instance_id == instance_id)
                    .options(joinedload(Instance.chute))
                )
            )
            .unique()
            .scalar_one_or_none()
        )
        if not instance:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Instance not found.",
            )
        if not current_user.has_role(Permissioning.chutes_support):
            if (
                instance.chute.user_id != current_user.user_id
                and not await is_shared(instance.chute.chute_id, current_user.user_id)
            ) or instance.chute.public:
                if not subnet_role_accessible(instance.chute, current_user, admin=True):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="You may only view logs for your own (private) chutes.",
                    )
        if not 0 <= backfill <= 10000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="`backfill` must be between 0 and 10000 (lines of logs)",
            )
        host = instance.host
        miner_hotkey = instance.miner_hotkey
        port_mappings = list(instance.port_mappings or [])

    async def _stream():
        log_port = next(p for p in port_mappings if p["internal_port"] == 8001)[
            "external_port"
        ]
        # Build a temporary client for the log port (always plain HTTP, even for v4/TLS instances).
        import httpx as _httpx

        client = _httpx.AsyncClient(
            base_url=f"http://{host}:{log_port}",
            timeout=_httpx.Timeout(connect=10.0, read=None, write=30.0, pool=10.0),
        )

        headers, _ = miner_client.sign_request(miner_hotkey, purpose="chutes")
        try:
            async with client.stream(
                "GET",
                "/logs/stream",
                headers=headers,
                params={"backfill": str(backfill)},
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk
        finally:
            await client.aclose()

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{chute_id}/{instance_id}/disable")
async def disable_instance_endpoint(
    chute_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="instances", registered_to=settings.netuid)
    ),
):
    instance = await get_instance_by_chute_and_id(db, instance_id, chute_id, hotkey)
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Instance with {chute_id=} {instance_id=} associated with {hotkey=} not found",
        )
    logger.info(f"INSTANCE DISABLE: {instance_id=} {hotkey=}")
    instance.active = False
    await db.commit()
    await invalidate_instance_cache(chute_id, instance_id=instance_id)
    asyncio.create_task(notify_disabled(instance))
    return {"instance_id": instance_id, "disabled": True}


@router.delete("/{chute_id}/{instance_id}")
async def delete_instance(
    chute_id: str,
    instance_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="instances", registered_to=settings.netuid)
    ),
):
    instance = await get_instance_by_chute_and_id(db, instance_id, chute_id, hotkey)
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Instance with {chute_id=} {instance_id} associated with {hotkey=} not found",
        )
    origin_ip = request.state.client_ip
    instance_logger(
        instance,
        event=LifecycleEvent.INSTANCE_DELETE,
        trigger="miner",
        origin_ip=origin_ip,
    ).info(f"instance deletion initialized: {instance_id} by {hotkey}")

    # Fail the job.
    job = (
        (await db.execute(select(Job).where(Job.instance_id == instance_id)))
        .unique()
        .scalar_one_or_none()
    )
    if job and not job.finished_at:
        job.status = "error"
        job.error_detail = f"Instance was terminated by miner: {hotkey=}"
        job.miner_terminated = True
        job.finished_at = func.now()

    # Bounties are negated if an instance of a public chute is deleted with no other active instances.
    # Additionally, heavily penalize the compute_multiplier:
    # - Public chutes: divide by 10
    # - Private chutes: zero entirely
    negate_bounty = False
    compute_multiplier_penalty = 1.0

    # Check if this is the last active instance
    active_count = (
        await db.execute(
            select(func.count())
            .select_from(Instance)
            .where(
                Instance.chute_id == instance.chute_id,
                Instance.instance_id != instance.instance_id,
                Instance.active.is_(True),
            )
        )
    ).scalar_one()

    # XXX d899b064-d9ae-5612-99e6-413e9136671b (glm5turbo) keeps crashing, and only one b200, so skip penalty.
    if (
        active_count == 0
        and instance.chute_id != "d899b064-d9ae-5612-99e6-413e9136671b"
    ):
        # This is the last instance - apply penalties
        if not instance.billed_to:
            # Public chute: negate bounty and apply 10x penalty
            negate_bounty = True
            compute_multiplier_penalty = 0.1
            logger.warning(
                f"Instance {instance.instance_id=} of {instance.miner_hotkey=} terminated without any other active instances, "
                f"negating bounty and applying 10x compute_multiplier penalty!"
            )
        else:
            # Private chute: zero out compute_multiplier entirely
            compute_multiplier_penalty = 0.0
            logger.warning(
                f"Private instance {instance.instance_id=} of {instance.miner_hotkey=} terminated without any other active instances, "
                f"zeroing compute_multiplier!"
            )

        # Apply penalty to instance_compute_history BEFORE delete (so the delete trigger
        # closes the record with the penalized multiplier already applied).
        # This ensures scoring uses the penalized value, not the original.
        await db.execute(
            text("""
                UPDATE instance_compute_history
                SET compute_multiplier = compute_multiplier * :penalty
                WHERE instance_id = :instance_id
                  AND ended_at IS NULL
            """),
            {"instance_id": instance_id, "penalty": compute_multiplier_penalty},
        )

    # Evict cached SSL context and httpx client for this instance.
    from api.instance.connection import evict_instance_ssl

    evict_instance_ssl(instance_id)

    if instance.config is not None and instance.config.failed_at is None:
        instance.config.completed_at = func.now()
    await db.delete(instance)

    # Update instance audit table.
    params = {"instance_id": instance_id, "penalty": compute_multiplier_penalty}
    sql = """
        UPDATE instance_audit
        SET deletion_reason = 'miner initialized',
            compute_multiplier = CASE
                WHEN :penalty < 1.0 THEN compute_multiplier * :penalty
                ELSE compute_multiplier
            END
    """
    if negate_bounty:
        sql += ", bounty = :bounty"
        params["bounty"] = False
    sql += " WHERE instance_id = :instance_id"
    await db.execute(text(sql), params)

    await db.commit()
    await invalidate_instance_cache(chute_id, instance_id=instance_id)
    await notify_deleted(instance)

    return {"instance_id": instance_id, "deleted": True}
