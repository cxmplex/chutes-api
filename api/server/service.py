"""
Core server management and TDX attestation logic.
"""

import asyncio
import hashlib
import pybase64 as base64
from datetime import datetime, timezone, timedelta
import json
import secrets
from typing import Dict, Any, Optional
from fastapi import HTTPException, Header, Request, status
from loguru import logger
from pydantic import ValidationError
from sqlalchemy import delete, exists, or_, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives import serialization

from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.constants import (
    CHUTEFS_DATA_VOLUME,
    NONCE_HEADER,
    NoncePurpose,
    LUKS_STORAGE_VOLUME,
)
from api.cpu import validate_cpu_benchmark
from api.gpu import SUPPORTED_GPUS
from api.metagraph import MetagraphNode
from bittensor_wallet.keypair import Keypair
from api.node.util import _track_nodes
from api.server.client import TeeServerClient
from api.server.quote import (
    BootTdxQuote,
    TdxQuote,
    build_runtime_quote,
)
from api.server.snp_quote import SnpReport
from api.server.schemas import (
    Server,
    Host,
    HostRegistrationArgs,
    ServerAttestation,
    BootAttestation,
    BootAttestationArgs,
    RuntimeAttestationArgs,
    RuntimeAttestationNonceContext,
    ServerArgs,
    CpuServerRegistrationArgs,
    TeeUpgradeWindow,
    MaintenanceReason,
    SoleSurvivorBlock,
    PreflightResult,
    UpgradeWindowInfo,
    ConfirmMaintenanceResult,
    LuksAttestRequest,
    LuksAttestResult,
    LuksCapabilityContext,
    LuksCapabilityPurpose,
    LuksConfirmRequest,
    LuksConfirmResult,
    BootAttestationNonceContext,
)
from api.server.exceptions import (
    AttestationError,
    GetEvidenceError,
    GpuEvidenceError,
    InvalidCpuBenchmarkError,
    InvalidGpuEvidenceError,
    InvalidQuoteError,
    MeasurementMismatchError,
    NonceError,
    ServerNotFoundError,
    ServerRegistrationError,
    ChuteNotTeeError,
    InstanceNotFoundError,
)
from api.server.util import (
    _track_server,
    _get_vm_cache_config_for_update,
    get_matching_measurement_config,
    generate_nonce,
    get_nonce_expiry_seconds,
    verify_quote,
    verify_gpu_evidence,
    lease_luks_passphrases,
    confirm_luks_generation_leases,
    generate_confirm_nonce,
    generate_luks_quote_nonce,
    encrypt_passphrase,
    decrypt_passphrase,
    get_public_key_hash,
    cert_to_base64_der,
    validate_user_nonce,
)
from api.instance.schemas import Instance, instance_nodes
from api.instance.util import purge_and_notify
from api.chute.schemas import Chute
from api.node.schemas import Node
from sqlalchemy.orm import joinedload
from api.server.schemas import TeeInstanceEvidence
from api.node.schemas import NodeArgs
from api.util import get_signing_message, nonce_is_valid_v2, semcomp


BOOT_LUKS_ALLOWED_VOLUMES = ("storage", "tdx-cache")
STORAGE_LUKS_ALLOWED_VOLUMES = (CHUTEFS_DATA_VOLUME,)
BOOT_NONCE_SIGNATURE_PURPOSE = "boot_luks_nonce"


def _measurement_fingerprints(measurement_config) -> tuple[str, str]:
    """Identity of the exact matched config and complete set used for this trust decision."""
    config_fingerprint = getattr(
        measurement_config, "config_fingerprint", None
    ) or measurement_config_fingerprint(measurement_config)
    trust_set_fingerprint = getattr(measurement_config, "trust_set_fingerprint", None)
    if not trust_set_fingerprint:
        trust_set_fingerprint = measurement_trust_set_fingerprint(settings.tee_measurements)
    return config_fingerprint, trust_set_fingerprint


def _stamp_server_measurement(server: Server, measurement_config) -> tuple[str, str]:
    config_fingerprint, trust_set_fingerprint = _measurement_fingerprints(measurement_config)
    server.version = measurement_config.version
    server.measurement_name = measurement_config.name
    server.measurement_config_fingerprint = config_fingerprint
    server.trust_set_fingerprint = trust_set_fingerprint
    return config_fingerprint, trust_set_fingerprint


async def create_nonce(
    server_ip: str, purpose: NoncePurpose, context: Optional[Dict[str, Any]] = None
) -> Dict[str, str]:
    """
    Create a new attestation nonce using Redis.

    Args:
        server_ip: IP address of the server/instance requesting the nonce
        purpose: Purpose of the nonce (NoncePurpose enum value)

    Returns:
        Dictionary with nonce and expiry info
    """
    nonce = generate_nonce()
    expiry_seconds = get_nonce_expiry_seconds()

    # Store the caller IP, purpose, and any operation-specific identity context together.
    redis_key = f"nonce:{nonce}"
    redis_value = json.dumps({"server_ip": server_ip, "purpose": purpose.value, "context": context})

    await settings.redis_client.setex(redis_key, expiry_seconds, redis_value)

    expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        seconds=expiry_seconds
    )

    logger.info(f"Created nonce: {nonce[:8]}... for server {server_ip} with purpose {purpose}")

    return {"nonce": nonce, "expires_at": expires_at.isoformat()}


async def validate_and_consume_nonce(
    nonce_value: str, server_ip: str, purpose: NoncePurpose
) -> Dict[str, Any]:
    """
    Validate and consume a nonce using Redis.

    Args:
        nonce_value: Nonce to validate
        server_ip: Expected server IP address
        purpose: Expected purpose for the nonce (NoncePurpose enum value)

    Raises:
        NonceError: If nonce is invalid, expired, already used, or purpose/server mismatch
    """
    redis_key = f"nonce:{nonce_value}"

    redis_value = await settings.redis_client.getdel(redis_key)

    if not redis_value:
        raise NonceError("Nonce not found or expired")

    # Parse the stored value
    try:
        stored_data = json.loads(redis_value.decode())
    except (ValueError, AttributeError, json.JSONDecodeError):
        raise NonceError("Invalid nonce format")

    # Every nonce writer (create_nonce) stores a JSON object {server_ip, purpose}. Fail closed on a
    # bare-string (legacy) value or a missing purpose: a purpose-less nonce would skip the
    # purpose check below and could be replayed across different operations.
    if not isinstance(stored_data, dict):
        raise NonceError("Invalid nonce format (missing purpose)")
    stored_server = stored_data.get("server_ip")
    stored_purpose = stored_data.get("purpose")

    # Validate server IP
    if stored_server != server_ip:
        raise NonceError(f"Nonce server mismatch: expected {server_ip}, got {stored_server}")

    # Validate purpose: nonces are purpose-specific and cannot be reused across operations.
    if not stored_purpose or stored_purpose != purpose.value:
        raise NonceError(
            f"Nonce purpose mismatch: expected {purpose.value}, got {stored_purpose}. "
            f"Nonces are purpose-specific and cannot be reused across different operations."
        )

    logger.info(f"Validated and consumed nonce: {nonce_value[:8]}... for purpose {purpose}")
    return stored_data


def validate_request_nonce(purpose: NoncePurpose):
    """
    Create a nonce validator dependency that validates nonces for a specific purpose.

    Args:
        purpose: The expected purpose for the nonce (NoncePurpose enum value)

    Returns:
        A FastAPI dependency function that validates the nonce
    """

    async def _validate_request_nonce(
        request: Request, nonce: str | None = Header(None, alias=NONCE_HEADER)
    ):
        server_ip = request.state.client_ip

        try:
            await validate_and_consume_nonce(nonce, server_ip, purpose)

            return nonce
        except NonceError as e:
            logger.error(f"Request nonce validation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid nonce supplied",
            )

    return _validate_request_nonce


def _registered_cert_hash(server: Server) -> str:
    """Return the persisted attested serving-cert hash, failing closed on incomplete identity."""
    cert_hash = (server.attested_cert_pubkey_hash or "").strip().lower()
    if not server.attested_cert or not cert_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Server has no persisted attested serving certificate.",
        )
    return cert_hash


def _assert_cert_binding(server: Server, expected_cert_hash: str, context_cert_hash: str) -> None:
    stored_cert_hash = _registered_cert_hash(server)
    supplied_cert_hash = (expected_cert_hash or "").strip().lower()
    authorized_cert_hash = (context_cert_hash or "").strip().lower()
    if not (
        secrets.compare_digest(stored_cert_hash, supplied_cert_hash)
        and secrets.compare_digest(stored_cert_hash, authorized_cert_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented certificate does not match the registered attested serving certificate.",
        )


async def issue_boot_attestation_nonce(
    db: AsyncSession,
    server_ip: str,
    server_id: str,
    miner_hotkey: str | None,
    authorization_nonce: str | None,
    signature: str | None,
    expected_cert_hash: str,
) -> Dict[str, str]:
    """Authorize a registered non-storage server before issuing its boot quote nonce."""
    if not miner_hotkey or not authorization_nonce or not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Miner hotkey, authorization nonce, and signature are required.",
        )
    if "." not in authorization_nonce or not nonce_is_valid_v2(authorization_nonce):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization nonce must be a fresh '{timestamp}.{random}' value.",
        )

    # Ownership and role are checked before any quote nonce is created. A miner naming another
    # miner's server receives the same not-found result as an unknown server.
    server = await check_server_ownership(db, server_id, miner_hotkey)
    if not server.is_tee:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Boot attestation nonce requires a registered TEE server.",
        )
    if server.storage_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Storage-role servers must use the storage LUKS capability.",
        )
    if server.ip != server_ip:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Boot attestation nonce request did not originate from the registered server.",
        )
    _assert_cert_binding(server, expected_cert_hash, expected_cert_hash)

    signature_purpose = (
        f"{BOOT_NONCE_SIGNATURE_PURPOSE}:{server.server_id}:"
        f"{server.attested_cert_pubkey_hash.lower()}"
    )
    signing_message = get_signing_message(
        miner_hotkey,
        authorization_nonce,
        payload_str=None,
        purpose=signature_purpose,
    )
    try:
        signature_bytes = bytes.fromhex(signature.removeprefix("0x"))
        if not Keypair(ss58_address=miner_hotkey).verify(signing_message, signature_bytes):
            raise ValueError("signature verification failed")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid miner signature for boot nonce authorization.",
        ) from exc

    # The authorization itself is one-use, so replaying a valid signed GET cannot mint more quote
    # nonces. Consume only after ownership, cert, and signature verification.
    try:
        claimed = await settings.redis_client.set(
            f"luks_boot_authorization:{miner_hotkey}:{authorization_nonce}",
            "1",
            nx=True,
            ex=get_nonce_expiry_seconds(),
        )
    except Exception as exc:
        logger.warning(f"Boot nonce authorization cache unavailable: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to validate one-use boot authorization.",
        ) from exc
    if not claimed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Boot nonce authorization has already been used.",
        )

    context = BootAttestationNonceContext(
        server_id=server.server_id,
        miner_hotkey=server.miner_hotkey,
        vm_name=server.name,
        cert_hash=server.attested_cert_pubkey_hash.lower(),
        storage_role=False,
        allowed_volumes=list(BOOT_LUKS_ALLOWED_VOLUMES),
    )
    return await create_nonce(
        server_ip,
        purpose=NoncePurpose.BOOT,
        context=context.model_dump(mode="json"),
    )


async def require_boot_attestation_nonce(
    request: Request, nonce: str | None = Header(None, alias=NONCE_HEADER)
) -> tuple[str, BootAttestationNonceContext]:
    """Consume a boot nonce and return its signature-authorized registered-server context."""
    if not nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Boot attestation nonce is required.",
        )
    try:
        stored_data = await validate_and_consume_nonce(
            nonce, request.state.client_ip, NoncePurpose.BOOT
        )
        context = BootAttestationNonceContext.model_validate(stored_data.get("context"))
    except (NonceError, ValidationError, TypeError) as exc:
        logger.warning(f"Invalid boot attestation nonce context: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid boot attestation nonce.",
        ) from exc
    return nonce, context


async def require_luks_quote_nonce(
    quote_nonce: str | None = Header(None, alias="X-Quote-Nonce"),
) -> tuple[str, LuksCapabilityContext]:
    """
    FastAPI dependency for POST /luks/attest (new VMs, version >= 1.3.0).

    The nonce is the Redis lookup key; its value is the immutable registered-server,
    certificate, measurement, role, and volume context created by boot attestation or
    signed storage self-registration.
    """
    if not quote_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Quote nonce (X-Quote-Nonce) is required",
        )
    redis_key = f"luks_quote_nonce:{quote_nonce}"
    stored = await settings.redis_client.getdel(redis_key)
    if not stored:
        logger.warning("LUKS quote capability not found, expired, or already consumed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Quote nonce not found or expired",
        )
    try:
        context = LuksCapabilityContext.model_validate_json(stored)
    except (ValidationError, ValueError, TypeError) as exc:
        logger.warning(f"Malformed LUKS quote capability: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid quote capability",
        ) from exc
    if context.issued_volumes is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid quote capability stage",
        )
    return quote_nonce, context


async def require_confirm_nonce(
    confirm_nonce: str | None = Header(None, alias="X-Confirm-Nonce"),
) -> LuksCapabilityContext:
    """
    FastAPI dependency for POST /luks/confirm.

    Return the exact server/volume/generation context issued by /luks/attest.

    The capability remains readable for its short TTL so an exact confirmation is idempotently
    queryable if the success response is dropped. Replays cannot select another generation or lease.
    """
    if not confirm_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Confirm nonce (X-Confirm-Nonce) is required",
        )
    redis_key = f"luks_confirm_nonce:{confirm_nonce}"
    stored = await settings.redis_client.get(redis_key)
    if not stored:
        logger.warning("LUKS confirm capability not found or expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Confirm nonce not found or expired",
        )
    try:
        context = LuksCapabilityContext.model_validate_json(stored)
    except (ValidationError, ValueError, TypeError) as exc:
        logger.warning(f"Malformed LUKS confirm capability: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid confirm capability",
        ) from exc
    if (
        context.issued_volumes is None
        or context.issued_generations is None
        or context.issued_lease_ids is None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid confirm capability stage",
        )
    return context


def validate_gpus_for_measurements(quote: TdxQuote, gpus: list[NodeArgs]) -> None:
    """
    Validate that the provided GPUs match the expected GPUs for this measurement configuration.

    Looks up the measurement configuration using the quote's RTMR0.

    Args:
        quote: Verified TDX quote (must have been verified via verify_quote)
        gpus: List of GPU nodes being registered

    Raises:
        MeasurementMismatchError: If GPUs don't match measurement configuration expectations
    """
    # Look up measurement configuration by full MRTD + RTMRs (same as verify_measurements)
    measurement_config = get_matching_measurement_config(quote)

    # Extract GPU identifiers
    provided_gpu_ids = {gpu.gpu_identifier.lower() for gpu in gpus}
    expected_gpu_ids = set(measurement_config.expected_gpus)

    # Check that all provided GPUs are in expected list
    unexpected_gpus = provided_gpu_ids - expected_gpu_ids
    if unexpected_gpus:
        raise MeasurementMismatchError(
            f"GPU mismatch for measurement config '{measurement_config.name}': "
            f"Expected GPUs {expected_gpu_ids}, but got {unexpected_gpus}"
        )

    # Check GPU count if specified
    if measurement_config.gpu_count and len(gpus) != measurement_config.gpu_count:
        raise MeasurementMismatchError(
            f"GPU count mismatch for measurement config '{measurement_config.name}': "
            f"Expected {measurement_config.gpu_count} GPUs, but got {len(gpus)}"
        )

    logger.info(
        f"GPU validation passed for measurement config '{measurement_config.name}': "
        f"{len(gpus)} GPUs of types {provided_gpu_ids}"
    )


async def _registered_boot_server(
    db: AsyncSession,
    server_ip: str,
    args: BootAttestationArgs,
    context: BootAttestationNonceContext,
    expected_cert_hash: str,
) -> Server:
    """Revalidate every identity field captured before boot nonce issuance."""
    if context.purpose != "boot_attestation":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Nonce is not authorized for boot attestation.",
        )
    if args.server_id != context.server_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Boot request server does not match the authorized nonce.",
        )
    if context.storage_role or tuple(context.allowed_volumes) != BOOT_LUKS_ALLOWED_VOLUMES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Boot nonce has an invalid LUKS role or volume namespace.",
        )

    server = await db.get(Server, context.server_id)
    if server is None:
        raise ServerNotFoundError(context.server_id)
    if (
        server.miner_hotkey != context.miner_hotkey
        or server.name != context.vm_name
        or not server.is_tee
        or server.storage_role
        or server.ip != server_ip
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registered server identity changed after nonce issuance.",
        )
    _assert_cert_binding(server, expected_cert_hash, context.cert_hash)
    return server


def _validate_boot_measurement(server: Server, measurement_config) -> None:
    """Reject measurements whose compute/storage role cannot authorize boot LUKS keys."""
    measurement_name = measurement_config.name or ""
    if measurement_name.startswith("storage-"):
        raise MeasurementMismatchError(
            "Storage measurements cannot authorize a boot LUKS capability."
        )
    gpu_count = measurement_config.gpu_count
    if server.compute_type == "cpu" and gpu_count != 0:
        raise MeasurementMismatchError(
            "CPU server boot attestation requires a CPU-only measurement."
        )
    if server.compute_type != "cpu" and gpu_count == 0:
        raise MeasurementMismatchError(
            "GPU server boot attestation cannot use a CPU-only measurement."
        )
    measurement_tee_type = (getattr(measurement_config, "tee_type", None) or "tdx").lower()
    server_tee_type = (server.tee_type or "tdx").lower()
    if measurement_tee_type != server_tee_type:
        raise MeasurementMismatchError(
            "Boot measurement TEE type does not match the registered server."
        )


def _luks_capability_for_measurement(
    server: Server,
    measurement_config,
    purpose: LuksCapabilityPurpose,
) -> LuksCapabilityContext:
    config_fingerprint, trust_set_fingerprint = _measurement_fingerprints(measurement_config)
    allowed_volumes = (
        STORAGE_LUKS_ALLOWED_VOLUMES
        if purpose == LuksCapabilityPurpose.STORAGE
        else BOOT_LUKS_ALLOWED_VOLUMES
    )
    return LuksCapabilityContext(
        purpose=purpose,
        server_id=server.server_id,
        miner_hotkey=server.miner_hotkey,
        vm_name=server.name,
        cert_hash=_registered_cert_hash(server),
        measurement_name=measurement_config.name,
        measurement_version=measurement_config.version,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
        tee_type=(getattr(measurement_config, "tee_type", None) or "tdx").lower(),
        storage_role=bool(server.storage_role),
        allowed_volumes=list(allowed_volumes),
    )


async def process_boot_attestation(
    db: AsyncSession,
    server_ip: str,
    args: BootAttestationArgs,
    nonce: str,
    nonce_context: BootAttestationNonceContext,
    expected_cert_hash: str,
) -> str:
    """
    Process a boot attestation request.

    Args:
        db: Database session
        server_ip: Server IP address
        args: Boot attestation arguments naming the registered server_id
        nonce: Validated, single-use quote nonce
        nonce_context: Signature-authorized server identity captured at nonce issuance
        expected_cert_hash: Expected certificate hash

    Returns:
        A one-use, exact-identity LUKS quote capability.

    Raises:
        NonceError: If nonce validation fails
        InvalidQuoteError: If quote is invalid
        MeasurementMismatchError: If measurements don't match
    """
    server = await _registered_boot_server(db, server_ip, args, nonce_context, expected_cert_hash)
    logger.info(
        f"Processing boot attestation for server {server.server_id} "
        f"(miner: {server.miner_hotkey}, IP: {server_ip})"
    )

    # Parse and verify quote
    try:  # Verify quote signature
        quote = BootTdxQuote.from_base64(args.quote)
        verification_result = await verify_quote(quote, nonce, expected_cert_hash)
        revocation_status = dict(getattr(verification_result, "revocation_status", {}) or {})

        measurement_config = get_matching_measurement_config(quote)
        _validate_boot_measurement(server, measurement_config)
        config_fingerprint, trust_set_fingerprint = _measurement_fingerprints(measurement_config)

        minimum_version = settings.tee_minimum_boot_version
        if semcomp(measurement_config.version, minimum_version) < 0:
            logger.warning(
                f"Boot attestation rejected: VM version {measurement_config.version} "
                f"is outdated (minimum: {minimum_version}). Please upgrade to the latest VM version."
            )
            raise MeasurementMismatchError(
                f"VM version {measurement_config.version} is no longer accepted for boot attestation. "
                f"Please upgrade to the latest VM version ({minimum_version})."
            )

        # Create boot attestation record
        boot_attestation = BootAttestation(
            quote_data=args.quote,
            server_ip=server_ip,
            miner_hotkey=server.miner_hotkey,
            vm_name=server.name,
            measurement_version=measurement_config.version,
            measurement_name=measurement_config.name,
            measurement_config_fingerprint=config_fingerprint,
            trust_set_fingerprint=trust_set_fingerprint,
            revocation_status=revocation_status,
            created_at=func.now(),
            verified_at=func.now(),
        )
        server.attestation_revocation_status = revocation_status

        db.add(boot_attestation)
        await db.commit()
        await db.refresh(boot_attestation)

        logger.success(f"Boot attestation successful: {boot_attestation.attestation_id}")

        await _handle_boot_version_update(
            db,
            server.miner_hotkey,
            server.name,
            measurement_config.version,
            measurement_config.name,
            config_fingerprint,
            trust_set_fingerprint,
        )

        capability = _luks_capability_for_measurement(
            server, measurement_config, LuksCapabilityPurpose.BOOT
        )
        return await generate_luks_quote_nonce(capability)

    except (InvalidQuoteError, MeasurementMismatchError) as e:
        # Create failed attestation record; set measurement_version if quote matched a config
        measurement_version = None
        measurement_name = None
        try:
            quote = BootTdxQuote.from_base64(args.quote)
            measurement_config = get_matching_measurement_config(quote)
            measurement_version = measurement_config.version
            measurement_name = measurement_config.name
        except (InvalidQuoteError, MeasurementMismatchError):
            pass
        if measurement_version is None:
            logger.warning(
                "Boot attestation failed with no matching measurement config (measurement_version will be NULL). "
            )
        boot_attestation = BootAttestation(
            quote_data=args.quote,
            server_ip=server_ip,
            miner_hotkey=server.miner_hotkey,
            vm_name=server.name,
            verification_error=str(e.detail),
            measurement_version=measurement_version,
            measurement_name=measurement_name,
            created_at=func.now(),
        )

        db.add(boot_attestation)
        await db.commit()

        logger.error(f"Boot attestation failed: {str(e)}")
        raise


async def _handle_boot_version_update(
    db: AsyncSession,
    miner_hotkey: str,
    vm_name: str,
    measurement_version: str,
    measurement_name: str,
    measurement_config_fingerprint_value: str,
    trust_set_fingerprint: str,
) -> None:
    """Update the exact latest boot identity; clear maintenance when its version meets target."""
    try:
        server = await get_server_by_name(db, miner_hotkey, vm_name)
    except ServerNotFoundError:
        return

    server.version = measurement_version
    server.measurement_name = measurement_name
    server.measurement_config_fingerprint = measurement_config_fingerprint_value
    server.trust_set_fingerprint = trust_set_fingerprint

    if server.in_maintenance:
        window = await db.get(TeeUpgradeWindow, server.maintenance_pending_window_id)
        if (
            window is not None
            and semcomp(measurement_version, window.target_measurement_version) >= 0
        ):
            logger.info(
                f"Maintenance complete for server {server.server_id}: "
                f"version {measurement_version} meets target {window.target_measurement_version}"
            )
            server.maintenance_pending_window_id = None
        elif window is not None:
            logger.warning(
                f"Boot attestation for server {server.server_id} has version {measurement_version} "
                f"but target is {window.target_measurement_version}; maintenance not complete"
            )
        else:
            logger.warning(
                f"Server {server.server_id} has stale maintenance_pending_window_id "
                f"pointing to missing window; clearing"
            )
            server.maintenance_pending_window_id = None

    await db.commit()


async def register_server(db: AsyncSession, args: ServerArgs, miner_hotkey: str):
    """
    Register a TEE server: create Server, verify attestation (creating a ServerAttestation
    record on success or failure), then track nodes. ServerAttestation is always inserted
    by verify_server for audit trail.
    """
    try:
        server = await _track_server(
            db, args.id, args.name or args.id, args.host, miner_hotkey, is_tee=True
        )

        is_cpu = args.compute_type == "cpu"

        if not is_cpu:
            # Set the attributes we can't get from pynvml
            for gpu in args.gpus:
                gpu_info = SUPPORTED_GPUS[gpu.gpu_identifier]
                for key in ["processors", "max_threads_per_processor"]:
                    setattr(gpu, key, gpu_info.get(key))

        # Start verification process. For CPU servers (gpus=None) verify_server skips GPU
        # evidence + GPU matching and gathers/persists the CPU benchmark itself.
        measurement_version = await verify_server(
            db, server, miner_hotkey, gpus=None if is_cpu else args.gpus
        )

        if measurement_version is not None:
            server.version = measurement_version
            await db.commit()

        # Track GPU nodes once verified. CPU servers have no GPU Node rows.
        if not is_cpu:
            await _track_nodes(db, miner_hotkey, server.server_id, args.gpus, "0", func.now())

    except AttestationError as e:
        # Clean up orphan server: _track_server committed before verify_server failed.
        await db.rollback()
        await db.execute(delete(Server).where(Server.server_id == args.id))
        await db.commit()
        error_detail = e.detail if hasattr(e, "detail") else str(e)
        logger.error(
            f"Server registration failed - attestation error: name={args.name or args.id} host={args.host} miner_hotkey={miner_hotkey} error={error_detail}"
        )
        raise ServerRegistrationError(f"Server registration failed - {error_detail}")
    except IntegrityError as e:
        await db.rollback()
        # Clean up orphan server when IntegrityError came from _track_nodes.
        # If from _track_server (duplicate server), this is a no-op.
        await db.execute(delete(Server).where(Server.server_id == args.id))
        await db.commit()
        logger.error(
            f"Server registration failed - IntegrityError: name={args.name or args.id} host={args.host} miner_hotkey={miner_hotkey} error={str(e)}"
        )
        raise ServerRegistrationError(
            "Server registration failed - database constraint violation. This may indicate a duplicate server ID, invalid miner configuration, or other database conflict. Please contact support with your server ID and miner hotkey."
        )
    except Exception as e:
        await db.rollback()
        # Clean up orphan server if failure occurred after _track_server.
        await db.execute(delete(Server).where(Server.server_id == args.id))
        await db.commit()
        logger.error(
            f"Unexpected error during server registration: name={args.name or args.id} host={args.host} miner_hotkey={miner_hotkey} error={str(e)}",
            exc_info=True,
        )
        raise ServerRegistrationError(
            "Server registration failed - unexpected error occurred. Please contact support with your server ID and miner hotkey."
        )


def _canonical_infrastructure_provider(provider: Optional[str]) -> str:
    """Normalize the provider names used by measurement manifests."""
    normalized = (provider or "").strip().lower().replace("_", "-")
    if normalized in {"baremetal", "bare-metal"}:
        return "baremetal"
    return normalized


def _expected_gcp_identity(server_id: str) -> Optional[dict]:
    prefix = "gcp-"
    if not server_id.startswith(prefix):
        return None
    instance_id = server_id[len(prefix) :]
    if not instance_id.isdigit():
        return None
    return {"instance_id": int(instance_id)}


def runtime_attestation_context_for_server(
    server: Server,
) -> RuntimeAttestationNonceContext:
    """Build the one accepted runtime identity from current trust and persisted registration."""
    if not server.is_tee:
        raise MeasurementMismatchError("Runtime attestation requires a registered TEE server.")
    measurements = settings.tee_measurements
    trust_set_fingerprint = measurement_trust_set_fingerprint(measurements)
    config = next(
        (
            measurement
            for measurement in measurements
            if measurement.name == server.measurement_name and measurement.version == server.version
        ),
        None,
    )
    if config is None:
        raise MeasurementMismatchError(
            "The server's exact registered measurement is no longer active."
        )
    config_fingerprint = measurement_config_fingerprint(config)
    if (
        server.measurement_config_fingerprint != config_fingerprint
        or server.trust_set_fingerprint != trust_set_fingerprint
    ):
        raise MeasurementMismatchError(
            "The server's registered attestation fingerprints are stale."
        )

    tee_type = (server.tee_type or "tdx").strip().lower()
    if tee_type != config.tee_type.strip().lower():
        raise MeasurementMismatchError(
            "The server's registered TEE type does not match its exact measurement."
        )
    provider = _canonical_infrastructure_provider(config.provider)
    if provider not in {"gcp", "baremetal"}:
        raise MeasurementMismatchError(
            "Runtime attestation requires an exact gcp or bare-metal provider pin."
        )
    canonical_provider = "bare-metal" if provider == "baremetal" else "gcp"
    if canonical_provider == "gcp":
        if server.host_id is not None or _expected_gcp_identity(server.server_id) is None:
            raise MeasurementMismatchError(
                "GCP Model-A runtime identity requires hostless server_id='gcp-<instance id>'."
            )
        deployment_model = "gcp-model-a"
    elif server.host_id is not None:
        deployment_model = "bare-metal-model-b"
    else:
        deployment_model = "bare-metal-direct"

    compute_type = (server.compute_type or "").strip().lower()
    if compute_type not in {"cpu", "gpu"}:
        raise MeasurementMismatchError("Runtime attestation has an invalid compute class.")
    if compute_type == "cpu" and (config.gpu_count != 0 or list(config.expected_gpus or [])):
        raise MeasurementMismatchError("CPU runtime identity matched a GPU-capable measurement.")
    if compute_type == "gpu" and (config.gpu_count or 0) <= 0:
        raise MeasurementMismatchError("GPU runtime identity matched a CPU-only measurement.")

    storage_role = bool(server.storage_role)
    storage_measurement = (config.name or "").startswith("storage-")
    if storage_role != storage_measurement:
        raise MeasurementMismatchError(
            "Runtime storage role does not match the exact measurement prefix."
        )
    if storage_role and (
        compute_type != "cpu"
        or canonical_provider != "bare-metal"
        or deployment_model != "bare-metal-model-b"
    ):
        raise MeasurementMismatchError(
            "Storage runtime identity requires a CPU-only bare-metal Model-B server."
        )

    return RuntimeAttestationNonceContext(
        server_id=server.server_id,
        miner_hotkey=server.miner_hotkey,
        vm_name=server.name,
        cert_hash=_registered_cert_hash(server),
        role="storage" if storage_role else "compute",
        compute_type=compute_type,
        tee_type=tee_type,
        provider=canonical_provider,
        deployment_model=deployment_model,
        host_id=server.host_id,
        measurement_name=config.name,
        measurement_version=config.version,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
    )


async def _validate_cpu_registration_host(
    db: AsyncSession,
    host_id: Optional[str],
    miner_hotkey: str,
    tee_type: str,
    measurement_config,
) -> Optional[Host]:
    """Bind a Model-B TD claim to its enrolled launcher before any capacity mutation."""
    measurement_provider = _canonical_infrastructure_provider(
        getattr(measurement_config, "provider", None)
    )
    if not host_id:
        if measurement_provider == "gcp":
            return None
        raise ServerRegistrationError(
            "Bare-metal CPU TEE self-registration requires the enrolled launcher host_id."
        )

    # A Host row represents the bare-metal Model-B launcher. A GCP Model-A VM is hostless and may
    # never consume a bare-metal host's scheduler slots.
    if measurement_provider != "baremetal":
        raise ServerRegistrationError(
            f"Measurement provider {measurement_provider or '<missing>'} is incompatible "
            f"with bare-metal host {host_id}."
        )

    host = (
        await db.execute(select(Host).where(Host.host_id == host_id).with_for_update())
    ).scalar_one_or_none()
    if host is None:
        raise ServerRegistrationError(f"Host {host_id} is not registered for this CPU TEE server.")
    if host.miner_hotkey != miner_hotkey:
        raise ServerRegistrationError(f"Host {host_id} is registered to a different miner.")

    registered_tee = (host.tee_type or "").strip().lower()
    if registered_tee != tee_type:
        raise ServerRegistrationError(f"Host {host_id} launches {registered_tee}, not {tee_type}.")
    return host


async def register_cpu_server(
    db: AsyncSession,
    server_ip: str,
    args: CpuServerRegistrationArgs,
    miner_hotkey: str,
    nonce: str,
    signature: str,
    expected_cert_hash: str,
    cert_pem: str,
) -> Dict[str, Any]:
    """
    Self-registration for a 1-click CPU TEE server (push attestation model).

    Unlike register_server (which the validator drives by dialing the server's :30443 proxy),
    here the booted server submits its own runtime TDX quote + CPU benchmark over an outbound
    request. The validator verifies:
      1. the owning miner is registered on the subnet and signed this registration,
      2. the TDX quote: report_data == release-bound nonce || sha256(mTLS client cert pubkey), a
         valid Intel signature, and MRTD/RTMRs matching a CPU-only measurement config, and
      3. the CPU benchmark shape (never trusted from the server),
    then upserts a self-registered CPU Server row (idempotent across reboots by server_id) and
    writes a ServerAttestation audit record. Returns a dict for CpuServerRegistrationResponse.
    """
    # 1. Miner must have signed this registration over the single-use attestation nonce and, in
    # production, be registered on the subnet. In dev (skip_metagraph_check) the metagraph
    # membership requirement is bypassed and a metagraph_nodes row is auto-created so the servers
    # foreign key is satisfied. The signature is verified in both cases.
    name = args.name or args.server_id
    storage_role = bool(getattr(args, "storage_role", False))
    if settings.skip_metagraph_check:
        existing_node = await db.get(MetagraphNode, (miner_hotkey, settings.netuid))
        if existing_node is None:
            db.add(
                MetagraphNode(
                    hotkey=miner_hotkey,
                    netuid=settings.netuid,
                    checksum="dev",
                    coldkey=miner_hotkey,
                    node_id=0,
                )
            )
            await db.commit()
            logger.warning(
                f"skip_metagraph_check: auto-created dev metagraph_nodes row for {miner_hotkey}"
            )
    else:
        is_registered = (
            await db.execute(
                select(
                    exists()
                    .where(MetagraphNode.hotkey == miner_hotkey)
                    .where(MetagraphNode.netuid == settings.netuid)
                )
            )
        ).scalar()
        if not is_registered:
            raise ServerRegistrationError(
                f"Miner hotkey {miner_hotkey} is not registered on netuid {settings.netuid}"
            )
    release_target_token = getattr(args, "release_target_token", None)
    registration_purpose = (
        f"{NoncePurpose.CPU_REGISTER.value}:{args.server_id}:{name}:"
        f"{expected_cert_hash.lower()}:{'storage' if storage_role else 'compute'}"
    )
    if release_target_token:
        registration_purpose += (
            f":{hashlib.sha256(release_target_token.encode('utf-8')).hexdigest()}"
        )
    signing_message = get_signing_message(
        miner_hotkey, nonce, payload_str=None, purpose=registration_purpose
    )
    try:
        if not Keypair(ss58_address=miner_hotkey).verify(signing_message, bytes.fromhex(signature)):
            raise ServerRegistrationError("Invalid miner signature for CPU server registration")
    except ServerRegistrationError:
        raise
    except Exception as exc:
        raise ServerRegistrationError(f"Invalid miner signature: {exc}")

    # 2. Verify the runtime attestation (Intel TDX quote or AMD SEV-SNP report) + match a CPU config.
    tee_type = (getattr(args, "tee_type", None) or "tdx").strip().lower()
    quote = build_runtime_quote(
        args.quote,
        tee_type,
        getattr(args, "snp_cert_chain", None),
        getattr(args, "vtpm_quote", None),
    )
    # Logged on every attempt so first-boot platform measurements can be captured and pinned in
    # tee_measurements.yaml (TDX: MRTD/RTMR0-2 alongside the offline RTMR3; SNP: launch measurement).
    if isinstance(quote, SnpReport):
        logger.info(
            f"CPU register SEV-SNP report for server_id={args.server_id}: "
            f"measurement={quote.measurement} policy={hex(quote.policy)} "
            f"reported_tcb={quote.reported_tcb_parts} chip_id={quote.chip_id[:16]}..."
        )
    else:
        logger.info(
            f"CPU register quote measurements for server_id={args.server_id}: "
            f"mrtd={quote.mrtd} rtmr0={quote.rtmrs.get('rtmr0')} rtmr1={quote.rtmrs.get('rtmr1')} "
            f"rtmr2={quote.rtmrs.get('rtmr2')} rtmr3={quote.rtmrs.get('rtmr3')}"
        )
    from api.releases.service import ReleaseError, release_bound_attestation_nonce

    try:
        quote_nonce = release_bound_attestation_nonce(nonce, release_target_token)
    except ReleaseError as exc:
        raise ServerRegistrationError(str(exc)) from exc
    expected_gcp_identity = _expected_gcp_identity(args.server_id)
    verification_result = await verify_quote(
        quote,
        quote_nonce,
        expected_cert_hash,
        expected_gcp_identity=expected_gcp_identity,
    )
    revocation_status = dict(getattr(verification_result, "revocation_status", {}) or {})
    measurement_config = get_matching_measurement_config(quote)
    if (
        _canonical_infrastructure_provider(measurement_config.provider) == "gcp"
        and expected_gcp_identity is None
    ):
        raise MeasurementMismatchError(
            "A GCP attestation must register as server_id='gcp-<signed instance id>'."
        )
    if (measurement_config.gpu_count or 0) != 0:
        raise MeasurementMismatchError(
            "Matched a GPU measurement config; CPU self-registration requires a gpu_count=0 config."
        )
    # The requested role is part of the miner signature above and must also be a capability of the
    # exact measured image. This happens before any registered server row is mutated.
    if storage_role and not (measurement_config.name or "").startswith("storage-"):
        raise MeasurementMismatchError(
            "storage_role registration requires the pinned storage-TD measurement (name 'storage-*'); "
            f"matched '{measurement_config.name}'."
        )
    if not storage_role and (measurement_config.name or "").startswith("storage-"):
        raise MeasurementMismatchError(
            "A storage-TD measurement may register only with storage_role enabled."
        )

    # Model-B host identity affects scheduler capacity and teardown routing. Validate the exact
    # enrolled host owner, TEE type, and bare-metal provider before benchmark/capacity accounting
    # or any Server row mutation. A standalone Model-A registration must omit host_id.
    host_id = (getattr(args, "host_id", None) or "").strip() or None
    await _validate_cpu_registration_host(
        db,
        host_id,
        miner_hotkey,
        tee_type,
        measurement_config,
    )
    release_target = None
    release_target_token_generation = None
    release_target_release = None
    if release_target_token:
        from api.releases.service import (
            ReleaseError,
            resolve_release_target_token,
            validate_release_target_attestation,
        )

        try:
            (
                release_target,
                release_target_token_generation,
                release_target_release,
            ) = await resolve_release_target_token(
                db,
                release_target_token,
                host_id=host_id,
                miner_hotkey=miner_hotkey,
                tee_type=tee_type,
            )
            validate_release_target_attestation(
                release_target,
                release_target_release,
                storage_role=storage_role,
                measurement_name=measurement_config.name,
                tee_type=tee_type,
            )
        except ReleaseError as exc:
            raise ServerRegistrationError(str(exc)) from exc

    # 3. Validate the benchmark shape (the validator never trusts the raw value).
    try:
        benchmark = validate_cpu_benchmark(args.benchmark)
    except ValueError as benchmark_error:
        raise InvalidCpuBenchmarkError(f"Invalid CPU benchmark: {benchmark_error}")

    # 4. Upsert the self-registered CPU server (idempotent across reboots by server_id). Lock an
    # existing identity before inspecting key-custody state so certificate replacement cannot race
    # a generation allocation/confirmation (both paths lock Server, then VmCacheConfig).
    server_result = await db.execute(
        select(Server).where(Server.server_id == args.server_id).with_for_update()
    )
    server = server_result.scalar_one_or_none()
    if server is not None and server.miner_hotkey != miner_hotkey:
        raise ServerRegistrationError(
            f"Server {args.server_id} is already registered to a different miner."
        )
    # Model B: several per-chute TDs run on ONE L0 host and self-register from that host's single
    # public IP -- they are distinguished by their DNAT'd external_ports, not by IP. A co-tenant
    # already registered under the SAME host_id is therefore expected and allowed; only a genuine
    # cross-host IP collision (a server with no/different host_id claiming this IP) is rejected.
    ip_owners = (
        (
            await db.execute(
                select(Server).where(Server.ip == server_ip, Server.server_id != args.server_id)
            )
        )
        .scalars()
        .all()
    )
    conflict = next(
        (owner for owner in ip_owners if not (host_id and owner.host_id == host_id)),
        None,
    )
    if conflict is not None:
        raise ServerRegistrationError(
            f"IP {server_ip} is already registered to server {conflict.server_id}."
        )

    if server is None:
        server = Server(server_id=args.server_id, netuid=settings.netuid)
        db.add(server)
    server.name = name
    server.ip = server_ip
    server.miner_hotkey = miner_hotkey
    server.is_tee = True
    server.self_registered = True
    server.compute_type = "cpu"
    server.tee_type = tee_type
    # Model B: stamp the launching L0 host (per-host capacity accounting + teardown), if provided.
    server.host_id = host_id
    # Model B: record the per-TD public host + DNAT external ports so the scheduler advertises the
    # externally reachable endpoint (public_host:<ext>) when it deploys a chute onto this TD.
    server.external_host = getattr(args, "external_host", None) or None
    server.external_ports = getattr(args, "external_ports", None) or None
    server.cpu_cores = int(benchmark["cpu_cores"])
    server.ram_gb = int(benchmark["ram_gb"])
    server.benchmark_score = float(benchmark["composite_score"])
    server.benchmark = benchmark
    config_fingerprint, trust_set_fingerprint = _stamp_server_measurement(
        server, measurement_config
    )
    server.attestation_revocation_status = revocation_status
    # ChuteFS: the always-on storage TD self-registers with storage_role=True so the CPU scheduler
    # never places user chutes on it and the reconcile loop never reaps it; it advertises durable
    # disk capacity for replica placement. A storage TD is a normal attested CPU server otherwise.
    # storage_role is asserted by the (untrusted) host config volume, so bind it to the dedicated,
    # pinned storage-TD measurement (name 'storage-*'): only the genuine storage image -- whose code
    # is trusted to use the released per-volume key solely for at-rest encryption -- may be a storage
    # node. This prevents a malicious operator from marking an arbitrary CPU-TEE image storage_role to
    # have replicas + per-volume keys released to code that could exfiltrate them.
    server.storage_role = storage_role
    server.disk_total_gb = getattr(args, "disk_total_gb", None)
    server.disk_free_gb = getattr(args, "disk_free_gb", None)
    # Persist the attestation-bound serving cert. Its pubkey hash was just verified against the
    # quote report_data (verify_quote above), so this PEM is the attested TLS identity of the TD.
    # The validator pins it as the instance cacert so the validator<->chute transport is TLS
    # terminated inside the attested TD (the untrusted host cannot MITM/read/tamper it).
    server.attested_cert = cert_pem
    # The pubkey hash was verified against the quote report_data above (expected_cert_hash); persist
    # it so ChuteFS peers presenting this attested mTLS cert map to this server row in O(1).
    server.attested_cert_pubkey_hash = expected_cert_hash
    # Advertised user-attestable reach info (host + attest/provision/ssh/wg ports) for discovery via
    # GET /servers/cpu/{id}/connection. Optional; pure convenience (trust is the client attestation).
    if args.endpoints:
        server.tee_endpoints = args.endpoints

    attestation = ServerAttestation(
        quote_data=args.quote,
        server_id=args.server_id,
        created_at=func.now(),
        verified_at=func.now(),
        measurement_version=measurement_config.version,
        measurement_name=measurement_config.name,
        measurement_config_fingerprint=config_fingerprint,
        trust_set_fingerprint=trust_set_fingerprint,
        revocation_status=revocation_status,
    )
    db.add(attestation)
    await db.flush()
    if (
        release_target is not None
        and release_target_token_generation is not None
        and release_target_release is not None
    ):
        from api.releases.service import ReleaseError, consume_release_target

        try:
            consume_release_target(
                release_target,
                release_target_token_generation,
                server=server,
                attestation=attestation,
                cert_pubkey_hash=expected_cert_hash,
            )
        except ReleaseError as exc:
            raise ServerRegistrationError(str(exc)) from exc
    await db.commit()
    await db.refresh(attestation)

    # Model B: a TD launched by an L0 host has registered -> release that host's in-flight slot count
    # (best-effort; the durable per-host usage is now this Server row's host_id).
    if server.host_id:
        try:
            await settings.redis_client.decr(f"mb:host_inflight:{server.host_id}")
        except Exception:  # noqa: BLE001 - inflight counter is a best-effort hint
            pass

    # ChuteFS: a storage TD then calls POST /{server_id}/luks/attest to obtain its persistent
    # data-volume passphrase. That endpoint is gated on a single-use luks_quote_nonce which, for the
    # validator-dialed GPU flow, is minted in boot attestation. The self-registering storage TD has
    # no boot-attestation step, so its already signature-authorized registration mints a separate
    # storage-only capability after owner, quote, measurement role, and cert persistence all succeed.
    luks_quote_nonce: Optional[str] = None
    if storage_role:
        capability = _luks_capability_for_measurement(
            server, measurement_config, LuksCapabilityPurpose.STORAGE
        )
        luks_quote_nonce = await generate_luks_quote_nonce(capability)

    logger.success(
        f"CPU server self-registered: server_id={args.server_id} ip={server_ip} "
        f"miner={miner_hotkey} score={server.benchmark_score} version={measurement_config.version}"
        + (f" host_id={server.host_id}" if server.host_id else "")
        + (" storage_role=True" if storage_role else "")
    )
    verified_at = attestation.verified_at
    return {
        "server_id": args.server_id,
        "measurement_version": measurement_config.version,
        "measurement_name": measurement_config.name,
        "measurement_config_fingerprint": config_fingerprint,
        "trust_set_fingerprint": trust_set_fingerprint,
        "revocation_status": revocation_status,
        "benchmark_score": float(server.benchmark_score),
        "verified_at": (
            verified_at.isoformat()
            if hasattr(verified_at, "isoformat")
            else datetime.now(timezone.utc).isoformat()
        ),
        "status": "registered",
        "luks_quote_nonce": luks_quote_nonce,
    }


def _sum_disk_gb(disks: Any) -> Optional[int]:
    """Sum the size_gb of a node-agent specs.disk_info() list (non-rotational + rotational), or None.

    specs["disks"] is a list of {name,size_gb,model,rotational,type} dicts (sek8s specs.disk_info()).
    """
    if not isinstance(disks, list):
        return None
    total = 0
    for disk in disks:
        if isinstance(disk, dict) and isinstance(disk.get("size_gb"), (int, float)):
            total += int(disk["size_gb"])
    return total or None


async def register_host(
    db: AsyncSession,
    args: HostRegistrationArgs,
    miner_hotkey: str,
) -> Dict[str, Any]:
    """Model B: register (or refresh) a bare-metal L0 launcher host.

    The host is NOT attested -- it is a launcher only. Authentication (signature over
    "{hotkey}:{nonce}:host_register" with a fresh unix-timestamp nonce + production metagraph
    membership) is enforced by the router's `get_current_user` dependency; this service only
    owns the host-specific logic. The validator records the host + its capacity so the CPU
    scheduler can dispatch per-chute TD launches to it; every launched TD attests itself.
    """
    if not miner_hotkey:
        raise ServerRegistrationError("Missing miner hotkey for host registration")
    capacity = int(args.capacity)
    storage_enabled = bool(getattr(args, "storage_enabled", False))
    if capacity < 0 or capacity > 64:
        raise ServerRegistrationError("Host capacity must be in 0..64.")
    if capacity == 0 and not storage_enabled:
        raise ServerRegistrationError(
            "capacity=0 is valid only for an enrolled ChuteFS storage host."
        )

    # Dev (skip_metagraph_check): auto-create the metagraph row so downstream FK references
    # (self-registered server rows) are satisfied. Prod membership is enforced by the router auth.
    if settings.skip_metagraph_check:
        if await db.get(MetagraphNode, (miner_hotkey, settings.netuid)) is None:
            db.add(
                MetagraphNode(
                    hotkey=miner_hotkey,
                    netuid=settings.netuid,
                    checksum="dev",
                    coldkey=miner_hotkey,
                    node_id=0,
                )
            )
            await db.commit()

    # Upsert the host (idempotent across reboots by host_id; ownership pinned to the first miner).
    host = await db.get(Host, args.host_id)
    if host is not None and host.miner_hotkey != miner_hotkey:
        raise ServerRegistrationError(
            f"Host {args.host_id} is already registered to a different miner."
        )
    if host is None:
        host = Host(host_id=args.host_id, netuid=args.netuid or settings.netuid)
        db.add(host)
    host.name = args.name or args.host_id
    host.miner_hotkey = miner_hotkey
    host.netuid = args.netuid or settings.netuid
    host.tee_type = (args.tee_type or "tdx").strip().lower()
    host.capacity = capacity
    host.storage_enabled = storage_enabled
    host.release_channel = args.release_channel
    host.default_mem = args.default_mem
    host.default_vcpus = args.default_vcpus
    host.external_host = args.external_host or None
    # Hardware inventory (informational; the host is not attested). Denormalize cores/ram for queries.
    specs = args.specs or {}
    host.specs = specs or None
    cpu = specs.get("cpu") or {}
    mem = specs.get("memory") or {}
    host.cpu_cores = cpu.get("physical_cores") or cpu.get("logical_cpus")
    host.ram_gb = mem.get("total_gb")
    # ChuteFS: physical disk inventory so the validator knows how much durable storage this host can
    # back. Reported explicitly by the agent (preferred) or denormalized from the specs disk list.
    host.disk_total_gb = args.disk_total_gb or _sum_disk_gb(specs.get("disks"))
    host.disk_free_gb = args.disk_free_gb
    # L0 image identity (re-netboot update tracking); tolerate older agents that don't report it.
    if getattr(args, "l0_version", None):
        host.l0_version = args.l0_version
    # Resolve desired state before committing this refresh. An active storage-carrying manifest is
    # newer operator intent than stale bootstrap CHUTES_STORAGE_NODE=false, so it reserves the
    # storage TD first and a reconnect can never restore impossible chute capacity.
    from api.releases.service import active_manifest_for_host

    await db.flush()
    manifest = await active_manifest_for_host(
        db,
        host.tee_type,
        args.release_channel,
        host_id=host.host_id,
        miner_hotkey=miner_hotkey,
    )
    if manifest is not None and manifest.storage is not None and not host.storage_enabled:
        host.storage_enabled = True
        host.capacity = max(0, int(host.capacity or 0) - 1)
    await db.commit()
    await db.refresh(host)

    logger.success(
        f"L0 host registered: host_id={host.host_id} miner={miner_hotkey} tee_type={host.tee_type} "
        f"capacity={host.capacity} cpu_cores={host.cpu_cores} ram_gb={host.ram_gb}"
    )
    # Fleet image releases: hand the booting host the active manifest for its configured channel so
    # it converges before any guest launch. Lookup/provenance validation failures MUST fail this
    # response: returning a successful registration with release=None would make a cold canary boot
    # indistinguishable from "no desired release" and could allow bootstrap bytes to launch.
    release = manifest.model_dump() if manifest else None
    return {
        "host_id": host.host_id,
        "capacity": host.capacity,
        "status": "registered",
        "release": release,
    }


async def request_host_image_upgrade(
    db: AsyncSession, host_id: str, miner_hotkey: str
) -> Dict[str, Any]:
    """Model B: tell an online L0 host to refresh its chute guest image (control-channel upgrade_image).

    Authentication (signature over "{hotkey}:{nonce}:host_upgrade", same scheme as registration)
    is enforced by the router's `get_current_user` dependency; this service owns ownership +
    online checks and the dispatch. The host re-fetches the published guest image and tears down
    its running per-chute TDs so the scheduler re-places their chutes onto fresh TDs from the new image.
    Remember to pin the new image's measurement on the validator in lockstep, or the new TDs fail attest.
    """
    from api.agent_channel import is_agent_online, send_agent_command

    if not miner_hotkey:
        raise ServerRegistrationError("Missing miner hotkey for host upgrade")

    host = await db.get(Host, host_id)
    if host is None:
        raise ServerRegistrationError(f"Host {host_id} is not registered")
    if host.miner_hotkey != miner_hotkey:
        raise ServerRegistrationError(f"Host {host_id} belongs to a different miner")
    if not await is_agent_online(host_id):
        raise ServerRegistrationError(
            f"Host {host_id} is not currently online (no control channel)"
        )

    command_id = await send_agent_command(host_id, "upgrade_image", {})
    logger.success(f"Dispatched upgrade_image to host {host_id} (command_id={command_id})")
    return {"host_id": host_id, "command_id": command_id, "status": "dispatched"}


async def request_host_reboot(
    db: AsyncSession,
    host_id: str,
    miner_hotkey: str,
    target_l0_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Model B: tell an online L0 host to REBOOT so it re-netboots into the current L0 squashfs.

    The bare-metal L0 is a RAM-root live appliance: a reboot re-fetches the (freshly published)
    netboot set, so this is how the node-agent + host image itself are updated -- without a provider
    reinstall, so the data disk (ChuteFS volume + staged guest images) survives. Same owning-miner
    auth as the image upgrade. ``target_l0_version`` makes it idempotent: the node-agent skips the
    reboot if it is already running that L0 version. All the host's TDs go down for the ~2-4 min
    re-netboot, so drive this one box at a time.
    """
    from api.agent_channel import is_agent_online, send_agent_command

    if not miner_hotkey:
        raise ServerRegistrationError("Missing miner hotkey for host reboot")

    host = await db.get(Host, host_id)
    if host is None:
        raise ServerRegistrationError(f"Host {host_id} is not registered")
    if host.miner_hotkey != miner_hotkey:
        raise ServerRegistrationError(f"Host {host_id} belongs to a different miner")
    if not await is_agent_online(host_id):
        raise ServerRegistrationError(
            f"Host {host_id} is not currently online (no control channel)"
        )

    command_id = await send_agent_command(
        host_id,
        "reboot",
        {"target_l0_version": target_l0_version} if target_l0_version else {},
    )
    logger.success(
        f"Dispatched reboot to host {host_id} (command_id={command_id} target_l0={target_l0_version})"
    )
    return {"host_id": host_id, "command_id": command_id, "status": "dispatched"}


async def verify_server(
    db: AsyncSession, server: Server, miner_hotkey: str, gpus: Optional[list[NodeArgs]]
) -> Optional[str]:
    """
    Verify server attestation and validate GPUs match measurement configuration.

    For CPU servers (gpus is None) the TDX quote (MRTD + RTMRs) is still verified, but GPU
    evidence verification and GPU-count/expected-GPU matching are skipped. The CPU benchmark
    is read from the attestation response (gathered by the validator, never trusted from the
    miner) and the CPU capacity + composite_score are persisted on the Server.

    Returns the measurement_version string on success, None on failure.
    """
    is_cpu = gpus is None
    failure_reason = ""
    quote = None
    measurement_config = None
    try:
        client = TeeServerClient(server)

        nonce = generate_nonce()
        logger.info(
            f"Verifying server server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} with nonce {nonce}"
        )
        quote, gpu_evidence, cert, benchmark = await client.get_server_evidence(nonce)
        measurement_config = get_matching_measurement_config(quote)
        expected_cert_hash = get_public_key_hash(cert)

        # Verify quote measurements (matches by full MRTD + RTMRs; multiple configs may share RTMR0)
        verification_result = await verify_quote(quote, nonce, expected_cert_hash)
        revocation_status = dict(getattr(verification_result, "revocation_status", {}) or {})
        if is_cpu:
            # CPU server: skip GPU evidence + GPU matching. Validate and persist the benchmark
            # the validator gathered itself from the attestation response.
            try:
                validated_benchmark = validate_cpu_benchmark(benchmark)
            except ValueError as benchmark_error:
                raise InvalidCpuBenchmarkError(f"Invalid CPU benchmark: {benchmark_error}")
            server.compute_type = "cpu"
            server.cpu_cores = int(validated_benchmark["cpu_cores"])
            server.ram_gb = int(validated_benchmark["ram_gb"])
            server.benchmark_score = float(validated_benchmark["composite_score"])
            server.benchmark = validated_benchmark
        else:
            # Verify GPU evidence
            await verify_gpu_evidence(gpu_evidence, nonce)

            # Validate GPUs match measurement configuration
            validate_gpus_for_measurements(quote, gpus)

        # Persist the exact serving identity only after every registration check succeeds. Boot
        # nonce issuance fails closed unless this cert is later presented with live mTLS possession.
        server.attested_cert = cert.public_bytes(serialization.Encoding.PEM).decode()
        server.attested_cert_pubkey_hash = expected_cert_hash.lower()
        config_fingerprint, trust_set_fingerprint = _stamp_server_measurement(
            server, measurement_config
        )
        server.attestation_revocation_status = revocation_status

        logger.success(
            f"Verified server server_id={server.server_id} ip={server.ip} for miner: {miner_hotkey}"
        )

        # Create attestation record (measurement_version for audit trail; server version = latest attestation).
        # Commit here so we have a durable record for this run even if _track_nodes or later steps fail.
        server_attestation = ServerAttestation(
            quote_data=base64.b64encode(quote.raw_bytes).decode("utf-8"),
            server_id=server.server_id,
            created_at=func.now(),
            verified_at=func.now(),
            measurement_version=measurement_config.version,
            measurement_name=measurement_config.name,
            measurement_config_fingerprint=config_fingerprint,
            trust_set_fingerprint=trust_set_fingerprint,
            revocation_status=revocation_status,
        )

        db.add(server_attestation)
        await db.commit()
        await db.refresh(server_attestation)

        return measurement_config.version

    except GetEvidenceError as e:
        failure_reason = "Failed to get attestation evidence."
        logger.error(
            f"Server verification failed - GetEvidenceError: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={e.detail}"
        )
        raise e
    except (InvalidQuoteError, MeasurementMismatchError) as e:
        logger.error(
            f"Server verification failed - quote error: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={e.detail}"
        )
        failure_reason = "Server verification failed: invalid quote"
        raise e
    except InvalidGpuEvidenceError as e:
        logger.error(
            f"Server verification failed - invalid GPU evidence: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={e.detail}"
        )
        failure_reason = "Server verification failed: invalid GPU evidence"
        raise e
    except GpuEvidenceError as e:
        logger.error(
            f"Server verification failed - GPU evidence error: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={e.detail}"
        )
        failure_reason = "Server verification failed: Failed to verify GPU evidence"
        raise e
    except InvalidCpuBenchmarkError as e:
        logger.error(
            f"Server verification failed - invalid CPU benchmark: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={e.detail}"
        )
        failure_reason = "Server verification failed: invalid CPU benchmark"
        raise e
    except Exception as e:
        logger.error(
            f"Unexpected error during server verification: server_id={server.server_id} ip={server.ip} miner_hotkey={miner_hotkey} error={str(e)}"
        )
        failure_reason = "Unexpected error during server verification."
        raise e
    finally:
        if failure_reason:
            measurement_version = measurement_config.version if measurement_config else None
            measurement_name = measurement_config.name if measurement_config else None
            server_attestation = ServerAttestation(
                quote_data=base64.b64encode(quote.raw_bytes).decode("utf-8") if quote else None,
                server_id=server.server_id,
                verification_error=failure_reason,
                created_at=func.now(),
                measurement_version=measurement_version,
                measurement_name=measurement_name,
            )

            try:
                db.add(server_attestation)
                await db.commit()
                await db.refresh(server_attestation)
                logger.info(
                    f"Persisted failed server attestation for server_id={server.server_id} (reason: {failure_reason})"
                )
            except Exception:
                logger.exception(
                    f"Failed to persist failed attestation record for server_id={server.server_id}; "
                    "attestation history will be incomplete",
                    exc_info=True,
                )
                raise


async def check_server_ownership(db: AsyncSession, server_id: str, miner_hotkey: str) -> Server:
    """
    Get a server by ID, ensuring it belongs to the authenticated miner.

    Args:
        db: Database session
        server_id: Server ID
        miner_hotkey: Authenticated miner hotkey

    Returns:
        Server object

    Raises:
        ServerNotFoundError: If server not found or doesn't belong to miner
    """
    query = select(Server).where(Server.server_id == server_id, Server.miner_hotkey == miner_hotkey)

    result = await db.execute(query)
    server = result.scalar_one_or_none()

    if not server:
        raise ServerNotFoundError(server_id)

    return server


async def get_server_by_name(db: AsyncSession, miner_hotkey: str, server_name: str) -> Server:
    """
    Get a server by miner hotkey and VM name (stable identity for API paths).

    Args:
        db: Database session
        miner_hotkey: Miner hotkey (must match authenticated user)
        vm_name: VM name

    Returns:
        Server object

    Raises:
        ServerNotFoundError: If server not found
    """
    query = select(Server).where(Server.miner_hotkey == miner_hotkey, Server.name == server_name)
    result = await db.execute(query)
    server = result.scalar_one_or_none()
    if not server:
        raise ServerNotFoundError(f"{server_name}")
    return server


async def get_server_by_name_or_id(
    db: AsyncSession, miner_hotkey: str, server_name_or_id: str
) -> Server:
    """
    Get a server by miner hotkey and either VM name or server id.

    Args:
        db: Database session
        miner_hotkey: Miner hotkey (must match authenticated user)
        server_name_or_id: VM name or server_id

    Returns:
        Server object

    Raises:
        ServerNotFoundError: If server not found
    """
    query = select(Server).where(
        Server.miner_hotkey == miner_hotkey,
        or_(
            Server.name == server_name_or_id,
            Server.server_id == server_name_or_id,
        ),
    )
    result = await db.execute(query)
    server = result.scalar_one_or_none()
    if not server:
        raise ServerNotFoundError(server_name_or_id)
    return server


async def update_server_name(
    db: AsyncSession, miner_hotkey: str, server_id: str, server_name: str
) -> Server:
    """
    Update name for an existing server (by server_id). Used to sync names for
    servers that existed before the name schema change.

    Args:
        db: Database session
        miner_hotkey: Authenticated miner hotkey (must own the server)
        server_id: Server ID (e.g. k8s node uid)
        server_name: New VM name to set (unique per miner)

    Returns:
        Updated Server

    Raises:
        ServerNotFoundError: If server not found or not owned by miner
        HTTPException 409: If new_vm_name is already used by another server of this miner
    """
    server = await check_server_ownership(db, server_id, miner_hotkey)
    if server.name == server_name:
        return server
    server.name = server_name
    try:
        await db.commit()
        await db.refresh(server)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"name '{server_name}' already in use by another server for this miner",
        )
    logger.info(f"Updated server {server_id} name to {server_name}")
    return server


async def process_runtime_attestation(
    db: AsyncSession,
    server_id: str,
    actual_ip: str,
    args: RuntimeAttestationArgs,
    miner_hotkey: str,
    expected_nonce: str,
    expected_cert_hash: str,
    nonce_context: RuntimeAttestationNonceContext,
) -> Dict[str, str]:
    """
    Process a runtime attestation request.

    Args:
        db: Database session
        server_id: Server ID
        args: Runtime attestation arguments
        miner_hotkey: Authenticated miner hotkey

    Returns:
        Dictionary containing attestation status info

    Raises:
        ServerNotFoundError: If server not found
        NonceError: If nonce validation fails
        InvalidQuoteError: If quote is invalid
        MeasurementMismatchError: If measurements don't match
    """
    logger.info(f"Processing runtime attestation for server: {server_id}")

    # Get server and verify ownership
    server = await check_server_ownership(db, server_id, miner_hotkey)

    if server.ip != actual_ip:
        raise MeasurementMismatchError(
            "Runtime attestation source IP does not match the registered server."
        )
    current_context = runtime_attestation_context_for_server(server)
    if nonce_context != current_context:
        raise NonceError("Runtime nonce identity no longer matches the exact registered server.")
    if (
        expected_cert_hash.lower() != nonce_context.cert_hash
        or expected_cert_hash.lower() != _registered_cert_hash(server)
    ):
        raise MeasurementMismatchError(
            "Runtime attestation certificate does not match the registered server."
        )

    # Parse and verify quote
    try:
        tee_type = (args.tee_type or "tdx").strip().lower()
        if tee_type != (server.tee_type or "tdx").strip().lower():
            raise MeasurementMismatchError(
                "Runtime attestation TEE type does not match the registered server."
            )
        quote = build_runtime_quote(
            args.quote,
            tee_type,
            args.snp_cert_chain,
            args.vtpm_quote,
        )
        verification_result = await verify_quote(
            quote,
            expected_nonce,
            expected_cert_hash,
            expected_gcp_identity=_expected_gcp_identity(server.server_id),
        )
        revocation_status = dict(getattr(verification_result, "revocation_status", {}) or {})

        # Create runtime attestation record
        measurement_config = get_matching_measurement_config(quote)
        config_fingerprint, trust_set_fingerprint = _measurement_fingerprints(measurement_config)
        provider = _canonical_infrastructure_provider(measurement_config.provider)
        provider = "bare-metal" if provider == "baremetal" else provider
        storage_measurement = (measurement_config.name or "").startswith("storage-")
        if (
            measurement_config.name != nonce_context.measurement_name
            or measurement_config.version != nonce_context.measurement_version
            or config_fingerprint != nonce_context.measurement_config_fingerprint
            or trust_set_fingerprint != nonce_context.trust_set_fingerprint
            or provider != nonce_context.provider
            or storage_measurement != (nonce_context.role == "storage")
            or (
                nonce_context.compute_type == "cpu"
                and (
                    measurement_config.gpu_count != 0
                    or list(measurement_config.expected_gpus or [])
                )
            )
            or (nonce_context.compute_type == "gpu" and (measurement_config.gpu_count or 0) <= 0)
        ):
            raise MeasurementMismatchError(
                "Runtime quote does not preserve the nonce-bound measurement, role, "
                "compute class, and provider identity."
            )
        config_fingerprint, trust_set_fingerprint = _stamp_server_measurement(
            server, measurement_config
        )
        server.attestation_revocation_status = revocation_status
        attestation = ServerAttestation(
            server_id=server_id,
            quote_data=args.quote,
            verification_error=None,
            measurement_version=measurement_config.version,
            measurement_name=measurement_config.name,
            measurement_config_fingerprint=config_fingerprint,
            trust_set_fingerprint=trust_set_fingerprint,
            revocation_status=revocation_status,
            verified_at=func.now(),
        )

        db.add(attestation)
        await db.commit()
        await db.refresh(attestation)

        logger.success(f"Runtime attestation successful: {attestation.attestation_id}")

        return {
            "attestation_id": attestation.attestation_id,
            "verified_at": attestation.verified_at.isoformat(),
            "status": "verified",
            "revocation_status": revocation_status,
        }

    except (InvalidQuoteError, MeasurementMismatchError) as e:
        # Create failed attestation record
        measurement_version = None
        measurement_name = None
        try:
            quote_parsed = build_runtime_quote(
                args.quote,
                (args.tee_type or "tdx").strip().lower(),
                args.snp_cert_chain,
                args.vtpm_quote,
            )
            measurement_config = get_matching_measurement_config(quote_parsed)
            measurement_version = measurement_config.version
            measurement_name = measurement_config.name
        except (InvalidQuoteError, MeasurementMismatchError):
            pass
        attestation = ServerAttestation(
            server_id=server_id,
            quote_data=args.quote,
            verification_error=str(e.detail),
            measurement_version=measurement_version,
            measurement_name=measurement_name,
        )

        db.add(attestation)
        await db.commit()

        logger.error(f"Runtime attestation failed: {str(e)}")
        raise


async def get_server_attestation_status(
    db: AsyncSession, server_id: str, miner_hotkey: str
) -> Dict[str, Any]:
    """
    Get the current attestation status for a server.

    Args:
        db: Database session
        server_id: Server ID
        miner_hotkey: Authenticated miner hotkey

    Returns:
        Dictionary containing attestation status
    """
    # Verify server ownership
    _ = await check_server_ownership(db, server_id, miner_hotkey)

    # Get latest attestation
    query = (
        select(ServerAttestation)
        .where(ServerAttestation.server_id == server_id)
        .order_by(ServerAttestation.created_at.desc())
        .limit(1)
    )

    result = await db.execute(query)
    latest_attestation = result.scalar_one_or_none()

    status = {
        "server_id": server_id,
        "last_attestation": None,
        "attestation_status": "never_attested",
    }

    if latest_attestation:
        verified = latest_attestation.verification_error is None
        status["last_attestation"] = {
            "attestation_id": latest_attestation.attestation_id,
            "verified": verified,
            "created_at": latest_attestation.created_at.isoformat(),
            "verified_at": latest_attestation.verified_at.isoformat()
            if latest_attestation.verified_at
            else None,
            "verification_error": latest_attestation.verification_error,
        }
        status["attestation_status"] = "verified" if verified else "failed"

    return status


async def delete_server(db: AsyncSession, server_id: str, miner_hotkey: str) -> bool:
    """
    Delete a server.

    Args:
        db: Database session
        server_id: Server ID
        miner_hotkey: Authenticated miner hotkey

    Returns:
        True if deleted successfully

    Raises:
        ServerNotFoundError: If server not found
    """
    server = await check_server_ownership(db, server_id, miner_hotkey)

    await db.delete(server)
    await db.commit()

    logger.info(f"Deleted server: {server_id}")
    return True


async def _validate_luks_capability_identity(
    db: AsyncSession,
    capability: LuksCapabilityContext,
    server_id: str,
    hotkey: str | None,
    expected_cert_hash: str,
    requested_volumes: list[str],
) -> Server:
    """Validate owner, server, cert, role, measurement version, and volume namespace."""
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Miner hotkey is required.",
        )
    if server_id != capability.server_id or hotkey != capability.miner_hotkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request identity does not match the issued LUKS capability.",
        )

    is_storage = capability.purpose == LuksCapabilityPurpose.STORAGE
    expected_allowed = STORAGE_LUKS_ALLOWED_VOLUMES if is_storage else BOOT_LUKS_ALLOWED_VOLUMES
    if (
        capability.storage_role != is_storage
        or tuple(capability.allowed_volumes) != expected_allowed
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="LUKS capability role or volume namespace is invalid.",
        )
    if (
        not requested_volumes
        or len(requested_volumes) != len(set(requested_volumes))
        or not set(requested_volumes).issubset(expected_allowed)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requested volume is outside the LUKS capability namespace.",
        )

    # Serialize certificate ownership with registration/upsert while a key lease is allocated or
    # confirmed. Without the row lock, a competing per-boot certificate could replace the server
    # after validation but before the generation transition commits.
    server_result = await db.execute(
        select(Server).where(Server.server_id == capability.server_id).with_for_update()
    )
    server = server_result.scalar_one_or_none()
    if server is None:
        raise ServerNotFoundError(capability.server_id)
    if (
        not server.is_tee
        or server.miner_hotkey != capability.miner_hotkey
        or server.name != capability.vm_name
        or bool(server.storage_role) != is_storage
        or server.version != capability.measurement_version
        or server.measurement_name != capability.measurement_name
        or server.measurement_config_fingerprint != capability.measurement_config_fingerprint
        or server.trust_set_fingerprint != capability.trust_set_fingerprint
        or (server.tee_type or "tdx").lower() != capability.tee_type
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registered server no longer matches the issued LUKS capability.",
        )
    _assert_cert_binding(server, expected_cert_hash, capability.cert_hash)
    return server


def _validate_luks_capability_measurement(
    server: Server, capability: LuksCapabilityContext, measurement_config
) -> None:
    """Require the fresh quote to match the exact measurement that minted the capability."""
    measurement_tee_type = (getattr(measurement_config, "tee_type", None) or "tdx").lower()
    config_fingerprint, trust_set_fingerprint = _measurement_fingerprints(measurement_config)
    if (
        measurement_config.name != capability.measurement_name
        or measurement_config.version != capability.measurement_version
        or config_fingerprint != capability.measurement_config_fingerprint
        or trust_set_fingerprint != capability.trust_set_fingerprint
        or measurement_tee_type != capability.tee_type
    ):
        raise MeasurementMismatchError(
            "LUKS quote measurement does not match the issued capability."
        )
    if capability.purpose == LuksCapabilityPurpose.STORAGE:
        if (
            measurement_config.gpu_count != 0
            or not (measurement_config.name or "").startswith("storage-")
            or not server.storage_role
        ):
            raise MeasurementMismatchError(
                "Storage LUKS capability requires the registered storage role and storage measurement."
            )
    else:
        _validate_boot_measurement(server, measurement_config)


async def process_luks_attest_request(
    db: AsyncSession,
    server_id: str,
    hotkey: str | None,
    body: LuksAttestRequest,
    validated_capability: tuple[str, LuksCapabilityContext],
    expected_cert_hash: str,
) -> LuksAttestResult:
    """
    Process POST /luks/attest for new-format VMs (version >= 1.3.0).

    The quote capability has already been atomically consumed. Revalidate its complete registered
    identity before any key lookup, then require the fresh quote to match the exact measurement that
    minted it. Storage capabilities can release only ``chutefs-data`` and never receive the k3s key.
    """
    quote_nonce, capability = validated_capability
    server = await _validate_luks_capability_identity(
        db, capability, server_id, hotkey, expected_cert_hash, body.volumes
    )
    tee_type = (getattr(body, "tee_type", None) or "tdx").strip().lower()
    if tee_type != capability.tee_type:
        raise MeasurementMismatchError(
            "Requested TEE type does not match the issued LUKS capability."
        )
    quote = build_runtime_quote(
        body.quote,
        tee_type,
        getattr(body, "snp_cert_chain", None),
        getattr(body, "vtpm_quote", None),
    )
    await verify_quote(
        quote,
        quote_nonce,
        expected_cert_hash,
        expected_gcp_identity=_expected_gcp_identity(server.server_id),
    )
    measurement_config = get_matching_measurement_config(quote)
    _validate_luks_capability_measurement(server, capability, measurement_config)

    volumes_data, vm_config = await lease_luks_passphrases(db, capability, body.volumes)

    # The k3s encryption key belongs only to the boot-LUKS namespace and is returned only when that
    # capability explicitly requested the storage volume. A storage TD receives no unrelated key.
    k3s_b64: Optional[str] = None
    if capability.purpose == LuksCapabilityPurpose.BOOT and LUKS_STORAGE_VOLUME in body.volumes:
        if not vm_config.k3s_encryption_key:
            k3s_bytes = secrets.token_bytes(32)
            k3s_b64 = base64.b64encode(k3s_bytes).decode()
            vm_config.k3s_encryption_key = encrypt_passphrase(k3s_b64)
            await db.commit()
        else:
            k3s_b64 = decrypt_passphrase(vm_config.k3s_encryption_key)

    confirm_nonce = await generate_confirm_nonce(capability, volumes_data)

    return LuksAttestResult(
        volumes=volumes_data,
        confirm_nonce=confirm_nonce,
        k3s_encryption_key=k3s_b64,
    )


async def process_luks_confirm(
    db: AsyncSession,
    server_id: str,
    hotkey: str | None,
    body: LuksConfirmRequest,
    capability: LuksCapabilityContext,
    expected_cert_hash: str,
) -> LuksConfirmResult:
    """
    Process POST /luks/confirm.

    The short-lived confirm capability authorizes exact volume generations and lease identities.
    It remains queryable for idempotent retries, and the caller must still present the currently
    registered attested certificate.
    """
    confirmed_volume_names = list(body.volumes)
    if set(confirmed_volume_names) != set(capability.issued_volumes or []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Confirmed volumes do not match the issued LUKS generation leases.",
        )
    await _validate_luks_capability_identity(
        db,
        capability,
        server_id,
        hotkey,
        expected_cert_hash,
        confirmed_volume_names,
    )

    vm_config = await _get_vm_cache_config_for_update(
        db,
        capability.miner_hotkey,
        capability.vm_name,
        create=False,
    )
    if vm_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No LUKS config found for server {server_id}",
        )

    confirmed_volumes = confirm_luks_generation_leases(vm_config, capability, body.volumes)
    await db.commit()

    logger.info(f"LUKS generation confirmation for server {server_id}: {confirmed_volumes}")

    return LuksConfirmResult(volumes=confirmed_volumes)


async def get_instance_server(db: AsyncSession, instance_id: str) -> tuple[Server, Instance]:
    """
    Get the TEE server and instance for evidence/attestation (instance has chute, nodes, server loaded).

    Args:
        db: Database session
        instance_id: Instance ID

    Returns:
        (Server, Instance). Use instance.deployment_id or instance.instance_id for proxy routing.

    Raises:
        InstanceNotFoundError: If instance not found
        ChuteNotTeeError: If the instance's chute is not TEE-enabled
    """
    # Load instance with chute, nodes and their servers
    query = (
        select(Instance)
        .where(Instance.instance_id == instance_id)
        .options(
            joinedload(Instance.chute),
            joinedload(Instance.nodes).joinedload(Node.server),
        )
    )
    result = await db.execute(query)
    instance = result.unique().scalar_one_or_none()

    if not instance:
        raise InstanceNotFoundError(instance_id)

    # Check if chute is TEE-enabled (TEE chutes can only run on TEE servers)
    if not instance.chute.tee:
        raise ChuteNotTeeError(instance.chute.chute_id)

    # GPU chutes link to their server via GPU nodes. CPU (GPU-less) chutes resolve by the
    # scheduler-stamped instance.server_id first (required for Model-B co-tenant TDs sharing
    # one L0 host IP), falling back to host + miner_hotkey for single-tenant servers.
    if instance.nodes:
        server = instance.nodes[0].server
    else:
        from api.instance.util import get_cpu_server_for_host

        server = await get_cpu_server_for_host(
            db, instance.host, instance.miner_hotkey, server_id=instance.server_id
        )
        if server is None:
            raise ServerNotFoundError(f"server for instance {instance_id}")

    return (server, instance)


async def _get_instance_evidence(
    server: Server, deployment_id: str, nonce: str
) -> TeeInstanceEvidence:
    """
    Get TEE instance evidence via the chute's evidence endpoint (third-party flow).
    Caller supplies nonce; we call chute-service-{deployment_id}/evidence?nonce=...
    Verification flow (no caller nonce) uses get_chute_evidence(deployment_id) → verify endpoint.
    """
    client = TeeServerClient(server)
    quote, gpu_evidence, cert = await client.get_chute_evidence(deployment_id, nonce=nonce)

    quote_base64 = base64.b64encode(quote.raw_bytes).decode("utf-8")
    cert_base64 = cert_to_base64_der(cert)

    return TeeInstanceEvidence(
        quote=quote_base64, gpu_evidence=gpu_evidence, certificate=cert_base64
    )


async def get_instance_evidence(
    db: AsyncSession, instance_id: str, nonce: str
) -> TeeInstanceEvidence:
    """
    Get TEE evidence for a specific instance (instance evidence endpoint flow).
    Requires instance.deployment_id (set when TEE launch config is claimed and verified).
    Runtime evidence is only supported for chutes_version >= 0.6.0.
    """
    validate_user_nonce(nonce)
    server, instance = await get_instance_server(db, instance_id)
    if semcomp(instance.chutes_version or "0.0.0", "0.6.0") < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Instances requires chutes_version >= 0.6.0 to retrieve evidence.",
        )
    if not instance.deployment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Instance has no deployment_id; evidence is only available after TEE verification",
        )
    return await _get_instance_evidence(server, instance.deployment_id, nonce)


async def _fetch_instance_evidence(
    instance: Instance, server: Optional[Server], nonce: str
) -> TeeInstanceEvidence | None:
    """Fetch evidence for a single instance, returning None on failure.

    The server is resolved by the caller (GPU chutes via Node rows, CPU chutes via
    host + miner_hotkey) so this coroutine performs no DB access and is safe under gather.
    """
    if server is None:
        logger.error(f"No server resolved for instance {instance.instance_id}; cannot get evidence")
        return None
    try:
        evidence = await _get_instance_evidence(server, instance.deployment_id, nonce)
        return TeeInstanceEvidence(
            quote=evidence.quote,
            gpu_evidence=evidence.gpu_evidence,
            instance_id=instance.instance_id,
            certificate=evidence.certificate,
        )
    except GetEvidenceError as e:
        logger.error(f"Failed to get evidence for instance {instance.instance_id}: {str(e)}")
        return None


async def get_chute_instances_evidence(
    db: AsyncSession, chute_id: str, nonce: str
) -> tuple[list[TeeInstanceEvidence], list[str]]:
    """
    Get TEE evidence for all instances of a chute (chute evidence endpoint flow).
    Returns (evidence_list, failed_instance_ids). Failed instance IDs are included
    so the user knows those instances still exist; access is already enforced at this point.
    Runtime evidence is only supported for chutes_version >= 0.6.0.
    """
    validate_user_nonce(nonce)

    query = select(Chute).where(Chute.chute_id == chute_id)
    result = await db.execute(query)
    chute = result.scalar_one_or_none()

    if not chute:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Chute {chute_id} not found"
        )

    if not chute.tee:
        raise ChuteNotTeeError(chute_id)

    if semcomp(chute.chutes_version or "0.0.0", "0.6.0") < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Instances requires chutes_version >= 0.6.0 to retrieve evidence.",
        )

    instances_query = (
        select(Instance)
        .where(
            Instance.chute_id == chute_id,
            Instance.active.is_(True),
            Instance.verified.is_(True),
            Instance.deployment_id.isnot(None),
        )
        .options(joinedload(Instance.nodes).joinedload(Node.server))
    )
    instances_result = await db.execute(instances_query)
    instances = instances_result.unique().scalars().all()

    # Resolve each instance's server sequentially (DB access is not safe under gather):
    # GPU chutes via their GPU nodes, CPU (GPU-less) chutes via the scheduler-stamped
    # instance.server_id (required for Model-B co-tenant TDs sharing one L0 host IP), with a
    # host + miner_hotkey fallback. An unresolvable/ambiguous server fails only that instance
    # (it lands in failed_instance_ids), not the whole evidence collection.
    from api.instance.util import get_cpu_server_for_host

    servers: list[Optional[Server]] = []
    for inst in instances:
        if inst.nodes:
            servers.append(inst.nodes[0].server)
        else:
            try:
                servers.append(
                    await get_cpu_server_for_host(
                        db, inst.host, inst.miner_hotkey, server_id=inst.server_id
                    )
                )
            except HTTPException as exc:
                logger.error(
                    f"Could not resolve server for instance {inst.instance_id}: {exc.detail}"
                )
                servers.append(None)

    results = await asyncio.gather(
        *[_fetch_instance_evidence(inst, server, nonce) for inst, server in zip(instances, servers)]
    )
    evidence_list: list[TeeInstanceEvidence] = []
    failed_instance_ids: list[str] = []
    for instance, result in zip(instances, results):
        if result is not None:
            evidence_list.append(result)
        else:
            failed_instance_ids.append(instance.instance_id)

    return (evidence_list, failed_instance_ids)


# ---------------------------------------------------------------------------
# TEE Maintenance Window
# ---------------------------------------------------------------------------


async def get_active_upgrade_window(
    db: AsyncSession,
) -> Optional[TeeUpgradeWindow]:
    """Return the active tee_upgrade_windows row (start <= now <= end), or None."""
    now = func.now()
    query = (
        select(TeeUpgradeWindow)
        .where(
            TeeUpgradeWindow.upgrade_window_start <= now,
            TeeUpgradeWindow.upgrade_window_end >= now,
        )
        .order_by(TeeUpgradeWindow.created_at.desc())
    )
    result = await db.execute(query)
    rows = result.scalars().all()
    if not rows:
        return None
    if len(rows) > 1:
        logger.warning(
            f"Multiple overlapping tee_upgrade_windows rows active ({len(rows)}); "
            f"using most recently created: {rows[0].id}"
        )
    return rows[0]


async def get_latest_upgrade_window(
    db: AsyncSession,
) -> Optional[TeeUpgradeWindow]:
    """Return the newest upgrade target even after its maintenance window closes."""
    query = select(TeeUpgradeWindow).order_by(TeeUpgradeWindow.upgrade_window_start.desc()).limit(1)
    result = await db.execute(query)
    return result.scalars().first()


def is_window_open(window: TeeUpgradeWindow) -> bool:
    """Whether the supplied maintenance window currently accepts confirmations."""
    now = datetime.now(timezone.utc)
    return window.upgrade_window_start <= now <= window.upgrade_window_end


async def _get_instances_on_server(db: AsyncSession, server_id: str) -> list[Instance]:
    """Return GPU-node-linked and directly linked CPU instances on a server."""
    query = (
        select(Instance)
        .outerjoin(instance_nodes, Instance.instance_id == instance_nodes.c.instance_id)
        .outerjoin(Node, instance_nodes.c.node_id == Node.uuid)
        .where(or_(Instance.server_id == server_id, Node.server_id == server_id))
        .distinct()
    )
    result = await db.execute(query)
    return list(result.scalars().all())


async def _find_sole_survivor_chutes(
    db: AsyncSession, instances: list[Instance]
) -> list[SoleSurvivorBlock]:
    """For each instance, check if it is the only active instance globally for its chute.

    Returns a list of SoleSurvivorBlock for blocking sole survivors.
    """
    blocking: list[SoleSurvivorBlock] = []
    seen_chutes: set[str] = set()
    for inst in instances:
        if inst.chute_id in seen_chutes:
            continue
        seen_chutes.add(inst.chute_id)
        count_query = (
            select(func.count())
            .select_from(Instance)
            .where(
                Instance.chute_id == inst.chute_id,
                Instance.active.is_(True),
                Instance.instance_id != inst.instance_id,
            )
        )
        result = await db.execute(count_query)
        other_active = result.scalar() or 0
        if other_active == 0:
            blocking.append(SoleSurvivorBlock(chute_id=inst.chute_id, instance_id=inst.instance_id))
    return blocking


async def _count_active_maintenance_slots(
    db: AsyncSession, miner_hotkey: str, active_window: TeeUpgradeWindow
) -> int:
    """Count servers for this miner that are in maintenance for the given active window."""
    query = (
        select(func.count())
        .select_from(Server)
        .where(
            Server.miner_hotkey == miner_hotkey,
            Server.maintenance_pending_window_id == active_window.id,
        )
    )
    result = await db.execute(query)
    return result.scalar() or 0


async def preflight_maintenance(
    db: AsyncSession, server: Server, miner_hotkey: str
) -> PreflightResult:
    """Read-only eligibility check for entering maintenance on a server."""
    denial_reasons: list[MaintenanceReason] = []
    blocking: list[SoleSurvivorBlock] = []
    limit = 1
    current_slots = 0
    active_window: Optional[TeeUpgradeWindow] = None

    if not server.is_tee:
        denial_reasons.append(MaintenanceReason(reason="not_tee"))

    if not denial_reasons:
        active_window = await get_active_upgrade_window(db)
        if active_window is None:
            denial_reasons.append(MaintenanceReason(reason="no_active_window"))

    if active_window is not None:
        limit = active_window.max_concurrent_per_miner

        if (
            server.version is not None
            and semcomp(server.version, active_window.target_measurement_version) >= 0
        ):
            denial_reasons.append(
                MaintenanceReason(
                    reason="already_at_target",
                    current_version=server.version,
                    target_version=active_window.target_measurement_version,
                )
            )

        if server.in_maintenance:
            if server.maintenance_pending_window_id == active_window.id:
                denial_reasons.append(
                    MaintenanceReason(
                        reason="maintenance_pending",
                        current_version=server.version,
                        target_version=active_window.target_measurement_version,
                        window_id=active_window.id,
                    )
                )
            else:
                server.maintenance_pending_window_id = None

        current_slots = await _count_active_maintenance_slots(db, miner_hotkey, active_window)
        if current_slots >= limit:
            denial_reasons.append(
                MaintenanceReason(
                    reason="concurrency_cap",
                    current_slots=current_slots,
                    limit=limit,
                )
            )

        instances = await _get_instances_on_server(db, server.server_id)
        blocking = await _find_sole_survivor_chutes(db, instances)
        if blocking:
            denial_reasons.append(
                MaintenanceReason(
                    reason="sole_survivor",
                    blocking=[b.model_dump() for b in blocking],
                )
            )

    return PreflightResult(
        eligible=len(denial_reasons) == 0,
        denial_reasons=denial_reasons,
        blocking_chute_ids=blocking,
        current_slots=current_slots,
        limit=limit,
    )


async def confirm_maintenance(
    db: AsyncSession, server: Server, miner_hotkey: str
) -> ConfirmMaintenanceResult:
    """Enter maintenance: re-validate, set pending window, and auto-purge instances.

    Raises HTTPException (409/403) on failure.
    """
    preflight = await preflight_maintenance(db, server, miner_hotkey)
    if not preflight.eligible:
        reason_codes = {r.reason for r in preflight.denial_reasons}
        conflict_reasons = {"sole_survivor", "concurrency_cap", "maintenance_pending"}
        if reason_codes & conflict_reasons:
            status_code = status.HTTP_409_CONFLICT
        else:
            status_code = status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=status_code, detail=preflight.model_dump())

    active_window = await get_active_upgrade_window(db)
    server.maintenance_pending_window_id = active_window.id
    await db.commit()
    await db.refresh(server)

    instances = await _get_instances_on_server(db, server.server_id)
    purged_ids: list[str] = []
    for inst in instances:
        try:
            await purge_and_notify(
                inst,
                reason="maintenance - server entering TEE upgrade window",
                valid_termination=True,
            )
            purged_ids.append(inst.instance_id)
        except Exception:
            logger.error(
                f"Failed to purge instance {inst.instance_id} during maintenance",
                exc_info=True,
            )

    return ConfirmMaintenanceResult(
        server_id=server.server_id,
        purged_instance_ids=purged_ids,
        window=UpgradeWindowInfo(
            id=active_window.id,
            target_measurement_version=active_window.target_measurement_version,
            upgrade_window_start=str(active_window.upgrade_window_start),
            upgrade_window_end=str(active_window.upgrade_window_end),
            max_concurrent_per_miner=active_window.max_concurrent_per_miner,
        ),
    )
