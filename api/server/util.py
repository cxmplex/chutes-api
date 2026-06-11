"""
TDX quote parsing, crypto operations, and server helper functions.
"""

import asyncio
import secrets
import base64
import json
import tempfile
from typing import Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import unquote
from aiohttp import ClientResponse
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from loguru import logger
from dcap_qvl import get_collateral_and_verify
from api.config import settings, TeeMeasurementConfig
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from api.server.exceptions import (
    AttestationError,
    GpuEvidenceError,
    InvalidClientCertError,
    InvalidGpuEvidenceError,
    InvalidQuoteError,
    InvalidSignatureError,
    InvalidTdxConfiguration,
    MeasurementMismatchError,
    NoClientCertError,
    NoServerCertError,
    NonceError,
)
from api.server.quote import TdxQuote, TdxVerificationResult
from api.server.snp_quote import SnpReport
from api.server.snp_verify import SnpVerificationResult, verify_snp_report
import hashlib
import os

from api.server.schemas import Server, VmCacheConfig, LuksVolumeRotation
from api.util import semcomp


def generate_nonce() -> str:
    """Generate a cryptographically secure nonce."""
    return secrets.token_hex(32)


def get_nonce_expiry_seconds(minutes: int = 10) -> int:
    """Get expiry time for a nonce in seconds."""
    return minutes * 60


def extract_client_cert_hash():
    async def _extract_request_client_cert(request: Request):
        try:
            cert = _get_client_certificate(request)
            return get_public_key_hash(cert)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Boot attestation failed, could not extract client cert:\n{e}")
            raise NoClientCertError(detail=str(e))

    return _extract_request_client_cert


def extract_client_cert_pem():
    """FastAPI dependency: return the client certificate as a canonical PEM string.

    Used by CPU TEE self-registration so the validator can persist the exact attestation-bound
    serving cert (whose pubkey hash is verified against the quote report_data) and later pin it as
    the instance cacert for the validator<->chute transport.
    """

    async def _extract_request_client_cert_pem(request: Request):
        try:
            cert = _get_client_certificate(request)
            return cert.public_bytes(serialization.Encoding.PEM).decode()
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Could not extract client cert PEM:\n{e}")
            raise NoClientCertError(detail=str(e))

    return _extract_request_client_cert_pem


def extract_server_cert_hash(response: ClientResponse):
    try:
        cert = _get_server_certificate(response)
        cert_hash = get_public_key_hash(cert)

        return cert_hash
    except Exception as e:
        logger.error(f"Exception trying to extract cert hash from server cert:\n{e}")
        raise NoServerCertError(detail=str(e))


def _get_server_certificate(response: ClientResponse) -> bytes:
    """
    Extract client certificate from Uvicorn request.
    Simplified for FastAPI-to-FastAPI communication.
    """
    # Get the server certificate from the connection
    # The transport contains the SSL object with peer certificate info
    transport = response.connection.transport
    ssl_object = transport.get_extra_info("ssl_object")

    if ssl_object is None:
        raise ValueError("No SSL connection established")

    # Get the peer certificate in DER format
    cert_der = ssl_object.getpeercert(binary_form=True)

    if cert_der is None:
        raise ValueError("No peer certificate available")

    # Load the DER certificate
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    return cert


def get_public_key_hash(cert: Certificate) -> str:
    """
    Compute SHA-256 hash of certificate's public key in DER format.
    This matches the bash snippet's logic:
    openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
    """
    # Extract the public key
    public_key = cert.public_key()

    # Serialize public key to DER format (matching openssl pkey -outform der)
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(public_key_der).hexdigest()

    return hash_digest


def validate_user_nonce(nonce: str) -> str:
    """
    Validate that a user-provided nonce is exactly 64 hex characters (32 bytes).

    Args:
        nonce: Nonce string to validate

    Returns:
        Validated nonce string

    Raises:
        NonceError: If nonce is not exactly 64 hex characters
    """
    if not nonce:
        raise NonceError("Nonce is required")

    if len(nonce) != 64:
        raise NonceError(f"Nonce must be exactly 64 hex characters (32 bytes), got {len(nonce)}")

    try:
        # Validate it's valid hex
        int(nonce, 16)
    except ValueError:
        raise NonceError("Nonce must be a valid hexadecimal string")

    return nonce


def cert_to_base64_der(cert: Certificate) -> str:
    """
    Convert a Certificate object to base64-encoded DER format.

    Args:
        cert: Certificate object to convert

    Returns:
        Base64-encoded DER certificate string
    """
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_base64 = base64.b64encode(cert_der).decode("utf-8")
    return cert_base64


# The verification result the mTLS-terminating proxy must report (nginx $ssl_client_verify) for the
# X-Client-Cert header to be trusted. A direct caller cannot produce this by setting a header,
# provided the proxy overwrites any client-supplied X-Client-* and the backend is not directly
# reachable -- so the cert in the header is the one the proxy actually verified PoP for in the
# TLS handshake, not a forged one.
CLIENT_CERT_VERIFY_SUCCESS = "SUCCESS"


def _get_client_certificate(request: Request) -> Certificate:
    """Extract the client certificate the mTLS-terminating proxy verified for this request.

    The proxy performs the TLS client-auth handshake (proving the peer holds the cert's private
    key), then forwards the verified peer cert as X-Client-Cert (URL-encoded PEM) and its result as
    X-Client-Verify. We only trust X-Client-Cert when X-Client-Verify == "SUCCESS" (unless
    REQUIRE_MTLS_CLIENT_VERIFY is disabled for a direct, plaintext dev validator with no mTLS
    terminator), so a direct caller cannot forge the header without completing mTLS at the verifying
    proxy. The proxy MUST overwrite any client-supplied X-Client-* headers and the backend MUST NOT
    be directly reachable.
    """
    if settings.require_mtls_client_verify:
        verify = (request.headers.get("X-Client-Verify") or "").strip().upper()
        if verify != CLIENT_CERT_VERIFY_SUCCESS:
            raise NoClientCertError(
                detail=(
                    "Client certificate was not verified by the mTLS terminator "
                    f"(X-Client-Verify={verify or 'missing'}); refusing to trust X-Client-Cert."
                )
            )

    cert_header = request.headers.get("X-Client-Cert")
    if not cert_header:
        raise NoClientCertError(detail="No client certificate provided")

    # Decode the URL-encoded PEM cert from the verifying mTLS terminator.
    cert_pem = unquote(cert_header).encode()

    # Parse the certificate
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

    return cert


def extract_nonce(quote: TdxQuote):
    """Extract nonce from quote report_data. Raises InvalidQuoteError if report_data is missing."""
    if quote.report_data is None:
        raise InvalidQuoteError(
            "Quote has no report data; nonce cannot be extracted. The quote may be malformed."
        )
    return quote.report_data[:64].lower()


def extract_cert_hash(quote: TdxQuote):
    return quote.report_data[64:128].lower()


def extract_report_data(quote: TdxQuote):
    # Extract nonce from report_data (first printable ASCII portion)
    nonce = extract_nonce(quote)
    cert_hash = extract_cert_hash(quote)

    return nonce, cert_hash


async def verify_quote_signature(quote: TdxQuote) -> TdxVerificationResult:
    """
    Verify the cryptographic signature of a TDX quote using dcap-qvl.

    Args:
        quote_bytes: Raw TDX quote bytes
        verify_collateral: Whether to verify against Intel's collateral (requires PCCS)

    Returns:
        True if signature is valid, False otherwise
    """

    logger.info("Verifying TDX quote signature using dcap-qvl")

    try:
        # Perform quote verification
        verified_report = await get_collateral_and_verify(quote.raw_bytes)

        result = TdxVerificationResult.from_report(verified_report)

        if result.is_valid:
            logger.success("TDX quote signature verification successful")
        else:
            error_msg = f"Verification status: {result.status}"
            if result.advisory_ids:
                error_msg += f"; advisory_ids: {result.advisory_ids}"
            logger.error(f"TDX quote signature verification failed: {error_msg}")
            raise InvalidSignatureError("TDX quote signature verification failed")

        return result
    except Exception as e:
        logger.error(f"Unexpected error during quote verification: {e}")
        raise InvalidQuoteError("Unable to parse provided quote for verification.")


def get_latest_measurement_version() -> str:
    """Return the highest semver version string across all accepted TEE measurement configs."""
    versions = [m.version for m in settings.tee_measurements if m.version]
    if not versions:
        return "0.0.0"
    latest = versions[0]
    for v in versions[1:]:
        if semcomp(v, latest) > 0:
            latest = v
    return latest


def get_matching_measurement_config(quote: TdxQuote) -> TeeMeasurementConfig:
    """
    Find the measurement config that matches the quote by full MRTD + RTMRs.

    Multiple configs may share the same RTMR0 (e.g. old and new VM versions);
    matching is by full MRTD and all RTMRs from the quote.

    Returns:
        The matching TeeMeasurementConfig

    Raises:
        MeasurementMismatchError: If no config matches
    """
    for config in settings.tee_measurements:
        if quote.matches_measurement(config):
            return config

    if isinstance(quote, SnpReport):
        logger.info(
            f"No SEV-SNP measurement config matched (measurement={quote.measurement[:16]}..., "
            f"policy={hex(quote.policy)}, reported_tcb={quote.reported_tcb_parts})"
        )
    else:
        logger.info(
            f"No measurement config matched quote (MRTD + RTMRs)\n{quote.mrtd=}\n{quote.rtmrs=}"
        )
    raise MeasurementMismatchError(
        "Quote does not match expected measurements. Ensure you are running a supported VM."
    )


def get_snp_processor_model() -> str:
    """Resolve the AMD processor model (Genoa/Milan/Turin) used to fetch the VCEK + pin the ARK.

    Derived from the configured SEV-SNP measurement configs when unambiguous (a deployment runs one
    AMD platform generation); falls back to SNP_PROCESSOR_MODEL or "Genoa".
    """
    models = {
        m.processor_model
        for m in settings.tee_measurements
        if getattr(m, "tee_type", "tdx") in ("sev-snp", "snp", "amd-snp") and m.processor_model
    }
    if len(models) == 1:
        return next(iter(models))
    return os.getenv("SNP_PROCESSOR_MODEL", "Genoa")


async def verify_snp_quote(quote: SnpReport, expected_nonce: str) -> SnpVerificationResult:
    """Verify an AMD SEV-SNP report end-to-end and match it to a configured SNP measurement config.

    Cryptographic verification (VCEK->ASK->ARK chain + ARK pin + ECDSA-P384 report signature +
    reported-TCB binding + debug-policy gate) is done by snp_verify; measurement/policy/min-TCB
    matching reuses the provider-agnostic get_matching_measurement_config.

    Image identity: on bare-metal SNP the dm-verity roothash is folded into the SNP launch
    measurement (direct-kernel-boot), so the measurement match IS the image-identity check. On GCP
    the SNP measurement is only Google's firmware, so the matched config additionally pins ``vtpm_pcrs``;
    when set, the report MUST carry a GCE vTPM quote, which is verified (AK->Google root + signature +
    nonce) and whose PCRs must equal the pinned values -- the GCP image-identity layer (Google-rooted).
    """
    model = get_snp_processor_model()
    # If the report carried an inline cert chain (GCP auxblob), use it; else fetch the VCEK from KDS.
    cert_chain = getattr(quote, "cert_chain", None)
    result = await verify_snp_report(
        quote, model=model, cert_chain=cert_chain, redis=settings.redis_client
    )
    if not result.is_valid:
        logger.error(f"SEV-SNP report verification failed: {result.errors}")
        raise InvalidSignatureError("SEV-SNP report verification failed")
    # Enforce the pinned measurement + policy + min-TCB (raises MeasurementMismatchError if none).
    config = get_matching_measurement_config(quote)

    # GCP image-identity: when the matched config pins vTPM PCRs, require + verify the vTPM quote.
    vtpm_pcrs = getattr(config, "vtpm_pcrs", None)
    if vtpm_pcrs:
        await _verify_snp_vtpm(quote, config, expected_nonce)

    logger.success(
        f"SEV-SNP report verified + measurement matched: measurement={quote.measurement[:16]}..."
        + (" + vTPM image identity" if vtpm_pcrs else "")
    )
    return result


async def _verify_snp_vtpm(quote: SnpReport, config, expected_nonce: str) -> None:
    """Verify the GCE vTPM measured-boot quote attached to a GCP SNP report against pinned PCRs.

    The vTPM quote (AK cert + TPMS_ATTEST + signature + PCRs) is verified by gcp_vtpm (AK chains to
    the pinned Google EK/AK CA Root, RSASSA/SHA256 signature, extraData == the registration nonce,
    pcrDigest == sha256(PCRs)); then the verified PCRs must equal the config's pinned ``vtpm_pcrs``.
    """
    from api.server.gcp_vtpm import verify_vtpm_quote

    vq = getattr(quote, "vtpm_quote", None)
    if not vq:
        raise MeasurementMismatchError(
            "SNP config requires a GCE vTPM quote for image identity, but none was provided."
        )
    try:
        ak = base64.b64decode(vq["ak_cert"])
        msg = base64.b64decode(vq["quote_msg"])
        sig = base64.b64decode(vq["quote_sig"])
        pcrs = {int(k): bytes.fromhex(v) for k, v in vq["pcrs"].items()}
        intermediate = base64.b64decode(vq["intermediate"]) if vq.get("intermediate") else None
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidQuoteError(f"Malformed vTPM quote: {exc}")

    vres = await verify_vtpm_quote(
        ak, msg, sig, pcrs,
        bytes.fromhex(expected_nonce),
        intermediate_der=intermediate,
        redis=settings.redis_client,
    )
    if not vres.is_valid:
        logger.error(f"GCE vTPM quote verification failed: {vres.errors}")
        raise InvalidSignatureError("GCE vTPM quote verification failed")

    # Compare the verified PCRs to the pinned per-image expected values (the image-identity check).
    mismatches = []
    for idx_str, expected_hex in config.vtpm_pcrs.items():
        idx = int(idx_str)
        actual = vres.pcrs.get(str(idx))
        if not actual or actual.upper() != expected_hex.upper():
            mismatches.append(f"PCR{idx}: expected {expected_hex[:16]}..., got {(actual or '')[:16]}...")
    if mismatches:
        logger.error(f"vTPM PCR mismatch (image identity): {'; '.join(mismatches)}")
        raise MeasurementMismatchError(
            "vTPM PCRs do not match the expected image measurements. "
            "Ensure you are running a supported GCP confidential image."
        )


def verify_measurements(quote: TdxQuote) -> bool:
    """
    Verify quote measurements against allowed measurement values.

    Finds the matching config by full MRTD + RTMRs (multiple configs may share RTMR0).

    Args:
        quote: Parsed TDX quote

    Returns:
        True if all measurements match

    Raises:
        MeasurementMismatchError: If any measurements don't match
    """
    measurement_config = get_matching_measurement_config(quote)
    expected_rtmrs = (
        measurement_config.boot_rtmrs
        if quote.quote_type == "boot"
        else measurement_config.runtime_rtmrs
    )

    logger.info(
        f"Verifying quote for measurement config '{measurement_config.name}' "
        f"(version={measurement_config.version}, RTMR0: {quote.rtmr0.upper()[:16]}...)"
    )
    return _verify_measurements(
        quote, expected_rtmrs, measurement_config.name, measurement_config.mrtd
    )


def verify_result(quote: TdxQuote, result: TdxVerificationResult) -> bool:
    """
    Ensure the parsed quote matches the DCAP verification result.

    Compares quote.mrtd and quote.rtmrs to result.mrtd and result.rtmrs.
    Has nothing to do with measurement config; only validates that our parsing
    matches what DCAP verified.

    Raises:
        MeasurementMismatchError: If quote and result measurements differ
    """
    logger.info("Verifying quote matches DCAP verification result.")
    return _verify_measurements(quote, result.rtmrs, "DCAP result", result.mrtd)


def _verify_measurements(
    quote: TdxQuote,
    expected_rtmrs: Dict[str, str],
    measurement_name: str,
    expected_mrtd: str,
) -> bool:
    """
    Compare quote measurements to expected mrtd and rtmrs.

    Used both to compare quote to config (verify_measurements) and quote to DCAP result (verify_result).
    """
    try:
        mismatches = []

        if quote.mrtd.upper() != expected_mrtd.upper():
            error_msg = (
                f"MRTD mismatch for measurement config '{measurement_name}': "
                f"expected {expected_mrtd[:16]}..., got {quote.mrtd[:16]}..."
            )
            logger.error(error_msg)
            mismatches.append(error_msg)

        for rtmr_name, expected_value in expected_rtmrs.items():
            actual_value = quote.rtmrs.get(rtmr_name.lower()) or quote.rtmrs.get(rtmr_name)
            if not actual_value:
                error_msg = f"Quote missing expected RTMR[{rtmr_name}]"
                logger.error(error_msg)
                mismatches.append(error_msg)
            elif actual_value.upper() != expected_value.upper():
                error_msg = (
                    f"RTMR {rtmr_name} mismatch for measurement config '{measurement_name}': "
                )
                logger.error(f"{error_msg} expected {expected_value}..., got {actual_value}...")
                mismatches.append(error_msg)

        if mismatches:
            logger.error(f"Measurement verification failed: {'; '.join(mismatches)}")
            raise MeasurementMismatchError()

        logger.info(
            f"Measurements verified successfully for measurement config '{measurement_name}'"
        )
        return True

    except MeasurementMismatchError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during measurement verification: {e}", exc_info=True)
        # Re-raise as AttestationError for unexpected exceptions
        raise AttestationError("Measurement verification failed due to an unexpected error.")


def get_luks_passphrase() -> str:
    """
    Get the LUKS passphrase for disk decryption.

    Returns:
        LUKS passphrase string
    """

    passphrase = settings.luks_passphrase
    if not passphrase:
        logger.error("No LUKS passphrase configured")
        raise InvalidTdxConfiguration("Missing LUKS passphrase configuration")

    return passphrase


def generate_cache_passphrase() -> str:
    """
    Generate a new cryptographically secure passphrase for cache volume encryption.

    Returns:
        128-character hex passphrase
    """
    return secrets.token_hex(64)


def _get_fernet() -> Fernet:
    """Get Fernet cipher for encrypting/decrypting cache passphrases.

    Returns:
        Fernet cipher instance

    Raises:
        InvalidTdxConfiguration: If encryption key is not configured
    """
    fernet = settings.fernet_key
    if not fernet:
        logger.error("No cache passphrase encryption key configured")
        raise InvalidTdxConfiguration(
            "CACHE_PASSPHRASE_KEY environment variable must be set. "
            "Generate a valid key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        )
    return fernet


def encrypt_passphrase(passphrase: str) -> str:
    """Encrypt a cache passphrase for storage.

    Args:
        passphrase: Plain text passphrase

    Returns:
        Encrypted passphrase (base64 encoded)
    """
    fernet = _get_fernet()
    encrypted = fernet.encrypt(passphrase.encode())
    return encrypted.decode()


def decrypt_passphrase(encrypted_passphrase: str) -> str:
    """Decrypt a stored cache passphrase.

    Args:
        encrypted_passphrase: Encrypted passphrase (base64 encoded)

    Returns:
        Plain text passphrase
    """
    fernet = _get_fernet()
    decrypted = fernet.decrypt(encrypted_passphrase.encode())
    return decrypted.decode()


async def _get_vm_cache_config(
    db: AsyncSession, miner_hotkey: str, vm_name: str
) -> Optional[VmCacheConfig]:
    """Get VmCacheConfig row if it exists."""
    result = await db.execute(
        select(VmCacheConfig).where(
            VmCacheConfig.miner_hotkey == miner_hotkey,
            VmCacheConfig.vm_name == vm_name,
        )
    )
    return result.scalar_one_or_none()


async def _create_vm_cache_config(
    db: AsyncSession, miner_hotkey: str, vm_name: str
) -> VmCacheConfig:
    """Create and persist a new VmCacheConfig row."""
    vm_config = VmCacheConfig(
        miner_hotkey=miner_hotkey,
        vm_name=vm_name,
        volume_passphrases={},
        last_boot_at=func.now(),
    )
    db.add(vm_config)
    await db.flush()
    return vm_config


async def sync_server_luks_passphrases(
    db: AsyncSession,
    miner_hotkey: str,
    vm_name: str,
    volume_names: List[str],
    rekey_volume_names: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Sync LUKS state: ensure passphrases for every volume in volume_names, prune others.
    Volumes in rekey_volume_names get new passphrases (no reuse).
    """
    rekey_set = set(rekey_volume_names or [])
    vm_config = await _get_vm_cache_config(db, miner_hotkey, vm_name)
    if vm_config is None:
        vm_config = await _create_vm_cache_config(db, miner_hotkey, vm_name)
    stored: Dict[str, str] = dict(vm_config.volume_passphrases or {})

    result: Dict[str, str] = {}
    for vol in volume_names:
        if vol in rekey_set or vol not in stored:
            passphrase = generate_cache_passphrase()
            stored[vol] = encrypt_passphrase(passphrase)
            result[vol] = passphrase
        else:
            result[vol] = decrypt_passphrase(stored[vol])

    # Prune: keep only volume_names
    vm_config.volume_passphrases = {k: v for k, v in stored.items() if k in volume_names}
    vm_config.last_boot_at = func.now()
    await db.commit()
    await db.refresh(vm_config)
    logger.info(f"LUKS sync for VM {vm_name}: volumes={volume_names}, rekey={list(rekey_set)}")
    return result


async def delete_luks_passphrases_for_server(
    db: AsyncSession, miner_hotkey: str, server_name: str
) -> None:
    """Remove all LUKS passphrases for a VM (e.g. when server is deleted)."""
    result = await db.execute(
        select(VmCacheConfig).where(
            VmCacheConfig.miner_hotkey == miner_hotkey,
            VmCacheConfig.vm_name == server_name,
        )
    )
    vm_config = result.scalar_one_or_none()
    if vm_config:
        await db.delete(vm_config)
        await db.commit()
        logger.info(f"Deleted LUKS config for VM {server_name} (miner: {miner_hotkey})")


async def generate_confirm_nonce(miner_hotkey: str, vm_name: str) -> str:
    """Generate a confirm nonce and store in Redis with 5-minute TTL."""
    nonce = secrets.token_hex(32)
    redis_key = f"confirm:{miner_hotkey}:{vm_name}"
    await settings.redis_client.setex(redis_key, 300, nonce)
    logger.info(f"Generated confirm nonce for VM {vm_name} (miner: {miner_hotkey})")
    return nonce


async def generate_luks_quote_nonce(miner_hotkey: str, vm_name: str) -> str:
    """Generate a LUKS quote nonce and store in Redis with 10-minute TTL."""
    nonce = secrets.token_hex(32)
    redis_key = f"luks_quote_nonce:{miner_hotkey}:{vm_name}"
    await settings.redis_client.setex(redis_key, 600, nonce)
    logger.info(f"Generated LUKS quote nonce for VM {vm_name} (miner: {miner_hotkey})")
    return nonce


async def rotate_luks_passphrases(
    db: AsyncSession,
    miner_hotkey: str,
    vm_name: str,
    volume_names: List[str],
) -> tuple[Dict[str, LuksVolumeRotation], "VmCacheConfig"]:
    """
    Rotate LUKS passphrases for the given volumes.

    For each volume:
    - Reads the current passphrase from DB (None if first boot)
    - Discards any stale pending passphrase from a prior unconfirmed rotation
    - Generates a new passphrase stored as pending_{vol} in volume_passphrases

    Returns a tuple of (volume_data, vm_config) where volume_data maps each
    volume name to a LuksVolumeRotation and vm_config is the updated ORM object
    (after commit + refresh).
    """
    vm_config = await _get_vm_cache_config(db, miner_hotkey, vm_name)
    if vm_config is None:
        vm_config = await _create_vm_cache_config(db, miner_hotkey, vm_name)

    stored: Dict[str, str] = dict(vm_config.volume_passphrases or {})
    result: Dict[str, LuksVolumeRotation] = {}

    for vol in volume_names:
        current_enc = stored.get(vol)
        current = decrypt_passphrase(current_enc) if current_enc else None

        # Discard any stale pending from a prior unconfirmed rotation
        stored.pop(f"pending_{vol}", None)

        new_passphrase = generate_cache_passphrase()
        stored[f"pending_{vol}"] = encrypt_passphrase(new_passphrase)

        result[vol] = LuksVolumeRotation(current=current, next=new_passphrase)

    vm_config.volume_passphrases = stored
    vm_config.last_boot_at = func.now()
    await db.commit()
    await db.refresh(vm_config)
    logger.info(f"LUKS rotation for VM {vm_name}: volumes={volume_names}")
    return result, vm_config


async def _track_server(
    db: AsyncSession,
    server_id: str,
    name: str,
    host: str,
    miner_hotkey: str,
    is_tee: bool = False,
):
    # Add server and nodes to DB (server_id provided by client)
    server = Server(
        server_id=server_id,
        name=name,
        ip=host,
        miner_hotkey=miner_hotkey,
        is_tee=is_tee,
    )

    db.add(server)
    await db.commit()
    await db.refresh(server)

    return server


async def verify_quote(quote, expected_nonce: str, expected_cert_hash: str):
    """Verify a TEE attestation (Intel TDX quote or AMD SEV-SNP report).

    The nonce + client-cert-hash binding (report_data = nonce || sha256(pubkey)) is identical for
    both providers; only the signature/measurement verification differs and is dispatched by type.
    """
    nonce, cert_hash = extract_report_data(quote)

    if nonce != expected_nonce:
        logger.info(f"Nonce error:  {nonce} =/= {expected_nonce}")
        raise NonceError("Quote nonce does not match expected nonce.")

    if cert_hash != expected_cert_hash:
        raise InvalidClientCertError()

    # AMD SEV-SNP: VCEK chain + report signature + measurement (no DCAP / MRTD / RTMRs).
    # On GCP, image identity is additionally enforced via the GCE vTPM quote (nonce-bound).
    if isinstance(quote, SnpReport):
        return await verify_snp_quote(quote, expected_nonce)

    # Intel TDX: dcap-qvl signature verification + DCAP-result cross-check + MRTD/RTMR match.
    result = await verify_quote_signature(quote)
    verify_result(quote, result)
    verify_measurements(quote)

    return result


async def verify_gpu_evidence(evidence: list[Dict[str, str]], expected_nonce: str) -> None:
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as fp:
            json.dump(evidence, fp)
            fp.flush()

            verify_gpus_cmd = ["chutes-nvattest", "--nonce", expected_nonce, "--evidence", fp.name]

            process = await asyncio.create_subprocess_exec(*verify_gpus_cmd)

            await asyncio.gather(process.wait())

            if process.returncode != 0:
                raise InvalidGpuEvidenceError()

            logger.info("GPU evidence verified successfully.")

    except FileNotFoundError as e:
        logger.error(f"Failed to verify GPU evidence.  chutes-nvattest command not found?:\n{e}")
        raise GpuEvidenceError("Failed to verify GPU evidence.")
    except Exception as e:
        logger.error(f"Unexepected exception encoutnered verifying GPU evidence:\n{e}")
        raise GpuEvidenceError("Encountered an unexpected exception verifying GPU evidence.")
