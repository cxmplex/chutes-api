"""
TDX quote parsing, crypto operations, and server helper functions.
"""

import asyncio
import secrets
import base64
import json
import struct
import tempfile
import time
from typing import Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import unquote
from aiohttp import ClientResponse
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request, status
from loguru import logger
from dcap_qvl import (
    PHALA_PCCS_URL,
    Quote,
    __version__ as DCAP_QVL_VERSION,
    get_collateral,
    verify_with_root_ca,
)
from api.config import settings, TeeMeasurementConfig
from api.server.intel_root import INTEL_SGX_ROOT_CA_DER
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
from api.server.quote import (
    TdxQuote,
    TdxVerificationResult,
    merge_tcb_status,
    resolve_tdx_tcb_status,
)
from api.server.snp_quote import SnpReport
from api.server.snp_verify import SnpVerificationResult, verify_snp_report
import hashlib
import os

from api.server.schemas import (
    Server,
    VmCacheConfig,
    LuksCapabilityContext,
    LuksVolumeConfirmStatus,
    LuksVolumeGenerationLease,
    LuksVolumeRotation,
)


def generate_nonce() -> str:
    """Generate a cryptographically secure nonce."""
    return secrets.token_hex(32)


def get_nonce_expiry_seconds(minutes: int = 10) -> int:
    """Get expiry time for a nonce in seconds."""
    return minutes * 60


def extract_client_cert_hash(require_proxy_verified: bool = False):
    """Dependency: the client cert's pubkey hash.

    require_proxy_verified=False (default; attestation/registration + per-volume key release): the
    cert pubkey is bound into the hardware quote, so a header-forwarded cert is trusted via that
    binding. require_proxy_verified=True (peer discovery / grant-verify, which have NO downstream
    quote check): require a LIVE mTLS handshake. nginx reports SUCCESS for a CA-chained cert and
    FAILED:<reason> for an expected self-signed TEE cert under optional_no_ca; both prove possession,
    while NONE/missing does not. A public cert PEM in a header alone cannot pass the gate (M4).
    """

    async def _extract_request_client_cert(request: Request):
        try:
            cert = _get_client_certificate(request, require_proxy_verified=require_proxy_verified)
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
            # Attestation/registration: cert is quote-bound; accept the header cert (the in-guest
            # agent posts it via header, not mTLS). The quote check is the trust anchor.
            cert = _get_client_certificate(request, require_proxy_verified=False)
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
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
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


def _get_client_certificate(request: Request, require_proxy_verified: bool = True) -> Certificate:
    """Extract the client certificate the mTLS-terminating proxy forwarded for this request.

    The proxy performs the TLS client-auth handshake (proving the peer holds the cert's private
    key), then forwards the peer cert as X-Client-Cert (URL-encoded PEM) and its result as
    X-Client-Verify.

    require_proxy_verified=True (secret-returning endpoints, e.g. /tee): only trust X-Client-Cert
    when X-Client-Verify proves the cert was presented in a LIVE handshake. Accept SUCCESS or
    FAILED:<reason>: optional_no_ca reports FAILED for self-signed attested TEE certs even though
    CertificateVerify proved private-key possession. Reject NONE/missing. A direct caller cannot
    forge the proxy-owned result header.

    require_proxy_verified=False (attestation/registration endpoints): the cert's public key is bound
    into the hardware attestation quote (report_data == nonce || sha256(cert pubkey)), so the cert is
    trusted via that hardware binding rather than a live handshake. This lets the in-guest agent post
    its attested cert over the X-Client-Cert header (its httpx client does not present a client cert
    to the optional mTLS edge) while the quote -- not the transport -- establishes trust.

    The presentation gate is skipped entirely when REQUIRE_MTLS_CLIENT_VERIFY is disabled (the
    plaintext dev posture). The proxy MUST overwrite any client-supplied X-Client-* headers.
    """
    if settings.require_mtls_client_verify and require_proxy_verified:
        verify = (request.headers.get("X-Client-Verify") or "").strip().upper()
        # SUCCESS = presented + CA-chain verified. FAILED:<reason> = the cert WAS presented in the
        # live TLS handshake (possession proven via CertificateVerify) but did not chain to a CA --
        # the expected verdict for attestation-bound SELF-SIGNED TEE certs (nginx runs
        # ssl_verify_client optional_no_ca; trust comes from the quote binding / attested-cert
        # registry, not a CA). NONE/missing = no live handshake at all, so the header PEM alone
        # proves nothing (the M4 forgery) -- reject. nginx overwrites client-supplied X-Client-*.
        presented = verify == CLIENT_CERT_VERIFY_SUCCESS or verify.startswith("FAILED")
        if not presented:
            raise NoClientCertError(
                detail=(
                    "Client certificate was not presented in the mTLS handshake "
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

    The quote's PCK chain is verified against the explicitly pinned Intel SGX Root CA
    (intel_root.py) via ``verify_with_root_ca`` -- never the library's built-in root -- matching
    the deliberate AMD ARK pin in snp_verify. The PCCS only serves collateral (TCB info / QE
    identity / CRLs), whose signatures chain to the same pinned root, so it is not a trust anchor.

    Args:
        quote: Parsed TDX quote (raw_bytes are verified)

    Returns:
        TdxVerificationResult derived from the dcap-qvl verified report
    """

    logger.info("Verifying TDX quote signature using dcap-qvl (pinned Intel root)")

    try:
        # Perform quote verification against the pinned Intel root.
        collateral = await get_collateral(PHALA_PCCS_URL, quote.raw_bytes)
        try:
            verified_report = verify_with_root_ca(
                quote.raw_bytes, collateral, INTEL_SGX_ROOT_CA_DER, int(time.time())
            )
            result = TdxVerificationResult.from_report(verified_report)
        except ValueError as exc:
            # dcap-qvl 0.5.3 compares module-governed SVN bytes while selecting the
            # platform level. Only its exact step-8 error enters the audited fallback.
            if not _is_audited_dcap_platform_tcb_error(exc):
                raise
            result = _resolve_tdx_tcb_via_module_identity(quote, collateral, exc)

        if result.is_valid:
            logger.success("TDX quote signature verification successful")
        else:
            error_msg = f"Verification status: {result.status}"
            if result.advisory_ids:
                error_msg += f"; advisory_ids: {result.advisory_ids}"
            logger.error(f"TDX quote signature verification failed: {error_msg}")
            raise InvalidSignatureError("TDX quote signature verification failed")

        return result
    except AttestationError:
        # Preserve structured fail-closed attestation verdicts such as an authenticated
        # quote whose TCB/advisory/debug status is unacceptable.
        raise
    except Exception as e:
        logger.error(f"Unexpected error during quote verification: {e}")
        raise InvalidQuoteError("Unable to parse provided quote for verification.")


_AUDITED_DCAP_QVL_FALLBACK_VERSION = "0.5.3"
_DCAP_PLATFORM_TCB_ERROR = "No matching TCB level found"
_TDX_V4_AUTH_LENGTH_OFFSET = 632
_TDX_V4_AUTH_DATA_OFFSET = 636
_ECDSA_SIGNATURE_AND_KEY_LENGTH = 128
_CERTIFICATION_DATA_HEADER_LENGTH = 6
_QE_REPORT_CERTIFICATION_DATA_TYPE = 6
_QE_REPORT_LENGTH = 384
_QE_REPORT_ISV_SVN_OFFSET = 258
_KNOWN_TCB_STATUSES = {
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "Revoked",
}


def _is_audited_dcap_platform_tcb_error(error: ValueError) -> bool:
    """Accept only the single audited dcap-qvl 0.5.3 step-8 failure."""
    if DCAP_QVL_VERSION != _AUDITED_DCAP_QVL_FALLBACK_VERSION:
        return False
    return str(error) in {
        _DCAP_PLATFORM_TCB_ERROR,
        f"Verification failed: {_DCAP_PLATFORM_TCB_ERROR}",
    }


def _extract_tdx_v4_qe_isv_svn(raw_quote: bytes) -> int:
    """Extract QE ISVSVN from dcap-qvl's authenticated v4 QE report."""
    try:
        auth_data_length = struct.unpack_from("<I", raw_quote, _TDX_V4_AUTH_LENGTH_OFFSET)[0]
    except struct.error as exc:
        raise InvalidQuoteError(
            "TDX quote is too short for its authentication-data length"
        ) from exc

    auth_data_end = _TDX_V4_AUTH_DATA_OFFSET + auth_data_length
    if auth_data_end > len(raw_quote):
        raise InvalidQuoteError("TDX quote authentication data is truncated")

    outer_cert_offset = _TDX_V4_AUTH_DATA_OFFSET + _ECDSA_SIGNATURE_AND_KEY_LENGTH
    try:
        cert_type, cert_body_length = struct.unpack_from("<HI", raw_quote, outer_cert_offset)
    except struct.error as exc:
        raise InvalidQuoteError("TDX quote is missing QE report certification data") from exc
    if cert_type != _QE_REPORT_CERTIFICATION_DATA_TYPE:
        raise InvalidQuoteError(
            f"TDX quote has unexpected outer certification data type {cert_type}"
        )

    qe_report_offset = outer_cert_offset + _CERTIFICATION_DATA_HEADER_LENGTH
    cert_body_end = qe_report_offset + cert_body_length
    if cert_body_end > auth_data_end or cert_body_length < _QE_REPORT_LENGTH:
        raise InvalidQuoteError("TDX quote QE report certification data is truncated")

    try:
        return struct.unpack_from("<H", raw_quote, qe_report_offset + _QE_REPORT_ISV_SVN_OFFSET)[0]
    except struct.error as exc:
        raise InvalidQuoteError("TDX quote QE report is truncated") from exc


def _resolve_authenticated_qe_tcb_status(
    raw_quote: bytes, qe_identity_json: str
) -> tuple[str, List[str]]:
    """Recover the QE verdict that dcap-qvl computed before its step-8 error.

    The exact dcap-qvl 0.5.3 error is reachable only after the pinned-root QE
    identity signature, PCK/QE/quote signatures, QE identity policy, and QE TCB
    match have succeeded. The fallback still has to carry that matched QE
    status and its advisories into the final verdict.
    """
    try:
        qe_identity = json.loads(qe_identity_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidQuoteError("Unable to parse authenticated QE Identity collateral") from exc
    if (
        not isinstance(qe_identity, dict)
        or qe_identity.get("id") != "TD_QE"
        or qe_identity.get("version") not in (2, 3)
    ):
        raise InvalidQuoteError("Authenticated QE Identity has an unsupported id or version")

    qe_isv_svn = _extract_tdx_v4_qe_isv_svn(raw_quote)
    levels = qe_identity.get("tcbLevels")
    if not isinstance(levels, list) or not levels:
        raise InvalidQuoteError("Authenticated QE Identity has no TCB levels")

    for level in levels:
        try:
            required_isv_svn = level["tcb"]["isvsvn"]
            status_value = level["tcbStatus"]
            advisory_ids = level.get("advisoryIDs", []) or []
        except (KeyError, TypeError) as exc:
            raise InvalidQuoteError("Authenticated QE Identity TCB level is malformed") from exc
        if (
            isinstance(required_isv_svn, bool)
            or not isinstance(required_isv_svn, int)
            or not isinstance(status_value, str)
            or status_value not in _KNOWN_TCB_STATUSES
            or not isinstance(advisory_ids, list)
            or any(not isinstance(item, str) for item in advisory_ids)
        ):
            raise InvalidQuoteError("Authenticated QE Identity TCB level is malformed")
        if qe_isv_svn >= required_isv_svn:
            return status_value, advisory_ids

    raise InvalidQuoteError(
        f"QE ISVSVN {qe_isv_svn} is below every authenticated QE Identity TCB level"
    )


def _resolve_tdx_tcb_via_module_identity(
    quote: TdxQuote, collateral, original_error: Exception
) -> TdxVerificationResult:
    """Replace only dcap-qvl's faulty platform match and finish its policy."""
    if not isinstance(original_error, ValueError) or not _is_audited_dcap_platform_tcb_error(
        original_error
    ):
        raise original_error
    parsed = Quote.parse(quote.raw_bytes)
    if not parsed.is_tdx():
        raise original_error
    report = parsed.report
    pck = parsed.pck_extension()
    if pck is None:
        raise InvalidQuoteError("Unable to parse the verified quote's PCK extension")
    status_value, advisory_ids = resolve_tdx_tcb_status(
        tcb_info=json.loads(collateral.tcb_info),
        tee_tcb_svn=list(report.tee_tcb_svn),
        sgx_tcb_components=list(pck.cpu_svn),
        pce_svn=pck.pce_svn,
        mr_signer_seam=report.mr_signer_seam,
        seam_attributes=report.seam_attributes,
    )
    qe_status = _resolve_authenticated_qe_tcb_status(quote.raw_bytes, collateral.qe_identity)
    status_value, advisory_ids = merge_tcb_status((status_value, advisory_ids), qe_status)
    logger.info(
        "Resolved TDX TCB via pinned module identity: "
        f"status={status_value}, tee_tcb_svn={list(report.tee_tcb_svn)[:2]}..."
    )
    return TdxVerificationResult.from_fields(
        mr_td=report.mr_td,
        rt_mr0=report.rt_mr0,
        rt_mr1=report.rt_mr1,
        rt_mr2=report.rt_mr2,
        rt_mr3=report.rt_mr3,
        report_data=report.report_data,
        td_attributes=report.td_attributes,
        status=status_value,
        advisory_ids=advisory_ids,
    )


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


def verify_snp_measurement_constraints(quote: SnpReport, config) -> None:
    """Enforce the exact SNP measurement, policy, TCB, ID-key, and VMPL pin."""
    if not quote.matches_measurement(config):
        raise MeasurementMismatchError(
            "SEV-SNP report does not match the exact configured measurement constraints."
        )
    expected_vmpl = getattr(config, "expected_vmpl", None)
    if (
        not isinstance(expected_vmpl, int)
        or isinstance(expected_vmpl, bool)
        or quote.vmpl != expected_vmpl
    ):
        raise MeasurementMismatchError("SEV-SNP report VMPL does not match the pinned measurement.")


async def verify_snp_quote(
    quote: SnpReport,
    expected_nonce: str,
    expected_gcp_identity: Optional[dict] = None,
) -> SnpVerificationResult:
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
        quote,
        model=model,
        cert_chain=cert_chain,
        redis=settings.redis_client,
        crl_outage_grace_seconds=settings.snp_crl_outage_grace_seconds,
    )
    if not result.is_valid:
        logger.error(f"SEV-SNP report verification failed: {result.errors}")
        raise InvalidSignatureError("SEV-SNP report verification failed")
    # Enforce the pinned measurement + policy + min-TCB (raises MeasurementMismatchError if none).
    config = get_matching_measurement_config(quote)
    verify_snp_measurement_constraints(quote, config)

    # GCP image-identity: when the matched config pins vTPM PCRs, require + verify the vTPM quote.
    vtpm_pcrs = getattr(config, "vtpm_pcrs", None)
    if vtpm_pcrs:
        vtpm_result = await _verify_snp_vtpm(
            quote, config, expected_nonce, expected_gcp_identity=expected_gcp_identity
        )
        result.revocation_status.update(vtpm_result.revocation_status)
        result.warnings.extend(vtpm_result.warnings)

    logger.success(
        f"SEV-SNP report verified + measurement matched: measurement={quote.measurement[:16]}..."
        + (" + vTPM image identity" if vtpm_pcrs else "")
    )
    return result


async def _verify_snp_vtpm(
    quote: SnpReport,
    config,
    expected_nonce: str,
    *,
    expected_gcp_identity: Optional[dict] = None,
):
    """Verify the GCE vTPM measured-boot quote attached to a GCP SNP report against pinned PCRs.

    The vTPM quote (AK cert + TPMS_ATTEST + signature + PCRs) is verified by gcp_vtpm (AK chains to
    the pinned Google EK/AK CA Root, RSASSA/SHA256 signature, pcrDigest == sha256(PCRs)); then the
    verified PCRs must equal the config's pinned ``vtpm_pcrs``.

    Channel binding: the quote's qualifying data must equal sha256(nonce || cert_pubkey_hash),
    where cert_pubkey_hash is taken from the SNP report's report_data -- which verify_quote has
    already proven equal to the actual mTLS client cert. This cross-binds the (Google-rooted)
    vTPM image identity to the SAME TLS key the (AMD-rooted) SNP report attests, so an attacker
    cannot relay a victim image's good-PCR vTPM quote alongside their own SNP report.
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

    expected_qualifying_data = hashlib.sha256(
        bytes.fromhex(expected_nonce) + bytes.fromhex(extract_cert_hash(quote))
    ).digest()
    vres = await verify_vtpm_quote(
        ak,
        msg,
        sig,
        pcrs,
        expected_qualifying_data,
        expected_security_flags={
            int(tag): value for tag, value in (config.vtpm_security_flags or {}).items()
        },
        intermediate_der=intermediate,
        redis=settings.redis_client,
        expected_zone=(expected_gcp_identity or {}).get("zone"),
        expected_project_id=(expected_gcp_identity or {}).get("project_id"),
        expected_project_number=(expected_gcp_identity or {}).get("project_number"),
        expected_instance_id=(expected_gcp_identity or {}).get("instance_id"),
        expected_instance_name=(expected_gcp_identity or {}).get("instance_name"),
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
            mismatches.append(
                f"PCR{idx}: expected {expected_hex[:16]}..., got {(actual or '')[:16]}..."
            )
    if mismatches:
        logger.error(f"vTPM PCR mismatch (image identity): {'; '.join(mismatches)}")
        raise MeasurementMismatchError(
            "vTPM PCRs do not match the expected image measurements. "
            "Ensure you are running a supported GCP confidential image."
        )
    return vres


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


async def generate_confirm_nonce(
    capability: LuksCapabilityContext,
    issued_volumes: Dict[str, LuksVolumeRotation],
) -> str:
    """Store an idempotent confirmation capability for exact durable generation leases."""
    nonce = secrets.token_hex(32)
    redis_key = f"luks_confirm_nonce:{nonce}"
    confirm_context = capability.model_copy(
        update={
            "issued_volumes": list(issued_volumes),
            "issued_generations": {
                volume: lease.generation for volume, lease in issued_volumes.items()
            },
            "issued_lease_ids": {
                volume: lease.lease_id for volume, lease in issued_volumes.items()
            },
        }
    )
    await settings.redis_client.setex(redis_key, 300, confirm_context.model_dump_json())
    logger.info(
        f"Generated {capability.purpose.value} confirm capability for server "
        f"{capability.server_id} generations={confirm_context.issued_generations}"
    )
    return nonce


async def generate_luks_quote_nonce(capability: LuksCapabilityContext) -> str:
    """Store a one-use quote capability with immutable server and key-scope context."""
    nonce = secrets.token_hex(32)
    redis_key = f"luks_quote_nonce:{nonce}"
    await settings.redis_client.setex(redis_key, 600, capability.model_dump_json())
    logger.info(
        f"Generated {capability.purpose.value} quote capability for server "
        f"{capability.server_id} volumes={capability.allowed_volumes}"
    )
    return nonce


def _generation_conflict(detail: str) -> None:
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _confirmed_generation(floors: Dict[str, object], volume: str) -> int:
    raw = floors.get(volume, 0)
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        _generation_conflict(f"Stored confirmed generation for volume {volume} is invalid.")
    return raw


def _load_generation_leases(
    vm_config: VmCacheConfig,
) -> Dict[str, LuksVolumeGenerationLease]:
    raw_leases = dict(vm_config.volume_generation_leases or {})
    leases: Dict[str, LuksVolumeGenerationLease] = {}
    for volume, raw_lease in raw_leases.items():
        try:
            leases[volume] = LuksVolumeGenerationLease.model_validate(raw_lease)
        except (TypeError, ValueError) as exc:
            _generation_conflict(f"Stored generation lease for volume {volume} is invalid: {exc}")
    return leases


def _same_stable_lease_identity(
    lease: LuksVolumeGenerationLease, capability: LuksCapabilityContext
) -> bool:
    """Compare the registered identity that survives an ephemeral-certificate reboot."""
    return (
        lease.server_id == capability.server_id
        and lease.miner_hotkey == capability.miner_hotkey
        and lease.vm_name == capability.vm_name
        and lease.measurement_name == capability.measurement_name
        and lease.measurement_version == capability.measurement_version
        and lease.measurement_config_fingerprint == capability.measurement_config_fingerprint
        and lease.trust_set_fingerprint == capability.trust_set_fingerprint
        and lease.tee_type == capability.tee_type
        and lease.purpose == capability.purpose
        and lease.storage_role == capability.storage_role
    )


def allocate_luks_generation_leases(
    vm_config: VmCacheConfig,
    capability: LuksCapabilityContext,
    volume_names: List[str],
) -> Dict[str, LuksVolumeRotation]:
    """Allocate or idempotently reissue one exclusive generation per volume.

    The caller holds a row lock on ``vm_cache_configs``. An unresolved lease is never replaced:
    its pending passphrase and generation are returned again only to the same stable registered
    server, measurement, and role identity. If a real reboot replaces the ephemeral certificate,
    the already-validated current capability atomically takes ownership and fences the prior cert.
    """
    stored: Dict[str, str] = dict(vm_config.volume_passphrases or {})
    floors: Dict[str, object] = dict(vm_config.volume_epochs or {})
    leases = _load_generation_leases(vm_config)
    result: Dict[str, LuksVolumeRotation] = {}

    for volume in volume_names:
        floor = _confirmed_generation(floors, volume)
        current_encrypted = stored.get(volume)
        current = decrypt_passphrase(current_encrypted) if current_encrypted else None
        pending_name = f"pending_{volume}"
        pending_encrypted = stored.get(pending_name)
        lease = leases.get(volume)

        if lease is not None:
            if not _same_stable_lease_identity(lease, capability):
                _generation_conflict(
                    f"Volume {volume} already has an unresolved lease for another "
                    "registered server or measurement identity."
                )
            if lease.generation != floor + 1:
                _generation_conflict(
                    f"Volume {volume} lease generation does not exactly follow its "
                    "confirmed generation."
                )
            if not pending_encrypted:
                _generation_conflict(
                    f"Volume {volume} has an unresolved generation lease without its "
                    "pending passphrase."
                )
            if lease.promotion_required != (current is None):
                _generation_conflict(
                    f"Volume {volume} key-promotion state conflicts with its generation lease."
                )

            if lease.cert_hash != capability.cert_hash:
                lease = lease.model_copy(update={"cert_hash": capability.cert_hash})
                leases[volume] = lease
            pending = decrypt_passphrase(pending_encrypted)
            reused = True
        else:
            # A pre-migration unresolved pending passphrase has no lease metadata. Preserve it and
            # adopt it as floor+1 instead of deleting the only key that may already format the disk.
            if pending_encrypted:
                pending = decrypt_passphrase(pending_encrypted)
                reused = True
            else:
                pending = generate_cache_passphrase()
                stored[pending_name] = encrypt_passphrase(pending)
                reused = False
            lease = LuksVolumeGenerationLease(
                generation=floor + 1,
                lease_id=secrets.token_hex(32),
                server_id=capability.server_id,
                miner_hotkey=capability.miner_hotkey,
                vm_name=capability.vm_name,
                cert_hash=capability.cert_hash,
                measurement_name=capability.measurement_name,
                measurement_version=capability.measurement_version,
                measurement_config_fingerprint=capability.measurement_config_fingerprint,
                trust_set_fingerprint=capability.trust_set_fingerprint,
                tee_type=capability.tee_type,
                purpose=capability.purpose,
                storage_role=capability.storage_role,
                promotion_required=current is None,
            )
            leases[volume] = lease

        result[volume] = LuksVolumeRotation(
            current=current,
            next=pending,
            generation=lease.generation,
            confirmed_generation=floor,
            lease_id=lease.lease_id,
            lease_reused=reused,
        )

    vm_config.volume_passphrases = stored
    vm_config.volume_epochs = floors
    vm_config.volume_generation_leases = {
        volume: lease.model_dump(mode="json") for volume, lease in leases.items()
    }
    return result


async def _get_vm_cache_config_for_update(
    db: AsyncSession,
    miner_hotkey: str,
    vm_name: str,
    *,
    create: bool,
) -> Optional[VmCacheConfig]:
    """Get the VM key-custody row under a database lock, creating it race-safely."""
    if create:
        await db.execute(
            pg_insert(VmCacheConfig)
            .values(
                miner_hotkey=miner_hotkey,
                vm_name=vm_name,
                volume_passphrases={},
                volume_epochs={},
                volume_generation_leases={},
                last_boot_at=func.now(),
            )
            .on_conflict_do_nothing(index_elements=["miner_hotkey", "vm_name"])
        )
    result = await db.execute(
        select(VmCacheConfig)
        .where(
            VmCacheConfig.miner_hotkey == miner_hotkey,
            VmCacheConfig.vm_name == vm_name,
        )
        .with_for_update()
    )
    return result.scalar_one_or_none()


async def lease_luks_passphrases(
    db: AsyncSession,
    capability: LuksCapabilityContext,
    volume_names: List[str],
) -> tuple[Dict[str, LuksVolumeRotation], VmCacheConfig]:
    """Allocate generation leases while serializing every transition on the VM custody row."""
    vm_config = await _get_vm_cache_config_for_update(
        db,
        capability.miner_hotkey,
        capability.vm_name,
        create=True,
    )
    if vm_config is None:
        raise RuntimeError("Failed to create the VM LUKS key-custody row.")

    result = allocate_luks_generation_leases(vm_config, capability, volume_names)
    vm_config.last_boot_at = func.now()
    await db.commit()
    await db.refresh(vm_config)
    logger.info(
        f"LUKS generation lease for VM {capability.vm_name}: "
        f"generations={{{', '.join(f'{volume}: {item.generation}' for volume, item in result.items())}}}"
    )
    return result, vm_config


def confirm_luks_generation_leases(
    vm_config: VmCacheConfig,
    capability: LuksCapabilityContext,
    confirmations: Dict[str, LuksVolumeConfirmStatus],
) -> Dict[str, dict]:
    """Apply exact, idempotent generation confirmations to one locked custody row."""
    stored: Dict[str, str] = dict(vm_config.volume_passphrases or {})
    floors: Dict[str, object] = dict(vm_config.volume_epochs or {})
    leases = _load_generation_leases(vm_config)
    outcomes: Dict[str, dict] = {}

    issued_generations = capability.issued_generations or {}
    issued_lease_ids = capability.issued_lease_ids or {}

    for volume, confirmation in confirmations.items():
        generation = confirmation.generation
        expected_generation = issued_generations.get(volume)
        expected_lease_id = issued_lease_ids.get(volume)
        if generation != expected_generation or not expected_lease_id:
            _generation_conflict(
                f"Confirmation for volume {volume} does not match the issued generation."
            )

        floor = _confirmed_generation(floors, volume)
        lease = leases.get(volume)

        if generation < floor:
            _generation_conflict(
                f"Confirmation generation {generation} for volume {volume} is stale; "
                f"the confirmed generation is {floor}."
            )
        if generation == floor:
            # The exact transition already committed (for example, the HTTP response was dropped).
            # It is queryable and harmless to acknowledge again, but it cannot mutate key state.
            outcomes[volume] = {
                "result": "already_confirmed",
                "generation": generation,
            }
            continue
        if generation != floor + 1:
            _generation_conflict(
                f"Confirmation generation {generation} for volume {volume} does not "
                f"exactly follow confirmed generation {floor}."
            )
        if lease is None:
            _generation_conflict(
                f"Volume {volume} has no unresolved lease for generation {generation}."
            )
        if (
            lease.generation != generation
            or lease.lease_id != expected_lease_id
            or lease.cert_hash != capability.cert_hash
            or not _same_stable_lease_identity(lease, capability)
        ):
            _generation_conflict(
                f"Confirmation for volume {volume} does not own its active generation lease."
            )

        pending_name = f"pending_{volume}"
        if pending_name not in stored:
            _generation_conflict(
                f"Volume {volume} generation lease has no pending passphrase to finalize."
            )
        if lease.promotion_required and not confirmation.rotated:
            _generation_conflict(
                f"Volume {volume} was first-formatted with its pending passphrase and "
                "requires promotion."
            )

        if confirmation.rotated:
            stored[volume] = stored.pop(pending_name)
            result_name = "promoted"
        else:
            stored.pop(pending_name)
            result_name = "confirmed"
        floors[volume] = generation
        leases.pop(volume)
        outcomes[volume] = {"result": result_name, "generation": generation}

    vm_config.volume_passphrases = stored
    vm_config.volume_epochs = floors
    vm_config.volume_generation_leases = {
        volume: lease.model_dump(mode="json") for volume, lease in leases.items()
    }
    return outcomes


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


async def verify_quote(
    quote,
    expected_nonce: str,
    expected_cert_hash: str,
    *,
    expected_gcp_identity: Optional[dict] = None,
):
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
        return await verify_snp_quote(
            quote, expected_nonce, expected_gcp_identity=expected_gcp_identity
        )

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

            verify_gpus_cmd = [
                "chutes-nvattest",
                "--nonce",
                expected_nonce,
                "--evidence",
                fp.name,
            ]

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
