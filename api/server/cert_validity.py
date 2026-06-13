"""Shared X.509 certificate-time validation for the TEE attestation verifiers.

Both the AMD SEV-SNP verifier (snp_verify.py: VCEK->ASK->ARK) and the GCP vTPM verifier
(gcp_vtpm.py: GCE AK -> EK/AK CA Intermediate -> Root) must reject any chain certificate outside
its validity window -- a signature-chain check alone would silently accept an expired/not-yet-valid
cert, extending trust past the issuer's validity period. This is the single implementation both use.
"""

from datetime import datetime, timezone

from cryptography import x509

from api.server.exceptions import InvalidQuoteError


def check_cert_time_valid(cert: x509.Certificate, what: str) -> None:
    """Reject a chain cert outside its validity window (expired or not-yet-valid)."""
    now = datetime.now(timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42: naive UTC datetimes
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before or now > not_after:
        raise InvalidQuoteError(
            f"{what} certificate is outside its validity period "
            f"({not_before.isoformat()} .. {not_after.isoformat()})"
        )
