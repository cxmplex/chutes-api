"""GCP Confidential VM vTPM measured-boot verification.

On GCP, AMD SEV-SNP's hardware report measures only Google's firmware (the managed launch gives no
RTMR3-equivalent), so it cannot attest OUR disk image. Image identity on GCP SNP is therefore
established by the Google-managed vTPM measured boot: the guest emits a TPM2 quote over the boot
PCRs, signed by the GCE Attestation Key (AK), whose cert chains to Google's pinned EK/AK CA Root.
PCR8 (grub-measured kernel cmdline, which carries our dm-verity verity.roothash) and PCR9
(kernel/initrd) are the image-identity registers -- the GCP analog of TDX RTMR3.

TRUST NOTE: the GCE vTPM is Google-managed (software-rooted), so this image-identity layer is
Google-rooted -- it is NOT malicious-host-safe the way TDX's hardware-extended RTMR3 is. SEV-SNP
hardware on GCP simply has no guest-extendable, hardware-signed runtime measurement register. The
SNP report (verified separately) remains the hardware root for "genuine AMD SNP + Google firmware";
this vTPM layer adds verifiable, auditable image identity on top.

Verified end-to-end in pure Python against a real GCE AK quote (tests/assets/snp/gcp-vtpm-quote.json).
"""

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from loguru import logger

from api.server.exceptions import InvalidQuoteError


def _check_cert_time_valid(cert: x509.Certificate, what: str) -> None:
    """Reject a cert outside its validity window (expired or not-yet-valid)."""
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


def _check_cert_is_ca(cert: x509.Certificate, what: str) -> None:
    """Require basicConstraints CA=true on a certificate used as an issuer (intermediate / root)."""
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise InvalidQuoteError(f"{what} certificate has no basicConstraints (expected a CA)")
    if not basic_constraints.ca:
        raise InvalidQuoteError(f"{what} certificate is not a CA (basicConstraints CA=false)")

# Pinned Google EK/AK CA Root (self-signed, valid to 2122). The GCE AK leaf chains to this via the
# per-CA EK/AK CA Intermediate (fetched from the leaf's AIA + cached). This is the trust anchor for
# GCP vTPM image identity -- the analog of pinning AMD's ARK for the SNP report.
GCE_EK_AK_CA_ROOT_PEM = b"""-----BEGIN CERTIFICATE-----
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
av16U4E=
-----END CERTIFICATE-----
"""

# TPM constants.
_TPM_GENERATED_VALUE = 0xFF544347
_TPM_ST_ATTEST_QUOTE = 0x8018
_TPM_ALG_RSASSA = 0x0014
_TPM_ALG_SHA256 = 0x000B


@dataclass
class GcpVtpmResult:
    pcrs: Dict[int, str]  # index -> hex sha256 PCR value (verified)
    status: str
    errors: list = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.status == "VALID" and not self.errors


def _load_root() -> x509.Certificate:
    return x509.load_pem_x509_certificate(GCE_EK_AK_CA_ROOT_PEM)


def _verify_rsa(child_pub, signed: bytes, signature: bytes, hash_alg) -> None:
    child_pub.verify(signature, signed, padding.PKCS1v15(), hash_alg)


def parse_tpms_attest(quote_msg: bytes) -> tuple[bytes, bytes]:
    """Parse a TPMS_ATTEST quote: validate magic + ATTEST_QUOTE type; return (extraData, pcrDigest).

    Layout (big-endian): magic u32 | type u16 | qualifiedSigner TPM2B | extraData TPM2B |
    clockInfo(17) | firmwareVersion(8) | [TPMS_QUOTE_INFO: TPML_PCR_SELECTION | pcrDigest TPM2B].
    """
    try:
        off = 0
        magic = struct.unpack_from(">I", quote_msg, off)[0]
        off += 4
        atype = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        if magic != _TPM_GENERATED_VALUE:
            raise InvalidQuoteError(f"bad TPM magic 0x{magic:08x}")
        if atype != _TPM_ST_ATTEST_QUOTE:
            raise InvalidQuoteError(f"not a TPM quote attestation (type 0x{atype:04x})")
        qs_len = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2 + qs_len
        ed_len = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        extra = quote_msg[off : off + ed_len]
        off += ed_len
        off += 17 + 8  # clockInfo + firmwareVersion
        count = struct.unpack_from(">I", quote_msg, off)[0]
        off += 4
        for _ in range(count):
            off += 2  # hashAlg
            sob = quote_msg[off]
            off += 1 + sob
        pd_len = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        pcr_digest = quote_msg[off : off + pd_len]
        return extra, pcr_digest
    except (struct.error, IndexError) as exc:
        raise InvalidQuoteError(f"malformed TPMS_ATTEST: {exc}")


def _parse_tpmt_signature(quote_sig: bytes) -> bytes:
    """Parse a TPMT_SIGNATURE (RSASSA): sigAlg u16 | hashAlg u16 | TPM2B sig. Returns the raw sig."""
    try:
        sig_alg, hash_alg = struct.unpack_from(">HH", quote_sig, 0)
        if sig_alg != _TPM_ALG_RSASSA:
            raise InvalidQuoteError(f"unsupported TPM sig alg 0x{sig_alg:04x} (expected RSASSA)")
        if hash_alg != _TPM_ALG_SHA256:
            raise InvalidQuoteError(f"unsupported TPM sig hash 0x{hash_alg:04x} (expected SHA256)")
        sig_size = struct.unpack_from(">H", quote_sig, 4)[0]
        return quote_sig[6 : 6 + sig_size]
    except struct.error as exc:
        raise InvalidQuoteError(f"malformed TPMT_SIGNATURE: {exc}")


async def _fetch_intermediate(ak: x509.Certificate, redis=None) -> Optional[x509.Certificate]:
    """Fetch the EK/AK CA Intermediate from the AK leaf's AIA (CA Issuers URI), caching in Redis.

    Mirrors the VCEK-from-KDS fetch+cache pattern. Returns None if the AK has no AIA (then the
    caller must have been supplied the intermediate out-of-band).
    """
    try:
        aia = ak.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    url = next(
        (
            d.access_location.value
            for d in aia
            if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
        ),
        None,
    )
    if not url:
        return None
    cache_key = f"gce:akca:{hashlib.sha256(url.encode()).hexdigest()}"
    if redis is not None:
        cached = await redis.get(cache_key)
        if cached:
            return x509.load_der_x509_certificate(cached)
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30.0)
        resp.raise_for_status()
        der = resp.content
    inter = x509.load_der_x509_certificate(der)
    if redis is not None:
        await redis.set(cache_key, der, ex=86400)
    return inter


async def verify_vtpm_quote(
    ak_cert_der: bytes,
    quote_msg: bytes,
    quote_sig: bytes,
    pcrs: Dict[int, bytes],
    expected_qualifying_data: bytes,
    *,
    intermediate_der: Optional[bytes] = None,
    redis=None,
) -> GcpVtpmResult:
    """Verify a GCE vTPM quote end-to-end.

    Checks: the AK leaf chains to the pinned Google EK/AK CA Root (via the per-CA intermediate,
    supplied or fetched from the leaf AIA); the quote signature (RSASSA/SHA256) verifies against the
    AK; the quote's extraData equals ``expected_qualifying_data`` (freshness + channel binding --
    callers pass sha256(nonce || cert_pubkey_hash) so the vTPM evidence is bound to the same TLS
    identity as the SNP report, not just the nonce); and the quoted pcrDigest equals sha256(concat
    of the provided PCR values, ascending index). Returns the verified PCRs; the caller compares
    them to the pinned per-image expected PCRs.
    """
    result = GcpVtpmResult(pcrs={str(i): v.hex().upper() for i, v in pcrs.items()}, status="INVALID")
    try:
        ak = x509.load_der_x509_certificate(ak_cert_der)
        if not isinstance(ak.public_key(), rsa.RSAPublicKey):
            raise InvalidQuoteError("GCE AK is not an RSA key")
        root = _load_root()

        inter = (
            x509.load_der_x509_certificate(intermediate_der)
            if intermediate_der
            else await _fetch_intermediate(ak, redis=redis)
        )
        if inter is None:
            raise InvalidQuoteError("could not obtain the EK/AK CA Intermediate for the AK")

        # Reject expired/not-yet-valid certs, and require the issuers to actually be CAs (a
        # signature chain alone would accept an in-window leaf misused as an issuer).
        _check_cert_time_valid(ak, "GCE AK")
        _check_cert_time_valid(inter, "EK/AK CA Intermediate")
        _check_cert_time_valid(root, "Google EK/AK CA Root")
        _check_cert_is_ca(inter, "EK/AK CA Intermediate")
        _check_cert_is_ca(root, "Google EK/AK CA Root")

        # Chain: AK <- intermediate <- pinned root (root self-signed). Any break => not valid.
        try:
            _verify_rsa(inter.public_key(), ak.tbs_certificate_bytes, ak.signature, ak.signature_hash_algorithm)
            _verify_rsa(root.public_key(), inter.tbs_certificate_bytes, inter.signature, inter.signature_hash_algorithm)
            _verify_rsa(root.public_key(), root.tbs_certificate_bytes, root.signature, root.signature_hash_algorithm)
        except InvalidSignature:
            raise InvalidQuoteError("AK certificate does not chain to the pinned Google EK/AK CA Root")

        # Quote signature over the TPMS_ATTEST message.
        sig = _parse_tpmt_signature(quote_sig)
        try:
            _verify_rsa(ak.public_key(), quote_msg, sig, hashes.SHA256())
        except InvalidSignature:
            raise InvalidQuoteError("vTPM quote signature is invalid (AK did not sign it)")

        extra, pcr_digest = parse_tpms_attest(quote_msg)
        if extra != expected_qualifying_data:
            raise InvalidQuoteError(
                "vTPM quote qualifying-data mismatch (stale/replayed quote, or evidence "
                "bound to a different nonce/TLS identity)"
            )

        concat = b"".join(pcrs[i] for i in sorted(pcrs))
        if hashlib.sha256(concat).digest() != pcr_digest:
            raise InvalidQuoteError("vTPM quote pcrDigest does not match the provided PCR values")

        result.status = "VALID"
        logger.success(
            f"GCE vTPM quote verified: AK={ak.subject.rfc4514_string()[:40]}... "
            f"PCR8={pcrs.get(8, b'').hex()[:16]}... PCR9={pcrs.get(9, b'').hex()[:16]}..."
        )
    except Exception as exc:  # noqa: BLE001 - any failure => not valid
        result.errors.append(str(exc))
        logger.error(f"GCE vTPM quote verification failed: {exc}")
    return result
