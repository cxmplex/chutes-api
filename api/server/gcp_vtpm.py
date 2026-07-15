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

import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from loguru import logger

from api.server.cert_validity import check_cert_time_valid
from api.server.exceptions import InvalidQuoteError

_GOOGLE_PRIVATE_CA_HOST = re.compile(r"^privateca-content-[a-z0-9-]+\.storage\.googleapis\.com$")
_MAX_GOOGLE_CA_OBJECT_BYTES = 1024 * 1024
_MAX_GOOGLE_CA_HEADER_BYTES = 64 * 1024
_GOOGLE_EK_AK_INTERMEDIATE_SPKI_SHA256 = {
    # Google EK/AK CA Intermediate used by the checked-in real GCP SNP AK fixture.
    # Rotation is an explicit trust-root update, never an AIA-selected implicit trust change.
    "5c808bf682efecd8d3ca93496bbecefce4967891e8e47b14b973b39a872b618d",
}
_GOOGLE_ATTESTATION_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.21")
_TCG_TPM_AIK_EKU_OID = ObjectIdentifier("2.23.133.8.1")


def _validate_google_ca_url(url: str) -> str:
    """Allow only direct Google Private CA objects used by GCE EK/AK certificates."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise InvalidQuoteError("GCE certificate contains an invalid CA URL") from exc
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme not in {"http", "https"}
        or not _GOOGLE_PRIVATE_CA_HOST.fullmatch(host)
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or any(segment in {"", ".", ".."} for segment in parsed.path.split("/")[1:])
    ):
        raise InvalidQuoteError("GCE certificate CA URL is outside the Google Private CA allowlist")
    return url


async def _public_google_ca_addresses(host: str) -> list[str]:
    """Resolve once and return only public addresses used directly for the connection."""
    loop = asyncio.get_running_loop()
    try:
        answers = await loop.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise InvalidQuoteError("GCE certificate CA hostname did not resolve") from exc
    addresses = sorted({str(answer[4][0]) for answer in answers})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise InvalidQuoteError("GCE certificate CA hostname resolved to a non-public address")
    return addresses


async def _read_google_ca_response_body(
    reader: asyncio.StreamReader, headers: dict[str, str]
) -> bytes:
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length = headers.get("content-length")
    chunks: list[bytes] = []
    size = 0

    async def append(chunk: bytes) -> None:
        nonlocal size
        size += len(chunk)
        if size > _MAX_GOOGLE_CA_OBJECT_BYTES:
            raise InvalidQuoteError("Google Private CA object is too large")
        chunks.append(chunk)

    if "chunked" in transfer_encoding:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            try:
                chunk_size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise InvalidQuoteError(
                    "Google Private CA returned invalid chunked encoding"
                ) from exc
            if chunk_size < 0 or chunk_size > _MAX_GOOGLE_CA_OBJECT_BYTES - size:
                raise InvalidQuoteError("Google Private CA object is too large")
            if chunk_size == 0:
                while await asyncio.wait_for(reader.readline(), timeout=10.0) not in (
                    b"\r\n",
                    b"",
                ):
                    pass
                break
            await append(await asyncio.wait_for(reader.readexactly(chunk_size), timeout=10.0))
            if await asyncio.wait_for(reader.readexactly(2), timeout=10.0) != b"\r\n":
                raise InvalidQuoteError("Google Private CA returned invalid chunk framing")
    elif content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise InvalidQuoteError("Google Private CA returned invalid Content-Length") from exc
        if length < 0 or length > _MAX_GOOGLE_CA_OBJECT_BYTES:
            raise InvalidQuoteError("Google Private CA object is too large")
        await append(await asyncio.wait_for(reader.readexactly(length), timeout=10.0))
    else:
        while True:
            chunk = await asyncio.wait_for(reader.read(64 * 1024), timeout=10.0)
            if not chunk:
                break
            await append(chunk)
    return b"".join(chunks)


async def _request_google_ca_address(
    url: str,
    address: str,
    *,
    method: str,
    body: bytes,
    content_type: Optional[str],
) -> bytes:
    """Connect to the already-vetted address, preserving Host/SNI without another DNS lookup."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    use_tls = parsed.scheme == "https"
    ssl_context = ssl.create_default_context() if use_tls else None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                443 if use_tls else 80,
                ssl=ssl_context,
                server_hostname=host if use_tls else None,
            ),
            timeout=10.0,
        )
        request_headers = [
            f"{method} {parsed.path} HTTP/1.1",
            f"Host: {host}",
            "Accept: */*",
            "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        if content_type:
            request_headers.append(f"Content-Type: {content_type}")
        writer.write(("\r\n".join(request_headers) + "\r\n\r\n").encode("ascii") + body)
        await asyncio.wait_for(writer.drain(), timeout=10.0)

        status_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        try:
            _http_version, status_text, _reason = status_line.decode("iso-8859-1").split(" ", 2)
            status_code = int(status_text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise InvalidQuoteError(
                "Google Private CA returned an invalid HTTP status line"
            ) from exc
        headers: dict[str, str] = {}
        header_bytes = len(status_line)
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            header_bytes += len(line)
            if header_bytes > _MAX_GOOGLE_CA_HEADER_BYTES:
                raise InvalidQuoteError("Google Private CA response headers are too large")
            if line in (b"\r\n", b""):
                break
            try:
                name, value = line.decode("iso-8859-1").split(":", 1)
            except (UnicodeDecodeError, ValueError) as exc:
                raise InvalidQuoteError("Google Private CA returned malformed headers") from exc
            headers[name.strip().lower()] = value.strip()
        if status_code != 200:
            raise InvalidQuoteError(
                f"Google Private CA object returned HTTP {status_code}; redirects are forbidden"
            )
        return await _read_google_ca_response_body(reader, headers)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as exc:
        raise InvalidQuoteError(f"Google Private CA fetch failed: {exc}") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


async def _fetch_google_ca_object(
    url: str,
    *,
    redis=None,
    cache_prefix: str,
    force_refresh: bool = False,
    method: str = "GET",
    body: bytes = b"",
    content_type: Optional[str] = None,
) -> bytes:
    url = _validate_google_ca_url(url)
    host = urlsplit(url).hostname
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise InvalidQuoteError("Unsupported Google Private CA request method")
    cache_material = method.encode() + b"\0" + url.encode() + b"\0" + body
    cache_key = f"{cache_prefix}:{hashlib.sha256(cache_material).hexdigest()}"
    if redis is not None and method == "GET" and not force_refresh:
        cached = await redis.get(cache_key)
        if cached:
            return cached
    addresses = await _public_google_ca_addresses(host)
    failures = []
    content = b""
    for address in addresses:
        try:
            content = await _request_google_ca_address(
                url,
                address,
                method=method,
                body=body,
                content_type=content_type,
            )
            break
        except InvalidQuoteError as exc:
            failures.append(str(exc))
    if not content and failures:
        raise InvalidQuoteError("; ".join(failures))
    if not content:
        raise InvalidQuoteError("Google Private CA object is empty")
    if redis is not None and method == "GET":
        await redis.set(cache_key, content, ex=86400)
    return content


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
_GOOGLE_SECURITY_FLAG_TAGS = frozenset({2, 3, 4, 5})


@dataclass
class GcpVtpmResult:
    pcrs: Dict[str, str]  # stringified index -> hex sha256 PCR value (verified)
    status: str
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    revocation_status: Dict[str, str] = field(default_factory=dict)
    instance_identity: Optional[dict] = None

    @property
    def is_valid(self) -> bool:
        return self.status == "VALID" and not self.errors


def _load_root() -> x509.Certificate:
    return x509.load_pem_x509_certificate(GCE_EK_AK_CA_ROOT_PEM)


def _spki_sha256(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _certificate_lifetime(cert: x509.Certificate):
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return (
            cert.not_valid_before.replace(tzinfo=timezone.utc),
            cert.not_valid_after.replace(tzinfo=timezone.utc),
        )


@dataclass(frozen=True)
class GcpInstanceIdentity:
    zone: str
    project_number: int
    project_id: str
    instance_id: int
    instance_name: str
    security_version: int
    is_production: bool
    security_flags: Dict[int, bool]

    def to_dict(self) -> dict:
        return {
            "zone": self.zone,
            "project_number": self.project_number,
            "project_id": self.project_id,
            "instance_id": self.instance_id,
            "instance_name": self.instance_name,
            "security_version": self.security_version,
            "is_production": self.is_production,
            "security_flags": dict(self.security_flags),
        }


def _der_tlv(data: bytes, offset: int, expected_tag: Optional[int] = None):
    if offset >= len(data):
        raise InvalidQuoteError("GCE AK Google attestation extension is truncated")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise InvalidQuoteError("GCE AK Google attestation extension uses an unsupported DER tag")
    if offset >= len(data):
        raise InvalidQuoteError("GCE AK Google attestation extension is truncated")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or offset + length_bytes > len(data):
            raise InvalidQuoteError("GCE AK Google attestation extension has an invalid DER length")
        if data[offset] == 0:
            raise InvalidQuoteError(
                "GCE AK Google attestation extension has a non-canonical DER length"
            )
        length = int.from_bytes(data[offset : offset + length_bytes], "big")
        offset += length_bytes
        if length < 128:
            raise InvalidQuoteError(
                "GCE AK Google attestation extension has a non-canonical DER length"
            )
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise InvalidQuoteError("GCE AK Google attestation extension is truncated")
    if expected_tag is not None and tag != expected_tag:
        raise InvalidQuoteError("GCE AK Google attestation extension has an unexpected ASN.1 field")
    return tag, data[offset:end], end


def _der_utf8(data: bytes, offset: int) -> tuple[str, int]:
    _tag, raw, offset = _der_tlv(data, offset, 0x0C)
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidQuoteError(
            "GCE AK Google attestation extension contains invalid UTF-8"
        ) from exc
    if not value or any(ord(character) < 0x20 for character in value):
        raise InvalidQuoteError(
            "GCE AK Google attestation extension contains an empty/control identity field"
        )
    return value, offset


def _der_integer(data: bytes, offset: int) -> tuple[int, int]:
    _tag, raw, offset = _der_tlv(data, offset, 0x02)
    if (
        not raw
        or len(raw) > 9
        or raw[0] & 0x80
        or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80)
    ):
        raise InvalidQuoteError(
            "GCE AK Google attestation extension contains an invalid/non-canonical integer"
        )
    value = int.from_bytes(raw, "big")
    if value > 0xFFFFFFFFFFFFFFFF:
        raise InvalidQuoteError("GCE AK Google attestation identity integer exceeds uint64")
    return value, offset


def _der_explicit_integer(data: bytes, offset: int, tag: int) -> tuple[int, int]:
    _tag, value, offset = _der_tlv(data, offset, tag)
    result, inner_end = _der_integer(value, 0)
    if inner_end != len(value):
        raise InvalidQuoteError("GCE AK Google security property has trailing ASN.1 data")
    return result, offset


def _der_explicit_boolean(data: bytes, offset: int, tag: int) -> tuple[bool, int]:
    _tag, value, offset = _der_tlv(data, offset, tag)
    _inner_tag, raw, inner_end = _der_tlv(value, 0, 0x01)
    if inner_end != len(value) or len(raw) != 1 or raw[0] not in (0x00, 0xFF):
        raise InvalidQuoteError("GCE AK Google security property is not a canonical DER BOOLEAN")
    return raw[0] == 0xFF, offset


def _parse_google_instance_identity(raw: bytes) -> GcpInstanceIdentity:
    _tag, sequence, end = _der_tlv(raw, 0, 0x30)
    if end != len(raw):
        raise InvalidQuoteError("GCE AK Google attestation extension has trailing DER data")
    offset = 0
    zone, offset = _der_utf8(sequence, offset)
    project_number, offset = _der_integer(sequence, offset)
    project_id, offset = _der_utf8(sequence, offset)
    instance_id, offset = _der_integer(sequence, offset)
    instance_name, offset = _der_utf8(sequence, offset)
    if offset >= len(sequence):
        raise InvalidQuoteError(
            "GCE AK Google attestation extension omits mandatory security properties"
        )

    _security_tag, security_wrapper, offset = _der_tlv(sequence, offset, 0xA0)
    if offset != len(sequence):
        raise InvalidQuoteError(
            "GCE AK Google attestation extension has unexpected identity fields"
        )
    _sequence_tag, security, security_end = _der_tlv(security_wrapper, 0, 0x30)
    if security_end != len(security_wrapper):
        raise InvalidQuoteError("GCE AK Google security properties have trailing DER data")

    security_offset = 0
    security_version, security_offset = _der_explicit_integer(security, security_offset, 0xA0)
    is_production, security_offset = _der_explicit_boolean(security, security_offset, 0xA1)
    security_flags: Dict[int, bool] = {}
    previous_tag = 1
    while security_offset < len(security):
        encoded_tag = security[security_offset]
        tag_number = encoded_tag - 0xA0
        if encoded_tag < 0xA2 or encoded_tag > 0xA5 or tag_number <= previous_tag:
            raise InvalidQuoteError(
                "GCE AK Google security properties contain unknown, duplicate, or "
                "out-of-order flags"
            )
        value, security_offset = _der_explicit_boolean(security, security_offset, encoded_tag)
        security_flags[tag_number] = value
        previous_tag = tag_number

    if set(security_flags) != _GOOGLE_SECURITY_FLAG_TAGS:
        raise InvalidQuoteError(
            "GCE AK Google security properties must contain exactly signed flag tags 2, 3, 4, and 5"
        )
    if security_version != 0:
        raise InvalidQuoteError(
            f"GCE AK Google security profile version {security_version} is unsupported"
        )
    if not is_production:
        raise InvalidQuoteError("GCE AK Google attestation identity is not production")
    return GcpInstanceIdentity(
        zone=zone,
        project_number=project_number,
        project_id=project_id,
        instance_id=instance_id,
        instance_name=instance_name,
        security_version=security_version,
        is_production=is_production,
        security_flags=security_flags,
    )


def _single_subject_value(ak: x509.Certificate, oid: ObjectIdentifier, what: str) -> str:
    values = ak.subject.get_attributes_for_oid(oid)
    if len(values) != 1 or not values[0].value:
        raise InvalidQuoteError(f"GCE AK subject has no unique {what}")
    if not isinstance(values[0].value, str):
        raise InvalidQuoteError(f"GCE AK subject {what} is not a string")
    return values[0].value


def _check_google_ak_constraints(ak: x509.Certificate) -> GcpInstanceIdentity:
    """Enforce the signed Google AK profile when the leaf publishes no revocation mechanism."""
    try:
        basic = ak.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = ak.extensions.get_extension_for_class(x509.KeyUsage).value
        attestation = ak.extensions.get_extension_for_oid(_GOOGLE_ATTESTATION_EXTENSION_OID).value
    except x509.ExtensionNotFound as exc:
        raise InvalidQuoteError("GCE AK is missing mandatory certificate constraints") from exc
    if basic.ca:
        raise InvalidQuoteError("GCE AK must be a leaf certificate (CA=false)")
    encipher_only = usage.encipher_only if usage.key_agreement else None
    decipher_only = usage.decipher_only if usage.key_agreement else None
    if (
        not usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or usage.key_cert_sign
        or usage.crl_sign
        or encipher_only is not None
        or decipher_only is not None
    ):
        raise InvalidQuoteError("GCE AK keyUsage is not restricted to attestation signing")
    if (
        _single_subject_value(ak, NameOID.ORGANIZATION_NAME, "organization")
        != "Google Compute Engine"
    ):
        raise InvalidQuoteError(
            "GCE AK subject is not a Google Compute Engine attestation identity"
        )
    raw_attestation = getattr(attestation, "value", b"")
    identity = _parse_google_instance_identity(raw_attestation)
    if _single_subject_value(ak, NameOID.LOCALITY_NAME, "zone") != identity.zone:
        raise InvalidQuoteError("GCE AK subject zone disagrees with its signed instance identity")
    if (
        _single_subject_value(ak, NameOID.ORGANIZATIONAL_UNIT_NAME, "project")
        != identity.project_id
    ):
        raise InvalidQuoteError(
            "GCE AK subject project disagrees with its signed instance identity"
        )
    if _single_subject_value(ak, NameOID.COMMON_NAME, "instance ID") != str(identity.instance_id):
        raise InvalidQuoteError(
            "GCE AK subject instance ID disagrees with its signed instance identity"
        )
    not_before, not_after = _certificate_lifetime(ak)
    if (not_after - not_before).days > 31 * 366:
        raise InvalidQuoteError("GCE AK certificate lifetime exceeds the pinned profile")
    return identity


def _check_google_security_flag_policy(
    identity: GcpInstanceIdentity, expected_security_flags: Dict[int, bool]
) -> None:
    if (
        not isinstance(expected_security_flags, dict)
        or set(expected_security_flags) != _GOOGLE_SECURITY_FLAG_TAGS
        or any(
            not isinstance(tag, int) or isinstance(tag, bool) or not isinstance(value, bool)
            for tag, value in expected_security_flags.items()
        )
    ):
        raise InvalidQuoteError(
            "Expected GCE AK security flags must contain exactly boolean tags 2, 3, 4, and 5"
        )
    if identity.security_flags != expected_security_flags:
        raise InvalidQuoteError(
            "GCE AK signed security flags do not match the expected measurement policy"
        )


def _check_google_intermediate_constraints(inter: x509.Certificate) -> None:
    if _spki_sha256(inter) not in _GOOGLE_EK_AK_INTERMEDIATE_SPKI_SHA256:
        raise InvalidQuoteError(
            "EK/AK CA Intermediate public key is not in the pinned Google SPKI set"
        )
    try:
        usage = inter.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = inter.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise InvalidQuoteError(
            "EK/AK CA Intermediate is missing mandatory key constraints"
        ) from exc
    if not usage.key_cert_sign or not usage.crl_sign or usage.digital_signature:
        raise InvalidQuoteError("EK/AK CA Intermediate keyUsage is invalid")
    if _TCG_TPM_AIK_EKU_OID not in eku:
        raise InvalidQuoteError("EK/AK CA Intermediate lacks the pinned TPM AIK EKU")


def _verify_rsa(child_pub, signed: bytes, signature: bytes, hash_alg) -> None:
    child_pub.verify(signature, signed, padding.PKCS1v15(), hash_alg)


def _decode_pcr_select(pcr_select: bytes) -> set[int]:
    """Decode a TPMS_PCR_SELECTION bitmap into the set of selected PCR indices (LSB-first per byte)."""
    indices: set[int] = set()
    for byte_index, byte in enumerate(pcr_select):
        for bit in range(8):
            if byte & (1 << bit):
                indices.add(byte_index * 8 + bit)
    return indices


def parse_tpms_attest(quote_msg: bytes) -> tuple[bytes, bytes, Dict[int, set]]:
    """Parse a TPMS_ATTEST quote: validate magic + ATTEST_QUOTE type.

    Returns (extraData, pcrDigest, selections) where selections maps each quoted bank's TPM hash alg
    id -> the set of PCR indices it covers (L3: the caller asserts the pinned indices/bank are the
    ones actually quoted, so the signed pcrDigest cannot be over a different bank/index set).

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
        off += 2
        if off + qs_len > len(quote_msg):
            raise InvalidQuoteError("malformed TPMS_ATTEST qualifiedSigner")
        off += qs_len
        ed_len = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        if off + ed_len > len(quote_msg):
            raise InvalidQuoteError("malformed TPMS_ATTEST extraData")
        extra = quote_msg[off : off + ed_len]
        off += ed_len
        if off + 17 + 8 > len(quote_msg):
            raise InvalidQuoteError("malformed TPMS_ATTEST clock/firmware fields")
        off += 17 + 8  # clockInfo + firmwareVersion
        count = struct.unpack_from(">I", quote_msg, off)[0]
        off += 4
        if not 1 <= count <= 16:
            raise InvalidQuoteError("malformed TPMS_ATTEST PCR selection count")
        selections: Dict[int, set] = {}
        for _ in range(count):
            hash_alg = struct.unpack_from(">H", quote_msg, off)[0]
            off += 2
            if hash_alg in selections:
                raise InvalidQuoteError("duplicate TPM PCR bank selection")
            sob = quote_msg[off]
            off += 1
            if not 1 <= sob <= 4 or off + sob > len(quote_msg):
                raise InvalidQuoteError("malformed TPMS_ATTEST PCR bitmap")
            pcr_select = quote_msg[off : off + sob]
            off += sob
            selections[hash_alg] = _decode_pcr_select(pcr_select)
        pd_len = struct.unpack_from(">H", quote_msg, off)[0]
        off += 2
        if pd_len != hashlib.sha256().digest_size or off + pd_len != len(quote_msg):
            raise InvalidQuoteError("malformed TPMS_ATTEST PCR digest size or trailing data")
        pcr_digest = quote_msg[off : off + pd_len]
        return extra, pcr_digest, selections
    except (struct.error, IndexError) as exc:
        raise InvalidQuoteError(f"malformed TPMS_ATTEST: {exc}")


def _validate_pcr_selection(selections: Dict[int, set[int]], pcrs: Dict[int, bytes]) -> None:
    if set(selections) != {_TPM_ALG_SHA256}:
        raise InvalidQuoteError("vTPM quote must contain exactly one SHA256 PCR bank selection")
    sha256_selection = selections[_TPM_ALG_SHA256]
    if sha256_selection != set(pcrs):
        raise InvalidQuoteError(
            "vTPM quote SHA256 PCR selection "
            f"{sorted(sha256_selection)} does not match the provided PCR indices "
            f"{sorted(pcrs)}"
        )


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
    der = await _fetch_google_ca_object(url, redis=redis, cache_prefix="gce:akca")
    return x509.load_der_x509_certificate(der)


def _certificate_crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for point in points:
        if point.full_name is None:
            continue
        urls.extend(
            name.value
            for name in point.full_name
            if isinstance(name, x509.UniformResourceIdentifier)
        )
    return urls


def _certificate_ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [
        description.access_location.value
        for description in aia
        if description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
        and isinstance(description.access_location, x509.UniformResourceIdentifier)
    ]


def _check_google_crl_freshness(crl: x509.CertificateRevocationList) -> None:
    now = datetime.now(timezone.utc)
    try:
        last_update = crl.last_update_utc
        next_update = crl.next_update_utc
    except AttributeError:
        last_update = crl.last_update.replace(tzinfo=timezone.utc)
        next_update = (
            crl.next_update.replace(tzinfo=timezone.utc) if crl.next_update is not None else None
        )
    if last_update > now or next_update is None or now > next_update:
        raise InvalidQuoteError("Google EK/AK revocation list is not current")


def _ocsp_time(response, name: str):
    value = getattr(response, f"{name}_utc", None)
    if value is not None:
        return value
    value = getattr(response, name, None)
    return value.replace(tzinfo=timezone.utc) if value is not None else None


def _verify_ocsp_signature(response, issuer: x509.Certificate) -> None:
    candidates = [issuer, *list(response.certificates)]
    for candidate in candidates:
        try:
            if candidate is not issuer:
                check_cert_time_valid(candidate, "delegated OCSP responder")
                _verify_rsa(
                    issuer.public_key(),
                    candidate.tbs_certificate_bytes,
                    candidate.signature,
                    candidate.signature_hash_algorithm,
                )
                eku = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    continue
            _verify_rsa(
                candidate.public_key(),
                response.tbs_response_bytes,
                response.signature,
                response.signature_hash_algorithm,
            )
            return
        except (InvalidSignature, x509.ExtensionNotFound):
            continue
    raise InvalidQuoteError("Google OCSP response signature is not authenticated by the issuer")


async def _check_google_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    url: str,
    what: str,
    *,
    redis=None,
) -> None:
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()
    content = await _fetch_google_ca_object(
        url,
        redis=redis,
        cache_prefix="gce:ocsp",
        method="POST",
        body=request.public_bytes(serialization.Encoding.DER),
        content_type="application/ocsp-request",
    )
    try:
        response = ocsp.load_der_ocsp_response(content)
    except ValueError as exc:
        raise InvalidQuoteError(f"{what} OCSP response is malformed") from exc
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise InvalidQuoteError(f"{what} OCSP responder returned {response.response_status.name}")
    _verify_ocsp_signature(response, issuer)
    now = datetime.now(timezone.utc)
    this_update = _ocsp_time(response, "this_update")
    next_update = _ocsp_time(response, "next_update")
    if (
        response.serial_number != cert.serial_number
        or this_update is None
        or this_update > now
        or next_update is None
        or now > next_update
    ):
        raise InvalidQuoteError(
            f"{what} OCSP response is not current or targets another certificate"
        )
    if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        raise InvalidQuoteError(f"{what} certificate is revoked")
    if response.certificate_status != ocsp.OCSPCertStatus.GOOD:
        raise InvalidQuoteError(f"{what} OCSP status is unknown")


async def _check_google_certificate_revocation(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    what: str,
    *,
    redis=None,
) -> str:
    urls = _certificate_crl_urls(cert)
    ocsp_urls = _certificate_ocsp_urls(cert)
    if not urls and not ocsp_urls:
        return "revocation_not_advertised"
    failures = []
    for url in urls:
        try:
            der = await _fetch_google_ca_object(url, redis=redis, cache_prefix="gce:crl")
            try:
                crl = x509.load_der_x509_crl(der)
            except ValueError:
                crl = x509.load_pem_x509_crl(der)
            try:
                _check_google_crl_freshness(crl)
            except InvalidQuoteError:
                der = await _fetch_google_ca_object(
                    url,
                    redis=redis,
                    cache_prefix="gce:crl",
                    force_refresh=True,
                )
                try:
                    crl = x509.load_der_x509_crl(der)
                except ValueError:
                    crl = x509.load_pem_x509_crl(der)
                _check_google_crl_freshness(crl)
            issuer_key = issuer.public_key()
            if not isinstance(issuer_key, rsa.RSAPublicKey) or not crl.is_signature_valid(
                issuer_key
            ):
                raise InvalidQuoteError(f"{what} revocation list has an invalid issuer signature")
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                raise InvalidQuoteError(f"{what} certificate is revoked")
            return "good"
        except Exception as exc:  # try another authenticated distribution point
            if "certificate is revoked" in str(exc):
                raise
            failures.append(str(exc))
    for url in ocsp_urls:
        try:
            await _check_google_ocsp(cert, issuer, url, what, redis=redis)
            return "good"
        except Exception as exc:
            if "certificate is revoked" in str(exc):
                raise
            failures.append(str(exc))
    raise InvalidQuoteError(
        f"Could not establish fresh revocation status for {what}: {'; '.join(failures)}"
    )


async def verify_vtpm_quote(
    ak_cert_der: bytes,
    quote_msg: bytes,
    quote_sig: bytes,
    pcrs: Dict[int, bytes],
    expected_qualifying_data: bytes,
    *,
    expected_security_flags: Dict[int, bool],
    intermediate_der: Optional[bytes] = None,
    redis=None,
    expected_zone: Optional[str] = None,
    expected_project_id: Optional[str] = None,
    expected_project_number: Optional[int] = None,
    expected_instance_id: Optional[int] = None,
    expected_instance_name: Optional[str] = None,
) -> GcpVtpmResult:
    """Verify a GCE vTPM quote end-to-end.

    Checks: the AK leaf chains to the pinned Google EK/AK CA Root (via the per-CA intermediate,
    supplied or fetched from the leaf AIA); the quote signature (RSASSA/SHA256) verifies against the
    AK; the quote's extraData equals ``expected_qualifying_data`` (freshness + channel binding --
    callers pass sha256(nonce || cert_pubkey_hash) so the vTPM evidence is bound to the same TLS
    identity as the SNP report, not just the nonce); the signed Google security flag map exactly
    equals the per-measurement policy; and the quoted pcrDigest equals sha256(concat of the provided
    PCR values, ascending index). Returns the verified PCRs; the caller compares them to the pinned
    per-image expected PCRs.
    """
    result = GcpVtpmResult(
        pcrs={str(i): v.hex().upper() for i, v in pcrs.items()}, status="INVALID"
    )
    try:
        if not pcrs or any(
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index <= 31
            or not isinstance(value, bytes)
            or len(value) != hashlib.sha256().digest_size
            for index, value in pcrs.items()
        ):
            raise InvalidQuoteError(
                "vTPM PCR values must be a non-empty map of integer indices to 32-byte SHA256 values"
            )
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
        check_cert_time_valid(ak, "GCE AK")
        check_cert_time_valid(inter, "EK/AK CA Intermediate")
        check_cert_time_valid(root, "Google EK/AK CA Root")
        _check_cert_is_ca(inter, "EK/AK CA Intermediate")
        _check_cert_is_ca(root, "Google EK/AK CA Root")
        identity = _check_google_ak_constraints(ak)
        result.instance_identity = identity.to_dict()
        _check_google_security_flag_policy(identity, expected_security_flags)
        expected_identity = {
            "zone": expected_zone,
            "project_id": expected_project_id,
            "project_number": expected_project_number,
            "instance_id": expected_instance_id,
            "instance_name": expected_instance_name,
        }
        for field_name, expected_value in expected_identity.items():
            if expected_value is not None and getattr(identity, field_name) != expected_value:
                raise InvalidQuoteError(
                    f"GCE AK signed {field_name} does not match the expected instance identity"
                )
        _check_google_intermediate_constraints(inter)

        # Chain: AK <- intermediate <- pinned root (root self-signed). Any break => not valid.
        try:
            _verify_rsa(
                inter.public_key(),
                ak.tbs_certificate_bytes,
                ak.signature,
                ak.signature_hash_algorithm,
            )
            _verify_rsa(
                root.public_key(),
                inter.tbs_certificate_bytes,
                inter.signature,
                inter.signature_hash_algorithm,
            )
            _verify_rsa(
                root.public_key(),
                root.tbs_certificate_bytes,
                root.signature,
                root.signature_hash_algorithm,
            )
        except InvalidSignature:
            raise InvalidQuoteError(
                "AK certificate does not chain to the pinned Google EK/AK CA Root"
            )

        ak_revocation = await _check_google_certificate_revocation(ak, inter, "GCE AK", redis=redis)
        intermediate_revocation = await _check_google_certificate_revocation(
            inter, root, "EK/AK CA Intermediate", redis=redis
        )
        result.revocation_status = {
            "gce_ak": ak_revocation,
            "ek_ak_ca_intermediate": intermediate_revocation,
        }
        for name, revocation_status in result.revocation_status.items():
            if revocation_status == "revocation_not_advertised":
                warning = (
                    f"{name} revocation_not_advertised; revocation was not checked. Enforced "
                    "pinned SPKI, certificate time, key usage, and Google attestation-extension "
                    "constraints instead"
                )
                result.warnings.append(warning)
                logger.warning(warning)

        # Quote signature over the TPMS_ATTEST message.
        sig = _parse_tpmt_signature(quote_sig)
        try:
            _verify_rsa(ak.public_key(), quote_msg, sig, hashes.SHA256())
        except InvalidSignature:
            raise InvalidQuoteError("vTPM quote signature is invalid (AK did not sign it)")

        extra, pcr_digest, selections = parse_tpms_attest(quote_msg)
        if extra != expected_qualifying_data:
            raise InvalidQuoteError(
                "vTPM quote qualifying-data mismatch (stale/replayed quote, or evidence "
                "bound to a different nonce/TLS identity)"
            )

        # L3: assert the quote's TPML_PCR_SELECTION actually covers EXACTLY the provided PCR indices
        # in the SHA256 bank, so the signed pcrDigest is over the pinned indices/bank and not some
        # other selection whose digest happens to be reproduced. (The digest check below + the
        # caller's per-index pin already compensate; this makes the binding explicit + fail-closed.)
        _validate_pcr_selection(selections, pcrs)

        # TPM computes pcrDigest over the selected PCRs in ascending index order (single SHA256 bank).
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
