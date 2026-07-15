import asyncio
import base64
import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from api.config import MAX_SNP_CRL_OUTAGE_GRACE_SECONDS, Settings
from api.server import gcp_vtpm, snp_verify
from api.server.exceptions import InvalidQuoteError
from api.server.quote import TdxQuote


GOOGLE_CA_URL = (
    "http://privateca-content-01234567-0000-1111-2222-0123456789ab."
    "storage.googleapis.com/path/ca.crt"
)


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    subject_key,
    issuer_key,
    *,
    subject,
    issuer,
    is_ca,
    crl_url=GOOGLE_CA_URL,
    ocsp_url=None,
):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _crl(
    issuer_cert,
    issuer_key,
    *,
    expired=False,
    future=False,
    revoked=None,
):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now + timedelta(minutes=1) if future else now - timedelta(hours=2))
    )
    builder = builder.next_update(
        now + timedelta(hours=2)
        if future
        else (now - timedelta(minutes=1) if expired else now + timedelta(hours=2))
    )
    if revoked is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(now - timedelta(minutes=1))
            .build()
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _snp_chain():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    return key, issuer, leaf


def _der_length(length):
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der(0x02, encoded)


def _google_identity_der(
    *,
    production=True,
    security_version=0,
    security_flags=None,
):
    security_flags = (
        {2: True, 3: False, 4: False, 5: False} if security_flags is None else security_flags
    )
    security = b"".join(
        [
            _der(0xA0, _der_integer(security_version)),
            _der(0xA1, _der(0x01, b"\xff" if production else b"\x00")),
            *[
                _der(
                    0xA0 + tag,
                    _der(0x01, b"\xff" if value else b"\x00"),
                )
                for tag, value in security_flags.items()
            ],
        ]
    )
    identity = b"".join(
        [
            _der(0x0C, b"us-central1-a"),
            _der_integer(421891914630),
            _der(0x0C, b"ardent-stacker-232906"),
            _der_integer(1618389494578039199),
            _der(0x0C, b"snp-gcp-explore"),
            _der(0xA0, _der(0x30, security)),
        ]
    )
    return _der(0x30, identity)


def _google_ak(
    *,
    subject_project="ardent-stacker-232906",
    extension=None,
    key_usage=None,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.LOCALITY_NAME, "us-central1-a"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Compute Engine"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_project),
            x509.NameAttribute(NameOID.COMMON_NAME, "1618389494578039199"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            key_usage
            or x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                gcp_vtpm._GOOGLE_ATTESTATION_EXTENSION_OID,
                extension or _google_identity_der(),
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def _revoked_ocsp_response(cert, issuer, issuer_key):
    now = datetime.now(timezone.utc)
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=issuer,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now - timedelta(minutes=1),
            next_update=now + timedelta(hours=1),
            revocation_time=now - timedelta(minutes=2),
            revocation_reason=x509.ReasonFlags.key_compromise,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
        .sign(issuer_key, hashes.SHA256())
    )


class _Redis:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.set_calls = []

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, **_kwargs):
        self.values[key] = value
        self.set_calls.append((key, value, _kwargs))

    async def delete(self, key):
        self.values.pop(key, None)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/ca.crt",
        "http://169.254.169.254/ca.crt",
        "http://metadata.google.internal/ca.crt",
        "http://user@privateca-content-a.storage.googleapis.com/ca.crt",
        "http://privateca-content-a.storage.googleapis.com:8080/ca.crt",
        "http://evil.example/ca.crt",
    ],
)
def test_gcp_certificate_url_allowlist_rejects_ssrf_targets(url):
    with pytest.raises(InvalidQuoteError, match="allowlist|invalid"):
        gcp_vtpm._validate_google_ca_url(url)


def test_gcp_certificate_url_allowlist_accepts_private_ca_object():
    assert gcp_vtpm._validate_google_ca_url(GOOGLE_CA_URL) == GOOGLE_CA_URL


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "fe80::1"])
async def test_gcp_certificate_fetch_rejects_private_and_link_local_dns(address):
    loop = asyncio.get_running_loop()
    with patch.object(
        loop,
        "getaddrinfo",
        new=AsyncMock(
            return_value=[
                (2, 1, 6, "", (address, 0)),
            ]
        ),
    ):
        with pytest.raises(InvalidQuoteError, match="non-public"):
            await gcp_vtpm._public_google_ca_addresses("privateca-content-a.storage.googleapis.com")


@pytest.mark.asyncio
async def test_gcp_certificate_fetch_pins_resolved_address_against_dns_rebinding():
    loop = asyncio.get_running_loop()
    resolver = AsyncMock(
        side_effect=[
            [(2, 1, 6, "", ("8.8.8.8", 0))],
            [(2, 1, 6, "", ("169.254.169.254", 0))],
        ]
    )
    request = AsyncMock(return_value=b"certificate")
    with (
        patch.object(loop, "getaddrinfo", new=resolver),
        patch.object(gcp_vtpm, "_request_google_ca_address", request),
    ):
        result = await gcp_vtpm._fetch_google_ca_object(GOOGLE_CA_URL, cache_prefix="test")
    assert result == b"certificate"
    assert resolver.await_count == 1
    assert request.await_args.args[1] == "8.8.8.8"


class _Writer:
    def write(self, _data):
        pass

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_gcp_certificate_fetch_does_not_follow_redirects():
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    reader.feed_eof()
    with patch.object(
        asyncio,
        "open_connection",
        new=AsyncMock(return_value=(reader, _Writer())),
    ):
        with pytest.raises(InvalidQuoteError, match="redirects are forbidden"):
            await gcp_vtpm._request_google_ca_address(
                GOOGLE_CA_URL,
                "8.8.8.8",
                method="GET",
                body=b"",
                content_type=None,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(gcp_vtpm._MAX_GOOGLE_CA_OBJECT_BYTES + 1).encode()
            + b"\r\n\r\n"
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{gcp_vtpm._MAX_GOOGLE_CA_OBJECT_BYTES + 1:x}\r\n".encode()
        ),
    ],
)
async def test_gcp_certificate_fetch_rejects_oversized_objects_before_body_read(response):
    reader = asyncio.StreamReader()
    reader.feed_data(response)
    reader.feed_eof()
    with patch.object(
        asyncio,
        "open_connection",
        new=AsyncMock(return_value=(reader, _Writer())),
    ):
        with pytest.raises(InvalidQuoteError, match="too large"):
            await gcp_vtpm._request_google_ca_address(
                GOOGLE_CA_URL,
                "8.8.8.8",
                method="GET",
                body=b"",
                content_type=None,
            )


@pytest.mark.asyncio
async def test_gcp_revocation_is_fresh_signed_and_fail_closed():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        leaf_key,
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    fresh = _crl(issuer, issuer_key).public_bytes(serialization.Encoding.DER)
    with patch.object(
        gcp_vtpm,
        "_fetch_google_ca_object",
        new_callable=AsyncMock,
        return_value=fresh,
    ):
        await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")

    revoked = _crl(issuer, issuer_key, revoked=leaf).public_bytes(serialization.Encoding.DER)
    with patch.object(
        gcp_vtpm,
        "_fetch_google_ca_object",
        new_callable=AsyncMock,
        return_value=revoked,
    ):
        with pytest.raises(InvalidQuoteError, match="revoked"):
            await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")


@pytest.mark.asyncio
@pytest.mark.parametrize("crl_kwargs", [{"expired": True}, {"future": True}])
async def test_gcp_advertised_stale_or_future_crl_fails_closed(crl_kwargs):
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    stale = _crl(issuer, issuer_key, **crl_kwargs).public_bytes(serialization.Encoding.DER)
    with patch.object(
        gcp_vtpm,
        "_fetch_google_ca_object",
        new_callable=AsyncMock,
        return_value=stale,
    ):
        with pytest.raises(InvalidQuoteError, match="not current"):
            await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")


@pytest.mark.asyncio
async def test_gcp_advertised_revocation_fetch_failure_fails_closed():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    with patch.object(
        gcp_vtpm,
        "_fetch_google_ca_object",
        new_callable=AsyncMock,
        side_effect=OSError("status service unavailable"),
    ):
        with pytest.raises(InvalidQuoteError, match="Could not establish fresh revocation"):
            await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")


@pytest.mark.asyncio
async def test_gcp_advertised_ocsp_revoked_certificate_fails_closed():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
        crl_url=None,
        ocsp_url=GOOGLE_CA_URL,
    )
    revoked = _revoked_ocsp_response(leaf, issuer, issuer_key).public_bytes(
        serialization.Encoding.DER
    )
    with patch.object(
        gcp_vtpm,
        "_fetch_google_ca_object",
        new_callable=AsyncMock,
        return_value=revoked,
    ):
        with pytest.raises(InvalidQuoteError, match="revoked"):
            await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")


@pytest.mark.asyncio
async def test_gcp_certificate_without_advertised_status_reports_warning_state():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
        crl_url=None,
    )
    assert (
        await gcp_vtpm._check_google_certificate_revocation(leaf, issuer, "leaf")
        == "revocation_not_advertised"
    )


@pytest.mark.asyncio
async def test_checked_in_real_gcp_ak_passes_with_not_advertised_leaf_status():
    assets = Path(__file__).resolve().parents[1] / "assets" / "snp"
    fixture = json.loads((assets / "gcp-vtpm-quote.json").read_text())
    ak = x509.load_der_x509_certificate(base64.b64decode(fixture["ak_cert"]))
    intermediate = x509.load_pem_x509_certificate((assets / "gcp-ak-intermediate.pem").read_bytes())
    assert gcp_vtpm._certificate_crl_urls(ak) == []
    assert gcp_vtpm._certificate_ocsp_urls(ak) == []
    original_check = gcp_vtpm._check_google_certificate_revocation

    async def check_real_leaf(cert, issuer, what, **kwargs):
        if what == "GCE AK":
            return await original_check(cert, issuer, what, **kwargs)
        return "good"

    with patch.object(
        gcp_vtpm,
        "_check_google_certificate_revocation",
        new=AsyncMock(side_effect=check_real_leaf),
    ):
        result = await gcp_vtpm.verify_vtpm_quote(
            base64.b64decode(fixture["ak_cert"]),
            base64.b64decode(fixture["quote_msg"]),
            base64.b64decode(fixture["quote_sig"]),
            {int(key): bytes.fromhex(value) for key, value in fixture["pcrs"].items()},
            bytes.fromhex(fixture["nonce"]),
            expected_security_flags={2: True, 3: False, 4: False, 5: False},
            intermediate_der=intermediate.public_bytes(serialization.Encoding.DER),
        )
    assert result.is_valid is True
    assert result.revocation_status == {
        "gce_ak": "revocation_not_advertised",
        "ek_ak_ca_intermediate": "good",
    }
    assert any("revocation_not_advertised" in warning for warning in result.warnings)
    assert any("revocation was not checked" in warning for warning in result.warnings)
    assert result.instance_identity == {
        "zone": "us-central1-a",
        "project_number": 421891914630,
        "project_id": "ardent-stacker-232906",
        "instance_id": 1618389494578039199,
        "instance_name": "snp-gcp-explore",
        "security_version": 0,
        "is_production": True,
        "security_flags": {2: True, 3: False, 4: False, 5: False},
    }


def test_google_attestation_extension_rejects_nonproduction_and_unknown_version():
    with pytest.raises(InvalidQuoteError, match="not production"):
        gcp_vtpm._parse_google_instance_identity(_google_identity_der(production=False))
    with pytest.raises(InvalidQuoteError, match="version 1 is unsupported"):
        gcp_vtpm._parse_google_instance_identity(_google_identity_der(security_version=1))


@pytest.mark.parametrize(
    "security_flags",
    [
        {2: True, 3: False, 4: False},
        {2: True, 3: False, 4: False, 5: False, 6: False},
    ],
)
def test_google_attestation_extension_requires_exact_signed_flag_tags(
    security_flags,
):
    with pytest.raises(InvalidQuoteError, match="flag|unknown"):
        gcp_vtpm._parse_google_instance_identity(
            _google_identity_der(security_flags=security_flags)
        )


def test_google_attestation_extension_rejects_flipped_pinned_flag():
    identity = gcp_vtpm._parse_google_instance_identity(_google_identity_der())
    with pytest.raises(InvalidQuoteError, match="do not match"):
        gcp_vtpm._check_google_security_flag_policy(
            identity,
            {2: False, 3: False, 4: False, 5: False},
        )


def _ak_key_usage(**overrides):
    values = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": None,
        "decipher_only": None,
    }
    values.update(overrides)
    if values["key_agreement"]:
        values["encipher_only"] = bool(values["encipher_only"])
        values["decipher_only"] = bool(values["decipher_only"])
    return x509.KeyUsage(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"digital_signature": False},
        {"content_commitment": True},
        {"key_encipherment": True},
        {"data_encipherment": True},
        {"key_agreement": True},
        {"key_agreement": True, "encipher_only": True},
        {"key_agreement": True, "decipher_only": True},
        {"key_cert_sign": True},
        {"crl_sign": True},
    ],
)
def test_google_ak_key_usage_is_exact_attestation_signing(overrides):
    with pytest.raises(InvalidQuoteError, match="keyUsage"):
        gcp_vtpm._check_google_ak_constraints(_google_ak(key_usage=_ak_key_usage(**overrides)))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw[:-1],
        lambda raw: raw + b"\x00",
        lambda raw: raw.replace(b"\xa1\x03\x01\x01\xff", b"\xa2\x03\x01\x01\xff", 1),
        lambda raw: raw.replace(b"\x0c\x0dus-central1-a", b"\x04\x0dus-central1-a", 1),
    ],
)
def test_google_attestation_extension_rejects_malformed_asn1(mutate):
    with pytest.raises(InvalidQuoteError):
        gcp_vtpm._parse_google_instance_identity(mutate(_google_identity_der()))


def test_google_ak_subject_must_match_signed_project_identity():
    with pytest.raises(InvalidQuoteError, match="subject project disagrees"):
        gcp_vtpm._check_google_ak_constraints(_google_ak(subject_project="different-project"))


def test_api_vtpm_signed_pcr_selection_rejects_caller_relabeling():
    assets = Path(__file__).resolve().parents[1] / "assets" / "snp"
    fixture = json.loads((assets / "gcp-vtpm-quote.json").read_text())
    quote_msg = base64.b64decode(fixture["quote_msg"])
    _extra, signed_digest, selections = gcp_vtpm.parse_tpms_attest(quote_msg)
    original_values = [
        bytes.fromhex(value)
        for _index, value in sorted(fixture["pcrs"].items(), key=lambda item: int(item[0]))
    ]
    relabeled = {index + 10: value for index, value in enumerate(original_values)}
    assert hashlib.sha256(b"".join(relabeled.values())).digest() == signed_digest
    with pytest.raises(InvalidQuoteError, match="selection"):
        gcp_vtpm._validate_pcr_selection(selections, relabeled)


def test_crl_freshness_rejects_expired_amd_and_google_lists():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    expired = _crl(issuer, key, expired=True)
    with pytest.raises(InvalidQuoteError, match="expired"):
        snp_verify._check_crl_freshness(expired)
    with pytest.raises(InvalidQuoteError, match="not current"):
        gcp_vtpm._check_google_crl_freshness(expired)


@pytest.mark.asyncio
async def test_snp_revocation_outage_without_fresh_cache_fails_closed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _certificate(
        leaf_key,
        key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    with patch.object(
        snp_verify,
        "_fetch_crl",
        new_callable=AsyncMock,
        side_effect=OSError("KDS unavailable"),
    ):
        with pytest.raises(InvalidQuoteError, match="no authenticated current"):
            await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa")


@pytest.mark.asyncio
async def test_snp_revoked_vcek_is_rejected():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        leaf_key,
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    revoked = _crl(issuer, issuer_key, revoked=leaf).public_bytes(serialization.Encoding.DER)
    with patch.object(snp_verify, "_fetch_crl", new_callable=AsyncMock, return_value=revoked):
        with pytest.raises(InvalidQuoteError, match="revoked"):
            await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"expired": True}, "expired"),
        ({"future": True}, "not yet valid"),
    ],
)
def test_snp_crl_rejects_bad_time_bounds(kwargs, message):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    with pytest.raises(InvalidQuoteError, match=message):
        snp_verify._check_crl_freshness(_crl(issuer, key, **kwargs))


@pytest.mark.asyncio
async def test_snp_fresh_authenticated_cache_survives_kds_outage():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    fresh = _crl(issuer, key)
    fresh_der = fresh.public_bytes(serialization.Encoding.DER)
    redis = _Redis({"snp:crl:Genoa": snp_verify._crl_cache_payload(fresh_der, fresh, issuer)})
    with patch.object(
        snp_verify,
        "_fetch_crl",
        new_callable=AsyncMock,
        side_effect=OSError("KDS unavailable"),
    ) as fetch:
        await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa", redis=redis)
    fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_snp_recently_expired_cache_is_used_only_during_real_kds_outage():
    key, issuer, leaf = _snp_chain()
    recently_expired = _crl(issuer, key, expired=True)
    encoded = recently_expired.public_bytes(serialization.Encoding.DER)
    redis = _Redis(
        {"snp:crl:Genoa": snp_verify._crl_cache_payload(encoded, recently_expired, issuer)}
    )
    with patch.object(
        snp_verify,
        "_fetch_crl",
        new_callable=AsyncMock,
        side_effect=OSError("KDS unavailable"),
    ) as fetch:
        await snp_verify._check_revocation(
            leaf,
            issuer,
            issuer,
            "Genoa",
            redis=redis,
            outage_grace_seconds=120,
        )
    fetch.assert_awaited_once_with("Genoa")


@pytest.mark.asyncio
async def test_snp_grace_never_masks_malformed_kds_revocation_state():
    key, issuer, leaf = _snp_chain()
    recently_expired = _crl(issuer, key, expired=True)
    encoded = recently_expired.public_bytes(serialization.Encoding.DER)
    redis = _Redis(
        {"snp:crl:Genoa": snp_verify._crl_cache_payload(encoded, recently_expired, issuer)}
    )
    with patch.object(
        snp_verify,
        "_fetch_crl",
        new_callable=AsyncMock,
        return_value=b"not a CRL",
    ):
        with pytest.raises(InvalidQuoteError, match="malformed"):
            await snp_verify._check_revocation(
                leaf,
                issuer,
                issuer,
                "Genoa",
                redis=redis,
                outage_grace_seconds=120,
            )


@pytest.mark.asyncio
async def test_snp_crl_signature_must_match_named_amd_issuer():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        issuer_key,
        issuer_key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        issuer_key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    forged = _crl(issuer, wrong_key).public_bytes(serialization.Encoding.DER)
    with patch.object(snp_verify, "_fetch_crl", new_callable=AsyncMock, return_value=forged):
        with pytest.raises(InvalidQuoteError, match="signature or issuer"):
            await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa")


@pytest.mark.asyncio
async def test_snp_expired_cache_never_extends_trust_during_outage():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = _certificate(
        key,
        key,
        subject=_name("issuer"),
        issuer=_name("issuer"),
        is_ca=True,
    )
    leaf = _certificate(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        key,
        subject=_name("leaf"),
        issuer=issuer.subject,
        is_ca=False,
    )
    stale = _crl(issuer, key, expired=True)
    stale_der = stale.public_bytes(serialization.Encoding.DER)
    redis = _Redis({"snp:crl:Genoa": snp_verify._crl_cache_payload(stale_der, stale, issuer)})
    with patch.object(
        snp_verify,
        "_fetch_crl",
        new_callable=AsyncMock,
        side_effect=OSError("KDS unavailable"),
    ):
        with pytest.raises(InvalidQuoteError, match="no authenticated current"):
            await snp_verify._check_revocation(
                leaf,
                issuer,
                issuer,
                "Genoa",
                redis=redis,
                outage_grace_seconds=30,
            )
    assert "snp:crl:Genoa" not in redis.values


def test_snp_crl_outage_grace_has_a_hard_safe_maximum():
    key, issuer, _leaf = _snp_chain()
    with pytest.raises(InvalidQuoteError, match="safe maximum"):
        snp_verify._check_crl_freshness(
            _crl(issuer, key),
            outage_grace_seconds=MAX_SNP_CRL_OUTAGE_GRACE_SECONDS + 1,
        )
    with pytest.raises(ValueError, match="SNP_CRL_OUTAGE_GRACE_SECONDS"):
        Settings(snp_crl_outage_grace_seconds=MAX_SNP_CRL_OUTAGE_GRACE_SECONDS + 1)


@pytest.mark.asyncio
async def test_snp_fetched_crl_is_cached_only_after_authentication_through_next_update():
    key, issuer, leaf = _snp_chain()
    fresh = _crl(issuer, key)
    fresh_der = fresh.public_bytes(serialization.Encoding.DER)
    remaining_before = int(
        (snp_verify._crl_times(fresh)[1] - datetime.now(timezone.utc)).total_seconds()
    )
    redis = _Redis()
    with patch.object(snp_verify, "_fetch_crl", new_callable=AsyncMock, return_value=fresh_der):
        await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa", redis=redis)

    assert len(redis.set_calls) == 1
    cache_key, payload, kwargs = redis.set_calls[0]
    assert cache_key == "snp:crl:Genoa"
    assert 0 < kwargs["ex"] <= remaining_before
    assert snp_verify._load_cached_crl(payload, issuer, issuer).issuer == issuer.subject


@pytest.mark.asyncio
async def test_snp_forged_fetched_crl_is_never_cached():
    key, issuer, leaf = _snp_chain()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _crl(issuer, wrong_key).public_bytes(serialization.Encoding.DER)
    redis = _Redis()
    with patch.object(snp_verify, "_fetch_crl", new_callable=AsyncMock, return_value=forged):
        with pytest.raises(InvalidQuoteError, match="signature or issuer"):
            await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa", redis=redis)
    assert redis.values == {}
    assert redis.set_calls == []


@pytest.mark.asyncio
async def test_snp_poisoned_cache_is_deleted_and_replaced_only_by_authenticated_fetch():
    key, issuer, leaf = _snp_chain()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _crl(issuer, wrong_key)
    forged_der = forged.public_bytes(serialization.Encoding.DER)
    poisoned = snp_verify._crl_cache_payload(forged_der, forged, issuer)
    fresh = _crl(issuer, key)
    fresh_der = fresh.public_bytes(serialization.Encoding.DER)
    redis = _Redis({"snp:crl:Genoa": poisoned})

    with patch.object(
        snp_verify, "_fetch_crl", new_callable=AsyncMock, return_value=fresh_der
    ) as fetch:
        await snp_verify._check_revocation(leaf, issuer, issuer, "Genoa", redis=redis)

    fetch.assert_awaited_once_with("Genoa")
    cached = snp_verify._load_cached_crl(redis.values["snp:crl:Genoa"], issuer, issuer)
    assert cached.is_signature_valid(issuer.public_key())


def test_tdx_quote_v5_is_rejected_until_body_descriptor_is_supported():
    quote = bytearray(632)
    struct.pack_into("<HHI16s20s", quote, 0, 5, 2, 0x81, b"\x00" * 16, b"\x00" * 20)
    with pytest.raises(InvalidQuoteError, match="only TDX quote v4"):
        TdxQuote.from_bytes(bytes(quote))
