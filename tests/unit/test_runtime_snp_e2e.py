"""Non-mocked synthetic runtime re-attestation flows for SNP providers."""

import base64
import hashlib
import struct
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier

from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.constants import NoncePurpose
from api.host.schemas import TdLaunchReservation
from api.server import gcp_vtpm, snp_verify
from api.server.exceptions import MeasurementMismatchError, NonceError
from api.server.schemas import (
    RuntimeAttestationArgs,
    RuntimeAttestationNonceContext,
    Server,
    ServerAttestation,
)
from api.server.service import (
    create_nonce,
    process_runtime_attestation,
    runtime_attestation_context_for_server,
    validate_and_consume_nonce,
)
from tests.fixtures.snp_synthetic import (
    SYNTHETIC_ID_KEY_DIGEST,
    SYNTHETIC_MEASUREMENT,
    SYNTHETIC_MODEL,
    SYNTHETIC_POLICY,
    SYNTHETIC_SNP_BUNDLE,
    SYNTHETIC_TCB,
    SYNTHETIC_VMPL,
)

CERT_HASH = "22" * 32
OWNER = "5F-runtime-owner"
IP = "203.0.113.40"
GCP_INSTANCE_ID = 1618389494578039199
GCP_SECURITY_FLAGS = {"2": True, "3": False, "4": False, "5": False}


class _Redis:
    def __init__(self):
        self.values = {}

    async def setex(self, key, _ttl, value):
        self.values[key] = value.encode() if isinstance(value, str) else value

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, **_kwargs):
        self.values[key] = value

    async def delete(self, key):
        self.values.pop(key, None)


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value


class _Database:
    def __init__(self, server):
        self.server = server
        self.added = []
        self.info = {}
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, statement, _params=None):
        descriptions = getattr(statement, "column_descriptions", ())
        entity = descriptions[0].get("entity") if descriptions else None
        if entity is ServerAttestation:
            latest = self.added[-1] if self.added else None
            return _Result(latest)
        if entity is TdLaunchReservation:
            return _Result(None)
        return _Result(self.server)

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        if self.added:
            self.added[-1].attempt_sequence = len(self.added)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, value):
        value.attestation_id = f"runtime-{self.commits}"
        value.verified_at = datetime.now(timezone.utc)


def _config(*, provider, vtpm_pcrs=None, vtpm_security_flags=None):
    config = TeeMeasurementConfig(
        version="2.0.0-snp-4vcpu",
        name=f"cpu-{provider.replace('-', '')}-snp-synthetic-4vcpu",
        provider=provider,
        tee_type="sev-snp",
        mrtd="",
        expected_gpus=[],
        gpu_count=0,
        measurement=SYNTHETIC_MEASUREMENT,
        policy=SYNTHETIC_POLICY,
        min_tcb=dict(SYNTHETIC_TCB),
        id_key_digest=SYNTHETIC_ID_KEY_DIGEST,
        processor_model=SYNTHETIC_MODEL,
        expected_vmpl=SYNTHETIC_VMPL,
        vtpm_pcrs=vtpm_pcrs,
        vtpm_security_flags=vtpm_security_flags,
        debug=False,
    )
    config.config_fingerprint = measurement_config_fingerprint(config)
    config.trust_set_fingerprint = measurement_trust_set_fingerprint([config])
    return config


def _server(config, *, gcp):
    return Server(
        server_id=f"gcp-{GCP_INSTANCE_ID}" if gcp else "baremetal-snp-runtime",
        ip=IP,
        miner_hotkey=OWNER,
        name="snp-runtime",
        is_tee=True,
        self_registered=True,
        compute_type="cpu",
        tee_type="sev-snp",
        # This synthetic test exercises bare-metal-direct SNP. Model-B requires an exact
        # consumed launch reservation and is covered by the authority protocol regressions.
        host_id=None,
        storage_role=False,
        version=config.version,
        measurement_name=config.name,
        measurement_config_fingerprint=config.config_fingerprint,
        trust_set_fingerprint=config.trust_set_fingerprint,
        attested_cert="-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----",
        attested_cert_pubkey_hash=CERT_HASH,
    )


def _report_for_nonce(nonce, *, different_measurement=False):
    report = bytearray(SYNTHETIC_SNP_BUNDLE.report)
    report[0x50:0x90] = bytes.fromhex(nonce + CERT_HASH)
    if different_measurement:
        report[0x90] ^= 0x01
    signature = ec.derive_private_key(42, ec.SECP384R1()).sign(
        bytes(report[:0x2A0]), ec.ECDSA(hashes.SHA384())
    )
    r_value, s_value = decode_dss_signature(signature)
    report[0x2A0 : 0x2A0 + 72] = r_value.to_bytes(72, "little")
    report[0x2A0 + 72 : 0x2A0 + 144] = s_value.to_bytes(72, "little")
    return bytes(report)


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    subject_key,
    issuer_key,
    *,
    subject,
    issuer,
    serial,
    is_ca,
    key_usage,
    extensions=(),
):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def _der(tag, content):
    if len(content) >= 128:
        raise AssertionError("synthetic identity DER unexpectedly large")
    return bytes([tag, len(content)]) + content


def _der_integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der(0x02, encoded)


def _google_identity_der():
    security = _der(
        0x30,
        _der(0xA0, _der_integer(0))
        + _der(0xA1, _der(0x01, b"\xff"))
        + _der(0xA2, _der(0x01, b"\xff"))
        + _der(0xA3, _der(0x01, b"\x00"))
        + _der(0xA4, _der(0x01, b"\x00"))
        + _der(0xA5, _der(0x01, b"\x00")),
    )
    return _der(
        0x30,
        _der(0x0C, b"us-central1-a")
        + _der_integer(421891914630)
        + _der(0x0C, b"synthetic-project")
        + _der_integer(GCP_INSTANCE_ID)
        + _der(0x0C, b"synthetic-instance")
        + _der(0xA0, security),
    )


def _synthetic_vtpm(expected_qualifying_data):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None,
    )
    ak_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=None,
        decipher_only=None,
    )
    root = _certificate(
        root_key,
        root_key,
        subject=_name("EK/AK CA Root"),
        issuer=_name("EK/AK CA Root"),
        serial=10,
        is_ca=True,
        key_usage=ca_usage,
    )
    intermediate = _certificate(
        intermediate_key,
        root_key,
        subject=_name("EK/AK CA Intermediate"),
        issuer=root.subject,
        serial=11,
        is_ca=True,
        key_usage=ca_usage,
        extensions=(
            (
                x509.ExtendedKeyUsage([ObjectIdentifier("2.23.133.8.1")]),
                False,
            ),
        ),
    )
    ak_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.LOCALITY_NAME, "us-central1-a"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Compute Engine"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "synthetic-project"),
            x509.NameAttribute(NameOID.COMMON_NAME, str(GCP_INSTANCE_ID)),
        ]
    )
    ak = _certificate(
        ak_key,
        intermediate_key,
        subject=ak_subject,
        issuer=intermediate.subject,
        serial=12,
        is_ca=False,
        key_usage=ak_usage,
        extensions=(
            (
                x509.UnrecognizedExtension(
                    gcp_vtpm._GOOGLE_ATTESTATION_EXTENSION_OID,
                    _google_identity_der(),
                ),
                False,
            ),
        ),
    )
    pcrs = {
        8: hashlib.sha256(b"synthetic PCR8").digest(),
        9: hashlib.sha256(b"synthetic PCR9").digest(),
    }
    pcr_digest = hashlib.sha256(pcrs[8] + pcrs[9]).digest()
    quote_msg = (
        struct.pack(">IH", 0xFF544347, 0x8018)
        + struct.pack(">H", 0)
        + struct.pack(">H", len(expected_qualifying_data))
        + expected_qualifying_data
        + b"\x00" * 25
        + struct.pack(">IHB", 1, 0x000B, 3)
        + b"\x00\x03\x00"
        + struct.pack(">H", len(pcr_digest))
        + pcr_digest
    )
    signature = ak_key.sign(quote_msg, padding.PKCS1v15(), hashes.SHA256())
    quote_signature = struct.pack(">HHH", 0x0014, 0x000B, len(signature)) + signature
    intermediate_spki = intermediate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    evidence = {
        "ak_cert": base64.b64encode(ak.public_bytes(serialization.Encoding.DER)).decode(),
        "quote_msg": base64.b64encode(quote_msg).decode(),
        "quote_sig": base64.b64encode(quote_signature).decode(),
        "pcrs": {str(index): value.hex() for index, value in pcrs.items()},
        "intermediate": base64.b64encode(
            intermediate.public_bytes(serialization.Encoding.DER)
        ).decode(),
    }
    return (
        evidence,
        {str(index): value.hex().upper() for index, value in pcrs.items()},
        root.public_bytes(serialization.Encoding.PEM),
        hashlib.sha256(intermediate_spki).hexdigest(),
    )


def _configure(monkeypatch, config, redis):
    settings = SimpleNamespace(
        tee_measurements=[config],
        redis_client=redis,
        snp_crl_outage_grace_seconds=0,
    )
    monkeypatch.setattr("api.server.service.settings", settings)
    monkeypatch.setattr("api.server.util.settings", settings)
    monkeypatch.setitem(
        snp_verify.ARK_PUBKEY_SHA384,
        SYNTHETIC_MODEL,
        SYNTHETIC_SNP_BUNDLE.ark_spki_sha384,
    )
    _vcek, ask, _ark = snp_verify.parse_ghcb_cert_table(SYNTHETIC_SNP_BUNDLE.aux)
    crl = x509.load_der_x509_crl(SYNTHETIC_SNP_BUNDLE.crl_der)
    redis.values[f"snp:crl:{SYNTHETIC_MODEL}"] = snp_verify._crl_cache_payload(
        SYNTHETIC_SNP_BUNDLE.crl_der, crl, ask
    )


async def _consume_runtime_nonce(server):
    context = runtime_attestation_context_for_server(server)
    nonce_info = await create_nonce(server.ip, NoncePurpose.RUNTIME, context=context.model_dump())
    nonce = nonce_info["nonce"]
    stored = await validate_and_consume_nonce(nonce, server.ip, NoncePurpose.RUNTIME)
    return nonce, RuntimeAttestationNonceContext.model_validate(stored["context"])


@pytest.mark.asyncio
async def test_bare_metal_snp_runtime_nonce_cert_measurement_and_replay(
    monkeypatch,
):
    redis = _Redis()
    config = _config(provider="bare-metal")
    server = _server(config, gcp=False)
    _configure(monkeypatch, config, redis)
    nonce, context = await _consume_runtime_nonce(server)
    report = _report_for_nonce(nonce)
    args = RuntimeAttestationArgs(
        quote=base64.b64encode(report).decode(),
        tee_type="sev-snp",
        snp_cert_chain=base64.b64encode(SYNTHETIC_SNP_BUNDLE.aux).decode(),
    )
    db = _Database(server)

    result = await process_runtime_attestation(
        db, server.server_id, server.ip, args, OWNER, nonce, CERT_HASH, context
    )

    assert result["status"] == "verified"
    attestation = db.added[-1]
    assert attestation.measurement_name == config.name
    assert attestation.measurement_config_fingerprint == config.config_fingerprint
    assert attestation.trust_set_fingerprint == config.trust_set_fingerprint
    assert attestation.revocation_status == {"amd_vcek": "good"}
    assert server.attestation_revocation_status == {"amd_vcek": "good"}
    assert result["revocation_status"] == {"amd_vcek": "good"}
    assert db.commits == 3  # durable pending row, unlocked preflight, final publication
    assert db.rollbacks == 0
    with pytest.raises(NonceError, match="not found or expired"):
        await validate_and_consume_nonce(nonce, server.ip, NoncePurpose.RUNTIME)


@pytest.mark.asyncio
async def test_gcp_snp_runtime_with_synthetic_vtpm_and_exact_instance_identity(
    monkeypatch,
):
    redis = _Redis()
    expected_pcrs = {
        "8": hashlib.sha256(b"synthetic PCR8").hexdigest().upper(),
        "9": hashlib.sha256(b"synthetic PCR9").hexdigest().upper(),
    }
    config = _config(
        provider="gcp",
        vtpm_pcrs=expected_pcrs,
        vtpm_security_flags=GCP_SECURITY_FLAGS,
    )
    server = _server(config, gcp=True)
    _configure(monkeypatch, config, redis)
    nonce, context = await _consume_runtime_nonce(server)
    qualifying_data = hashlib.sha256(bytes.fromhex(nonce) + bytes.fromhex(CERT_HASH)).digest()
    vtpm_quote, pcrs, root_pem, intermediate_spki = _synthetic_vtpm(qualifying_data)
    assert pcrs == expected_pcrs
    monkeypatch.setattr(gcp_vtpm, "GCE_EK_AK_CA_ROOT_PEM", root_pem)
    monkeypatch.setattr(
        gcp_vtpm,
        "_GOOGLE_EK_AK_INTERMEDIATE_SPKI_SHA256",
        {intermediate_spki},
    )
    report = _report_for_nonce(nonce)
    args = RuntimeAttestationArgs(
        quote=base64.b64encode(report).decode(),
        tee_type="sev-snp",
        snp_cert_chain=base64.b64encode(SYNTHETIC_SNP_BUNDLE.aux).decode(),
        vtpm_quote=vtpm_quote,
    )
    db = _Database(server)

    result = await process_runtime_attestation(
        db, server.server_id, server.ip, args, OWNER, nonce, CERT_HASH, context
    )

    assert result["status"] == "verified"
    attestation = db.added[-1]
    assert attestation.measurement_name == config.name
    assert attestation.measurement_config_fingerprint == config.config_fingerprint
    assert attestation.trust_set_fingerprint == config.trust_set_fingerprint
    assert attestation.revocation_status == {
        "amd_vcek": "good",
        "gce_ak": "revocation_not_advertised",
        "ek_ak_ca_intermediate": "revocation_not_advertised",
    }
    assert server.attestation_revocation_status == attestation.revocation_status
    assert result["revocation_status"] == attestation.revocation_status
    assert db.commits == 3  # durable pending row, unlocked preflight, final publication
    assert db.rollbacks == 0
    with pytest.raises(NonceError, match="not found or expired"):
        await validate_and_consume_nonce(nonce, server.ip, NoncePurpose.RUNTIME)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["cert", "role", "compute", "host", "measurement"])
async def test_runtime_context_rejects_identity_mutation_after_nonce(monkeypatch, mutation):
    redis = _Redis()
    config = _config(provider="bare-metal")
    server = _server(config, gcp=False)
    _configure(monkeypatch, config, redis)
    nonce, context = await _consume_runtime_nonce(server)
    args = RuntimeAttestationArgs(
        quote=base64.b64encode(
            _report_for_nonce(nonce, different_measurement=mutation == "measurement")
        ).decode(),
        tee_type="sev-snp",
        snp_cert_chain=base64.b64encode(SYNTHETIC_SNP_BUNDLE.aux).decode(),
    )
    expected_cert_hash = CERT_HASH
    if mutation == "cert":
        expected_cert_hash = "33" * 32
    elif mutation == "role":
        server.storage_role = True
    elif mutation == "compute":
        server.compute_type = "gpu"
    elif mutation == "host":
        server.host_id = "unexpected-model-b-host"

    with pytest.raises((MeasurementMismatchError, NonceError)):
        await process_runtime_attestation(
            _Database(server),
            server.server_id,
            server.ip,
            args,
            OWNER,
            nonce,
            expected_cert_hash,
            context,
        )
