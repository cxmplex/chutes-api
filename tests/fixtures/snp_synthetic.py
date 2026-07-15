"""Deterministic cryptographically valid synthetic SEV-SNP fixtures.

These assets exercise parsing, certificate-chain, CRL, report-signature, VMPL, TCB, and
id_key_digest logic. They are synthetic and must never be described as hardware evidence.
"""

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

_SYNTHETIC_RSA_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWwArWUCxrrfnZ
MDbsF3S+9T6V3Vl2QwJC3+vobnCclAj+kXFi5kmg2yVBoLSGDbSNNK3f2N6qeIdX
cdztKHBuyHVPk2uhjJ8ojxFgPGwRrXVcMjCHKD9b5fX1+hxqUieA4ePLwbl3GXMz
4w3Og4TfL6QWRdi4P6ZSSJknf+SXprBYsjYbOpEh0jC6Qf4m36tOmsjiAkv773Eg
F93+7Y0Lc1jzL/pVtvkHL8ScfMG96zKkdN/HCWyVq5H3HFzbJncJ22T8/S9Nf3e1
o9H4HFx4H6j8JDNbdwdaEYkY/7Wf2c6lrUta1c+ROt74BBUBA4eZa7kD4GjOTlml
QOemUAM/AgMBAAECggEAAy4b2vmb9spAQW2b2posUema0ChTe1NZtLjRKwN7qm3s
xixMNA05+OZV4mdpVPTeABtQGdkBzx9yzaIzhdWL+LACQLfrp5xH/RdFSBoM9aQO
cVuS6WV4rrk0j7xw8EggKqHtuCY5w2A+mv2ZRj4fWRjBAs1s/KmAooZNsk6MCYzY
6d5WkB0xF040hyioi4QyvSXVshs2YAIDq6Ldhup1/naw2fqPDYs+5zzs1+kf0zRr
hTCaG5APwgFcYtLVhi8HH13dnDzprI7pPPzJ17F7MWsoFnifbnH5F4gHfAswFP9W
Z2EjdAdeCKiOc3BPLEiL17Kppnh0LNapGFWQwHcrZQKBgQD4or98PwKuE4Y7AJDF
k+CTqvYKhA0C7Ngj2bRcnmUO49oJWv+FM6y7b9s/4u6B1hnvDbiN9RLCjI+79Lcs
mCeEHGU5tW1J8rXe/dvq28q0He2GPAh7iftHPNt9gpDjA/WqzogBFzZQfA0xf0DC
7AM1LKvoEhg7h/1uGRrrnCzQVQKBgQDdHFxjfACz1vTS8StMT8zGTaGemM5AKgai
9tlfaC+fR3e6P9icJUItG+z2dT6oRrbTlaXzm1DswTJq/03Ai6dssMuCKxFN0dzG
PznE9KqU/aXvJb2S3vYioqcSS3k1emmB9ATB2E+vnJtAAPAAjJGAIGIU9we1tFs5
oNAZ1riJQwKBgQDSYAJdgoMl/2coLUZRptnymEkuhKTtwLDxRJeTdoJTov8tw01I
y3xv7Ck7WSwtt5ah6p4pnx+MdZp4kosatHNbGRudRKGAXFj+oRWfFvHgjSIY3lrf
DNUMZbXh8MPfEc6gA7iYE6flWdFf/CgzxbbBG1cpOYY/eMU6jwt0J+TTMQKBgExD
9QYHhoKBeU6tCr82oy4fJsj6ceGl3UYmmNGUsSBiWUSvsvogy9OdVz2nMSZ/xZ3z
dxswjlgrR0Wqq9nnEaemz3slecF6yojC1B1AOvpLBwoW3W2kZAeMTM49pCAzCeNe
FKn7/3hWLyKDcETwN1uXT91lW45sGC8nbcAL1PjbAoGBALswYqveRV9C1uuBzdto
GvmmB6f9/M+pSeDD4DDItrvVLpPd4itsdfuPV21x2h/X4Y3vB04NHG1n5K0V4ngx
BOA2WofOts17unrueXFocBez9RkZ/EQoK7yUmTly8sK4TmM7tLh2lGW22xXfxB0Q
Tf4B4NlHkFvF2ZEnHpowiTpd
-----END PRIVATE KEY-----
"""

SYNTHETIC_MODEL = "Synthetic"
SYNTHETIC_TCB = {"bootloader": 7, "tee": 0, "snp": 23, "microcode": 72}
SYNTHETIC_POLICY = 0x30000
SYNTHETIC_VMPL = 0
SYNTHETIC_MEASUREMENT = hashlib.sha384(b"chutes synthetic SNP measurement v1").hexdigest().upper()
SYNTHETIC_ID_KEY_DIGEST = hashlib.sha384(b"chutes synthetic SNP id key v1").hexdigest().upper()
SYNTHETIC_REPORT_DATA = ("11" * 32 + "22" * 32).upper()
_REPORT_SIGNATURE_R = int(
    "d89b6c1b55aa9268fd95101d6dffa7d22ea45b767aa5a61f81e1d2369cd1fa2e"
    "fc91f4d68cd98947ff560893a9d73eaa",
    16,
)
_REPORT_SIGNATURE_S = int(
    "150f56521cf2c936323a8b5db61e6f2b313af54b88aefbac1bba29779fd8a343"
    "fa62473e37ef493cbf59f6a869a258d0",
    16,
)


@dataclass(frozen=True)
class SyntheticSnpBundle:
    report: bytes
    vcek_der: bytes
    ask_pem: bytes
    ark_pem: bytes
    ca_pem: bytes
    crl_der: bytes
    aux: bytes
    ark_spki_sha384: str


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    public_key,
    subject: x509.Name,
    issuer: x509.Name,
    issuer_key,
    serial: int,
    *,
    is_ca: bool,
    extensions=(),
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2045, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    for oid, value in extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(oid), value),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA384())


def build_synthetic_snp_bundle() -> SyntheticSnpBundle:
    issuer_key = serialization.load_pem_private_key(_SYNTHETIC_RSA_PRIVATE_KEY_PEM, password=None)
    vcek_key = ec.derive_private_key(42, ec.SECP384R1())
    ark = _certificate(
        issuer_key.public_key(),
        _name("ARK-Synthetic"),
        _name("ARK-Synthetic"),
        issuer_key,
        1,
        is_ca=True,
    )
    ask = _certificate(
        issuer_key.public_key(),
        _name("ASK-Synthetic"),
        ark.subject,
        issuer_key,
        2,
        is_ca=True,
    )
    tcb_extensions = [
        (
            oid,
            b"\x02\x01" + bytes([SYNTHETIC_TCB[component]]),
        )
        for oid, component in (
            ("1.3.6.1.4.1.3704.1.3.1", "bootloader"),
            ("1.3.6.1.4.1.3704.1.3.2", "tee"),
            ("1.3.6.1.4.1.3704.1.3.3", "snp"),
            ("1.3.6.1.4.1.3704.1.3.8", "microcode"),
        )
    ]
    vcek = _certificate(
        vcek_key.public_key(),
        _name("VCEK-Synthetic"),
        ask.subject,
        issuer_key,
        3,
        is_ca=False,
        extensions=tcb_extensions,
    )

    report = bytearray(1184)
    struct.pack_into("<I", report, 0, 3)
    struct.pack_into("<Q", report, 0x08, SYNTHETIC_POLICY)
    struct.pack_into("<I", report, 0x30, SYNTHETIC_VMPL)
    tcb_value = 0x4817000000000007
    struct.pack_into("<Q", report, 0x38, tcb_value)
    struct.pack_into("<Q", report, 0x180, tcb_value)
    report[0x50:0x90] = bytes.fromhex(SYNTHETIC_REPORT_DATA)
    report[0x90:0xC0] = bytes.fromhex(SYNTHETIC_MEASUREMENT)
    report[0xC0:0xE0] = hashlib.sha256(b"synthetic host data").digest()
    report[0xE0:0x110] = bytes.fromhex(SYNTHETIC_ID_KEY_DIGEST)
    report[0x110:0x140] = hashlib.sha384(b"synthetic author key").digest()
    report[0x1A0:0x1E0] = hashlib.sha512(b"synthetic chip id").digest()
    report[0x2A0 : 0x2A0 + 72] = _REPORT_SIGNATURE_R.to_bytes(72, "little")
    report[0x2A0 + 72 : 0x2A0 + 144] = _REPORT_SIGNATURE_S.to_bytes(72, "little")

    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ask.subject)
        .last_update(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .next_update(datetime(2045, 1, 1, tzinfo=timezone.utc))
        .sign(issuer_key, hashes.SHA384())
    )
    certs = [
        vcek.public_bytes(serialization.Encoding.DER),
        ask.public_bytes(serialization.Encoding.DER),
        ark.public_bytes(serialization.Encoding.DER),
    ]
    header_size = 24 * 4
    aux = bytearray(header_size + sum(len(cert) for cert in certs))
    cert_offset = header_size
    for index, cert_der in enumerate(certs):
        entry_offset = index * 24
        aux[entry_offset : entry_offset + 16] = bytes([index + 1]) * 16
        struct.pack_into("<II", aux, entry_offset + 16, cert_offset, len(cert_der))
        aux[cert_offset : cert_offset + len(cert_der)] = cert_der
        cert_offset += len(cert_der)

    ark_spki = ark.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ask_pem = ask.public_bytes(serialization.Encoding.PEM)
    ark_pem = ark.public_bytes(serialization.Encoding.PEM)
    return SyntheticSnpBundle(
        report=bytes(report),
        vcek_der=certs[0],
        ask_pem=ask_pem,
        ark_pem=ark_pem,
        ca_pem=ask_pem + ark_pem,
        crl_der=crl.public_bytes(serialization.Encoding.DER),
        aux=bytes(aux),
        ark_spki_sha384=hashlib.sha384(ark_spki).hexdigest(),
    )


SYNTHETIC_SNP_BUNDLE = build_synthetic_snp_bundle()
