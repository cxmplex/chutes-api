"""
Unit tests for the CPU-TEE e2e_pubkey attestation-binding check in api/instance/router.py.

A CPU-TEE chute publishes an ML-KEM e2e public key only if it is signed by the in-TD attested cert
key (whose pubkey hash is committed in the server's registration quote). _verify_e2e_pubkey_sig must
accept a signature by the attested cert key over f"{e2e_pubkey}:{config_id}" and reject anything else,
so neither the untrusted host nor the validator can substitute the key.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from api.instance.router import _verify_e2e_pubkey_sig

E2E_PUBKEY = "dGVzdF9tbGtlbV9wdWJrZXk="  # base64-like test value
CONFIG_ID = "11111111-2222-3333-4444-555555555555"


def _self_signed_cert(key) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "td-attest")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _rsa_sign(key, e2e_pubkey: str, config_id: str) -> str:
    data = f"{e2e_pubkey}:{config_id}".encode()
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256()).hex()


def test_valid_rsa_signature_accepted():
    # The attestation cert is RSA-4096 (setup-tls-certs.sh), so RSA is the primary path.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_pem = _self_signed_cert(key)
    sig = _rsa_sign(key, E2E_PUBKEY, CONFIG_ID)
    assert _verify_e2e_pubkey_sig(cert_pem, E2E_PUBKEY, sig, CONFIG_ID) is True


def test_valid_ec_signature_accepted():
    # Robustness: the helper must also handle an EC attestation cert.
    key = ec.generate_private_key(ec.SECP256R1())
    cert_pem = _self_signed_cert(key)
    data = f"{E2E_PUBKEY}:{CONFIG_ID}".encode()
    sig = key.sign(data, ec.ECDSA(hashes.SHA256())).hex()
    assert _verify_e2e_pubkey_sig(cert_pem, E2E_PUBKEY, sig, CONFIG_ID) is True


def test_tampered_pubkey_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_pem = _self_signed_cert(key)
    sig = _rsa_sign(key, E2E_PUBKEY, CONFIG_ID)
    assert _verify_e2e_pubkey_sig(cert_pem, "ZGlmZmVyZW50X3B1YmtleQ==", sig, CONFIG_ID) is False


def test_wrong_config_id_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_pem = _self_signed_cert(key)
    sig = _rsa_sign(key, E2E_PUBKEY, CONFIG_ID)
    assert (
        _verify_e2e_pubkey_sig(cert_pem, E2E_PUBKEY, sig, "00000000-0000-0000-0000-000000000000")
        is False
    )


def test_signature_from_different_key_rejected():
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_cert_pem = _self_signed_cert(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    sig = _rsa_sign(signer, E2E_PUBKEY, CONFIG_ID)
    assert _verify_e2e_pubkey_sig(other_cert_pem, E2E_PUBKEY, sig, CONFIG_ID) is False


def test_malformed_signature_rejected():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_pem = _self_signed_cert(key)
    assert _verify_e2e_pubkey_sig(cert_pem, E2E_PUBKEY, "not-hex", CONFIG_ID) is False
    assert _verify_e2e_pubkey_sig(cert_pem, E2E_PUBKEY, "deadbeef", CONFIG_ID) is False
