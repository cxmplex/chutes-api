"""Storage control-plane calls require proxy-proven live certificate possession."""

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from api.config import settings
from api.server.exceptions import NoClientCertError
from api.server.util import _get_client_certificate
from api.storage.router import require_fresh_storage_caller
from api.storage.schemas import (
    LegacyReplicaAdoptionRequest,
    ReplicationCapabilityCompleteRequest,
    ReplicationCapabilityIssueRequest,
)


def _request(cert_pem: str, verify: str | None) -> Request:
    headers = [(b"x-client-cert", quote(cert_pem).encode())]
    if verify is not None:
        headers.append((b"x-client-verify", verify.encode()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/storage/replicas/announce",
            "headers": headers,
        }
    )


@lru_cache(maxsize=1)
def _certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "storage-test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def test_header_only_public_certificate_does_not_prove_possession(monkeypatch):
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    with pytest.raises(NoClientCertError):
        _get_client_certificate(_request(_certificate(), None), require_proxy_verified=True)


@pytest.mark.parametrize(
    "verify",
    ["SUCCESS", "FAILED:self-signed certificate"],
)
def test_live_proxy_client_certificate_handshake_is_accepted(monkeypatch, verify):
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    certificate = _get_client_certificate(
        _request(_certificate(), verify),
        require_proxy_verified=True,
    )
    assert certificate.subject


@pytest.mark.asyncio
async def test_storage_receipts_fail_closed_without_mtls_terminator(monkeypatch):
    monkeypatch.setattr(settings, "require_mtls_client_verify", False)
    with pytest.raises(HTTPException, match="mTLS terminator"):
        await require_fresh_storage_caller(
            db=None,
            caller=SimpleNamespace(storage_role=True, server_id="storage"),
        )


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            ReplicationCapabilityIssueRequest,
            {
                "object_id": "object",
                "target_server_id": "target",
                "ciphertext_sha256": "a" * 64,
                "ciphertext_size_bytes": True,
            },
        ),
        (
            ReplicationCapabilityCompleteRequest,
            {
                "capability": "capability",
                "ciphertext_sha256": "a" * 64,
                "ciphertext_size_bytes": "1",
            },
        ),
        (
            LegacyReplicaAdoptionRequest,
            {
                "storage_incarnation": "00000000-0000-0000-0000-000000000001",
                "objects": [
                    {
                        "object_id": "object",
                        "result": "verified",
                        "ciphertext_sha256": "a" * 64,
                        "ciphertext_size_bytes": True,
                        "plaintext_size_bytes": 1,
                        "plaintext_sha256": "b" * 64,
                    }
                ],
            },
        ),
    ],
)
def test_storage_exact_receipt_sizes_do_not_coerce(schema, payload):
    with pytest.raises(ValidationError):
        schema(**payload)
