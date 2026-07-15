"""Storage control-plane calls require proxy-proven live certificate possession."""

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest
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


def _certificate() -> str:
    return (Path(__file__).resolve().parents[1] / "assets/snp/gcp-ak-root.pem").read_text()


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
