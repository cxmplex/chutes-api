"""GPU Registration V2 requires live proxy-verified certificate possession."""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from starlette.requests import Request

from api.config import settings
from api.server.router import (
    _gpu_registration_live_cert_hash,
    _gpu_registration_live_cert_pem,
    router,
)


def _certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gpu-registrar")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _request(cert_pem: str, verify: str | None, path: str) -> Request:
    headers = [(b"x-client-cert", quote(cert_pem).encode())]
    if verify is not None:
        headers.append((b"x-client-verify", verify.encode()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
        }
    )


def test_all_gpu_registration_v2_routes_use_live_certificate_dependency() -> None:
    routes = {route.path: route for route in router.routes}
    nonce_calls = {
        dependency.call
        for dependency in routes["/gpu/registration/nonces"].dependant.dependencies
    }
    post_calls = {
        dependency.call
        for dependency in routes["/gpu/registration/attempts"].dependant.dependencies
    }
    get_calls = {
        dependency.call
        for dependency in routes[
            "/gpu/registration/attempts/{attempt_id}"
        ].dependant.dependencies
    }
    assert _gpu_registration_live_cert_hash in nonce_calls
    assert _gpu_registration_live_cert_hash in post_calls
    assert _gpu_registration_live_cert_pem in post_calls
    assert _gpu_registration_live_cert_hash in get_calls


@pytest.mark.asyncio
async def test_forwarded_certificate_without_live_handshake_cannot_register_or_replay(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    cert_pem = _certificate()
    for path in (
        "/gpu/registration/nonces",
        "/gpu/registration/attempts",
        "/gpu/registration/attempts/attempt-id",
    ):
        request = _request(cert_pem, None, path)
        with pytest.raises(HTTPException) as rejected:
            await _gpu_registration_live_cert_hash(request)
        assert rejected.value.status_code == 401
    with pytest.raises(HTTPException) as rejected:
        await _gpu_registration_live_cert_pem(
            _request(cert_pem, None, "/gpu/registration/attempts")
        )
    assert rejected.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("verify", ["SUCCESS", "FAILED:self-signed certificate"])
async def test_optional_no_ca_live_client_verification_is_accepted(
    monkeypatch, verify
) -> None:
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    cert_pem = _certificate()
    request = _request(cert_pem, verify, "/gpu/registration/attempts")
    assert await _gpu_registration_live_cert_hash(request)
    assert await _gpu_registration_live_cert_pem(request) == cert_pem
