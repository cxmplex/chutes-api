"""GPU runtime authority requires the current live attested certificate."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from starlette.requests import Request

from api.config import settings
from api.server import router as server_router
from api.server import service as server_service
from api.server.exceptions import ServerNotFoundError
from api.server.service import check_server_ownership
from api.server.util import get_public_key_hash, require_live_attested_client_cert
from api.user import service as user_service


def _certificate(name: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )


def _request(cert: x509.Certificate | None, *, path: str) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cert is not None:
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        headers.extend(
            [
                (b"x-client-cert", quote(cert_pem, safe="").encode()),
                (b"x-client-verify", b"FAILED:self-signed certificate"),
            ]
        )
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
            "state": {"client_ip": "192.0.2.30"},
        }
    )


def _gpu_server(cert: x509.Certificate):
    return SimpleNamespace(
        server_id="gpu-server",
        ip="192.0.2.30",
        miner_hotkey="owner-hotkey",
        compute_type="gpu",
        launch_reservation_id=None,
        gpu_launch_reservation_id="gpu-reservation",
        attested_cert=cert.public_bytes(serialization.Encoding.PEM).decode(),
        attested_cert_pubkey_hash=get_public_key_hash(cert),
    )


def _db_for(server):
    result = Mock()
    result.scalar_one_or_none.return_value = server
    db = AsyncMock()
    db.execute.return_value = result
    db.get.return_value = server
    return db


def test_live_attested_cert_requires_current_proxy_proven_identity(monkeypatch):
    current = _certificate("current")
    stale = _certificate("stale")
    server = _gpu_server(current)
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)

    assert require_live_attested_client_cert(
        _request(current, path="/gpu"),
        server,
    ) == get_public_key_hash(current)
    with pytest.raises(HTTPException, match="current attested identity") as stale_error:
        require_live_attested_client_cert(
            _request(stale, path="/gpu"),
            server,
        )
    assert stale_error.value.status_code == 403
    with pytest.raises(HTTPException, match="could not be verified") as missing_error:
        require_live_attested_client_cert(
            _request(None, path="/gpu"),
            server,
        )
    assert missing_error.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("hotkey", "cert_selector", "allowed"),
    [
        (None, "current", True),
        ("owner-hotkey", "current", True),
        ("different-hotkey", "current", False),
        ("owner-hotkey", "stale", False),
    ],
)
async def test_gpu_guest_possession_uses_current_cert_and_matching_optional_hotkey(
    monkeypatch,
    hotkey,
    cert_selector,
    allowed,
):
    current = _certificate("ownership-current")
    stale = _certificate("ownership-stale")
    server = _gpu_server(current)
    db = _db_for(server)
    monkeypatch.setattr(server_service.settings, "skip_metagraph_check", True)
    expected_cert_hash = get_public_key_hash(current if cert_selector == "current" else stale)

    if allowed:
        assert (
            await check_server_ownership(
                db,
                server.server_id,
                hotkey,
                expected_cert_hash,
            )
            is server
        )
    else:
        with pytest.raises(ServerNotFoundError):
            await check_server_ownership(
                db,
                server.server_id,
                hotkey,
                expected_cert_hash,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("hotkey", "allowed"),
    [
        ("owner-hotkey", True),
        (None, False),
        ("different-hotkey", False),
    ],
)
async def test_gpu_management_without_cert_retains_owner_auth(
    monkeypatch,
    hotkey,
    allowed,
):
    server = _gpu_server(_certificate("management"))
    db = _db_for(server)
    monkeypatch.setattr(server_service.settings, "skip_metagraph_check", True)

    if allowed:
        assert await check_server_ownership(db, server.server_id, hotkey) is server
    else:
        with pytest.raises(ServerNotFoundError):
            await check_server_ownership(db, server.server_id, hotkey)


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["nonce", "attestation"])
@pytest.mark.parametrize("presentation", ["missing", "stale"])
async def test_gpu_runtime_endpoints_reject_missing_or_stale_live_cert(
    monkeypatch,
    endpoint,
    presentation,
):
    current = _certificate("runtime-current")
    stale = _certificate("runtime-stale")
    server = _gpu_server(current)
    db = _db_for(server)
    request = _request(
        None if presentation == "missing" else stale,
        path=f"/servers/{server.server_id}/{endpoint}",
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    create_nonce = AsyncMock()
    consume_nonce = AsyncMock()

    with (
        patch.object(server_router, "create_nonce", create_nonce),
        patch.object(server_router, "validate_and_consume_nonce", consume_nonce),
        pytest.raises(HTTPException) as error,
    ):
        if endpoint == "nonce":
            await server_router.get_runtime_nonce(
                request,
                server.server_id,
                db,
                hotkey=server.miner_hotkey,
                _=None,
            )
        else:
            await server_router.verify_runtime_attestation(
                request,
                server.server_id,
                Mock(),
                db,
                hotkey=server.miner_hotkey,
                _=None,
                nonce="12" * 32,
            )

    assert error.value.status_code == (403 if presentation == "missing" else 404)
    create_nonce.assert_not_awaited()
    consume_nonce.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("presentation", ["missing", "stale"])
async def test_generic_gpu_runtime_session_auth_rejects_missing_or_stale_cert(
    monkeypatch,
    presentation,
):
    current = _certificate("session-current")
    stale = _certificate("session-stale")
    server = _gpu_server(current)
    db = AsyncMock()

    @asynccontextmanager
    async def session_scope(*_args, **_kwargs):
        yield db

    runtime_validator = AsyncMock(return_value=(server, {"exp": 1234567890}))
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    monkeypatch.setattr(user_service, "get_session", session_scope)
    monkeypatch.setattr(
        user_service,
        "validate_gpu_runtime_session",
        runtime_validator,
    )
    authenticate = user_service.get_current_user(
        purpose="instances",
        raise_not_found=False,
    )
    request = _request(
        None if presentation == "missing" else stale,
        path="/instances/gpu-instance",
    )

    with pytest.raises(HTTPException) as error:
        await authenticate(
            request,
            api_key=None,
            hotkey=None,
            signature=None,
            nonce=None,
            authorization=None,
            sig_version=None,
            attested_session="gpu-runtime-session",
        )

    assert error.value.status_code == 403
    runtime_validator.assert_awaited_once()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_generic_gpu_runtime_session_auth_accepts_current_live_cert(
    monkeypatch,
):
    current = _certificate("session-current-positive")
    server = _gpu_server(current)
    result = Mock()
    result.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute.return_value = result

    @asynccontextmanager
    async def session_scope(*_args, **_kwargs):
        yield db

    runtime_validator = AsyncMock(return_value=(server, {"exp": 1234567890}))
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    monkeypatch.setattr(user_service, "get_session", session_scope)
    monkeypatch.setattr(
        user_service,
        "validate_gpu_runtime_session",
        runtime_validator,
    )
    authenticate = user_service.get_current_user(
        purpose="instances",
        raise_not_found=False,
    )
    request = _request(
        current,
        path="/instances/gpu-instance",
    )

    assert (
        await authenticate(
            request,
            api_key=None,
            hotkey=None,
            signature=None,
            nonce=None,
            authorization=None,
            sig_version=None,
            attested_session="gpu-runtime-session",
        )
        is None
    )
    assert request.state.gpu_runtime_server_id == server.server_id
    assert request.state.gpu_runtime_session_expires_at == 1234567890
    runtime_validator.assert_awaited_once()
    db.execute.assert_awaited_once()
