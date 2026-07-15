from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.client_ip import resolve_client_ip
from api.user.service import _RESTRICTED_HOTKEY, _enforce_restricted_hotkey_ip


def _request(peer: str, headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": raw_headers,
            "client": (peer, 12345),
            "server": ("api", 8000),
        }
    )


def test_untrusted_peer_cannot_spoof_resolved_or_forwarded_ip(monkeypatch):
    monkeypatch.setattr(
        "api.client_ip.settings.trusted_proxy_cidrs",
        ["10.0.0.0/8"],
    )
    request = _request(
        "198.51.100.20",
        {
            "X-Resolved-IP": "207.246.94.14",
            "X-Forwarded-For": "207.246.94.14",
        },
    )

    assert resolve_client_ip(request) == ("198.51.100.20", False)


def test_trusted_direct_proxy_owns_single_resolved_ip(monkeypatch):
    monkeypatch.setattr(
        "api.client_ip.settings.trusted_proxy_cidrs",
        ["10.0.0.0/8"],
    )
    request = _request("10.20.30.40", {"X-Resolved-IP": "2001:db8::1"})

    assert resolve_client_ip(request) == ("2001:db8::1", True)


@pytest.mark.parametrize("value", ["not-an-ip", "192.0.2.1, 198.51.100.2"])
def test_trusted_proxy_malformed_value_fails_closed(monkeypatch, value):
    monkeypatch.setattr(
        "api.client_ip.settings.trusted_proxy_cidrs",
        ["10.0.0.0/8"],
    )
    with pytest.raises(HTTPException) as exc_info:
        resolve_client_ip(_request("10.20.30.40", {"X-Resolved-IP": value}))
    assert exc_info.value.status_code == 400


def test_restricted_hotkey_uses_middleware_owned_state():
    request = SimpleNamespace(state=SimpleNamespace(client_ip="198.51.100.20"))
    with pytest.raises(HTTPException) as exc_info:
        _enforce_restricted_hotkey_ip(request, _RESTRICTED_HOTKEY, "images")
    assert exc_info.value.status_code == 401
