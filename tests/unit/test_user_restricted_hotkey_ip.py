import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.user.service import (
    _RESTRICTED_HOTKEY,
    _enforce_restricted_hotkey_ip,
)


def _request(client_ip: str) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "scheme": "https",
            "server": ("api.test", 443),
            "client": ("198.51.100.10", 1234),
        }
    )
    request.state.client_ip = client_ip
    return request


def test_restricted_hotkey_rejects_wrong_middleware_ip():
    with pytest.raises(HTTPException) as exc:
        _enforce_restricted_hotkey_ip(
            _request("198.51.100.20"),
            _RESTRICTED_HOTKEY,
            "tee",
        )
    assert exc.value.status_code == 401


def test_restricted_hotkey_accepts_allowed_middleware_ip():
    _enforce_restricted_hotkey_ip(
        _request("207.246.94.14"),
        _RESTRICTED_HOTKEY,
        "tee",
    )
