import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.user.service import (
    _RESTRICTED_HOTKEY,
    _enforce_restricted_hotkey_ip,
)


def _request(x_forwarded_for: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", x_forwarded_for.encode())],
            "scheme": "https",
            "server": ("api.test", 443),
            "client": ("198.51.100.10", 1234),
        }
    )


def test_restricted_hotkey_ignores_spoofed_leftmost_xff():
    with pytest.raises(HTTPException) as exc:
        _enforce_restricted_hotkey_ip(
            _request("207.246.94.14, 198.51.100.20"),
            _RESTRICTED_HOTKEY,
            "tee",
        )
    assert exc.value.status_code == 401


def test_restricted_hotkey_accepts_trusted_rightmost_xff():
    _enforce_restricted_hotkey_ip(
        _request("198.51.100.20, 207.246.94.14"),
        _RESTRICTED_HOTKEY,
        "tee",
    )
