from types import SimpleNamespace

import orjson
import pytest
from starlette.requests import Request

from api.api_key.schemas import APIKey, APIKeyScope, Action
from api.api_key.storage_scope import DENY_ACTION, DENY_OBJECT_ID, storage_authorization_scope
from api.api_key.util import OAuthTokenWrapper


def _request(method, path, payload=None):
    body = orjson.dumps(payload) if payload is not None else b""
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "scheme": "https",
            "server": ("api.test", 443),
            "client": ("127.0.0.1", 1),
        },
        receive,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/storage/volumes", ("read", "__self__")),
        ("POST", "/storage/volumes", ("write", "__self__")),
        ("GET", "/storage/volumes/volume-a", ("read", "volume-a")),
        ("DELETE", "/storage/volumes/volume-a", ("delete", "volume-a")),
        (
            "POST",
            "/storage/volumes/volume-a/objects/placement",
            ("write", "volume-a"),
        ),
        (
            "POST",
            "/storage/volumes/volume-a/objects/locate",
            ("read", "volume-a"),
        ),
        (
            "POST",
            "/storage/volumes/volume-a/objects/delete",
            ("delete", "volume-a"),
        ),
        (
            "DELETE",
            "/storage/default-volume/chutes/chute-a",
            ("delete", "__self__"),
        ),
        (
            "POST",
            "/storage/admin/chutefs/token-keys/stage",
            ("write", "__self__"),
        ),
    ],
)
async def test_storage_routes_use_semantic_volume_scopes(method, path, expected):
    assert await storage_authorization_scope(_request(method, path)) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "action"),
    [("get", "read"), ("put", "write"), ("list", "read")],
)
async def test_grant_action_follows_exact_requested_operation(operation, action):
    request = _request(
        "POST",
        "/storage/grant",
        {"volume_id": "volume-a", "ops": [operation]},
    )
    assert await storage_authorization_scope(request) == (action, "volume-a")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("PUT", "/storage/volumes/volume-a", None),
        ("GET", "/storage/volumes/volume-a/objects/locate", None),
        ("GET", "/storage/grant", None),
        ("POST", "/storage/grant", {"volume_id": "volume-a", "ops": []}),
        ("POST", "/storage/grant", {"volume_id": "volume-a", "ops": ["get", "put"]}),
        ("POST", "/storage/grant", {"volume_id": "", "ops": ["get"]}),
        ("POST", "/storage/default-volume/session/exchange", {}),
        ("POST", "/storage/default-volume/session/refresh", {}),
        ("POST", "/storage/default-volume/grant", {}),
        ("POST", "/storage/grant/verify", {}),
        ("GET", "/storage/key-nonce", None),
        ("POST", "/storage/volumes/volume-a/key", {}),
        ("GET", "/storage/unmapped", None),
        ("DELETE", "/storage/unmapped", None),
    ],
)
async def test_unmapped_or_separately_authenticated_storage_routes_deny(method, path, payload):
    assert await storage_authorization_scope(_request(method, path, payload)) == (
        DENY_ACTION,
        DENY_OBJECT_ID,
    )


def test_storage_api_key_is_volume_and_action_scoped():
    key = APIKey(admin=False)
    key.scopes = [
        APIKeyScope(
            scope_id="scope",
            api_key_id="key",
            object_type="storage",
            object_id="volume-a",
            action=Action.READ,
        )
    ]

    assert key.has_access("storage", "volume-a", "read")
    assert not key.has_access("storage", "volume-a", "delete")
    assert not key.has_access("storage", "volume-b", "read")


def test_default_deny_cannot_be_bypassed_by_administrative_credentials():
    assert not APIKey(admin=True).has_access("storage", DENY_OBJECT_ID, DENY_ACTION)
    oauth = OAuthTokenWrapper(SimpleNamespace(user_id="administrator"), ["admin"])
    assert not oauth.has_access("storage", DENY_OBJECT_ID, DENY_ACTION)
