import re

import orjson
from fastapi import Request


DENY_ACTION = "__deny__"
DENY_OBJECT_ID = "__list_or_invalid__"


def _deny() -> tuple[str, str]:
    return DENY_ACTION, DENY_OBJECT_ID


async def storage_authorization_scope(request: Request) -> tuple[str, str]:
    """Map only explicitly supported API-key storage routes; every other route denies."""
    path = request.url.path.rstrip("/")
    method = request.method.upper()

    if path == "/storage/volumes":
        if method == "GET":
            return "read", "__self__"
        if method == "POST":
            return "write", "__self__"
        return _deny()

    volume_match = re.fullmatch(r"/storage/volumes/([^/]+)", path)
    if volume_match:
        volume_id = volume_match.group(1)
        if method == "GET":
            return "read", volume_id
        if method == "DELETE":
            return "delete", volume_id
        return _deny()

    operation_match = re.fullmatch(
        r"/storage/volumes/([^/]+)/objects/(placement|commit|locate|list|delete)",
        path,
    )
    if operation_match:
        if method != "POST":
            return _deny()
        volume_id, operation = operation_match.groups()
        return {
            "placement": "write",
            "commit": "write",
            "locate": "read",
            "list": "read",
            "delete": "delete",
        }[operation], volume_id

    if path == "/storage/grant":
        if method != "POST":
            return _deny()
        try:
            payload = orjson.loads(await request.body())
            grant_volume = payload["volume_id"]
            operations = payload["ops"]
            if (
                not isinstance(grant_volume, str)
                or not grant_volume
                or not isinstance(operations, list)
                or len(operations) != 1
                or operations[0] not in {"get", "put", "list"}
            ):
                return _deny()
            return {
                "get": "read",
                "put": "write",
                "list": "read",
            }[operations[0]], grant_volume
        except (KeyError, TypeError, ValueError, orjson.JSONDecodeError):
            return _deny()

    if re.fullmatch(r"/storage/default-volume/chutes/[^/]+", path):
        return ("delete", "__self__") if method == "DELETE" else _deny()

    administrator_routes = {
        "/storage/admin/erase/retire",
        "/storage/admin/chutefs/token-keys/stage",
        "/storage/admin/chutefs/token-keys/activate",
        "/storage/admin/chutefs/token-keys/retire",
    }
    if path in administrator_routes:
        return ("write", "__self__") if method == "POST" else _deny()

    # Launch-bound sessions/default-volume routes and storage-TD internal routes use their own
    # authentication. They must never inherit an API key's generic read/write/delete authority.
    return _deny()
