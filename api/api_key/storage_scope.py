import re

import orjson
from fastapi import Request


async def storage_authorization_scope(request: Request) -> tuple[str, str]:
    """Map ChuteFS route semantics to an action and volume-scoped authorization object."""
    path = request.url.path.rstrip("/")
    method = request.method.upper()
    volume_match = re.match(r"^/storage/volumes/([^/]+)(?:/|$)", path)
    volume_id = volume_match.group(1) if volume_match else "__self__"

    if path == "/storage/volumes":
        return ("write" if method == "POST" else "read", "__self__")
    if volume_match and path == f"/storage/volumes/{volume_id}":
        return ("delete" if method == "DELETE" else "read", volume_id)
    if path.endswith("/objects/placement") or path.endswith("/objects/commit"):
        return "write", volume_id
    if path.endswith("/objects/locate") or path.endswith("/objects/list"):
        return "read", volume_id
    if path.endswith("/objects/delete"):
        return "delete", volume_id
    if path == "/storage/grant" and method == "POST":
        try:
            payload = orjson.loads(await request.body())
            grant_volume = str(payload["volume_id"])
            operations = payload["ops"]
            if (
                not isinstance(operations, list)
                or len(operations) != 1
                or operations[0] not in {"get", "put", "list"}
            ):
                return "write", "__list_or_invalid__"
            return {
                "get": "read",
                "put": "write",
                "list": "read",
            }[operations[0]], grant_volume
        except (KeyError, TypeError, ValueError, orjson.JSONDecodeError):
            return "write", "__list_or_invalid__"
    return "read", "__self__"
