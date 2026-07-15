"""Canonical request client-IP resolution across an explicit proxy boundary."""

import ipaddress

from fastapi import HTTPException, Request

from api.config import settings


def resolve_client_ip(request: Request) -> tuple[str, bool]:
    """Return (client_ip, used_proxy_header) for the directly connected peer."""
    peer = request.client.host if request.client else ""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer, False

    trusted = any(
        peer_ip in ipaddress.ip_network(cidr, strict=False) for cidr in settings.trusted_proxy_cidrs
    )
    if not trusted:
        return str(peer_ip), False

    forwarded = (request.headers.get("X-Resolved-IP") or "").strip()
    if not forwarded:
        return str(peer_ip), False
    if "," in forwarded:
        raise HTTPException(status_code=400, detail="X-Resolved-IP must contain one address.")
    try:
        return str(ipaddress.ip_address(forwarded)), True
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Resolved-IP address.") from exc
