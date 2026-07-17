import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from api.client_ip import resolve_client_ip
from api.main import host_router_middleware
from api.user.service import _RESTRICTED_HOTKEY, _enforce_restricted_hotkey_ip


ROOT = Path(__file__).resolve().parents[2]
API_INGRESS_TEMPLATE = ROOT / "charts/templates/api-ingress.yaml"
CHART_DIR = ROOT / "charts"


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


@pytest.mark.parametrize(
    ("value", "detail"),
    [
        ("not-an-ip", "Invalid X-Resolved-IP address."),
        ("192.0.2.1, 198.51.100.2", "X-Resolved-IP must contain one address."),
    ],
)
def test_malformed_trusted_proxy_header_returns_400_from_middleware(monkeypatch, value, detail):
    monkeypatch.setattr(
        "api.client_ip.settings.trusted_proxy_cidrs",
        ["10.0.0.0/8"],
    )
    test_app = FastAPI()

    @test_app.get("/")
    async def endpoint():
        return {"status": "unexpected"}

    test_app.middleware("http")(host_router_middleware)
    with TestClient(
        test_app,
        raise_server_exceptions=False,
        client=("10.20.30.40", 12345),
    ) as client:
        response = client.get("/", headers={"X-Resolved-IP": value})

    assert response.status_code == 400
    assert response.json() == {"detail": detail}


def test_restricted_hotkey_uses_middleware_owned_state():
    request = SimpleNamespace(state=SimpleNamespace(client_ip="198.51.100.20"))
    with pytest.raises(HTTPException) as exc_info:
        _enforce_restricted_hotkey_ip(request, _RESTRICTED_HOTKEY, "images")
    assert exc_info.value.status_code == 401


def test_public_api_ingress_defaults_to_direct_peer_ip():
    template = API_INGRESS_TEMPLATE.read_text()
    values = yaml.safe_load((CHART_DIR / "values.yaml").read_text())

    assert values["ingress"]["cloudflareClientIp"]["enabled"] is False
    assert "proxy_set_header X-Resolved-IP $remote_addr;" in template
    assert "proxy_set_header X-Resolved-IP $http_cf_connecting_ip;" in template
    assert template.count("proxy_set_header X-Resolved-IP") == 2


def test_public_api_ingress_cloudflare_mode_requires_whitelist():
    template = API_INGRESS_TEMPLATE.read_text()
    assert (
        'fail "ingress.cloudflareClientIp.enabled requires a non-empty '
        'ingress.whitelistSourceRange"' in template
    )
    assert ".Values.ingress.cloudflareClientIp.enabled" in template
    assert "(empty (trim .Values.ingress.whitelistSourceRange))" in template


def test_public_api_ingress_helm_rendering_enforces_client_ip_modes():
    helm = os.getenv("HELM_TEST_BINARY") or shutil.which("helm")
    if not helm:
        pytest.skip("helm binary is required for render-level chart verification")

    base = [
        helm,
        "template",
        "client-ip-test",
        str(CHART_DIR),
        "--show-only",
        "templates/api-ingress.yaml",
    ]
    default = subprocess.run(base, capture_output=True, text=True, check=False)
    assert default.returncode == 0, default.stderr
    default_ingress = next(yaml.safe_load_all(default.stdout))
    default_annotations = default_ingress["metadata"]["annotations"]
    assert (
        default_annotations["nginx.ingress.kubernetes.io/server-snippet"]
        == "proxy_set_header X-Resolved-IP $remote_addr;"
    )
    assert "nginx.ingress.kubernetes.io/whitelist-source-range" not in default_annotations

    unsafe = subprocess.run(
        [*base, "--set", "ingress.cloudflareClientIp.enabled=true"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert unsafe.returncode != 0
    assert (
        "ingress.cloudflareClientIp.enabled requires a non-empty "
        "ingress.whitelistSourceRange" in unsafe.stderr
    )

    trusted = subprocess.run(
        [
            *base,
            "--set",
            "ingress.cloudflareClientIp.enabled=true",
            "--set-string",
            "ingress.whitelistSourceRange=173.245.48.0/20",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert trusted.returncode == 0, trusted.stderr
    trusted_ingress = next(yaml.safe_load_all(trusted.stdout))
    trusted_annotations = trusted_ingress["metadata"]["annotations"]
    assert (
        trusted_annotations["nginx.ingress.kubernetes.io/server-snippet"]
        == "proxy_set_header X-Resolved-IP $http_cf_connecting_ip;"
    )
    assert (
        trusted_annotations["nginx.ingress.kubernetes.io/whitelist-source-range"]
        == "173.245.48.0/20"
    )
