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
from api.config import Settings
from api.graval_server import resolved_ip_middleware as graval_resolved_ip_middleware
from api.main import _require_operator_peer, host_router_middleware
from api.user.service import _RESTRICTED_HOTKEY, _enforce_restricted_hotkey_ip


ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "charts"
CHART_TEMPLATES_DIR = CHART_DIR / "templates"
INGRESS_CLIENT_IP_HELPER = CHART_TEMPLATES_DIR / "_helpers.tpl"
DIRECT_API_INGRESS_TEMPLATES = tuple(
    path
    for path in sorted(CHART_TEMPLATES_DIR.glob("*-ingress.yaml"))
    if "name: api\n" in path.read_text()
)


@pytest.fixture(scope="module")
def helm_binary():
    helm = os.getenv("HELM_TEST_BINARY") or shutil.which("helm")
    if not helm:
        pytest.skip("helm binary is required for render-level chart verification")
    return helm


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


def test_operator_endpoint_dev_default_is_loopback(monkeypatch):
    monkeypatch.setenv("SKIP_METAGRAPH_CHECK", "true")
    monkeypatch.delenv("OPERATOR_ENDPOINT_CIDRS", raising=False)

    configured = Settings()

    assert configured.operator_endpoint_cidrs == ["127.0.0.0/8", "::1/128"]


def test_operator_endpoint_production_requires_explicit_allowlist(monkeypatch):
    monkeypatch.setenv("SKIP_METAGRAPH_CHECK", "false")
    monkeypatch.delenv("OPERATOR_ENDPOINT_CIDRS", raising=False)

    with pytest.raises(ValueError, match="OPERATOR_ENDPOINT_CIDRS"):
        Settings()


def test_operator_endpoint_cidr_environment_parser():
    configured = Settings(operator_endpoint_cidrs="10.42.0.0/16,2001:db8:42::/64")
    assert configured.operator_endpoint_cidrs == ["10.42.0.0/16", "2001:db8:42::/64"]


def test_operator_endpoint_uses_direct_peer_and_ignores_forwarding_headers(monkeypatch):
    monkeypatch.setattr(
        "api.main.settings.operator_endpoint_cidrs",
        ["10.0.0.0/8"],
    )

    _require_operator_peer(_request("10.20.30.40", {"X-Resolved-IP": "198.51.100.20"}))

    denied = _request(
        "198.51.100.20",
        {"X-Resolved-IP": "10.20.30.40", "X-Forwarded-For": "10.20.30.40"},
    )
    with pytest.raises(HTTPException) as exc_info:
        _require_operator_peer(denied)
    assert exc_info.value.status_code == 403


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


@pytest.mark.parametrize(
    ("value", "detail"),
    [
        ("not-an-ip", "Invalid X-Resolved-IP address."),
        ("192.0.2.1, 198.51.100.2", "X-Resolved-IP must contain one address."),
    ],
)
def test_malformed_trusted_proxy_header_returns_400_from_graval(monkeypatch, value, detail):
    monkeypatch.setattr(
        "api.client_ip.settings.trusted_proxy_cidrs",
        ["10.0.0.0/8"],
    )
    test_app = FastAPI()

    @test_app.get("/")
    async def endpoint():
        return {"status": "unexpected"}

    test_app.middleware("http")(graval_resolved_ip_middleware)
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


def test_all_direct_api_ingresses_use_shared_client_ip_boundary():
    assert {path.name for path in DIRECT_API_INGRESS_TEMPLATES} == {
        "api-ingress.yaml",
        "proxy-ingress.yaml",
    }
    for path in DIRECT_API_INGRESS_TEMPLATES:
        template = path.read_text()
        assert 'include "chutes.apiIngressClientIpAnnotations"' in template
        assert 'include "chutes.apiIngressClientIpConfiguration"' in template
        assert "nginx.ingress.kubernetes.io/configuration-snippet" in template
        assert "nginx.ingress.kubernetes.io/server-snippet" not in template
        assert "proxy_set_header X-Resolved-IP" not in template


def test_direct_api_ingress_client_ip_helper_defaults_to_direct_peer():
    template = INGRESS_CLIENT_IP_HELPER.read_text()
    values = yaml.safe_load((CHART_DIR / "values.yaml").read_text())

    assert values["ingress"]["cloudflareClientIp"]["enabled"] is False
    assert "proxy_set_header X-Resolved-IP $remote_addr;" in template
    assert "proxy_set_header X-Resolved-IP $http_cf_connecting_ip;" in template
    assert template.count("proxy_set_header X-Resolved-IP") == 2
    assert "nginx.ingress.kubernetes.io/server-snippet" not in template


def test_direct_api_ingress_cloudflare_mode_requires_whitelist():
    template = INGRESS_CLIENT_IP_HELPER.read_text()
    assert 'define "chutes.apiIngressClientIpValidation"' in template
    assert template.count('include "chutes.apiIngressClientIpValidation"') == 2
    assert 'fail "ingress.cloudflareClientIp must be a map"' in template
    assert 'fail "ingress.cloudflareClientIp.enabled must be a boolean"' in template
    assert "ingress.cloudflareClientIp contains unsupported key %q" in template
    assert (
        'fail "ingress.cloudflareClientIp.enabled requires a non-empty '
        'ingress.whitelistSourceRange"' in template
    )
    assert 'get .Values.ingress.cloudflareClientIp "enabled"' in template
    assert "(empty (trim .Values.ingress.whitelistSourceRange))" in template


@pytest.mark.parametrize(
    "template_path",
    DIRECT_API_INGRESS_TEMPLATES,
    ids=lambda path: path.name,
)
def test_direct_api_ingress_helm_rendering_enforces_client_ip_modes(template_path):
    helm = os.getenv("HELM_TEST_BINARY") or shutil.which("helm")
    if not helm:
        pytest.skip("helm binary is required for render-level chart verification")

    base = [
        helm,
        "template",
        "client-ip-test",
        str(CHART_DIR),
        "--show-only",
        f"templates/{template_path.name}",
    ]
    default = subprocess.run(base, capture_output=True, text=True, check=False)
    assert default.returncode == 0, default.stderr
    default_ingress = next(yaml.safe_load_all(default.stdout))
    default_annotations = default_ingress["metadata"]["annotations"]
    assert "nginx.ingress.kubernetes.io/server-snippet" not in default_annotations
    default_configuration = default_annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
    assert default_configuration.count("proxy_set_header X-Resolved-IP") == 1
    assert "proxy_set_header X-Resolved-IP $remote_addr;" in default_configuration
    assert "proxy_set_header X-Resolved-IP $http_cf_connecting_ip;" not in default_configuration
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
    assert "nginx.ingress.kubernetes.io/server-snippet" not in trusted_annotations
    trusted_configuration = trusted_annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
    assert trusted_configuration.count("proxy_set_header X-Resolved-IP") == 1
    assert "proxy_set_header X-Resolved-IP $http_cf_connecting_ip;" in trusted_configuration
    assert "proxy_set_header X-Resolved-IP $remote_addr;" not in trusted_configuration
    assert (
        trusted_annotations["nginx.ingress.kubernetes.io/whitelist-source-range"]
        == "173.245.48.0/20"
    )


@pytest.mark.parametrize(
    "template_path",
    DIRECT_API_INGRESS_TEMPLATES,
    ids=lambda path: path.name,
)
@pytest.mark.parametrize(
    ("cloudflare_config", "expected_error"),
    [
        ({"enabled": "false"}, "ingress.cloudflareClientIp.enabled must be a boolean"),
        ({"enabled": "true"}, "ingress.cloudflareClientIp.enabled must be a boolean"),
        ("false", "ingress.cloudflareClientIp must be a map"),
        (True, "ingress.cloudflareClientIp must be a map"),
        (None, "ingress.cloudflareClientIp must be a map"),
        ([{"enabled": False}], "ingress.cloudflareClientIp must be a map"),
        (
            {"enabled": {"value": True}},
            "ingress.cloudflareClientIp.enabled must be a boolean",
        ),
        (
            {"enabled": False, "forwardedHeader": "CF-Connecting-IP"},
            'ingress.cloudflareClientIp contains unsupported key "forwardedHeader"',
        ),
    ],
    ids=[
        "quoted-false",
        "quoted-true",
        "string-value",
        "boolean-value",
        "null-value",
        "list-value",
        "enabled-map",
        "unknown-key",
    ],
)
def test_direct_api_ingress_rejects_malformed_cloudflare_config(
    helm_binary, tmp_path, template_path, cloudflare_config, expected_error
):
    values_path = tmp_path / "values.yaml"
    values_path.write_text(
        yaml.safe_dump(
            {"ingress": {"cloudflareClientIp": cloudflare_config}},
            sort_keys=False,
        )
    )
    rendered = subprocess.run(
        [
            helm_binary,
            "template",
            "client-ip-validation-test",
            str(CHART_DIR),
            "--show-only",
            f"templates/{template_path.name}",
            "--values",
            str(values_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert rendered.returncode != 0
    assert expected_error in rendered.stderr
    assert "proxy_set_header X-Resolved-IP" not in rendered.stdout
