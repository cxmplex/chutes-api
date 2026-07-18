import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "charts"


@pytest.fixture(scope="module")
def helm_binary():
    helm = os.getenv("HELM_TEST_BINARY") or shutil.which("helm")
    if not helm:
        pytest.skip("helm binary is required for render-level chart verification")
    return helm


def _render_chart(helm_binary, tmp_path, values=None, show_only=None):
    command = [helm_binary, "template", "security-test", str(CHART_DIR)]
    if show_only:
        command.extend(["--show-only", f"templates/{show_only}"])
    if values is not None:
        values_path = tmp_path / "values.yaml"
        values_path.write_text(yaml.safe_dump(values, sort_keys=False))
        command.extend(["--values", str(values_path)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _documents(rendered):
    return [document for document in yaml.safe_load_all(rendered.stdout) if document]


def _document(documents, kind, name):
    return next(
        document
        for document in documents
        if document["kind"] == kind and document["metadata"]["name"] == name
    )


def _container(deployment, name):
    return next(
        container
        for container in deployment["spec"]["template"]["spec"]["containers"]
        if container["name"] == name
    )


def _environment(container):
    return {entry["name"]: entry for entry in container["env"]}


def test_remote_forge_omits_redis_ca_cleanly_and_applies_security_contexts(helm_binary, tmp_path):
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={"remoteForge": {"enabled": True}},
        show_only="remote-forge-deployment.yaml",
    )
    assert rendered.returncode == 0, rendered.stderr
    deployment = _document(_documents(rendered), "Deployment", "remote-forge")
    pod_spec = deployment["spec"]["template"]["spec"]
    container = _container(deployment, "remote-forge")

    assert pod_spec["securityContext"] == {"seccompProfile": {"type": "RuntimeDefault"}}
    assert container["securityContext"] == {"capabilities": {"drop": ["NET_RAW"]}}
    assert "readOnlyRootFilesystem" not in container["securityContext"]
    assert _environment(container)["TRUSTED_PROXY_CIDRS"]["value"] == ""
    assert "REDIS_CACERT" not in _environment(container)
    assert {mount["name"] for mount in container["volumeMounts"]} == {"cosign-key"}
    assert {volume["name"] for volume in pod_spec["volumes"]} == {"cosign-key"}


def test_remote_forge_projects_exact_redis_ca_secret(helm_binary, tmp_path):
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "remoteForge": {"enabled": True},
            "redis": {
                "cacertSecret": "managed-redis-ca",
                "cacertMode": 0o440,
            },
        },
        show_only="remote-forge-deployment.yaml",
    )
    assert rendered.returncode == 0, rendered.stderr
    deployment = _document(_documents(rendered), "Deployment", "remote-forge")
    pod_spec = deployment["spec"]["template"]["spec"]
    container = _container(deployment, "remote-forge")
    environment = _environment(container)
    mount = next(mount for mount in container["volumeMounts"] if mount["name"] == "redis-cacert")
    volume = next(volume for volume in pod_spec["volumes"] if volume["name"] == "redis-cacert")

    assert environment["REDIS_CACERT"] == {
        "name": "REDIS_CACERT",
        "value": "/etc/redis-cacert/cacert.pem",
    }
    assert mount == {
        "name": "redis-cacert",
        "mountPath": "/etc/redis-cacert",
        "readOnly": True,
    }
    assert volume == {
        "name": "redis-cacert",
        "secret": {
            "secretName": "managed-redis-ca",
            "defaultMode": 0o440,
            "items": [{"key": "ca", "path": "cacert.pem"}],
        },
    }


@pytest.mark.parametrize(
    "values",
    [
        None,
        {
            "networkPolicies": {
                "enabled": False,
                "internalCidr": "10.222.0.0/16",
            }
        },
    ],
    ids=["defaults", "network-policies-disabled"],
)
def test_chart_defaults_to_no_trusted_proxies(helm_binary, tmp_path, values):
    rendered = _render_chart(helm_binary, tmp_path, values=values)
    assert rendered.returncode == 0, rendered.stderr
    documents = _documents(rendered)
    deployment = _document(documents, "Deployment", "api")

    assert _environment(_container(deployment, "api"))["TRUSTED_PROXY_CIDRS"]["value"] == ""
    assert not any(
        document["kind"] == "NetworkPolicy" and document["metadata"]["name"] == "api-ingress-netpol"
        for document in documents
    )


def test_explicit_trusted_proxy_cidrs_render_unchanged_with_external_policy_acknowledgement(
    helm_binary, tmp_path
):
    trusted_cidrs = "10.42.1.0/24,2001:db8:42::/64"
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "trustedProxyCidrs": trusted_cidrs,
            "networkPolicies": {
                "enabled": False,
                "api": {"externalPolicyAcknowledged": True},
            },
        },
        show_only="api-deployment.yaml",
    )
    assert rendered.returncode == 0, rendered.stderr
    deployment = _document(_documents(rendered), "Deployment", "api")

    assert (
        _environment(_container(deployment, "api"))["TRUSTED_PROXY_CIDRS"]["value"] == trusted_cidrs
    )


@pytest.mark.parametrize(
    "network_policy_values",
    [
        {},
        {
            "enabled": False,
            "api": {
                "enabled": True,
                "ingressPeers": [
                    {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "ingress-nginx"}}}
                ],
            },
        },
    ],
    ids=["no-api-policy", "globally-disabled-api-policy"],
)
def test_trusted_proxy_cidrs_without_effective_peer_isolation_are_rejected(
    helm_binary, tmp_path, network_policy_values
):
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "trustedProxyCidrs": "10.42.0.0/16",
            "networkPolicies": network_policy_values,
        },
        show_only="api-deployment.yaml",
    )

    assert rendered.returncode != 0
    assert (
        "trustedProxyCidrs requires networkPolicies.enabled=true with "
        "networkPolicies.api.enabled=true and non-empty networkPolicies.api.ingressPeers"
        in rendered.stderr
    )


def test_api_network_policy_selects_api_and_only_allows_explicit_peers(helm_binary, tmp_path):
    peers = [
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}},
            "podSelector": {"matchLabels": {"app.kubernetes.io/component": "controller"}},
        },
        {"ipBlock": {"cidr": "10.42.8.0/24", "except": ["10.42.8.128/25"]}},
    ]
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "trustedProxyCidrs": "10.42.8.0/25",
            "networkPolicies": {
                "enabled": True,
                "api": {
                    "enabled": True,
                    "ingressPeers": peers,
                },
            },
        },
    )
    assert rendered.returncode == 0, rendered.stderr
    documents = _documents(rendered)
    policy = _document(documents, "NetworkPolicy", "api-ingress-netpol")
    api_deployment = _document(documents, "Deployment", "api")

    assert policy["spec"] == {
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "api"}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": peers,
                "ports": [{"port": 8000, "protocol": "TCP"}],
            }
        ],
    }
    api_labels = api_deployment["spec"]["template"]["metadata"]["labels"]
    assert api_labels["app.kubernetes.io/name"] == "api"
    assert policy["spec"]["ingress"][0]["from"]
    assert {} not in policy["spec"]["ingress"][0]["from"]


def test_enabled_api_network_policy_requires_peers(helm_binary, tmp_path):
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "networkPolicies": {
                "enabled": True,
                "api": {"enabled": True, "ingressPeers": []},
            }
        },
    )

    assert rendered.returncode != 0
    assert (
        "networkPolicies.api.enabled requires non-empty networkPolicies.api.ingressPeers"
        in rendered.stderr
    )


@pytest.mark.parametrize(
    "peer",
    [
        {},
        {"podSelector": {}},
        {"namespaceSelector": {}},
        {"ipBlock": {"cidr": "0.0.0.0/0"}},
        {"ipBlock": {"cidr": "::/0"}},
    ],
)
def test_api_network_policy_rejects_allow_all_peers(helm_binary, tmp_path, peer):
    rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={
            "networkPolicies": {
                "enabled": True,
                "api": {"enabled": True, "ingressPeers": [peer]},
            }
        },
    )

    assert rendered.returncode != 0
    assert "networkPolicies.api.ingressPeers[0]" in rendered.stderr


def test_known_nginx_final_hops_overwrite_resolved_ip(helm_binary, tmp_path):
    registry_rendered = _render_chart(
        helm_binary,
        tmp_path,
        show_only="registry-proxy-cm.yaml",
    )
    assert registry_rendered.returncode == 0, registry_rendered.stderr
    registry_config = _document(
        _documents(registry_rendered), "ConfigMap", "registry-proxy-config"
    )["data"]["nginx.conf.template"]
    registry_auth = registry_config.split("location = /auth {", 1)[1].split("location @block", 1)[0]

    assert registry_auth.count("proxy_pass http://api.") == 1
    assert registry_auth.count("proxy_set_header X-Resolved-IP $remote_addr;") == 1
    assert "$http_x_resolved_ip" not in registry_auth

    attestation_rendered = _render_chart(
        helm_binary,
        tmp_path,
        values={"attestationProxy": {"enabled": True}},
        show_only="attestation-proxy-cm.yaml",
    )
    assert attestation_rendered.returncode == 0, attestation_rendered.stderr
    attestation_config = _document(
        _documents(attestation_rendered), "ConfigMap", "attestation-proxy-config"
    )["data"]["nginx.conf"]

    assert attestation_config.count("proxy_pass http://api.") == 2
    assert attestation_config.count("proxy_set_header X-Resolved-IP $remote_addr;") == 2
    assert "$http_x_resolved_ip" not in attestation_config


@pytest.mark.parametrize(
    ("trusted_proxy_env", "expected"),
    [
        (None, ["127.0.0.0/8", "::1/128"]),
        ("", []),
        ("10.42.1.0/24,2001:db8:42::/64", ["10.42.1.0/24", "2001:db8:42::/64"]),
    ],
    ids=["standalone-default", "explicit-empty-chart-override", "explicit-cidrs"],
)
def test_trusted_proxy_environment_parsing(trusted_proxy_env, expected):
    environment = os.environ.copy()
    environment["TEE_MEASUREMENT_CONFIG_REQUIRED"] = "false"
    if trusted_proxy_env is None:
        environment.pop("TRUSTED_PROXY_CIDRS", None)
    else:
        environment["TRUSTED_PROXY_CIDRS"] = trusted_proxy_env

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; "
                "from api.config import settings; "
                'print("TRUSTED_PROXY_RESULT=" + json.dumps(settings.trusted_proxy_cidrs))'
            ),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result_line = next(
        line for line in completed.stdout.splitlines() if line.startswith("TRUSTED_PROXY_RESULT=")
    )

    assert json.loads(result_line.removeprefix("TRUSTED_PROXY_RESULT=")) == expected
