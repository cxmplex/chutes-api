from pathlib import Path

import yaml


class _ComposeLoader(yaml.SafeLoader):
    pass


_ComposeLoader.add_constructor(
    "!override",
    lambda loader, node: loader.construct_sequence(node),
)


def test_settings_importers_share_validator_dev_trust_posture():
    root = Path(__file__).resolve().parents[2]
    document = yaml.safe_load((root / "docker-compose.validator-dev.yml").read_text())
    required_environment = {
        "ALLOW_DEBUG_MEASUREMENTS": "true",
        "ALLOW_DEV_ATTESTED_MTLS": "true",
        "REQUIRE_MTLS_CLIENT_VERIFY": "true",
        "SKIP_METAGRAPH_CHECK": "true",
        "TEE_MEASUREMENT_CONFIG_REQUIRED": "true",
        "TRUSTED_PROXY_CIDRS": "172.18.0.10/32",
        "TRUSTED_PROVENANCE_PUBLIC_KEY_PATH": "/etc/chutes/provenance/cosign.pub",
        "TRUSTED_L0_PUBLISHER_KEYS_PATH": "/etc/chutes/l0-publisher/keys.json",
    }
    required_mounts = {
        "/etc/chutes/provenance/cosign.pub:/etc/chutes/provenance/cosign.pub:ro",
        "./config/l0-publisher-keys.json:/etc/chutes/l0-publisher/keys.json:ro",
        "./config/tee_measurements.yaml:/etc/config/tee_measurements.yaml:ro",
    }

    for service_name in ("api", "socket", "events_socket", "forge"):
        service = document["services"][service_name]
        assert service["environment"] == required_environment
        assert set(service["volumes"]) == required_mounts


def test_dev_gpu_scheduler_mounts_exact_l0_publisher_registry_contract():
    root = Path(__file__).resolve().parents[2]
    document = yaml.load(
        (root / "docker-compose.dev.yml").read_text(),
        Loader=_ComposeLoader,
    )
    scheduler = document["services"]["gpu_platform_scheduler"]
    assert scheduler["environment"]["TRUSTED_L0_PUBLISHER_KEYS_PATH"] == (
        "/etc/chutes/l0-publisher/keys.json"
    )
    assert (
        "./config/l0-publisher-keys.json:/etc/chutes/l0-publisher/keys.json:ro"
        in scheduler["volumes"]
    )
