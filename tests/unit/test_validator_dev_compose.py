from pathlib import Path

import yaml


def test_settings_importers_share_validator_dev_trust_posture():
    root = Path(__file__).resolve().parents[2]
    document = yaml.safe_load((root / "docker-compose.validator-dev.yml").read_text())
    required_environment = {
        "ALLOW_DEBUG_MEASUREMENTS": "true",
        "ALLOW_DEV_ATTESTED_MTLS": "true",
        "REQUIRE_MTLS_CLIENT_VERIFY": "true",
        "SKIP_METAGRAPH_CHECK": "true",
        "TEE_MEASUREMENT_CONFIG_REQUIRED": "true",
        "TRUSTED_PROXY_CIDRS": "172.16.0.0/12,127.0.0.0/8,::1/128",
        "TRUSTED_PROVENANCE_PUBLIC_KEY_PATH": "/etc/chutes/provenance/cosign.pub",
    }
    required_mounts = {
        "/etc/chutes/provenance/cosign.pub:/etc/chutes/provenance/cosign.pub:ro",
        "./config/tee_measurements.yaml:/etc/config/tee_measurements.yaml:ro",
    }

    for service_name in ("api", "socket", "events_socket", "forge"):
        service = document["services"][service_name]
        assert service["environment"] == required_environment
        assert set(service["volumes"]) == required_mounts
