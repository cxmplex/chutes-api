import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from api.config import settings


def test_registration_recovery_keyring_requires_explicit_configuration(monkeypatch):
    monkeypatch.setattr(settings, "gpu_registration_recovery_keys_json", None)
    monkeypatch.setattr(settings, "gpu_registration_allow_insecure_dev_key", False)

    with pytest.raises(ValueError, match="GPU_REGISTRATION_ALLOW_INSECURE_DEV_KEY"):
        _ = settings.gpu_registration_recovery_keys


def test_registration_recovery_keyring_requires_active_valid_fernet_key(monkeypatch):
    monkeypatch.setattr(settings, "gpu_registration_recovery_key_id", "active")
    monkeypatch.setattr(
        settings,
        "gpu_registration_recovery_keys_json",
        json.dumps({"retained": Fernet.generate_key().decode("ascii")}),
    )
    with pytest.raises(ValueError, match="GPU_REGISTRATION_RECOVERY_KEY_ID"):
        _ = settings.gpu_registration_recovery_keys

    monkeypatch.setattr(
        settings,
        "gpu_registration_recovery_keys_json",
        json.dumps({"active": "not-a-fernet-key"}),
    )
    with pytest.raises(ValueError, match="valid Fernet key"):
        _ = settings.gpu_registration_recovery_keys


def test_registration_recovery_keyring_rejects_cache_key_reuse(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "gpu_registration_recovery_key_id", "active")
    monkeypatch.setattr(
        settings,
        "gpu_registration_recovery_keys_json",
        json.dumps({"active": key}),
    )
    monkeypatch.setenv("CACHE_PASSPHRASE_KEY", key)

    with pytest.raises(ValueError, match="must not reuse CACHE_PASSPHRASE_KEY"):
        _ = settings.gpu_registration_recovery_keys


def test_registration_recovery_keyring_rejects_chutefs_key_reuse(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "gpu_registration_recovery_key_id", "active")
    monkeypatch.setattr(
        settings,
        "gpu_registration_recovery_keys_json",
        json.dumps({"active": key}),
    )
    monkeypatch.setattr(settings, "chutefs_token_key_id", "chutefs")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"chutefs": key}),
    )

    with pytest.raises(ValueError, match="must not reuse a ChuteFS token key"):
        _ = settings.gpu_registration_recovery_keys


def test_registration_recovery_keys_use_external_secret_and_explicit_dev_opt_in():
    root = Path(__file__).resolve().parents[2]
    helpers = (root / "charts/templates/_helpers.tpl").read_text()
    assert "name: GPU_REGISTRATION_RECOVERY_KEY_ID" in helpers
    assert "name: GPU_REGISTRATION_RECOVERY_KEYS_JSON" in helpers
    assert helpers.count("name: gpu-registration-recovery-keys") == 2
    assert "GPU_REGISTRATION_ALLOW_INSECURE_DEV_KEY" not in helpers

    for compose_name in ("docker-compose.dev.yml", "docker-compose.validator-dev.yml"):
        compose = (root / compose_name).read_text()
        assert compose.count("GPU_REGISTRATION_ALLOW_INSECURE_DEV_KEY") == compose.count(
            "CHUTEFS_ALLOW_INSECURE_DEV_KEY"
        )
