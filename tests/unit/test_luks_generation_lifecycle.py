"""State-machine tests for recoverable LUKS key promotion and generation fencing."""

from cryptography.fernet import Fernet
from fastapi import HTTPException
from pathlib import Path
import pytest

from api.server import util as server_util
from api.server.schemas import (
    LuksCapabilityContext,
    LuksCapabilityPurpose,
    LuksVolumeConfirmStatus,
    VmCacheConfig,
)


OWNER = "5FGenerationOwner"
VM_NAME = "storage-vm"
SERVER_ID = "storage-server"
CERT_A = "a" * 64
CERT_B = "b" * 64
VOLUME = "chutefs-data"


@pytest.fixture(autouse=True)
def real_passphrase_cipher(monkeypatch):
    cipher = Fernet(Fernet.generate_key())
    monkeypatch.setattr(server_util, "_get_fernet", lambda: cipher)
    return cipher


def _capability(*, cert_hash: str = CERT_A, server_id: str = SERVER_ID):
    return LuksCapabilityContext(
        purpose=LuksCapabilityPurpose.STORAGE,
        server_id=server_id,
        miner_hotkey=OWNER,
        vm_name=VM_NAME,
        cert_hash=cert_hash,
        measurement_name="storage-generation-test",
        measurement_version="2.0.0",
        measurement_config_fingerprint="c" * 64,
        trust_set_fingerprint="d" * 64,
        tee_type="sev-snp",
        storage_role=True,
        allowed_volumes=[VOLUME],
    )


def _config(
    *,
    passphrases: dict | None = None,
    generations: dict | None = None,
    leases: dict | None = None,
):
    return VmCacheConfig(
        miner_hotkey=OWNER,
        vm_name=VM_NAME,
        volume_passphrases=passphrases or {},
        volume_epochs=generations or {},
        volume_generation_leases=leases or {},
    )


def _confirm_capability(capability, rotation):
    return LuksCapabilityContext.model_validate(
        {
            **capability.model_dump(),
            "issued_volumes": [VOLUME],
            "issued_generations": {VOLUME: rotation.generation},
            "issued_lease_ids": {VOLUME: rotation.lease_id},
        }
    )


def test_first_format_pending_key_and_generation_survive_lost_confirmation():
    config = _config()
    capability = _capability()

    first = server_util.allocate_luks_generation_leases(config, capability, [VOLUME])[VOLUME]
    retry = server_util.allocate_luks_generation_leases(config, capability, [VOLUME])[VOLUME]

    assert first.current is None
    assert retry.current is None
    assert retry.next == first.next
    assert retry.generation == first.generation == 1
    assert retry.lease_id == first.lease_id
    assert retry.lease_reused is True

    confirm_capability = _confirm_capability(capability, retry)
    with pytest.raises(HTTPException):
        server_util.confirm_luks_generation_leases(
            config,
            confirm_capability,
            {
                VOLUME: LuksVolumeConfirmStatus(
                    rotated=False,
                    generation=retry.generation,
                )
            },
        )
    assert VOLUME in config.volume_generation_leases
    assert f"pending_{VOLUME}" in config.volume_passphrases

    outcome = server_util.confirm_luks_generation_leases(
        config,
        confirm_capability,
        {
            VOLUME: LuksVolumeConfirmStatus(
                rotated=True,
                generation=retry.generation,
            )
        },
    )

    assert outcome[VOLUME] == {"result": "promoted", "generation": 1}
    assert config.volume_epochs == {VOLUME: 1}
    assert config.volume_generation_leases == {}
    assert "pending_chutefs-data" not in config.volume_passphrases
    assert server_util.decrypt_passphrase(config.volume_passphrases[VOLUME]) == first.next

    duplicate = server_util.confirm_luks_generation_leases(
        config,
        confirm_capability,
        {
            VOLUME: LuksVolumeConfirmStatus(
                rotated=True,
                generation=retry.generation,
            )
        },
    )
    assert duplicate[VOLUME] == {
        "result": "already_confirmed",
        "generation": 1,
    }


def test_prelease_pending_key_is_adopted_instead_of_discarded():
    pending = "pending-before-generation-migration"
    config = _config(passphrases={f"pending_{VOLUME}": server_util.encrypt_passphrase(pending)})

    rotation = server_util.allocate_luks_generation_leases(config, _capability(), [VOLUME])[VOLUME]

    assert rotation.next == pending
    assert rotation.generation == 1
    assert rotation.lease_reused is True


def test_reboot_cert_reissues_same_lease_and_fences_competing_old_cert():
    config = _config()
    cap_a = _capability(cert_hash=CERT_A)
    cap_b = _capability(cert_hash=CERT_B)
    lease_a = server_util.allocate_luks_generation_leases(config, cap_a, [VOLUME])[VOLUME]

    lease_b = server_util.allocate_luks_generation_leases(config, cap_b, [VOLUME])[VOLUME]
    assert lease_b.next == lease_a.next
    assert lease_b.generation == lease_a.generation
    assert lease_b.lease_id == lease_a.lease_id
    assert lease_b.lease_reused is True

    with pytest.raises(HTTPException) as competing_confirm:
        server_util.confirm_luks_generation_leases(
            config,
            _confirm_capability(cap_a, lease_a),
            {
                VOLUME: LuksVolumeConfirmStatus(
                    rotated=True,
                    generation=lease_a.generation,
                )
            },
        )
    assert competing_confirm.value.status_code == 409

    outcome = server_util.confirm_luks_generation_leases(
        config,
        _confirm_capability(cap_b, lease_b),
        {
            VOLUME: LuksVolumeConfirmStatus(
                rotated=True,
                generation=lease_b.generation,
            )
        },
    )
    assert outcome[VOLUME]["result"] == "promoted"


def test_unresolved_lease_rejects_another_registered_identity():
    config = _config()
    server_util.allocate_luks_generation_leases(config, _capability(), [VOLUME])

    with pytest.raises(HTTPException) as conflict:
        server_util.allocate_luks_generation_leases(
            config,
            _capability(server_id="competing-storage-server"),
            [VOLUME],
        )
    assert conflict.value.status_code == 409


def test_exact_confirmation_advances_once_before_next_generation():
    current = "current-passphrase"
    config = _config(
        passphrases={VOLUME: server_util.encrypt_passphrase(current)},
        generations={VOLUME: 5},
    )
    capability = _capability()
    generation_six = server_util.allocate_luks_generation_leases(config, capability, [VOLUME])[
        VOLUME
    ]
    assert generation_six.generation == 6

    confirm_six = _confirm_capability(capability, generation_six)
    with pytest.raises(HTTPException):
        server_util.confirm_luks_generation_leases(
            config,
            confirm_six,
            {
                VOLUME: LuksVolumeConfirmStatus(
                    rotated=False,
                    generation=7,
                )
            },
        )
    assert config.volume_epochs == {VOLUME: 5}
    assert VOLUME in config.volume_generation_leases

    outcome = server_util.confirm_luks_generation_leases(
        config,
        confirm_six,
        {
            VOLUME: LuksVolumeConfirmStatus(
                rotated=False,
                generation=6,
            )
        },
    )
    assert outcome[VOLUME] == {"result": "confirmed", "generation": 6}
    assert config.volume_epochs == {VOLUME: 6}
    assert server_util.decrypt_passphrase(config.volume_passphrases[VOLUME]) == current

    generation_seven = server_util.allocate_luks_generation_leases(config, capability, [VOLUME])[
        VOLUME
    ]
    assert generation_seven.generation == 7

    stale_capability = LuksCapabilityContext.model_validate(
        {
            **capability.model_dump(),
            "issued_volumes": [VOLUME],
            "issued_generations": {VOLUME: 5},
            "issued_lease_ids": {VOLUME: "stale-lease"},
        }
    )
    with pytest.raises(HTTPException) as stale:
        server_util.confirm_luks_generation_leases(
            config,
            stale_capability,
            {
                VOLUME: LuksVolumeConfirmStatus(
                    rotated=False,
                    generation=5,
                )
            },
        )
    assert stale.value.status_code == 409
    assert config.volume_epochs == {VOLUME: 6}
    assert config.volume_generation_leases[VOLUME]["generation"] == 7


def test_generation_lease_migration_matches_orm_schema():
    migration = (
        Path(__file__).resolve().parents[2]
        / "api/migrations/20260713140000_vm_cache_volume_generation_leases.sql"
    ).read_text()

    assert "-- migrate:up" in migration
    assert "ADD COLUMN IF NOT EXISTS volume_generation_leases JSONB NOT NULL" in migration
    assert "-- migrate:down" in migration
    assert "DROP COLUMN IF EXISTS volume_generation_leases" in migration
    column = VmCacheConfig.__table__.c.volume_generation_leases
    assert column.nullable is False
