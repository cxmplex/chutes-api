"""Focused contracts for idempotent ChuteFS launch-session rotation."""

import json
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.config import settings
from api.server.schemas import (
    ChuteFSLaunchSession,
    ChuteFSTokenKeyEpoch,
    ChuteFSTokenKeyReplicaAck,
)
from api.storage import launch_sessions
from api.storage import service as storage_service
from api.storage import startup as storage_startup
from api.storage.startup import missing_retained_token_keys, token_keyset_sha256


def _row(**updates):
    values = {
        "session_id": "session-1",
        "generation": 7,
        "token_seed": "ab" * 32,
        "token_key_id": "chutefs-dev-key-v1",
    }
    values.update(updates)
    return SimpleNamespace(**values)


def test_deterministic_tokens_replay_exactly_and_are_purpose_separated(monkeypatch):
    monkeypatch.setattr(settings, "launch_config_key", "k" * 32)
    row = _row()

    first_access = launch_sessions._derived_token(
        row,
        launch_sessions._ACCESS_PREFIX,
        "access",
    )
    replayed_access = launch_sessions._derived_token(
        row,
        launch_sessions._ACCESS_PREFIX,
        "access",
    )
    refresh = launch_sessions._derived_token(
        row,
        launch_sessions._REFRESH_PREFIX,
        "refresh",
    )

    assert first_access == replayed_access
    assert first_access != refresh
    assert (
        launch_sessions._session_id_from_token(
            first_access,
            launch_sessions._ACCESS_PREFIX,
        )
        == row.session_id
    )


def test_generation_and_seed_change_the_recovered_token(monkeypatch):
    monkeypatch.setattr(settings, "launch_config_key", "k" * 32)
    first = launch_sessions._derived_token(
        _row(),
        launch_sessions._ACCESS_PREFIX,
        "access",
    )
    next_generation = launch_sessions._derived_token(
        _row(generation=8),
        launch_sessions._ACCESS_PREFIX,
        "access",
    )
    next_seed = launch_sessions._derived_token(
        _row(token_seed="cd" * 32),
        launch_sessions._ACCESS_PREFIX,
        "access",
    )

    assert len({first, next_generation, next_seed}) == 3


def test_retained_token_key_replays_after_active_key_rotation(monkeypatch):
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"old-key": "o" * 32, "new-key": "n" * 32}),
    )
    monkeypatch.setattr(settings, "chutefs_token_key_id", "old-key")
    row = _row(token_key_id="old-key")
    before_rotation = launch_sessions._derived_token(
        row,
        launch_sessions._ACCESS_PREFIX,
        "access",
    )

    monkeypatch.setattr(settings, "chutefs_token_key_id", "new-key")
    after_rotation = launch_sessions._derived_token(
        row,
        launch_sessions._ACCESS_PREFIX,
        "access",
    )
    new_session = launch_sessions._derived_token(
        _row(token_key_id="new-key"),
        launch_sessions._ACCESS_PREFIX,
        "access",
    )

    assert after_rotation == before_rotation
    assert new_session != before_rotation


def test_keyring_rejects_missing_active_and_duplicate_ids(monkeypatch):
    monkeypatch.setattr(settings, "chutefs_token_key_id", "active")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"retained": "r" * 32}),
    )
    with pytest.raises(ValueError, match="CHUTEFS_TOKEN_KEY_ID"):
        _ = settings.chutefs_token_keys

    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        '{"active":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","active":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}',
    )
    with pytest.raises(ValueError, match="duplicate"):
        _ = settings.chutefs_token_keys


def test_keyring_requires_explicit_dev_opt_in_and_never_reuses_launch_jwt(monkeypatch):
    monkeypatch.setattr(settings, "chutefs_token_keys_json", None)
    monkeypatch.setattr(settings, "chutefs_allow_insecure_dev_key", False)
    with pytest.raises(ValueError, match="CHUTEFS_ALLOW_INSECURE_DEV_KEY"):
        _ = settings.chutefs_token_keys

    monkeypatch.setattr(settings, "chutefs_token_key_id", "dedicated")
    monkeypatch.setattr(
        settings,
        "chutefs_token_keys_json",
        json.dumps({"dedicated": settings.launch_config_key}),
    )
    with pytest.raises(ValueError, match="launch-JWT"):
        _ = settings.chutefs_token_keys


def test_keyset_fingerprint_binds_actual_secret_bytes():
    first = token_keyset_sha256({"old": "o" * 32, "new": "n" * 32})
    different_secret = token_keyset_sha256({"old": "o" * 32, "new": "x" * 32})
    assert first != different_secret


def test_session_model_has_one_active_successor_and_replay_metadata():
    columns = ChuteFSLaunchSession.__table__.columns
    assert {
        "rotated_from_session_id",
        "rotated_from_session_sha256",
        "rotation_request_sha256",
        "token_seed",
        "token_key_id",
        "response_replay_until",
    }.issubset(columns.keys())
    indexes = {index.name: index for index in ChuteFSLaunchSession.__table__.indexes}
    assert indexes["uq_chutefs_launch_session_active_config"].unique
    assert indexes["uq_chutefs_launch_session_active_instance"].unique
    assert indexes["uq_chutefs_launch_session_successor"].unique
    assert not columns["rotated_from_session_id"].foreign_keys

    assert {
        "key_id",
        "predecessor_key_id",
        "state",
        "required_replica_ids",
    }.issubset(ChuteFSTokenKeyEpoch.__table__.columns.keys())
    assert {
        "replica_id",
        "key_id",
        "key_ids",
        "key_fingerprints",
        "keyring_sha256",
    }.issubset(ChuteFSTokenKeyReplicaAck.__table__.columns.keys())


def test_current_lineage_binds_certificate_and_operational_attestation():
    config = SimpleNamespace(
        config_id="config",
        user_id="user",
        chute_id="chute",
        job_id="job",
        compute_type="gpu",
        gpu_management_mode="miner",
    )
    instance = SimpleNamespace(instance_id="instance")
    binding = SimpleNamespace(binding_id="binding")
    volume = SimpleNamespace(volume_id="volume")
    server = SimpleNamespace(
        server_id="server",
        gpu_runtime_session_attestation_id="attestation-a",
        attested_cert_pubkey_hash="A" * 64,
    )
    reservation = SimpleNamespace(
        reservation_id="reservation",
        allocation_group_id="group",
        allocation_group_generation=3,
        process_incarnation="process",
    )
    current = launch_sessions._current_session_identity(
        config, instance, binding, volume, server, reservation
    )
    assert current["attestation_id"] == "attestation-a"
    assert current["attested_cert_pubkey_hash"] == "a" * 64
    assert launch_sessions._session_matches_current(SimpleNamespace(**current), current)

    server.gpu_runtime_session_attestation_id = "attestation-b"
    advanced = launch_sessions._current_session_identity(
        config, instance, binding, volume, server, reservation
    )
    assert not launch_sessions._session_matches_current(
        SimpleNamespace(**current), advanced
    )


def test_revocation_preflight_and_binding_locks_follow_shared_order():
    lock_source = inspect.getsource(
        launch_sessions.lock_launch_storage_configurations
    )
    lineage_source = inspect.getsource(launch_sessions._load_current_lineage)

    revocation_preflight = lock_source.index("_require_not_disabled")
    user_lock = lock_source.index("select(User)")
    lifecycle_lock = lock_source.index("await acquire_gpu_lifecycle_lock")
    configuration_lock = lock_source.index("select(LaunchConfig)", user_lock)
    instance_lock = lock_source.index("select(Instance)", configuration_lock)
    session_lock = lock_source.index(
        "select(ChuteFSLaunchSession)",
        instance_lock,
    )

    assert (
        revocation_preflight
        < user_lock
        < lifecycle_lock
        < configuration_lock
        < instance_lock
        < session_lock
    )
    assert ".order_by(User.user_id)" in lock_source
    assert ".order_by(LaunchConfig.config_id)" in lock_source
    assert "actual_config_owners != expected_config_owners" in lock_source
    assert "_require_not_disabled" not in lineage_source
    assert lineage_source.index("_current_attestation") < lineage_source.index(
        "select(DefaultChuteFSVolumeBinding)"
    )
    assert lineage_source.index("GPU launch reservation or allocation identity") < (
        lineage_source.index("select(DefaultChuteFSVolumeBinding)")
    )


def test_purge_and_account_erasure_do_not_prelock_the_user():
    for function in (
        storage_service.delete_volume,
        storage_service.delete_default_volume_for_chute,
        storage_service.prepare_user_storage_erasure,
    ):
        source = inspect.getsource(function)
        assert "_lock_storage_user" not in source
    assert "additional_user_ids=[user_id]" in inspect.getsource(
        storage_service.delete_volume
    )
    assert "additional_user_ids=[user_id]" in inspect.getsource(
        storage_service.prepare_user_storage_erasure
    )
    delete_source = inspect.getsource(storage_service.delete_volume)
    erasure_source = inspect.getsource(storage_service.prepare_user_storage_erasure)
    assert delete_source.index("select(DefaultChuteFSVolumeBinding)") < delete_source.index(
        "select(StorageVolume)"
    )
    assert erasure_source.index("select(DefaultChuteFSVolumeBinding)") < erasure_source.index(
        "select(StorageVolume)"
    )


def test_rotation_migration_locks_and_guards_only_its_state():
    migration = (
        Path(__file__).parents[2]
        / "api/migrations/20260726121000_chutefs_session_rotation_replay.sql"
    ).read_text()
    down = migration.split("-- migrate:down", maxsplit=1)[1]

    assert "SELECT pg_advisory_xact_lock(" in down
    advisory = down.index("chutes.chutefs-token-key-epochs.v1")
    epoch_lock = down.index(
        "LOCK TABLE chutefs_token_key_epochs IN ACCESS EXCLUSIVE MODE;"
    )
    ack_lock = down.index(
        "LOCK TABLE chutefs_token_key_replica_acks IN ACCESS EXCLUSIVE MODE;"
    )
    operation_lock = down.index(
        "LOCK TABLE chutefs_token_key_epoch_operations IN ACCESS EXCLUSIVE MODE;"
    )
    session_lock = down.index(
        "LOCK TABLE chutefs_launch_sessions IN ACCESS EXCLUSIVE MODE;"
    )
    assert advisory < epoch_lock < ack_lock < operation_lock < session_lock
    assert "LOCK TABLE chutefs_token_key_epochs IN ACCESS EXCLUSIVE MODE;" in down
    assert "LOCK TABLE chutefs_token_key_replica_acks IN ACCESS EXCLUSIVE MODE;" in down
    for column in (
        "rotated_from_session_id",
        "rotated_from_session_sha256",
        "rotation_request_sha256",
        "token_seed",
        "token_key_id",
        "response_replay_until",
    ):
        assert f"{column} IS NOT NULL" in down
    assert "GROUP BY config_id" in down
    assert "GROUP BY instance_id" in down
    assert "repository" not in down
    assert "descriptor_closure" not in down

    up = migration.split("-- migrate:down", maxsplit=1)[0]
    assert "REFERENCES chutefs_launch_sessions(session_id)" not in up
    for field in (
        "generation",
        "access_token_hash",
        "refresh_token_hash",
        "access_expires_at",
        "refresh_expires_at",
        "rotated_from_session_id",
        "rotated_from_session_sha256",
        "rotation_request_sha256",
        "token_seed",
        "token_key_id",
        "response_replay_until",
        "attestation_id",
        "rotated_at",
    ):
        assert f"NEW.{field} IS DISTINCT FROM OLD.{field}" in up
    assert "acknowledged_keyring_sha256 IS DISTINCT FROM expected_keyring_sha256" in up
    assert "acknowledged_key_fingerprints IS DISTINCT FROM expected_key_fingerprints" in up
    assert "fk_chutefs_launch_session_token_key" in up
    assert "require_active_chutefs_token_key_on_session_insert" in up
    assert "FOR SHARE" in up


def test_key_epoch_bootstrap_orders_stage_ack_then_activation():
    source = inspect.getsource(storage_startup.require_chutefs_token_key_retention)
    staged = source.index("INSERT INTO chutefs_token_key_epochs")
    acknowledged = source.index("INSERT INTO chutefs_token_key_replica_acks")
    activated = source.index("UPDATE chutefs_token_key_epochs")
    assert staged < acknowledged < activated
    assert "active key fingerprint" in source


def test_key_epoch_ack_is_readiness_only_and_liveness_stays_independent():
    source = (Path(__file__).parents[2] / "api/main.py").read_text()
    ping = source.split("async def ping():", maxsplit=1)[1].split(
        "async def ready(", maxsplit=1
    )[0]
    ready = source.split("async def ready(", maxsplit=1)[1].split(
        "def _tee_trust_metrics", maxsplit=1
    )[0]

    assert "require_chutefs_token_key_retention" not in ping
    assert "require_chutefs_token_key_retention" in ready
    assert "require_gpu_registration_recovery_key_retention" not in ping
    assert "require_gpu_registration_recovery_key_retention" in ready


def test_default_volume_down_guard_is_locked_binding_scoped_and_precedes_ddl():
    migration = (
        Path(__file__).parents[2] / "api/migrations/20260724234500_gpu_chutefs_default_volume.sql"
    ).read_text()
    down = migration.split("-- migrate:down", maxsplit=1)[1]
    guard_end = down.index("$$;", down.index("DO $$"))
    first_drop = down.index("DROP TRIGGER")

    assert guard_end < first_drop
    assert "SELECT pg_advisory_xact_lock(" in down
    assert down.index("chutes.chutefs-schema-fence.v1") < down.index("LOCK TABLE ")
    lock_targets = [
        line.split()[2]
        for line in down[:guard_end].splitlines()
        if line.startswith("LOCK TABLE ")
    ]
    assert lock_targets == [
        "gpu_launch_reservations",
        "instances",
        "jobs",
        "launch_configs",
        "servers",
        "storage_volume_keys",
        "storage_volumes",
        "users",
        "chutefs_launch_sessions",
        "default_chutefs_volume_bindings",
    ]
    guard = down[:guard_end]
    assert "FROM storage_volumes volume" in guard
    assert "volume.purged_at IS NULL" in guard
    assert "volume.key_shredded_at IS NULL" in guard
    assert "NOT EXISTS" in guard
    assert "FROM storage_volume_keys" in guard
    assert "default_volume_id IS NOT NULL" in guard
    assert "storage_session_exchange_allowed" in guard
    assert "completed_at IS NOT NULL" not in guard
    assert "failed_at IS NULL AND completed_at IS NULL" in guard


def test_server_revocation_trigger_uses_distinct_identity_changes():
    migration = (
        Path(__file__).parents[2] / "api/migrations/20260724234500_gpu_chutefs_default_volume.sql"
    ).read_text()
    function = migration.split(
        "CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_server_change()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    assert "gpu_runtime_session_attestation_id\n            IS DISTINCT FROM" in function
    assert "attested_cert_pubkey_hash\n            IS DISTINCT FROM" in function
    assert "gpu_runtime_session_attestation_id IS NULL" not in function


def test_pruning_requires_all_authority_windows_to_expire_and_is_bounded():
    source = inspect.getsource(launch_sessions._prune_expired_session_lineage)
    assert "access_expires_at <= now" in source
    assert "refresh_expires_at <= now" in source
    assert "response_replay_until <= now" in source
    assert ".limit(limit)" in source
    assert "limit: int = 128" in source


def test_token_key_retention_accepts_present_live_key():
    now = datetime.now(timezone.utc)
    assert missing_retained_token_keys(
        [("retained", now + timedelta(minutes=1))],
        {"retained"},
        now=now,
    ) == []


def test_token_key_retention_rejects_absent_live_key():
    now = datetime.now(timezone.utc)
    assert missing_retained_token_keys(
        [("removed", now + timedelta(minutes=1))],
        {"active"},
        now=now,
    ) == ["removed"]


def test_token_key_retention_ignores_expired_session_key():
    now = datetime.now(timezone.utc)
    assert missing_retained_token_keys(
        [("expired", now - timedelta(microseconds=1))],
        {"active"},
        now=now,
    ) == []


def test_startup_retains_keys_through_strict_refresh_expiry():
    source = inspect.getsource(storage_startup.require_chutefs_token_key_retention)
    assert '"SELECT token_key_id, MAX(refresh_expires_at) "' in source
    assert "CASE WHEN revoked_at IS NULL" not in source
