"""Focused contracts for idempotent ChuteFS launch-session rotation."""

import json
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.config import settings
from api.server.schemas import ChuteFSLaunchSession
from api.storage import launch_sessions
from api.storage import service as storage_service
from api.storage.startup import missing_retained_token_keys


def _row(**updates):
    values = {
        "session_id": "session-1",
        "generation": 7,
        "token_seed": "ab" * 32,
        "token_key_id": "launch-config-key-v1",
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


def test_session_model_has_one_active_successor_and_replay_metadata():
    columns = ChuteFSLaunchSession.__table__.columns
    assert {
        "rotated_from_session_id",
        "rotation_request_sha256",
        "token_seed",
        "token_key_id",
        "response_replay_until",
    }.issubset(columns.keys())
    indexes = {index.name: index for index in ChuteFSLaunchSession.__table__.indexes}
    assert indexes["uq_chutefs_launch_session_active_config"].unique
    assert indexes["uq_chutefs_launch_session_active_instance"].unique
    assert indexes["uq_chutefs_launch_session_successor"].unique


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


def test_rotation_migration_locks_and_guards_only_its_state():
    migration = (
        Path(__file__).parents[2]
        / "api/migrations/20260726121000_chutefs_session_rotation_replay.sql"
    ).read_text()
    down = migration.split("-- migrate:down", maxsplit=1)[1]

    assert down.lstrip().startswith("LOCK TABLE chutefs_launch_sessions IN ACCESS EXCLUSIVE MODE;")
    for column in (
        "rotated_from_session_id",
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


def test_default_volume_down_guard_is_locked_binding_scoped_and_precedes_ddl():
    migration = (
        Path(__file__).parents[2] / "api/migrations/20260724234500_gpu_chutefs_default_volume.sql"
    ).read_text()
    down = migration.split("-- migrate:down", maxsplit=1)[1]
    guard_end = down.index("$$;", down.index("DO $$"))
    first_drop = down.index("DROP TRIGGER")

    assert guard_end < first_drop
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
        "storage_volumes",
        "users",
        "chutefs_launch_sessions",
        "default_chutefs_volume_bindings",
    ]
    assert "JOIN storage_volumes volume ON volume.volume_id = binding.volume_id" in down[:guard_end]
    assert "volume.purged_at IS NULL" in down[:guard_end]
    assert "volume.key_shredded_at IS NULL" in down[:guard_end]
    assert "FROM storage_volumes\n            WHERE" not in down[:guard_end]


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
