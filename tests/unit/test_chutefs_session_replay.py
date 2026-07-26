"""Focused contracts for idempotent ChuteFS launch-session rotation."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.config import settings
from api.server.schemas import ChuteFSLaunchSession
from api.storage import launch_sessions


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
