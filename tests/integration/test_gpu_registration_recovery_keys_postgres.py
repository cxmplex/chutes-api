"""Real-PostgreSQL recovery-key authority and crash-boundary coverage."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from api.config import settings
from api.gpu_models import (
    GpuRegistrationAttempt,
    GpuRegistrationConflict,
    GpuRegistrationRecoveryKeyEpoch,
    GpuRegistrationRecoveryKeyReplicaAck,
)
from api.gpu_registration_keys import (
    GpuRegistrationRecoveryKeyUnavailable,
    activate_gpu_registration_recovery_key_epoch,
    cancel_gpu_registration_recovery_key_epoch,
    ensure_gpu_registration_recovery_key_authority,
    gpu_registration_recovery_key_retention_status,
    load_registration_recovery_cipher,
    lock_active_registration_recovery_key,
    retire_gpu_registration_recovery_key_epoch,
    stage_gpu_registration_recovery_key_epoch,
)
from api.gpu_registration_service import (
    _claim_attempt,
    _decrypt_registration_request,
    _locked_processing_snapshot,
    _run_registration_attempt,
    _verify_recorded_conflict,
)
from api.host.locks import acquire_gpu_lifecycle_lock
from tests.integration import test_gpu_allocations_postgres as gpu_pg

postgres_schema = gpu_pg.postgres_schema
unsigned_debug_provenance = gpu_pg.unsigned_debug_provenance
nv_attest = gpu_pg.nv_attest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for recovery-key tests",
    ),
]


def _new_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _configure_keyring(monkeypatch, keys: dict[str, str], preferred: str) -> None:
    monkeypatch.setattr(
        settings,
        "gpu_registration_recovery_keys_json",
        json.dumps(keys, sort_keys=True),
    )
    monkeypatch.setattr(settings, "gpu_registration_recovery_key_id", preferred)


async def _active_epoch(session) -> GpuRegistrationRecoveryKeyEpoch:
    return (
        await session.execute(
            select(GpuRegistrationRecoveryKeyEpoch).where(
                GpuRegistrationRecoveryKeyEpoch.state == "active"
            )
        )
    ).scalar_one()


async def test_readiness_bootstrap_is_idempotent_and_acknowledges_this_replica(
    postgres_schema,
):
    sessions, _ = postgres_schema
    async with sessions() as session:
        key_id, _ = await ensure_gpu_registration_recovery_key_authority(session)
        await session.commit()
        epochs = list(
            (
                await session.execute(
                    select(GpuRegistrationRecoveryKeyEpoch).order_by(
                        GpuRegistrationRecoveryKeyEpoch.key_id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert [(epoch.key_id, epoch.state) for epoch in epochs] == [(key_id, "active")]
        acknowledgement = await session.get(
            GpuRegistrationRecoveryKeyReplicaAck,
            (settings.gpu_registration_recovery_replica_id, key_id),
        )
        assert acknowledgement is not None
        assert acknowledgement.key_fingerprints[key_id] == epochs[0].key_sha256


async def test_stale_stage_requires_audited_cancellation_and_cannot_poison_activation(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    old_materials = settings.gpu_registration_recovery_key_materials
    async with sessions() as session:
        old = await _active_epoch(session)

    abandoned_id = "gpu-recovery-abandoned-v2"
    abandoned_material = _new_key()
    _configure_keyring(
        monkeypatch,
        {**old_materials, abandoned_id: abandoned_material},
        abandoned_id,
    )
    async with sessions() as session:
        selected_id, _ = await lock_active_registration_recovery_key(session)
        assert selected_id == old.key_id
        staged = await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-1",
            request_id=str(uuid4()),
            key_id=abandoned_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
        assert staged["active_key_id"] == old.key_id

    replacement_id = "gpu-recovery-replacement-v2"
    _configure_keyring(
        monkeypatch,
        {**old_materials, replacement_id: _new_key()},
        replacement_id,
    )
    async with sessions() as session:
        await ensure_gpu_registration_recovery_key_authority(session)
        await session.commit()
        stale_ack = await session.get(
            GpuRegistrationRecoveryKeyReplicaAck,
            (settings.gpu_registration_recovery_replica_id, abandoned_id),
        )
        assert stale_ack is None
    async with sessions() as session:
        with pytest.raises(HTTPException, match="cancel that exact epoch") as blocked:
            await stage_gpu_registration_recovery_key_epoch(
                session,
                administrator_id="admin-1",
                request_id=str(uuid4()),
                key_id=replacement_id,
                required_replica_ids=[settings.gpu_registration_recovery_replica_id],
            )
        assert blocked.value.status_code == 409
        await session.rollback()

    cancel_request_id = str(uuid4())
    async with sessions() as session:
        cancelled = await cancel_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-1",
            request_id=cancel_request_id,
            key_id=abandoned_id,
            reason="The staged key was not distributed to the serving cohort.",
        )
    async with sessions() as session:
        replay = await cancel_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-1",
            request_id=cancel_request_id,
            key_id=abandoned_id,
            reason="The staged key was not distributed to the serving cohort.",
        )
        assert replay == cancelled

    replacement_material = settings.gpu_registration_recovery_key_materials[replacement_id]
    _configure_keyring(
        monkeypatch,
        {
            **old_materials,
            abandoned_id: abandoned_material,
            replacement_id: replacement_material,
        },
        replacement_id,
    )
    async with sessions() as session:
        await ensure_gpu_registration_recovery_key_authority(session)
        await session.commit()
        terminal = await session.get(GpuRegistrationRecoveryKeyEpoch, abandoned_id)
        assert terminal is not None and terminal.state == "cancelled"
        assert terminal.cancelled_at is not None
        assert (
            await session.get(
                GpuRegistrationRecoveryKeyReplicaAck,
                (settings.gpu_registration_recovery_replica_id, abandoned_id),
            )
            is None
        )
        with pytest.raises(DBAPIError, match="not ACK-eligible"):
            session.add(
                GpuRegistrationRecoveryKeyReplicaAck(
                    replica_id=settings.gpu_registration_recovery_replica_id,
                    key_id=abandoned_id,
                    key_ids=sorted(settings.gpu_registration_recovery_key_materials),
                    key_fingerprints={
                        abandoned_id: terminal.key_sha256,
                    },
                    keyring_sha256="0" * 64,
                )
            )
            await session.flush()
        await session.rollback()

    async with sessions() as session:
        replacement = await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-1",
            request_id=str(uuid4()),
            key_id=replacement_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
        assert replacement["state"] == "staged"
    async with sessions() as session:
        activated = await activate_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-1",
            request_id=str(uuid4()),
            key_id=replacement_id,
        )
        assert activated["active_key_id"] == replacement_id


async def test_readiness_rejects_active_and_configured_staged_fingerprint_mismatch(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    materials = settings.gpu_registration_recovery_key_materials
    async with sessions() as session:
        active = await _active_epoch(session)
        active_id = active.key_id

    _configure_keyring(monkeypatch, {active_id: _new_key()}, active_id)
    async with sessions() as session:
        with pytest.raises(GpuRegistrationRecoveryKeyUnavailable, match="fingerprint"):
            await ensure_gpu_registration_recovery_key_authority(session)
        await session.rollback()

    staged_id = "gpu-recovery-mismatch-v2"
    staged_material = _new_key()
    _configure_keyring(
        monkeypatch,
        {**materials, staged_id: staged_material},
        active_id,
    )
    async with sessions() as session:
        await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-mismatch",
            request_id=str(uuid4()),
            key_id=staged_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
    _configure_keyring(
        monkeypatch,
        {**materials, staged_id: _new_key()},
        active_id,
    )
    async with sessions() as session:
        with pytest.raises(GpuRegistrationRecoveryKeyUnavailable, match="fingerprint"):
            await ensure_gpu_registration_recovery_key_authority(session)
        await session.rollback()


async def test_direct_sql_requires_successor_ack_and_rejects_epoch_delete(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    materials = settings.gpu_registration_recovery_key_materials
    async with sessions() as session:
        active = await _active_epoch(session)
        active_id = active.key_id
        with pytest.raises(DBAPIError, match="lacks one exact ACKed successor"):
            await session.execute(
                text(
                    "UPDATE gpu_registration_recovery_key_epochs "
                    "SET state = 'retiring', retiring_at = NOW() "
                    "WHERE key_id = :key_id"
                ),
                {"key_id": active_id},
            )
        await session.rollback()

    successor_id = "gpu-recovery-trigger-v2"
    _configure_keyring(
        monkeypatch,
        {**materials, successor_id: _new_key()},
        active_id,
    )
    async with sessions() as session:
        await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-2",
            request_id=str(uuid4()),
            key_id=successor_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
        acknowledgement = await session.get(
            GpuRegistrationRecoveryKeyReplicaAck,
            (settings.gpu_registration_recovery_replica_id, successor_id),
        )
        acknowledgement.key_fingerprints = {
            **acknowledgement.key_fingerprints,
            successor_id: "0" * 64,
        }
        await session.commit()
        with pytest.raises(DBAPIError, match="lacks one exact ACKed successor"):
            await session.execute(
                text(
                    "UPDATE gpu_registration_recovery_key_epochs "
                    "SET state = 'retiring', retiring_at = NOW() "
                    "WHERE key_id = :key_id"
                ),
                {"key_id": active_id},
            )
        await session.rollback()
        with pytest.raises(DBAPIError, match="cannot be deleted"):
            await session.execute(
                text("DELETE FROM gpu_registration_recovery_key_epochs WHERE key_id = :key_id"),
                {"key_id": active_id},
            )
        await session.rollback()


async def test_mismatched_key_preserves_attempt_and_conflict_ciphertext_then_resumes(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        _, request, cert_pem, spki_sha256 = await gpu_pg._prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, conflict = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None and conflict is None
        await session.commit()
        competitor_spki = "d" * 64
        competitor_cert = "fixture-competitor-certificate"
        competitor = gpu_pg._registration_competitor(
            request,
            spki_sha256=competitor_spki,
            suffix="recovery-key",
        )
        _, _, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            competitor,
            competitor_spki,
            competitor_cert,
        )
        assert conflict is not None
        await session.commit()
        attempt_id = attempt.attempt_id
        conflict_id = conflict.conflict_id
        attempt_ciphertext = attempt.request_payload_ciphertext
        conflict_ciphertext = conflict.request_payload_ciphertext
        retained_materials = settings.gpu_registration_recovery_key_materials

        persisted_key_id = attempt.request_payload_key_id
        _configure_keyring(
            monkeypatch,
            {persisted_key_id: _new_key()},
            persisted_key_id,
        )
        with pytest.raises(GpuRegistrationRecoveryKeyUnavailable) as attempt_error:
            await _run_registration_attempt(
                session,
                attempt_id,
                lease_owner,
                spki_sha256,
            )
        assert attempt_error.value.headers == {"Retry-After": "5"}
        conflict = await session.get(GpuRegistrationConflict, conflict_id)
        assert (
            await _verify_recorded_conflict(
                session,
                conflict,
                competitor,
                competitor_spki,
                competitor_cert,
            )
            == "recorded"
        )
        await session.rollback()

        persisted_attempt = await session.get(
            GpuRegistrationAttempt, attempt_id, populate_existing=True
        )
        persisted_conflict = await session.get(
            GpuRegistrationConflict, conflict_id, populate_existing=True
        )
        assert persisted_attempt.state == "processing"
        assert persisted_attempt.request_payload_ciphertext == attempt_ciphertext
        assert persisted_conflict.state == "recorded"
        assert persisted_conflict.request_payload_ciphertext == conflict_ciphertext
        assert persisted_conflict.request_payload_key_id == persisted_key_id
        assert persisted_conflict.processing_lease_owner is None
        assert persisted_conflict.processing_lease_expires_at is None
        assert persisted_conflict.verification_attempt_count == 1
        assert persisted_conflict.last_attempt_at is not None
        assert persisted_conflict.next_attempt_at is not None
        assert (
            persisted_conflict.last_transient_error_code == "GpuRegistrationRecoveryKeyUnavailable"
        )

        _configure_keyring(
            monkeypatch,
            retained_materials,
            persisted_attempt.request_payload_key_id,
        )
        snapshot = await _locked_processing_snapshot(
            session,
            persisted_attempt.attempt_id,
            lease_owner,
        )
        assert snapshot.request.request_sha256() == request.request_sha256()
        restored_conflict = await _decrypt_registration_request(
            session,
            persisted_conflict.request_payload_ciphertext,
            persisted_conflict.request_payload_key_id,
            persisted_conflict.request_sha256,
        )
        assert restored_conflict.request_sha256() == competitor.request_sha256()
        await session.rollback()


async def test_retirement_blocks_attempt_then_conflict_and_exact_replay_is_stable(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        active = await _active_epoch(session)
        active_id = active.key_id
        materials = settings.gpu_registration_recovery_key_materials
        _, request, cert_pem, spki_sha256 = await gpu_pg._prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, _ = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        await session.commit()
        attempt_id = attempt.attempt_id
        competitor_spki = "c" * 64
        competitor = gpu_pg._registration_competitor(
            request,
            spki_sha256=competitor_spki,
            suffix="retirement",
        )
        _, _, conflict = await _claim_attempt(
            session,
            "192.0.2.30",
            competitor,
            competitor_spki,
            "fixture-retirement-competitor",
        )
        await session.commit()
        conflict_id = conflict.conflict_id

        successor_id = "gpu-recovery-retirement-v2"
        _configure_keyring(
            monkeypatch,
            {**materials, successor_id: _new_key()},
            active_id,
        )
        await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-3",
            request_id=str(uuid4()),
            key_id=successor_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
        activate_request_id = str(uuid4())
        activated = await activate_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-3",
            request_id=activate_request_id,
            key_id=successor_id,
        )
        replay = await activate_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-3",
            request_id=activate_request_id,
            key_id=successor_id,
        )
        assert replay == activated
        selected_id, _ = await lock_active_registration_recovery_key(session)
        assert selected_id == successor_id
        await session.rollback()

        successor_material = settings.gpu_registration_recovery_key_materials[successor_id]
        _configure_keyring(
            monkeypatch,
            {successor_id: successor_material},
            successor_id,
        )
        degraded = await gpu_registration_recovery_key_retention_status(session)
        assert degraded.missing_referenced_key_ids == (active_id,)
        await session.commit()
        with pytest.raises(
            GpuRegistrationRecoveryKeyUnavailable,
            match="Persisted GPU registration recovery key",
        ) as unavailable:
            await load_registration_recovery_cipher(session, active_id)
        assert unavailable.value.status_code == 503
        assert unavailable.value.headers == {"Retry-After": "5"}
        await session.rollback()

        retained_keyring = {
            **materials,
            successor_id: successor_material,
        }
        _configure_keyring(
            monkeypatch,
            retained_keyring,
            successor_id,
        )
        restored = await gpu_registration_recovery_key_retention_status(session)
        assert restored.missing_referenced_key_ids == ()
        assert await load_registration_recovery_cipher(session, active_id) is not None
        await session.commit()

        _configure_keyring(
            monkeypatch,
            materials,
            active_id,
        )
        with pytest.raises(
            GpuRegistrationRecoveryKeyUnavailable,
            match="Database-active GPU registration recovery key",
        ):
            await gpu_registration_recovery_key_retention_status(session)
        await session.rollback()

        _configure_keyring(
            monkeypatch,
            retained_keyring,
            successor_id,
        )
        assert (
            await gpu_registration_recovery_key_retention_status(session)
        ).missing_referenced_key_ids == ()
        await session.commit()

        with pytest.raises(HTTPException, match="nonterminal reference"):
            await retire_gpu_registration_recovery_key_epoch(
                session,
                administrator_id="admin-3",
                request_id=str(uuid4()),
                key_id=active_id,
            )
        await session.rollback()
        now = datetime.now(timezone.utc)
        attempt = await session.get(GpuRegistrationAttempt, attempt_id)
        attempt.state = "failed"
        attempt.processing_lease_owner = None
        attempt.processing_lease_expires_at = None
        attempt.request_payload_ciphertext = None
        attempt.request_payload_key_id = None
        attempt.failure_code = "test_terminal"
        attempt.failure_detail = "terminal fixture"
        attempt.completed_at = now
        attempt.registration_replay_until = now + timedelta(minutes=15)
        await session.commit()

        with pytest.raises(HTTPException, match="nonterminal reference"):
            await retire_gpu_registration_recovery_key_epoch(
                session,
                administrator_id="admin-3",
                request_id=str(uuid4()),
                key_id=active_id,
            )
        await session.rollback()
        conflict = await session.get(GpuRegistrationConflict, conflict_id)
        conflict.state = "invalid"
        conflict.request_payload_ciphertext = None
        conflict.request_payload_key_id = None
        conflict.next_attempt_at = None
        conflict.verification_detail = "terminal fixture"
        conflict.verified_at = now
        await session.commit()

        retire_request_id = str(uuid4())
        retired = await retire_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-3",
            request_id=retire_request_id,
            key_id=active_id,
        )
        replay = await retire_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-3",
            request_id=retire_request_id,
            key_id=active_id,
        )
        assert replay == retired


async def test_mint_shared_lock_serializes_activation_without_deadlock(
    postgres_schema,
    monkeypatch,
):
    sessions, _ = postgres_schema
    materials = settings.gpu_registration_recovery_key_materials
    async with sessions() as session:
        active = await _active_epoch(session)
    successor_id = "gpu-recovery-concurrent-v2"
    _configure_keyring(
        monkeypatch,
        {**materials, successor_id: _new_key()},
        active.key_id,
    )
    async with sessions() as stage_session:
        await stage_gpu_registration_recovery_key_epoch(
            stage_session,
            administrator_id="admin-4",
            request_id=str(uuid4()),
            key_id=successor_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )

    first = sessions()
    second = sessions()
    try:
        selected_id, _ = await lock_active_registration_recovery_key(first)
        assert selected_id == active.key_id
        await acquire_gpu_lifecycle_lock(first)
        activation = asyncio.create_task(
            activate_gpu_registration_recovery_key_epoch(
                second,
                administrator_id="admin-4",
                request_id=str(uuid4()),
                key_id=successor_id,
            )
        )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(activation), timeout=0.1)
        await first.commit()
        result = await asyncio.wait_for(activation, timeout=2)
        assert result["active_key_id"] == successor_id
    finally:
        await first.close()
        await second.close()


async def test_failed_down_preserves_recovery_key_catalog(
    postgres_schema,
    monkeypatch,
):
    sessions, schema = postgres_schema
    materials = settings.gpu_registration_recovery_key_materials
    async with sessions() as session:
        active = await _active_epoch(session)
    staged_id = "gpu-recovery-down-guard-v2"
    _configure_keyring(
        monkeypatch,
        {**materials, staged_id: _new_key()},
        active.key_id,
    )
    async with sessions() as session:
        await stage_gpu_registration_recovery_key_epoch(
            session,
            administrator_id="admin-5",
            request_id=str(uuid4()),
            key_id=staged_id,
            required_replica_ids=[settings.gpu_registration_recovery_replica_id],
        )
    with pytest.raises(AssertionError, match="cannot roll back durable GPU lifecycle"):
        await gpu_pg._apply_migration(
            schema,
            "down",
            "20260725120000_gpu_lifecycle_durability.sql",
        )
    async with sessions() as session:
        assert (
            await session.execute(
                text("SELECT to_regclass('gpu_registration_recovery_key_epochs')")
            )
        ).scalar_one() == "gpu_registration_recovery_key_epochs"
        persisted = await session.get(GpuRegistrationRecoveryKeyEpoch, staged_id)
        assert persisted is not None and persisted.state == "staged"


async def test_singleton_bootstrap_authority_allows_down_and_clean_up_rebootstrap(
    postgres_schema,
):
    sessions, schema = postgres_schema
    await gpu_pg._apply_migration(
        schema,
        "down",
        "20260725120000_gpu_lifecycle_durability.sql",
    )
    async with sessions() as session:
        assert (
            await session.execute(
                text("SELECT to_regclass('gpu_registration_recovery_key_epochs')")
            )
        ).scalar_one() is None
    await gpu_pg._apply_migration(
        schema,
        "up",
        "20260725120000_gpu_lifecycle_durability.sql",
    )
    async with sessions() as session:
        key_id, _ = await ensure_gpu_registration_recovery_key_authority(session)
        await session.commit()
        active = await _active_epoch(session)
        assert active.key_id == key_id


async def test_create_all_first_unresolved_ciphertext_preflight_preserves_catalog(
    postgres_schema,
):
    sessions, schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        _, request, cert_pem, spki_sha256 = await gpu_pg._prepare_registration_request(
            session, "miner"
        )
        attempt, lease_owner, _ = await _claim_attempt(
            session, "192.0.2.30", request, spki_sha256, cert_pem
        )
        assert lease_owner is not None
        attempt_id = attempt.attempt_id
        key_id = attempt.request_payload_key_id
        await session.commit()
        await session.execute(text("DROP TABLE gpu_registration_recovery_key_epoch_operations"))
        await session.execute(text("DROP TABLE gpu_registration_recovery_key_replica_acks"))
        await session.execute(text("DROP TABLE gpu_registration_recovery_key_epochs CASCADE"))
        await session.commit()

    with pytest.raises(AssertionError, match=attempt_id):
        await gpu_pg._apply_migration(
            schema,
            "up",
            "20260725120000_gpu_lifecycle_durability.sql",
        )
    async with sessions() as session:
        persisted = await session.get(GpuRegistrationAttempt, attempt_id)
        assert persisted is not None
        assert persisted.request_payload_key_id == key_id
        assert (
            await session.execute(
                text("SELECT to_regclass('gpu_registration_recovery_key_epochs')")
            )
        ).scalar_one() is None
