"""Direct-SQL immutability coverage for launch-bound ChuteFS authority."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from api.server.schemas import (
    ChuteFSLaunchSession,
    DefaultChuteFSVolumeBinding,
    Server,
)
from tests.integration import test_gpu_chutefs_postgres as chutefs_pg
from tests.integration import test_storage_reconciliation_postgres as storage_pg

pg_session = storage_pg.pg_session
storage_crypto = chutefs_pg.storage_crypto

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for ChuteFS authority SQL tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """These database-state tests never invoke the external evidence verifier."""
    yield


async def _assert_authority_update_rejected(
    db,
    session_id: str,
    assignment: str,
) -> None:
    with pytest.raises(DBAPIError) as captured:
        async with db.begin_nested():
            await db.execute(
                text(
                    f"""
                    UPDATE chutefs_launch_sessions
                       SET {assignment}
                     WHERE session_id = :session_id
                    """
                ),
                {"session_id": session_id},
            )
    assert "launch-bound ChuteFS session authority is immutable" in str(captured.value.orig)


async def test_every_chutefs_authority_and_replay_field_is_sql_immutable(
    pg_session,
):
    db, _redis = pg_session
    chute = await chutefs_pg._chute(
        db,
        storage_pg.USER_ID,
        f"authority-{uuid.uuid4().hex}",
    )
    _private_key, certificate = chutefs_pg._identity("chutefs-authority")
    config, instance = await chutefs_pg._cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"authority-server-{uuid.uuid4().hex}",
        cert=certificate,
    )
    key_id = await chutefs_pg._ensure_test_token_key_epoch(db)
    binding = await db.scalar(
        select(DefaultChuteFSVolumeBinding).where(
            DefaultChuteFSVolumeBinding.user_id == storage_pg.USER_ID,
            DefaultChuteFSVolumeBinding.chute_id == chute.chute_id,
            DefaultChuteFSVolumeBinding.volume_id == config.default_volume_id,
            DefaultChuteFSVolumeBinding.lifecycle_state == "active",
        )
    )
    server = await db.get(Server, config.server_id)
    now = datetime.now(timezone.utc)
    session_id = f"authority-session-{uuid.uuid4().hex}"
    db.add(
        ChuteFSLaunchSession(
            session_id=session_id,
            config_id=config.config_id,
            instance_id=instance.instance_id,
            binding_id=binding.binding_id,
            user_id=storage_pg.USER_ID,
            chute_id=chute.chute_id,
            compute_type="cpu",
            management_mode="platform",
            server_id=server.server_id,
            volume_id=config.default_volume_id,
            attested_cert_pubkey_hash=server.attested_cert_pubkey_hash,
            allowed_operations=["put", "get", "list", "delete"],
            generation=1,
            revocation_epoch=instance.storage_revocation_epoch,
            access_token_hash="1" * 64,
            refresh_token_hash="2" * 64,
            reexchange_token_hash="5" * 64,
            access_expires_at=now + timedelta(minutes=10),
            refresh_expires_at=now + timedelta(hours=1),
            rotation_request_sha256="3" * 64,
            token_seed="4" * 64,
            token_key_id=key_id,
            response_replay_until=now + timedelta(minutes=15),
            created_at=now,
            rotated_at=now,
        )
    )
    await db.commit()

    assignments = (
        "generation = generation + 1",
        "revocation_epoch = revocation_epoch + 1",
        "access_token_hash = repeat('a', 64)",
        "refresh_token_hash = repeat('b', 64)",
        "reexchange_token_hash = repeat('g', 64)",
        "access_expires_at = access_expires_at + INTERVAL '1 second'",
        "refresh_expires_at = refresh_expires_at + INTERVAL '1 second'",
        "rotated_from_session_id = 'predecessor-session'",
        "rotated_from_session_sha256 = repeat('c', 64)",
        "rotation_request_sha256 = repeat('d', 64)",
        "token_seed = repeat('e', 64)",
        "token_key_id = NULL",
        "response_replay_until = response_replay_until + INTERVAL '1 second'",
        "attestation_id = 'replacement-attestation'",
        "attested_cert_pubkey_hash = repeat('f', 64)",
        "rotated_at = rotated_at + INTERVAL '1 second'",
    )
    for assignment in assignments:
        await _assert_authority_update_rejected(db, session_id, assignment)

    revoked_at = now + timedelta(minutes=20)
    await db.execute(
        text(
            """
            UPDATE chutefs_launch_sessions
               SET revoked_at = :revoked_at
             WHERE session_id = :session_id
            """
        ),
        {"session_id": session_id, "revoked_at": revoked_at},
    )
    await db.commit()
    stored_revoked_at = await db.scalar(
        select(ChuteFSLaunchSession.revoked_at).where(ChuteFSLaunchSession.session_id == session_id)
    )
    assert stored_revoked_at == revoked_at
