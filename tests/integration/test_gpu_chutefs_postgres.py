"""Real-Postgres coverage for durable default volumes and launch-bound sessions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import lazyload, sessionmaker
from starlette.requests import Request

from api.chute.schemas import Chute
from api.config import settings
from api.image.schemas import Image
from api.instance import util as instance_util
from api.instance.locking import prepare_instance_terminal_writes
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import create_launch_jwt_v2
from api.job.schemas import Job
from api.server.schemas import (
    ChuteFSLaunchSession,
    ChuteFSTokenKeyEpoch,
    ChuteFSTokenKeyReplicaAck,
    DefaultChuteFSVolumeBinding,
    Server,
    StorageVolume,
    StorageVolumeKey,
)
from api.server.util import get_public_key_hash
from api.server.service import delete_server
from api.storage import launch_sessions, service
from api.storage import startup as storage_startup
from api.storage.startup import token_key_fingerprints, token_keyset_sha256
from api.storage.router import issue_default_volume_grant
from api.storage.schemas import DefaultGrantRequest
from api.user.schemas import User
from api.user.router import delete_my_user
from tests.integration import test_storage_reconciliation_postgres as storage_pg

pytest_plugins = ["tests.integration.test_storage_reconciliation_postgres"]

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for GPU ChuteFS Postgres tests",
    ),
]


@pytest.fixture(autouse=True)
def storage_crypto(monkeypatch):
    monkeypatch.setattr(
        "api.server.util.settings.fernet_key",
        Fernet(Fernet.generate_key()),
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setattr(settings, "launch_config_private_key_bytes", private_pem)


@pytest.fixture(autouse=True)
def nv_attest():
    yield


class _DisablePipeline:
    def zremrangebyscore(self, *_args):
        return self

    def zadd(self, *_args):
        return self

    def zcard(self, *_args):
        return self

    def expire(self, *_args):
        return self

    async def execute(self):
        return [0, 1, 1, 1]


class _DisableRedis:
    def __init__(self, values):
        self.values = values
        self.client = self

    async def get(self, key):
        return self.values.get(key)

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def set(self, key, value, *, nx=False, ex=None):
        del ex
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def delete(self, key):
        return int(self.values.pop(key, None) is not None)

    async def expire(self, key, _ttl):
        return int(key in self.values)

    def pipeline(self):
        return _DisablePipeline()


async def _user(db: AsyncSession, user_id: str) -> User:
    user = User(
        user_id=user_id,
        username=f"u{uuid.uuid4().hex[:10]}",
        coldkey=f"cold-{user_id}",
        fingerprint_hash=uuid.uuid4().hex,
        storage_volume_quota_bytes=20 * 1024**3,
        storage_aggregate_quota_bytes=100 * 1024**3,
    )
    db.add(user)
    await db.commit()
    return user


async def _chute(db: AsyncSession, user_id: str, chute_id: str) -> Chute:
    suffix = uuid.uuid4().hex
    image = Image(
        image_id=f"image-{suffix}",
        user_id=user_id,
        name=f"image-{suffix}",
        tag="latest",
        status="built and pushed",
        public=False,
        compute_type="cpu",
    )
    db.add(image)
    await db.flush()
    await db.execute(
        Chute.__table__.insert().values(
            chute_id=chute_id,
            user_id=user_id,
            name=f"chute-{suffix}",
            tagline="",
            readme="",
            image_id=image.image_id,
            public=False,
            cords=[],
            node_selector={"compute_type": "cpu", "cpu_cores": 2, "ram_gb": 4},
            code="from chutes import Chute\n",
            filename="app.py",
            ref_str="app:chute",
            version="1",
            tee=True,
        )
    )
    await db.commit()
    return await db.get(Chute, chute_id)


def _identity(name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mtls_request(cert) -> Request:
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    headers = [
        (b"x-client-cert", quote(pem, safe="").encode()),
        (b"x-client-verify", b"FAILED:self-signed certificate"),
    ]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/storage/default-volume",
            "headers": headers,
        }
    )


async def _cpu_launch(
    db: AsyncSession,
    *,
    user_id: str,
    chute: Chute,
    server_id: str,
    cert,
) -> tuple[LaunchConfig, Instance]:
    _, volume, _ = await service.ensure_default_volume_binding(
        db,
        user_id,
        chute.chute_id,
    )
    server = Server(
        server_id=server_id,
        ip=f"192.0.2.{int(uuid.uuid4().hex[:2], 16) % 200 + 1}",
        miner_hotkey=storage_pg.MINER,
        name=server_id,
        netuid=settings.netuid,
        is_tee=True,
        self_registered=True,
        compute_type="cpu",
        tee_type="sev-snp",
        storage_role=False,
        attested_cert=cert.public_bytes(serialization.Encoding.PEM).decode(),
        attested_cert_pubkey_hash=get_public_key_hash(cert),
    )
    db.add(server)
    await db.flush()
    config = LaunchConfig(
        config_id=f"config-{uuid.uuid4().hex}",
        seed=0,
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=user_id,
        compute_type="cpu",
        default_volume_id=volume.volume_id,
        storage_session_exchange_allowed=True,
        env_type="tee",
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        server_id=server_id,
        verified_at=datetime.now(),
    )
    instance = Instance(
        instance_id=f"instance-{uuid.uuid4().hex}",
        host=server.ip,
        port=8000,
        chute_id=chute.chute_id,
        version=chute.version,
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        active=True,
        verified=True,
        activated_at=datetime.now(timezone.utc),
        config_id=config.config_id,
        server_id=server_id,
    )
    db.add_all([config, instance])
    await db.commit()
    return config, instance


async def _install_launch_erasure_migration(db: AsyncSession) -> None:
    await db.commit()
    async with db.bind.begin() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(
            storage_pg._migration_up_sql("20260724234500_gpu_chutefs_default_volume.sql")
        )
    await db.rollback()


async def _ensure_test_token_key_epoch(db: AsyncSession) -> str:
    key_id = settings.chutefs_token_key_id
    keys = settings.chutefs_token_keys
    fingerprints = token_key_fingerprints(keys)
    storage_startup._VALIDATED_TOKEN_KEY_FINGERPRINTS = {key_id: fingerprints[key_id]}
    existing = await db.get(ChuteFSTokenKeyEpoch, key_id)
    if existing is not None:
        return key_id
    replica_id = "chutefs-test-replica"
    epoch = ChuteFSTokenKeyEpoch(
        key_id=key_id,
        key_sha256=fingerprints[key_id],
        state="staged",
        cohort_id="test-api",
        required_ack_count=1,
    )
    db.add(epoch)
    await db.flush()
    db.add(
        ChuteFSTokenKeyReplicaAck(
            replica_id=replica_id,
            key_id=key_id,
            cohort_id="test-api",
            key_ids=sorted(keys),
            key_fingerprints=token_key_fingerprints(keys),
            keyring_sha256=token_keyset_sha256(keys),
        )
    )
    await db.flush()
    epoch.state = "active"
    epoch.activated_at = datetime.now(timezone.utc)
    await db.commit()
    return key_id


async def test_timestamped_migration_applies_with_durable_constraints(pg_session):
    db, _ = pg_session
    migration = "20260724234500_gpu_chutefs_default_volume.sql"
    async with db.bind.connect() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(storage_pg._migration_down_sql(migration))
        await raw.driver_connection.execute(storage_pg._migration_up_sql(migration))
        await connection.commit()
    await db.rollback()
    active_unique = await db.scalar(
        text(
            "SELECT COUNT(*) FROM pg_indexes "
            "WHERE schemaname = current_schema() "
            "AND indexname = 'uq_default_chutefs_binding_active'"
        )
    )
    trigger_count = await db.scalar(
        text(
            "SELECT COUNT(*) FROM pg_trigger AS trigger_row "
            "JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE NOT trigger_row.tgisinternal "
            "AND namespace.oid = current_schema()::regnamespace "
            "AND trigger_row.tgname IN ("
            "'trg_default_chutefs_binding_identity', "
            "'trg_revoke_chutefs_session_on_instance_disable', "
            "'trg_revoke_chutefs_session_on_config_failure', "
            "'trg_revoke_chutefs_session_on_server_change', "
            "'trg_revoke_chutefs_session_on_reservation_change', "
            "'trg_complete_launch_config_on_job_terminal', "
            "'trg_prevent_user_delete_before_chutefs_erasure')"
        )
    )
    chute_foreign_key = await db.scalar(
        text(
            "SELECT COUNT(*) "
            "FROM information_schema.table_constraints tc "
            "JOIN information_schema.key_column_usage kcu "
            "  ON tc.constraint_schema = kcu.constraint_schema "
            " AND tc.constraint_name = kcu.constraint_name "
            "JOIN information_schema.constraint_column_usage ccu "
            "  ON tc.constraint_schema = ccu.constraint_schema "
            " AND tc.constraint_name = ccu.constraint_name "
            "WHERE tc.table_schema = current_schema() "
            "AND tc.table_name = 'default_chutefs_volume_bindings' "
            "AND tc.constraint_type = 'FOREIGN KEY' "
            "AND kcu.column_name = 'chute_id' "
            "AND ccu.table_name = 'chutes'"
        )
    )
    assert active_unique == 1
    assert trigger_count == 7
    assert chute_foreign_key == 0


async def test_concurrent_default_creation_is_single_and_owner_isolated(pg_session):
    db, _ = pg_session
    chute_id = f"durable-{uuid.uuid4().hex}"
    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def create_once():
        async with sessions() as candidate:
            binding, volume, _ = await service.ensure_default_volume_binding(
                candidate,
                storage_pg.USER_ID,
                chute_id,
            )
            await candidate.commit()
            return binding.binding_id, volume.volume_id

    first, second = await asyncio.gather(create_once(), create_once())
    assert first == second
    assert (
        await db.scalar(
            select(func.count())
            .select_from(DefaultChuteFSVolumeBinding)
            .where(
                DefaultChuteFSVolumeBinding.user_id == storage_pg.USER_ID,
                DefaultChuteFSVolumeBinding.chute_id == chute_id,
                DefaultChuteFSVolumeBinding.lifecycle_state == "active",
            )
        )
        == 1
    )
    assert await db.scalar(select(func.count()).select_from(StorageVolumeKey)) == 1

    other = await _user(db, f"other-{uuid.uuid4().hex}")
    other_binding, other_volume, _ = await service.ensure_default_volume_binding(
        db,
        other.user_id,
        chute_id,
    )
    await db.commit()
    assert other_binding.user_id == other.user_id
    assert other_volume.volume_id != first[1]


async def test_explicit_purge_blocks_then_allows_fresh_binding(pg_session):
    db, _ = pg_session
    chute_id = f"purge-{uuid.uuid4().hex}"
    first_binding, first_volume, _ = await service.ensure_default_volume_binding(
        db,
        storage_pg.USER_ID,
        chute_id,
    )
    await db.commit()
    deleted = await service.delete_volume(db, first_volume.volume_id, storage_pg.USER_ID)
    assert deleted["purge_pending"] is True
    with pytest.raises(HTTPException, match="still completing"):
        await service.ensure_default_volume_binding(db, storage_pg.USER_ID, chute_id)
    await db.rollback()

    await service.reconcile_storage(db)
    await db.refresh(first_volume)
    assert first_volume.key_shredded_at is not None
    assert first_volume.purged_at is not None
    second_binding, second_volume, _ = await service.ensure_default_volume_binding(
        db,
        storage_pg.USER_ID,
        chute_id,
    )
    await db.commit()
    assert first_binding.lifecycle_state == "retired"
    assert second_binding.binding_id != first_binding.binding_id
    assert second_volume.volume_id != first_volume.volume_id


async def test_default_volume_creation_preserves_volume_count_quota(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    user = await _user(db, f"quota-{uuid.uuid4().hex}")
    monkeypatch.setattr(settings, "storage_max_volumes_per_user", 1)
    await service.create_volume(db, user.user_id, "explicit", 1)
    with pytest.raises(HTTPException, match="maximum number"):
        await service.ensure_default_volume_binding(
            db,
            user.user_id,
            f"quota-chute-{uuid.uuid4().hex}",
        )


async def test_instance_and_chute_deletion_do_not_delete_binding(pg_session):
    db, _ = pg_session
    chute = await _chute(db, storage_pg.USER_ID, f"keep-{uuid.uuid4().hex}")
    binding, volume, _ = await service.ensure_default_volume_binding(
        db,
        storage_pg.USER_ID,
        chute.chute_id,
    )
    config = LaunchConfig(
        config_id=f"config-{uuid.uuid4().hex}",
        seed=0,
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=storage_pg.USER_ID,
        compute_type="cpu",
        default_volume_id=volume.volume_id,
        storage_session_exchange_allowed=False,
        env_type="tee",
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
    )
    instance = Instance(
        instance_id=f"instance-{uuid.uuid4().hex}",
        host=f"198.51.100.{int(uuid.uuid4().hex[:2], 16) % 200 + 1}",
        port=8000,
        chute_id=chute.chute_id,
        version=chute.version,
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        config_id=config.config_id,
    )
    db.add_all([config, instance])
    await db.commit()

    await prepare_instance_terminal_writes(
        db,
        [instance.instance_id],
        complete_launch_configs=True,
    )
    await db.delete(instance)
    await db.commit()
    assert await db.get(DefaultChuteFSVolumeBinding, binding.binding_id) is not None
    await db.delete(chute)
    await db.commit()
    kept = await db.get(DefaultChuteFSVolumeBinding, binding.binding_id)
    assert kept is not None
    assert kept.lifecycle_state == "active"
    assert await db.get(StorageVolume, volume.volume_id) is not None


async def test_launch_session_rotates_once_and_revokes_on_disable(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    await _install_launch_erasure_migration(db)
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"session-{uuid.uuid4().hex}")
    _, cert = _identity("launch-session")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"server-{uuid.uuid4().hex}",
        cert=cert,
    )
    config_id = config.config_id
    default_volume_id = config.default_volume_id
    instance_id = instance.instance_id
    attestation_check = AsyncMock(return_value=None)
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        attestation_check,
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    context, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config_id,
        request,
    )
    assert context.user_id == storage_pg.USER_ID
    assert context.default_volume_id == default_volume_id
    authorized = await launch_sessions.authorize_default_volume(
        db,
        f"Bearer {issued.access_token}",
        request,
        "put",
    )
    assert authorized.volume.volume_id == default_volume_id
    await db.commit()
    grant_response = await issue_default_volume_grant(
        DefaultGrantRequest(op="list"),
        request,
        db,
        f"Bearer {issued.access_token}",
    )
    launch_grant = grant_response.grant
    assert 0 < grant_response.expires_in <= launch_sessions.ACCESS_TTL_SECONDS
    grant_payload = json.loads(redis.values[f"storage:grant:{launch_grant}"])
    assert grant_payload["launch_session_generation"] == issued.generation
    assert datetime.fromisoformat(grant_payload["expires_at"]) <= datetime.fromisoformat(
        issued.access_expires_at
    )
    assert (
        await service.verify_grant(
            launch_grant,
            authorized.volume.volume_id,
            "list",
            db=db,
        )
    )["auth_kind"] == "launch_default"
    await db.commit()

    _, rotated = await launch_sessions.refresh_launch_storage_session(
        db,
        f"Bearer {issued.refresh_token}",
        request,
    )
    assert rotated.access_token != issued.access_token
    assert rotated.refresh_token != issued.refresh_token
    assert rotated.reexchange_token != issued.reexchange_token
    assert rotated.generation == issued.generation + 1
    assert (
        await service.verify_grant(
            launch_grant,
            default_volume_id,
            "list",
            db=db,
        )
        is None
    )
    await db.commit()
    _, replayed = await launch_sessions.refresh_launch_storage_session(
        db,
        f"Bearer {issued.refresh_token}",
        request,
    )
    assert replayed.model_dump(mode="json") == rotated.model_dump(mode="json")
    rows = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession)
                .where(ChuteFSLaunchSession.config_id == config_id)
                .order_by(ChuteFSLaunchSession.generation)
            )
        )
        .scalars()
        .all()
    )
    assert [row.generation for row in rows] == [issued.generation, rotated.generation]
    assert sum(row.revoked_at is None for row in rows) == 1
    replay_deadline = rows[-1].response_replay_until
    assert replay_deadline is not None
    with monkeypatch.context() as replay_time:
        replay_time.setattr(
            launch_sessions,
            "_now",
            lambda: replay_deadline + timedelta(seconds=1),
        )
        with pytest.raises(HTTPException, match="invalid, expired, replayed, or revoked"):
            await launch_sessions.refresh_launch_storage_session(
                db,
                f"Bearer {issued.refresh_token}",
                request,
            )
    await db.rollback()
    replay_rows = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession)
                .where(ChuteFSLaunchSession.config_id == config_id)
                .order_by(ChuteFSLaunchSession.generation)
            )
        )
        .scalars()
        .all()
    )
    assert [row.generation for row in replay_rows] == [
        issued.generation,
        rotated.generation,
    ]
    assert sum(row.revoked_at is None for row in replay_rows) == 1
    with pytest.raises(HTTPException, match="invalid"):
        await launch_sessions.authorize_default_volume(
            db,
            f"Bearer {issued.access_token}",
            request,
            "get",
        )
    await db.rollback()
    assert (
        await launch_sessions.authorize_default_volume(
            db,
            f"Bearer {rotated.access_token}",
            request,
            "get",
        )
    ).instance.instance_id == instance_id
    await db.commit()

    attestation_check.side_effect = HTTPException(
        status_code=403,
        detail="latest attestation failed",
    )
    with pytest.raises(HTTPException, match="latest attestation failed"):
        await launch_sessions.authorize_default_volume(
            db,
            f"Bearer {rotated.access_token}",
            request,
            "list",
        )
    await db.rollback()
    attestation_check.side_effect = None
    attestation_check.return_value = None

    current_instance = await db.get(Instance, instance_id)
    assert current_instance is not None
    prior_revocation_epoch = current_instance.storage_revocation_epoch
    await prepare_instance_terminal_writes(
        db,
        [instance_id],
        complete_launch_configs=False,
    )
    current_instance.active = False
    await db.commit()
    await db.refresh(current_instance)
    assert current_instance.storage_revocation_epoch == prior_revocation_epoch + 1
    with pytest.raises(
        HTTPException,
        match="inactive|invalid, expired, or revoked",
    ):
        await launch_sessions.authorize_default_volume(
            db,
            f"Bearer {rotated.access_token}",
            request,
            "get",
        )
    await db.rollback()
    assert (
        await service.verify_grant(
            launch_grant,
            default_volume_id,
            "list",
            db=db,
        )
        is None
    )
    await db.commit()


async def test_disable_between_preflight_and_lifecycle_lock_fences_authority(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    await _install_launch_erasure_migration(db)
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"disable-race-{uuid.uuid4().hex}")
    _, cert = _identity("disable-race")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"disable-race-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    _, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config.config_id,
        request,
    )
    grant = (
        await issue_default_volume_grant(
            DefaultGrantRequest(op="list"),
            request,
            db,
            f"Bearer {issued.access_token}",
        )
    ).grant
    await db.commit()
    prior_epoch = instance.storage_revocation_epoch

    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    @asynccontextmanager
    async def dedicated_session(*_args, **_kwargs):
        async with sessions() as candidate:
            yield candidate

    monkeypatch.setattr(instance_util, "get_session", dedicated_session)
    monkeypatch.setattr(settings, "_redis_client", _DisableRedis(redis.values))
    passed_redis_preflight = asyncio.Event()
    release_refresh = asyncio.Event()
    original_preflight = launch_sessions._require_not_disabled

    async def pause_after_redis_preflight(candidate, instance_id):
        await original_preflight(candidate, instance_id)
        passed_redis_preflight.set()
        await release_refresh.wait()

    monkeypatch.setattr(
        launch_sessions,
        "_require_not_disabled",
        pause_after_redis_preflight,
    )

    async def refresh_in_separate_transaction():
        async with sessions() as candidate:
            return await launch_sessions.refresh_launch_storage_session(
                candidate,
                f"Bearer {issued.refresh_token}",
                request,
            )

    refresh_task = asyncio.create_task(refresh_in_separate_transaction())
    await asyncio.wait_for(passed_redis_preflight.wait(), timeout=10)
    try:
        assert await instance_util.disable_instance(
            instance.instance_id,
            chute.chute_id,
            storage_pg.MINER,
        )
    finally:
        release_refresh.set()

    with pytest.raises(HTTPException) as rejected:
        await asyncio.wait_for(refresh_task, timeout=10)
    assert rejected.value.status_code == 401

    # Expire the transient Redis fast-path before checking the grant so this
    # assertion exercises only the durable epoch/session revocation boundary.
    redis.values.pop(f"instance_disabled:{instance.instance_id}", None)
    async with sessions() as verifier:
        durable_instance = await verifier.get(Instance, instance.instance_id)
        durable_session = await verifier.scalar(
            select(ChuteFSLaunchSession).where(
                ChuteFSLaunchSession.access_token_hash
                == launch_sessions._token_hash(issued.access_token)
            )
        )
        assert durable_instance.storage_revocation_epoch == prior_epoch + 1
        assert durable_session.revoked_at is not None
        assert (
            await service.verify_grant(
                grant,
                config.default_volume_id,
                "list",
                db=verifier,
            )
            is None
        )
        await verifier.commit()


async def test_refresh_lost_response_replays_after_predecessor_expiry(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"refresh-boundary-{uuid.uuid4().hex}")
    _, cert = _identity("refresh-boundary")
    config, _instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"refresh-boundary-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    _, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config.config_id,
        request,
    )
    refresh_expiry = datetime.fromisoformat(issued.refresh_expires_at)

    with monkeypatch.context() as clock:
        clock.setattr(
            launch_sessions,
            "_now",
            lambda: refresh_expiry - timedelta(seconds=1),
        )
        _, rotated = await launch_sessions.refresh_launch_storage_session(
            db,
            f"Bearer {issued.refresh_token}",
            request,
        )
        clock.setattr(
            launch_sessions,
            "_now",
            lambda: refresh_expiry + timedelta(seconds=1),
        )
        _, replayed = await launch_sessions.refresh_launch_storage_session(
            db,
            f"Bearer {issued.refresh_token}",
            request,
        )
    assert replayed.model_dump(mode="json") == rotated.model_dump(mode="json")


async def test_reexchange_rotates_after_refresh_expiry_with_exact_replay(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"reexchange-{uuid.uuid4().hex}")
    _, cert = _identity("launch-reexchange")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"reexchange-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    _, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config.config_id,
        request,
    )
    after_refresh_expiry = datetime.fromisoformat(issued.refresh_expires_at) + timedelta(seconds=1)

    with monkeypatch.context() as future:
        future.setattr(
            launch_sessions,
            "_now",
            lambda: after_refresh_expiry,
        )
        _, recovered = await launch_sessions.exchange_launch_token(
            db,
            config.config_id,
            issued.reexchange_token,
            request,
        )
        assert recovered.generation == issued.generation + 1
        assert recovered.access_token != issued.access_token
        assert recovered.refresh_token != issued.refresh_token
        assert recovered.reexchange_token != issued.reexchange_token

        _, replayed = await launch_sessions.exchange_launch_token(
            db,
            config.config_id,
            issued.reexchange_token,
            request,
        )
        assert replayed.model_dump(mode="json") == recovered.model_dump(mode="json")

        with pytest.raises(HTTPException, match="invalid, expired"):
            await launch_sessions.refresh_launch_storage_session(
                db,
                f"Bearer {issued.refresh_token}",
                request,
            )
        await db.rollback()
        with pytest.raises(HTTPException, match="invalid"):
            await launch_sessions.authorize_default_volume(
                db,
                f"Bearer {issued.access_token}",
                request,
                "get",
            )
        await db.rollback()
        authorized = await launch_sessions.authorize_default_volume(
            db,
            f"Bearer {recovered.access_token}",
            request,
            "get",
        )
        assert authorized.instance.instance_id == instance.instance_id
        await db.commit()

    rows = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession)
                .where(ChuteFSLaunchSession.config_id == config.config_id)
                .order_by(ChuteFSLaunchSession.generation)
            )
        )
        .scalars()
        .all()
    )
    assert [row.generation for row in rows] == [1, 2]
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None


async def test_delayed_launch_exchange_cannot_replace_refreshed_session(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"stale-issue-{uuid.uuid4().hex}")
    _, cert = _identity("stale-issue")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"stale-issue-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    launch_token = create_launch_jwt_v2(config)
    config_id = config.config_id
    instance_id = instance.instance_id

    _, issued = await launch_sessions.exchange_launch_token(
        db,
        config_id,
        launch_token,
        request,
    )
    _, issue_replay = await launch_sessions.exchange_launch_token(
        db,
        config_id,
        launch_token,
        request,
    )
    assert issue_replay.model_dump(mode="json") == issued.model_dump(mode="json")

    issued_session_id = launch_sessions._session_id_from_token(
        issued.access_token,
        launch_sessions._ACCESS_PREFIX,
    )
    issued_row = await db.get(ChuteFSLaunchSession, issued_session_id)
    issue_replay_deadline = issued_row.response_replay_until
    assert issue_replay_deadline is not None
    with monkeypatch.context() as issue_time:
        issue_time.setattr(
            launch_sessions,
            "_now",
            lambda: issue_replay_deadline + timedelta(seconds=1),
        )
        with pytest.raises(HTTPException, match="advanced beyond this issue request"):
            await launch_sessions.exchange_launch_token(
                db,
                config_id,
                launch_token,
                request,
            )
    await db.rollback()
    pre_rotation_rows = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession).where(ChuteFSLaunchSession.config_id == config_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(pre_rotation_rows) == 1
    assert pre_rotation_rows[0].session_id == issued_session_id
    assert pre_rotation_rows[0].revoked_at is None

    _, rotated = await launch_sessions.refresh_launch_storage_session(
        db,
        f"Bearer {issued.refresh_token}",
        request,
    )
    with pytest.raises(HTTPException, match="advanced beyond this issue request"):
        await launch_sessions.exchange_launch_token(
            db,
            config_id,
            launch_token,
            request,
        )
    await db.rollback()

    rows = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession)
                .where(ChuteFSLaunchSession.config_id == config_id)
                .order_by(ChuteFSLaunchSession.generation)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert [row.generation for row in rows] == [issued.generation, rotated.generation]
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None
    assert rows[0].rotated_from_session_id is None
    assert rows[1].rotated_from_session_id == rows[0].session_id
    assert rows[1].session_id == launch_sessions._session_id_from_token(
        rotated.access_token,
        launch_sessions._ACCESS_PREFIX,
    )
    authorized = await launch_sessions.authorize_default_volume(
        db,
        f"Bearer {rotated.access_token}",
        request,
        "get",
    )
    assert authorized.instance.instance_id == instance_id


async def test_launch_exchange_denies_cross_config_and_requires_mtls(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    chute = await _chute(db, storage_pg.USER_ID, f"exchange-{uuid.uuid4().hex}")
    _, cert = _identity("launch-exchange")
    config, _ = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    token = create_launch_jwt_v2(config)
    with pytest.raises(HTTPException, match="permission"):
        await launch_sessions.exchange_launch_token(
            db,
            "different-config",
            token,
            _mtls_request(cert),
        )
    missing_mtls = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/storage/default-volume/session/exchange",
            "headers": [],
        }
    )
    with pytest.raises(HTTPException):
        await launch_sessions.exchange_launch_token(
            db,
            config.config_id,
            token,
            missing_mtls,
        )


async def test_account_delete_stages_then_waits_for_launch_and_key_shred(
    pg_session,
):
    db, _ = pg_session
    await _install_launch_erasure_migration(db)
    fingerprint = f"account-delete-{uuid.uuid4().hex}"
    user = await _user(db, f"delete-{uuid.uuid4().hex}")
    user.fingerprint_hash = hashlib.blake2b(fingerprint.encode()).hexdigest()
    await db.commit()
    chute = await _chute(db, user.user_id, f"delete-chute-{uuid.uuid4().hex}")
    _, explicit_volume_quota = await service.create_volume(
        db,
        user.user_id,
        "explicit-account-volume",
        1,
    )
    assert explicit_volume_quota > 0
    _, cert = _identity("account-delete")
    config, instance = await _cpu_launch(
        db,
        user_id=user.user_id,
        chute=chute,
        server_id=f"delete-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    historical = LaunchConfig(
        config_id=f"historical-{uuid.uuid4().hex}",
        seed=0,
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=user.user_id,
        compute_type="cpu",
        storage_session_exchange_allowed=False,
        env_type="tee",
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        server_id=config.server_id,
        verified_at=datetime.now(),
    )
    db.add(historical)
    await db.commit()

    with pytest.raises(HTTPException) as active_error:
        await delete_my_user(db=db, authorization=f"Bearer {fingerprint}")
    assert active_error.value.status_code == 409
    assert active_error.value.detail["active_launches"] == [config.config_id]
    await db.refresh(historical)
    assert historical.completed_at is not None
    assert await db.get(User, user.user_id) is not None
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageVolume)
            .where(StorageVolume.user_id == user.user_id, StorageVolume.deleted.is_(True))
        )
        == 2
    )

    await prepare_instance_terminal_writes(
        db,
        [instance.instance_id],
        complete_launch_configs=True,
    )
    await db.delete(instance)
    await db.commit()
    await db.refresh(config)
    assert config.failed_at is None
    assert config.completed_at is not None
    with pytest.raises(HTTPException) as purge_error:
        await delete_my_user(db=db, authorization=f"Bearer {fingerprint}")
    assert purge_error.value.status_code == 409
    assert purge_error.value.detail["active_launches"] == []
    assert len(purge_error.value.detail["purge_pending"]) == 2

    await service.reconcile_storage(db)
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageVolumeKey)
            .join(StorageVolume, StorageVolume.volume_id == StorageVolumeKey.volume_id)
            .where(StorageVolume.user_id == user.user_id)
        )
        == 0
    )
    assert await delete_my_user(db=db, authorization=f"Bearer {fingerprint}") == {"deleted": True}
    assert (
        await db.scalar(select(func.count()).select_from(User).where(User.user_id == user.user_id))
        == 0
    )
    assert (
        await db.scalar(
            select(func.count())
            .select_from(DefaultChuteFSVolumeBinding)
            .where(DefaultChuteFSVolumeBinding.user_id == user.user_id)
        )
        == 0
    )
    assert (
        await db.scalar(
            select(func.count())
            .select_from(LaunchConfig)
            .where(LaunchConfig.user_id == user.user_id)
        )
        == 0
    )


async def test_public_job_account_delete_accepts_completed_launch_config(pg_session):
    db, _ = pg_session
    await _install_launch_erasure_migration(db)
    fingerprint = f"public-job-delete-{uuid.uuid4().hex}"
    user = await _user(db, f"public-job-{uuid.uuid4().hex}")
    user.fingerprint_hash = hashlib.blake2b(fingerprint.encode()).hexdigest()
    chute = await _chute(db, user.user_id, f"public-job-chute-{uuid.uuid4().hex}")
    chute.public = True
    job = Job(
        job_id=f"job-{uuid.uuid4().hex}",
        user_id=user.user_id,
        chute_id=chute.chute_id,
        version=chute.version,
        method="run",
        active=True,
        verified=True,
        job_args={},
        status="running",
        compute_multiplier=1.0,
        miner_history=[],
    )
    config = LaunchConfig(
        config_id=f"job-config-{uuid.uuid4().hex}",
        seed=0,
        env_key=uuid.uuid4().hex,
        chute_id=chute.chute_id,
        user_id=user.user_id,
        compute_type="cpu",
        storage_session_exchange_allowed=False,
        job_id=job.job_id,
        env_type="tee",
        miner_uid=1,
        miner_hotkey=storage_pg.MINER,
        miner_coldkey="coldkey",
        verified_at=datetime.now(),
    )
    db.add_all([job, config])
    await db.commit()
    job.finished_at = datetime.now()
    job.active = False
    job.verified = False
    await db.commit()
    await db.refresh(config)
    assert config.completed_at is not None

    assert await delete_my_user(db=db, authorization=f"Bearer {fingerprint}") == {"deleted": True}
    assert (
        await db.scalar(select(func.count()).select_from(User).where(User.user_id == user.user_id))
        == 0
    )


async def test_retired_server_delete_cleans_launch_identity_and_session(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"server-delete-{uuid.uuid4().hex}")
    _, cert = _identity("server-delete")
    server_id = f"server-delete-{uuid.uuid4().hex}"
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=server_id,
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    await launch_sessions.issue_launch_storage_session(db, config.config_id, _mtls_request(cert))

    assert await delete_server(db, server_id, storage_pg.MINER) is True
    assert await db.get(Server, server_id) is None
    assert await db.get(LaunchConfig, config.config_id) is None
    assert (
        await db.scalar(
            select(func.count())
            .select_from(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.server_id == server_id)
        )
        == 0
    )
    await db.refresh(instance)
    assert instance.active is False
    assert instance.verified is False
    assert instance.server_id is None
    assert instance.config_id is None


async def test_refresh_and_instance_disable_share_lifecycle_lock_without_deadlock(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"lock-order-{uuid.uuid4().hex}")
    _, cert = _identity("lock-order")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"lock-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    _, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config.config_id,
        request,
    )
    config_id = config.config_id
    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_after_lifecycle_rows(*_args, **_kwargs):
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        pause_after_lifecycle_rows,
    )

    async def refresh():
        async with sessions() as candidate:
            return await launch_sessions.refresh_launch_storage_session(
                candidate,
                f"Bearer {issued.refresh_token}",
                request,
            )

    async def disable():
        await entered.wait()
        async with sessions() as candidate:
            current = (
                await candidate.execute(
                    select(Instance)
                    .where(Instance.instance_id == instance.instance_id)
                    .options(lazyload("*"))
                    .with_for_update()
                )
            ).scalar_one()
            current.active = False
            await candidate.commit()

    refresh_task = asyncio.create_task(refresh())
    disable_task = asyncio.create_task(disable())
    await entered.wait()
    release.set()
    (rotated_context, rotated_session), _ = await asyncio.wait_for(
        asyncio.gather(refresh_task, disable_task),
        timeout=10,
    )
    assert rotated_context.config_id == config_id
    async with sessions() as candidate:
        with pytest.raises(
            HTTPException,
            match="invalid, expired, or revoked",
        ) as rejected:
            await launch_sessions.authorize_default_volume(
                candidate,
                f"Bearer {rotated_session.access_token}",
                request,
                "get",
            )
        assert rejected.value.status_code == 401


async def test_refresh_and_account_erasure_share_lock_order_without_deadlock(
    pg_session,
    monkeypatch,
):
    db, _ = pg_session
    await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"erasure-lock-{uuid.uuid4().hex}")
    _, cert = _identity("erasure-lock")
    config, _ = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"erasure-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(settings, "require_mtls_client_verify", True)
    request = _mtls_request(cert)
    _, issued = await launch_sessions.issue_launch_storage_session(
        db,
        config.config_id,
        request,
    )
    config_id = config.config_id
    sessions = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause_after_lifecycle_rows(*_args, **_kwargs):
        entered.set()
        await release.wait()

    monkeypatch.setattr(
        launch_sessions,
        "_require_current_attestation_identity",
        pause_after_lifecycle_rows,
    )

    async def refresh():
        async with sessions() as candidate:
            return await launch_sessions.refresh_launch_storage_session(
                candidate,
                f"Bearer {issued.refresh_token}",
                request,
            )

    async def erase():
        await entered.wait()
        async with sessions() as candidate:
            return await service.prepare_user_storage_erasure(
                candidate,
                storage_pg.USER_ID,
            )

    refresh_task = asyncio.create_task(refresh())
    erasure_task = asyncio.create_task(erase())
    await entered.wait()
    release.set()
    (_, rotated), erasure = await asyncio.wait_for(
        asyncio.gather(refresh_task, erasure_task),
        timeout=10,
    )
    assert rotated.generation == issued.generation + 1
    assert erasure["ready"] is False
    assert config_id in erasure["active_launches"]


async def test_expired_rotation_lineage_prunes_in_bounded_batches(pg_session):
    db, _ = pg_session
    key_id = await _ensure_test_token_key_epoch(db)
    chute = await _chute(db, storage_pg.USER_ID, f"prune-{uuid.uuid4().hex}")
    _, cert = _identity("prune-lineage")
    config, instance = await _cpu_launch(
        db,
        user_id=storage_pg.USER_ID,
        chute=chute,
        server_id=f"prune-server-{uuid.uuid4().hex}",
        cert=cert,
    )
    binding = await db.scalar(
        select(DefaultChuteFSVolumeBinding).where(
            DefaultChuteFSVolumeBinding.user_id == storage_pg.USER_ID,
            DefaultChuteFSVolumeBinding.chute_id == chute.chute_id,
            DefaultChuteFSVolumeBinding.lifecycle_state == "active",
        )
    )
    server = await db.get(Server, config.server_id)
    now = datetime.now(timezone.utc)

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    common = {
        "config_id": config.config_id,
        "instance_id": instance.instance_id,
        "binding_id": binding.binding_id,
        "user_id": storage_pg.USER_ID,
        "chute_id": chute.chute_id,
        "job_id": None,
        "compute_type": "cpu",
        "management_mode": "platform",
        "server_id": server.server_id,
        "volume_id": binding.volume_id,
        "reservation_id": None,
        "allocation_group_id": None,
        "allocation_group_generation": None,
        "process_incarnation": None,
        "attestation_id": None,
        "attested_cert_pubkey_hash": server.attested_cert_pubkey_hash,
        "allowed_operations": list(launch_sessions.ALLOWED_OPERATIONS),
        "revocation_epoch": instance.storage_revocation_epoch,
        "token_key_id": key_id,
    }
    history_ids = [f"history-{index:03d}-{uuid.uuid4().hex}" for index in range(129)]
    for index, session_id in enumerate(history_ids, start=1):
        db.add(
            ChuteFSLaunchSession(
                session_id=session_id,
                rotated_from_session_id=None,
                rotated_from_session_sha256=None,
                generation=index,
                access_token_hash=digest(f"access-{session_id}"),
                refresh_token_hash=digest(f"refresh-{session_id}"),
                reexchange_token_hash=digest(f"reexchange-{session_id}"),
                access_expires_at=now - timedelta(hours=2),
                refresh_expires_at=now - timedelta(hours=1),
                rotation_request_sha256=digest(f"rotate-{session_id}"),
                token_seed=digest(f"seed-{session_id}"),
                response_replay_until=now - timedelta(minutes=90),
                revoked_at=now - timedelta(hours=2),
                **common,
            )
        )

    active_id = f"active-{uuid.uuid4().hex}"
    db.add(
        ChuteFSLaunchSession(
            session_id=active_id,
            rotated_from_session_id=history_ids[0],
            rotated_from_session_sha256=digest(history_ids[0]),
            generation=130,
            access_token_hash=digest(f"access-{active_id}"),
            refresh_token_hash=digest(f"refresh-{active_id}"),
            reexchange_token_hash=digest(f"reexchange-{active_id}"),
            access_expires_at=now + timedelta(minutes=15),
            refresh_expires_at=now + timedelta(hours=24),
            rotation_request_sha256=digest(f"rotate-{active_id}"),
            token_seed=digest(f"seed-{active_id}"),
            response_replay_until=now + timedelta(minutes=15),
            revoked_at=None,
            **common,
        )
    )
    await db.commit()

    assert (
        await launch_sessions._prune_expired_session_lineage(
            db,
            config.config_id,
            now=now,
        )
        == 128
    )
    await db.commit()
    assert (
        await db.scalar(
            select(func.count())
            .select_from(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.config_id == config.config_id)
        )
        == 2
    )
    assert await db.get(ChuteFSLaunchSession, history_ids[0]) is not None
    active = await db.get(ChuteFSLaunchSession, active_id)
    assert active.rotated_from_session_id == history_ids[0]
    assert active.rotated_from_session_sha256 == digest(history_ids[0])

    assert (
        await launch_sessions._prune_expired_session_lineage(
            db,
            config.config_id,
            now=now,
        )
        == 0
    )
    await db.commit()
    assert (
        await db.scalar(
            select(func.count())
            .select_from(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.config_id == config.config_id)
        )
        == 2
    )

    after_replay = active.response_replay_until + timedelta(seconds=1)
    assert (
        await launch_sessions._prune_expired_session_lineage(
            db,
            config.config_id,
            now=after_replay,
        )
        == 1
    )
    await db.commit()
    assert await db.get(ChuteFSLaunchSession, history_ids[0]) is None
    assert (
        await db.scalar(
            select(func.count())
            .select_from(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.config_id == config.config_id)
        )
        == 1
    )
