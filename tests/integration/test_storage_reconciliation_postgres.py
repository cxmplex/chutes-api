"""Real-Postgres durability tests for ChuteFS placement and reconciliation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import uuid
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import api.database.orms  # noqa: F401
from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.database import Base
from api.database import migrations as database_migrations
from api.image.util import image_id_for
from api.metagraph import MetagraphNode
from api.server.schemas import (
    ContentHolding,
    ReplicaPlacement,
    Server,
    ServerAttestation,
    StorageObject,
    StorageEraseTask,
    StorageInventorySnapshot,
    StorageIncarnationRetirementAudit,
    StorageModelInventorySnapshot,
    StorageReplicaCertRebindAudit,
    StorageReplicationCapability,
    StorageObjectDeleteFence,
    StorageVolume,
    StorageVolumeKey,
)
from api.server.util import get_public_key_hash
from api.storage import reconcile as storage_reconcile
from api.storage import service
from api.storage.router import require_fresh_storage_caller
from api.user.schemas import User


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
DBMATE_BIN = os.getenv("DBMATE_BIN")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real-Postgres storage tests",
    ),
]

NOW = datetime.now(timezone.utc)
MINER = "5StorageMiner"
USER_ID = "storage-test-user"


@pytest.fixture(autouse=True)
def nv_attest():
    """Tracker tests do not invoke the external GPU-attestation CLI."""
    yield


class FakeRedis:
    def __init__(self):
        self.values: dict[str, str] = {}

    async def setex(self, key, _ttl, value):
        self.values[key] = value
        return True

    async def exists(self, key):
        return int(key in self.values)

    async def get(self, key):
        return self.values.get(key)

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def set(self, key, value, ex=None):
        self.values[key] = value
        return True

    async def delete(self, key):
        return int(self.values.pop(key, None) is not None)


def _migration_up_sql(filename: str) -> str:
    migration = (Path(__file__).resolve().parents[2] / f"api/migrations/{filename}").read_text()
    return migration.split("-- migrate:up", 1)[1].split("-- migrate:down", 1)[0]


def _migration_down_sql(filename: str) -> str:
    migration = (Path(__file__).resolve().parents[2] / f"api/migrations/{filename}").read_text()
    return migration.split("-- migrate:down", 1)[1]


async def _wait_for_postgres_blocker(engine, blocked_pid: int, blocker_pid: int) -> None:
    for _ in range(500):
        async with engine.connect() as observer:
            blocked = await observer.scalar(
                text(
                    "SELECT CAST(:blocker_pid AS integer) = ANY(pg_blocking_pids(:blocked_pid))"
                ),
                {
                    "blocked_pid": blocked_pid,
                    "blocker_pid": blocker_pid,
                },
            )
        if blocked:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(
        f"backend {blocked_pid} was not blocked by expected backend {blocker_pid}"
    )


PRE_MIGRATION_DDL = """
    ALTER TABLE vm_cache_configs
        DROP COLUMN IF EXISTS volume_generation_leases;
    DROP TABLE IF EXISTS storage_erase_tasks;
    DROP TABLE IF EXISTS storage_model_inventory_entries;
    DROP TABLE IF EXISTS storage_model_inventory_snapshots;
    DROP TABLE IF EXISTS storage_inventory_snapshots;
    DROP TABLE IF EXISTS storage_object_delete_fences;
    DROP INDEX IF EXISTS uq_servers_attested_pubkey;
    DROP INDEX IF EXISTS idx_servers_attested_pubkey;
    DROP INDEX IF EXISTS idx_servers_model_inventory_fresh;
    ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_model_inventory_marker;
    ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_fresh_at;
    ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_snapshot_id;
    ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_snapshot_started_at;
    ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_cert_pubkey_hash;
    ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_storage_incarnation;
    DROP INDEX IF EXISTS idx_content_holdings_stale;
    ALTER TABLE content_holdings DROP CONSTRAINT IF EXISTS ck_content_holding_signed_bytes;
    ALTER TABLE content_holdings DROP COLUMN IF EXISTS last_snapshot_started_at;
    ALTER TABLE content_holdings DROP COLUMN IF EXISTS last_snapshot_id;
    ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_storage_aggregate_quota;
    ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_storage_volume_quota;
    ALTER TABLE users DROP COLUMN IF EXISTS storage_aggregate_quota_bytes;
    ALTER TABLE users DROP COLUMN IF EXISTS storage_volume_quota_bytes;
    DROP TRIGGER IF EXISTS trg_storage_volume_grant_epoch_monotonic ON storage_volumes;
    DROP FUNCTION IF EXISTS enforce_storage_volume_grant_epoch_monotonic();
    ALTER TABLE storage_volumes
        DROP CONSTRAINT IF EXISTS ck_storage_volume_grant_revocation_epoch;
    ALTER TABLE storage_volumes DROP COLUMN IF EXISTS grant_revocation_epoch;
    ALTER TABLE storage_volumes DROP COLUMN IF EXISTS purged_at;
    ALTER TABLE storage_volumes DROP COLUMN IF EXISTS key_shredded_at;
    ALTER TABLE storage_volumes DROP COLUMN IF EXISTS delete_requested_at;
    DROP INDEX IF EXISTS idx_storage_volumes_deleted_work;
    DROP INDEX IF EXISTS idx_storage_objects_erase_queue;
    DROP INDEX IF EXISTS uq_storage_object_placement_request;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS erase_enqueued_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS placement_request_id;
    DROP INDEX IF EXISTS idx_storage_objects_expected_predecessor;
    DROP INDEX IF EXISTS idx_storage_objects_terminal_erase;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_detached_predecessor;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_signed_sizes;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS predecessor_detached_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS detached_predecessor_id;
    DROP INDEX IF EXISTS idx_replica_inventory_snapshot;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_plaintext_hash;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_plaintext_size;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_ciphertext_size;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_inventory_seen_at;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_inventory_snapshot_id;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_plaintext_sha256;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_plaintext_size_bytes;
    DROP TABLE IF EXISTS storage_replication_capabilities;
    DROP INDEX IF EXISTS idx_storage_objects_gc;
    DROP INDEX IF EXISTS idx_storage_objects_pending;
    DROP INDEX IF EXISTS idx_storage_objects_current;
    DROP INDEX IF EXISTS uq_storage_object_current;
    DROP INDEX IF EXISTS idx_storage_objects_volume;
    DROP INDEX IF EXISTS idx_storage_objects_reconcile;
    DROP TRIGGER IF EXISTS trg_storage_object_generation_immutable ON storage_objects;
    DROP FUNCTION IF EXISTS prevent_storage_object_generation_mutation();
    ALTER TABLE storage_objects
        DROP CONSTRAINT IF EXISTS uq_storage_object_volume_generation,
        DROP CONSTRAINT IF EXISTS ck_storage_object_generation;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS generation;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_lifecycle_state;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS fk_storage_object_expected_predecessor;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS uq_storage_object_key;
    ALTER TABLE storage_objects
        DROP CONSTRAINT IF EXISTS storage_objects_volume_id_object_key_key;
    ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE storage_objects
        ADD CONSTRAINT storage_objects_volume_id_object_key_key
        UNIQUE (volume_id, object_key);
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS tombstoned_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS superseded_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS committed_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS expected_predecessor_id;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS lifecycle_state;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_placement_status;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_placement_attempt_count;
    ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_placement_proof_mode;
    ALTER TABLE replica_placement ALTER COLUMN status SET DEFAULT 'present';
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS legacy_adoption_started_at;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_mode;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_capability_id;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_size_bytes;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_error;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_attempt_at;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS attempt_count;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS pending_deadline;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS pending_since;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_at;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_sha256;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS target_cert_pubkey_hash;
    ALTER TABLE replica_placement DROP COLUMN IF EXISTS storage_incarnation;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS durability_updated_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_storage_incarnation;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_cert_pubkey_hash;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_server_id;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_placement_id;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adopted_at;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS ciphertext_size_bytes;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS durable_replica_count;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS durability_state;
    ALTER TABLE storage_objects DROP COLUMN IF EXISTS projected_size_bytes;
    ALTER TABLE servers DROP COLUMN IF EXISTS storage_incarnation_announced_at;
    ALTER TABLE servers DROP COLUMN IF EXISTS storage_incarnation;
"""

FORWARD_MIGRATION_HAZARD_DDL = """
    DROP INDEX IF EXISTS idx_servers_last_health;
    ALTER TABLE servers DROP COLUMN IF EXISTS last_health_at;
    ALTER TABLE images ADD COLUMN IF NOT EXISTS cpu BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE images DROP COLUMN IF EXISTS compute_type;
    ALTER TABLE images DROP COLUMN IF EXISTS artifact_id;
"""


async def _rewind_to_legacy_schema(engine) -> None:
    async with engine.connect() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(PRE_MIGRATION_DDL)


async def _apply_restore_migration(engine) -> None:
    async with engine.connect() as connection:
        raw = await connection.get_raw_connection()
        await raw.driver_connection.execute(
            _migration_up_sql("20260713140000_vm_cache_volume_generation_leases.sql")
        )
        await raw.driver_connection.execute(
            _migration_up_sql("20260713150000_restore_reconciliation.sql")
        )
        await raw.driver_connection.execute(
            _migration_up_sql("20260713160000_transactional_storage_objects.sql")
        )
        await raw.driver_connection.execute(
            _migration_up_sql("20260713170000_secure_replication.sql")
        )
        await raw.driver_connection.execute(_migration_up_sql("20260713220000_storage_hygiene.sql"))
        await raw.driver_connection.execute(
            _migration_up_sql("20260726121000_chutefs_session_rotation_replay.sql")
        )
        await raw.driver_connection.execute(
            _migration_up_sql("20260806120000_api_trust_boundary_hardening.sql")
        )


@pytest_asyncio.fixture
async def pg_session(monkeypatch):
    schema = f"storage_test_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        connect_args={"server_settings": {"search_path": schema}},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    # Rewind the synchronized ORM schema to the pre-migration shape. This exercises the real upgrade
    # path; Base.metadata.create_all above separately proves the clean-schema ORM is internally valid.
    await _rewind_to_legacy_schema(engine)
    await _apply_restore_migration(engine)

    redis = FakeRedis()
    monkeypatch.setattr(settings, "_redis_client", redis)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        await session.execute(
            User.__table__.insert().values(
                user_id=USER_ID,
                username=f"stor{uuid.uuid4().hex[:8]}",
                coldkey="coldkey",
                fingerprint_hash=uuid.uuid4().hex,
                storage_volume_quota_bytes=500 * 1024**3,
                storage_aggregate_quota_bytes=2 * 1024**4,
            )
        )
        session.add(
            MetagraphNode(
                hotkey=MINER,
                netuid=settings.netuid,
                checksum="test",
                coldkey="coldkey",
                node_id=1,
            )
        )
        await session.commit()
        yield session, redis

    await engine.dispose()
    async with admin.begin() as connection:
        await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await admin.dispose()


def _storage_version() -> str:
    return _storage_measurement().version


def _storage_measurement():
    return next(
        config
        for config in settings.tee_measurements
        if (config.name or "").startswith("storage-") and config.tee_type == "sev-snp"
    )


async def _server(
    db: AsyncSession,
    redis: FakeRedis,
    server_id: str,
    host_id: str,
    *,
    disk_free_gb: int = 100,
    live: bool = True,
    attestation_age: timedelta = timedelta(seconds=0),
    attested_identity=None,
) -> Server:
    cert_pem = None
    if attested_identity is None:
        cert_hash = hashlib.sha256(f"cert:{server_id}".encode()).hexdigest()
    else:
        _private_key, certificate = attested_identity
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        cert_hash = get_public_key_hash(certificate)
    server = Server(
        server_id=server_id,
        ip=f"10.0.0.{len(server_id)}",
        miner_hotkey=MINER,
        name=server_id,
        netuid=settings.netuid,
        is_tee=True,
        self_registered=True,
        compute_type="cpu",
        tee_type="sev-snp",
        storage_role=True,
        host_id=host_id,
        external_host=f"{server_id}.example",
        external_ports={"storage": 8445},
        attested_cert=cert_pem,
        attested_cert_pubkey_hash=cert_hash,
        storage_incarnation=str(uuid.uuid4()),
        storage_incarnation_announced_at=NOW,
        disk_total_gb=200,
        disk_free_gb=disk_free_gb,
    )
    verified_at = NOW - attestation_age
    measurement = _storage_measurement()
    config_fingerprint = measurement.config_fingerprint or measurement_config_fingerprint(
        measurement
    )
    trust_set_fingerprint = measurement_trust_set_fingerprint(settings.tee_measurements)
    server.version = measurement.version
    server.measurement_name = measurement.name
    server.measurement_config_fingerprint = config_fingerprint
    server.trust_set_fingerprint = trust_set_fingerprint
    db.add_all(
        [
            server,
            ServerAttestation(
                server_id=server_id,
                quote_data="quote",
                measurement_version=measurement.version,
                measurement_name=measurement.name,
                measurement_config_fingerprint=config_fingerprint,
                trust_set_fingerprint=trust_set_fingerprint,
                created_at=verified_at,
                verified_at=verified_at,
            ),
        ]
    )
    await db.commit()
    if live:
        await redis.setex(f"storage:online:{server_id}", 180, "1")
    return server


async def _commit_failed_attestation(
    db: AsyncSession,
    server_id: str,
    *,
    detail: str = "injected latest attestation failure",
) -> None:
    db.add(
        ServerAttestation(
            server_id=server_id,
            quote_data="failed-quote",
            verification_error=detail,
            created_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()


def _attested_identity(common_name: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def _sign_capability(attested_identity, capability: str) -> str:
    return (
        attested_identity[0]
        .sign(
            service.replication_capability_message(capability),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        .hex()
    )


async def _volume(db: AsyncSession, replication_factor: int) -> StorageVolume:
    volume = StorageVolume(
        user_id=USER_ID,
        name=f"volume-{uuid.uuid4().hex}",
        replication_factor=replication_factor,
        quota_bytes=500 * 1024**3,
        used_bytes=0,
    )
    db.add(volume)
    await db.commit()
    return volume


async def _object(
    db: AsyncSession,
    volume: StorageVolume,
    object_id: str,
    *,
    sha256: str | None = None,
    size_bytes: int = 1024,
    deleted: bool = False,
    object_key: str | None = None,
    generation: str | None = None,
) -> StorageObject:
    values = dict(
        object_id=object_id,
        volume_id=volume.volume_id,
        object_key=object_key or f"key-{object_id}",
        lifecycle_state="pending",
        size_bytes=0,
        projected_size_bytes=size_bytes,
        salt=base64.b64encode(hashlib.sha256(object_id.encode()).digest()).decode(),
        durability_state="pending",
        durable_replica_count=0,
    )
    if generation is not None:
        values["generation"] = generation
    obj = StorageObject(**values)
    db.add(obj)
    await db.flush()
    if sha256:
        obj.size_bytes = size_bytes
        obj.ciphertext_size_bytes = size_bytes
        obj.sha256 = sha256
        obj.committed_at = NOW
        obj.lifecycle_state = "committed"
        obj.durability_state = "irrecoverable"
        await db.flush()
    if deleted:
        obj.lifecycle_state = "tombstoned"
        obj.tombstoned_at = NOW
    await db.commit()
    return obj


async def _placement(
    db: AsyncSession,
    obj: StorageObject,
    server: Server,
    *,
    status: str,
    deadline: datetime | None = None,
) -> ReplicaPlacement:
    now = datetime.now(timezone.utc)
    placement = ReplicaPlacement(
        object_id=obj.object_id,
        server_id=server.server_id,
        status="pending",
        storage_incarnation=server.storage_incarnation,
        target_cert_pubkey_hash=server.attested_cert_pubkey_hash,
        pending_since=now - timedelta(minutes=1),
        pending_deadline=deadline or now + timedelta(hours=1),
        attempt_count=1,
    )
    db.add(placement)
    await db.flush()
    if status == "present":
        placement.proof_sha256 = obj.sha256
        placement.proof_size_bytes = obj.ciphertext_size_bytes
        placement.proof_plaintext_size_bytes = obj.size_bytes
        placement.proof_plaintext_sha256 = hashlib.sha256(
            f"plaintext:{obj.object_id}".encode()
        ).hexdigest()
        placement.proof_mode = "direct_upload"
        placement.proof_at = obj.committed_at or now
        placement.confirmed_at = now
        placement.status = "present"
    elif status == "evicted":
        placement.status = "evicted"
    await db.commit()
    return placement


async def test_one_time_legacy_adoption_restores_only_intact_assigned_bytes(
    monkeypatch,
):
    schema = f"storage_upgrade_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    engine = None
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await _rewind_to_legacy_schema(engine)

        legacy_identity = _attested_identity("legacy-storage")
        legacy_cert = legacy_identity[1].public_bytes(serialization.Encoding.PEM).decode()
        cert_hash = get_public_key_hash(legacy_identity[1])
        volume_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    """
                    INSERT INTO users (user_id, coldkey, username, fingerprint_hash)
                    VALUES (:user_id, 'coldkey', :username, :fingerprint)
                    """
                ),
                {
                    "user_id": USER_ID,
                    "username": f"up{uuid.uuid4().hex[:8]}",
                    "fingerprint": uuid.uuid4().hex,
                },
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO metagraph_nodes
                        (hotkey, netuid, checksum, coldkey, node_id)
                    VALUES (:hotkey, :netuid, 'test', 'coldkey', 1)
                    """
                ),
                {"hotkey": MINER, "netuid": settings.netuid},
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO servers (
                        server_id, ip, miner_hotkey, name, netuid, is_tee,
                        self_registered, compute_type, tee_type, storage_role,
                        host_id, external_host, external_ports,
                        attested_cert, attested_cert_pubkey_hash,
                        disk_total_gb, disk_free_gb
                    ) VALUES (
                        'legacy-storage', '10.0.0.9', :hotkey, 'legacy-storage',
                        :netuid, true, true, 'cpu', 'sev-snp', true,
                        'legacy-host', 'legacy.example', '{"storage": 8445}'::jsonb,
                        :attested_cert, :cert_hash, 200, 150
                    )
                    """
                ),
                {
                    "hotkey": MINER,
                    "netuid": settings.netuid,
                    "attested_cert": legacy_cert,
                    "cert_hash": cert_hash,
                },
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO server_attestations (
                        attestation_id, server_id, quote_data, measurement_version,
                        created_at, verified_at
                    ) VALUES (
                        :attestation_id, 'legacy-storage', 'quote', :version, :now, :now
                    )
                    """
                ),
                {
                    "attestation_id": str(uuid.uuid4()),
                    "version": _storage_version(),
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO storage_volumes (
                        volume_id, user_id, name, replication_factor,
                        quota_bytes, used_bytes, deleted
                    ) VALUES (
                        :volume_id, :user_id, 'legacy-volume', 1,
                        10737418240, 8192, false
                    )
                    """
                ),
                {"volume_id": volume_id, "user_id": USER_ID},
            )
            for object_id, object_key, digest in (
                ("legacy-good", "good", "a" * 64),
                ("legacy-bad", "bad", "b" * 64),
                ("legacy-wiped", "wiped", "c" * 64),
            ):
                await connection.execute(
                    text(
                        """
                        INSERT INTO storage_objects (
                            object_id, volume_id, object_key, size_bytes,
                            sha256, deleted
                        ) VALUES (
                            :object_id, :volume_id, :object_key, 4096,
                            :digest, false
                        )
                        """
                    ),
                    {
                        "object_id": object_id,
                        "volume_id": volume_id,
                        "object_key": object_key,
                        "digest": digest,
                    },
                )
                await connection.execute(
                    text(
                        """
                        INSERT INTO replica_placement (
                            placement_id, object_id, server_id, status, confirmed_at
                        ) VALUES (
                            :placement_id, :object_id, 'legacy-storage', 'present', :now
                        )
                        """
                    ),
                    {
                        "placement_id": f"placement-{object_id}",
                        "object_id": object_id,
                        "now": now,
                    },
                )

        await _apply_restore_migration(engine)
        redis = FakeRedis()
        await redis.setex("storage:online:legacy-storage", 180, "1")
        monkeypatch.setattr(settings, "_redis_client", redis)
        session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as db:
            good = await db.get(ReplicaPlacement, "placement-legacy-good")
            bad = await db.get(ReplicaPlacement, "placement-legacy-bad")
            wiped = await db.get(ReplicaPlacement, "placement-legacy-wiped")
            good_obj = await db.get(StorageObject, "legacy-good")
            bad_obj = await db.get(StorageObject, "legacy-bad")
            wiped_obj = await db.get(StorageObject, "legacy-wiped")
            legacy_server = await db.get(Server, "legacy-storage")
            volume = await db.get(StorageVolume, volume_id)
            assert good.status == bad.status == wiped.status == "evicted"
            assert good.storage_incarnation is None
            assert good.target_cert_pubkey_hash is None
            assert good.last_error == "secure_replication_requires_new_receipt"
            assert good_obj.durability_state == "irrecoverable"

            incarnation = str(uuid.uuid4())
            legacy_server.storage_incarnation = incarnation
            legacy_server.storage_incarnation_announced_at = datetime.now(timezone.utc)
            measurement = _storage_measurement()
            config_fingerprint = measurement.config_fingerprint or measurement_config_fingerprint(
                measurement
            )
            trust_set_fingerprint = measurement_trust_set_fingerprint(settings.tee_measurements)
            legacy_server.version = measurement.version
            legacy_server.measurement_name = measurement.name
            legacy_server.measurement_config_fingerprint = config_fingerprint
            legacy_server.trust_set_fingerprint = trust_set_fingerprint
            freshly_verified_at = datetime.now(timezone.utc)
            db.add(
                ServerAttestation(
                    server_id=legacy_server.server_id,
                    quote_data="fresh-upgrade-quote",
                    measurement_version=measurement.version,
                    measurement_name=measurement.name,
                    measurement_config_fingerprint=config_fingerprint,
                    trust_set_fingerprint=trust_set_fingerprint,
                    created_at=freshly_verified_at,
                    verified_at=freshly_verified_at,
                )
            )
            await db.commit()
            other_identity = _attested_identity("legacy-other")
            other = await _server(
                db,
                redis,
                "legacy-other",
                "legacy-other-host",
                attested_identity=other_identity,
            )

            assert await service.adopt_legacy_replicas(
                db,
                other,
                other.storage_incarnation,
                [
                    {
                        "object_id": "legacy-good",
                        "result": "verified",
                        "ciphertext_sha256": "a" * 64,
                        "ciphertext_size_bytes": 4096,
                        "plaintext_size_bytes": 1024,
                        "plaintext_sha256": "d" * 64,
                    }
                ],
            ) == [
                {
                    "object_id": "legacy-good",
                    "status": "quarantined",
                    "detail": "assignment_not_tracked",
                }
            ]
            await db.refresh(good_obj)
            assert good_obj.ciphertext_size_bytes is None

            with pytest.raises(HTTPException) as wrong_incarnation:
                await service.adopt_legacy_replicas(
                    db,
                    legacy_server,
                    str(uuid.uuid4()),
                    [],
                )
            assert wrong_incarnation.value.status_code == 403
            await db.rollback()
            await db.refresh(legacy_server)
            await db.refresh(other)
            await db.refresh(volume)

            original_refresh_durability = service._refresh_object_durability
            fail_good_once = True

            async def intermittently_fail_good_adoption(db, obj, **kwargs):
                nonlocal fail_good_once
                if obj.object_id == "legacy-good" and fail_good_once:
                    fail_good_once = False
                    raise RuntimeError("injected legacy adoption failure")
                return await original_refresh_durability(db, obj, **kwargs)

            monkeypatch.setattr(
                service,
                "_refresh_object_durability",
                intermittently_fail_good_adoption,
            )
            good_receipt = {
                "object_id": "legacy-good",
                "result": "verified",
                "ciphertext_sha256": "a" * 64,
                "ciphertext_size_bytes": 4096,
                "plaintext_size_bytes": 1024,
                "plaintext_sha256": "d" * 64,
            }
            outcomes = await service.adopt_legacy_replicas(
                db,
                legacy_server,
                incarnation,
                [
                    {
                        "object_id": "legacy-bad",
                        "result": "verified",
                        "ciphertext_sha256": "f" * 64,
                        "ciphertext_size_bytes": 4096,
                        "plaintext_size_bytes": 2048,
                        "plaintext_sha256": "e" * 64,
                    },
                    good_receipt,
                ],
            )
            await db.refresh(good)
            await db.refresh(good_obj)
            assert outcomes == [
                {
                    "object_id": "legacy-bad",
                    "status": "quarantined",
                    "idempotent": False,
                    "detail": "evidence_mismatch",
                },
                {
                    "object_id": "legacy-good",
                    "status": "retry",
                    "detail": "transaction_failed:RuntimeError",
                },
            ]
            assert good.status == "evicted"
            assert good_obj.ciphertext_size_bytes is None

            assert await service.adopt_legacy_replicas(
                db, legacy_server, incarnation, [good_receipt]
            ) == [
                {
                    "object_id": "legacy-good",
                    "status": "accepted",
                    "idempotent": False,
                }
            ]
            await db.refresh(good)
            await db.refresh(bad)
            await db.refresh(wiped)
            await db.refresh(good_obj)
            await db.refresh(bad_obj)
            await db.refresh(wiped_obj)
            assert bad.status == "evicted"
            assert wiped.status == "evicted"
            assert good.status == "present"
            assert good.storage_incarnation == incarnation
            assert good.target_cert_pubkey_hash == cert_hash
            assert good.proof_sha256 == "a" * 64
            assert good.proof_size_bytes == 4096
            assert good.proof_plaintext_size_bytes == 1024
            assert good.proof_plaintext_sha256 == "d" * 64
            assert good.proof_mode == "legacy_adoption"
            assert good.proof_capability_id is None
            assert good.legacy_adoption_started_at == good.proof_at
            assert good_obj.lifecycle_state == "committed"
            assert good_obj.ciphertext_size_bytes == 4096
            assert good_obj.size_bytes == 1024
            assert good_obj.projected_size_bytes == 1024
            assert good_obj.plaintext_sha256 == "d" * 64
            assert good_obj.legacy_adopted_at == good.proof_at
            assert good_obj.legacy_adoption_placement_id == good.placement_id
            assert good_obj.legacy_adoption_server_id == legacy_server.server_id
            assert good_obj.legacy_adoption_cert_pubkey_hash == cert_hash
            assert good_obj.legacy_adoption_storage_incarnation == incarnation
            assert good_obj.durable_replica_count == 1
            assert good_obj.durability_state == "healthy"
            await db.refresh(volume)
            assert volume.used_bytes == 9216
            assert bad_obj.ciphertext_size_bytes is None
            assert bad_obj.durability_state == "irrecoverable"
            assert wiped_obj.ciphertext_size_bytes is None
            assert wiped_obj.durability_state == "irrecoverable"

            corrupt_report = {
                "object_id": "legacy-bad",
                "result": "corrupt",
                "ciphertext_sha256": "b" * 64,
                "ciphertext_size_bytes": 4096,
                "plaintext_size_bytes": None,
                "plaintext_sha256": None,
                "error": "authenticated_decrypt_failed",
            }
            assert await service.adopt_legacy_replicas(
                db, legacy_server, incarnation, [corrupt_report]
            ) == [
                {
                    "object_id": "legacy-bad",
                    "status": "quarantined",
                    "idempotent": False,
                    "detail": "authenticated_decrypt_failed",
                }
            ]
            assert await service.adopt_legacy_replicas(
                db, legacy_server, incarnation, [corrupt_report]
            ) == [
                {
                    "object_id": "legacy-bad",
                    "status": "quarantined",
                    "idempotent": True,
                    "detail": "authenticated_decrypt_failed",
                }
            ]
            await db.refresh(bad)
            assert bad.last_error == "legacy_adoption_quarantined:authenticated_decrypt_failed"

            located, peers, count = await service.locate_object(db, volume, "good")
            assert located.object_id == good_obj.object_id
            assert count == 1
            assert [peer.server_id for peer in peers] == [legacy_server.server_id]

            # Once the object has an exact size, neither repeated adoption nor the ordinary
            # capability-free inventory endpoint may mutate or resurrect a receipt.
            assert await service.adopt_legacy_replicas(
                db,
                legacy_server,
                incarnation,
                [
                    {
                        "object_id": "legacy-good",
                        "result": "verified",
                        "ciphertext_sha256": "a" * 64,
                        "ciphertext_size_bytes": 4096,
                        "plaintext_size_bytes": 1024,
                        "plaintext_sha256": "d" * 64,
                    }
                ],
            ) == [
                {
                    "object_id": "legacy-good",
                    "status": "accepted",
                    "idempotent": True,
                }
            ]
            assert (
                await service.announce_replicas(
                    db,
                    MINER,
                    legacy_server.server_id,
                    legacy_server.server_id,
                    incarnation,
                    [
                        {
                            "object_id": "legacy-good",
                            "status": "stored",
                            "ciphertext_sha256": "a" * 64,
                            "ciphertext_size_bytes": 4096,
                            "plaintext_size_bytes": 1024,
                            "plaintext_sha256": "d" * 64,
                        }
                    ],
                )
                == 0
            )

            target = await _placement(db, good_obj, other, status="pending")
            target.status = "evicted"
            target.last_error = "legacy_adoption_exploit_setup"
            await db.commit()
            exploit_started_at = datetime.now(timezone.utc)
            target.status = "pending"
            target.legacy_adoption_started_at = exploit_started_at
            target.pending_since = exploit_started_at
            target.pending_deadline = exploit_started_at + timedelta(hours=1)
            target.attempt_count += 1
            target.last_attempt_at = exploit_started_at
            target.last_error = None
            await db.flush()
            target.proof_sha256 = "a" * 64
            target.proof_size_bytes = 4096
            target.proof_plaintext_size_bytes = 1024
            target.proof_plaintext_sha256 = "d" * 64
            target.proof_mode = "legacy_adoption"
            target.proof_at = exploit_started_at
            with pytest.raises(Exception, match="legacy adoption proof is not eligible"):
                await db.flush()
            await db.rollback()
            await db.refresh(target)
            await db.refresh(other)
            await db.refresh(legacy_server)
            await db.refresh(good_obj)
            await service._upsert_pending_placement(db, good_obj, other)
            await db.commit()
            await db.refresh(target)
            lease = await service.issue_replication_capability(
                db,
                legacy_server,
                good_obj.object_id,
                other.server_id,
                "a" * 64,
                4096,
            )
            assert lease["target_placement_attempt"] == target.attempt_count
            signature = _sign_capability(legacy_identity, lease["capability"])
            await service.consume_replication_capability(db, other, lease["capability"], signature)
            await service.complete_replication_capability(
                db,
                other,
                lease["capability"],
                "a" * 64,
                4096,
            )
            await db.refresh(target)
            assert target.status == "present"
            assert target.proof_mode == "replication_capability"

            good_obj.ciphertext_size_bytes = 4097
            with pytest.raises(
                Exception,
                match="committed storage object generation metadata is immutable",
            ):
                await db.flush()
            await db.rollback()
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def test_legacy_adoption_revalidates_server_identity_after_rotation_lock(
    pg_session, monkeypatch
):
    db, redis = pg_session
    server = await _server(db, redis, "legacy-race-holder", "legacy-race-host")
    server_id = server.server_id
    old_incarnation = server.storage_incarnation
    old_cert_hash = server.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    object_id = "legacy-race-object"
    placement_id = "legacy-race-placement"
    # This row represents a production object created before the enforced generation trigger.
    # Suppress triggers only while loading the fixture, then restore enforcement before the race.
    await db.execute(text("SET LOCAL session_replication_role = replica"))
    await db.execute(
        StorageObject.__table__.insert().values(
            object_id=object_id,
            volume_id=volume.volume_id,
            object_key="legacy-race-key",
            lifecycle_state="committed",
            size_bytes=32,
            projected_size_bytes=32,
            ciphertext_size_bytes=None,
            sha256="7" * 64,
            salt=base64.b64encode(hashlib.sha256(object_id.encode()).digest()).decode(),
            durability_state="irrecoverable",
            durable_replica_count=0,
            committed_at=NOW,
        )
    )
    await db.execute(
        ReplicaPlacement.__table__.insert().values(
            placement_id=placement_id,
            object_id=object_id,
            server_id=server_id,
            status="evicted",
            storage_incarnation=None,
            target_cert_pubkey_hash=None,
            attempt_count=0,
            last_error="legacy_adoption_required",
        )
    )
    await db.execute(text("SET LOCAL session_replication_role = origin"))
    await db.commit()
    submission = {
        "object_id": object_id,
        "result": "verified",
        "ciphertext_sha256": "7" * 64,
        "ciphertext_size_bytes": 48,
        "plaintext_size_bytes": 32,
        "plaintext_sha256": "8" * 64,
    }

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as locker, factory() as adopter:
        locked_revalidation_entered = asyncio.Event()
        original_require_server = service._require_legacy_adoption_server

        async def observed_require_server(*args, **kwargs):
            if kwargs.get("lock") is True:
                locked_revalidation_entered.set()
            return await original_require_server(*args, **kwargs)

        monkeypatch.setattr(
            service,
            "_require_legacy_adoption_server",
            observed_require_server,
        )
        # Match production: require_attested_caller and the service share this identity map.
        adopter_caller = await adopter.get(Server, server_id)
        rotating_server = (
            await locker.execute(
                select(Server).where(Server.server_id == server_id).with_for_update()
            )
        ).scalar_one()
        rotating_server.attested_cert_pubkey_hash = "9" * 64
        await locker.flush()

        adoption = asyncio.create_task(
            service.adopt_legacy_replicas(
                adopter,
                adopter_caller,
                old_incarnation,
                [submission],
            )
        )
        try:
            await asyncio.wait_for(locked_revalidation_entered.wait(), timeout=5)
            assert not adoption.done()
            await locker.commit()
            with pytest.raises(HTTPException) as stale_identity:
                await asyncio.wait_for(adoption, timeout=5)
            assert stale_identity.value.status_code == 403
        finally:
            if locker.in_transaction():
                await locker.rollback()
            if not adoption.done():
                adoption.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await adoption

    db.expire_all()
    obj = await db.get(StorageObject, object_id)
    placement = await db.get(ReplicaPlacement, placement_id)
    assert obj.ciphertext_size_bytes is None
    assert obj.legacy_adopted_at is None
    assert obj.legacy_adoption_placement_id is None
    assert obj.legacy_adoption_server_id is None
    assert obj.legacy_adoption_cert_pubkey_hash is None
    assert obj.legacy_adoption_storage_incarnation is None
    assert placement.status == "evicted"
    assert placement.proof_at is None
    assert placement.proof_mode is None
    assert placement.storage_incarnation is None
    assert placement.target_cert_pubkey_hash is None
    assert old_cert_hash != "9" * 64


async def test_secure_replication_migration_down_up_round_trip(pg_session):
    db, redis = pg_session
    legacy_server = await _server(db, redis, "migration-storage", "migration-host")
    legacy_volume = await _volume(db, 1)
    legacy_object = await _object(
        db,
        legacy_volume,
        "migration-object",
        sha256="a" * 64,
        generation="migration-object",
    )
    legacy_placement = await _placement(db, legacy_object, legacy_server, status="present")
    legacy_object_id = legacy_object.object_id
    legacy_placement_id = legacy_placement.placement_id
    connection = await db.connection()
    raw = await connection.get_raw_connection()
    driver = raw.driver_connection

    await driver.execute(
        _migration_down_sql("20260806120000_api_trust_boundary_hardening.sql")
    )
    await driver.execute(
        _migration_down_sql("20260726121000_chutefs_session_rotation_replay.sql")
    )
    await driver.execute(_migration_down_sql("20260713220000_storage_hygiene.sql"))
    await driver.execute(_migration_down_sql("20260713170000_secure_replication.sql"))
    assert not await driver.fetchval(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'storage_replication_capabilities'
        )
        """
    )
    assert not await driver.fetchval(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'storage_objects'
              AND column_name = 'ciphertext_size_bytes'
        )
        """
    )

    up = _migration_up_sql("20260713170000_secure_replication.sql")
    await driver.execute(up)
    await driver.execute(up)
    hygiene_up = _migration_up_sql("20260713220000_storage_hygiene.sql")
    await driver.execute(hygiene_up)
    await driver.execute(hygiene_up)
    await driver.execute(
        _migration_up_sql("20260726121000_chutefs_session_rotation_replay.sql")
    )
    await driver.execute(
        _migration_up_sql("20260806120000_api_trust_boundary_hardening.sql")
    )
    active_inventory_index = await driver.fetchrow(
        """
        SELECT pg_index.indisunique, pg_get_expr(pg_index.indpred, pg_index.indrelid) AS predicate
        FROM pg_index
        JOIN pg_class ON pg_class.oid = pg_index.indexrelid
        JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
        WHERE pg_class.relname = 'uq_storage_model_inventory_active_identity'
          AND pg_namespace.nspname = current_schema()
        """
    )
    assert active_inventory_index["indisunique"]
    assert "applying" in active_inventory_index["predicate"]
    assert "omitting" in active_inventory_index["predicate"]
    assert await driver.fetchval(
        """
        SELECT count(*) = 3
        FROM pg_class
        JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
        WHERE relname IN (
            'idx_storage_model_inventory_waiting',
            'idx_servers_model_inventory_fresh',
            'idx_content_holdings_snapshot_omission'
        )
          AND pg_namespace.nspname = current_schema()
        """
    )
    assert await driver.fetchval(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'storage_replication_capabilities'
        )
        """
    )
    assert (
        await driver.fetchval(
            """
            SELECT status
            FROM replica_placement
            WHERE placement_id = $1
            """,
            legacy_placement_id,
        )
        == "evicted"
    )
    assert not await driver.fetchval(
        """
        SELECT proof_sha256 IS NOT NULL
            OR proof_size_bytes IS NOT NULL
            OR proof_capability_id IS NOT NULL
            OR proof_mode IS NOT NULL
            OR legacy_adoption_started_at IS NOT NULL
            OR proof_at IS NOT NULL
        FROM replica_placement
        WHERE placement_id = $1
        """,
        legacy_placement_id,
    )
    assert not await driver.fetchval(
        """
        SELECT legacy_adopted_at IS NOT NULL
            OR legacy_adoption_placement_id IS NOT NULL
            OR legacy_adoption_server_id IS NOT NULL
            OR legacy_adoption_cert_pubkey_hash IS NOT NULL
            OR legacy_adoption_storage_incarnation IS NOT NULL
        FROM storage_objects
        WHERE object_id = $1
        """,
        legacy_object_id,
    )
    assert (
        await driver.fetchval(
            """
            SELECT durability_state
            FROM storage_objects
            WHERE object_id = $1
            """,
            legacy_object_id,
        )
        == "irrecoverable"
    )
    await db.commit()


async def test_orm_bootstrap_cannot_skip_secure_replication_quarantine():
    schema = f"storage_clean_chain_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    engine = None
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as db:
            await db.execute(
                User.__table__.insert().values(
                    user_id=USER_ID,
                    username=f"clean{uuid.uuid4().hex[:8]}",
                    coldkey="coldkey",
                    fingerprint_hash=uuid.uuid4().hex,
                )
            )
            db.add(
                MetagraphNode(
                    hotkey=MINER,
                    netuid=settings.netuid,
                    checksum="test",
                    coldkey="coldkey",
                    node_id=1,
                )
            )
            server = Server(
                server_id="clean-chain-server",
                ip="10.0.0.20",
                miner_hotkey=MINER,
                name="clean-chain-server",
                netuid=settings.netuid,
                is_tee=True,
                self_registered=True,
                compute_type="cpu",
                tee_type="sev-snp",
                storage_role=True,
                host_id="clean-chain-host",
                attested_cert_pubkey_hash="a" * 64,
            )
            volume = StorageVolume(
                volume_id=str(uuid.uuid4()),
                user_id=USER_ID,
                name="clean-chain-volume",
                replication_factor=1,
            )
            obj = StorageObject(
                object_id="clean-chain-object",
                volume_id=volume.volume_id,
                object_key="legacy",
                lifecycle_state="committed",
                size_bytes=7,
                projected_size_bytes=7,
                ciphertext_size_bytes=None,
                sha256="b" * 64,
                salt=base64.b64encode(b"s" * 32).decode(),
                committed_at=NOW,
                durability_state="healthy",
                durable_replica_count=1,
            )
            placement = ReplicaPlacement(
                placement_id="clean-chain-placement",
                object_id=obj.object_id,
                server_id=server.server_id,
                status="present",
                confirmed_at=NOW,
                proof_sha256="b" * 64,
                proof_at=NOW,
            )
            db.add_all([server, volume, obj, placement])
            await db.commit()

        async with engine.connect() as connection:
            raw = await connection.get_raw_connection()
            driver = raw.driver_connection
            for migration_name in (
                "20260713140000_vm_cache_volume_generation_leases.sql",
                "20260713150000_restore_reconciliation.sql",
                "20260713160000_transactional_storage_objects.sql",
            ):
                await driver.execute(_migration_up_sql(migration_name))
            await driver.execute(_migration_up_sql("20260713170000_secure_replication.sql"))
            assert (
                await driver.fetchval(
                    """
                    SELECT status
                    FROM replica_placement
                    WHERE placement_id = 'clean-chain-placement'
                    """
                )
                == "evicted"
            )
            assert (
                await driver.fetchval(
                    """
                    SELECT last_error
                    FROM replica_placement
                    WHERE placement_id = 'clean-chain-placement'
                    """
                )
                == "secure_replication_requires_new_receipt"
            )
            await driver.execute(_migration_up_sql("20260713220000_storage_hygiene.sql"))
            assert await driver.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgname = 'trg_storage_hygiene_object'
                      AND tgrelid = 'storage_objects'::regclass
                      AND NOT tgisinternal
                )
                """
            )
            assert await driver.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'replica_placement'::regclass
                      AND conname = 'uq_replica_object_server'
                )
                """
            )
            assert await driver.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'content_holdings'::regclass
                      AND conname = 'uq_content_holding'
                )
                """
            )
            assert not await driver.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE schemaname = current_schema()
                      AND indexname = 'idx_servers_attested_pubkey'
                )
                """
            )
            assert await driver.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE schemaname = current_schema()
                      AND indexname = 'uq_servers_attested_pubkey'
                )
                """
            )
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def test_image_compute_type_migration_rekeys_legacy_rows():
    schema = f"image_id_cutover_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    engine = None
    username = "Alice"
    user_id = f"image-cutover-{uuid.uuid4()}"
    legacy_ids = {
        "gpu-model": str(uuid.uuid5(uuid.NAMESPACE_OID, "alice/gpu-model:v1")),
        "cpu-model": str(uuid.uuid5(uuid.NAMESPACE_OID, "alice/cpu-model:v1")),
    }
    canonical_ids = {
        "gpu-model": image_id_for(username, "gpu-model", "v1", "gpu"),
        "cpu-model": image_id_for(username, "cpu-model", "v1", "cpu"),
    }
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            raw = await connection.get_raw_connection()
            await raw.driver_connection.execute(FORWARD_MIGRATION_HAZARD_DDL)
            await connection.execute(
                text(
                    """
                    INSERT INTO users (user_id, username, coldkey, fingerprint_hash)
                    VALUES (:user_id, :username, 'coldkey', :fingerprint_hash)
                    """
                ),
                {
                    "user_id": user_id,
                    "username": username,
                    "fingerprint_hash": uuid.uuid4().hex,
                },
            )
            for index, (name, legacy_id) in enumerate(legacy_ids.items()):
                await connection.execute(
                    text(
                        """
                        INSERT INTO images (
                            image_id, user_id, name, tag, public, status, patch_version, cpu
                        )
                        VALUES (
                            :image_id, :user_id, :name, 'v1', false,
                            'built and pushed', 'initial', :cpu
                        )
                        """
                    ),
                    {
                        "image_id": legacy_id,
                        "user_id": user_id,
                        "name": name,
                        "cpu": name == "cpu-model",
                    },
                )
                await connection.execute(
                    text(
                        """
                        INSERT INTO image_history (
                            entry_id, image_id, user_id, name, tag, public, status
                        )
                        VALUES (
                            :entry_id, :image_id, :user_id, :name, 'v1', false,
                            'built and pushed'
                        )
                        """
                    ),
                    {
                        "entry_id": str(uuid.uuid4()),
                        "image_id": legacy_id,
                        "user_id": user_id,
                        "name": name,
                    },
                )
                chute_id = f"cutover-chute-{index}"
                await connection.execute(
                    text(
                        """
                        INSERT INTO chutes (
                            chute_id, user_id, name, image_id, cords, node_selector,
                            code, filename, ref_str, public
                        )
                        VALUES (
                            :chute_id, :user_id, :name, :image_id, '[]'::jsonb,
                            CAST(:node_selector AS jsonb), 'pass', 'app.py', 'app:chute', false
                        )
                        """
                    ),
                    {
                        "chute_id": chute_id,
                        "user_id": user_id,
                        "name": f"{name}-chute",
                        "image_id": legacy_id,
                        "node_selector": (
                            '{"compute_type":"cpu","gpu_count":0}'
                            if name == "cpu-model"
                            else '{"compute_type":"gpu","gpu_count":1}'
                        ),
                    },
                )
                await connection.execute(
                    text(
                        """
                        INSERT INTO chute_history (
                            entry_id, chute_id, user_id, version, name, image_id,
                            cords, node_selector, code, filename, ref_str
                        )
                        VALUES (
                            :entry_id, :chute_id, :user_id, 'v1', :name, :image_id,
                            '[]'::jsonb, '{}'::jsonb, 'pass', 'app.py', 'app:chute'
                        )
                        """
                    ),
                    {
                        "entry_id": str(uuid.uuid4()),
                        "chute_id": chute_id,
                        "user_id": user_id,
                        "name": f"{name}-chute",
                        "image_id": legacy_id,
                    },
                )
            await connection.execute(
                text(
                    """
                    CREATE TABLE partitioned_invocations (
                        invocation_id TEXT PRIMARY KEY,
                        image_id TEXT NOT NULL
                    )
                    """
                )
            )
            for index, legacy_id in enumerate(legacy_ids.values()):
                await connection.execute(
                    text(
                        """
                        INSERT INTO partitioned_invocations (invocation_id, image_id)
                        VALUES (:invocation_id, :image_id)
                        """
                    ),
                    {"invocation_id": f"inv-{index}", "image_id": legacy_id},
                )

            raw = await connection.get_raw_connection()
            await raw.driver_connection.execute(
                _migration_up_sql("20260715121000_image_compute_type.sql")
            )

        async with engine.connect() as connection:
            image_rows = {
                row.name: row
                for row in (
                    await connection.execute(
                        text(
                            """
                            SELECT image_id, artifact_id, compute_type, name
                            FROM images
                            """
                        )
                    )
                )
            }
            assert set(image_rows) == set(legacy_ids)
            for name, row in image_rows.items():
                assert row.image_id == canonical_ids[name]
                assert row.artifact_id == legacy_ids[name]
                assert row.compute_type == ("cpu" if name == "cpu-model" else "gpu")

            for table in (
                "chutes",
                "image_history",
                "chute_history",
                "partitioned_invocations",
            ):
                migrated = set(
                    (await connection.execute(text(f"SELECT image_id FROM {table}"))).scalars()
                )
                assert migrated == set(canonical_ids.values())

            assert (
                await connection.execute(
                    text(
                        """
                        SELECT update_rule
                        FROM information_schema.referential_constraints
                        WHERE constraint_schema = current_schema()
                          AND constraint_name = (
                              SELECT constraint_name
                              FROM information_schema.key_column_usage
                              WHERE table_schema = current_schema()
                                AND table_name = 'chutes'
                                AND column_name = 'image_id'
                          )
                        """
                    )
                )
            ).scalar_one() == "CASCADE"

        async with engine.begin() as connection:
            raw = await connection.get_raw_connection()
            await raw.driver_connection.execute(
                _migration_down_sql("20260715121000_image_compute_type.sql")
            )
        async with engine.connect() as connection:
            assert set(
                (await connection.execute(text("SELECT image_id FROM images"))).scalars()
            ) == set(legacy_ids.values())
            columns = set(
                (
                    await connection.execute(
                        text(
                            """
                            SELECT column_name
                            FROM information_schema.columns
                            WHERE table_schema = current_schema()
                              AND table_name = 'images'
                            """
                        )
                    )
                ).scalars()
            )
            assert "cpu" in columns
            assert "compute_type" not in columns
            assert "artifact_id" not in columns
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


@pytest.mark.skipif(not DBMATE_BIN, reason="DBMATE_BIN is required for migration-runner test")
@pytest.mark.parametrize("legacy_upgrade", [False, True])
async def test_dbmate_applies_enforced_storage_chain(legacy_upgrade):
    schema = f"storage_dbmate_chain_{int(legacy_upgrade)}_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    engine = None
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        if legacy_upgrade:
            await _rewind_to_legacy_schema(engine)
            async with engine.connect() as connection:
                raw = await connection.get_raw_connection()
                await raw.driver_connection.execute(FORWARD_MIGRATION_HAZARD_DDL)
        async with engine.connect() as connection:
            await database_migrations.record_historical_migration_baseline(connection)

        sync_url = TEST_DATABASE_URL.replace("+asyncpg", "")
        separator = "&" if "?" in sync_url else "?"
        sync_url = f"{sync_url}{separator}search_path={schema}&sslmode=disable"
        process = await asyncio.create_subprocess_exec(
            DBMATE_BIN,
            "--url",
            sync_url,
            "--migrations-dir",
            str(Path(__file__).resolve().parents[2] / "api/migrations"),
            "--migrations-table",
            "schema_migrations",
            "--no-dump-schema",
            "migrate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )
        async with engine.connect() as connection:
            versions = set(
                (
                    await connection.execute(
                        text("SELECT version FROM schema_migrations"),
                    )
                ).scalars()
            )
            expected_versions = {
                path.name.split("_", 1)[0]
                for path in (Path(__file__).resolve().parents[2] / "api/migrations").glob("*.sql")
            }
            assert versions == expected_versions
            server_health_shape = (
                await connection.execute(
                    text(
                        """
                        SELECT
                            EXISTS (
                                SELECT 1 FROM information_schema.columns
                                WHERE table_schema = current_schema()
                                  AND table_name = 'servers'
                                  AND column_name = 'last_health_at'
                                  AND data_type = 'timestamp with time zone'
                            ),
                            EXISTS (
                                SELECT 1 FROM pg_indexes
                                WHERE schemaname = current_schema()
                                  AND indexname = 'idx_servers_last_health'
                            )
                        """
                    )
                )
            ).one()
            assert tuple(server_health_shape) == (True, True)
            image_compute_shape = (
                await connection.execute(
                    text(
                        """
                        SELECT
                            EXISTS (
                                SELECT 1 FROM information_schema.columns
                                WHERE table_schema = current_schema()
                                  AND table_name = 'images'
                                  AND column_name = 'compute_type'
                                  AND is_nullable = 'NO'
                            ),
                            EXISTS (
                                SELECT 1 FROM information_schema.columns
                                WHERE table_schema = current_schema()
                                  AND table_name = 'images'
                                  AND column_name = 'artifact_id'
                                  AND is_nullable = 'NO'
                            ),
                            NOT EXISTS (
                                SELECT 1 FROM information_schema.columns
                                WHERE table_schema = current_schema()
                                  AND table_name = 'images'
                                  AND column_name = 'cpu'
                            )
                        """
                    )
                )
            ).one()
            assert tuple(image_compute_shape) == (True, True, True)
            assert (
                await connection.execute(
                    text(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM pg_trigger
                            WHERE tgname = 'trg_storage_hygiene_object'
                              AND tgrelid = 'storage_objects'::regclass
                              AND NOT tgisinternal
                        )
                        """
                    )
                )
            ).scalar_one()
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()


async def test_erasure_finalization_has_matching_composite_indexes(pg_session):
    db, _redis = pg_session
    rows = (
        await db.execute(
            text(
                """
                SELECT indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND indexname = ANY(:index_names)
                """
            ),
            {
                "index_names": [
                    "idx_storage_objects_terminal_erase",
                    "idx_storage_objects_expected_predecessor",
                    "idx_storage_objects_volume",
                    "idx_replica_placement_object",
                    "idx_storage_erase_object",
                    "idx_storage_erase_terminal_unpurged",
                    "idx_storage_erase_volume_finalize",
                    "idx_storage_volumes_deleted_work",
                ]
            },
        )
    ).all()
    definitions = {name: " ".join(definition.lower().split()) for name, definition in rows}
    assert set(definitions) == {
        "idx_storage_objects_terminal_erase",
        "idx_storage_objects_expected_predecessor",
        "idx_storage_objects_volume",
        "idx_replica_placement_object",
        "idx_storage_erase_object",
        "idx_storage_erase_terminal_unpurged",
        "idx_storage_erase_volume_finalize",
        "idx_storage_volumes_deleted_work",
    }
    assert "(object_id, placement_id)" in definitions["idx_replica_placement_object"]
    assert "(volume_id, object_id)" in definitions["idx_storage_objects_volume"]
    assert "(object_id, task_id)" in definitions["idx_storage_erase_terminal_unpurged"]
    assert "metadata_purged_at is null" in definitions["idx_storage_erase_terminal_unpurged"]
    assert (
        "(volume_id, state, reason, metadata_purged_at)"
        in definitions["idx_storage_erase_volume_finalize"]
    )

    await db.execute(text("SET LOCAL enable_seqscan = off"))
    plan = "\n".join(
        (
            await db.execute(
                text(
                    """
                    EXPLAIN (COSTS OFF)
                    SELECT task_id
                    FROM storage_erase_tasks
                    WHERE object_id = 'generation'
                      AND state IN ('erased', 'retired')
                      AND metadata_purged_at IS NULL
                    ORDER BY task_id
                    LIMIT 10
                    """
                )
            )
        ).scalars()
    )
    assert "idx_storage_erase_terminal_unpurged" in plan
    await db.rollback()


async def test_reconcile_upserts_evicted_rows_and_isolates_object_failure(pg_session):
    db, redis = pg_session
    source = await _server(db, redis, "source", "host-source")
    target = await _server(db, redis, "target", "host-target")
    volume = await _volume(db, 2)
    good = await _object(db, volume, "obj-good", sha256="a" * 64)
    bad = await _object(db, volume, "obj-bad", sha256="b" * 64)
    deleted = await _object(db, volume, "obj-deleted", deleted=True)
    await _placement(db, good, source, status="present")
    await _placement(db, good, target, status="evicted")
    await _placement(db, bad, source, status="present")
    await _placement(db, bad, target, status="evicted")
    deleted_placement = await _placement(db, deleted, target, status="pending")

    await db.execute(
        text(
            """
            CREATE FUNCTION fail_one_reconcile_object() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.object_id = 'obj-bad'
                   AND OLD.status = 'evicted'
                   AND NEW.status = 'pending' THEN
                    RAISE EXCEPTION 'injected per-object failure';
                END IF;
                RETURN NEW;
            END
            $$
            """
        )
    )
    await db.execute(
        text(
            """
            CREATE TRIGGER zz_fail_one_reconcile_object
            BEFORE UPDATE ON replica_placement
            FOR EACH ROW EXECUTE FUNCTION fail_one_reconcile_object()
            """
        )
    )
    await db.commit()

    summary = await service.reconcile_storage(db)
    assert summary["gc_deleted_object_placements"] == 0
    assert summary["erase_tasks_enqueued"] == 1
    assert summary["reassigned"] == 1
    assert summary["object_failures"] == 1
    deleted_count = (
        await db.execute(
            select(func.count())
            .select_from(ReplicaPlacement)
            .where(ReplicaPlacement.placement_id == deleted_placement.placement_id)
        )
    ).scalar_one()
    assert deleted_count == 1
    await db.refresh(deleted_placement)
    assert deleted_placement.status == "evicted"

    good_target = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == good.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one()
    bad_target = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == bad.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one()
    assert good_target.status == "pending"
    assert bad_target.status == "evicted"

    repeated = await service.reconcile_storage(db)
    assert repeated["reassigned"] == 0
    assert repeated["object_failures"] == 1
    assert (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == good.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one().status == "pending"

    connection = await db.connection()
    raw = await connection.get_raw_connection()
    await raw.driver_connection.execute(
        _migration_up_sql("20260713160000_transactional_storage_objects.sql")
    )
    await db.commit()
    assert (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == good.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one().status == "pending"


async def test_false_present_and_direct_evicted_promotion_are_rejected(pg_session):
    db, redis = pg_session
    target = await _server(db, redis, "target", "host-target")
    target_id = target.server_id
    target_incarnation = target.storage_incarnation
    volume = await _volume(db, 1)
    obj = await _object(db, volume, "obj-proof", sha256="a" * 64)
    placement = await _placement(db, obj, target, status="pending")

    with pytest.raises(Exception):
        await service.announce_replicas(
            db,
            MINER,
            target_id,
            "different-mtls-server",
            target_incarnation,
            [
                {
                    "object_id": obj.object_id,
                    "status": "stored",
                    "ciphertext_sha256": "a" * 64,
                    "ciphertext_size_bytes": 1024,
                }
            ],
        )
    await db.commit()

    recorded = await service.announce_replicas(
        db,
        MINER,
        target_id,
        target_id,
        target_incarnation,
        [
            {
                "object_id": obj.object_id,
                "status": "stored",
                "ciphertext_sha256": "b" * 64,
                "ciphertext_size_bytes": 1024,
            }
        ],
    )
    assert recorded == 0
    await db.refresh(placement)
    assert placement.status == "pending"
    assert placement.last_error == "capability_required_for_committed_replica_receipt"

    placement.proof_sha256 = "a" * 64
    placement.proof_at = NOW
    placement.confirmed_at = NOW
    placement.status = "present"
    with pytest.raises(Exception):
        await db.flush()
    await db.rollback()


async def test_precommit_target_receipt_promotes_only_after_exact_hash_commit(
    pg_session,
):
    db, redis = pg_session
    target = await _server(db, redis, "target", "host-target")
    target_id = target.server_id
    original_incarnation = target.storage_incarnation
    volume = await _volume(db, 1)
    obj = await _object(db, volume, "obj-precommit", size_bytes=2048)
    placement = await _placement(db, obj, target, status="pending")
    ciphertext_sha256 = "c" * 64
    direct_receipt = {
        "object_id": obj.object_id,
        "status": "stored",
        "ciphertext_sha256": ciphertext_sha256,
        "ciphertext_size_bytes": 2048,
        "plaintext_size_bytes": 2048,
        "plaintext_sha256": "d" * 64,
    }

    recorded = await service.announce_replicas(
        db,
        MINER,
        target.server_id,
        target.server_id,
        target.storage_incarnation,
        [direct_receipt],
    )
    await db.refresh(placement)
    assert recorded == 1
    assert placement.status == "pending"
    assert placement.proof_sha256 == ciphertext_sha256
    assert placement.proof_size_bytes == 2048

    committed, replicas = await service.commit_object(
        db,
        volume,
        obj.object_id,
        obj.object_key,
        salt=obj.salt,
    )
    await db.refresh(placement)
    assert replicas == 1
    assert placement.status == "present"
    assert committed.ciphertext_size_bytes == 2048
    assert committed.durable_replica_count == 1
    assert committed.durability_state == "healthy"

    proof_at = placement.proof_at
    assert (
        await service.announce_replicas(
            db,
            MINER,
            target.server_id,
            target.server_id,
            target.storage_incarnation,
            [direct_receipt],
        )
        == 1
    )
    await db.refresh(placement)
    assert placement.proof_at == proof_at

    for changed_field, changed_value in (
        ("ciphertext_sha256", "e" * 64),
        ("ciphertext_size_bytes", 2049),
        ("plaintext_size_bytes", 2047),
        ("plaintext_sha256", "f" * 64),
    ):
        mismatched = {**direct_receipt, changed_field: changed_value}
        assert (
            await service.announce_replicas(
                db,
                MINER,
                target.server_id,
                target.server_id,
                target.storage_incarnation,
                [mismatched],
            )
            == 0
        )
        await db.refresh(placement)
        assert placement.status == "present"
        assert placement.proof_at == proof_at
        assert placement.proof_sha256 == ciphertext_sha256
        assert placement.proof_size_bytes == 2048
        assert placement.proof_plaintext_size_bytes == 2048
        assert placement.proof_plaintext_sha256 == "d" * 64

    original_cert_hash = target.attested_cert_pubkey_hash
    target.attested_cert_pubkey_hash = "f" * 64
    await db.commit()
    assert (
        await service.announce_replicas(
            db,
            MINER,
            target.server_id,
            target.server_id,
            target.storage_incarnation,
            [direct_receipt],
        )
        == 0
    )
    await db.refresh(placement)
    assert placement.status == "present"
    assert placement.proof_at == proof_at
    target.attested_cert_pubkey_hash = original_cert_hash
    await db.commit()

    attestation = (
        (
            await db.execute(
                select(ServerAttestation)
                .where(ServerAttestation.server_id == target.server_id)
                .order_by(ServerAttestation.created_at.desc())
            )
        )
        .scalars()
        .first()
    )
    assert attestation is not None
    attestation.verified_at = datetime.now(timezone.utc) - timedelta(hours=2)
    await db.commit()
    with pytest.raises(HTTPException) as stale_attestation:
        await service.announce_replicas(
            db,
            MINER,
            target.server_id,
            target.server_id,
            target.storage_incarnation,
            [direct_receipt],
        )
    assert stale_attestation.value.status_code == 403
    await db.rollback()
    await db.refresh(placement)
    assert placement.status == "present"
    assert placement.proof_at == proof_at

    changed_incarnation = str(uuid.uuid4())
    with pytest.raises(HTTPException) as stale_identity_transition:
        await service.announce_replicas(
            db,
            MINER,
            target_id,
            target_id,
            changed_incarnation,
            [direct_receipt],
        )
    assert stale_identity_transition.value.status_code == 403
    await db.rollback()
    await db.refresh(target)
    assert target.storage_incarnation == original_incarnation

    measurement = _storage_measurement()
    config_fingerprint = measurement.config_fingerprint or measurement_config_fingerprint(
        measurement
    )
    verified_at = datetime.now(timezone.utc)
    db.add(
        ServerAttestation(
            server_id=target_id,
            quote_data="fresh-replacement-quote",
            measurement_version=measurement.version,
            measurement_name=measurement.name,
            measurement_config_fingerprint=config_fingerprint,
            trust_set_fingerprint=measurement_trust_set_fingerprint(settings.tee_measurements),
            created_at=verified_at,
            verified_at=verified_at,
        )
    )
    await db.commit()
    assert (
        await service.announce_replicas(
            db,
            MINER,
            target_id,
            target_id,
            changed_incarnation,
            [direct_receipt],
        )
        == 0
    )
    await db.refresh(target)
    await db.refresh(placement)
    assert target.storage_incarnation == changed_incarnation
    assert placement.storage_incarnation != changed_incarnation
    assert placement.status == "present"
    assert placement.proof_at == proof_at


async def test_one_use_capability_drives_initial_copy_and_repair(pg_session):
    db, redis = pg_session
    source_identity = _attested_identity("source")
    source = await _server(
        db,
        redis,
        "cap-source",
        "host-source",
        attested_identity=source_identity,
    )
    target = await _server(db, redis, "cap-target", "host-target")
    wrong_target = await _server(db, redis, "cap-wrong", "host-wrong")
    repair_target = await _server(db, redis, "cap-repair", "host-repair")
    volume = await _volume(db, 3)
    obj = await _object(db, volume, "obj-capability", size_bytes=100)
    source_placement = await _placement(db, obj, source, status="pending")
    target_placement = await _placement(db, obj, target, status="pending")
    digest = "c" * 64
    ciphertext_size = 144

    assert (
        await service.announce_replicas(
            db,
            MINER,
            source.server_id,
            source.server_id,
            source.storage_incarnation,
            [
                {
                    "object_id": obj.object_id,
                    "status": "stored",
                    "ciphertext_sha256": digest,
                    "ciphertext_size_bytes": ciphertext_size,
                    "plaintext_size_bytes": 100,
                    "plaintext_sha256": "d" * 64,
                }
            ],
        )
        == 1
    )
    target_placement.proof_sha256 = digest
    target_placement.proof_size_bytes = ciphertext_size
    target_placement.proof_capability_id = "forged-capability"
    target_placement.proof_mode = "replication_capability"
    target_placement.proof_at = NOW
    with pytest.raises(Exception, match="capability is absent"):
        await db.flush()
    await db.rollback()
    await db.refresh(obj)
    await db.refresh(source)
    await db.refresh(target)
    await db.refresh(wrong_target)
    await db.refresh(repair_target)
    await db.refresh(volume)
    await db.refresh(source_placement)
    await db.refresh(target_placement)

    # Simulate a serial queue that reaches this descriptor after the old placement deadline. The
    # capability is leased only now, atomically advancing the attempt and deadline.
    target_placement.pending_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.commit()
    initial_peers = await service.object_replica_peers(db, obj.object_id)
    assert target.server_id in {peer.server_id for peer in initial_peers}
    lease = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    signature = (
        source_identity[0]
        .sign(
            service.replication_capability_message(lease["capability"]),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        .hex()
    )

    with pytest.raises(HTTPException) as wrong_identity:
        await service.consume_replication_capability(
            db, wrong_target, lease["capability"], signature
        )
    assert wrong_identity.value.status_code == 403

    binding = await service.consume_replication_capability(
        db, target, lease["capability"], signature
    )
    assert binding["source_server_id"] == source.server_id
    assert binding["target_server_id"] == target.server_id
    assert binding["target_placement_attempt"] == 2
    await db.refresh(target_placement)
    assert target_placement.pending_deadline > datetime.now(timezone.utc)
    with pytest.raises(HTTPException) as replay:
        await service.consume_replication_capability(db, target, lease["capability"], signature)
    assert replay.value.status_code == 409

    with pytest.raises(HTTPException) as wrong_receipt_hash:
        await service.complete_replication_capability(
            db, target, lease["capability"], "f" * 64, ciphertext_size
        )
    assert wrong_receipt_hash.value.status_code == 409
    with pytest.raises(HTTPException) as wrong_receipt_size:
        await service.complete_replication_capability(
            db, target, lease["capability"], digest, ciphertext_size + 1
        )
    assert wrong_receipt_size.value.status_code == 409
    assert (
        await service.complete_replication_capability(
            db, target, lease["capability"], digest, ciphertext_size
        )
    )["recorded"]
    await db.refresh(target_placement)
    assert target_placement.proof_mode == "replication_capability"

    race_placement = await _placement(db, obj, wrong_target, status="pending")
    stale_transfer = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        wrong_target.server_id,
        digest,
        ciphertext_size,
    )
    stale_signature = _sign_capability(source_identity, stale_transfer["capability"])
    await service.consume_replication_capability(
        db, wrong_target, stale_transfer["capability"], stale_signature
    )
    await service.fail_replication_capability(
        db, source, stale_transfer["capability"], "source_timeout"
    )
    replacement_transfer = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        wrong_target.server_id,
        digest,
        ciphertext_size,
    )
    replacement_signature = _sign_capability(source_identity, replacement_transfer["capability"])
    await service.consume_replication_capability(
        db, wrong_target, replacement_transfer["capability"], replacement_signature
    )
    await service.complete_replication_capability(
        db,
        wrong_target,
        replacement_transfer["capability"],
        digest,
        ciphertext_size,
    )
    assert (
        await service.complete_replication_capability(
            db,
            wrong_target,
            stale_transfer["capability"],
            digest,
            ciphertext_size,
        )
    )["recorded"]
    race_placement.status = "evicted"
    race_placement.last_error = "race_receipt_test_complete"
    await db.commit()

    await db.refresh(source_placement)
    await db.refresh(target_placement)
    assert source_placement.proof_mode == "direct_upload"
    # Completed exact possession must survive a long serial fan-out queue. The work lease expires,
    # but both receipts arrived within it and remain eligible for the atomic generation commit.
    source_placement.pending_deadline = source_placement.proof_at
    target_placement.pending_deadline = target_placement.proof_at
    await db.commit()
    source_proof_at = source_placement.proof_at
    assert (
        await service.announce_replicas(
            db,
            MINER,
            source.server_id,
            source.server_id,
            source.storage_incarnation,
            [
                {
                    "object_id": obj.object_id,
                    "status": "stored",
                    "ciphertext_sha256": digest,
                    "ciphertext_size_bytes": ciphertext_size,
                    "plaintext_size_bytes": 100,
                    "plaintext_sha256": "d" * 64,
                }
            ],
        )
        == 1
    )
    await db.refresh(source_placement)
    assert source_placement.proof_at == source_proof_at
    committed, replicas = await service.commit_object(
        db,
        volume,
        obj.object_id,
        obj.object_key,
        salt=obj.salt,
    )
    await db.refresh(source_placement)
    await db.refresh(target_placement)
    assert replicas == 2
    assert committed.ciphertext_size_bytes == ciphertext_size
    assert source_placement.status == target_placement.status == "present"
    assert target_placement.proof_capability_id == lease["capability_id"]

    repair_placement = await _placement(db, committed, repair_target, status="pending")
    repair_placement.pending_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.commit()
    queued = await service.repair_tasks_for_server(db, source.server_id)
    assert queued
    assert repair_target.server_id in {
        peer["server_id"] for task in queued for peer in task["peers"]
    }
    repair_lease = await service.issue_replication_capability(
        db,
        source,
        committed.object_id,
        repair_target.server_id,
        digest,
        ciphertext_size,
    )
    repair_signature = (
        source_identity[0]
        .sign(
            service.replication_capability_message(repair_lease["capability"]),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        .hex()
    )
    await service.consume_replication_capability(
        db, repair_target, repair_lease["capability"], repair_signature
    )
    await service.complete_replication_capability(
        db,
        repair_target,
        repair_lease["capability"],
        digest,
        ciphertext_size,
    )
    await db.refresh(repair_placement)
    await db.refresh(committed)
    assert repair_placement.status == "present"
    assert committed.durable_replica_count == 3
    assert committed.durability_state == "healthy"
    repair_placement.proof_at = datetime.now(timezone.utc) + timedelta(seconds=1)
    with pytest.raises(Exception, match="possession evidence is immutable"):
        await db.flush()
    await db.rollback()
    await db.refresh(repair_target)
    await db.refresh(committed)
    await db.refresh(repair_placement)
    assert (
        await service.complete_replication_capability(
            db,
            repair_target,
            repair_lease["capability"],
            digest,
            ciphertext_size,
        )
    )["recorded"]

    repair_placement.status = "evicted"
    repair_placement.last_error = "test_eviction_after_completed_receipt"
    await db.commit()
    with pytest.raises(HTTPException) as stale_idempotent_receipt:
        await service.complete_replication_capability(
            db,
            repair_target,
            repair_lease["capability"],
            digest,
            ciphertext_size,
        )
    assert stale_idempotent_receipt.value.status_code == 409


async def test_replication_receipt_rechecks_deadline_after_authority_lock_wait(
    pg_session, monkeypatch
):
    db, redis = pg_session
    source_identity = _attested_identity("receipt-lock-source")
    source = await _server(
        db,
        redis,
        "receipt-lock-source",
        "receipt-lock-source-host",
        attested_identity=source_identity,
    )
    target = await _server(db, redis, "receipt-lock-target", "receipt-lock-target-host")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "receipt-lock-object", size_bytes=32)
    await _placement(db, obj, source, status="pending")
    target_placement = await _placement(db, obj, target, status="pending")
    target_placement_id = target_placement.placement_id
    digest = "e" * 64
    ciphertext_size = 80
    assert (
        await service.announce_replicas(
            db,
            MINER,
            source.server_id,
            source.server_id,
            source.storage_incarnation,
            [
                {
                    "object_id": obj.object_id,
                    "status": "stored",
                    "ciphertext_sha256": digest,
                    "ciphertext_size_bytes": ciphertext_size,
                    "plaintext_size_bytes": 32,
                    "plaintext_sha256": "f" * 64,
                }
            ],
        )
        == 1
    )
    lease = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    await service.consume_replication_capability(
        db,
        target,
        lease["capability"],
        _sign_capability(source_identity, lease["capability"]),
    )

    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    deadline = datetime.now(timezone.utc) + timedelta(seconds=2)
    capability.expires_at = deadline
    capability.transfer_deadline = deadline
    target_placement.pending_deadline = deadline
    await db.commit()

    lock_wait_entered = asyncio.Event()
    original_locked_servers = service._locked_replication_servers

    async def delayed_locked_servers(*args, **kwargs):
        lock_wait_entered.set()
        return await original_locked_servers(*args, **kwargs)

    monkeypatch.setattr(service, "_locked_replication_servers", delayed_locked_servers)
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as locker, factory() as contender:
        await locker.execute(
            select(Server).where(Server.server_id == target.server_id).with_for_update()
        )
        contender_target = await contender.get(Server, target.server_id)
        completion = asyncio.create_task(
            service.complete_replication_capability(
                contender,
                contender_target,
                lease["capability"],
                digest,
                ciphertext_size,
            )
        )
        try:
            await asyncio.wait_for(lock_wait_entered.wait(), timeout=5)

            async def wait_until_expired():
                while datetime.now(timezone.utc) <= deadline:
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(wait_until_expired(), timeout=5)
            await locker.commit()

            with pytest.raises(HTTPException) as expired:
                await asyncio.wait_for(completion, timeout=5)
            assert expired.value.status_code == 409
        finally:
            if locker.in_transaction():
                await locker.rollback()
            if not completion.done():
                completion.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await completion

    db.expire_all()
    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    assert capability.completed_at is None
    assert target_placement.proof_at is None
    assert target_placement.proof_capability_id is None
    assert target_placement.confirmed_at is None
    assert target_placement.status == "pending"


async def test_capability_rejects_wrong_object_hash_size_expiry_and_incarnation(
    pg_session,
):
    db, redis = pg_session
    source_identity = _attested_identity("source-adversarial")
    source = await _server(
        db,
        redis,
        "adv-source",
        "host-source",
        attested_identity=source_identity,
    )
    target = await _server(db, redis, "adv-target", "host-target")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "obj-adversarial", size_bytes=20)
    await _placement(db, obj, source, status="pending")
    await _placement(db, obj, target, status="pending")
    digest = "e" * 64
    ciphertext_size = 64
    await service.announce_replicas(
        db,
        MINER,
        source.server_id,
        source.server_id,
        source.storage_incarnation,
        [
            {
                "object_id": obj.object_id,
                "status": "stored",
                "ciphertext_sha256": digest,
                "ciphertext_size_bytes": ciphertext_size,
                "plaintext_size_bytes": 20,
                "plaintext_sha256": "d" * 64,
            }
        ],
    )

    for wrong_object, wrong_hash, wrong_size, expected_status in (
        ("missing-generation", digest, ciphertext_size, 404),
        (obj.object_id, "f" * 64, ciphertext_size, 409),
        (obj.object_id, digest, ciphertext_size + 1, 409),
    ):
        with pytest.raises(HTTPException) as rejected:
            await service.issue_replication_capability(
                db,
                source,
                wrong_object,
                target.server_id,
                wrong_hash,
                wrong_size,
            )
        assert rejected.value.status_code == expected_status

    source_failure = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    assert (
        await service.fail_replication_capability(
            db, source, source_failure["capability"], "source_connection_failed"
        )
    )["recorded"]
    assert (
        await service.fail_replication_capability(
            db, target, source_failure["capability"], "insufficient_storage_replay"
        )
    )["recorded"]
    target_placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == obj.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one()
    assert target_placement.status == "pending"
    assert target_placement.last_error == "source_connection_failed"

    bad_signature = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    with pytest.raises(HTTPException) as source_proof:
        await service.consume_replication_capability(db, target, bad_signature["capability"], "00")
    assert source_proof.value.status_code == 403

    expired = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    capability = await db.get(StorageReplicationCapability, expired["capability_id"])
    now = datetime.now(timezone.utc)
    capability.issued_at = now - timedelta(minutes=2)
    capability.expires_at = now - timedelta(minutes=1)
    await db.commit()
    signature = (
        source_identity[0]
        .sign(
            service.replication_capability_message(expired["capability"]),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        .hex()
    )
    with pytest.raises(HTTPException) as expired_error:
        await service.consume_replication_capability(db, target, expired["capability"], signature)
    assert expired_error.value.status_code == 410
    expired_target_placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == obj.object_id,
                ReplicaPlacement.server_id == target.server_id,
            )
        )
    ).scalar_one()
    assert expired_target_placement.last_error == "capability_expired"

    fresh = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    fresh_signature = (
        source_identity[0]
        .sign(
            service.replication_capability_message(fresh["capability"]),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        .hex()
    )
    target.storage_incarnation = str(uuid.uuid4())
    await db.commit()
    with pytest.raises(HTTPException) as stale_target:
        await service.consume_replication_capability(
            db, target, fresh["capability"], fresh_signature
        )
    assert stale_target.value.status_code == 403


async def test_capability_rejects_wrong_source_cert_incarnation_target_cert_and_attempt(
    pg_session,
):
    db, redis = pg_session
    source_identity = _attested_identity("binding-source")
    intruder_identity = _attested_identity("binding-intruder")
    source = await _server(
        db,
        redis,
        "binding-source",
        "host-source",
        attested_identity=source_identity,
    )
    intruder = await _server(
        db,
        redis,
        "binding-intruder",
        "host-intruder",
        attested_identity=intruder_identity,
    )
    target = await _server(db, redis, "binding-target", "host-target")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "obj-binding", size_bytes=32)
    source_placement = await _placement(db, obj, source, status="pending")
    target_placement = await _placement(db, obj, target, status="pending")
    digest = "a" * 64
    ciphertext_size = 80
    assert (
        await service.announce_replicas(
            db,
            MINER,
            source.server_id,
            source.server_id,
            source.storage_incarnation,
            [
                {
                    "object_id": obj.object_id,
                    "status": "stored",
                    "ciphertext_sha256": digest,
                    "ciphertext_size_bytes": ciphertext_size,
                    "plaintext_size_bytes": 32,
                    "plaintext_sha256": "d" * 64,
                }
            ],
        )
        == 1
    )

    with pytest.raises(HTTPException) as wrong_source:
        await service.issue_replication_capability(
            db,
            intruder,
            obj.object_id,
            target.server_id,
            digest,
            ciphertext_size,
        )
    assert wrong_source.value.status_code == 409

    source_cert_lease = await service.issue_replication_capability(
        db, source, obj.object_id, target.server_id, digest, ciphertext_size
    )
    source_cert = source.attested_cert
    source_cert_hash = source.attested_cert_pubkey_hash
    rotated_source_identity = _attested_identity("binding-source-rotated")
    source.attested_cert = (
        rotated_source_identity[1].public_bytes(serialization.Encoding.PEM).decode()
    )
    source.attested_cert_pubkey_hash = get_public_key_hash(rotated_source_identity[1])
    await db.commit()
    with pytest.raises(HTTPException) as stale_source_cert:
        await service.consume_replication_capability(
            db,
            target,
            source_cert_lease["capability"],
            _sign_capability(source_identity, source_cert_lease["capability"]),
        )
    assert stale_source_cert.value.status_code == 409
    source.attested_cert = source_cert
    source.attested_cert_pubkey_hash = source_cert_hash
    await db.commit()

    target_cert_lease = await service.issue_replication_capability(
        db, source, obj.object_id, target.server_id, digest, ciphertext_size
    )
    target_cert_hash = target.attested_cert_pubkey_hash
    target.attested_cert_pubkey_hash = "f" * 64
    await db.commit()
    with pytest.raises(HTTPException) as stale_target_cert:
        await service.consume_replication_capability(
            db,
            target,
            target_cert_lease["capability"],
            _sign_capability(source_identity, target_cert_lease["capability"]),
        )
    assert stale_target_cert.value.status_code == 403
    await service.fail_replication_capability(
        db,
        source,
        target_cert_lease["capability"],
        "target_identity_rejected",
    )
    await db.refresh(target_placement)
    assert target_placement.status == "evicted"
    assert target_placement.last_error == "stale_storage_identity"
    target.attested_cert_pubkey_hash = target_cert_hash
    await service._upsert_pending_placement(db, obj, target)
    await db.commit()
    db.expire(target_placement)

    wrong_attempt_lease = await service.issue_replication_capability(
        db, source, obj.object_id, target.server_id, digest, ciphertext_size
    )
    target_placement.attempt_count += 1
    await db.commit()
    with pytest.raises(HTTPException) as wrong_attempt:
        await service.consume_replication_capability(
            db,
            target,
            wrong_attempt_lease["capability"],
            _sign_capability(source_identity, wrong_attempt_lease["capability"]),
        )
    assert wrong_attempt.value.status_code == 409
    await db.refresh(source_placement)
    assert source_placement.proof_sha256 == digest

    source_incarnation_lease = await service.issue_replication_capability(
        db, source, obj.object_id, target.server_id, digest, ciphertext_size
    )
    old_source_incarnation = source.storage_incarnation
    new_source_incarnation = str(uuid.uuid4())
    await service._bind_storage_identity(db, source, new_source_incarnation)
    await db.commit()
    with pytest.raises(HTTPException) as stale_source_incarnation:
        await service.consume_replication_capability(
            db,
            target,
            source_incarnation_lease["capability"],
            _sign_capability(source_identity, source_incarnation_lease["capability"]),
        )
    assert stale_source_incarnation.value.status_code == 409
    capability = await db.get(
        StorageReplicationCapability,
        source_incarnation_lease["capability_id"],
    )
    assert capability.source_storage_incarnation == old_source_incarnation
    assert capability.failed_at is not None
    assert capability.last_error == "capability_binding_stale"


async def test_replication_issue_and_fail_preserve_presented_identity_across_refresh(
    pg_session,
):
    db, redis = pg_session
    source_identity = _attested_identity("presented-replication-source")
    source = await _server(
        db,
        redis,
        "presented-replication-source",
        "presented-replication-source-host",
        attested_identity=source_identity,
    )
    target = await _server(
        db,
        redis,
        "presented-replication-target",
        "presented-replication-target-host",
    )
    source_id = source.server_id
    target_id = target.server_id
    old_source_incarnation = source.storage_incarnation
    replacement_incarnation = str(uuid.uuid4())
    digest = "e" * 64
    ciphertext_size = 80

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with (
        factory() as stale_issuer,
        factory() as stale_reporter,
        factory() as replacement,
    ):
        presented_issuer = await stale_issuer.get(Server, source_id)
        presented_reporter = await stale_reporter.get(Server, source_id)
        assert presented_issuer.storage_incarnation == old_source_incarnation
        assert presented_reporter.storage_incarnation == old_source_incarnation

        current_source = await replacement.get(Server, source_id)
        await service._bind_storage_identity(
            replacement,
            current_source,
            replacement_incarnation,
        )
        await replacement.commit()

        # Build the transfer from a genuinely fresh post-rotation generation. A receipt on the
        # retired incarnation is immutable audit evidence and must never be cleared merely to
        # manufacture a retry fixture.
        replacement.expire_all()
        current_source = await replacement.get(Server, source_id)
        current_target = await replacement.get(Server, target_id)
        volume = await _volume(replacement, 2)
        obj = await _object(
            replacement,
            volume,
            "presented-replication-object",
            size_bytes=32,
        )
        object_id = obj.object_id
        await _placement(replacement, obj, current_source, status="pending")
        target_placement = await _placement(replacement, obj, current_target, status="pending")
        target_placement_id = target_placement.placement_id
        direct_receipt = {
            "object_id": object_id,
            "status": "stored",
            "ciphertext_sha256": digest,
            "ciphertext_size_bytes": ciphertext_size,
            "plaintext_size_bytes": 32,
            "plaintext_sha256": "f" * 64,
        }
        assert (
            await service.announce_replicas(
                replacement,
                MINER,
                source_id,
                source_id,
                replacement_incarnation,
                [direct_receipt],
            )
            == 1
        )
        replacement.expire_all()
        current_source = await replacement.get(Server, source_id)
        lease = await service.issue_replication_capability(
            replacement,
            current_source,
            object_id,
            target_id,
            digest,
            ciphertext_size,
        )

        with pytest.raises(HTTPException) as stale_issue:
            await service.issue_replication_capability(
                stale_issuer,
                presented_issuer,
                object_id,
                target_id,
                digest,
                ciphertext_size,
            )
        assert stale_issue.value.status_code == 403
        assert "source identity is stale" in stale_issue.value.detail
        await stale_issuer.rollback()

        with pytest.raises(HTTPException) as stale_failure_report:
            await service.fail_replication_capability(
                stale_reporter,
                presented_reporter,
                lease["capability"],
                "stale_presenter_must_not_terminalize",
            )
        assert stale_failure_report.value.status_code == 403
        assert "current bound source or target identity" in stale_failure_report.value.detail
        await stale_reporter.rollback()

    db.expire_all()
    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    unchanged_target = await db.get(ReplicaPlacement, target_placement_id)
    assert capability.failed_at is None
    assert capability.last_error is None
    assert unchanged_target.status == "pending"
    assert unchanged_target.last_error is None


async def test_concurrent_capability_issuance_has_one_active_attempt(pg_session):
    db, redis = pg_session
    source_identity = _attested_identity("concurrent-source")
    source = await _server(
        db,
        redis,
        "concurrent-source",
        "host-source",
        attested_identity=source_identity,
    )
    target = await _server(db, redis, "concurrent-target", "host-target")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "obj-concurrent-capability", size_bytes=16)
    await _placement(db, obj, source, status="pending")
    await _placement(db, obj, target, status="pending")
    digest = "b" * 64
    ciphertext_size = 64
    await service.announce_replicas(
        db,
        MINER,
        source.server_id,
        source.server_id,
        source.storage_incarnation,
        [
            {
                "object_id": obj.object_id,
                "status": "stored",
                "ciphertext_sha256": digest,
                "ciphertext_size_bytes": ciphertext_size,
                "plaintext_size_bytes": 16,
                "plaintext_sha256": "d" * 64,
            }
        ],
    )

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def issue():
        async with factory() as contender:
            contender_source = await contender.get(Server, source.server_id)
            return await service.issue_replication_capability(
                contender,
                contender_source,
                obj.object_id,
                target.server_id,
                digest,
                ciphertext_size,
            )

    results = await asyncio.gather(issue(), issue(), return_exceptions=True)
    leases = [result for result in results if isinstance(result, dict)]
    conflicts = [result for result in results if isinstance(result, HTTPException)]
    assert len(leases) == 1
    assert len(conflicts) == 1
    assert conflicts[0].status_code == 409
    active_count = (
        await db.execute(
            select(func.count())
            .select_from(StorageReplicationCapability)
            .where(
                StorageReplicationCapability.object_id == obj.object_id,
                StorageReplicationCapability.target_server_id == target.server_id,
                StorageReplicationCapability.failed_at.is_(None),
                StorageReplicationCapability.completed_at.is_(None),
            )
        )
    ).scalar_one()
    assert active_count == 1


async def test_stale_attestation_cannot_revive_storage_liveness(pg_session):
    db, redis = pg_session
    stale = await _server(
        db,
        redis,
        "stale",
        "host-stale",
        live=False,
        attestation_age=timedelta(seconds=service.STORAGE_ATTESTATION_MAX_AGE_SECONDS + 1),
    )
    assert not await service.is_freshly_attested_storage_server(db, stale)
    with pytest.raises(Exception):
        await require_fresh_storage_caller(db, stale)
    assert f"storage:online:{stale.server_id}" not in redis.values


async def test_dead_source_pending_is_evicted_and_object_is_irrecoverable(pg_session):
    db, redis = pg_session
    dead_source = await _server(db, redis, "dead-source", "host-source", live=False)
    target = await _server(db, redis, "target", "host-target")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "obj-dead", sha256="d" * 64)
    await _placement(db, obj, dead_source, status="present")
    pending = await _placement(db, obj, target, status="pending")

    summary = await service.reconcile_storage(db)
    await db.refresh(obj)
    await db.refresh(pending)
    assert summary["irrecoverable"] == 1
    assert summary["unfulfillable_pending"] >= 1
    assert pending.status == "evicted"
    assert obj.durable_replica_count == 0
    assert obj.durability_state == "irrecoverable"


async def test_expired_pending_is_evicted_then_reassigned_with_new_attempt(pg_session):
    db, redis = pg_session
    source = await _server(db, redis, "source", "host-source")
    target = await _server(db, redis, "target", "host-target")
    volume = await _volume(db, 2)
    obj = await _object(db, volume, "obj-expired", sha256="f" * 64)
    await _placement(db, obj, source, status="present")
    pending = await _placement(
        db,
        obj,
        target,
        status="pending",
        deadline=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    summary = await service.reconcile_storage(db)
    await db.refresh(pending)
    assert summary["expired_pending"] == 1
    assert summary["reassigned"] == 1
    assert pending.status == "pending"
    assert pending.attempt_count == 2
    assert pending.pending_deadline > datetime.now(timezone.utc)


async def test_new_disk_incarnation_invalidates_old_present_receipts(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "storage", "host-storage")
    volume = await _volume(db, 1)
    obj = await _object(db, volume, "obj-wipe", sha256="e" * 64)
    placement = await _placement(db, obj, server, status="present")
    new_incarnation = str(uuid.uuid4())

    await service.announce_model_holdings(
        db,
        MINER,
        server.server_id,
        server.server_id,
        str(uuid.uuid4()),
        0,
        new_incarnation,
        150,
        [],
        True,
    )
    # A wiped node has no local object to inventory, so it emits no possession receipt. Reconcile
    # observes the incarnation mismatch, evicts the stale row, and surfaces total loss.
    await service.reconcile_storage(db)
    await db.refresh(server)
    await db.refresh(placement)
    await db.refresh(obj)
    assert server.storage_incarnation == new_incarnation
    assert placement.status == "evicted"
    assert placement.storage_incarnation != new_incarnation
    assert obj.durable_replica_count == 0
    assert obj.durability_state == "irrecoverable"


async def test_certificate_rebind_mixed_journal_is_atomic_ordered_and_replayable(pg_session):
    db, redis = pg_session
    old_identity = _attested_identity("cert-rebind-old")
    holder = await _server(
        db,
        redis,
        "cert-rebind-holder",
        "cert-rebind-host",
        attested_identity=old_identity,
    )
    old_cert_hash = holder.attested_cert_pubkey_hash
    incarnation = holder.storage_incarnation
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    rebound = await _object(
        db,
        volume,
        "a-rebound",
        sha256="a" * 64,
        size_bytes=11,
    )
    rebound_placement = await _placement(db, rebound, holder, status="present")
    unassigned = await _object(
        db,
        volume,
        "c-unassigned",
        sha256="c" * 64,
        size_bytes=13,
    )
    mismatched = await _object(
        db,
        volume,
        "d-mismatch",
        sha256="d" * 64,
        size_bytes=17,
    )
    mismatch_placement = await _placement(db, mismatched, holder, status="present")

    new_identity = _attested_identity("cert-rebind-new")
    holder.attested_cert = new_identity[1].public_bytes(serialization.Encoding.PEM).decode()
    holder.attested_cert_pubkey_hash = get_public_key_hash(new_identity[1])
    assert await service._refresh_object_durability(db, rebound, volume=volume) == 0
    await db.commit()
    new_cert_hash = holder.attested_cert_pubkey_hash

    with pytest.raises(HTTPException) as rejected:
        await service.rebind_replica_certificates(
            db,
            holder,
            request_id=str(uuid.uuid4()),
            storage_incarnation=incarnation,
            old_cert_pubkey_hash=old_cert_hash,
            placements=[
                {
                    "object_id": rebound.object_id,
                    "ciphertext_sha256": rebound.sha256,
                    "ciphertext_size_bytes": rebound.ciphertext_size_bytes,
                },
                {
                    "object_id": mismatched.object_id,
                    "ciphertext_sha256": mismatched.sha256,
                    "ciphertext_size_bytes": mismatched.ciphertext_size_bytes + 1,
                },
            ],
        )
    assert rejected.value.status_code == 409
    await db.commit()
    await db.refresh(rebound_placement)
    await db.refresh(mismatch_placement)
    assert rebound_placement.target_cert_pubkey_hash == old_cert_hash
    assert mismatch_placement.target_cert_pubkey_hash == old_cert_hash

    holder = await db.get(Server, holder_id)
    with pytest.raises(HTTPException, match="authenticated server") as changed_server:
        await service.rebind_replica_certificates(
            db,
            holder,
            request_id=str(uuid.uuid4()),
            storage_incarnation=incarnation,
            old_cert_pubkey_hash=old_cert_hash,
            placements=[
                {
                    "object_id": unassigned.object_id,
                    "ciphertext_sha256": unassigned.sha256,
                    "ciphertext_size_bytes": unassigned.ciphertext_size_bytes,
                }
            ],
        )
    assert changed_server.value.status_code == 409
    await db.commit()
    holder = await db.get(Server, holder_id)

    request_id = str(uuid.uuid4())
    response = await service.rebind_replica_certificates(
        db,
        holder,
        request_id=request_id,
        storage_incarnation=incarnation,
        old_cert_pubkey_hash=old_cert_hash,
        placements=[
            {
                "object_id": "b-not-current",
                "ciphertext_sha256": "b" * 64,
                "ciphertext_size_bytes": 12,
            },
            {
                "object_id": rebound.object_id,
                "ciphertext_sha256": rebound.sha256,
                "ciphertext_size_bytes": rebound.ciphertext_size_bytes,
            },
        ],
    )
    assert response == {
        "request_id": request_id,
        "server_id": holder.server_id,
        "storage_incarnation": incarnation,
        "old_cert_pubkey_hash": old_cert_hash,
        "new_cert_pubkey_hash": new_cert_hash,
        "rebound_object_ids": ["a-rebound"],
        "outcomes": [
            {"object_id": "a-rebound", "outcome": "rebound"},
            {"object_id": "b-not-current", "outcome": "not_current"},
        ],
    }
    await db.refresh(rebound_placement)
    await db.refresh(rebound)
    assert rebound_placement.target_cert_pubkey_hash == new_cert_hash
    assert rebound.durable_replica_count == 1
    assert rebound.durability_state == "healthy"
    assert rebound.durability_updated_at is not None
    audit = await db.get(StorageReplicaCertRebindAudit, request_id)
    assert audit.object_bindings == [
        {
            "object_id": "a-rebound",
            "ciphertext_sha256": "a" * 64,
            "ciphertext_size_bytes": 11,
        }
    ]
    assert (
        await service.rebind_replica_certificates(
            db,
            holder,
            request_id=request_id,
            storage_incarnation=incarnation,
            old_cert_pubkey_hash=old_cert_hash,
            placements=[
                {
                    "object_id": "a-rebound",
                    "ciphertext_sha256": "a" * 64,
                    "ciphertext_size_bytes": 11,
                },
                {
                    "object_id": "b-not-current",
                    "ciphertext_sha256": "b" * 64,
                    "ciphertext_size_bytes": 12,
                },
            ],
        )
        == response
    )
    with pytest.raises(DBAPIError, match="audit rows are immutable"):
        await db.execute(
            update(StorageReplicaCertRebindAudit)
            .where(StorageReplicaCertRebindAudit.request_id == request_id)
            .values(response_json={})
        )
        await db.commit()
    await db.rollback()


async def test_certificate_rebind_recovers_reconcile_winner_and_rejects_near_misses(
    pg_session,
):
    db, redis = pg_session
    old_identity = _attested_identity("cert-rebind-race-old")
    holder = await _server(
        db,
        redis,
        "cert-rebind-race-holder",
        "cert-rebind-race-host",
        attested_identity=old_identity,
    )
    holder_id = holder.server_id
    incarnation = holder.storage_incarnation
    old_cert_hash = holder.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    objects = {}
    placements = {}
    for index, name in enumerate(("winner", "wrong-reason", "no-audit", "extra-change"), 1):
        obj = await _object(
            db,
            volume,
            f"cert-rebind-race-{name}",
            sha256=f"{index}" * 64,
            size_bytes=10 + index,
        )
        objects[name] = obj
        placements[name] = await _placement(db, obj, holder, status="present")
    object_ids = {name: obj.object_id for name, obj in objects.items()}
    object_hashes = {name: obj.sha256 for name, obj in objects.items()}
    object_sizes = {name: obj.ciphertext_size_bytes for name, obj in objects.items()}
    placement_ids = {
        name: placement.placement_id for name, placement in placements.items()
    }
    stale_bystander = await _server(
        db,
        redis,
        "cert-rebind-stale-bystander",
        "cert-rebind-stale-bystander-host",
        attestation_age=timedelta(hours=2),
    )
    await _placement(db, objects["winner"], stale_bystander, status="present")
    assert await service._refresh_object_durability(
        db,
        objects["winner"],
        volume=volume,
    ) == 1
    await db.commit()

    new_identity = _attested_identity("cert-rebind-race-new")
    holder.attested_cert = new_identity[1].public_bytes(serialization.Encoding.PEM).decode()
    holder.attested_cert_pubkey_hash = get_public_key_hash(new_identity[1])
    await db.commit()
    new_cert_hash = holder.attested_cert_pubkey_hash

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as reconcile_winner, factory() as rebinder:
        await reconcile_winner.execute(
            select(StorageObject)
            .where(StorageObject.object_id == object_ids["winner"])
            .with_for_update()
        )
        reconcile_placement = (
            await reconcile_winner.execute(
                select(ReplicaPlacement)
                .where(ReplicaPlacement.placement_id == placement_ids["winner"])
                .with_for_update()
            )
        ).scalar_one()
        reconcile_placement.status = "evicted"
        reconcile_placement.last_error = "stale_storage_identity"
        await reconcile_winner.flush()

        rebound_caller = await rebinder.get(Server, holder_id)
        rebound = asyncio.create_task(
            service.rebind_replica_certificates(
                rebinder,
                rebound_caller,
                request_id=str(uuid.uuid4()),
                storage_incarnation=incarnation,
                old_cert_pubkey_hash=old_cert_hash,
                placements=[
                    {
                        "object_id": object_ids["winner"],
                        "ciphertext_sha256": object_hashes["winner"],
                        "ciphertext_size_bytes": object_sizes["winner"],
                    }
                ],
            )
        )
        await asyncio.sleep(0.05)
        assert not rebound.done()
        await reconcile_winner.commit()
        response = await asyncio.wait_for(rebound, timeout=5)
    assert response["rebound_object_ids"] == [object_ids["winner"]]
    recovered = await db.get(ReplicaPlacement, placement_ids["winner"])
    recovered_object = await db.get(StorageObject, object_ids["winner"])
    await db.refresh(recovered)
    await db.refresh(recovered_object)
    assert recovered.status == "present"
    assert recovered.last_error is None
    assert recovered.target_cert_pubkey_hash == new_cert_hash
    assert recovered_object.durable_replica_count == 1
    assert recovered_object.durability_state == "healthy"
    assert recovered_object.durability_updated_at is not None

    wrong_reason = await db.get(ReplicaPlacement, placement_ids["wrong-reason"])
    wrong_reason.status = "evicted"
    wrong_reason.last_error = "pending_target_unavailable"
    no_audit = await db.get(ReplicaPlacement, placement_ids["no-audit"])
    no_audit.status = "evicted"
    no_audit.last_error = "stale_storage_identity"
    extra_change = await db.get(ReplicaPlacement, placement_ids["extra-change"])
    extra_change.status = "evicted"
    extra_change.last_error = "stale_storage_identity"
    extra_attempt_count = extra_change.attempt_count
    await db.commit()

    holder = await db.get(Server, holder_id)
    with pytest.raises(HTTPException, match="present placement or a reconcile-evicted") as rejected:
        await service.rebind_replica_certificates(
            db,
            holder,
            request_id=str(uuid.uuid4()),
            storage_incarnation=incarnation,
            old_cert_pubkey_hash=old_cert_hash,
            placements=[
                {
                    "object_id": object_ids["wrong-reason"],
                    "ciphertext_sha256": object_hashes["wrong-reason"],
                    "ciphertext_size_bytes": object_sizes["wrong-reason"],
                }
            ],
        )
    assert rejected.value.status_code == 409
    await db.rollback()

    with pytest.raises(DBAPIError, match="lacks exact immutable audit authority"):
        await db.execute(
            update(ReplicaPlacement)
            .where(ReplicaPlacement.placement_id == placement_ids["no-audit"])
            .values(
                status="present",
                last_error=None,
                target_cert_pubkey_hash=new_cert_hash,
            )
        )
        await db.commit()
    await db.rollback()

    request_id = str(uuid.uuid4())
    db.add(
        StorageReplicaCertRebindAudit(
            request_id=request_id,
            request_sha256="f" * 64,
            server_id=holder_id,
            storage_incarnation=incarnation,
            old_cert_pubkey_hash=old_cert_hash,
            new_cert_pubkey_hash=new_cert_hash,
            object_bindings=[
                {
                    "object_id": object_ids["extra-change"],
                    "ciphertext_sha256": object_hashes["extra-change"],
                    "ciphertext_size_bytes": object_sizes["extra-change"],
                }
            ],
            response_json={},
        )
    )
    await db.flush()
    await db.execute(
        text("SELECT set_config('chutes.storage_cert_rebind_request_id', :request_id, true)"),
        {"request_id": request_id},
    )
    with pytest.raises(
        DBAPIError,
        match="lacks exact inactive binding or audited active rebind",
    ):
        await db.execute(
            update(ReplicaPlacement)
            .where(ReplicaPlacement.placement_id == placement_ids["extra-change"])
            .values(
                status="present",
                last_error=None,
                target_cert_pubkey_hash=new_cert_hash,
                attempt_count=extra_attempt_count + 1,
            )
        )
        await db.commit()
    await db.rollback()


async def test_new_incarnation_retires_old_erase_tasks_with_immutable_audit(pg_session):
    db, redis = pg_session
    fresh = await _server(db, redis, "fresh-bind-holder", "fresh-bind-host")
    first_incarnation = fresh.storage_incarnation
    fresh.storage_incarnation = None
    await db.commit()
    assert await service._bind_storage_identity(db, fresh, first_incarnation) == set()
    await db.commit()
    await db.refresh(fresh)
    assert fresh.storage_incarnation == first_incarnation

    holder = await _server(db, redis, "erase-rollover-holder", "erase-rollover-host")
    old_incarnation = holder.storage_incarnation
    old_cert_hash = holder.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        "retired-incarnation-bytes",
        sha256="9" * 64,
        size_bytes=19,
    )
    placement = await _placement(db, obj, holder, status="present")
    holder_id = holder.server_id
    placement_id = placement.placement_id
    object_id = obj.object_id
    volume_id = volume.volume_id
    assert await service._refresh_object_durability(db, obj, volume=volume) == 1
    await db.commit()
    assert await service._bind_storage_identity(db, holder, old_incarnation) == set()
    await db.commit()
    now = datetime.now(timezone.utc)
    tasks = [
        StorageEraseTask(
            object_id="erase-pending",
            volume_id="erase-volume",
            server_id=holder.server_id,
            storage_incarnation=old_incarnation,
            holder_cert_pubkey_hash=old_cert_hash,
            reason="object_deleted",
            state="pending",
            retention_deadline=now + timedelta(days=1),
        ),
        StorageEraseTask(
            object_id="erase-claimed",
            volume_id="erase-volume",
            server_id=holder.server_id,
            storage_incarnation=old_incarnation,
            holder_cert_pubkey_hash=old_cert_hash,
            reason="object_deleted",
            state="claimed",
            claimed_at=now,
            lease_expires_at=now + timedelta(minutes=1),
            claim_cert_pubkey_hash=old_cert_hash,
            retention_deadline=now + timedelta(days=1),
        ),
        StorageEraseTask(
            object_id="erase-already-terminal",
            volume_id="erase-volume",
            server_id=holder.server_id,
            storage_incarnation=old_incarnation,
            holder_cert_pubkey_hash=old_cert_hash,
            reason="object_deleted",
            state="erased",
            completed_at=now,
            erased_file_was_present=True,
            retention_deadline=now + timedelta(days=1),
        ),
        StorageEraseTask(
            object_id="erase-other-incarnation",
            volume_id="erase-volume",
            server_id=holder.server_id,
            storage_incarnation=str(uuid.uuid4()),
            holder_cert_pubkey_hash=old_cert_hash,
            reason="object_deleted",
            state="pending",
            retention_deadline=now + timedelta(days=1),
        ),
    ]
    db.add_all(tasks)
    await db.commit()
    task_ids = [task.task_id for task in tasks]
    new_incarnation = str(uuid.uuid4())

    await service._bind_storage_identity(db, holder, new_incarnation)
    await db.commit()
    await service.reconcile_storage(db)
    db.expire_all()
    rows = {task_id: await db.get(StorageEraseTask, task_id) for task_id in task_ids}
    retired = [rows[task_ids[0]], rows[task_ids[1]]]
    assert [task.state for task in retired] == ["retired", "retired"]
    assert all(task.erased_file_was_present is None for task in retired)
    assert all(task.completed_at is not None for task in retired)
    assert all(task.claimed_at is None and task.lease_expires_at is None for task in retired)
    assert all(task.last_error == "attested_incarnation_retired_unreachable" for task in retired)
    assert rows[task_ids[2]].state == "erased"
    assert rows[task_ids[2]].retirement_audit_id is None
    assert rows[task_ids[3]].state == "pending"
    assert rows[task_ids[3]].retirement_audit_id is None

    audit_id = retired[0].retirement_audit_id
    assert audit_id and retired[1].retirement_audit_id == audit_id
    audit = await db.get(StorageIncarnationRetirementAudit, audit_id)
    assert audit.previous_storage_incarnation == old_incarnation
    assert audit.replacement_storage_incarnation == new_incarnation
    assert audit.replacement_cert_pubkey_hash == old_cert_hash
    assert audit.retired_task_ids == sorted(task.task_id for task in retired)
    assert audit.retired_holder_cert_pubkey_hashes == [old_cert_hash]

    holder = await db.get(Server, holder_id)
    with pytest.raises(HTTPException, match="permanently retired") as reused:
        await service._bind_storage_identity(db, holder, old_incarnation)
    assert reused.value.status_code == 409
    await db.rollback()
    with pytest.raises(DBAPIError, match="permanently retired"):
        await db.execute(
            update(Server)
            .where(Server.server_id == holder_id)
            .values(storage_incarnation=old_incarnation)
        )
        await db.commit()
    await db.rollback()
    db.expire_all()
    holder = await db.get(Server, holder_id)
    placement = await db.get(ReplicaPlacement, placement_id)
    obj = await db.get(StorageObject, object_id)
    volume = await db.get(StorageVolume, volume_id)
    assert holder.storage_incarnation == new_incarnation
    assert placement.storage_incarnation == old_incarnation
    assert placement.status == "evicted"
    assert await service._refresh_object_durability(db, obj, volume=volume) == 0
    await db.commit()

    with pytest.raises(DBAPIError, match="audit rows are immutable"):
        await db.execute(
            update(StorageIncarnationRetirementAudit)
            .where(StorageIncarnationRetirementAudit.audit_id == audit_id)
            .values(retired_task_ids=[])
        )
        await db.commit()
    await db.rollback()


async def test_delete_after_incarnation_retirement_creates_only_audited_terminal_work(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "late-erase-holder", "late-erase-host")
    holder_id = holder.server_id
    old_incarnation = holder.storage_incarnation
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        "late-erase-object",
        object_key="late-erase-key",
        sha256="7" * 64,
        size_bytes=23,
    )
    placement = await _placement(db, obj, holder, status="present")
    volume_id = volume.volume_id
    object_id = obj.object_id
    object_hash = obj.sha256
    object_size = obj.ciphertext_size_bytes
    placement_id = placement.placement_id
    holder_cert_hash = placement.target_cert_pubkey_hash
    await service._bind_storage_identity(db, holder, str(uuid.uuid4()))
    await db.commit()

    representative, _used_bytes, pending_tasks = await service.delete_object(
        db,
        volume,
        "late-erase-key",
    )
    assert representative.object_id == object_id
    assert pending_tasks == 0
    task = (
        await db.execute(
            select(StorageEraseTask).where(
                StorageEraseTask.object_id == object_id,
                StorageEraseTask.server_id == holder_id,
                StorageEraseTask.storage_incarnation == old_incarnation,
            )
        )
    ).scalar_one()
    task_id = task.task_id
    audit_id = task.retirement_audit_id
    audit = await db.get(StorageIncarnationRetirementAudit, audit_id)
    assert task.state == "retired"
    assert task.completed_at is not None
    assert task.retirement_audit_id is not None
    assert task.last_error == "attested_incarnation_retired_unreachable"
    assert audit.server_id == holder_id
    assert audit.previous_storage_incarnation == old_incarnation
    assert placement_id == task.placement_id
    assert object_hash == representative.sha256
    assert object_size == representative.ciphertext_size_bytes
    linked_completed_at = task.completed_at

    assert await service._retire_deleted_volume_batch(db, volume, limit=10) == (0, 1)
    await db.commit()
    await db.refresh(task)
    assert task.state == "retired"
    assert task.reason == "volume_deleted"
    assert task.retirement_audit_id == audit_id
    assert task.completed_at == linked_completed_at

    with pytest.raises(DBAPIError, match="lacks exact incarnation-retirement audit authority"):
        await db.execute(
            StorageEraseTask.__table__.insert().values(
                task_id=str(uuid.uuid4()),
                object_id="late-direct-pending",
                volume_id=volume_id,
                server_id=holder_id,
                storage_incarnation=old_incarnation,
                holder_cert_pubkey_hash=holder_cert_hash,
                reason="object_deleted",
                state="pending",
                retention_deadline=datetime.now(timezone.utc) + timedelta(days=1),
            )
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError, match="lacks exact incarnation-retirement audit authority"):
        await db.execute(
            StorageEraseTask.__table__.insert().values(
                task_id=str(uuid.uuid4()),
                object_id="late-direct-unlinked-terminal",
                volume_id=volume_id,
                server_id=holder_id,
                storage_incarnation=old_incarnation,
                holder_cert_pubkey_hash=holder_cert_hash,
                reason="object_deleted",
                state="retired",
                completed_at=datetime.now(timezone.utc),
                retention_deadline=datetime.now(timezone.utc) + timedelta(days=1),
                last_error="attested_incarnation_retired_unreachable",
            )
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError, match="lacks exact incarnation-retirement audit authority"):
        await db.execute(
            StorageEraseTask.__table__.insert().values(
                task_id=str(uuid.uuid4()),
                object_id="late-direct-wrong-audit",
                volume_id=volume_id,
                server_id=holder_id,
                storage_incarnation=old_incarnation,
                holder_cert_pubkey_hash=holder_cert_hash,
                reason="object_deleted",
                state="retired",
                completed_at=datetime.now(timezone.utc),
                retirement_audit_id=str(uuid.uuid4()),
                retention_deadline=datetime.now(timezone.utc) + timedelta(days=1),
                last_error="attested_incarnation_retired_unreachable",
            )
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError, match="audited storage incarnation retirement is immutable"):
        await db.execute(
            update(StorageEraseTask)
            .where(StorageEraseTask.task_id == task_id)
            .values(
                state="pending",
                completed_at=None,
                retirement_audit_id=None,
                last_error=None,
            )
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError, match="audited storage incarnation retirement is immutable"):
        await db.execute(
            update(StorageEraseTask)
            .where(StorageEraseTask.task_id == task_id)
            .values(completed_at=linked_completed_at + timedelta(seconds=1))
        )
        await db.commit()
    await db.rollback()


@pytest.mark.parametrize(
    "identity_wins",
    [False, True],
    ids=["volume-enqueue-wins", "identity-retirement-wins"],
)
async def test_incarnation_retirement_and_mixed_volume_enqueue_serialize_both_orders(
    pg_session,
    identity_wins,
):
    db, redis = pg_session
    suffix = "identity" if identity_wins else "volume"
    holder = await _server(
        db,
        redis,
        f"mixed-retirement-{suffix}",
        f"mixed-retirement-host-{suffix}",
    )
    holder_id = holder.server_id
    old_incarnation = holder.storage_incarnation
    old_cert_hash = holder.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    existing_obj = await _object(
        db,
        volume,
        f"mixed-existing-{suffix}",
        sha256="8" * 64,
        size_bytes=31,
    )
    missing_obj = await _object(
        db,
        volume,
        f"mixed-missing-{suffix}",
        sha256="9" * 64,
        size_bytes=37,
    )
    existing_placement = await _placement(db, existing_obj, holder, status="present")
    await _placement(db, missing_obj, holder, status="present")
    volume_id = volume.volume_id
    existing_object_id = existing_obj.object_id
    missing_object_id = missing_obj.object_id
    existing_placement_id = existing_placement.placement_id
    now = datetime.now(timezone.utc)
    existing_task = StorageEraseTask(
        object_id=existing_object_id,
        volume_id=volume_id,
        placement_id=existing_placement_id,
        server_id=holder_id,
        storage_incarnation=old_incarnation,
        holder_cert_pubkey_hash=old_cert_hash,
        reason="object_deleted",
        state="erased",
        completed_at=now,
        erased_file_was_present=True,
        retention_deadline=now + timedelta(days=1),
    )
    db.add(existing_task)
    await db.commit()
    new_incarnation = str(uuid.uuid4())

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as identity_worker, factory() as volume_worker:
        identity_holder = await identity_worker.get(Server, holder_id)
        deleted_volume = await volume_worker.get(StorageVolume, volume_id)
        if identity_wins:
            await service._bind_storage_identity(
                identity_worker,
                identity_holder,
                new_incarnation,
            )
            volume_retirement = asyncio.create_task(
                service._retire_deleted_volume_batch(volume_worker, deleted_volume, limit=10)
            )
            await asyncio.sleep(0.05)
            assert not volume_retirement.done()
            await identity_worker.commit()
            assert await asyncio.wait_for(volume_retirement, timeout=5) == (2, 1)
            await volume_worker.commit()
        else:
            assert await service._retire_deleted_volume_batch(
                volume_worker,
                deleted_volume,
                limit=10,
            ) == (2, 1)
            identity_retirement = asyncio.create_task(
                service._bind_storage_identity(
                    identity_worker,
                    identity_holder,
                    new_incarnation,
                )
            )
            await asyncio.sleep(0.05)
            assert not identity_retirement.done()
            await volume_worker.commit()
            await asyncio.wait_for(identity_retirement, timeout=5)
            await identity_worker.commit()

    db.expire_all()
    audit = (
        await db.execute(
            select(StorageIncarnationRetirementAudit).where(
                StorageIncarnationRetirementAudit.server_id == holder_id,
                StorageIncarnationRetirementAudit.previous_storage_incarnation == old_incarnation,
            )
        )
    ).scalar_one()
    tasks = list(
        (
            await db.execute(
                select(StorageEraseTask)
                .where(
                    StorageEraseTask.server_id == holder_id,
                    StorageEraseTask.storage_incarnation == old_incarnation,
                )
                .order_by(StorageEraseTask.object_id)
            )
        ).scalars()
    )
    task_by_object_id = {task.object_id: task for task in tasks}
    assert set(task_by_object_id) == {
        existing_object_id,
        missing_object_id,
    }
    existing_result = task_by_object_id[existing_object_id]
    missing_result = task_by_object_id[missing_object_id]
    assert missing_result.state == "retired"
    assert missing_result.retirement_audit_id == audit.audit_id
    if identity_wins:
        assert existing_result.state == "erased"
        assert existing_result.retirement_audit_id is None
        assert existing_result.erased_file_was_present is True
    else:
        assert existing_result.state == "retired"
        assert existing_result.retirement_audit_id == audit.audit_id
        assert existing_result.erased_file_was_present is None
    assert all(task.reason == "volume_deleted" for task in tasks)
    assert all(task.completed_at is not None for task in tasks)


@pytest.mark.parametrize(
    "identity_wins",
    [False, True],
    ids=["enqueue-wins", "identity-wins"],
)
async def test_bind_and_multigeneration_enqueue_share_server_publication_fence(
    pg_session,
    identity_wins,
):
    db, redis = pg_session
    suffix = "identity" if identity_wins else "enqueue"
    holder = await _server(
        db,
        redis,
        f"placement-order-{suffix}",
        f"placement-order-host-{suffix}",
    )
    holder_id = holder.server_id
    old_incarnation = holder.storage_incarnation
    volume = await _volume(db, 1)
    # Object lexical order is intentionally the inverse of placement UUID order. Placement order
    # remains a secondary defense; the server-wide publication fence keeps bind out of the placement
    # graph regardless of which operation wins.
    high_object = await _object(
        db,
        volume,
        f"a-object-high-placement-{suffix}",
        sha256="a" * 64,
        size_bytes=41,
    )
    low_object = await _object(
        db,
        volume,
        f"z-object-low-placement-{suffix}",
        sha256="b" * 64,
        size_bytes=43,
    )
    high_placement = await _placement(db, high_object, holder, status="present")
    low_placement = await _placement(db, low_object, holder, status="present")
    high_placement_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    low_placement_id = "00000000-0000-0000-0000-000000000001"
    high_placement.placement_id = high_placement_id
    low_placement.placement_id = low_placement_id
    await db.commit()
    object_ids = [high_object.object_id, low_object.object_id]
    assert object_ids[0] < object_ids[1]
    assert low_placement_id < high_placement_id
    new_incarnation = str(uuid.uuid4())

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as identity_worker, factory() as enqueue_worker:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(
            gate,
            [holder_id],
            shared=False,
        )
        identity_holder = await identity_worker.get(Server, holder_id)
        enqueue_generations = list(
            (
                await enqueue_worker.execute(
                    select(StorageObject)
                    .where(StorageObject.object_id.in_(object_ids))
                    .order_by(StorageObject.object_id)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        identity_pid = await identity_worker.scalar(text("SELECT pg_backend_pid()"))
        enqueue_pid = await enqueue_worker.scalar(text("SELECT pg_backend_pid()"))

        if identity_wins:
            identity_retirement = asyncio.create_task(
                service._bind_storage_identity(
                    identity_worker,
                    identity_holder,
                    new_incarnation,
                )
            )
            await _wait_for_postgres_blocker(db.bind, identity_pid, gate_pid)
            erase_enqueue = asyncio.create_task(
                service._enqueue_erase_tasks_for_generations(
                    enqueue_worker,
                    enqueue_generations,
                    reason="object_deleted",
                )
            )
            await _wait_for_postgres_blocker(db.bind, enqueue_pid, identity_pid)
            await gate.commit()
            await asyncio.wait_for(identity_retirement, timeout=10)
            await _wait_for_postgres_blocker(db.bind, enqueue_pid, identity_pid)
            await identity_worker.commit()
            enqueued = await asyncio.wait_for(erase_enqueue, timeout=10)
            await enqueue_worker.commit()
        else:
            erase_enqueue = asyncio.create_task(
                service._enqueue_erase_tasks_for_generations(
                    enqueue_worker,
                    enqueue_generations,
                    reason="object_deleted",
                )
            )
            await _wait_for_postgres_blocker(db.bind, enqueue_pid, gate_pid)
            identity_retirement = asyncio.create_task(
                service._bind_storage_identity(
                    identity_worker,
                    identity_holder,
                    new_incarnation,
                )
            )
            await _wait_for_postgres_blocker(db.bind, identity_pid, enqueue_pid)
            await gate.commit()
            enqueued = await asyncio.wait_for(erase_enqueue, timeout=10)
            await _wait_for_postgres_blocker(db.bind, identity_pid, enqueue_pid)
            await enqueue_worker.commit()
            await asyncio.wait_for(identity_retirement, timeout=10)
            await identity_worker.commit()

    assert enqueued == (0 if identity_wins else 2)
    with pytest.raises(
        RuntimeError,
        match="authority changed, retired, or failed attestation",
    ):
        await service._upsert_pending_placement(db, high_object, holder)
    await db.rollback()
    db.expire_all()
    rebound_holder = await db.get(Server, holder_id)
    assert rebound_holder.storage_incarnation == new_incarnation
    audit = (
        await db.execute(
            select(StorageIncarnationRetirementAudit).where(
                StorageIncarnationRetirementAudit.server_id == holder_id,
                StorageIncarnationRetirementAudit.previous_storage_incarnation == old_incarnation,
            )
        )
    ).scalar_one()
    tasks = list(
        (
            await db.execute(
                select(StorageEraseTask)
                .where(StorageEraseTask.object_id.in_(object_ids))
                .order_by(StorageEraseTask.object_id)
            )
        )
        .scalars()
        .all()
    )
    assert [task.object_id for task in tasks] == object_ids
    assert all(task.state == "retired" for task in tasks)
    assert all(task.retirement_audit_id == audit.audit_id for task in tasks)
    assert all(task.completed_at is not None for task in tasks)
    assert all(task.last_error == "attested_incarnation_retired_unreachable" for task in tasks)
    assert all(task.claimed_at is None for task in tasks)
    assert all(task.lease_expires_at is None for task in tasks)
    assert all(task.erased_file_was_present is None for task in tasks)


@pytest.mark.parametrize(
    "identity_wins",
    [False, True],
    ids=["replication-wins", "identity-wins"],
)
async def test_replication_identity_reads_share_server_publication_fence(
    pg_session,
    identity_wins,
):
    db, redis = pg_session
    holder = await _server(
        db,
        redis,
        f"replication-fence-{'identity' if identity_wins else 'transfer'}",
        f"replication-fence-host-{'identity' if identity_wins else 'transfer'}",
    )
    holder_id = holder.server_id
    replacement_incarnation = str(uuid.uuid4())
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as identity_worker, factory() as transfer_worker:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        identity_holder = await identity_worker.get(Server, holder_id)
        identity_pid = await identity_worker.scalar(text("SELECT pg_backend_pid()"))
        transfer_pid = await transfer_worker.scalar(text("SELECT pg_backend_pid()"))

        if identity_wins:
            binding = asyncio.create_task(
                service._bind_storage_identity(
                    identity_worker,
                    identity_holder,
                    replacement_incarnation,
                )
            )
            await _wait_for_postgres_blocker(db.bind, identity_pid, gate_pid)
            reading = asyncio.create_task(
                service._locked_replication_servers(transfer_worker, holder_id, holder_id)
            )
            await _wait_for_postgres_blocker(db.bind, transfer_pid, identity_pid)
            await gate.commit()
            await asyncio.wait_for(binding, timeout=10)
            await _wait_for_postgres_blocker(db.bind, transfer_pid, identity_pid)
            await identity_worker.commit()
            locked = await asyncio.wait_for(reading, timeout=10)
            await transfer_worker.commit()
        else:
            reading = asyncio.create_task(
                service._locked_replication_servers(transfer_worker, holder_id, holder_id)
            )
            await _wait_for_postgres_blocker(db.bind, transfer_pid, gate_pid)
            binding = asyncio.create_task(
                service._bind_storage_identity(
                    identity_worker,
                    identity_holder,
                    replacement_incarnation,
                )
            )
            await _wait_for_postgres_blocker(db.bind, identity_pid, transfer_pid)
            await gate.commit()
            locked = await asyncio.wait_for(reading, timeout=10)
            await _wait_for_postgres_blocker(db.bind, identity_pid, transfer_pid)
            await transfer_worker.commit()
            await asyncio.wait_for(binding, timeout=10)
            await identity_worker.commit()

    assert locked[holder_id].server_id == holder_id
    db.expire_all()
    holder = await db.get(Server, holder_id)
    assert holder.storage_incarnation == replacement_incarnation


@pytest.mark.parametrize(
    "identity_wins",
    [False, True],
    ids=["reconcile-wins", "identity-wins"],
)
async def test_reconcile_reassignment_and_bind_use_fence_before_server(
    pg_session,
    monkeypatch,
    identity_wins,
):
    db, redis = pg_session
    suffix = "identity" if identity_wins else "reconcile"
    source = await _server(db, redis, f"reconcile-source-{suffix}", f"source-host-{suffix}")
    target = await _server(db, redis, f"reconcile-target-{suffix}", f"target-host-{suffix}")
    target_id = target.server_id
    old_incarnation = target.storage_incarnation
    replacement_incarnation = str(uuid.uuid4())
    volume = await _volume(db, 2)
    obj = await _object(db, volume, f"reconcile-object-{suffix}", sha256="6" * 64)
    object_id = obj.object_id
    await _placement(db, obj, source, status="present")
    await service._refresh_object_durability(db, obj, volume=volume)
    await db.commit()

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as identity_worker, factory() as reconcile_worker:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [target_id], shared=False)
        identity_target = await identity_worker.get(Server, target_id)
        identity_pid = await identity_worker.scalar(text("SELECT pg_backend_pid()"))
        reconcile_publication_entered = asyncio.Event()
        reconcile_pid = {}
        original_locked_server_rows = service._locked_storage_publication_server_rows

        async def observed_locked_server_rows(lock_db, server_ids):
            normalized = {str(server_id) for server_id in server_ids}
            if (
                lock_db is reconcile_worker
                and target_id in normalized
                and not reconcile_publication_entered.is_set()
            ):
                # reconcile_storage commits between phases and may therefore reconnect. Capture
                # the backend that actually joins this publication frontier, not an earlier PID.
                reconcile_pid["value"] = await lock_db.scalar(text("SELECT pg_backend_pid()"))
                reconcile_publication_entered.set()
            return await original_locked_server_rows(lock_db, server_ids)

        monkeypatch.setattr(
            service,
            "_locked_storage_publication_server_rows",
            observed_locked_server_rows,
        )

        binding = None
        reconciling = None
        try:
            if identity_wins:
                binding = asyncio.create_task(
                    service._bind_storage_identity(
                        identity_worker,
                        identity_target,
                        replacement_incarnation,
                    )
                )
                await _wait_for_postgres_blocker(db.bind, identity_pid, gate_pid)
                reconciling = asyncio.create_task(
                    service.reconcile_storage(reconcile_worker, 10)
                )
                await asyncio.wait_for(reconcile_publication_entered.wait(), timeout=10)
                await _wait_for_postgres_blocker(
                    db.bind,
                    reconcile_pid["value"],
                    identity_pid,
                )
                await gate.commit()
                await asyncio.wait_for(binding, timeout=10)
                await _wait_for_postgres_blocker(
                    db.bind,
                    reconcile_pid["value"],
                    identity_pid,
                )
                await identity_worker.commit()
                summary = await asyncio.wait_for(reconciling, timeout=20)
            else:
                reconciling = asyncio.create_task(
                    service.reconcile_storage(reconcile_worker, 10)
                )
                await asyncio.wait_for(reconcile_publication_entered.wait(), timeout=10)
                await _wait_for_postgres_blocker(
                    db.bind,
                    reconcile_pid["value"],
                    gate_pid,
                )
                binding = asyncio.create_task(
                    service._bind_storage_identity(
                        identity_worker,
                        identity_target,
                        replacement_incarnation,
                    )
                )
                await _wait_for_postgres_blocker(
                    db.bind,
                    identity_pid,
                    reconcile_pid["value"],
                )
                await gate.commit()
                summary = await asyncio.wait_for(reconciling, timeout=20)
                await asyncio.wait_for(binding, timeout=10)
                await identity_worker.commit()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            for task in (binding, reconciling):
                if task is not None and not task.done():
                    task.cancel()
            pending_tasks = [task for task in (binding, reconciling) if task is not None]
            if pending_tasks:
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        asyncio.gather(*pending_tasks, return_exceptions=True),
                        timeout=10,
                    )
            if identity_worker.in_transaction():
                await identity_worker.rollback()
            if reconcile_worker.in_transaction():
                await reconcile_worker.rollback()

    db.expire_all()
    target = await db.get(Server, target_id)
    placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == object_id,
                ReplicaPlacement.server_id == target_id,
            )
        )
    ).scalar_one_or_none()
    assert target.storage_incarnation == replacement_incarnation
    assert summary["object_failures"] == 0
    assert summary["reassigned"] == 1
    assert placement is not None
    assert placement.status == "pending"
    assert placement.storage_incarnation == (
        replacement_incarnation if identity_wins else old_incarnation
    )


async def test_bind_revalidates_authority_after_waiting_for_publication_fence(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "bind-authority-holder", "bind-authority-host")
    holder_id = holder.server_id
    incarnation = holder.storage_incarnation
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as binder, factory() as mutator:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        stale_authority = await binder.get(Server, holder_id)
        binder_pid = await binder.scalar(text("SELECT pg_backend_pid()"))
        binding = asyncio.create_task(
            service._bind_storage_identity(binder, stale_authority, incarnation)
        )
        await _wait_for_postgres_blocker(db.bind, binder_pid, gate_pid)
        await mutator.execute(
            update(Server)
            .where(Server.server_id == holder_id)
            .values(attested_cert_pubkey_hash="f" * 64)
        )
        await mutator.commit()
        await gate.commit()
        with pytest.raises(HTTPException) as rejected:
            await asyncio.wait_for(binding, timeout=10)
        assert rejected.value.status_code == 403
        assert "attested certificate changed" in rejected.value.detail
        await binder.rollback()


async def test_bind_rejects_newer_failed_attestation_after_publication_wait(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "bind-attestation-holder", "bind-attestation-host")
    holder_id = holder.server_id
    old_incarnation = holder.storage_incarnation
    replacement_incarnation = str(uuid.uuid4())
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as binder, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        stale_authority = await binder.get(Server, holder_id)
        binder_pid = await binder.scalar(text("SELECT pg_backend_pid()"))
        binding = asyncio.create_task(
            service._bind_storage_identity(
                binder,
                stale_authority,
                replacement_incarnation,
            )
        )
        await _wait_for_postgres_blocker(db.bind, binder_pid, gate_pid)
        await _commit_failed_attestation(attestor, holder_id)
        await gate.commit()
        with pytest.raises(HTTPException) as rejected:
            await asyncio.wait_for(binding, timeout=10)
        assert rejected.value.status_code == 403
        assert "latest attestation" in rejected.value.detail
        await binder.rollback()

    db.expire_all()
    holder = await db.get(Server, holder_id)
    assert holder.storage_incarnation == old_incarnation
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageIncarnationRetirementAudit)
            .where(StorageIncarnationRetirementAudit.server_id == holder_id)
        )
        == 0
    )


async def test_erase_claim_rejects_newer_failed_attestation_after_publication_wait(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "claim-attestation-holder", "claim-attestation-host")
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    generation = await _object(
        db,
        volume,
        "claim-attestation-generation",
        sha256="7" * 64,
        size_bytes=29,
    )
    await _placement(db, generation, holder, status="present")
    await service.delete_object(db, volume, generation.object_key)
    task = (
        await db.execute(
            select(StorageEraseTask).where(StorageEraseTask.object_id == generation.object_id)
        )
    ).scalar_one()
    task_id = task.task_id

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as claimant, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        stale_caller = await claimant.get(Server, holder_id)
        claimant_pid = await claimant.scalar(text("SELECT pg_backend_pid()"))
        claiming = asyncio.create_task(service.claim_erase_tasks(claimant, stale_caller, 10))
        await _wait_for_postgres_blocker(db.bind, claimant_pid, gate_pid)
        await _commit_failed_attestation(attestor, holder_id)
        await gate.commit()
        assert await asyncio.wait_for(claiming, timeout=10) == []

    db.expire_all()
    task = await db.get(StorageEraseTask, task_id)
    assert task.state == "pending"
    assert task.claimed_at is None
    assert task.claim_cert_pubkey_hash is None
    assert task.attempt_count == 0


async def test_certificate_rebind_rejects_newer_failed_attestation_after_wait(pg_session):
    db, redis = pg_session
    old_identity = _attested_identity("rebind-attestation-old")
    holder = await _server(
        db,
        redis,
        "rebind-attestation-holder",
        "rebind-attestation-host",
        attested_identity=old_identity,
    )
    holder_id = holder.server_id
    incarnation = holder.storage_incarnation
    old_cert_hash = holder.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    obj = await _object(db, volume, "rebind-attestation-object", sha256="8" * 64, size_bytes=31)
    placement = await _placement(db, obj, holder, status="present")
    object_id = obj.object_id
    object_sha256 = obj.sha256
    object_size = obj.ciphertext_size_bytes
    placement_id = placement.placement_id
    await service._refresh_object_durability(db, obj, volume=volume)
    await db.commit()

    new_identity = _attested_identity("rebind-attestation-new")
    holder.attested_cert = new_identity[1].public_bytes(serialization.Encoding.PEM).decode()
    holder.attested_cert_pubkey_hash = get_public_key_hash(new_identity[1])
    assert await service._refresh_object_durability(db, obj, volume=volume) == 0
    await db.commit()
    new_cert_hash = holder.attested_cert_pubkey_hash
    request_id = str(uuid.uuid4())

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as rebinder, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        caller = await rebinder.get(Server, holder_id)
        rebinder_pid = await rebinder.scalar(text("SELECT pg_backend_pid()"))
        rebinding = asyncio.create_task(
            service.rebind_replica_certificates(
                rebinder,
                caller,
                request_id=request_id,
                storage_incarnation=incarnation,
                old_cert_pubkey_hash=old_cert_hash,
                placements=[
                    {
                        "object_id": object_id,
                        "ciphertext_sha256": object_sha256,
                        "ciphertext_size_bytes": object_size,
                    }
                ],
            )
        )
        await _wait_for_postgres_blocker(db.bind, rebinder_pid, gate_pid)
        await _commit_failed_attestation(attestor, holder_id)
        await gate.commit()
        with pytest.raises(HTTPException) as rejected:
            await asyncio.wait_for(rebinding, timeout=10)
        assert rejected.value.status_code == 409
        assert "latest-successfully-attested" in rejected.value.detail
        await rebinder.rollback()

    db.expire_all()
    placement = await db.get(ReplicaPlacement, placement_id)
    obj = await db.get(StorageObject, object_id)
    assert placement.target_cert_pubkey_hash == old_cert_hash
    assert obj.durable_replica_count == 0
    assert obj.durability_state != "healthy"
    assert await db.get(StorageReplicaCertRebindAudit, request_id) is None
    assert new_cert_hash != old_cert_hash


async def test_deferred_active_placement_guard_validates_final_committed_identity(pg_session):
    db, redis = pg_session
    trigger_flags = (
        await db.execute(
            text(
                """
                SELECT tgconstraint <> 0, tgdeferrable, tginitdeferred
                  FROM pg_trigger
                 WHERE tgrelid = 'replica_placement'::regclass
                   AND tgname = 'trg_active_replica_storage_identity_at_commit'
                """
            )
        )
    ).one()
    assert tuple(trigger_flags) == (True, True, True)

    holder = await _server(db, redis, "deferred-placement-holder", "deferred-placement-host")
    holder_id = holder.server_id
    old_incarnation = holder.storage_incarnation
    old_cert_hash = holder.attested_cert_pubkey_hash
    volume = await _volume(db, 1)
    rejected_object = await _object(db, volume, "deferred-stale-active", size_bytes=13)
    evicted_object = await _object(db, volume, "deferred-final-evicted", size_bytes=17)
    pre_retirement_object = await _object(db, volume, "deferred-pre-retirement", size_bytes=19)
    rejected_object_id = rejected_object.object_id
    evicted_object_id = evicted_object.object_id
    pre_retirement_object_id = pre_retirement_object.object_id

    await service._bind_storage_identity(db, holder, str(uuid.uuid4()))
    await db.commit()

    def pending_placement(
        object_id: str,
        incarnation: str,
        cert_hash: str,
    ) -> ReplicaPlacement:
        now = datetime.now(timezone.utc)
        return ReplicaPlacement(
            object_id=object_id,
            server_id=holder_id,
            status="pending",
            storage_incarnation=incarnation,
            target_cert_pubkey_hash=cert_hash,
            pending_since=now,
            pending_deadline=now + timedelta(hours=1),
            attempt_count=1,
        )

    stale_active = pending_placement(rejected_object_id, old_incarnation, old_cert_hash)
    db.add(stale_active)
    await db.flush()
    with pytest.raises(DBAPIError):
        await db.commit()
    await db.rollback()

    # The deferred event from the active INSERT must inspect the row's final state. An inactive
    # final row is valid even though its intermediate pending identity has since been retired.
    final_evicted = pending_placement(evicted_object_id, old_incarnation, old_cert_hash)
    db.add(final_evicted)
    await db.flush()
    final_evicted.status = "evicted"
    await db.flush()
    await db.commit()
    assert final_evicted.status == "evicted"

    db.expire_all()
    current_holder = await db.get(Server, holder_id)
    publisher_first = pending_placement(
        pre_retirement_object_id,
        current_holder.storage_incarnation,
        current_holder.attested_cert_pubkey_hash,
    )
    db.add(publisher_first)
    await db.commit()
    published_incarnation = current_holder.storage_incarnation
    await service._bind_storage_identity(db, current_holder, str(uuid.uuid4()))
    await db.commit()
    await db.refresh(publisher_first)
    assert publisher_first.status == "pending"
    assert publisher_first.storage_incarnation == published_incarnation


async def test_placement_skips_full_nodes_and_never_duplicates_hosts(pg_session):
    db, redis = pg_session
    full = await _server(db, redis, "full", "shared-host", disk_free_gb=10)
    roomy_same_host = await _server(db, redis, "roomy-a", "shared-host", disk_free_gb=100)
    roomy_b = await _server(db, redis, "roomy-b", "host-b", disk_free_gb=80)
    roomy_c = await _server(db, redis, "roomy-c", "host-c", disk_free_gb=70)
    reserved = await _server(db, redis, "reserved", "host-reserved", disk_free_gb=200)
    volume = await _volume(db, 3)
    reservation = await _object(
        db,
        volume,
        "obj-reservation",
        size_bytes=190 * 1024**3,
    )
    await _placement(db, reservation, reserved, status="pending")

    obj, peers = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), "capacity-key", 2 * 1024**3
    )
    peer_ids = {peer.server_id for peer in peers}
    hosts = {
        server.host_id
        for server in (roomy_same_host, roomy_b, roomy_c)
        if server.server_id in peer_ids
    }
    assert obj.projected_size_bytes == 2 * 1024**3
    assert full.server_id not in peer_ids
    assert reserved.server_id not in peer_ids
    assert len(peers) == 3
    assert len(hosts) == 3


async def _store_generation_receipt(
    db: AsyncSession,
    server: Server,
    generation: StorageObject,
    ciphertext_sha256: str,
) -> None:
    recorded = await service.announce_replicas(
        db,
        MINER,
        server.server_id,
        server.server_id,
        server.storage_incarnation,
        [
            {
                "object_id": generation.object_id,
                "status": "stored",
                "ciphertext_sha256": ciphertext_sha256,
                "ciphertext_size_bytes": max(1, int(generation.projected_size_bytes)),
                "plaintext_size_bytes": int(generation.projected_size_bytes),
                "plaintext_sha256": hashlib.sha256(
                    f"plaintext:{generation.object_id}".encode()
                ).hexdigest(),
            }
        ],
    )
    assert recorded == 1


async def _commit_generation(
    db: AsyncSession,
    volume_id: str,
    generation_id: str,
    key: str,
    size_bytes: int,
    ciphertext_sha256: str,
    plaintext_sha256: str,
    server_id: str,
):
    volume = await db.get(StorageVolume, volume_id)
    generation = await db.get(StorageObject, generation_id)
    return await service.commit_object(
        db,
        volume,
        generation_id,
        key,
        salt=generation.salt,
    )


async def test_concurrent_first_put_commits_are_serialized_by_generation_cas(
    pg_session,
):
    db, redis = pg_session
    server = await _server(db, redis, "cas-target", "cas-host")
    volume = await _volume(db, 1)
    volume_id = volume.volume_id
    first, _ = await service.plan_object_placement(db, volume, str(uuid.uuid4()), "shared-key", 11)
    second, _ = await service.plan_object_placement(db, volume, str(uuid.uuid4()), "shared-key", 17)
    first_id = first.object_id
    second_id = second.object_id
    assert first.object_id != second.object_id
    assert first.expected_predecessor_id is None
    assert second.expected_predecessor_id is None
    await _store_generation_receipt(db, server, first, "a" * 64)
    await _store_generation_receipt(db, server, second, "b" * 64)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def _race(generation, size, ciphertext, plaintext):
        async with factory() as contender:
            return await _commit_generation(
                contender,
                volume_id,
                generation.object_id,
                "shared-key",
                size,
                ciphertext,
                plaintext,
                server.server_id,
            )

    results = await asyncio.gather(
        _race(first, 11, "a" * 64, "c" * 64),
        _race(second, 17, "b" * 64, "d" * 64),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    conflicts = [result for result in results if isinstance(result, HTTPException)]
    assert len(conflicts) == 1
    assert conflicts[0].status_code == 409

    db.expire_all()
    current = (
        await db.execute(
            select(StorageObject).where(
                StorageObject.volume_id == volume_id,
                StorageObject.object_key == "shared-key",
                StorageObject.lifecycle_state == "committed",
            )
        )
    ).scalar_one()
    loser_id = first_id if current.object_id == second_id else second_id
    loser = await db.get(StorageObject, loser_id)
    volume = await db.get(StorageVolume, volume_id)
    assert loser.lifecycle_state == "tombstoned"
    assert volume.used_bytes == current.size_bytes


async def test_reordered_commit_loses_cas_without_replacing_winner(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "order-target", "order-host")
    volume = await _volume(db, 1)
    old = await _object(db, volume, "old-generation", sha256="1" * 64, size_bytes=9)
    await _placement(db, old, server, status="present")
    volume.used_bytes = 9
    await db.commit()

    earlier, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), "key-old-generation", 13
    )
    later, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), "key-old-generation", 21
    )
    assert earlier.expected_predecessor_id == old.object_id
    assert later.expected_predecessor_id == old.object_id
    await _store_generation_receipt(db, server, earlier, "2" * 64)
    await _store_generation_receipt(db, server, later, "3" * 64)

    await _commit_generation(
        db,
        volume.volume_id,
        later.object_id,
        later.object_key,
        21,
        "3" * 64,
        "4" * 64,
        server.server_id,
    )
    with pytest.raises(HTTPException) as stale:
        await _commit_generation(
            db,
            volume.volume_id,
            earlier.object_id,
            earlier.object_key,
            13,
            "2" * 64,
            "5" * 64,
            server.server_id,
        )
    assert stale.value.status_code == 409
    await db.refresh(old)
    await db.refresh(earlier)
    await db.refresh(later)
    await db.refresh(volume)
    assert old.lifecycle_state == "superseded"
    assert later.lifecycle_state == "committed"
    assert earlier.lifecycle_state == "tombstoned"
    assert volume.used_bytes == 21
    assert volume.grant_revocation_epoch == 1


async def test_repeated_overwrites_detach_terminal_chain_and_purge_in_bounds(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "chain-holder", "chain-host")
    volume = await _volume(db, 1)
    current = await _object(
        db,
        volume,
        "chain-generation-0",
        sha256="1" * 64,
        size_bytes=5,
        object_key="chain-key",
    )
    await _placement(db, current, holder, status="present")
    volume.used_bytes = 5
    await db.commit()
    retired_ids = []
    for index in range(1, 4):
        replacement, _ = await service.plan_object_placement(
            db,
            volume,
            str(uuid.uuid4()),
            "chain-key",
            5 + index,
        )
        assert replacement.expected_predecessor_id == current.object_id
        await _store_generation_receipt(
            db,
            holder,
            replacement,
            f"{index + 1:x}" * 64,
        )
        await service.commit_object(
            db,
            volume,
            replacement.object_id,
            replacement.object_key,
            replacement.salt,
        )
        retired_ids.append(current.object_id)
        current = replacement
    current_id = current.object_id

    claimed = await service.claim_erase_tasks(db, holder, 100)
    retired_tasks = [task for task in claimed if task["object_id"] in set(retired_ids)]
    assert {task["object_id"] for task in retired_tasks} == set(retired_ids)
    for task in retired_tasks:
        await service.record_erase_task_result(
            db,
            holder,
            task["task_id"],
            "erased",
            True,
            None,
        )

    for _ in range(20):
        await service.reconcile_storage(db, max_objects=2)
        remaining = (
            await db.execute(
                select(func.count())
                .select_from(StorageObject)
                .where(StorageObject.object_id.in_(retired_ids))
            )
        ).scalar_one()
        if remaining == 0:
            break
    assert remaining == 0
    db.expire_all()
    current = await db.get(StorageObject, current_id)
    assert current.lifecycle_state == "committed"
    assert current.expected_predecessor_id is None
    assert current.detached_predecessor_id == retired_ids[-1]
    audit_tasks = list(
        (
            await db.execute(
                select(StorageEraseTask).where(StorageEraseTask.object_id.in_(retired_ids))
            )
        )
        .scalars()
        .all()
    )
    assert {task.object_id for task in audit_tasks} == set(retired_ids)
    assert all(task.metadata_purged_at is not None for task in audit_tasks)


async def test_terminal_predecessor_is_retained_while_pending_cas_depends_on_it(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "pending-chain-holder", "pending-chain-host")
    volume = await _volume(db, 1)
    volume_id = volume.volume_id
    base = await _object(
        db,
        volume,
        "pending-chain-base",
        sha256="a" * 64,
        size_bytes=5,
        object_key="pending-chain-key",
    )
    await _placement(db, base, holder, status="present")
    volume.used_bytes = 5
    await db.commit()
    stale, _ = await service.plan_object_placement(
        db,
        volume,
        str(uuid.uuid4()),
        base.object_key,
        6,
    )
    winner, _ = await service.plan_object_placement(
        db,
        volume,
        str(uuid.uuid4()),
        base.object_key,
        7,
    )
    await _store_generation_receipt(db, holder, stale, "b" * 64)
    await _store_generation_receipt(db, holder, winner, "c" * 64)
    await service.commit_object(
        db,
        volume,
        winner.object_id,
        winner.object_key,
        winner.salt,
    )
    base_id = base.object_id
    stale_id = stale.object_id
    winner_id = winner.object_id
    claimed = await service.claim_erase_tasks(db, holder, 100)
    base_task = next(task for task in claimed if task["object_id"] == base_id)
    await service.record_erase_task_result(
        db,
        holder,
        base_task["task_id"],
        "erased",
        True,
        None,
    )

    await service._finalize_erasure_batch(db, limit=100)
    db.expire_all()
    assert await db.get(StorageObject, base_id) is not None
    assert (await db.get(StorageObject, stale_id)).expected_predecessor_id == base_id

    stale = await db.get(StorageObject, stale_id)
    volume = await db.get(StorageVolume, volume_id)
    with pytest.raises(HTTPException) as conflict:
        await service.commit_object(
            db,
            volume,
            stale.object_id,
            stale.object_key,
            stale.salt,
        )
    assert conflict.value.status_code == 409
    await service._finalize_erasure_batch(db, limit=100)
    db.expire_all()
    assert await db.get(StorageObject, base_id) is None
    winner = await db.get(StorageObject, winner_id)
    assert winner.expected_predecessor_id is None
    assert winner.detached_predecessor_id == base_id


async def test_delayed_commit_after_delete_cannot_resurrect_generation(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "delete-target", "delete-host")
    volume = await _volume(db, 1)
    old = await _object(db, volume, "delete-old", sha256="6" * 64, size_bytes=8)
    await _placement(db, old, server, status="present")
    volume.used_bytes = 8
    await db.commit()
    replacement, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), old.object_key, 12
    )
    await _store_generation_receipt(db, server, replacement, "7" * 64)

    deleted, used, erase_tasks_pending = await service.delete_object(db, volume, old.object_key)
    assert deleted.object_id == old.object_id
    assert used == 0
    assert erase_tasks_pending >= 1
    with pytest.raises(HTTPException) as delayed:
        await _commit_generation(
            db,
            volume.volume_id,
            replacement.object_id,
            replacement.object_key,
            12,
            "7" * 64,
            "8" * 64,
            server.server_id,
        )
    assert delayed.value.status_code == 409
    await db.refresh(old)
    await db.refresh(replacement)
    assert old.lifecycle_state == "tombstoned"
    assert replacement.lifecycle_state == "tombstoned"
    assert (
        await db.execute(
            select(func.count())
            .select_from(StorageObject)
            .where(
                StorageObject.volume_id == volume.volume_id,
                StorageObject.object_key == old.object_key,
                StorageObject.lifecycle_state == "committed",
            )
        )
    ).scalar_one() == 0


async def test_delete_object_uses_bounded_fence_pages(pg_session, monkeypatch):
    db, redis = pg_session
    monkeypatch.setattr(settings, "storage_reconcile_batch_size", 2)
    holder = await _server(db, redis, "delete-fence-holder", "delete-fence-host")
    volume = await _volume(db, 1)
    volume_id = volume.volume_id
    old = await _object(
        db,
        volume,
        "delete-fence-old",
        sha256="a" * 64,
        size_bytes=5,
        object_key="bounded-delete",
    )
    await _placement(db, old, holder, status="present")
    volume.used_bytes = 5
    await db.commit()
    pending = []
    for index in range(5):
        generation, _ = await service.plan_object_placement(
            db,
            volume,
            str(uuid.uuid4()),
            "bounded-delete",
            index + 1,
        )
        await _store_generation_receipt(
            db,
            holder,
            generation,
            f"{index + 1:x}" * 64,
        )
        pending.append(generation)

    class SkewedApiDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) - timedelta(days=1)

    # StorageObject.created_at is assigned by PostgreSQL. A skewed API host clock must not place
    # generations that already exist before this owner-delete outside the durable cutoff.
    monkeypatch.setattr(service, "datetime", SkewedApiDateTime)
    await service.delete_object(db, volume, "bounded-delete")
    fence = (
        await db.execute(
            select(StorageObjectDeleteFence).where(
                StorageObjectDeleteFence.volume_id == volume_id,
                StorageObjectDeleteFence.object_key == "bounded-delete",
            )
        )
    ).scalar_one()
    fence_id = fence.fence_id
    assert fence.completed_at is None
    tombstoned = (
        await db.execute(
            select(func.count())
            .select_from(StorageObject)
            .where(
                StorageObject.volume_id == volume_id,
                StorageObject.object_key == "bounded-delete",
                StorageObject.lifecycle_state == "tombstoned",
            )
        )
    ).scalar_one()
    assert tombstoned <= 2

    still_pending = None
    for generation in pending:
        refreshed = await db.get(StorageObject, generation.object_id)
        if refreshed.lifecycle_state == "pending":
            still_pending = refreshed
            break
    assert still_pending is not None
    with pytest.raises(HTTPException) as fenced:
        await service.commit_object(
            db,
            volume,
            still_pending.object_id,
            still_pending.object_key,
            still_pending.salt,
        )
    assert fenced.value.status_code == 409

    for _ in range(10):
        await service.reconcile_storage(db, max_objects=2)
        db.expire_all()
        fence = await db.get(StorageObjectDeleteFence, fence_id)
        if fence.completed_at is not None:
            break
    assert fence.completed_at is not None
    assert (
        await db.execute(
            select(func.count())
            .select_from(StorageObject)
            .where(
                StorageObject.volume_id == volume_id,
                StorageObject.object_key == "bounded-delete",
                StorageObject.lifecycle_state != "tombstoned",
            )
        )
    ).scalar_one() == 0


async def test_overwrite_quota_reserves_positive_delta_and_releases_expiry(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "quota-delta-target", "quota-delta-host")
    server_id = server.server_id
    user = await db.get(User, USER_ID)
    user.storage_volume_quota_bytes = 10
    user.storage_aggregate_quota_bytes = 100
    await db.commit()

    volume = await _volume(db, 1)
    volume.quota_bytes = 10
    predecessor = await _object(
        db,
        volume,
        "quota-delta-predecessor",
        sha256="a" * 64,
        size_bytes=8,
        object_key="quota-delta-key",
    )
    await _placement(db, predecessor, server, status="present")
    volume.used_bytes = 8
    await db.commit()

    expired_ids = []

    async def reserve_then_expire(current_volume, key, size):
        generation, _ = await service.plan_object_placement(
            db, current_volume, str(uuid.uuid4()), key, size
        )
        placement = (
            await db.execute(
                select(ReplicaPlacement).where(ReplicaPlacement.object_id == generation.object_id)
            )
        ).scalar_one()
        placement.pending_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
        expired_ids.append(generation.object_id)
        return generation

    for size in (7, 8, 10):
        replacement = await reserve_then_expire(volume, predecessor.object_key, size)
        assert replacement.expected_predecessor_id == predecessor.object_id

    with pytest.raises(HTTPException) as volume_limit:
        await service.plan_object_placement(
            db, volume, str(uuid.uuid4()), predecessor.object_key, 11
        )
    assert volume_limit.value.status_code == 413
    assert "Volume quota exceeded" in volume_limit.value.detail
    await db.rollback()
    server = await db.get(Server, server_id)
    assert server is not None

    # Exercise aggregate accounting separately: 16 committed bytes plus a 2-byte overwrite delta
    # exactly fits; a 3-byte delta does not. Expired reservations from the first volume stay free.
    user = await db.get(User, USER_ID)
    user.storage_volume_quota_bytes = 100
    user.storage_aggregate_quota_bytes = 18
    await db.commit()
    aggregate_volume = await _volume(db, 1)
    aggregate_volume.quota_bytes = 100
    aggregate_predecessor = await _object(
        db,
        aggregate_volume,
        "aggregate-delta-predecessor",
        sha256="b" * 64,
        size_bytes=8,
        object_key="aggregate-delta-key",
    )
    await _placement(db, aggregate_predecessor, server, status="present")
    aggregate_volume.used_bytes = 8
    await db.commit()

    replacement = await reserve_then_expire(aggregate_volume, aggregate_predecessor.object_key, 10)
    assert replacement.expected_predecessor_id == aggregate_predecessor.object_id
    with pytest.raises(HTTPException) as aggregate_limit:
        await service.plan_object_placement(
            db,
            aggregate_volume,
            str(uuid.uuid4()),
            aggregate_predecessor.object_key,
            11,
        )
    assert aggregate_limit.value.status_code == 413
    assert "Account storage quota exceeded" in aggregate_limit.value.detail
    await db.rollback()

    summary = await service.reconcile_storage(db)
    assert summary["expired_reservations"] == len(expired_ids) == 4
    for object_id in expired_ids:
        assert (await db.get(StorageObject, object_id)).lifecycle_state == "tombstoned"


async def test_duplicate_commit_is_idempotent_and_accounts_once(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "duplicate-target", "duplicate-host")
    volume = await _volume(db, 1)
    generation, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), "duplicate", 14
    )
    await _store_generation_receipt(db, server, generation, "9" * 64)

    first, first_replicas = await _commit_generation(
        db,
        volume.volume_id,
        generation.object_id,
        generation.object_key,
        14,
        "9" * 64,
        "a" * 64,
        server.server_id,
    )
    duplicate, duplicate_replicas = await _commit_generation(
        db,
        volume.volume_id,
        generation.object_id,
        generation.object_key,
        14,
        "9" * 64,
        "a" * 64,
        server.server_id,
    )
    await db.refresh(volume)
    assert first.object_id == duplicate.object_id
    assert first_replicas == duplicate_replicas == 1
    assert volume.used_bytes == 14


async def test_locate_and_list_switch_only_after_generation_commit(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "visibility-target", "visibility-host")
    volume = await _volume(db, 1)
    old = await _object(db, volume, "visibility-old", sha256="e" * 64, size_bytes=6)
    await _placement(db, old, server, status="present")
    volume.used_bytes = 6
    await db.commit()
    replacement, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), old.object_key, 15
    )

    located_before, _peers, _count = await service.locate_object(db, volume, old.object_key)
    listed_before = await service.list_objects(db, volume, None, 100)
    assert located_before.object_id == old.object_id
    assert [item.object_id for item in listed_before] == [old.object_id]

    await _store_generation_receipt(db, server, replacement, "f" * 64)
    await _commit_generation(
        db,
        volume.volume_id,
        replacement.object_id,
        replacement.object_key,
        15,
        "f" * 64,
        "0" * 64,
        server.server_id,
    )
    located_after, _peers, _count = await service.locate_object(db, volume, old.object_key)
    listed_after = await service.list_objects(db, volume, None, 100)
    await db.refresh(old)
    await db.refresh(volume)
    assert located_after.object_id == replacement.object_id
    assert [item.object_id for item in listed_after] == [replacement.object_id]
    assert old.lifecycle_state == "superseded"
    assert volume.grant_revocation_epoch == 1


async def test_empty_commit_is_distinct_from_abandoned_pending_reservation(
    pg_session,
):
    db, redis = pg_session
    server = await _server(db, redis, "empty-target", "empty-host")
    volume = await _volume(db, 1)
    empty, _ = await service.plan_object_placement(db, volume, str(uuid.uuid4()), "empty", 0)
    abandoned, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), "abandoned", 0
    )
    await _store_generation_receipt(db, server, empty, "1" * 64)
    await _commit_generation(
        db,
        volume.volume_id,
        empty.object_id,
        empty.object_key,
        0,
        "1" * 64,
        hashlib.sha256(b"").hexdigest(),
        server.server_id,
    )
    abandoned.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    await db.commit()

    listed = await service.list_objects(db, volume, None, 100)
    assert [(item.object_key, item.size_bytes) for item in listed] == [("empty", 0)]
    summary = await service.reconcile_storage(db)
    await db.refresh(empty)
    await db.refresh(abandoned)
    await db.refresh(volume)
    assert summary["reaped_abandoned"] == 1
    assert empty.lifecycle_state == "committed"
    assert abandoned.lifecycle_state == "tombstoned"
    assert volume.used_bytes == 0


async def test_database_failure_rolls_back_entire_generation_swap(pg_session):
    db, redis = pg_session
    server = await _server(db, redis, "failure-target", "failure-host")
    volume = await _volume(db, 1)
    old = await _object(db, volume, "failure-old", sha256="b" * 64, size_bytes=10)
    old_id = old.object_id
    volume_id = volume.volume_id
    await _placement(db, old, server, status="present")
    volume.used_bytes = 10
    await db.commit()
    replacement, _ = await service.plan_object_placement(
        db, volume, str(uuid.uuid4()), old.object_key, 19
    )
    replacement_id = replacement.object_id
    replacement_key = replacement.object_key
    await _store_generation_receipt(db, server, replacement, "c" * 64)
    await db.execute(
        text(
            """
            CREATE FUNCTION fail_transactional_generation_swap() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.lifecycle_state = 'pending'
                   AND NEW.lifecycle_state = 'committed' THEN
                    RAISE EXCEPTION 'injected validator transaction failure';
                END IF;
                RETURN NEW;
            END
            $$
            """
        )
    )
    await db.execute(
        text(
            """
            CREATE TRIGGER zz_fail_transactional_generation_swap
            BEFORE UPDATE ON storage_objects
            FOR EACH ROW EXECUTE FUNCTION fail_transactional_generation_swap()
            """
        )
    )
    await db.commit()

    with pytest.raises(Exception, match="injected validator transaction failure"):
        await _commit_generation(
            db,
            volume_id,
            replacement_id,
            replacement_key,
            19,
            "c" * 64,
            "d" * 64,
            server.server_id,
        )
    await db.rollback()
    db.expire_all()
    old = await db.get(StorageObject, old_id)
    replacement = await db.get(StorageObject, replacement_id)
    volume = await db.get(StorageVolume, volume_id)
    assert old.lifecycle_state == "committed"
    assert replacement.lifecycle_state == "pending"
    assert volume.used_bytes == 10


async def test_offline_delete_rejoins_erases_exact_generation_then_purges(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "erase-holder", "erase-host")
    volume = await _volume(db, 1)
    generation = await _object(db, volume, "erase-generation", sha256="a" * 64, size_bytes=31)
    placement = await _placement(db, generation, holder, status="present")
    volume.used_bytes = 31
    await db.commit()

    deleted, used_bytes, pending = await service.delete_object(db, volume, generation.object_key)
    assert deleted.object_id == generation.object_id
    assert used_bytes == 0
    assert pending == 1
    task = (
        await db.execute(
            select(StorageEraseTask).where(StorageEraseTask.object_id == generation.object_id)
        )
    ).scalar_one()
    task_id = task.task_id
    generation_id = generation.object_id
    placement_id = placement.placement_id
    assert task.server_id == holder.server_id
    assert task.storage_incarnation == holder.storage_incarnation
    assert task.state == "pending"

    # An offline holder does not lose metadata or silently reach a terminal state.
    redis.values.pop(f"storage:online:{holder.server_id}", None)
    await service.reconcile_storage(db)
    await db.refresh(task)
    assert task.state == "pending"
    assert await db.get(StorageObject, generation.object_id) is not None
    assert await db.get(ReplicaPlacement, placement.placement_id) is not None

    await redis.setex(f"storage:online:{holder.server_id}", 180, "1")
    claimed = await service.claim_erase_tasks(db, holder, 10)
    assert [(item["object_id"], item["storage_incarnation"]) for item in claimed] == [
        (generation.object_id, holder.storage_incarnation)
    ]
    result = await service.record_erase_task_result(
        db,
        holder,
        task.task_id,
        "erased",
        True,
        None,
    )
    assert result["terminal"]
    await service.reconcile_storage(db)
    db.expire_all()
    assert await db.get(StorageObject, generation_id) is None
    assert await db.get(ReplicaPlacement, placement_id) is None
    task = await db.get(StorageEraseTask, task_id)
    assert task.state == "erased"
    assert task.metadata_purged_at is not None


async def test_volume_delete_shreds_key_only_after_all_holder_tasks_terminal(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "volume-erase-holder", "volume-erase-host")
    volume = await _volume(db, 1)
    db.add(StorageVolumeKey(volume_id=volume.volume_id, encrypted_key="encrypted-key"))
    generation = await _object(
        db, volume, "volume-erase-generation", sha256="b" * 64, size_bytes=41
    )
    await _placement(db, generation, holder, status="present")
    volume.used_bytes = 41
    await db.commit()

    first = await service.delete_volume(db, volume.volume_id, USER_ID)
    assert first["deleted"]
    assert first["erase_tasks_pending"] == 1
    assert await db.get(StorageVolumeKey, volume.volume_id) is not None
    await service.reconcile_storage(db)
    assert await db.get(StorageVolumeKey, volume.volume_id) is not None

    task = (
        await db.execute(
            select(StorageEraseTask).where(StorageEraseTask.volume_id == volume.volume_id)
        )
    ).scalar_one()
    volume_id = volume.volume_id
    claimed = await service.claim_erase_tasks(db, holder, 10)
    assert [item["task_id"] for item in claimed] == [task.task_id]
    await service.record_erase_task_result(db, holder, task.task_id, "erased", False, None)
    await service.reconcile_storage(db)
    db.expire_all()
    volume = await db.get(StorageVolume, volume_id)
    assert await db.get(StorageVolumeKey, volume.volume_id) is None
    assert volume.key_shredded_at is not None
    assert volume.purged_at is not None
    assert (
        await db.execute(
            select(func.count())
            .select_from(StorageObject)
            .where(StorageObject.volume_id == volume.volume_id)
        )
    ).scalar_one() == 0

    repeated = await service.delete_volume(db, volume.volume_id, USER_ID)
    assert repeated["deleted"]
    assert repeated["key_shredded"]


async def _volume_key_release_fixture(db, redis, prefix: str, placement_status: str = "pending"):
    holder = await _server(db, redis, f"{prefix}-holder", f"{prefix}-host")
    volume = await _volume(db, 1)
    if placement_status == "present":
        obj = await _object(
            db,
            volume,
            f"{prefix}-object",
            sha256="a" * 64,
            size_bytes=41,
        )
    else:
        obj = await _object(db, volume, f"{prefix}-object", size_bytes=41)
    placement = await _placement(db, obj, holder, status=placement_status)
    db.add(StorageVolumeKey(volume_id=volume.volume_id, encrypted_key="encrypted-volume-key"))
    await db.commit()
    return holder, volume, obj, placement


def _mock_volume_key_release_attestation(
    monkeypatch,
    release_db: AsyncSession,
    *,
    paused: bool,
):
    quote_entered = asyncio.Event()
    resume_quote = asyncio.Event()
    if not paused:
        resume_quote.set()
    state = {
        "quote_verified": False,
        "object_lock_entered": False,
        "server_lock_entered": False,
        "decrypt_calls": [],
    }
    original_object_lock = service._lock_storage_object_transactions
    original_server_lock = service._locked_storage_publication_server_rows
    runtime_quote = object()

    monkeypatch.setattr(service, "build_runtime_quote", lambda *args, **kwargs: runtime_quote)

    async def verify_without_database_locks(quote, expected_nonce, expected_cert_hash):
        assert quote is runtime_quote
        assert expected_nonce == "key-release-nonce"
        assert len(expected_cert_hash) == 64
        assert not release_db.in_transaction()
        assert not state["object_lock_entered"]
        assert not state["server_lock_entered"]
        quote_entered.set()
        await resume_quote.wait()
        state["quote_verified"] = True

    async def object_lock_after_quote(lock_db, object_ids):
        assert state["quote_verified"]
        state["object_lock_entered"] = True
        return await original_object_lock(lock_db, object_ids)

    async def server_lock_after_quote(lock_db, server_ids):
        assert state["quote_verified"]
        assert state["object_lock_entered"]
        state["server_lock_entered"] = True
        return await original_server_lock(lock_db, server_ids)

    def record_decryption(encrypted_key):
        assert state["server_lock_entered"]
        state["decrypt_calls"].append(encrypted_key)
        return "decrypted-volume-key"

    monkeypatch.setattr(service, "verify_quote", verify_without_database_locks)
    monkeypatch.setattr(
        service,
        "get_matching_measurement_config",
        lambda quote: _storage_measurement(),
    )
    monkeypatch.setattr(service, "_lock_storage_object_transactions", object_lock_after_quote)
    monkeypatch.setattr(
        service,
        "_locked_storage_publication_server_rows",
        server_lock_after_quote,
    )
    monkeypatch.setattr(service, "decrypt_passphrase", record_decryption)
    return quote_entered, resume_quote, state


def _release_fixture_volume_key(
    db: AsyncSession,
    volume_id: str,
    caller: Server,
    expected_cert_hash: str,
):
    return service.release_volume_key(
        db,
        volume_id,
        caller,
        "mock-runtime-quote",
        "sev-snp",
        None,
        None,
        "key-release-nonce",
        expected_cert_hash,
    )


@pytest.mark.parametrize("placement_status", ("pending", "present"))
async def test_volume_key_release_verifies_quote_before_locks_and_returns_exact_key(
    pg_session,
    monkeypatch,
    placement_status,
):
    db, redis = pg_session
    holder, volume, _obj, _placement_row = await _volume_key_release_fixture(
        db,
        redis,
        f"key-release-success-{placement_status}",
        placement_status,
    )
    _quote_entered, _resume_quote, state = _mock_volume_key_release_attestation(
        monkeypatch,
        db,
        paused=False,
    )

    released = await _release_fixture_volume_key(
        db,
        volume.volume_id,
        holder,
        holder.attested_cert_pubkey_hash,
    )
    assert released == "decrypted-volume-key"
    assert state == {
        "quote_verified": True,
        "object_lock_entered": True,
        "server_lock_entered": True,
        "decrypt_calls": ["encrypted-volume-key"],
    }


@pytest.mark.parametrize(
    "authority_change",
    ("certificate", "incarnation", "failed_attestation"),
    ids=("certificate-replaced", "incarnation-replaced", "newest-attestation-failed"),
)
async def test_volume_key_release_revalidates_authority_after_quote(
    pg_session,
    monkeypatch,
    authority_change,
):
    db, redis = pg_session
    holder, volume, _obj, _placement_row = await _volume_key_release_fixture(
        db,
        redis,
        f"key-release-authority-{authority_change}",
    )
    holder_id = holder.server_id
    volume_id = volume.volume_id
    presented_cert_hash = holder.attested_cert_pubkey_hash
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as releaser, factory() as authority_writer:
        caller = await releaser.get(Server, holder_id)
        quote_entered, resume_quote, state = _mock_volume_key_release_attestation(
            monkeypatch,
            releaser,
            paused=True,
        )
        releasing = asyncio.create_task(
            _release_fixture_volume_key(
                releaser,
                volume_id,
                caller,
                presented_cert_hash,
            )
        )
        try:
            await asyncio.wait_for(quote_entered.wait(), timeout=10)
            assert not releaser.in_transaction()
            if authority_change == "certificate":
                await authority_writer.execute(
                    update(Server)
                    .where(Server.server_id == holder_id)
                    .values(attested_cert_pubkey_hash="f" * 64)
                )
                await asyncio.wait_for(authority_writer.commit(), timeout=5)
            elif authority_change == "incarnation":
                current_holder = await authority_writer.get(Server, holder_id)
                await service._bind_storage_identity(
                    authority_writer,
                    current_holder,
                    str(uuid.uuid4()),
                )
                await asyncio.wait_for(authority_writer.commit(), timeout=5)
            else:
                await asyncio.wait_for(
                    _commit_failed_attestation(authority_writer, holder_id),
                    timeout=5,
                )
            resume_quote.set()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(releasing, timeout=10)
            assert rejected.value.status_code == 403
            assert "storage authority changed" in rejected.value.detail
            await releaser.rollback()
        finally:
            resume_quote.set()
            if not releasing.done():
                releasing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await releasing
            if releaser.in_transaction():
                await releaser.rollback()

    assert state["quote_verified"]
    assert state["decrypt_calls"] == []
    db.expire_all()
    assert await db.get(StorageVolumeKey, volume_id) is not None


@pytest.mark.parametrize(
    "authority_loss",
    ("volume_deleted", "placement_lost"),
    ids=("volume-deleted", "qualifying-placement-lost"),
)
async def test_volume_key_release_revalidates_volume_and_placement_after_quote(
    pg_session,
    monkeypatch,
    authority_loss,
):
    db, redis = pg_session
    holder, volume, _obj, placement = await _volume_key_release_fixture(
        db,
        redis,
        f"key-release-loss-{authority_loss}",
    )
    holder_id = holder.server_id
    volume_id = volume.volume_id
    placement_id = placement.placement_id
    presented_cert_hash = holder.attested_cert_pubkey_hash
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as releaser, factory() as authority_writer:
        caller = await releaser.get(Server, holder_id)
        quote_entered, resume_quote, state = _mock_volume_key_release_attestation(
            monkeypatch,
            releaser,
            paused=True,
        )
        releasing = asyncio.create_task(
            _release_fixture_volume_key(
                releaser,
                volume_id,
                caller,
                presented_cert_hash,
            )
        )
        try:
            await asyncio.wait_for(quote_entered.wait(), timeout=10)
            assert not releaser.in_transaction()
            if authority_loss == "volume_deleted":
                current_volume = await authority_writer.get(StorageVolume, volume_id)
                current_volume.deleted = True
                current_volume.delete_requested_at = datetime.now(timezone.utc)
            else:
                current_placement = await authority_writer.get(
                    ReplicaPlacement,
                    placement_id,
                    with_for_update=True,
                )
                current_placement.status = "evicted"
                current_placement.last_error = "placement_lost_while_quote_verified"
            await asyncio.wait_for(authority_writer.commit(), timeout=5)
            resume_quote.set()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(releasing, timeout=10)
            assert rejected.value.status_code == (
                404 if authority_loss == "volume_deleted" else 403
            )
            await releaser.rollback()
        finally:
            resume_quote.set()
            if not releasing.done():
                releasing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await releasing
            if releaser.in_transaction():
                await releaser.rollback()

    assert state["quote_verified"]
    assert state["decrypt_calls"] == []
    db.expire_all()
    assert await db.get(StorageVolumeKey, volume_id) is not None


async def test_volume_key_release_rechecks_pending_deadline_after_server_lock_wait(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    holder, volume, _obj, placement = await _volume_key_release_fixture(
        db,
        redis,
        "key-release-deadline",
    )
    holder_id = holder.server_id
    volume_id = volume.volume_id
    deadline = datetime.now(timezone.utc) + timedelta(seconds=2)
    placement.pending_deadline = deadline
    await db.commit()

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as releaser:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        caller = await releaser.get(Server, holder_id)
        _quote_entered, _resume_quote, state = _mock_volume_key_release_attestation(
            monkeypatch,
            releaser,
            paused=False,
        )
        publication_entered = asyncio.Event()
        release_pid = {}
        observed_server_lock = service._locked_storage_publication_server_rows

        async def capture_release_backend(lock_db, server_ids):
            if lock_db is releaser and not publication_entered.is_set():
                release_pid["value"] = await lock_db.scalar(text("SELECT pg_backend_pid()"))
                publication_entered.set()
            return await observed_server_lock(lock_db, server_ids)

        monkeypatch.setattr(
            service,
            "_locked_storage_publication_server_rows",
            capture_release_backend,
        )
        releasing = asyncio.create_task(
            _release_fixture_volume_key(
                releaser,
                volume_id,
                caller,
                holder.attested_cert_pubkey_hash,
            )
        )
        try:
            await asyncio.wait_for(publication_entered.wait(), timeout=10)
            await _wait_for_postgres_blocker(db.bind, release_pid["value"], gate_pid)

            async def wait_for_deadline():
                while datetime.now(timezone.utc) <= deadline:
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(wait_for_deadline(), timeout=5)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(releasing, timeout=10)
            assert rejected.value.status_code == 403
            assert "replica authority changed" in rejected.value.detail
            await releaser.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not releasing.done():
                releasing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await releasing
            if releaser.in_transaction():
                await releaser.rollback()

    assert state["decrypt_calls"] == []


async def test_inventory_is_authoritative_only_after_complete_snapshot(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "inventory-holder", "inventory-host")
    volume = await _volume(db, 1)
    generation = await _object(db, volume, "inventory-generation", sha256="c" * 64, size_bytes=51)
    placement = await _placement(db, generation, holder, status="present")
    snapshot_id = str(uuid.uuid4())
    entry = {
        "volume_id": volume.volume_id,
        "object_id": generation.object_id,
        "ciphertext_sha256": generation.sha256,
        "ciphertext_size_bytes": generation.ciphertext_size_bytes,
    }

    await service.record_inventory_page(
        db,
        holder,
        snapshot_id,
        holder.storage_incarnation,
        [entry],
        False,
    )
    await service.reconcile_storage(db)
    await db.refresh(placement)
    assert placement.status == "present"
    assert (await db.get(StorageInventorySnapshot, snapshot_id)).state == "scanning"

    await service.record_inventory_page(
        db,
        holder,
        snapshot_id,
        holder.storage_incarnation,
        [],
        True,
    )
    await service.reconcile_storage(db)
    await db.refresh(placement)
    assert placement.status == "present"
    assert (await db.get(StorageInventorySnapshot, snapshot_id)).state == "reconciled"

    orphan_id = "untracked-finalized-generation"
    orphan_snapshot = str(uuid.uuid4())
    response = await service.record_inventory_page(
        db,
        holder,
        orphan_snapshot,
        holder.storage_incarnation,
        [
            {
                "volume_id": volume.volume_id,
                "object_id": orphan_id,
                "ciphertext_sha256": "d" * 64,
                "ciphertext_size_bytes": 7,
            }
        ],
        True,
    )
    assert response["erase_tasks_enqueued"] == 1
    orphan_task = (
        await db.execute(select(StorageEraseTask).where(StorageEraseTask.object_id == orphan_id))
    ).scalar_one()
    assert orphan_task.reason == "inventory_untracked_or_mismatched_file"

    omission_snapshot = str(uuid.uuid4())
    await service.record_inventory_page(
        db,
        holder,
        omission_snapshot,
        holder.storage_incarnation,
        [],
        True,
    )
    await service.reconcile_storage(db)
    await db.refresh(placement)
    assert placement.status == "evicted"


async def test_inventory_omission_waits_for_locked_rows_without_cursor_loss(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "inventory-lock-holder", "inventory-lock-host")
    volume = await _volume(db, 1)
    first = await _object(db, volume, "inventory-lock-a", sha256="1" * 64)
    second = await _object(db, volume, "inventory-lock-b", sha256="2" * 64)
    first_placement = await _placement(db, first, holder, status="present")
    second_placement = await _placement(db, second, holder, status="present")
    first_placement_id = first_placement.placement_id
    second_placement_id = second_placement.placement_id
    snapshot_id = str(uuid.uuid4())
    await service.record_inventory_page(
        db,
        holder,
        snapshot_id,
        holder.storage_incarnation,
        [],
        True,
    )
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as locker, factory() as reconciler:
        await locker.execute(
            select(ReplicaPlacement)
            .where(ReplicaPlacement.placement_id == first_placement_id)
            .with_for_update()
        )
        reconcile = asyncio.create_task(
            service._reconcile_inventory_omissions(
                reconciler,
                max_snapshots=1,
                max_placements=10,
            )
        )
        await asyncio.sleep(0.05)
        assert not reconcile.done()
        await locker.commit()
        omitted, completed = await asyncio.wait_for(reconcile, timeout=5)
    assert (omitted, completed) == (2, 1)
    db.expire_all()
    assert (await db.get(ReplicaPlacement, first_placement_id)).status == "evicted"
    assert (await db.get(ReplicaPlacement, second_placement_id)).status == "evicted"
    assert (await db.get(StorageInventorySnapshot, snapshot_id)).state == "reconciled"


async def test_inventory_cutoff_preserves_new_and_proven_during_scan_placements(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "inventory-cutoff-holder", "inventory-cutoff-host")
    volume = await _volume(db, 1)
    proving, _ = await service.plan_object_placement(
        db,
        volume,
        str(uuid.uuid4()),
        "proven-during-scan",
        12,
    )
    snapshot_id = str(uuid.uuid4())
    await service.record_inventory_page(
        db,
        holder,
        snapshot_id,
        holder.storage_incarnation,
        [],
        False,
    )

    await _store_generation_receipt(db, holder, proving, "3" * 64)
    await service.commit_object(
        db,
        volume,
        proving.object_id,
        proving.object_key,
        proving.salt,
    )
    new_generation = await _object(
        db,
        volume,
        "created-during-scan",
        sha256="4" * 64,
        size_bytes=9,
    )
    new_placement = await _placement(db, new_generation, holder, status="present")
    proving_placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == proving.object_id,
                ReplicaPlacement.server_id == holder.server_id,
            )
        )
    ).scalar_one()
    snapshot = await db.get(StorageInventorySnapshot, snapshot_id)
    assert proving_placement.proof_at > snapshot.eligibility_cutoff_at
    assert new_placement.created_at > snapshot.eligibility_cutoff_at

    await service.record_inventory_page(
        db,
        holder,
        snapshot_id,
        holder.storage_incarnation,
        [],
        True,
    )
    omitted, completed = await service._reconcile_inventory_omissions(
        db,
        max_snapshots=1,
        max_placements=10,
    )
    assert (omitted, completed) == (0, 1)
    await db.refresh(proving_placement)
    await db.refresh(new_placement)
    assert proving_placement.status == "present"
    assert new_placement.status == "present"


async def test_later_serialized_inventory_sighting_uses_database_wall_clock(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "inventory-order-holder", "inventory-order-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        "inventory-order-object",
        sha256="5" * 64,
        size_bytes=17,
    )
    placement = await _placement(db, obj, holder, status="present")
    placement_id = placement.placement_id
    empty_snapshot_id = str(uuid.uuid4())
    sighting_snapshot_id = str(uuid.uuid4())
    entry = {
        "volume_id": volume.volume_id,
        "object_id": obj.object_id,
        "ciphertext_sha256": obj.sha256,
        "ciphertext_size_bytes": obj.ciphertext_size_bytes,
    }

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as earlier_transaction, factory() as later_transaction:
        # Anchor this transaction before the empty snapshot, but publish its sighting afterward.
        anchored_at = await earlier_transaction.scalar(select(func.now()))
        assert anchored_at is not None
        await asyncio.sleep(0.05)

        later_holder = await later_transaction.get(Server, holder_id)
        await service.record_inventory_page(
            later_transaction,
            later_holder,
            empty_snapshot_id,
            holder_incarnation,
            [],
            True,
        )
        earlier_holder = await earlier_transaction.get(Server, holder_id)
        await service.record_inventory_page(
            earlier_transaction,
            earlier_holder,
            sighting_snapshot_id,
            holder_incarnation,
            [entry],
            True,
        )

    db.expire_all()
    empty_snapshot = await db.get(StorageInventorySnapshot, empty_snapshot_id)
    sighting_snapshot = await db.get(StorageInventorySnapshot, sighting_snapshot_id)
    empty_cutoff = empty_snapshot.eligibility_cutoff_at
    assert empty_snapshot.completed_at < sighting_snapshot.completed_at
    assert sighting_snapshot.completed_at > anchored_at
    assert await service._reconcile_inventory_omissions(
        db,
        max_snapshots=2,
        max_placements=10,
    ) == (0, 2)

    db.expire_all()
    placement = await db.get(ReplicaPlacement, placement_id)
    assert placement.status == "present"
    assert placement.last_inventory_snapshot_id == sighting_snapshot_id
    assert placement.last_inventory_seen_at > empty_cutoff


async def test_attested_receipt_drives_exact_accounting_and_aggregate_quota(pg_session):
    db, redis = pg_session
    user = await db.get(User, USER_ID)
    user.storage_volume_quota_bytes = 20
    user.storage_aggregate_quota_bytes = 15
    await db.commit()
    holder = await _server(db, redis, "accounting-holder", "accounting-host")
    first_volume = await _volume(db, 1)
    first_volume.quota_bytes = 20
    second_volume = await _volume(db, 1)
    second_volume.quota_bytes = 20
    await db.commit()

    generation, _ = await service.plan_object_placement(
        db, first_volume, str(uuid.uuid4()), "trusted-size", 10
    )
    await _store_generation_receipt(db, holder, generation, "e" * 64)
    committed, _ = await service.commit_object(
        db,
        first_volume,
        generation.object_id,
        generation.object_key,
        salt=generation.salt,
    )
    await db.refresh(first_volume)
    assert committed.size_bytes == 10
    assert first_volume.used_bytes == 10

    with pytest.raises(HTTPException) as aggregate:
        await service.plan_object_placement(
            db, second_volume, str(uuid.uuid4()), "aggregate-overage", 6
        )
    assert aggregate.value.status_code == 413
    await db.rollback()


async def test_concurrent_volume_and_placement_creates_are_conflict_safe(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    monkeypatch.setattr(service, "encrypt_passphrase", lambda value: f"enc:{value}")
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    async def create_same_volume():
        async with factory() as contender:
            try:
                volume, _aggregate = await service.create_volume(
                    contender, USER_ID, "concurrent-volume", 1
                )
                return volume.volume_id
            except HTTPException as exc:
                return exc

    creates = await asyncio.gather(create_same_volume(), create_same_volume())
    assert sum(isinstance(result, str) for result in creates) == 1
    conflicts = [result for result in creates if isinstance(result, HTTPException)]
    assert len(conflicts) == 1 and conflicts[0].status_code == 409

    holder = await _server(db, redis, "idempotent-holder", "idempotent-host")
    volume = (
        await db.execute(select(StorageVolume).where(StorageVolume.name == "concurrent-volume"))
    ).scalar_one()
    request_id = str(uuid.uuid4())

    async def reserve_same_generation():
        async with factory() as contender:
            contender_volume = await contender.get(StorageVolume, volume.volume_id)
            generation, _ = await service.plan_object_placement(
                contender,
                contender_volume,
                request_id,
                "idempotent-key",
                9,
            )
            return generation.object_id

    reservations = await asyncio.gather(reserve_same_generation(), reserve_same_generation())
    assert reservations[0] == reservations[1]
    assert holder.server_id


async def test_literal_prefix_volume_pagination_and_holdings_omission(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "control-holder", "control-host")
    volume = await _volume(db, 1)
    for object_id, key, digest in (
        ("literal-percent", "%literal", "a" * 64),
        ("literal-underscore", "_literal", "b" * 64),
        ("ordinary", "ordinary", "c" * 64),
    ):
        await _object(
            db,
            volume,
            object_id,
            sha256=digest,
            size_bytes=1,
            object_key=key,
        )
    await db.commit()
    assert [
        generation.object_key for generation in await service.list_objects(db, volume, "%", 100)
    ] == ["%literal"]
    assert [
        generation.object_key for generation in await service.list_objects(db, volume, "_", 100)
    ] == ["_literal"]

    for index in range(5):
        db.add(
            StorageVolume(
                user_id=USER_ID,
                name=f"page-volume-{index}",
                replication_factor=1,
                quota_bytes=100,
                used_bytes=0,
            )
        )
    await db.commit()
    first_page, _aggregate = await service.list_volumes(db, USER_ID, 2)
    second_page, _aggregate = await service.list_volumes(db, USER_ID, 2, first_page[-1].volume_id)
    assert len(first_page) == len(second_page) == 2
    assert {item.volume_id for item in first_page}.isdisjoint(
        {item.volume_id for item in second_page}
    )

    first_snapshot = str(uuid.uuid4())
    await service.announce_model_holdings(
        db,
        MINER,
        holder.server_id,
        holder.server_id,
        first_snapshot,
        0,
        holder.storage_incarnation,
        100,
        [
            {"repo_id": "org/a", "revision": "main", "bytes": 1},
            {"repo_id": "org/b", "revision": "main", "bytes": 1},
        ],
        True,
    )
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=1000)
    second_snapshot = str(uuid.uuid4())
    await service.announce_model_holdings(
        db,
        MINER,
        holder.server_id,
        holder.server_id,
        second_snapshot,
        0,
        holder.storage_incarnation,
        100,
        [{"repo_id": "org/a", "revision": "main", "bytes": 1}],
        True,
    )
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=1000)
    assert (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder.server_id)
        )
    ).scalar_one() == 1
    holding = (
        await db.execute(select(ContentHolding).where(ContentHolding.server_id == holder.server_id))
    ).scalar_one()
    holding.announced_at = datetime.now(timezone.utc) - timedelta(hours=1)
    holder.model_inventory_fresh_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await db.commit()
    assert await service.model_peers(db, "org/a", "main") == []


async def test_model_inventory_heartbeat_bridges_reconcile_cadence_jitter(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "jitter-holder", "jitter-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    authoritative_snapshot_id = str(uuid.uuid4())
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        authoritative_snapshot_id,
        0,
        holder_incarnation,
        100,
        [{"repo_id": "org/authoritative", "revision": "a" * 40, "bytes": 7}],
        True,
    )
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
    db.expire_all()
    holder = await db.get(Server, holder_id)
    marker_order = (
        holder.model_inventory_snapshot_started_at,
        holder.model_inventory_snapshot_id,
    )
    assert marker_order[1] == authoritative_snapshot_id

    stale_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_model_holding_freshness_seconds + 1
    )
    holder.model_inventory_fresh_at = stale_at
    await db.commit()
    assert await service.model_peers(db, "org/authoritative", "a" * 40) == []

    scanning_snapshot_id = str(uuid.uuid4())
    heartbeat_started_at = await db.scalar(select(func.now()))
    assert heartbeat_started_at is not None
    assert await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        scanning_snapshot_id,
        0,
        holder_incarnation,
        100,
        [{"repo_id": "org/staged", "revision": "b" * 40, "bytes": 9}],
        False,
    ) == {"recorded": 1, "complete": False}

    db.expire_all()
    holder = await db.get(Server, holder_id)
    assert holder.model_inventory_fresh_at >= heartbeat_started_at
    assert (
        holder.model_inventory_snapshot_started_at,
        holder.model_inventory_snapshot_id,
    ) == marker_order
    assert [
        peer.server_id for peer in await service.model_peers(db, "org/authoritative", "a" * 40)
    ] == [holder_id]
    assert await service.model_peers(db, "org/staged", "b" * 40) == []
    assert (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder_id)
        )
    ).scalar_one() == 1
    scanning_snapshot = await db.get(StorageModelInventorySnapshot, scanning_snapshot_id)
    assert scanning_snapshot.state == "scanning"


async def test_more_than_ten_active_model_streams_keep_waiting_marker_fresh(
    pg_session,
):
    db, redis = pg_session
    streams = []
    for index in range(11):
        holder = await _server(
            db,
            redis,
            f"active-stream-{index:02d}",
            f"active-stream-host-{index:02d}",
        )
        authoritative_snapshot_id = str(uuid.uuid4())
        await service.announce_model_holdings(
            db,
            MINER,
            holder.server_id,
            holder.server_id,
            authoritative_snapshot_id,
            0,
            holder.storage_incarnation,
            100,
            [
                {
                    "repo_id": f"org/authoritative-{index:02d}",
                    "revision": f"{index:040x}",
                    "bytes": index,
                }
            ],
            True,
        )
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
        streams.append(
            (
                holder.server_id,
                holder.storage_incarnation,
                authoritative_snapshot_id,
            )
        )

    active_started_at = datetime.now(timezone.utc)
    active_snapshot_ids = []
    for stream_index, (server_id, incarnation, _) in enumerate(streams):
        snapshot_id = str(uuid.uuid4())
        active_snapshot_ids.append(snapshot_id)
        await service.announce_model_holdings(
            db,
            MINER,
            server_id,
            server_id,
            snapshot_id,
            0,
            incarnation,
            100,
            [
                {
                    "repo_id": (f"org/active-{stream_index:02d}-{entry_index:04d}"),
                    "revision": f"{entry_index:040x}",
                    "bytes": entry_index,
                }
                for entry_index in range(251)
            ],
            True,
        )
        snapshot = await db.get(StorageModelInventorySnapshot, snapshot_id)
        snapshot.state = "applying"
        snapshot.application_started_at = active_started_at + timedelta(microseconds=stream_index)
    await db.commit()

    assert (
        await db.execute(
            select(func.count())
            .select_from(StorageModelInventorySnapshot)
            .where(StorageModelInventorySnapshot.state.in_(("applying", "omitting")))
        )
    ).scalar_one() == 11

    target_id, target_incarnation, target_marker_id = streams[-1]
    target_active_snapshot_id = active_snapshot_ids[-1]
    db.expire_all()
    target = await db.get(Server, target_id)
    marker_order = (
        target.model_inventory_snapshot_started_at,
        target.model_inventory_snapshot_id,
    )
    assert marker_order[1] == target_marker_id

    for _ in range(3):
        target.model_inventory_fresh_at = datetime.now(timezone.utc) - timedelta(
            seconds=settings.storage_model_holding_freshness_seconds + 1
        )
        await db.commit()
        assert await service.model_peers(db, "org/authoritative-10", f"{10:040x}") == []

        heartbeat_started_at = await db.scalar(select(func.now()))
        assert heartbeat_started_at is not None
        await service.announce_model_holdings(
            db,
            MINER,
            target_id,
            target_id,
            str(uuid.uuid4()),
            0,
            target_incarnation,
            100,
            [],
            True,
        )
        db.expire_all()
        target = await db.get(Server, target_id)
        assert target.model_inventory_fresh_at >= heartbeat_started_at
        assert (
            target.model_inventory_snapshot_started_at,
            target.model_inventory_snapshot_id,
        ) == marker_order
        assert [
            peer.server_id
            for peer in await service.model_peers(db, "org/authoritative-10", f"{10:040x}")
        ] == [target_id]
        assert await service.model_peers(db, "org/active-10-0000", f"{0:040x}") == []

        await service._reconcile_model_inventory_snapshots(db, max_snapshots=10, max_entries=250)
        db.expire_all()
        target = await db.get(Server, target_id)

    target_active_snapshot = await db.get(StorageModelInventorySnapshot, target_active_snapshot_id)
    assert target_active_snapshot.state == "applying"
    assert target_active_snapshot.applied_entries == 0
    assert (
        target.model_inventory_snapshot_started_at,
        target.model_inventory_snapshot_id,
    ) == marker_order


async def test_first_incomplete_model_snapshot_does_not_create_authority(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "first-scan-holder", "first-scan-host")
    holder_id = holder.server_id
    snapshot_id = str(uuid.uuid4())

    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        snapshot_id,
        0,
        holder.storage_incarnation,
        100,
        [{"repo_id": "org/first-staged", "revision": "c" * 40, "bytes": 13}],
        False,
    )

    db.expire_all()
    holder = await db.get(Server, holder_id)
    assert (
        holder.model_inventory_storage_incarnation,
        holder.model_inventory_cert_pubkey_hash,
        holder.model_inventory_snapshot_started_at,
        holder.model_inventory_snapshot_id,
        holder.model_inventory_fresh_at,
    ) == (None, None, None, None, None)
    snapshot = await db.get(StorageModelInventorySnapshot, snapshot_id)
    assert snapshot.state == "scanning"
    assert (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder.server_id)
        )
    ).scalar_one() == 0
    assert await service.model_peers(db, "org/first-staged", "c" * 40) == []


@pytest.mark.parametrize("replacement", ("certificate", "incarnation"))
async def test_model_inventory_replacement_identity_remains_fail_closed(
    pg_session,
    replacement,
):
    db, redis = pg_session
    holder = await _server(
        db,
        redis,
        f"{replacement}-replacement-holder",
        f"{replacement}-replacement-host",
    )
    holder_id = holder.server_id
    authoritative_snapshot_id = str(uuid.uuid4())
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        authoritative_snapshot_id,
        0,
        holder.storage_incarnation,
        100,
        [{"repo_id": "org/old-identity", "revision": "d" * 40, "bytes": 17}],
        True,
    )
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
    assert [
        peer.server_id for peer in await service.model_peers(db, "org/old-identity", "d" * 40)
    ] == [holder_id]

    replacement_incarnation = holder.storage_incarnation
    if replacement == "certificate":
        replacement_at = datetime.now(timezone.utc)
        measurement = _storage_measurement()
        config_fingerprint = measurement.config_fingerprint or measurement_config_fingerprint(
            measurement
        )
        holder.attested_cert_pubkey_hash = hashlib.sha256(
            b"replacement-attested-certificate"
        ).hexdigest()
        db.add(
            ServerAttestation(
                server_id=holder_id,
                quote_data="replacement-quote",
                measurement_version=measurement.version,
                measurement_name=measurement.name,
                measurement_config_fingerprint=config_fingerprint,
                trust_set_fingerprint=measurement_trust_set_fingerprint(
                    settings.tee_measurements
                ),
                created_at=replacement_at,
                verified_at=replacement_at,
            )
        )
    else:
        replacement_incarnation = str(uuid.uuid4())
    await db.commit()

    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        str(uuid.uuid4()),
        0,
        replacement_incarnation,
        100,
        [{"repo_id": "org/new-identity", "revision": "e" * 40, "bytes": 19}],
        False,
    )

    db.expire_all()
    holder = await db.get(Server, holder_id)
    assert holder.storage_incarnation == replacement_incarnation
    assert (
        holder.model_inventory_storage_incarnation,
        holder.model_inventory_cert_pubkey_hash,
        holder.model_inventory_snapshot_started_at,
        holder.model_inventory_snapshot_id,
        holder.model_inventory_fresh_at,
    ) == (None, None, None, None, None)
    assert await service.model_peers(db, "org/old-identity", "d" * 40) == []
    assert await service.model_peers(db, "org/new-identity", "e" * 40) == []
    holdings_count = (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder_id)
        )
    ).scalar_one()
    assert holdings_count == (1 if replacement == "certificate" else 0)


async def test_model_holding_snapshot_over_one_thousand_is_atomic_until_final_page(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "model-snapshot-holder", "model-snapshot-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    db.add(
        ContentHolding(
            server_id=holder_id,
            repo_id="org/old",
            revision="0" * 40,
            bytes=7,
            status="present",
        )
    )
    await db.commit()
    snapshot_id = str(uuid.uuid4())
    holdings = [
        {
            "repo_id": f"org/model-{index:04d}",
            "revision": f"{index:040x}",
            "bytes": index,
        }
        for index in range(1005)
    ]

    first = await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        snapshot_id,
        0,
        holder_incarnation,
        100,
        holdings[:1000],
        False,
    )
    assert first == {"recorded": 1000, "complete": False}
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=10, max_entries=200)
    assert (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder_id)
        )
    ).scalar_one() == 1
    snapshot = await db.get(StorageModelInventorySnapshot, snapshot_id)
    assert snapshot.state == "scanning"

    final = await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        snapshot_id,
        1,
        holder_incarnation,
        100,
        holdings[1000:],
        True,
    )
    assert final == {"recorded": 5, "complete": True}
    for _ in range(20):
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=200)
        db.expire_all()
        snapshot = await db.get(StorageModelInventorySnapshot, snapshot_id)
        if snapshot.state == "reconciled":
            break
    assert snapshot.state == "reconciled"
    assert snapshot.applied_entries == 1005
    assert snapshot.omitted_entries == 1
    assert (
        await db.execute(
            select(func.count())
            .select_from(ContentHolding)
            .where(ContentHolding.server_id == holder_id)
        )
    ).scalar_one() == 1005
    assert (
        await db.execute(
            select(
                exists().where(
                    ContentHolding.server_id == holder_id,
                    ContentHolding.repo_id == "org/old",
                )
            )
        )
    ).scalar_one() is False


async def test_newest_completed_model_snapshot_wins_when_reconciliation_overlaps(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "model-overlap-holder", "model-overlap-host")
    holder_id = holder.server_id
    older_snapshot_id = str(uuid.uuid4())
    newer_snapshot_id = str(uuid.uuid4())
    db.add(
        ContentHolding(
            server_id=holder_id,
            repo_id="org/stale",
            revision="1" * 40,
            bytes=7,
            status="present",
            announced_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    await db.commit()

    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        older_snapshot_id,
        0,
        holder.storage_incarnation,
        100,
        [
            {"repo_id": "org/keep", "revision": "2" * 40, "bytes": 11},
            {"repo_id": "org/stale", "revision": "1" * 40, "bytes": 7},
        ],
        True,
    )
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        newer_snapshot_id,
        0,
        holder.storage_incarnation,
        100,
        [{"repo_id": "org/keep", "revision": "2" * 40, "bytes": 12}],
        True,
    )
    older = await db.get(StorageModelInventorySnapshot, older_snapshot_id)
    newer = await db.get(StorageModelInventorySnapshot, newer_snapshot_id)
    older.started_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    older.eligibility_cutoff_at = older.started_at
    newer.started_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    newer.eligibility_cutoff_at = newer.started_at
    await db.commit()

    applied, omitted, completed = await service._reconcile_model_inventory_snapshots(
        db, max_snapshots=1, max_entries=100
    )
    assert (applied, omitted, completed) == (1, 1, 2)
    db.expire_all()
    older = await db.get(StorageModelInventorySnapshot, older_snapshot_id)
    newer = await db.get(StorageModelInventorySnapshot, newer_snapshot_id)
    assert older.state == "reconciled"
    assert older.application_started_at is None
    assert newer.state == "reconciled"
    holdings = list(
        (await db.execute(select(ContentHolding).where(ContentHolding.server_id == holder_id)))
        .scalars()
        .all()
    )
    assert [(item.repo_id, item.bytes) for item in holdings] == [("org/keep", 12)]
    assert holdings[0].announced_at > newer.started_at
    assert holdings[0].last_snapshot_id == newer_snapshot_id
    assert holdings[0].last_snapshot_started_at == newer.started_at

    assert await service._reconcile_model_inventory_snapshots(
        db, max_snapshots=1, max_entries=100
    ) == (0, 0, 0)
    db.expire_all()
    older = await db.get(StorageModelInventorySnapshot, older_snapshot_id)
    holdings = list(
        (await db.execute(select(ContentHolding).where(ContentHolding.server_id == holder_id)))
        .scalars()
        .all()
    )
    assert older.state == "reconciled"
    assert [(item.repo_id, item.bytes, item.last_snapshot_id) for item in holdings] == [
        ("org/keep", 12, newer_snapshot_id)
    ]


async def test_later_serialized_model_snapshot_uses_database_wall_clock(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "model-order-holder", "model-order-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    empty_snapshot_id = str(uuid.uuid4())
    authoritative_snapshot_id = str(uuid.uuid4())

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as earlier_transaction, factory() as later_transaction:
        # PostgreSQL now() is fixed at transaction start; this transaction publishes second.
        anchored_at = await earlier_transaction.scalar(select(func.now()))
        assert anchored_at is not None
        await asyncio.sleep(0.05)

        later_holder = await later_transaction.get(Server, holder_id)
        await service.announce_model_holdings(
            later_transaction,
            MINER,
            holder_id,
            later_holder.server_id,
            empty_snapshot_id,
            0,
            holder_incarnation,
            100,
            [],
            True,
        )
        earlier_holder = await earlier_transaction.get(Server, holder_id)
        await service.announce_model_holdings(
            earlier_transaction,
            MINER,
            holder_id,
            earlier_holder.server_id,
            authoritative_snapshot_id,
            0,
            holder_incarnation,
            100,
            [{"repo_id": "org/transaction-order", "revision": "6" * 40, "bytes": 23}],
            True,
        )

    db.expire_all()
    empty_snapshot = await db.get(StorageModelInventorySnapshot, empty_snapshot_id)
    authoritative_snapshot = await db.get(StorageModelInventorySnapshot, authoritative_snapshot_id)
    assert empty_snapshot.started_at < authoritative_snapshot.started_at
    assert authoritative_snapshot.started_at > anchored_at

    for _ in range(4):
        await service._reconcile_model_inventory_snapshots(
            db,
            max_snapshots=2,
            max_entries=100,
        )
        db.expire_all()
        states = dict(
            (
                await db.execute(
                    select(
                        StorageModelInventorySnapshot.snapshot_id,
                        StorageModelInventorySnapshot.state,
                    ).where(
                        StorageModelInventorySnapshot.snapshot_id.in_(
                            [empty_snapshot_id, authoritative_snapshot_id]
                        )
                    )
                )
            ).all()
        )
        if states == {
            empty_snapshot_id: "reconciled",
            authoritative_snapshot_id: "reconciled",
        }:
            break
    else:
        pytest.fail("serialized model inventory snapshots did not reconcile")

    holdings = list(
        (await db.execute(select(ContentHolding).where(ContentHolding.server_id == holder_id)))
        .scalars()
        .all()
    )
    assert [
        (holding.repo_id, holding.revision, holding.bytes, holding.last_snapshot_id)
        for holding in holdings
    ] == [("org/transaction-order", "6" * 40, 23, authoritative_snapshot_id)]


async def test_active_large_model_snapshot_finishes_while_newer_snapshots_keep_arriving(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "continuous-model-holder", "continuous-model-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    active_snapshot_id = str(uuid.uuid4())
    active_holdings = [
        {
            "repo_id": f"org/active-{index:04d}",
            "revision": f"{index:040x}",
            "bytes": index,
        }
        for index in range(1001)
    ]
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        active_snapshot_id,
        0,
        holder_incarnation,
        100,
        active_holdings[:1000],
        False,
    )
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        active_snapshot_id,
        1,
        holder_incarnation,
        100,
        active_holdings[1000:],
        True,
    )
    active_snapshot = await db.get(StorageModelInventorySnapshot, active_snapshot_id)
    active_snapshot.started_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_model_holding_freshness_seconds * 2
    )
    active_snapshot.eligibility_cutoff_at = active_snapshot.started_at
    await db.commit()

    assert await service._reconcile_model_inventory_snapshots(
        db, max_snapshots=1, max_entries=250
    ) == (250, 0, 0)
    db.expire_all()
    active_snapshot = await db.get(StorageModelInventorySnapshot, active_snapshot_id)
    assert active_snapshot.state == "applying"
    first_holding = (
        await db.execute(
            select(ContentHolding).where(
                ContentHolding.server_id == holder_id,
                ContentHolding.repo_id == "org/active-0000",
            )
        )
    ).scalar_one()
    assert first_holding.announced_at > active_snapshot.started_at

    stale_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_model_holding_freshness_seconds + 1
    )
    first_holding.announced_at = stale_at
    current_server = await db.get(Server, holder_id)
    current_server.model_inventory_fresh_at = stale_at
    await db.commit()
    assert await service.model_peers(db, "org/active-0000", f"{0:040x}") == []

    waiting_snapshot_ids = []
    for version in range(20):
        waiting_snapshot_id = str(uuid.uuid4())
        waiting_snapshot_ids.append(waiting_snapshot_id)
        await service.announce_model_holdings(
            db,
            MINER,
            holder_id,
            holder_id,
            waiting_snapshot_id,
            0,
            holder_incarnation,
            100,
            [
                {
                    "repo_id": "org/winner",
                    "revision": "f" * 40,
                    "bytes": version,
                }
            ],
            True,
        )
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=250)
        db.expire_all()
        active_snapshot = await db.get(StorageModelInventorySnapshot, active_snapshot_id)
        active_count = (
            await db.execute(
                select(func.count())
                .select_from(StorageModelInventorySnapshot)
                .where(
                    StorageModelInventorySnapshot.server_id == holder_id,
                    StorageModelInventorySnapshot.storage_incarnation == holder_incarnation,
                    StorageModelInventorySnapshot.state.in_(("applying", "omitting")),
                )
            )
        ).scalar_one()
        assert active_count <= 1
        if version == 0:
            assert [
                peer.server_id
                for peer in await service.model_peers(db, "org/active-0000", f"{0:040x}")
            ] == [holder_id]
        if active_snapshot.state == "reconciled":
            break
    else:
        pytest.fail("active model snapshot did not finish under continuous newer arrivals")

    assert active_snapshot.applied_entries == 1001
    assert len(waiting_snapshot_ids) > 1
    newest_waiting_id = await db.scalar(
        select(StorageModelInventorySnapshot.snapshot_id)
        .where(StorageModelInventorySnapshot.snapshot_id.in_(waiting_snapshot_ids))
        .order_by(
            StorageModelInventorySnapshot.started_at.desc(),
            StorageModelInventorySnapshot.snapshot_id.desc(),
        )
        .limit(1)
    )
    assert newest_waiting_id is not None
    newest_waiting_version = waiting_snapshot_ids.index(newest_waiting_id)
    for _ in range(20):
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=250)
        db.expire_all()
        newest_waiting = await db.get(StorageModelInventorySnapshot, newest_waiting_id)
        if newest_waiting.state == "reconciled":
            break
    else:
        pytest.fail("newest waiting model snapshot did not reconcile")

    assert newest_waiting.application_started_at is not None
    for superseded_id in (
        snapshot_id for snapshot_id in waiting_snapshot_ids if snapshot_id != newest_waiting_id
    ):
        superseded = await db.get(StorageModelInventorySnapshot, superseded_id)
        assert superseded.state == "reconciled"
        assert superseded.application_started_at is None
    final_holdings = list(
        (await db.execute(select(ContentHolding).where(ContentHolding.server_id == holder_id)))
        .scalars()
        .all()
    )
    assert [
        (holding.repo_id, holding.bytes, holding.last_snapshot_id) for holding in final_holdings
    ] == [("org/winner", newest_waiting_version, newest_waiting_id)]


async def test_newer_snapshot_omits_late_applied_older_rows_but_not_future_rows(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "ordered-omission-holder", "ordered-omission-host")
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    older_snapshot_id = str(uuid.uuid4())
    newer_snapshot_id = str(uuid.uuid4())
    older_holdings = [
        {
            "repo_id": f"org/ordered-{index:04d}",
            "revision": f"{index:040x}",
            "bytes": index,
        }
        for index in range(501)
    ]
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        older_snapshot_id,
        0,
        holder_incarnation,
        100,
        older_holdings,
        True,
    )
    await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
    await service.announce_model_holdings(
        db,
        MINER,
        holder_id,
        holder_id,
        newer_snapshot_id,
        0,
        holder_incarnation,
        100,
        [{"repo_id": "org/ordered-0000", "revision": f"{0:040x}", "bytes": 999}],
        True,
    )
    newer_snapshot = await db.get(StorageModelInventorySnapshot, newer_snapshot_id)
    newer_started_at = newer_snapshot.started_at

    for _ in range(20):
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
        db.expire_all()
        older_snapshot = await db.get(StorageModelInventorySnapshot, older_snapshot_id)
        if older_snapshot.state == "reconciled":
            break
    else:
        pytest.fail("older active model snapshot did not finish")

    late_older_holding = (
        await db.execute(
            select(ContentHolding).where(
                ContentHolding.server_id == holder_id,
                ContentHolding.repo_id == "org/ordered-0500",
            )
        )
    ).scalar_one()
    assert late_older_holding.announced_at > newer_started_at
    assert late_older_holding.last_snapshot_started_at < newer_started_at

    future_snapshot_id = str(uuid.uuid4())
    future_started_at = newer_started_at + timedelta(hours=1)
    db.add(
        ContentHolding(
            server_id=holder_id,
            repo_id="org/future",
            revision="e" * 40,
            bytes=3,
            status="present",
            announced_at=datetime.now(timezone.utc),
            last_snapshot_id=future_snapshot_id,
            last_snapshot_started_at=future_started_at,
        )
    )
    await db.commit()

    for _ in range(20):
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=100)
        db.expire_all()
        newer_snapshot = await db.get(StorageModelInventorySnapshot, newer_snapshot_id)
        if newer_snapshot.state == "reconciled":
            break
    else:
        pytest.fail("newer model snapshot did not reconcile")

    remaining = list(
        (
            await db.execute(
                select(ContentHolding)
                .where(ContentHolding.server_id == holder_id)
                .order_by(ContentHolding.repo_id)
            )
        )
        .scalars()
        .all()
    )
    assert [(holding.repo_id, holding.bytes) for holding in remaining] == [
        ("org/future", 3),
        ("org/ordered-0000", 999),
    ]
    assert remaining[0].last_snapshot_started_at == future_started_at
    assert remaining[1].last_snapshot_id == newer_snapshot_id


async def test_duplicate_attested_certificate_hash_is_rejected(pg_session):
    db, redis = pg_session
    identity = _attested_identity("duplicate-cert")
    await _server(
        db,
        redis,
        "duplicate-cert-a",
        "duplicate-cert-host-a",
        attested_identity=identity,
    )
    with pytest.raises(Exception):
        await _server(
            db,
            redis,
            "duplicate-cert-b",
            "duplicate-cert-host-b",
            attested_identity=identity,
        )
    await db.rollback()


async def test_administrative_erase_retirement_is_explicit_and_overdue_only(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    holder = await _server(db, redis, "retention-holder", "retention-host")
    task = StorageEraseTask(
        object_id="retention-generation",
        volume_id="retention-volume",
        server_id=holder.server_id,
        storage_incarnation=holder.storage_incarnation,
        holder_cert_pubkey_hash=holder.attested_cert_pubkey_hash,
        reason="offline_holder",
        state="pending",
        retention_deadline=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(task)
    await db.commit()
    task_id = task.task_id

    monkeypatch.setattr(settings, "storage_allow_administrative_erase_retirement", False)
    with pytest.raises(HTTPException) as disabled:
        await service.administratively_retire_erase_tasks(
            db, "administrator", [task_id], "approved device loss"
        )
    assert disabled.value.status_code == 403
    await db.rollback()

    monkeypatch.setattr(settings, "storage_allow_administrative_erase_retirement", True)
    with pytest.raises(HTTPException) as too_early:
        await service.administratively_retire_erase_tasks(
            db, "administrator", [task_id], "approved device loss"
        )
    assert too_early.value.status_code == 409
    await db.rollback()

    task = await db.get(StorageEraseTask, task_id)
    task.retention_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.commit()
    assert (
        await service.administratively_retire_erase_tasks(
            db, "administrator", [task_id], "approved device loss"
        )
        == 1
    )
    await db.refresh(task)
    assert task.state == "retired"
    assert task.retired_by_user_id == "administrator"


async def test_reconcile_advisory_lock_survives_work_commits(pg_session, monkeypatch):
    db, _redis = pg_session
    lock_engine = create_async_engine(TEST_DATABASE_URL, pool_size=2, max_overflow=0)
    factory = sessionmaker(lock_engine, class_=AsyncSession, expire_on_commit=False)
    contender_results = []

    async def reconcile_with_overlap(work_session):
        # The bounded work pass can commit freely without owning the leadership connection.
        assert work_session is not db
        await work_session.execute(text("SELECT 1"))
        await work_session.commit()
        await asyncio.sleep(0.05)
        async with factory() as contender:
            contender_results.append(
                (
                    await contender.execute(
                        text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                        {"lock_key": storage_reconcile._RECONCILE_LOCK_KEY},
                    )
                ).scalar_one()
            )

    monkeypatch.setattr(storage_reconcile, "engine", lock_engine)
    monkeypatch.setattr(storage_reconcile, "get_session", lambda: factory())
    monkeypatch.setattr(storage_reconcile, "reconcile_storage", reconcile_with_overlap)

    try:
        assert await storage_reconcile.reconcile_storage_once()
        assert contender_results == [False]

        # The production function asserted its unlock; a new session can immediately become leader.
        async with factory() as contender:
            assert (
                await contender.execute(
                    text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                    {"lock_key": storage_reconcile._RECONCILE_LOCK_KEY},
                )
            ).scalar_one()
            assert (
                await contender.execute(
                    text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
                    {"lock_key": storage_reconcile._RECONCILE_LOCK_KEY},
                )
            ).scalar_one()
    finally:
        await lock_engine.dispose()


async def _replication_fence_fixture(db, redis, prefix: str):
    source_identity = _attested_identity(f"{prefix}-source")
    source = await _server(
        db,
        redis,
        f"{prefix}-source",
        f"{prefix}-source-host",
        attested_identity=source_identity,
    )
    target = await _server(
        db,
        redis,
        f"{prefix}-target",
        f"{prefix}-target-host",
    )
    volume = await _volume(db, 2)
    obj = await _object(
        db,
        volume,
        f"{prefix}-object",
        sha256="a" * 64,
        size_bytes=41,
    )
    source_placement = await _placement(db, obj, source, status="present")
    target_placement = await _placement(db, obj, target, status="pending")
    await service._refresh_object_durability(db, obj, volume=volume)
    await db.commit()
    return (
        source_identity,
        source,
        target,
        volume,
        obj,
        source_placement,
        target_placement,
    )


def _pending_placement_mutation_snapshot(placement: ReplicaPlacement) -> tuple:
    return (
        placement.status,
        placement.attempt_count,
        placement.pending_since,
        placement.pending_deadline,
        placement.last_attempt_at,
        placement.last_error,
        placement.proof_sha256,
        placement.proof_size_bytes,
        placement.proof_capability_id,
        placement.proof_mode,
        placement.proof_at,
        placement.confirmed_at,
    )


@pytest.mark.parametrize(
    "announce_wins",
    [False, True],
    ids=["reconcile-wins", "unassigned-announce-wins"],
)
async def test_reconcile_new_candidate_and_unassigned_announce_share_object_frontier(
    pg_session,
    monkeypatch,
    announce_wins,
):
    db, redis = pg_session
    suffix = "announce" if announce_wins else "reconcile"
    source = await _server(
        db,
        redis,
        f"new-candidate-{suffix}-source",
        f"new-candidate-{suffix}-source-host",
    )
    target = await _server(
        db,
        redis,
        f"new-candidate-{suffix}-target",
        f"new-candidate-{suffix}-target-host",
    )
    volume = await _volume(db, 2)
    obj = await _object(
        db,
        volume,
        f"new-candidate-{suffix}-object",
        sha256="b" * 64,
        size_bytes=43,
    )
    await _placement(db, obj, source, status="present")
    await service._refresh_object_durability(db, obj, volume=volume)
    await db.commit()
    object_id = obj.object_id
    target_id = target.server_id
    target_incarnation = target.storage_incarnation

    announcement = [
        {
            "object_id": object_id,
            "status": "stored",
            "ciphertext_sha256": obj.sha256,
            "ciphertext_size_bytes": obj.ciphertext_size_bytes,
            "plaintext_size_bytes": obj.size_bytes,
            "plaintext_sha256": "c" * 64,
        }
    ]
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as announcer, factory() as reconciler:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        announce_pid = await announcer.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [target_id], shared=False)
        reconcile_object_frontier_entered = asyncio.Event()
        reconcile_pid = {}
        original_lock_objects = service._lock_storage_object_transactions

        async def observe_reconcile_object_frontier(lock_db, object_ids):
            if lock_db is reconciler and object_id in {str(value) for value in object_ids}:
                reconcile_pid["value"] = await lock_db.scalar(text("SELECT pg_backend_pid()"))
                reconcile_object_frontier_entered.set()
            return await original_lock_objects(lock_db, object_ids)

        monkeypatch.setattr(
            service,
            "_lock_storage_object_transactions",
            observe_reconcile_object_frontier,
        )

        async def announce():
            return await service.announce_replicas(
                announcer,
                MINER,
                target_id,
                target_id,
                target_incarnation,
                announcement,
            )

        announcing = None
        reconciling = None
        try:
            if announce_wins:
                announcing = asyncio.create_task(announce())
                await _wait_for_postgres_blocker(db.bind, announce_pid, gate_pid)
                reconciling = asyncio.create_task(service.reconcile_storage(reconciler, 10))
                await asyncio.wait_for(reconcile_object_frontier_entered.wait(), timeout=10)
                await _wait_for_postgres_blocker(
                    db.bind,
                    reconcile_pid["value"],
                    announce_pid,
                )
            else:
                reconciling = asyncio.create_task(service.reconcile_storage(reconciler, 10))
                await asyncio.wait_for(reconcile_object_frontier_entered.wait(), timeout=10)
                await _wait_for_postgres_blocker(
                    db.bind,
                    reconcile_pid["value"],
                    gate_pid,
                )
                announcing = asyncio.create_task(announce())
                await _wait_for_postgres_blocker(
                    db.bind,
                    announce_pid,
                    reconcile_pid["value"],
                )

            await gate.commit()
            announce_result, summary = await asyncio.wait_for(
                asyncio.gather(announcing, reconciling),
                timeout=20,
            )
        finally:
            if gate.in_transaction():
                await gate.rollback()
            for task in (announcing, reconciling):
                if task is not None and not task.done():
                    task.cancel()
            for task in (announcing, reconciling):
                if task is not None:
                    with suppress(asyncio.CancelledError, HTTPException):
                        await task

    assert announce_result == 0
    assert summary["reassigned"] == 1
    db.expire_all()
    placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == object_id,
                ReplicaPlacement.server_id == target_id,
            )
        )
    ).scalar_one()
    assert placement.status == "pending"
    assert placement.storage_incarnation == target_incarnation


@pytest.mark.parametrize(
    "finalizer_wins",
    [False, True],
    ids=["failure-report-wins", "erasure-finalizer-wins"],
)
async def test_erasure_finalizer_and_replication_failure_share_object_frontier(
    pg_session,
    monkeypatch,
    finalizer_wins,
):
    db, redis = pg_session
    (
        _source_identity,
        source,
        target,
        volume,
        obj,
        _source_placement,
        _target_placement,
    ) = await _replication_fence_fixture(
        db,
        redis,
        f"finalizer-failure-{'finalizer' if finalizer_wins else 'failure'}",
    )
    object_id = obj.object_id
    source_id = source.server_id
    target_id = target.server_id
    lease = await service.issue_replication_capability(
        db,
        source,
        object_id,
        target_id,
        obj.sha256,
        obj.ciphertext_size_bytes,
    )
    await service.delete_object(db, volume, obj.object_key)
    for holder_id in (source_id, target_id):
        db.expire_all()
        holder = await db.get(Server, holder_id)
        claimed = await service.claim_erase_tasks(db, holder, 10)
        object_tasks = [task for task in claimed if task["object_id"] == object_id]
        assert len(object_tasks) == 1
        await service.record_erase_task_result(
            db,
            holder,
            object_tasks[0]["task_id"],
            "erased",
            True,
            None,
        )
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageEraseTask)
            .where(
                StorageEraseTask.object_id == object_id,
                StorageEraseTask.state.not_in(service.ERASE_TERMINAL_STATES),
            )
        )
        == 0
    )

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as finalizer, factory() as reporter:
        finalizer_pid = await finalizer.scalar(text("SELECT pg_backend_pid()"))
        reporter_pid = await reporter.scalar(text("SELECT pg_backend_pid()"))
        reporter_source = await reporter.get(Server, source_id)
        winner_pid = finalizer_pid if finalizer_wins else reporter_pid
        loser_pid = reporter_pid if finalizer_wins else finalizer_pid
        winner_entered = asyncio.Event()
        release_winner = asyncio.Event()
        original_lock_objects = service._lock_storage_object_transactions

        async def pause_winner_after_object_frontier(lock_db, object_ids):
            locked = await original_lock_objects(lock_db, object_ids)
            backend_pid = await lock_db.scalar(text("SELECT pg_backend_pid()"))
            if backend_pid == winner_pid and not winner_entered.is_set():
                winner_entered.set()
                await release_winner.wait()
            return locked

        monkeypatch.setattr(
            service,
            "_lock_storage_object_transactions",
            pause_winner_after_object_frontier,
        )

        async def report_failure():
            return await service.fail_replication_capability(
                reporter,
                reporter_source,
                lease["capability"],
                "failure_reported_at_erasure_boundary",
            )

        finalizing = None
        reporting = None
        try:
            if finalizer_wins:
                finalizing = asyncio.create_task(
                    service._finalize_erasure_batch(finalizer, limit=100)
                )
                await asyncio.wait_for(winner_entered.wait(), timeout=10)
                reporting = asyncio.create_task(report_failure())
            else:
                reporting = asyncio.create_task(report_failure())
                await asyncio.wait_for(winner_entered.wait(), timeout=10)
                finalizing = asyncio.create_task(
                    service._finalize_erasure_batch(finalizer, limit=100)
                )
            await _wait_for_postgres_blocker(db.bind, loser_pid, winner_pid)
            release_winner.set()

            if finalizer_wins:
                purged, _shredded = await asyncio.wait_for(finalizing, timeout=20)
                with pytest.raises(HTTPException) as rejected:
                    await asyncio.wait_for(reporting, timeout=20)
                assert rejected.value.status_code == 403
                await reporter.rollback()
            else:
                failure = await asyncio.wait_for(reporting, timeout=20)
                purged, _shredded = await asyncio.wait_for(finalizing, timeout=20)
                assert failure == {
                    "recorded": True,
                    "capability_id": lease["capability_id"],
                }
        finally:
            release_winner.set()
            for task in (finalizing, reporting):
                if task is not None and not task.done():
                    task.cancel()
            for task in (finalizing, reporting):
                if task is not None:
                    with suppress(asyncio.CancelledError, HTTPException):
                        await task
            if finalizer.in_transaction():
                await finalizer.rollback()
            if reporter.in_transaction():
                await reporter.rollback()

    assert purged == 1
    db.expire_all()
    assert await db.get(StorageObject, object_id) is None
    assert await db.get(StorageReplicationCapability, lease["capability_id"]) is None


async def test_replication_issue_rejects_failed_attestation_committed_during_fence_wait(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    (
        _source_identity,
        source,
        target,
        _volume_row,
        obj,
        _source_placement,
        target_placement,
    ) = await _replication_fence_fixture(db, redis, "issue-attestation-fence")
    source_id = source.server_id
    target_id = target.server_id
    object_id = obj.object_id
    target_placement_id = target_placement.placement_id
    target_before = _pending_placement_mutation_snapshot(target_placement)
    capability_count_before = await db.scalar(
        select(func.count())
        .select_from(StorageReplicationCapability)
        .where(StorageReplicationCapability.object_id == object_id)
    )

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as issuer, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [source_id], shared=False)
        presented_source = await issuer.get(Server, source_id)
        original_locked_servers = service._locked_storage_publication_server_rows
        issuer_frontier_entered = asyncio.Event()
        issuer_pid = {}

        async def observed_locked_servers(current_db, server_ids):
            if current_db is issuer:
                issuer_pid["value"] = await current_db.scalar(
                    text("SELECT pg_backend_pid()")
                )
                issuer_frontier_entered.set()
            return await original_locked_servers(current_db, server_ids)

        monkeypatch.setattr(
            service,
            "_locked_storage_publication_server_rows",
            observed_locked_servers,
        )
        issuing = asyncio.create_task(
            service.issue_replication_capability(
                issuer,
                presented_source,
                object_id,
                target_id,
                obj.sha256,
                obj.ciphertext_size_bytes,
            )
        )
        try:
            await asyncio.wait_for(issuer_frontier_entered.wait(), timeout=10)
            await _wait_for_postgres_blocker(
                db.bind,
                issuer_pid["value"],
                gate_pid,
            )
            await _commit_failed_attestation(attestor, source_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(issuing, timeout=10)
            assert rejected.value.status_code == 403
            assert "source identity is stale" in rejected.value.detail
            await issuer.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not issuing.done():
                issuing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await issuing

    db.expire_all()
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageReplicationCapability)
            .where(StorageReplicationCapability.object_id == object_id)
        )
        == capability_count_before
    )
    target_after = await db.get(ReplicaPlacement, target_placement_id)
    assert _pending_placement_mutation_snapshot(target_after) == target_before


@pytest.mark.parametrize(
    "authority_change",
    ("certificate", "failed_attestation"),
    ids=("certificate-replaced", "newest-attestation-failed"),
)
async def test_inventory_page_revalidates_presented_authority_after_publication_wait(
    pg_session,
    authority_change,
):
    db, redis = pg_session
    holder = await _server(
        db,
        redis,
        f"inventory-authority-{authority_change}",
        f"inventory-authority-host-{authority_change}",
    )
    holder_id = holder.server_id
    holder_incarnation = holder.storage_incarnation
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        f"inventory-authority-object-{authority_change}",
        sha256="7" * 64,
        size_bytes=37,
    )
    placement = await _placement(db, obj, holder, status="present")
    object_id = obj.object_id
    placement_id = placement.placement_id
    snapshot_id = str(uuid.uuid4())
    entry = {
        "volume_id": volume.volume_id,
        "object_id": object_id,
        "ciphertext_sha256": obj.sha256,
        "ciphertext_size_bytes": obj.ciphertext_size_bytes,
    }

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as recorder, factory() as authority_writer:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        recorder_pid = await recorder.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        presented_holder = await recorder.get(Server, holder_id)
        recording = asyncio.create_task(
            service.record_inventory_page(
                recorder,
                presented_holder,
                snapshot_id,
                holder_incarnation,
                [entry],
                True,
            )
        )
        try:
            await _wait_for_postgres_blocker(db.bind, recorder_pid, gate_pid)
            if authority_change == "certificate":
                replacement_hash = hashlib.sha256(
                    f"inventory-replacement:{holder_id}".encode()
                ).hexdigest()
                await authority_writer.execute(
                    update(Server)
                    .where(Server.server_id == holder_id)
                    .values(attested_cert_pubkey_hash=replacement_hash)
                )
                await authority_writer.commit()
            else:
                await _commit_failed_attestation(authority_writer, holder_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(recording, timeout=10)
            assert rejected.value.status_code == 403
            assert "current storage certificate and incarnation" in rejected.value.detail
            await recorder.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not recording.done():
                recording.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await recording

    db.expire_all()
    assert await db.get(StorageInventorySnapshot, snapshot_id) is None
    placement = await db.get(ReplicaPlacement, placement_id)
    assert placement.status == "present"
    assert placement.last_inventory_snapshot_id is None
    assert placement.last_inventory_seen_at is None
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageEraseTask)
            .where(StorageEraseTask.object_id == object_id)
        )
        == 0
    )


async def _claimed_authority_erase_task_fixture(db, redis, suffix):
    holder = await _server(
        db,
        redis,
        f"erase-result-authority-{suffix}",
        f"erase-result-authority-host-{suffix}",
    )
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        f"erase-result-authority-object-{suffix}",
        sha256="8" * 64,
        size_bytes=41,
    )
    await _placement(db, obj, holder, status="present")
    await service.delete_object(db, volume, obj.object_key)
    holder_id = holder.server_id
    object_id = obj.object_id
    task = (
        await db.execute(
            select(StorageEraseTask).where(StorageEraseTask.object_id == object_id)
        )
    ).scalar_one()
    task_id = task.task_id
    claimed = await service.claim_erase_tasks(db, holder, 10)
    assert [item["task_id"] for item in claimed if item["object_id"] == object_id] == [task_id]
    db.expire_all()
    return holder_id, object_id, task_id


@pytest.mark.parametrize(
    "authority_change",
    ("certificate", "failed_attestation"),
    ids=("certificate-replaced", "newest-attestation-failed"),
)
async def test_erase_result_revalidates_presented_authority_after_publication_wait(
    pg_session,
    authority_change,
):
    db, redis = pg_session
    holder_id, _object_id, task_id = await _claimed_authority_erase_task_fixture(
        db,
        redis,
        authority_change,
    )
    task = await db.get(StorageEraseTask, task_id)
    task_before = (
        task.state,
        task.completed_at,
        task.erased_file_was_present,
        task.claimed_at,
        task.lease_expires_at,
        task.claim_cert_pubkey_hash,
        task.attempt_count,
        task.last_error,
    )

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as recorder, factory() as authority_writer:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        recorder_pid = await recorder.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        presented_holder = await recorder.get(Server, holder_id)
        recording = asyncio.create_task(
            service.record_erase_task_result(
                recorder,
                presented_holder,
                task_id,
                "erased",
                True,
                None,
            )
        )
        try:
            await _wait_for_postgres_blocker(db.bind, recorder_pid, gate_pid)
            if authority_change == "certificate":
                replacement_hash = hashlib.sha256(
                    f"erase-result-replacement:{holder_id}".encode()
                ).hexdigest()
                await authority_writer.execute(
                    update(Server)
                    .where(Server.server_id == holder_id)
                    .values(attested_cert_pubkey_hash=replacement_hash)
                )
                await authority_writer.commit()
            else:
                await _commit_failed_attestation(authority_writer, holder_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(recording, timeout=10)
            assert rejected.value.status_code == 403
            assert "current attested storage identity" in rejected.value.detail
            await recorder.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not recording.done():
                recording.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await recording

    db.expire_all()
    task = await db.get(StorageEraseTask, task_id)
    assert (
        task.state,
        task.completed_at,
        task.erased_file_was_present,
        task.claimed_at,
        task.lease_expires_at,
        task.claim_cert_pubkey_hash,
        task.attempt_count,
        task.last_error,
    ) == task_before


async def test_erase_result_terminal_replay_requires_exact_current_holder(pg_session):
    db, redis = pg_session
    holder_id, _object_id, task_id = await _claimed_authority_erase_task_fixture(
        db,
        redis,
        "terminal-replay",
    )
    holder = await db.get(Server, holder_id)
    first = await service.record_erase_task_result(
        db,
        holder,
        task_id,
        "erased",
        True,
        None,
    )
    assert first["terminal"]
    db.expire_all()
    holder = await db.get(Server, holder_id)
    replay = await service.record_erase_task_result(
        db,
        holder,
        task_id,
        "erased",
        True,
        None,
    )
    assert replay["terminal"]

    other = await _server(
        db,
        redis,
        "erase-result-terminal-other",
        "erase-result-terminal-other-host",
    )
    with pytest.raises(HTTPException) as rejected:
        await service.record_erase_task_result(
            db,
            other,
            task_id,
            "erased",
            True,
            None,
        )
    assert rejected.value.status_code == 403
    await db.rollback()


async def test_replication_fail_rejects_failed_attestation_committed_during_fence_wait(
    pg_session,
):
    db, redis = pg_session
    (
        _source_identity,
        source,
        target,
        _volume_row,
        obj,
        _source_placement,
        target_placement,
    ) = await _replication_fence_fixture(db, redis, "fail-attestation-fence")
    lease = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        obj.sha256,
        obj.ciphertext_size_bytes,
    )
    source_id = source.server_id
    target_placement_id = target_placement.placement_id
    db.expire_all()
    capability_before = await db.get(
        StorageReplicationCapability,
        lease["capability_id"],
    )
    capability_mutation_before = (
        capability_before.failed_at,
        capability_before.last_error,
        capability_before.completed_at,
        capability_before.consumed_at,
    )
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    target_before = _pending_placement_mutation_snapshot(target_placement)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as reporter, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        reporter_pid = await reporter.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [source_id], shared=False)
        presented_source = await reporter.get(Server, source_id)
        reporting = asyncio.create_task(
            service.fail_replication_capability(
                reporter,
                presented_source,
                lease["capability"],
                "latest_attestation_must_win",
            )
        )
        try:
            await _wait_for_postgres_blocker(db.bind, reporter_pid, gate_pid)
            await _commit_failed_attestation(attestor, source_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(reporting, timeout=10)
            assert rejected.value.status_code == 403
            assert "current bound source or target identity" in rejected.value.detail
            await reporter.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not reporting.done():
                reporting.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await reporting

    db.expire_all()
    capability_after = await db.get(
        StorageReplicationCapability,
        lease["capability_id"],
    )
    assert (
        capability_after.failed_at,
        capability_after.last_error,
        capability_after.completed_at,
        capability_after.consumed_at,
    ) == capability_mutation_before
    target_after = await db.get(ReplicaPlacement, target_placement_id)
    assert _pending_placement_mutation_snapshot(target_after) == target_before


# --- final publication-frontier regressions ---------------------------------------------------


async def test_replication_complete_rejects_failed_target_attestation_during_fence_wait(
    pg_session,
):
    db, redis = pg_session
    (
        source_identity,
        source,
        target,
        _volume_row,
        obj,
        _source_placement,
        target_placement,
    ) = await _replication_fence_fixture(db, redis, "complete-attestation-fence")
    digest = obj.sha256
    ciphertext_size = obj.ciphertext_size_bytes
    lease = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        digest,
        ciphertext_size,
    )
    await service.consume_replication_capability(
        db,
        target,
        lease["capability"],
        _sign_capability(source_identity, lease["capability"]),
    )
    target_id = target.server_id
    target_placement_id = target_placement.placement_id
    db.expire_all()
    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    capability_before = (
        capability.consumed_at,
        capability.completed_at,
        capability.failed_at,
        capability.last_error,
    )
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    target_before = _pending_placement_mutation_snapshot(target_placement)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as completer, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        completer_pid = await completer.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [target_id], shared=False)
        presented_target = await completer.get(Server, target_id)
        completing = asyncio.create_task(
            service.complete_replication_capability(
                completer,
                presented_target,
                lease["capability"],
                digest,
                ciphertext_size,
            )
        )
        try:
            await _wait_for_postgres_blocker(db.bind, completer_pid, gate_pid)
            await _commit_failed_attestation(attestor, target_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(completing, timeout=10)
            assert rejected.value.status_code == 403
            assert "latest attestation" in rejected.value.detail
            await completer.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not completing.done():
                completing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await completing

    db.expire_all()
    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    assert (
        capability.consumed_at,
        capability.completed_at,
        capability.failed_at,
        capability.last_error,
    ) == capability_before
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    assert _pending_placement_mutation_snapshot(target_placement) == target_before


@pytest.mark.parametrize(
    "authority_change",
    ("failed_attestation", "storage_role_disabled"),
    ids=("newest-attestation-failed", "storage-role-disabled"),
)
async def test_plan_revalidates_selected_peer_under_server_lock(
    pg_session,
    monkeypatch,
    authority_change,
):
    db, redis = pg_session
    holder = await _server(
        db,
        redis,
        f"plan-authority-{authority_change}",
        f"plan-authority-host-{authority_change}",
    )
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    volume_id = volume.volume_id
    request_id = str(uuid.uuid4())
    upsert_entered = asyncio.Event()
    release_upsert = asyncio.Event()
    original_upsert = service._upsert_pending_placement

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as planner, factory() as authority_writer:
        async def pause_after_peer_selection(upsert_db, candidate_obj, candidate_server):
            if upsert_db is planner and candidate_server.server_id == holder_id:
                upsert_entered.set()
                await release_upsert.wait()
            return await original_upsert(upsert_db, candidate_obj, candidate_server)

        monkeypatch.setattr(
            service,
            "_upsert_pending_placement",
            pause_after_peer_selection,
        )
        planner_volume = await planner.get(StorageVolume, volume_id)
        planning = asyncio.create_task(
            service.plan_object_placement(
                planner,
                planner_volume,
                request_id,
                f"plan-authority-key-{authority_change}",
                1024,
                observed_live_storage_ids={holder_id},
            )
        )
        try:
            await asyncio.wait_for(upsert_entered.wait(), timeout=10)
            if authority_change == "failed_attestation":
                await _commit_failed_attestation(authority_writer, holder_id)
            else:
                current_holder = (
                    await authority_writer.execute(
                        select(Server)
                        .where(Server.server_id == holder_id)
                        .with_for_update()
                    )
                ).scalar_one()
                current_holder.storage_role = False
                await authority_writer.commit()
            release_upsert.set()
            with pytest.raises(RuntimeError, match="Storage authority changed"):
                await asyncio.wait_for(planning, timeout=10)
            await planner.rollback()
        finally:
            release_upsert.set()
            if not planning.done():
                planning.cancel()
            with suppress(asyncio.CancelledError, RuntimeError):
                await planning
            if planner.in_transaction():
                await planner.rollback()

    db.expire_all()
    assert (
        await db.scalar(
            select(func.count())
            .select_from(StorageObject)
            .where(StorageObject.placement_request_id == request_id)
        )
        == 0
    )


async def test_commit_rechecks_latest_attestation_after_waiting_for_server_row(pg_session):
    db, redis = pg_session
    holder = await _server(db, redis, "commit-attestation-holder", "commit-attestation-host")
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    volume_id = volume.volume_id
    obj = await _object(db, volume, "commit-attestation-object", size_bytes=41)
    object_id = obj.object_id
    object_key = obj.object_key
    salt = obj.salt
    placement = await _placement(db, obj, holder, status="pending")
    placement_id = placement.placement_id
    assert (
        await service.announce_replicas(
            db,
            MINER,
            holder_id,
            holder_id,
            holder.storage_incarnation,
            [
                {
                    "object_id": object_id,
                    "status": "stored",
                    "ciphertext_sha256": "9" * 64,
                    "ciphertext_size_bytes": 73,
                    "plaintext_size_bytes": 41,
                    "plaintext_sha256": "8" * 64,
                }
            ],
        )
        == 1
    )
    db.expire_all()
    placement = await db.get(ReplicaPlacement, placement_id)
    placement_before = _pending_placement_mutation_snapshot(placement)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as committer, factory() as attestation_writer:
        committer_pid = await committer.scalar(text("SELECT pg_backend_pid()"))
        writer_pid = await attestation_writer.scalar(text("SELECT pg_backend_pid()"))
        committer_volume = await committer.get(StorageVolume, volume_id)
        attestation_writer.add(
            ServerAttestation(
                server_id=holder_id,
                quote_data="commit-barrier-failed-quote",
                verification_error="newer failed attempt before receipt publication",
                created_at=datetime.now(timezone.utc),
            )
        )
        await attestation_writer.flush()
        await attestation_writer.execute(
            select(Server).where(Server.server_id == holder_id).with_for_update()
        )
        committing = asyncio.create_task(
            service.commit_object(
                committer,
                committer_volume,
                object_id,
                object_key,
                salt,
                observed_live_storage_ids={holder_id},
            )
        )
        try:
            await _wait_for_postgres_blocker(db.bind, committer_pid, writer_pid)
            await attestation_writer.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(committing, timeout=10)
            assert rejected.value.status_code == 409
            assert "No assigned target supplied" in rejected.value.detail
            await committer.rollback()
        finally:
            if attestation_writer.in_transaction():
                await attestation_writer.rollback()
            if not committing.done():
                committing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await committing
            if committer.in_transaction():
                await committer.rollback()

    db.expire_all()
    obj = await db.get(StorageObject, object_id)
    placement = await db.get(ReplicaPlacement, placement_id)
    volume = await db.get(StorageVolume, volume_id)
    assert obj.lifecycle_state == "pending"
    assert _pending_placement_mutation_snapshot(placement) == placement_before
    assert volume.used_bytes == 0


async def test_concurrent_plans_serialize_final_capacity_in_server_order(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    first_holder = await _server(db, redis, "capacity-lock-a", "capacity-lock-host-a", disk_free_gb=11)
    second_holder = await _server(
        db,
        redis,
        "capacity-lock-b",
        "capacity-lock-host-b",
        disk_free_gb=11,
    )
    holder_ids = sorted([first_holder.server_id, second_holder.server_id])
    second_user_id = f"capacity-user-{uuid.uuid4().hex}"
    await db.execute(
        User.__table__.insert().values(
            user_id=second_user_id,
            username=f"cap{uuid.uuid4().hex[:8]}",
            coldkey="capacity-coldkey",
            fingerprint_hash=uuid.uuid4().hex,
            storage_volume_quota_bytes=500 * 1024**3,
            storage_aggregate_quota_bytes=2 * 1024**4,
        )
    )
    first_volume = StorageVolume(
        user_id=USER_ID,
        name=f"capacity-first-{uuid.uuid4().hex}",
        replication_factor=2,
        quota_bytes=500 * 1024**3,
        used_bytes=0,
    )
    second_volume = StorageVolume(
        user_id=second_user_id,
        name=f"capacity-second-{uuid.uuid4().hex}",
        replication_factor=2,
        quota_bytes=500 * 1024**3,
        used_bytes=0,
    )
    db.add_all([first_volume, second_volume])
    await db.commit()
    volume_ids = [first_volume.volume_id, second_volume.volume_id]
    object_size = 700 * 1024**2

    original_pick = service._pick_replicas
    original_upsert = service._upsert_pending_placement
    both_selected = asyncio.Event()
    selection_count = 0
    selected_ids: dict[int, list[str]] = {}
    upsert_order: dict[int, list[str]] = {}

    async def synchronize_initial_selection(pick_db, *args, **kwargs):
        nonlocal selection_count
        peers = await original_pick(pick_db, *args, **kwargs)
        selected_ids[id(pick_db)] = [peer.server_id for peer in peers]
        selection_count += 1
        if selection_count == 2:
            both_selected.set()
        await both_selected.wait()
        return peers

    async def record_upsert_order(upsert_db, candidate_obj, candidate_server):
        upsert_order.setdefault(id(upsert_db), []).append(candidate_server.server_id)
        return await original_upsert(upsert_db, candidate_obj, candidate_server)

    monkeypatch.setattr(service, "_pick_replicas", synchronize_initial_selection)
    monkeypatch.setattr(service, "_upsert_pending_placement", record_upsert_order)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as first_planner, factory() as second_planner:
        async def run_plan(planner, volume_id, suffix):
            planner_volume = await planner.get(StorageVolume, volume_id)
            try:
                return await service.plan_object_placement(
                    planner,
                    planner_volume,
                    str(uuid.uuid4()),
                    f"capacity-race-{suffix}",
                    object_size,
                    observed_live_storage_ids=set(holder_ids),
                )
            except Exception as exc:  # noqa: BLE001 - the losing reservation must fail closed
                await planner.rollback()
                return exc

        results = await asyncio.wait_for(
            asyncio.gather(
                run_plan(first_planner, volume_ids[0], "first"),
                run_plan(second_planner, volume_ids[1], "second"),
            ),
            timeout=20,
        )

        assert sorted(selected_ids[id(first_planner)]) == holder_ids
        assert sorted(selected_ids[id(second_planner)]) == holder_ids
        assert upsert_order[id(first_planner)] == sorted(upsert_order[id(first_planner)])
        assert upsert_order[id(second_planner)] == sorted(upsert_order[id(second_planner)])

    successes = [result for result in results if isinstance(result, tuple)]
    failures = [result for result in results if isinstance(result, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], RuntimeError)
    assert "Storage capacity changed" in str(failures[0])

    db.expire_all()
    reserved_by_server = dict(
        (
            await db.execute(
                select(
                    ReplicaPlacement.server_id,
                    func.sum(StorageObject.projected_size_bytes),
                )
                .join(StorageObject, StorageObject.object_id == ReplicaPlacement.object_id)
                .where(ReplicaPlacement.status == "pending")
                .group_by(ReplicaPlacement.server_id)
            )
        ).all()
    )
    assert reserved_by_server == {holder_id: object_size for holder_id in holder_ids}


@pytest.mark.parametrize("operation", ("plan", "commit", "issue", "consume"))
async def test_storage_liveness_is_observed_before_authority_locks(
    pg_session,
    monkeypatch,
    operation,
):
    db, redis = pg_session
    suffix = f"liveness-order-{operation}"
    if operation in {"issue", "consume"}:
        (
            source_identity,
            source,
            target,
            _volume_row,
            obj,
            _source_placement,
            _target_placement,
        ) = await _replication_fence_fixture(db, redis, suffix)
        if operation == "issue":
            async def invocation():
                return await service.issue_replication_capability(
                    db,
                    source,
                    obj.object_id,
                    target.server_id,
                    obj.sha256,
                    obj.ciphertext_size_bytes,
                )
        else:
            lease = await service.issue_replication_capability(
                db,
                source,
                obj.object_id,
                target.server_id,
                obj.sha256,
                obj.ciphertext_size_bytes,
            )

            async def invocation():
                return await service.consume_replication_capability(
                    db,
                    target,
                    lease["capability"],
                    _sign_capability(source_identity, lease["capability"]),
                )
        first_lock_name = "_lock_storage_object_transactions"
    else:
        holder = await _server(db, redis, f"{suffix}-holder", f"{suffix}-host")
        volume = await _volume(db, 1)
        if operation == "plan":
            async def invocation():
                return await service.plan_object_placement(
                    db,
                    volume,
                    str(uuid.uuid4()),
                    f"{suffix}-key",
                    37,
                )
        else:
            obj = await _object(db, volume, f"{suffix}-object", size_bytes=37)
            await _placement(db, obj, holder, status="pending")
            assert (
                await service.announce_replicas(
                    db,
                    MINER,
                    holder.server_id,
                    holder.server_id,
                    holder.storage_incarnation,
                    [
                        {
                            "object_id": obj.object_id,
                            "status": "stored",
                            "ciphertext_sha256": "7" * 64,
                            "ciphertext_size_bytes": 69,
                            "plaintext_size_bytes": 37,
                            "plaintext_sha256": "6" * 64,
                        }
                    ],
                )
                == 1
            )

            async def invocation():
                return await service.commit_object(
                    db,
                    volume,
                    obj.object_id,
                    obj.object_key,
                    obj.salt,
                )
        first_lock_name = "_lock_storage_user"

    observed = False
    first_lock_entered = False
    original_observe = service.observe_storage_liveness
    original_first_lock = getattr(service, first_lock_name)

    async def record_observation(observe_db):
        nonlocal observed
        assert not first_lock_entered
        live_ids = await original_observe(observe_db)
        observed = True
        return live_ids

    async def require_prior_observation(lock_db, *args, **kwargs):
        nonlocal first_lock_entered
        assert observed
        first_lock_entered = True
        return await original_first_lock(lock_db, *args, **kwargs)

    monkeypatch.setattr(service, "observe_storage_liveness", record_observation)
    monkeypatch.setattr(service, first_lock_name, require_prior_observation)
    await invocation()
    assert observed
    assert first_lock_entered


async def test_consume_rejects_stale_presented_target_after_identity_rebind(pg_session):
    db, redis = pg_session
    (
        source_identity,
        source,
        target,
        _volume_row,
        obj,
        _source_placement,
        target_placement,
    ) = await _replication_fence_fixture(db, redis, "consume-target-rebind")
    lease = await service.issue_replication_capability(
        db,
        source,
        obj.object_id,
        target.server_id,
        obj.sha256,
        obj.ciphertext_size_bytes,
    )
    target_id = target.server_id
    target_placement_id = target_placement.placement_id
    replacement_incarnation = str(uuid.uuid4())
    db.expire_all()
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    target_before = _pending_placement_mutation_snapshot(target_placement)

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as stale_consumer, factory() as binder:
        presented_target = await stale_consumer.get(Server, target_id)
        old_incarnation = presented_target.storage_incarnation
        current_target = await binder.get(Server, target_id)
        await service._bind_storage_identity(binder, current_target, replacement_incarnation)
        await binder.commit()
        assert presented_target.storage_incarnation == old_incarnation

        with pytest.raises(HTTPException) as rejected:
            await service.consume_replication_capability(
                stale_consumer,
                presented_target,
                lease["capability"],
                _sign_capability(source_identity, lease["capability"]),
            )
        assert rejected.value.status_code == 403
        assert "target identity changed" in rejected.value.detail
        await stale_consumer.rollback()

    db.expire_all()
    capability = await db.get(StorageReplicationCapability, lease["capability_id"])
    target_placement = await db.get(ReplicaPlacement, target_placement_id)
    assert capability.consumed_at is None
    assert capability.failed_at is None
    assert capability.last_error is None
    assert _pending_placement_mutation_snapshot(target_placement) == target_before


# --- Final storage lock/frontier regressions ---------------------------------------------------


async def _explicit_storage_volume(
    db: AsyncSession,
    volume_id: str,
) -> StorageVolume:
    volume = StorageVolume(
        volume_id=volume_id,
        user_id=USER_ID,
        name=f"volume-{volume_id}",
        replication_factor=1,
        quota_bytes=500 * 1024**3,
        used_bytes=0,
    )
    db.add(volume)
    await db.commit()
    return volume


async def test_user_erasure_prelocks_cross_volume_object_frontier_globally(
    pg_session,
    monkeypatch,
):
    db, _redis = pg_session
    first_volume = await _explicit_storage_volume(db, "00-user-erasure-volume")
    second_volume = await _explicit_storage_volume(db, "50-user-erasure-volume")
    empty_page_volume = await _explicit_storage_volume(db, "99-user-erasure-volume")
    # Per-volume iteration would discover z first and a second. The transaction must instead join
    # one globally sorted a -> z object frontier before either volume-retirement helper runs. A
    # third volume proves the single global page budget has already reached zero.
    z_object = await _object(db, first_volume, "z-user-erasure-object", size_bytes=17)
    a_object = await _object(db, second_volume, "a-user-erasure-object", size_bytes=19)
    deferred_object = await _object(
        db,
        empty_page_volume,
        "m-user-erasure-deferred-object",
        size_bytes=23,
    )
    a_object_id = a_object.object_id
    z_object_id = z_object.object_id
    deferred_object_id = deferred_object.object_id
    volume_ids = {
        first_volume.volume_id,
        second_volume.volume_id,
        empty_page_volume.volume_id,
    }
    hint_pages = []
    object_frontiers = []
    original_hints = service._deleted_volume_retirement_hints
    original_lock_objects = service._lock_storage_object_transactions

    async def capture_hints(hint_db, volume_id, *, limit):
        hints = await original_hints(hint_db, volume_id, limit=limit)
        hint_pages.append((volume_id, limit, list(hints[2]), list(hints[3])))
        return hints

    async def capture_object_frontier(lock_db, object_ids):
        object_frontiers.append(list(object_ids))
        return await original_lock_objects(lock_db, object_ids)

    monkeypatch.setattr(settings, "storage_reconcile_batch_size", 2)
    monkeypatch.setattr(service, "_deleted_volume_retirement_hints", capture_hints)
    monkeypatch.setattr(service, "_lock_storage_object_transactions", capture_object_frontier)
    outcome = await service.prepare_user_storage_erasure(db, USER_ID)

    assert [(volume_id, limit) for volume_id, limit, _objects, _history in hint_pages] == [
        (first_volume.volume_id, 2),
        (second_volume.volume_id, 1),
        (empty_page_volume.volume_id, 0),
    ]
    assert [objects for _volume_id, _limit, objects, _history in hint_pages] == [
        [z_object_id],
        [a_object_id],
        [],
    ]
    assert object_frontiers == [[a_object_id, z_object_id]]
    assert outcome["ready"] is False
    assert set(outcome["purge_pending"]) == volume_ids
    db.expire_all()
    assert (await db.get(StorageObject, deferred_object_id)).lifecycle_state == "pending"


async def test_reconcile_skip_releases_outer_locks_before_next_liveness_observation(
    pg_session,
    monkeypatch,
):
    db, redis = pg_session
    holder = await _server(db, redis, "reconcile-skip-holder", "reconcile-skip-host")
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    first = await _object(
        db,
        volume,
        "a-reconcile-skip-object",
        sha256="1" * 64,
        size_bytes=23,
    )
    second = await _object(
        db,
        volume,
        "b-reconcile-next-object",
        sha256="2" * 64,
        size_bytes=29,
    )
    await _placement(db, first, holder, status="present")
    await _placement(db, second, holder, status="present")
    first_object_id = first.object_id

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    observation_count = 0
    released_before_next_observation = {
        "advisory": False,
        "server": False,
    }
    original_observe = service.observe_storage_liveness

    async def observe_and_probe(observe_db):
        nonlocal observation_count
        observation_count += 1
        if observation_count == 2:
            async with factory() as probe:
                released_before_next_observation["advisory"] = bool(
                    await probe.scalar(
                        text(
                            "SELECT pg_try_advisory_xact_lock("
                            "hashtextextended(:lock_key, 0))"
                        ),
                        {
                            "lock_key": (
                                f"{service._STORAGE_OBJECT_TRANSACTION_FENCE_PREFIX}:"
                                f"{first_object_id}"
                            )
                        },
                    )
                )
                try:
                    locked_server_id = await probe.scalar(
                        select(Server.server_id)
                        .where(Server.server_id == holder_id)
                        .with_for_update(nowait=True)
                    )
                    released_before_next_observation["server"] = (
                        locked_server_id == holder_id
                    )
                except DBAPIError:
                    released_before_next_observation["server"] = False
                finally:
                    await probe.rollback()
        return await original_observe(observe_db)

    monkeypatch.setattr(service, "observe_storage_liveness", observe_and_probe)
    async with factory() as gate, factory() as reconciler:
        await gate.execute(
            select(StorageObject)
            .where(StorageObject.object_id == first_object_id)
            .with_for_update()
        )
        reconciling = asyncio.create_task(service.reconcile_storage(reconciler, max_objects=2))
        try:
            summary = await asyncio.wait_for(reconciling, timeout=20)
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not reconciling.done():
                reconciling.cancel()
            with suppress(asyncio.CancelledError):
                await reconciling

    assert observation_count == 2
    assert released_before_next_observation == {"advisory": True, "server": True}
    assert summary["object_failures"] == 0


async def test_erasure_finalizer_pages_large_dependent_frontier_with_bounded_queries(
    pg_session,
    monkeypatch,
):
    db, _redis = pg_session
    volume = await _explicit_storage_volume(db, "bounded-finalizer-volume")
    predecessor_id = "bounded-finalizer-predecessor"
    dependent_ids = [f"bounded-finalizer-dependent-{index:02d}" for index in range(7)]
    now = datetime.now(timezone.utc)
    await db.execute(text("SET LOCAL session_replication_role = replica"))
    await db.execute(
        StorageObject.__table__.insert().values(
            object_id=predecessor_id,
            generation=f"generation-{predecessor_id}",
            volume_id=volume.volume_id,
            object_key="bounded-finalizer-predecessor-key",
            lifecycle_state="tombstoned",
            size_bytes=0,
            projected_size_bytes=0,
            salt=base64.b64encode(hashlib.sha256(predecessor_id.encode()).digest()).decode(),
            durability_state="irrecoverable",
            durable_replica_count=0,
            tombstoned_at=now,
            erase_enqueued_at=now,
        )
    )
    for dependent_id in dependent_ids:
        await db.execute(
            StorageObject.__table__.insert().values(
                object_id=dependent_id,
                generation=f"generation-{dependent_id}",
                volume_id=volume.volume_id,
                object_key=f"key-{dependent_id}",
                lifecycle_state="tombstoned",
                expected_predecessor_id=predecessor_id,
                size_bytes=0,
                projected_size_bytes=0,
                salt=base64.b64encode(
                    hashlib.sha256(dependent_id.encode()).digest()
                ).decode(),
                durability_state="irrecoverable",
                durable_replica_count=0,
                tombstoned_at=now,
            )
        )
    await db.execute(text("SET LOCAL session_replication_role = origin"))
    await db.commit()

    captured_frontiers = []
    dependent_page_limits = []
    original_lock_objects = service._lock_storage_object_transactions
    original_execute = db.execute

    async def capture_frontier(lock_db, object_ids):
        captured_frontiers.append(list(object_ids))
        return await original_lock_objects(lock_db, object_ids)

    async def capture_dependency_limits(statement, *args, **kwargs):
        normalized = " ".join(str(statement).split())
        limit_clause = getattr(statement, "_limit_clause", None)
        if (
            "WHERE storage_objects.expected_predecessor_id" in normalized
            and limit_clause is not None
        ):
            dependent_page_limits.append(int(limit_clause.value))
        return await original_execute(statement, *args, **kwargs)

    monkeypatch.setattr(service, "_lock_storage_object_transactions", capture_frontier)
    monkeypatch.setattr(db, "execute", capture_dependency_limits)

    remaining_references = []
    purged_by_page = []
    for _ in range(3):
        purged, _shredded = await service._finalize_erasure_batch(db, limit=3)
        purged_by_page.append(purged)
        remaining_references.append(
            int(
                await db.scalar(
                    select(func.count())
                    .select_from(StorageObject)
                    .where(StorageObject.expected_predecessor_id == predecessor_id)
                )
            )
        )

    assert remaining_references == [4, 1, 0]
    assert purged_by_page == [0, 0, 1]
    assert dependent_page_limits == [4, 4, 4, 4, 4, 4]
    assert [len(frontier) for frontier in captured_frontiers] == [5, 5, 2]
    assert all(frontier[0] == predecessor_id for frontier in captured_frontiers)
    assert await db.get(StorageObject, predecessor_id) is None
    detached = list(
        (
            await db.execute(
                select(StorageObject)
                .where(StorageObject.object_id.in_(dependent_ids))
                .order_by(StorageObject.object_id)
            )
        )
        .scalars()
        .all()
    )
    assert [item.object_id for item in detached] == dependent_ids
    assert all(item.expected_predecessor_id is None for item in detached)
    assert all(item.detached_predecessor_id == predecessor_id for item in detached)


async def test_deleted_volume_finalizer_uses_user_erasure_volume_lock_order(
    pg_session,
    monkeypatch,
):
    db, _redis = pg_session
    a_volume = await _explicit_storage_volume(db, "a-finalizer-volume")
    z_volume = await _explicit_storage_volume(db, "z-finalizer-volume")
    a_volume_id = a_volume.volume_id
    z_volume_id = z_volume.volume_id

    volume_lock_statements = []
    original_execute = db.execute

    async def capture_volume_locks(statement, *args, **kwargs):
        normalized = " ".join(
            str(statement.compile(dialect=db.bind.sync_engine.dialect)).lower().split()
        )
        if "from storage_volumes" in normalized and "for update" in normalized:
            volume_lock_statements.append(normalized)
        return await original_execute(statement, *args, **kwargs)

    monkeypatch.setattr(db, "execute", capture_volume_locks)
    prepared = await service.prepare_user_storage_erasure(db, USER_ID)
    assert prepared["ready"] is False

    db.expire_all()
    a_volume = await db.get(StorageVolume, a_volume_id)
    z_volume = await db.get(StorageVolume, z_volume_id)
    # Make chronological order the inverse of ID order so the finalizer cannot accidentally pass
    # by retaining a delete_requested_at-first scan.
    a_volume.delete_requested_at = NOW
    z_volume.delete_requested_at = NOW - timedelta(minutes=1)
    await db.commit()

    _purged, shredded = await service._finalize_erasure_batch(db, limit=2)
    assert shredded == 2

    user_erasure_locks = [
        statement
        for statement in volume_lock_statements
        if "where storage_volumes.user_id =" in statement
    ]
    finalizer_locks = [
        statement
        for statement in volume_lock_statements
        if "storage_volumes.deleted is true" in statement and "skip locked" in statement
    ]
    assert len(user_erasure_locks) == 1
    assert len(finalizer_locks) == 1
    user_erasure_lock = user_erasure_locks[0]
    finalizer_lock = finalizer_locks[0]
    assert "order by storage_volumes.volume_id" in user_erasure_lock
    assert "order by storage_volumes.volume_id" in finalizer_lock
    assert "order by storage_volumes.delete_requested_at" not in finalizer_lock

    db.expire_all()
    finalized = [
        await db.get(StorageVolume, volume_id)
        for volume_id in (a_volume_id, z_volume_id)
    ]
    assert all(volume.key_shredded_at is not None for volume in finalized)
    assert all(volume.purged_at is not None for volume in finalized)


async def test_legacy_metadata_rejects_newest_failed_attestation_after_publication_wait(
    pg_session,
):
    db, redis = pg_session
    holder = await _server(db, redis, "legacy-metadata-holder", "legacy-metadata-host")
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    object_id = "legacy-metadata-object"
    placement_id = "legacy-metadata-placement"
    sensitive_hash = "d" * 64
    sensitive_salt = base64.b64encode(b"legacy-metadata-sensitive-salt!!").decode()
    await db.execute(text("SET LOCAL session_replication_role = replica"))
    await db.execute(
        StorageObject.__table__.insert().values(
            object_id=object_id,
            generation=f"generation-{object_id}",
            volume_id=volume.volume_id,
            object_key="legacy-metadata-key",
            lifecycle_state="committed",
            size_bytes=31,
            projected_size_bytes=31,
            ciphertext_size_bytes=None,
            sha256=sensitive_hash,
            salt=sensitive_salt,
            durability_state="irrecoverable",
            durable_replica_count=0,
            committed_at=NOW,
        )
    )
    await db.execute(
        ReplicaPlacement.__table__.insert().values(
            placement_id=placement_id,
            object_id=object_id,
            server_id=holder_id,
            status="evicted",
            storage_incarnation=None,
            target_cert_pubkey_hash=None,
            attempt_count=0,
            last_error="legacy_adoption_required",
        )
    )
    await db.execute(text("SET LOCAL session_replication_role = origin"))
    await db.commit()

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as reader, factory() as attestor:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        reader_pid = await reader.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        presented_holder = await reader.get(Server, holder_id)
        reading = asyncio.create_task(
            service.legacy_adoption_metadata(reader, presented_holder, object_id)
        )
        try:
            await _wait_for_postgres_blocker(db.bind, reader_pid, gate_pid)
            await _commit_failed_attestation(attestor, holder_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(reading, timeout=10)
            assert rejected.value.status_code == 403
            assert sensitive_hash not in str(rejected.value.detail)
            assert sensitive_salt not in str(rejected.value.detail)
            await reader.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not reading.done():
                reading.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await reading


@pytest.mark.parametrize(
    "authority_change",
    ("certificate", "failed_attestation"),
    ids=("certificate-replaced", "newest-attestation-failed"),
)
async def test_replica_authorization_rejects_stale_authority_after_publication_wait(
    pg_session,
    authority_change,
):
    db, redis = pg_session
    holder = await _server(
        db,
        redis,
        f"replica-authorization-{authority_change}",
        f"replica-authorization-host-{authority_change}",
    )
    holder_id = holder.server_id
    volume = await _volume(db, 1)
    obj = await _object(
        db,
        volume,
        f"replica-authorization-object-{authority_change}",
        size_bytes=43,
    )
    await _placement(db, obj, holder, status="pending")
    object_id = obj.object_id
    sensitive_salt = obj.salt

    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as gate, factory() as reader, factory() as authority_writer:
        gate_pid = await gate.scalar(text("SELECT pg_backend_pid()"))
        reader_pid = await reader.scalar(text("SELECT pg_backend_pid()"))
        await service._lock_storage_publication_servers(gate, [holder_id], shared=False)
        presented_holder = await reader.get(Server, holder_id)
        authorizing = asyncio.create_task(
            service.replica_authorization(reader, object_id, presented_holder)
        )
        try:
            await _wait_for_postgres_blocker(db.bind, reader_pid, gate_pid)
            if authority_change == "certificate":
                replacement_hash = hashlib.sha256(
                    f"replica-authorization-replacement:{holder_id}".encode()
                ).hexdigest()
                await authority_writer.execute(
                    update(Server)
                    .where(Server.server_id == holder_id)
                    .values(attested_cert_pubkey_hash=replacement_hash)
                )
                await authority_writer.commit()
            else:
                await _commit_failed_attestation(authority_writer, holder_id)
            await gate.commit()
            with pytest.raises(HTTPException) as rejected:
                await asyncio.wait_for(authorizing, timeout=10)
            assert rejected.value.status_code == 403
            assert sensitive_salt not in str(rejected.value.detail)
            await reader.rollback()
        finally:
            if gate.in_transaction():
                await gate.rollback()
            if not authorizing.done():
                authorizing.cancel()
            with suppress(asyncio.CancelledError, HTTPException):
                await authorizing
