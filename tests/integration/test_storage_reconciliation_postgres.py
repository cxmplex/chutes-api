"""Real-Postgres durability tests for ChuteFS placement and reconciliation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import exists, func, select, text
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
    StorageModelInventorySnapshot,
    StorageReplicationCapability,
    StorageObjectDeleteFence,
    StorageVolume,
    StorageVolumeKey,
)
from api.server.util import get_public_key_hash
from api.storage import service
from api.storage.reconcile import _RECONCILE_LOCK_KEY
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
    DROP INDEX IF EXISTS idx_storage_objects_reconcile;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_lifecycle_state;
    ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS fk_storage_object_expected_predecessor;
    ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false;
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
) -> StorageObject:
    obj = StorageObject(
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


async def test_secure_replication_migration_down_up_round_trip(pg_session):
    db, redis = pg_session
    legacy_server = await _server(db, redis, "migration-storage", "migration-host")
    legacy_volume = await _volume(db, 1)
    legacy_object = await _object(db, legacy_volume, "migration-object", sha256="a" * 64)
    legacy_placement = await _placement(db, legacy_object, legacy_server, status="present")
    legacy_object_id = legacy_object.object_id
    legacy_placement_id = legacy_placement.placement_id
    connection = await db.connection()
    raw = await connection.get_raw_connection()
    driver = raw.driver_connection

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
                        text("SELECT version FROM schema_migrations WHERE version >= :cutoff"),
                        {"cutoff": database_migrations.TRACKED_MIGRATION_BASELINE},
                    )
                ).scalars()
            )
            assert versions == {
                "20260713140000",
                "20260713150000",
                "20260713160000",
                "20260713170000",
                "20260713220000",
                "20260714070000",
                "20260714071000",
                "20260714072000",
                "20260714073000",
                "20260714100000",
                "20260714110000",
                "20260715120000",
                "20260715121000",
            }
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

    changed_incarnation = str(uuid.uuid4())
    assert (
        await service.announce_replicas(
            db,
            MINER,
            target.server_id,
            target.server_id,
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

    source_incarnation_lease = await service.issue_replication_capability(
        db, source, obj.object_id, target.server_id, digest, ciphertext_size
    )
    source_incarnation = source.storage_incarnation
    source.storage_incarnation = str(uuid.uuid4())
    await db.commit()
    with pytest.raises(HTTPException) as stale_source_incarnation:
        await service.consume_replication_capability(
            db,
            target,
            source_incarnation_lease["capability"],
            _sign_capability(source_identity, source_incarnation_lease["capability"]),
        )
    assert stale_source_incarnation.value.status_code == 409
    source.storage_incarnation = source_incarnation
    await db.commit()

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
    target.attested_cert_pubkey_hash = target_cert_hash
    await db.commit()

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
    assert located_after.object_id == replacement.object_id
    assert [item.object_id for item in listed_after] == [replacement.object_id]
    assert old.lifecycle_state == "superseded"


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
    heartbeat_started_at = datetime.now(timezone.utc)
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

        heartbeat_started_at = datetime.now(timezone.utc)
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
        holder.attested_cert_pubkey_hash = hashlib.sha256(
            b"replacement-attested-certificate"
        ).hexdigest()
        db.add(
            ServerAttestation(
                server_id=holder_id,
                quote_data="replacement-quote",
                measurement_version=_storage_version(),
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
    newest_waiting_id = waiting_snapshot_ids[-1]
    for _ in range(20):
        await service._reconcile_model_inventory_snapshots(db, max_snapshots=1, max_entries=250)
        db.expire_all()
        newest_waiting = await db.get(StorageModelInventorySnapshot, newest_waiting_id)
        if newest_waiting.state == "reconciled":
            break
    else:
        pytest.fail("newest waiting model snapshot did not reconcile")

    assert newest_waiting.application_started_at is not None
    for superseded_id in waiting_snapshot_ids[:-1]:
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
    ] == [("org/winner", len(waiting_snapshot_ids) - 1, newest_waiting_id)]


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


async def test_reconcile_advisory_lock_survives_long_overlap(pg_session):
    db, _redis = pg_session
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
    async with factory() as leader, factory() as contender:
        leader_won = (
            await leader.execute(
                text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                {"lock_key": _RECONCILE_LOCK_KEY},
            )
        ).scalar_one()
        assert leader_won
        await asyncio.sleep(0.05)
        contender_won = (
            await contender.execute(
                text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                {"lock_key": _RECONCILE_LOCK_KEY},
            )
        ).scalar_one()
        assert not contender_won
        await leader.execute(
            text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
            {"lock_key": _RECONCILE_LOCK_KEY},
        )
        assert (
            await contender.execute(
                text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                {"lock_key": _RECONCILE_LOCK_KEY},
            )
        ).scalar_one()
        await contender.execute(
            text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
            {"lock_key": _RECONCILE_LOCK_KEY},
        )
