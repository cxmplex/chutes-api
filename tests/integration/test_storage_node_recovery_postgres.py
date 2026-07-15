"""Optional local cross-repository recovery test against the real Postgres tracker."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from api.storage import service
from tests.integration import test_storage_reconciliation_postgres as api_pg

pytest_plugins = ["tests.integration.test_storage_reconciliation_postgres"]

SEK8S_SOURCE_ROOT = Path(__file__).resolve().parents[3] / "sek8s" / "src" / "sek8s"
if not SEK8S_SOURCE_ROOT.is_dir():
    pytest.skip(
        "Local cross-layer recovery test requires the sibling sek8s source checkout.",
        allow_module_level=True,
    )
sys.path.insert(0, str(SEK8S_SOURCE_ROOT))

from sek8s.storage_node.publication import write_async as node_write_async
from sek8s.storage_node.recovery import recover_pending_replications
from sek8s.storage_node.store import ContentStore

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for the local cross-layer recovery test",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """This storage-only test never invokes the external GPU attestation CLI."""
    yield


class ServiceBackedRecoveryTracker:
    """Storage-node tracker adapter that executes the real validator service against Postgres."""

    def __init__(
        self,
        db: AsyncSession,
        server_id: str,
        storage_incarnation: str,
    ):
        self.db = db
        self.server_id = server_id
        self.storage_incarnation = storage_incarnation
        self.recorded_results: list[int] = []

    async def announce_replicas(self, placements):
        recorded = await service.announce_replicas(
            self.db,
            api_pg.MINER,
            self.server_id,
            self.server_id,
            self.storage_incarnation,
            placements,
        )
        self.recorded_results.append(recorded)
        return recorded


class RestartedStorageNodeContext:
    def __init__(self, store: ContentStore, tracker: ServiceBackedRecoveryTracker):
        self.store = store
        self.tracker = tracker
        self._object_locks: dict[tuple[str, str], asyncio.Lock] = {}

    @asynccontextmanager
    async def object_write_lock(self, volume_id: str, object_id: str):
        lock = self._object_locks.setdefault((volume_id, object_id), asyncio.Lock())
        async with lock:
            yield


async def test_direct_upload_commit_restart_replay_is_cross_layer_safe(pg_session, tmp_path):
    db, redis = pg_session
    target = await api_pg._server(db, redis, "restart-target", "restart-host")
    volume = await api_pg._volume(db, 1)
    plaintext = b"direct upload plaintext"
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    obj = await api_pg._object(
        db,
        volume,
        "obj-restart-direct",
        size_bytes=len(plaintext),
    )
    placement = await api_pg._placement(db, obj, target, status="pending")
    ciphertext = b"sealed immutable ciphertext for restart replay"
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    data_dir = tmp_path / "chutefs"
    store = ContentStore(
        str(data_dir),
        str(data_dir / "models"),
        str(data_dir / "objects"),
    )

    async def ciphertext_stream():
        yield ciphertext

    written, digest, _, journal_path = await node_write_async(
        store,
        volume.volume_id,
        obj.object_id,
        ciphertext_stream(),
        expected_sha256=ciphertext_sha256,
        expected_bytes=len(ciphertext),
        publication_record={
            "receipt_kind": "direct",
            "volume_id": volume.volume_id,
            "object_id": obj.object_id,
            "plaintext_size_bytes": len(plaintext),
            "plaintext_sha256": plaintext_sha256,
        },
    )
    assert journal_path is not None and journal_path.exists()
    direct_receipt = {
        "object_id": obj.object_id,
        "status": "stored",
        "ciphertext_sha256": digest,
        "ciphertext_size_bytes": written,
        "plaintext_size_bytes": len(plaintext),
        "plaintext_sha256": plaintext_sha256,
    }
    assert (
        await service.announce_replicas(
            db,
            api_pg.MINER,
            target.server_id,
            target.server_id,
            target.storage_incarnation,
            [direct_receipt],
        )
        == 1
    )
    committed, replicas = await service.commit_object(
        db,
        volume,
        obj.object_id,
        obj.object_key,
        salt=obj.salt,
    )
    assert replicas == 1
    assert committed.lifecycle_state == "committed"

    restarted_store = ContentStore(
        str(data_dir),
        str(data_dir / "models"),
        str(data_dir / "objects"),
    )
    tracker = ServiceBackedRecoveryTracker(
        db,
        target.server_id,
        target.storage_incarnation,
    )
    restarted = RestartedStorageNodeContext(restarted_store, tracker)
    final_path = restarted_store.object_path(volume.volume_id, obj.object_id)
    original_inode = final_path.stat().st_ino
    await recover_pending_replications(restarted)

    assert tracker.recorded_results == [1]
    assert final_path.read_bytes() == ciphertext
    assert final_path.stat().st_ino == original_inode
    assert not restarted_store.list_replication_journals()

    restarted_store.write_replication_journal(
        {
            **direct_receipt,
            "receipt_kind": "direct",
            "volume_id": volume.volume_id,
            "plaintext_sha256": "f" * 64,
        }
    )
    await recover_pending_replications(restarted)

    assert tracker.recorded_results == [1, 0]
    assert final_path.read_bytes() == ciphertext
    assert final_path.stat().st_ino == original_inode
    assert not restarted_store.list_replication_journals()
    await db.refresh(placement)
    assert placement.status == "present"
    assert placement.proof_sha256 == ciphertext_sha256
    assert placement.proof_size_bytes == len(ciphertext)
    assert placement.proof_plaintext_size_bytes == len(plaintext)
    assert placement.proof_plaintext_sha256 == plaintext_sha256
    assert placement.last_error == "committed_direct_receipt_replay_mismatch"
