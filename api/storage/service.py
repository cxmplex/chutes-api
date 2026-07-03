"""ChuteFS storage tracker business logic.

The validator is the coordinator, never a data path: it records who holds what, vouches for peers'
attested certs, custodies per-volume keys (released only to attested replica-holders), and meters
per-volume bytes. All object bytes flow peer-to-peer over mutually-attested TLS, never through here.
"""

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Set

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.server.quote import build_runtime_quote
from api.server.schemas import (
    ContentHolding,
    ReplicaPlacement,
    Server,
    ServerAttestation,
    StorageObject,
    StorageVolume,
    StorageVolumeKey,
)
from api.server.util import (
    decrypt_passphrase,
    encrypt_passphrase,
    get_public_key_hash,
    get_matching_measurement_config,
    verify_quote,
)
from api.storage.schemas import StoragePeer

# How long a storage TD's announce/heartbeat keeps it eligible as a live peer (seconds).
STORAGE_PEER_TTL_SECONDS = 180
# Default storage-node DNAT port name the TD advertises in external_ports.
STORAGE_PORT_KEY = "storage"
# L5: how long a reserved-but-never-committed (size-0, no present holder) object lingers before the
# reconcile loop reaps it. Well beyond the put + grant window so an in-flight large upload is safe.
_ABANDONED_OBJECT_TTL_SECONDS = 24 * 3600
# How long an object-op grant is valid (seconds). Must exceed the whole put window: the primary
# forwards the SAME grant to replica peers only AFTER receiving the full body (SDK put timeout 3600s),
# and each replicate is itself up to 3600s -- so a shorter TTL made every replica of a >~15min upload
# 403 with the caller still told "success", silently landing the object at rf=1 (H3). Cover push +
# replicate; the reconcile loop re-replicates anything still short.
GRANT_TTL_SECONDS = 7200


# --- liveness ----------------------------------------------------------------------------------


async def mark_storage_online(server_id: str) -> None:
    """Refresh a storage TD's liveness on announce (its heartbeat into the peer directory)."""
    try:
        await settings.redis_client.setex(f"storage:online:{server_id}", STORAGE_PEER_TTL_SECONDS, "1")
    except Exception:  # noqa: BLE001 - liveness is best-effort; attestation is the trust anchor
        logger.warning(f"Failed to mark storage TD {server_id} online")


async def _live_storage_ids(server_ids: Sequence[str]) -> Set[str]:
    if not server_ids:
        return set()
    live: Set[str] = set()
    for sid in server_ids:
        try:
            if await settings.redis_client.exists(f"storage:online:{sid}"):
                live.add(sid)
        except Exception:  # noqa: BLE001
            pass
    return live


async def _verified_storage_ids(db: AsyncSession, server_ids: Sequence[str]) -> Set[str]:
    """Return the subset of server_ids whose LATEST attestation verified (no verification_error)."""
    if not server_ids:
        return set()
    # Latest attestation per server (created_at desc), then keep those with no verification_error.
    latest = (
        select(
            ServerAttestation.server_id,
            ServerAttestation.verification_error,
            func.row_number()
            .over(
                partition_by=ServerAttestation.server_id,
                order_by=ServerAttestation.created_at.desc(),
            )
            .label("rn"),
        )
        .where(ServerAttestation.server_id.in_(list(server_ids)))
        .subquery()
    )
    rows = (
        await db.execute(
            select(latest.c.server_id).where(latest.c.rn == 1, latest.c.verification_error.is_(None))
        )
    ).all()
    return {r[0] for r in rows}


def _cert_pubkey_hash(pem: Optional[str]) -> Optional[str]:
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
        return get_public_key_hash(cert)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Failed to parse attested cert for pubkey hash: {exc}")
        return None


def _server_pubkey_hash(server: Server) -> Optional[str]:
    """The server's attested-cert pubkey hash (indexed column, recomputed from PEM as a fallback)."""
    return server.attested_cert_pubkey_hash or _cert_pubkey_hash(server.attested_cert)


def _to_peer(server: Server, include_cert: bool = False) -> Optional[StoragePeer]:
    """Build a StoragePeer from a storage-role Server, or None if it lacks reachability/cert.

    include_cert inlines the attested cert PEM (for the user-facing placement/locate flows, where an
    off-TD client cannot use the attested-caller cert authority).
    """
    host = server.external_host or server.ip
    ports = server.external_ports or {}
    port = ports.get(STORAGE_PORT_KEY)
    pubkey_hash = _server_pubkey_hash(server)
    if not host or not port or not pubkey_hash:
        return None
    return StoragePeer(
        server_id=server.server_id,
        host=host,
        port=int(port),
        cert_pubkey_hash=pubkey_hash,
        attested_cert=server.attested_cert if include_cert else None,
    )


async def find_server_by_attested_cert_hash(db: AsyncSession, cert_hash: str) -> Optional[Server]:
    """Map a presented attested mTLS cert (its pubkey hash) to its registered server row, or None.

    Used to authenticate "this request comes from inside some attested TD" for peer discovery.
    """
    if not cert_hash:
        return None
    return (
        await db.execute(
            select(Server).where(Server.attested_cert_pubkey_hash == cert_hash)
        )
    ).scalar_one_or_none()


async def is_attested_server_cert(db: AsyncSession, cert_hash: str) -> bool:
    """Whether cert_hash belongs to some registered attested server (M15 model-ensure gate)."""
    return await find_server_by_attested_cert_hash(db, cert_hash) is not None


async def _attested_live_peers(
    db: AsyncSession, servers: Sequence[Server], include_cert: bool = False
) -> List[StoragePeer]:
    """Filter servers to attested + live + reachable storage peers, as StoragePeer objects."""
    ids = [s.server_id for s in servers]
    verified = await _verified_storage_ids(db, ids)
    live = await _live_storage_ids(ids)
    peers: List[StoragePeer] = []
    for s in servers:
        if s.server_id not in verified or s.server_id not in live:
            continue
        peer = _to_peer(s, include_cert=include_cert)
        if peer is not None:
            peers.append(peer)
    return peers


async def _storage_servers_by_id(db: AsyncSession, server_ids: Sequence[str]) -> List[Server]:
    if not server_ids:
        return []
    return list(
        (
            await db.execute(
                select(Server).where(
                    Server.server_id.in_(list(server_ids)),
                    Server.storage_role.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )


# --- ownership / lookup helpers ----------------------------------------------------------------


async def _get_storage_server(db: AsyncSession, server_id: str, miner_hotkey: str) -> Server:
    server = (
        await db.execute(
            select(Server).where(
                Server.server_id == server_id,
                Server.miner_hotkey == miner_hotkey,
                Server.storage_role.is_(True),
            )
        )
    ).scalar_one_or_none()
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No storage-role server with that id owned by this miner.",
        )
    return server


async def _get_owned_volume(db: AsyncSession, volume_id: str, user_id: str) -> StorageVolume:
    volume = (
        await db.execute(
            select(StorageVolume).where(
                StorageVolume.volume_id == volume_id,
                StorageVolume.user_id == user_id,
                StorageVolume.deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")
    return volume


# --- model distribution registry ---------------------------------------------------------------


async def announce_model_holdings(
    db: AsyncSession,
    miner_hotkey: str,
    server_id: str,
    disk_free_gb: Optional[int],
    holdings: List[Dict],
) -> int:
    """Record/refresh the public model repos a storage TD holds + its free disk; heartbeat it."""
    server = await _get_storage_server(db, server_id, miner_hotkey)
    if disk_free_gb is not None:
        server.disk_free_gb = int(disk_free_gb)
    recorded = 0
    for h in holdings:
        repo_id = h["repo_id"]
        revision = h.get("revision") or "main"
        existing = (
            await db.execute(
                select(ContentHolding).where(
                    ContentHolding.server_id == server_id,
                    ContentHolding.repo_id == repo_id,
                    ContentHolding.revision == revision,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                ContentHolding(
                    server_id=server_id,
                    repo_id=repo_id,
                    revision=revision,
                    bytes=int(h.get("bytes") or 0),
                    status="present",
                    announced_at=func.now(),
                )
            )
        else:
            existing.bytes = int(h.get("bytes") or existing.bytes)
            existing.status = "present"
            existing.announced_at = func.now()
        recorded += 1
    await db.commit()
    await mark_storage_online(server_id)
    return recorded


async def local_storage_peer(db: AsyncSession, host_id: str) -> Optional[StoragePeer]:
    """The attested storage TD on a given L0 host (for a chute to reach its same-host storage node).

    Same-host chute<->storage traffic is L2-isolated, so it traverses the host DNAT at
    external_host:<storage port> exactly like a cross-host peer -- this just resolves which one is local.
    """
    servers = list(
        (
            await db.execute(
                select(Server).where(
                    Server.storage_role.is_(True), Server.host_id == host_id
                )
            )
        )
        .scalars()
        .all()
    )
    peers = await _attested_live_peers(db, servers)
    return peers[0] if peers else None


async def model_peers(db: AsyncSession, repo_id: str, revision: str) -> List[StoragePeer]:
    """Return attested, live storage peers that hold (repo_id, revision)."""
    rows = (
        await db.execute(
            select(Server)
            .join(ContentHolding, ContentHolding.server_id == Server.server_id)
            .where(
                ContentHolding.repo_id == repo_id,
                ContentHolding.revision == revision,
                ContentHolding.status == "present",
                Server.storage_role.is_(True),
            )
            .distinct()
        )
    ).scalars().all()
    return await _attested_live_peers(db, rows)


# --- peer-cert authority (workstream D) ---------------------------------------------------------


async def peer_cert(db: AsyncSession, server_id: str) -> tuple[str, str]:
    """Return (attested_cert_pem, cert_pubkey_hash) for a storage TD so a peer can pin it.

    The per-TD serving certs are self-issued (no shared CA), so the validator vouches for the
    attested cert it pinned at registration; this is the trust anchor for peer mutual TLS.
    """
    server = (
        await db.execute(
            select(Server).where(Server.server_id == server_id, Server.storage_role.is_(True))
        )
    ).scalar_one_or_none()
    if server is None or not server.attested_cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No attested storage peer with that id."
        )
    pubkey_hash = _server_pubkey_hash(server)
    if not pubkey_hash:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Peer cert unavailable.")
    return server.attested_cert, pubkey_hash


# --- confidential volumes ----------------------------------------------------------------------


def _volume_response(volume: StorageVolume) -> Dict:
    return {
        "volume_id": volume.volume_id,
        "name": volume.name,
        "replication_factor": volume.replication_factor,
        "quota_bytes": volume.quota_bytes,
        "used_bytes": volume.used_bytes,
        "created_at": volume.created_at.isoformat() if volume.created_at else "",
    }


async def create_volume(
    db: AsyncSession, user_id: str, name: str, replication_factor: int, quota_bytes: int
) -> StorageVolume:
    """Create a confidential volume and generate + store its (encrypted) application-layer key."""
    existing = (
        await db.execute(
            select(StorageVolume).where(
                StorageVolume.user_id == user_id,
                StorageVolume.name == name,
                StorageVolume.deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"Volume '{name}' already exists."
        )
    volume = StorageVolume(
        user_id=user_id,
        name=name,
        replication_factor=replication_factor,
        quota_bytes=quota_bytes,
        used_bytes=0,
    )
    db.add(volume)
    await db.flush()
    # Per-volume application-layer key (32 bytes), encrypted at rest with the same Fernet primitive
    # as LUKS passphrases; released only to attested storage TDs that hold a replica of this volume.
    key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()
    db.add(StorageVolumeKey(volume_id=volume.volume_id, encrypted_key=encrypt_passphrase(key_b64)))
    await db.commit()
    await db.refresh(volume)
    logger.success(f"Created ChuteFS volume {volume.volume_id} ({name}) for user {user_id}")
    return volume


async def list_volumes(db: AsyncSession, user_id: str) -> List[StorageVolume]:
    return list(
        (
            await db.execute(
                select(StorageVolume).where(
                    StorageVolume.user_id == user_id, StorageVolume.deleted.is_(False)
                )
            )
        )
        .scalars()
        .all()
    )


async def delete_volume(db: AsyncSession, volume_id: str, user_id: str) -> None:
    volume = await _get_owned_volume(db, volume_id, user_id)
    volume.deleted = True
    # Soft-delete the objects, and DROP their replica_placement rows now (the ON DELETE CASCADE only
    # fires on a hard object delete, and objects are soft-deleted). This stops locate from returning
    # holders for a deleted volume and keeps placement rows from growing unbounded (M7).
    object_ids = [
        r[0]
        for r in (
            await db.execute(
                select(StorageObject.object_id).where(StorageObject.volume_id == volume_id)
            )
        ).all()
    ]
    await db.execute(
        update(StorageObject).where(StorageObject.volume_id == volume_id).values(deleted=True)
    )
    if object_ids:
        await db.execute(
            ReplicaPlacement.__table__.delete().where(
                ReplicaPlacement.object_id.in_(object_ids)
            )
        )
    await db.commit()
    logger.info(f"Deleted ChuteFS volume {volume_id} for user {user_id}")


# --- object placement / commit / locate (replication + byte accounting) ------------------------


async def _pick_replicas(db: AsyncSession, replication_factor: int) -> List[StoragePeer]:
    """Pick up to replication_factor attested, live storage peers on DISTINCT hosts (durability)."""
    servers = list(
        (await db.execute(select(Server).where(Server.storage_role.is_(True)))).scalars().all()
    )
    peers = await _attested_live_peers(db, servers, include_cert=True)
    # Map server_id -> host_id for distinct-host placement.
    host_by_id = {s.server_id: (s.host_id or s.server_id) for s in servers}
    chosen: List[StoragePeer] = []
    used_hosts: Set[str] = set()
    # Prefer distinct hosts first; then fill from the rest if we still need replicas.
    for peer in peers:
        host = host_by_id.get(peer.server_id, peer.server_id)
        if host in used_hosts:
            continue
        chosen.append(peer)
        used_hosts.add(host)
        if len(chosen) >= replication_factor:
            break
    if len(chosen) < replication_factor:
        for peer in peers:
            if peer in chosen:
                continue
            chosen.append(peer)
            if len(chosen) >= replication_factor:
                break
    return chosen


async def plan_object_placement(
    db: AsyncSession, volume: StorageVolume, key: str, size_bytes: int
) -> tuple[StorageObject, List[StoragePeer]]:
    """Reserve/locate the object row and return the target replica set (quota-enforced)."""
    obj = (
        await db.execute(
            select(StorageObject).where(
                StorageObject.volume_id == volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    prior = obj.size_bytes if obj is not None else 0
    projected = volume.used_bytes - prior + size_bytes
    if projected > volume.quota_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Volume quota exceeded: {projected} > {volume.quota_bytes} bytes.",
        )
    if obj is None:
        # Create with size_bytes=0 (reserve nothing yet); commit_object sets the real size and does
        # used_bytes += size_bytes. If we stored size_bytes here, commit's delta would be 0 and the
        # quota would never be enforced for new objects.
        obj = StorageObject(
            volume_id=volume.volume_id, object_key=key, size_bytes=0, deleted=False
        )
        db.add(obj)
        await db.flush()
    peers = await _pick_replicas(db, volume.replication_factor)
    if not peers:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No attested storage peers are currently available for placement.",
        )
    # Assign the chosen peers as PENDING replicas now, so each one passes the "holds/assigned a
    # replica" gate when it calls release_volume_key to obtain the key it needs to encrypt the bytes
    # (commit_object promotes the holders that confirm to "present"). Bootstraps the first object.
    existing_servers = {
        p.server_id
        for p in (
            await db.execute(
                select(ReplicaPlacement).where(ReplicaPlacement.object_id == obj.object_id)
            )
        ).scalars().all()
    }
    for peer in peers:
        if peer.server_id not in existing_servers:
            db.add(
                ReplicaPlacement(object_id=obj.object_id, server_id=peer.server_id, status="pending")
            )
    await db.commit()
    await db.refresh(obj)
    return obj, peers


async def commit_object(
    db: AsyncSession,
    volume: StorageVolume,
    object_id: str,
    key: str,
    size_bytes: int,
    sha256: Optional[str],
    holder_server_ids: List[str],
    salt: Optional[str] = None,
    plaintext_sha256: Optional[str] = None,
) -> tuple[StorageObject, int]:
    """Finalize an object: record replica placements, update byte accounting (quota-enforced).

    Returns (object, replicas_confirmed). The caller surfaces replicas_confirmed vs the volume's
    replication_factor so an under-replicated commit is reported truthfully instead of as a plain
    success; the reconcile loop then re-replicates it up to target (H3/M7).
    """
    obj = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.object_id == object_id,
                StorageObject.volume_id == volume.volume_id,
            )
            # M3: row-lock the object so two concurrent commits of the SAME object read a consistent
            # `prior` size and can't double-apply the used_bytes delta.
            .with_for_update()
        )
    ).scalar_one_or_none()
    if obj is None or obj.object_key != key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    # Only count holders that are real storage-role servers (cannot inflate replication by claiming).
    valid_holders = {s.server_id for s in await _storage_servers_by_id(db, holder_server_ids)}
    if not valid_holders:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid storage-role holders in holder_server_ids.",
        )
    prior = obj.size_bytes
    delta = size_bytes - prior
    obj.size_bytes = size_bytes
    obj.sha256 = sha256
    # H1: anchor the v3 salt + plaintext hash in the tracker so decryption binds to (volume, object,
    # salt) and get() can verify end-to-end. The storage node reports both after sealing.
    obj.salt = salt
    obj.plaintext_sha256 = plaintext_sha256
    obj.deleted = False
    # Reconcile replica placements to exactly the confirmed holders.
    existing = (
        await db.execute(select(ReplicaPlacement).where(ReplicaPlacement.object_id == object_id))
    ).scalars().all()
    existing_by_server = {p.server_id: p for p in existing}
    # Only promote holders that the validator ASSIGNED a placement (pending/present) at plan time.
    # plan_object_placement created a pending row for every chosen replica (incl. the primary), and
    # the primary replicates only to the validator-derived peer set, so every genuine holder already
    # has a row. Refusing to CREATE a present row for an unassigned server (mirrors M1) stops an owner
    # from faking full replication by naming arbitrary storage servers in holder_server_ids.
    confirmed = 0
    for sid in valid_holders:
        placement = existing_by_server.get(sid)
        if placement is None:
            logger.warning(
                f"commit_object: ignoring holder {sid} for object {object_id} with no assigned "
                "placement (unrequested replica claim)."
            )
            continue
        placement.status = "present"
        placement.confirmed_at = func.now()
        confirmed += 1
    if confirmed == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No confirmed holders had an assigned placement for this object.",
        )
    confirmed_servers = {sid for sid in valid_holders if sid in existing_by_server}
    for sid, placement in existing_by_server.items():
        if sid not in confirmed_servers:
            placement.status = "evicted"
    # M3: atomic byte accounting. A self-referential UPDATE (row-locked in Postgres) instead of a
    # read-modify-write, so concurrent commits to the same volume can't lose updates and drift the
    # owner past quota. On growth the quota ceiling is enforced IN the same statement (rowcount==0 =>
    # would exceed -> 413, and the surrounding transaction rolls back the object/placement changes).
    if delta > 0:
        res = await db.execute(
            update(StorageVolume)
            .where(
                StorageVolume.volume_id == volume.volume_id,
                StorageVolume.used_bytes + delta <= StorageVolume.quota_bytes,
            )
            .values(used_bytes=StorageVolume.used_bytes + delta)
        )
        if (res.rowcount or 0) == 0:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Volume quota exceeded (would exceed {volume.quota_bytes} bytes).",
            )
    elif delta < 0:
        await db.execute(
            update(StorageVolume)
            .where(StorageVolume.volume_id == volume.volume_id)
            .values(used_bytes=func.greatest(0, StorageVolume.used_bytes + delta))
        )
    await db.commit()
    await db.refresh(obj)
    await db.refresh(volume)
    # Report the count that ACTUALLY had an assigned placement (not just what the client named).
    replicas_confirmed = confirmed
    if replicas_confirmed < volume.replication_factor:
        logger.warning(
            f"ChuteFS object {object_id} committed under-replicated: {replicas_confirmed}/"
            f"{volume.replication_factor} holders; reconcile will re-replicate."
        )
    return obj, replicas_confirmed


async def _live_attested_server_ids(db: AsyncSession) -> Set[str]:
    """server_ids of storage servers that are currently BOTH attested and live (heartbeating)."""
    all_ids = [
        s.server_id
        for s in (
            await db.execute(select(Server.server_id).where(Server.storage_role.is_(True)))
        ).all()
    ]
    if not all_ids:
        return set()
    verified = await _verified_storage_ids(db, all_ids)
    live = await _live_storage_ids(all_ids)
    return verified & live


async def reconcile_storage(db: AsyncSession, max_objects: int = 500) -> Dict[str, int]:
    """Repair pass (M7): GC dead placements, then re-assign replicas for under-target live objects.

    - Drops replica_placement rows for soft-deleted objects and for placements whose server row is
      gone (a reaped storage TD), so accounting + locate reflect reality.
    - For each live object whose PRESENT holders on currently attested+live servers are below the
      volume's replication_factor, assigns fresh PENDING placements on distinct healthy hosts. The
      actual ciphertext copy is executed by a source storage TD via GET /storage/repair/tasks.

    Returns a summary of counts. Bounded per pass (max_objects) so a large fleet reconciles amortized.
    """
    # (Placements for a hard-deleted server cascade-delete via the server_id FK, so no orphan GC.)
    summary = {
        "gc_deleted_object_placements": 0,
        "reaped_abandoned": 0,
        "reassigned": 0,
        "under_replicated": 0,
    }

    # L5: reap ABANDONED placements -- a put that reserved a size-0 object + pending rows but never
    # committed. After a generous TTL (well beyond the put+grant window) with no present holder and
    # still size 0, soft-delete the object so it stops showing in list()/locate() as a phantom.
    abandon_cutoff = datetime.now(timezone.utc) - timedelta(seconds=_ABANDONED_OBJECT_TTL_SECONDS)
    abandoned = list(
        (
            await db.execute(
                select(StorageObject).where(
                    StorageObject.deleted.is_(False),
                    StorageObject.size_bytes == 0,
                    StorageObject.created_at < abandon_cutoff,
                    ~select(ReplicaPlacement.placement_id)
                    .where(
                        ReplicaPlacement.object_id == StorageObject.object_id,
                        ReplicaPlacement.status == "present",
                    )
                    .exists(),
                )
            )
        )
        .scalars()
        .all()
    )
    for obj in abandoned:
        obj.deleted = True
        summary["reaped_abandoned"] += 1

    # GC placements for soft-deleted objects (soft delete does not fire the ON DELETE CASCADE); this
    # also sweeps the placements of anything reaped just above once it commits below.
    if summary["reaped_abandoned"]:
        await db.flush()
    deleted_obj_ids = [
        r[0]
        for r in (
            await db.execute(select(StorageObject.object_id).where(StorageObject.deleted.is_(True)))
        ).all()
    ]
    if deleted_obj_ids:
        res = await db.execute(
            ReplicaPlacement.__table__.delete().where(
                ReplicaPlacement.object_id.in_(deleted_obj_ids)
            )
        )
        summary["gc_deleted_object_placements"] = res.rowcount or 0

    live_ids = await _live_attested_server_ids(db)
    # Map server_id -> host for distinct-host placement, over all storage servers.
    servers = list(
        (await db.execute(select(Server).where(Server.storage_role.is_(True)))).scalars().all()
    )
    host_by_server = {s.server_id: (s.host_id or s.server_id) for s in servers}

    # Under-replicated live objects: assign fresh pending placements on distinct healthy hosts.
    # Random ordering (not a stable LIMIT window) so that with more than max_objects live objects, a
    # persistently under-replicated object beyond the first page is still eventually examined across
    # passes rather than being starved behind a stable prefix of healthy objects.
    live_objects = list(
        (
            await db.execute(
                select(StorageObject)
                .join(StorageVolume, StorageVolume.volume_id == StorageObject.volume_id)
                .where(StorageObject.deleted.is_(False), StorageVolume.deleted.is_(False))
                .order_by(func.random())
                .limit(max_objects)
            )
        )
        .scalars()
        .all()
    )
    for obj in live_objects:
        volume = await db.get(StorageVolume, obj.volume_id)
        if volume is None:
            continue
        placements = list(
            (
                await db.execute(
                    select(ReplicaPlacement).where(ReplicaPlacement.object_id == obj.object_id)
                )
            )
            .scalars()
            .all()
        )
        present_live = [p for p in placements if p.status == "present" and p.server_id in live_ids]
        pending_live = [p for p in placements if p.status == "pending" and p.server_id in live_ids]
        # Reap pendings whose target is no longer live: they will never confirm, so they must not
        # count toward the target (nor pin their host) -- otherwise the gap can never be filled.
        for p in placements:
            if p.status == "pending" and p.server_id not in live_ids:
                p.status = "evicted"
        # Count already-assigned live pendings toward the target so repeated passes DON'T keep adding
        # new pendings (which converged rf=3 objects to 4-5+ replicas); only fill the true gap.
        effective = len(present_live) + len(pending_live)
        if effective >= volume.replication_factor:
            continue
        summary["under_replicated"] += 1
        # Hosts already covered by a live present/pending placement -- keep replicas on DISTINCT hosts.
        used_hosts = {
            host_by_server.get(p.server_id, p.server_id) for p in (present_live + pending_live)
        }
        assigned_servers = {p.server_id for p in (present_live + pending_live)}
        needed = volume.replication_factor - effective
        candidates = await _attested_live_peers(db, servers)
        for peer in candidates:
            if needed <= 0:
                break
            host = host_by_server.get(peer.server_id, peer.server_id)
            if peer.server_id in assigned_servers or host in used_hosts:
                continue
            db.add(
                ReplicaPlacement(object_id=obj.object_id, server_id=peer.server_id, status="pending")
            )
            used_hosts.add(host)
            assigned_servers.add(peer.server_id)
            needed -= 1
            summary["reassigned"] += 1
    await db.commit()
    if summary["reassigned"] or summary["gc_deleted_object_placements"]:
        logger.info(f"ChuteFS reconcile: {summary}")
    return summary


async def repair_tasks_for_server(db: AsyncSession, server_id: str, max_tasks: int = 25) -> List[Dict]:
    """Objects THIS storage TD holds (present) that need copies pushed to newly-assigned peers (M7).

    Returns [{object_id, volume_id, grant, peers:[{server_id,host,port}]}]. The grant is a short-lived
    system put-grant the source TD forwards to each target's /replicate; peers are the object's
    pending placements on OTHER servers. Only objects the caller actually holds are returned.
    """
    held_object_ids = [
        r[0]
        for r in (
            await db.execute(
                select(ReplicaPlacement.object_id).where(
                    ReplicaPlacement.server_id == server_id, ReplicaPlacement.status == "present"
                )
            )
        ).all()
    ]
    tasks: List[Dict] = []
    for object_id in held_object_ids:
        if len(tasks) >= max_tasks:
            break
        obj = await db.get(StorageObject, object_id)
        if obj is None or obj.deleted:
            continue
        volume = await db.get(StorageVolume, obj.volume_id)
        if volume is None or volume.deleted:
            continue
        pending_ids = [
            p.server_id
            for p in (
                await db.execute(
                    select(ReplicaPlacement).where(
                        ReplicaPlacement.object_id == object_id,
                        ReplicaPlacement.status == "pending",
                        ReplicaPlacement.server_id != server_id,
                    )
                )
            )
            .scalars()
            .all()
        ]
        if not pending_ids:
            continue
        target_servers = await _storage_servers_by_id(db, pending_ids)
        peers = await _attested_live_peers(db, target_servers)
        if not peers:
            continue
        # TTL must cover the repair push window (the source TD replicates with a 3600s timeout, and a
        # batch of tasks is pushed sequentially), matching the user put-grant TTL rather than 900s.
        grant = await _issue_system_grant(obj.volume_id, ["put"], ttl=GRANT_TTL_SECONDS)
        tasks.append(
            {
                "object_id": object_id,
                "volume_id": obj.volume_id,
                "grant": grant,
                "peers": [p.model_dump() for p in peers],
            }
        )
    return tasks


async def object_replica_peers(db: AsyncSession, object_id: str) -> List[StoragePeer]:
    """The storage peers the validator ASSIGNED for an object (pending or present).

    The primary storage TD replicates to THIS set instead of a client-supplied ``X-ChuteFS-Peers``
    header, so a user cannot pin replicas onto storage nodes of its choosing or collapse them onto
    correlated hosts (M2) -- the tracker's distinct-host placement stays authoritative.
    """
    server_ids = [
        p.server_id
        for p in (
            await db.execute(
                select(ReplicaPlacement).where(
                    ReplicaPlacement.object_id == object_id,
                    ReplicaPlacement.status.in_(("present", "pending")),
                )
            )
        ).scalars().all()
    ]
    servers = await _storage_servers_by_id(db, server_ids)
    return await _attested_live_peers(db, servers)


async def locate_object(
    db: AsyncSession, volume: StorageVolume, key: str
) -> tuple[StorageObject, List[StoragePeer]]:
    obj = (
        await db.execute(
            select(StorageObject).where(
                StorageObject.volume_id == volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    holder_ids = [
        p.server_id
        for p in (
            await db.execute(
                select(ReplicaPlacement).where(
                    ReplicaPlacement.object_id == obj.object_id, ReplicaPlacement.status == "present"
                )
            )
        ).scalars().all()
    ]
    servers = await _storage_servers_by_id(db, holder_ids)
    peers = await _attested_live_peers(db, servers, include_cert=True)
    return obj, peers


async def list_objects(
    db: AsyncSession,
    volume: StorageVolume,
    prefix: Optional[str],
    limit: int,
    after: Optional[str] = None,
) -> List[StorageObject]:
    query = select(StorageObject).where(
        StorageObject.volume_id == volume.volume_id, StorageObject.deleted.is_(False)
    )
    if prefix:
        query = query.where(StorageObject.object_key.like(f"{prefix}%"))
    # L4: keyset cursor -- return keys strictly AFTER the caller's last-seen key so a volume with more
    # than `limit` objects can be fully enumerated (page by passing the previous page's last key).
    if after:
        query = query.where(StorageObject.object_key > after)
    query = query.order_by(StorageObject.object_key).limit(limit)
    return list((await db.execute(query)).scalars().all())


async def delete_object(db: AsyncSession, volume: StorageVolume, key: str) -> int:
    obj = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.volume_id == volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.deleted.is_(False),
            )
            # M3: row-lock so a concurrent delete of the same object can't double-decrement used_bytes
            # (the second waits, then sees deleted=True and 404s below).
            .with_for_update()
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    obj.deleted = True
    await db.execute(
        update(ReplicaPlacement)
        .where(ReplicaPlacement.object_id == obj.object_id)
        .values(status="evicted")
    )
    # M3: atomic decrement (clamped at 0), not a read-modify-write, so it can't lose updates.
    await db.execute(
        update(StorageVolume)
        .where(StorageVolume.volume_id == volume.volume_id)
        .values(used_bytes=func.greatest(0, StorageVolume.used_bytes - obj.size_bytes))
    )
    await db.commit()
    await db.refresh(volume)
    return volume.used_bytes


async def announce_replicas(
    db: AsyncSession, miner_hotkey: str, server_id: str, placements: List[Dict]
) -> int:
    """A storage TD reports the object replicas it now holds (replication confirmation)."""
    await _get_storage_server(db, server_id, miner_hotkey)
    recorded = 0
    for p in placements:
        object_id = p["object_id"]
        new_status = p.get("status") or "present"
        existing = (
            await db.execute(
                select(ReplicaPlacement).where(
                    ReplicaPlacement.object_id == object_id,
                    ReplicaPlacement.server_id == server_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            # M1: refuse to forge a placement the validator never assigned. A 'present' claim is only
            # honored when plan_object_placement already created a (pending/present) row for
            # (object_id, server_id) -- otherwise a storage-owning miner who learns an object_id could
            # inflate replication accounting and satisfy the key-release replica gate for a volume it
            # was never assigned. A non-assigned announce (present or evicted) is a no-op.
            logger.warning(
                f"Ignoring unassigned replica announce for object {object_id} from {server_id} "
                f"(status={new_status}); no prior placement."
            )
            continue
        existing.status = new_status
        existing.confirmed_at = func.now() if new_status == "present" else existing.confirmed_at
        recorded += 1
    await db.commit()
    await mark_storage_online(server_id)
    return recorded


# --- per-volume key release (attested storage TD only) -----------------------------------------


async def release_volume_key(
    db: AsyncSession,
    volume_id: str,
    miner_hotkey: str,
    server_id: str,
    quote_b64: str,
    tee_type: str,
    snp_cert_chain: Optional[str],
    vtpm_quote: Optional[Dict],
    expected_nonce: str,
    expected_cert_hash: str,
) -> str:
    """Release a confidential volume's app-layer key to an attested storage TD holding a replica.

    Gate: (1) the server is a storage-role server owned by this miner, (2) a fresh quote verifies
    against the pinned storage-TD measurement and binds the nonce + the TD's serving-cert pubkey,
    (3) the server holds (or is assigned) a replica of the volume. The key never leaves an attested
    TD: an operator with only the miner hotkey cannot complete the mTLS handshake nor pass the quote.
    """
    server = await _get_storage_server(db, server_id, miner_hotkey)

    # Verify a fresh attestation bound to the nonce + the serving-cert pubkey hash.
    quote = build_runtime_quote(quote_b64, (tee_type or "tdx").strip().lower(), snp_cert_chain, vtpm_quote)
    await verify_quote(quote, expected_nonce, expected_cert_hash)
    measurement_config = get_matching_measurement_config(quote)
    if (measurement_config.gpu_count or 0) != 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Volume key release requires a CPU-only (gpu_count=0) attested measurement.",
        )
    # The per-volume key is released only to the genuine, pinned storage-TD image (name 'storage-*'),
    # whose code uses it solely for at-rest object encryption -- not to any CPU-only image that merely
    # claims storage_role (which could otherwise run arbitrary code that exfiltrates the key).
    if not (measurement_config.name or "").startswith("storage-"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Volume key release requires the pinned storage-TD measurement (name 'storage-*').",
        )
    # The pinned serving cert must match the attested cert the TD presented at mTLS time.
    if _server_pubkey_hash(server) != expected_cert_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented attested cert does not match the registered storage TD cert.",
        )

    volume = (
        await db.execute(
            select(StorageVolume).where(
                StorageVolume.volume_id == volume_id, StorageVolume.deleted.is_(False)
            )
        )
    ).scalar_one_or_none()
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")

    # The TD must hold (or be assigned) a replica of an object in this volume to receive the key.
    holds_replica = (
        await db.execute(
            select(func.count())
            .select_from(ReplicaPlacement)
            .join(StorageObject, StorageObject.object_id == ReplicaPlacement.object_id)
            .where(
                StorageObject.volume_id == volume_id,
                ReplicaPlacement.server_id == server_id,
                ReplicaPlacement.status.in_(("present", "pending")),
            )
        )
    ).scalar() or 0
    if holds_replica == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Storage TD does not hold a replica of this volume; key not released.",
        )

    key_row = await db.get(StorageVolumeKey, volume_id)
    if key_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Volume key not found."
        )
    logger.success(
        f"Released ChuteFS volume key {volume_id} to attested storage TD {server_id} (miner {miner_hotkey})"
    )
    return decrypt_passphrase(key_row.encrypted_key)


# --- object-op grants --------------------------------------------------------------------------


async def issue_grant(db: AsyncSession, user_id: str, volume_id: str, ops: List[str]) -> str:
    """Mint a short-lived opaque grant a storage TD can verify to authorize object ops on a volume."""
    await _get_owned_volume(db, volume_id, user_id)
    token = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": user_id, "volume_id": volume_id, "ops": list(ops)})
    await settings.redis_client.setex(f"storage:grant:{token}", GRANT_TTL_SECONDS, payload)
    return token


async def _issue_system_grant(volume_id: str, ops: List[str], ttl: int = 900) -> str:
    """Mint a grant WITHOUT user ownership, for validator-driven repair replication (M7).

    The reconcile loop hands this to a source storage TD so it can push a held object's ciphertext to
    the newly-assigned replica peers; it is put-scoped and short-lived, and the storage node forwards
    it to the peer's /replicate exactly like a user's put grant.
    """
    token = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": "__reconcile__", "volume_id": volume_id, "ops": list(ops)})
    await settings.redis_client.setex(f"storage:grant:{token}", ttl, payload)
    return token


async def verify_grant(grant: str, volume_id: str, op: str) -> Optional[Dict]:
    """Verify a grant authorizes `op` on `volume_id`; returns the grant payload or None."""
    raw = await settings.redis_client.get(f"storage:grant:{grant}")
    if not raw:
        return None
    try:
        payload = json.loads(raw.decode() if isinstance(raw, (bytes, bytearray)) else raw)
    except (ValueError, AttributeError):
        return None
    if payload.get("volume_id") != volume_id or op not in (payload.get("ops") or []):
        return None
    return payload
