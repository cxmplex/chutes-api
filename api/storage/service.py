"""ChuteFS storage tracker business logic.

The validator is the coordinator, never a data path: it records who holds what, vouches for peers'
attested certs, custodies per-volume keys (released only to attested replica-holders), and meters
per-volume bytes. All object bytes flow peer-to-peer over mutually-attested TLS, never through here.
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Set
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy import and_, delete, exists, func, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.chute.schemas import Chute
from api.instance.schemas import Instance, LaunchConfig
from api.server.quote import build_runtime_quote
from api.server.schemas import (
    ContentHolding,
    ReplicaPlacement,
    Server,
    ServerAttestation,
    StorageEraseTask,
    StorageInventorySnapshot,
    StorageModelInventoryEntry,
    StorageModelInventorySnapshot,
    StorageObject,
    StorageObjectDeleteFence,
    StorageReplicationCapability,
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
from api.user.schemas import User
from api.util import extract_hf_model_name

# How long a storage TD's announce/heartbeat keeps it eligible as a live peer (seconds).
STORAGE_PEER_TTL_SECONDS = 180
# A storage TD re-attests every 30 minutes. Liveness expires after two missed attestations even when
# an operator still controls the miner hotkey and keeps sending signed heartbeats.
STORAGE_ATTESTATION_MAX_AGE_SECONDS = 3600
# Default storage-node DNAT port name the TD advertises in external_ports.
STORAGE_PORT_KEY = "storage"
# Pending assignments reserve capacity durably and expire if no target possession receipt arrives.
PENDING_PLACEMENT_TTL_SECONDS = 2 * 3600
MAX_PLACEMENT_ATTEMPTS = 8
# A capability only needs to survive source->target connection setup: the target consumes it before
# reading a byte. The separately bound transfer deadline covers the streamed body and receipt.
REPLICATION_CAPABILITY_TTL_SECONDS = 120
REPLICATION_TRANSFER_LEASE_SECONDS = 2 * 3600
# A CPU chute requests this with live attested mTLS plus its verified launch identity; non-CPU/GPU
# chutes use the same verified launch identity on the narrow model-access route. The selected storage
# target consumes the exact one-use binding over its own live attested mTLS channel before doing work.
MODEL_ENSURE_CAPABILITY_TTL_SECONDS = 120
# Match the measured storage-node's default low-disk guard. A candidate must fit the projected object
# after all live pending reservations while retaining this headroom.
STORAGE_CAPACITY_HEADROOM_BYTES = 10 * 1024**3
_GIB = 1024**3
# L5: how long a reserved-but-never-committed (size-0, no present holder) object lingers before the
# reconcile loop reaps it. Well beyond the put + grant window so an in-flight large upload is safe.
_ABANDONED_OBJECT_TTL_SECONDS = 24 * 3600
# How long an owner object-op grant is valid. Replication never accepts or forwards this grant; the
# long window only covers a slow direct owner upload and its response.
GRANT_TTL_SECONDS = 7200
OBJECT_PENDING = "pending"
OBJECT_COMMITTED = "committed"
OBJECT_SUPERSEDED = "superseded"
OBJECT_TOMBSTONED = "tombstoned"
ERASE_TERMINAL_STATES = ("erased", "retired")


# --- liveness ----------------------------------------------------------------------------------


async def mark_storage_online(server_id: str) -> None:
    """Refresh a storage TD's liveness on announce (its heartbeat into the peer directory)."""
    try:
        await settings.redis_client.setex(
            f"storage:online:{server_id}", STORAGE_PEER_TTL_SECONDS, "1"
        )
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
    """Return storage IDs with a fresh successful attestation against a currently loaded storage pin."""
    if not server_ids:
        return set()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=STORAGE_ATTESTATION_MAX_AGE_SECONDS)
    try:
        active_measurements = settings.tee_measurements
        active_storage_configs = {
            config.name: config
            for config in active_measurements
            if (config.name or "").startswith("storage-")
        }
    except Exception as exc:  # noqa: BLE001 - trust-config failure must fail closed
        logger.error(f"Could not load active storage attestation versions: {exc}")
        return set()
    if not active_storage_configs:
        return set()
    current_trust_set_fingerprint = measurement_trust_set_fingerprint(active_measurements)

    # The latest attempt wins: a newer failed attestation cannot be hidden by an older success.
    latest = (
        select(
            ServerAttestation.server_id,
            ServerAttestation.verification_error,
            ServerAttestation.measurement_version,
            ServerAttestation.measurement_name,
            ServerAttestation.measurement_config_fingerprint,
            ServerAttestation.trust_set_fingerprint,
            ServerAttestation.verified_at,
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
            select(
                latest.c.server_id,
                latest.c.measurement_name,
                latest.c.measurement_version,
                latest.c.measurement_config_fingerprint,
                latest.c.trust_set_fingerprint,
            ).where(
                latest.c.rn == 1,
                latest.c.verification_error.is_(None),
                latest.c.verified_at.is_not(None),
                latest.c.verified_at >= cutoff,
            )
        )
    ).all()
    verified = set()
    for row in rows:
        config = active_storage_configs.get(row.measurement_name)
        if config is None:
            continue
        expected_config_fingerprint = getattr(
            config, "config_fingerprint", None
        ) or measurement_config_fingerprint(config)
        if (
            row.measurement_version == config.version
            and row.measurement_config_fingerprint == expected_config_fingerprint
            and row.trust_set_fingerprint == current_trust_set_fingerprint
        ):
            verified.add(row.server_id)
    return verified


async def is_freshly_attested_storage_server(db: AsyncSession, server: Server) -> bool:
    """Whether this exact registered storage TD still has an accepted, bounded-age attestation."""
    if not server.storage_role:
        return False
    return server.server_id in await _verified_storage_ids(db, [server.server_id])


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
    if not host or not port or not pubkey_hash or not server.storage_incarnation:
        return None
    return StoragePeer(
        server_id=server.server_id,
        host=host,
        port=int(port),
        cert_pubkey_hash=pubkey_hash,
        storage_incarnation=server.storage_incarnation,
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
            select(Server).where(func.lower(Server.attested_cert_pubkey_hash) == cert_hash.lower())
        )
    ).scalar_one_or_none()


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


async def _get_storage_server(
    db: AsyncSession,
    server_id: str,
    miner_hotkey: str,
    *,
    caller_server_id: Optional[str] = None,
    lock: bool = False,
) -> Server:
    query = select(Server).where(
        Server.server_id == server_id,
        Server.miner_hotkey == miner_hotkey,
        Server.storage_role.is_(True),
    )
    if lock:
        query = query.with_for_update()
    server = (await db.execute(query)).scalar_one_or_none()
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No storage-role server with that id owned by this miner.",
        )
    if caller_server_id is not None and server.server_id != caller_server_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The mTLS storage identity does not match the announced server_id.",
        )
    return server


def _normalize_incarnation(value: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="storage_incarnation must be a canonical UUID.",
        ) from exc


def replication_capability_message(capability: str) -> bytes:
    """Canonical attested-key proof signed by the source for one opaque capability."""
    return f"chutefs-replication-v1\n{capability}".encode()


def _replication_token_hash(capability: str) -> str:
    return hashlib.sha256(capability.encode()).hexdigest()


def _verify_replication_source_signature(
    source: Server, capability: str, signature_hex: str
) -> bool:
    if not source.attested_cert or not signature_hex:
        return False
    try:
        certificate = x509.load_pem_x509_certificate(source.attested_cert.encode())
        public_key = certificate.public_key()
        signature = bytes.fromhex(signature_hex)
        message = replication_capability_message(capability)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001 - malformed/unsupported certificates fail closed
        return False


def _placement_identity_matches(placement: ReplicaPlacement, server: Server) -> bool:
    return bool(
        server.storage_incarnation
        and placement.storage_incarnation == server.storage_incarnation
        and _server_pubkey_hash(server)
        and placement.target_cert_pubkey_hash
        and placement.target_cert_pubkey_hash.lower() == _server_pubkey_hash(server).lower()
    )


def _durability_state(replica_count: int, replication_factor: int, committed: bool) -> str:
    if not committed:
        return "pending"
    if replica_count >= replication_factor:
        return "healthy"
    if replica_count <= 0:
        return "irrecoverable"
    if replica_count == 1 and replication_factor > 1:
        return "at_risk"
    return "under_replicated"


async def _current_durable_placements(
    db: AsyncSession,
    obj: StorageObject,
    *,
    live_ids: Optional[Set[str]] = None,
    placements: Optional[Sequence[ReplicaPlacement]] = None,
    servers: Optional[Sequence[Server]] = None,
) -> List[ReplicaPlacement]:
    """Current possession receipts, deduplicated by physical host failure domain."""
    if obj.lifecycle_state != OBJECT_COMMITTED:
        return []
    if placements is None:
        placements = list(
            (
                await db.execute(
                    select(ReplicaPlacement).where(
                        ReplicaPlacement.object_id == obj.object_id,
                        ReplicaPlacement.status == "present",
                    )
                )
            )
            .scalars()
            .all()
        )
    if servers is None:
        servers = await _storage_servers_by_id(db, [p.server_id for p in placements])
    server_by_id = {server.server_id: server for server in servers}
    if live_ids is None:
        live_ids = await _live_attested_server_ids(db)

    chosen: List[ReplicaPlacement] = []
    used_hosts: Set[str] = set()
    for placement in sorted(
        placements,
        key=lambda item: (
            item.confirmed_at or datetime.min.replace(tzinfo=timezone.utc),
            item.server_id,
        ),
        reverse=True,
    ):
        server = server_by_id.get(placement.server_id)
        if (
            placement.status != "present"
            or placement.server_id not in live_ids
            or server is None
            or not _placement_identity_matches(placement, server)
            or not placement.proof_sha256
            or not obj.sha256
            or placement.proof_sha256.lower() != obj.sha256.lower()
            or placement.proof_size_bytes is None
            or placement.proof_mode
            not in ("direct_upload", "replication_capability", "legacy_adoption")
            or obj.ciphertext_size_bytes is None
            or int(placement.proof_size_bytes) != int(obj.ciphertext_size_bytes)
        ):
            continue
        host = server.host_id or server.server_id
        if host in used_hosts:
            continue
        used_hosts.add(host)
        chosen.append(placement)
    return chosen


async def _refresh_object_durability(
    db: AsyncSession,
    obj: StorageObject,
    *,
    volume: Optional[StorageVolume] = None,
    live_ids: Optional[Set[str]] = None,
    placements: Optional[Sequence[ReplicaPlacement]] = None,
    servers: Optional[Sequence[Server]] = None,
) -> int:
    if volume is None:
        volume = await db.get(StorageVolume, obj.volume_id)
    if volume is None:
        return 0
    durable = await _current_durable_placements(
        db,
        obj,
        live_ids=live_ids,
        placements=placements,
        servers=servers,
    )
    obj.durable_replica_count = len(durable)
    obj.durability_state = _durability_state(
        len(durable),
        volume.replication_factor,
        committed=obj.lifecycle_state == OBJECT_COMMITTED,
    )
    obj.durability_updated_at = func.now()
    return len(durable)


async def _bind_storage_identity(
    db: AsyncSession,
    server: Server,
    storage_incarnation: str,
) -> Set[str]:
    """Bind this live attested cert to its mounted disk without resurrecting any placement.

    Existing present rows stop counting immediately because every durability query requires their
    stored incarnation/cert to equal this server row. Reconcile evicts stale rows. Only a per-object
    inventory receipt may rebind an evicted row, because a wiped disk has no file from which the
    measured storage-node code could produce that receipt.
    """
    storage_incarnation = _normalize_incarnation(storage_incarnation)
    cert_hash = _server_pubkey_hash(server)
    if not cert_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Storage TD has no registered attestation-bound certificate.",
        )

    incarnation_changed = server.storage_incarnation != storage_incarnation
    server.storage_incarnation = storage_incarnation
    server.storage_incarnation_announced_at = func.now()
    marker_identity_changed = (
        server.model_inventory_storage_incarnation != storage_incarnation
        or (server.model_inventory_cert_pubkey_hash or "").lower() != cert_hash.lower()
    )
    if marker_identity_changed:
        server.model_inventory_storage_incarnation = None
        server.model_inventory_cert_pubkey_hash = None
        server.model_inventory_snapshot_started_at = None
        server.model_inventory_snapshot_id = None
        server.model_inventory_fresh_at = None
    if incarnation_changed:
        # Model holdings share the same disk. An empty replacement volume cannot inherit the old
        # incarnation's model inventory.
        await db.execute(delete(ContentHolding).where(ContentHolding.server_id == server.server_id))
    await db.flush()
    return set()


def _refresh_model_inventory_marker_freshness(
    server: Server,
    storage_incarnation: str,
    now: datetime,
) -> None:
    """Refresh an existing authoritative marker only for its exact current storage identity."""
    cert_hash = (_server_pubkey_hash(server) or "").lower()
    if (
        server.storage_incarnation == storage_incarnation
        and server.model_inventory_storage_incarnation == storage_incarnation
        and cert_hash
        and (server.model_inventory_cert_pubkey_hash or "").lower() == cert_hash
        and server.model_inventory_snapshot_started_at is not None
        and server.model_inventory_snapshot_id is not None
        and server.model_inventory_fresh_at is not None
    ):
        server.model_inventory_fresh_at = now


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


def _model_ensure_capability_key(capability: str) -> str:
    token_hash = hashlib.sha256(capability.encode()).hexdigest()
    return f"storage:model_ensure_capability:{token_hash}"


async def authorize_launch_model_request(
    db: AsyncSession,
    authorization: str,
    repo_id: str,
    revision: str,
    requested_revision: str,
    *,
    expected_server_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a signed launch token to one verified instance and its declared immutable model."""
    from api.instance.util import _decode_chutes_jwt

    token = (authorization or "").strip().split(" ")[-1]
    try:
        payload = _decode_chutes_jwt(token, require_exp=True)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired launch token.",
        ) from exc

    config_id = payload.get("sub")
    token_chute_id = payload.get("chute_id")
    if not isinstance(config_id, str) or not isinstance(token_chute_id, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch token is missing its config or chute binding.",
        )

    launch_config = (
        await db.execute(select(LaunchConfig).where(LaunchConfig.config_id == config_id))
    ).scalar_one_or_none()
    instance = (
        await db.execute(select(Instance).where(Instance.config_id == config_id))
    ).scalar_one_or_none()
    chute = (
        await db.execute(select(Chute).where(Chute.chute_id == token_chute_id))
    ).scalar_one_or_none()
    if (
        launch_config is None
        or instance is None
        or chute is None
        or launch_config.failed_at is not None
        or launch_config.verified_at is None
        or not instance.verified
        or launch_config.chute_id != token_chute_id
        or instance.chute_id != token_chute_id
        or payload.get("env_type") != launch_config.env_type
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Launch token is not bound to a verified running instance.",
        )

    if expected_server_id is None:
        # CPU-TEE instances carry a registered attested server identity and must use the mTLS route.
        if instance.server_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Attested CPU instances must authorize model access over mTLS.",
            )
        requester_kind = "launch_instance"
        requester_server_id = None
        requester_cert_hash = None
    else:
        if instance.server_id != expected_server_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Launch token instance does not match the attested mTLS server.",
            )
        requester_kind = "attested_server"
        requester_server_id = expected_server_id
        requester_cert_hash = None

    declared_repo = extract_hf_model_name(chute.chute_id, chute.code)
    if not declared_repo or not secrets.compare_digest(declared_repo, repo_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requested repository is not the model declared by this chute.",
        )

    declared_revision = str(chute.revision or "").strip()
    if not declared_revision or not secrets.compare_digest(declared_revision, requested_revision):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requested model ref is not the revision declared by this chute.",
        )

    normalized_commit = revision.strip().lower()
    immutable = len(normalized_commit) == 40 and all(
        character in "0123456789abcdef" for character in normalized_commit
    )
    if not immutable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Model access requires an immutable lowercase 40-hex commit.",
        )
    declared_commit = declared_revision.lower()
    if len(declared_commit) == 40 and all(
        character in "0123456789abcdef" for character in declared_commit
    ):
        if not secrets.compare_digest(declared_commit, normalized_commit):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Requested model commit differs from the chute's immutable revision.",
            )
    else:
        # Older rows may contain a mutable ref. Resolve it through the same validator manifest
        # authority the client used, then compare the exact immutable commit.
        from api.misc.router import get_hf_repo_info

        manifest = await get_hf_repo_info(
            repo_id=repo_id,
            repo_type="model",
            revision=declared_revision,
            x_hf_token=None,
        )
        resolved = str(manifest.get("commit_hash") or "").strip().lower()
        if not secrets.compare_digest(resolved, normalized_commit):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The declared model ref no longer resolves to the requested commit.",
            )

    return {
        "requester_kind": requester_kind,
        "requester_server_id": requester_server_id,
        "requester_cert_pubkey_hash": requester_cert_hash,
        "requester_instance_id": instance.instance_id,
        "requester_config_id": config_id,
        "requester_chute_id": token_chute_id,
        "requester_deployment_id": instance.deployment_id,
    }


async def issue_model_ensure_capability(
    db: AsyncSession,
    requester: Dict[str, Any],
    request_id: str,
    target_server_id: str,
    repo_id: str,
    revision: str,
    requested_revision: str,
) -> Dict:
    """Issue one exact ensure capability to an already authenticated launch instance."""
    required_requester_fields = (
        "requester_kind",
        "requester_instance_id",
        "requester_config_id",
        "requester_chute_id",
    )
    if requester.get("requester_kind") not in {
        "attested_server",
        "launch_instance",
    } or not all(isinstance(requester.get(field), str) for field in required_requester_fields):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requester launch identity is incomplete.",
        )

    target = await db.get(Server, target_server_id)
    target_cert_hash = _server_pubkey_hash(target) if target is not None else None
    if (
        target is None
        or not target.storage_role
        or not target_cert_hash
        or not target.storage_incarnation
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model ensure target is not an available attested storage server.",
        )

    capability_id = str(uuid4())
    capability = f"{capability_id}.{secrets.token_urlsafe(48)}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=MODEL_ENSURE_CAPABILITY_TTL_SECONDS)
    context = {
        "capability_id": capability_id,
        "request_id": request_id,
        **{
            field: requester.get(field)
            for field in (
                "requester_kind",
                "requester_server_id",
                "requester_cert_pubkey_hash",
                "requester_instance_id",
                "requester_config_id",
                "requester_chute_id",
                "requester_deployment_id",
            )
        },
        "target_server_id": target.server_id,
        "target_cert_pubkey_hash": target_cert_hash.lower(),
        "target_storage_incarnation": target.storage_incarnation,
        "repo_id": repo_id,
        "revision": revision,
        "requested_revision": requested_revision,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    try:
        await settings.redis_client.setex(
            _model_ensure_capability_key(capability),
            MODEL_ENSURE_CAPABILITY_TTL_SECONDS,
            json.dumps(context),
        )
    except Exception as exc:
        logger.warning(f"Could not persist model ensure capability: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model ensure authorization is temporarily unavailable.",
        ) from exc
    return {
        "capability": capability,
        "capability_id": capability_id,
        "expires_at": expires_at.isoformat(),
    }


async def consume_model_ensure_capability(
    target: Server,
    capability: str,
    request_id: str,
    repo_id: str,
    revision: str,
    requested_revision: str,
) -> Dict:
    """Atomically consume and validate every request/target/content binding."""
    try:
        encoded = await settings.redis_client.getdel(_model_ensure_capability_key(capability))
    except Exception as exc:
        logger.warning(f"Could not consume model ensure capability: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model ensure authorization is temporarily unavailable.",
        ) from exc
    if not encoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Model ensure capability is invalid, expired, or already consumed.",
        )
    try:
        if isinstance(encoded, bytes):
            encoded = encoded.decode()
        context = json.loads(encoded)
        expires_at = datetime.fromisoformat(context["expires_at"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Model ensure capability is malformed.",
        ) from exc

    target_cert_hash = (_server_pubkey_hash(target) or "").strip().lower()
    exact_strings = {
        "request_id": request_id,
        "target_server_id": target.server_id,
        "target_cert_pubkey_hash": target_cert_hash,
        "target_storage_incarnation": target.storage_incarnation or "",
        "repo_id": repo_id,
        "revision": revision,
        "requested_revision": requested_revision,
    }
    valid = (
        target.storage_role
        and expires_at > datetime.now(timezone.utc)
        and all(
            isinstance(context.get(field), str) and secrets.compare_digest(context[field], expected)
            for field, expected in exact_strings.items()
        )
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Model ensure capability does not match this target or request.",
        )

    return {
        field: context[field]
        for field in (
            "capability_id",
            "request_id",
            "requester_kind",
            "requester_server_id",
            "requester_cert_pubkey_hash",
            "requester_instance_id",
            "requester_config_id",
            "requester_chute_id",
            "requester_deployment_id",
            "target_server_id",
            "target_cert_pubkey_hash",
            "repo_id",
            "revision",
            "requested_revision",
            "expires_at",
        )
    }


async def announce_model_holdings(
    db: AsyncSession,
    miner_hotkey: str,
    server_id: str,
    caller_server_id: str,
    snapshot_id: str,
    page_index: int,
    storage_incarnation: str,
    disk_free_gb: Optional[int],
    holdings: List[Dict],
    complete: bool,
) -> Dict:
    """Stage one bounded authoritative model inventory page after exact mTLS authentication."""
    if len(holdings) > 1000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Model holding page exceeds 1000 entries.",
        )
    storage_incarnation = _normalize_incarnation(storage_incarnation)
    await _lock_model_inventory_snapshot_stream(db, server_id, storage_incarnation)
    server = await _get_storage_server(
        db,
        server_id,
        miner_hotkey,
        caller_server_id=caller_server_id,
        lock=True,
    )
    await _bind_storage_identity(db, server, storage_incarnation)
    if disk_free_gb is not None:
        server.disk_free_gb = int(disk_free_gb)
    snapshot = (
        await db.execute(
            select(StorageModelInventorySnapshot)
            .where(StorageModelInventorySnapshot.snapshot_id == snapshot_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if snapshot is None:
        if page_index != 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A model inventory snapshot must begin at page zero.",
            )
        snapshot = StorageModelInventorySnapshot(
            snapshot_id=snapshot_id,
            server_id=server.server_id,
            storage_incarnation=storage_incarnation,
            cert_pubkey_hash=(_server_pubkey_hash(server) or "").lower(),
            state="scanning",
            started_at=now,
            eligibility_cutoff_at=now,
            next_page_index=0,
        )
        db.add(snapshot)
        await db.flush()
    elif (
        snapshot.server_id != server.server_id
        or snapshot.storage_incarnation != storage_incarnation
        or snapshot.cert_pubkey_hash != (_server_pubkey_hash(server) or "").lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Model snapshot id is bound to a different storage identity.",
        )

    if snapshot.state != "scanning":
        _refresh_model_inventory_marker_freshness(server, storage_incarnation, now)
        await db.commit()
        await mark_storage_online(server_id)
        return {"recorded": 0, "complete": True}
    if page_index < int(snapshot.next_page_index):
        _refresh_model_inventory_marker_freshness(server, storage_incarnation, now)
        await db.commit()
        await mark_storage_online(server_id)
        return {"recorded": 0, "complete": False}
    if page_index != int(snapshot.next_page_index):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Model inventory expected page {snapshot.next_page_index}, received {page_index}."
            ),
        )

    _refresh_model_inventory_marker_freshness(server, storage_incarnation, now)
    deduplicated = {
        (holding["repo_id"], holding.get("revision") or "main"): int(holding.get("bytes") or 0)
        for holding in holdings
    }
    if deduplicated:
        statement = pg_insert(StorageModelInventoryEntry).values(
            [
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "repo_id": repo_id,
                    "revision": revision,
                    "bytes": held_bytes,
                }
                for (repo_id, revision), held_bytes in deduplicated.items()
            ]
        )
        await db.execute(
            statement.on_conflict_do_update(
                index_elements=["snapshot_id", "repo_id", "revision"],
                set_={"bytes": statement.excluded.bytes},
            )
        )
    snapshot.reported_entries = int(snapshot.reported_entries or 0) + len(deduplicated)
    snapshot.next_page_index = int(snapshot.next_page_index) + 1
    snapshot.last_page_at = now
    if complete:
        snapshot.state = "complete"
        snapshot.completed_at = now
    await db.commit()
    await mark_storage_online(server_id)
    return {"recorded": len(deduplicated), "complete": bool(complete)}


async def local_storage_peer(db: AsyncSession, host_id: str) -> Optional[StoragePeer]:
    """The attested storage TD on a given L0 host (for a chute to reach its same-host storage node).

    Same-host chute<->storage traffic is L2-isolated, so it traverses the host DNAT at
    external_host:<storage port> exactly like a cross-host peer -- this just resolves which one is local.
    """
    servers = list(
        (
            await db.execute(
                select(Server).where(Server.storage_role.is_(True), Server.host_id == host_id)
            )
        )
        .scalars()
        .all()
    )
    peers = await _attested_live_peers(db, servers)
    return peers[0] if peers else None


async def model_peers(db: AsyncSession, repo_id: str, revision: str) -> List[StoragePeer]:
    """Return attested, live storage peers that hold (repo_id, revision)."""
    freshness_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_model_holding_freshness_seconds
    )
    rows = (
        (
            await db.execute(
                select(Server)
                .join(ContentHolding, ContentHolding.server_id == Server.server_id)
                .where(
                    ContentHolding.repo_id == repo_id,
                    ContentHolding.revision == revision,
                    ContentHolding.status == "present",
                    Server.model_inventory_fresh_at >= freshness_cutoff,
                    Server.model_inventory_storage_incarnation == Server.storage_incarnation,
                    func.lower(Server.model_inventory_cert_pubkey_hash)
                    == func.lower(Server.attested_cert_pubkey_hash),
                    Server.storage_role.is_(True),
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    return await _attested_live_peers(db, rows)


async def model_ensure_target(
    db: AsyncSession,
    repo_id: str,
    revision: str,
    *,
    preferred_host_id: Optional[str] = None,
) -> Optional[StoragePeer]:
    """Choose a live attested target: same-host, current holder, then highest-free-space node."""
    if preferred_host_id:
        local = await local_storage_peer(db, preferred_host_id)
        if local is not None:
            pem, _ = await peer_cert(db, local.server_id)
            return local.model_copy(update={"attested_cert": pem})

    holders = await model_peers(db, repo_id, revision)
    if holders:
        pem, _ = await peer_cert(db, holders[0].server_id)
        return holders[0].model_copy(update={"attested_cert": pem})

    candidates = list(
        (
            await db.execute(
                select(Server)
                .where(Server.storage_role.is_(True))
                .order_by(Server.disk_free_gb.desc().nullslast(), Server.server_id)
            )
        )
        .scalars()
        .all()
    )
    available = await _attested_live_peers(db, candidates, include_cert=True)
    return available[0] if available else None


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
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No attested storage peer with that id.",
        )
    pubkey_hash = _server_pubkey_hash(server)
    if not pubkey_hash:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Peer cert unavailable.")
    return server.attested_cert, pubkey_hash


# --- confidential volumes ----------------------------------------------------------------------


def _effective_storage_quotas(user: User) -> tuple[int, int]:
    """Return server-capped per-volume and aggregate byte entitlements for an account."""
    per_volume = (
        int(user.storage_volume_quota_bytes)
        if user.storage_volume_quota_bytes is not None
        else settings.storage_default_volume_quota_bytes
    )
    aggregate = (
        int(user.storage_aggregate_quota_bytes)
        if user.storage_aggregate_quota_bytes is not None
        else settings.storage_default_aggregate_quota_bytes
    )
    per_volume = min(per_volume, settings.storage_max_volume_quota_bytes)
    aggregate = min(aggregate, settings.storage_max_aggregate_quota_bytes)
    if per_volume <= 0 or aggregate <= 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has no positive ChuteFS storage entitlement.",
        )
    return min(per_volume, aggregate), aggregate


async def _lock_storage_user(db: AsyncSession, user_id: str) -> User:
    user = (
        await db.execute(select(User).where(User.user_id == user_id).with_for_update(of=User))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def storage_aggregate_quota(db: AsyncSession, user_id: str) -> int:
    user = (await db.execute(select(User).where(User.user_id == user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return _effective_storage_quotas(user)[1]


def _volume_response(volume: StorageVolume, aggregate_quota_bytes: int) -> Dict:
    return {
        "volume_id": volume.volume_id,
        "name": volume.name,
        "replication_factor": volume.replication_factor,
        "quota_bytes": volume.quota_bytes,
        "aggregate_quota_bytes": aggregate_quota_bytes,
        "used_bytes": volume.used_bytes,
        "created_at": volume.created_at.isoformat() if volume.created_at else "",
    }


async def create_volume(
    db: AsyncSession, user_id: str, name: str, replication_factor: int
) -> tuple[StorageVolume, int]:
    """Create a confidential volume and generate + store its (encrypted) application-layer key."""
    user = await _lock_storage_user(db, user_id)
    per_volume_quota, aggregate_quota = _effective_storage_quotas(user)
    active_count = (
        await db.execute(
            select(func.count())
            .select_from(StorageVolume)
            .where(
                StorageVolume.user_id == user_id,
                StorageVolume.deleted.is_(False),
            )
        )
    ).scalar_one()
    if active_count >= settings.storage_max_volumes_per_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This account has reached its maximum number of active storage volumes.",
        )
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
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Volume '{name}' already exists.",
        )
    volume = StorageVolume(
        user_id=user_id,
        name=name,
        replication_factor=replication_factor,
        quota_bytes=per_volume_quota,
        used_bytes=0,
    )
    db.add(volume)
    try:
        async with db.begin_nested():
            await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Volume '{name}' already exists.",
        ) from exc
    # Per-volume application-layer key (32 bytes), encrypted at rest with the same Fernet primitive
    # as LUKS passphrases; released only to attested storage TDs that hold a replica of this volume.
    key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()
    db.add(StorageVolumeKey(volume_id=volume.volume_id, encrypted_key=encrypt_passphrase(key_b64)))
    await db.commit()
    await db.refresh(volume)
    logger.success(f"Created ChuteFS volume {volume.volume_id} ({name}) for user {user_id}")
    return volume, aggregate_quota


async def list_volumes(
    db: AsyncSession, user_id: str, limit: int, after: Optional[str] = None
) -> tuple[List[StorageVolume], int]:
    query = select(StorageVolume).where(
        StorageVolume.user_id == user_id,
        StorageVolume.deleted.is_(False),
    )
    if after:
        query = query.where(StorageVolume.volume_id > after)
    query = query.order_by(StorageVolume.volume_id).limit(
        min(limit, settings.storage_volume_page_size_max)
    )
    volumes = list((await db.execute(query)).scalars().all())
    return volumes, await storage_aggregate_quota(db, user_id)


async def _enqueue_erase_tasks_for_generations(
    db: AsyncSession,
    generations: Sequence[StorageObject],
    *,
    reason: str,
    now: Optional[datetime] = None,
) -> int:
    """Materialize one durable task for every known holder before any metadata is purged."""
    if not generations:
        return 0
    now = now or datetime.now(timezone.utc)
    generation_by_id = {generation.object_id: generation for generation in generations}
    existing_erase_task = StorageEraseTask.__table__.alias("existing_erase_task")
    placements = list(
        (
            await db.execute(
                select(ReplicaPlacement)
                .where(
                    ReplicaPlacement.object_id.in_(list(generation_by_id)),
                    ~exists(
                        select(1)
                        .select_from(existing_erase_task)
                        .where(
                            existing_erase_task.c.object_id == ReplicaPlacement.object_id,
                            existing_erase_task.c.server_id == ReplicaPlacement.server_id,
                            func.coalesce(existing_erase_task.c.storage_incarnation, "")
                            == func.coalesce(ReplicaPlacement.storage_incarnation, ""),
                        )
                    ),
                )
                .order_by(
                    ReplicaPlacement.object_id,
                    ReplicaPlacement.placement_id,
                )
                .limit(settings.storage_reconcile_batch_size)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    enqueued = 0
    retention_deadline = now + timedelta(seconds=settings.storage_erase_retention_seconds)
    for placement in placements:
        generation = generation_by_id[placement.object_id]
        existing_task = (
            await db.execute(
                select(StorageEraseTask)
                .where(
                    StorageEraseTask.object_id == generation.object_id,
                    StorageEraseTask.server_id == placement.server_id,
                    (
                        StorageEraseTask.storage_incarnation == placement.storage_incarnation
                        if placement.storage_incarnation is not None
                        else StorageEraseTask.storage_incarnation.is_(None)
                    ),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if existing_task is not None:
            if reason == "volume_deleted":
                # Even an already-erased historical generation is polled once more so every former
                # key holder drops its bounded in-process volume-key cache before validator shred.
                existing_task.reason = reason
                existing_task.retention_deadline = retention_deadline
                existing_task.metadata_purged_at = None
                if existing_task.state in ERASE_TERMINAL_STATES:
                    existing_task.state = "pending"
                    existing_task.completed_at = None
                    existing_task.erased_file_was_present = None
                    existing_task.retired_by_user_id = None
                    existing_task.last_error = None
                    enqueued += 1
            if placement.status in ("pending", "present"):
                placement.status = "evicted"
            placement.last_error = reason
            continue
        statement = (
            pg_insert(StorageEraseTask)
            .values(
                object_id=generation.object_id,
                volume_id=generation.volume_id,
                placement_id=placement.placement_id,
                server_id=placement.server_id,
                storage_incarnation=placement.storage_incarnation,
                holder_cert_pubkey_hash=placement.target_cert_pubkey_hash,
                reason=reason,
                state="pending",
                retention_deadline=retention_deadline,
            )
            .on_conflict_do_nothing()
        )
        result = await db.execute(statement)
        enqueued += int(result.rowcount or 0)
        if placement.status in ("pending", "present"):
            placement.status = "evicted"
        placement.last_error = reason
    for generation in generations:
        holder = ReplicaPlacement.__table__.alias("erase_holder")
        matching_task = StorageEraseTask.__table__.alias("matching_erase_task")
        missing_holder = (
            await db.execute(
                select(holder.c.placement_id)
                .where(
                    holder.c.object_id == generation.object_id,
                    ~exists(
                        select(1)
                        .select_from(matching_task)
                        .where(
                            matching_task.c.object_id == holder.c.object_id,
                            matching_task.c.server_id == holder.c.server_id,
                            func.coalesce(matching_task.c.storage_incarnation, "")
                            == func.coalesce(holder.c.storage_incarnation, ""),
                        )
                    ),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if missing_holder is None:
            generation.erase_enqueued_at = now
    return enqueued


async def _retire_deleted_volume_batch(
    db: AsyncSession,
    volume: StorageVolume,
    *,
    limit: int,
) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    historical_tasks = list(
        (
            await db.execute(
                select(StorageEraseTask)
                .where(
                    StorageEraseTask.volume_id == volume.volume_id,
                    StorageEraseTask.reason != "volume_deleted",
                )
                .order_by(StorageEraseTask.task_id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for task in historical_tasks:
        task.reason = "volume_deleted"
        task.retention_deadline = now + timedelta(seconds=settings.storage_erase_retention_seconds)
        task.metadata_purged_at = None
        if task.state in ERASE_TERMINAL_STATES:
            task.state = "pending"
            task.completed_at = None
            task.erased_file_was_present = None
            task.retired_by_user_id = None
            task.last_error = None

    generation_limit = max(0, limit - len(historical_tasks))
    generations = list(
        (
            await db.execute(
                select(StorageObject)
                .where(
                    StorageObject.volume_id == volume.volume_id,
                    StorageObject.lifecycle_state.in_(
                        (OBJECT_PENDING, OBJECT_COMMITTED, OBJECT_SUPERSEDED)
                    ),
                )
                .order_by(StorageObject.object_id)
                .limit(generation_limit)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for generation in generations:
        if generation.lifecycle_state != OBJECT_TOMBSTONED:
            generation.lifecycle_state = OBJECT_TOMBSTONED
            generation.tombstoned_at = now
    await db.flush()
    await _enqueue_erase_tasks_for_generations(db, generations, reason="volume_deleted", now=now)
    return len(generations), len(historical_tasks)


async def delete_volume(db: AsyncSession, volume_id: str, user_id: str) -> Dict:
    await _lock_storage_user(db, user_id)
    volume = (
        await db.execute(
            select(StorageVolume)
            .where(
                StorageVolume.volume_id == volume_id,
                StorageVolume.user_id == user_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")
    if not volume.deleted:
        volume.deleted = True
        volume.delete_requested_at = datetime.now(timezone.utc)
        volume.used_bytes = 0
        await db.flush()
    await _retire_deleted_volume_batch(db, volume, limit=settings.storage_reconcile_batch_size)
    pending = (
        await db.execute(
            select(func.count())
            .select_from(StorageEraseTask)
            .where(
                StorageEraseTask.volume_id == volume_id,
                StorageEraseTask.state.not_in(ERASE_TERMINAL_STATES),
            )
        )
    ).scalar_one()
    await db.commit()
    logger.info(f"Deleted ChuteFS volume {volume_id} for user {user_id}")
    return {
        "deleted": True,
        "volume_id": volume_id,
        "erase_tasks_pending": int(pending),
        "key_shredded": volume.key_shredded_at is not None,
        "purge_pending": volume.purged_at is None,
    }


# --- object placement / commit / locate (replication + byte accounting) ------------------------


async def _pending_reserved_bytes(db: AsyncSession) -> Dict[str, int]:
    rows = (
        await db.execute(
            select(
                ReplicaPlacement.server_id,
                func.coalesce(
                    func.sum(
                        func.greatest(
                            StorageObject.projected_size_bytes,
                            StorageObject.size_bytes,
                        )
                    ),
                    0,
                ),
            )
            .join(StorageObject, StorageObject.object_id == ReplicaPlacement.object_id)
            .where(
                ReplicaPlacement.status == "pending",
                ReplicaPlacement.pending_deadline > func.now(),
                StorageObject.lifecycle_state.in_((OBJECT_PENDING, OBJECT_COMMITTED)),
            )
            .group_by(ReplicaPlacement.server_id)
        )
    ).all()
    return {server_id: int(reserved or 0) for server_id, reserved in rows}


async def _capacity_ranked_peers(
    db: AsyncSession,
    servers: Sequence[Server],
    projected_size_bytes: int,
    *,
    include_cert: bool = False,
) -> List[StoragePeer]:
    """Fresh peers with enough unreserved disk, roomiest first."""
    peers = await _attested_live_peers(db, servers, include_cert=include_cert)
    server_by_id = {server.server_id: server for server in servers}
    reserved = await _pending_reserved_bytes(db)
    ranked: List[tuple[int, StoragePeer]] = []
    for peer in peers:
        server = server_by_id[peer.server_id]
        if server.disk_free_gb is None:
            continue
        available = (
            int(server.disk_free_gb) * _GIB
            - STORAGE_CAPACITY_HEADROOM_BYTES
            - reserved.get(server.server_id, 0)
        )
        if available < projected_size_bytes:
            continue
        ranked.append((available - projected_size_bytes, peer))
    ranked.sort(key=lambda item: (item[0], item[1].server_id), reverse=True)
    return [peer for _, peer in ranked]


async def _pick_replicas(
    db: AsyncSession, replication_factor: int, projected_size_bytes: int
) -> List[StoragePeer]:
    """Pick capacity-safe, fresh replicas on distinct physical failure domains only."""
    servers = list(
        (await db.execute(select(Server).where(Server.storage_role.is_(True)))).scalars().all()
    )
    peers = await _capacity_ranked_peers(db, servers, projected_size_bytes, include_cert=True)
    # Map server_id -> host_id for distinct-host placement.
    host_by_id = {s.server_id: (s.host_id or s.server_id) for s in servers}
    chosen: List[StoragePeer] = []
    used_hosts: Set[str] = set()
    for peer in peers:
        host = host_by_id.get(peer.server_id, peer.server_id)
        if host in used_hosts:
            continue
        chosen.append(peer)
        used_hosts.add(host)
        if len(chosen) >= replication_factor:
            break
    return chosen


async def _upsert_pending_placement(
    db: AsyncSession,
    obj: StorageObject,
    server: Server,
) -> None:
    """Assign/retry one target without colliding with its existing evicted unique row."""
    cert_hash = _server_pubkey_hash(server)
    if not server.storage_incarnation or not cert_hash:
        raise ValueError(f"Storage server {server.server_id} has no current attested disk identity")
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(seconds=PENDING_PLACEMENT_TTL_SECONDS)
    statement = pg_insert(ReplicaPlacement).values(
        object_id=obj.object_id,
        server_id=server.server_id,
        status="pending",
        storage_incarnation=server.storage_incarnation,
        target_cert_pubkey_hash=cert_hash.lower(),
        proof_sha256=None,
        proof_size_bytes=None,
        proof_plaintext_size_bytes=None,
        proof_plaintext_sha256=None,
        proof_capability_id=None,
        proof_mode=None,
        proof_at=None,
        legacy_adoption_started_at=None,
        confirmed_at=None,
        pending_since=now,
        pending_deadline=deadline,
        attempt_count=1,
        last_attempt_at=None,
        last_error=None,
    )
    statement = statement.on_conflict_do_update(
        index_elements=["object_id", "server_id"],
        set_={
            "status": "pending",
            "storage_incarnation": statement.excluded.storage_incarnation,
            "target_cert_pubkey_hash": statement.excluded.target_cert_pubkey_hash,
            "proof_sha256": None,
            "proof_size_bytes": None,
            "proof_plaintext_size_bytes": None,
            "proof_plaintext_sha256": None,
            "proof_capability_id": None,
            "proof_mode": None,
            "proof_at": None,
            "legacy_adoption_started_at": None,
            "confirmed_at": None,
            "pending_since": statement.excluded.pending_since,
            "pending_deadline": statement.excluded.pending_deadline,
            "attempt_count": ReplicaPlacement.attempt_count + 1,
            "last_attempt_at": None,
            "last_error": None,
        },
        where=ReplicaPlacement.status == "evicted",
    )
    result = await db.execute(statement)
    if (result.rowcount or 0) != 1:
        raise RuntimeError(
            f"Placement {obj.object_id}/{server.server_id} was concurrently assigned"
        )


async def plan_object_placement(
    db: AsyncSession,
    volume: StorageVolume,
    request_id: str,
    key: str,
    size_bytes: int,
) -> tuple[StorageObject, List[StoragePeer]]:
    """Create one immutable pending generation and assign its initial replica targets."""
    if size_bytes < 0 or size_bytes > settings.storage_max_object_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Object reservation must be between 0 and "
                f"{settings.storage_max_object_bytes} bytes."
            ),
        )
    user = await _lock_storage_user(db, volume.user_id)
    per_volume_entitlement, aggregate_entitlement = _effective_storage_quotas(user)
    locked_volume = (
        await db.execute(
            select(StorageVolume)
            .where(
                StorageVolume.volume_id == volume.volume_id,
                StorageVolume.deleted.is_(False),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if locked_volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")

    existing_request = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.volume_id == locked_volume.volume_id,
                StorageObject.placement_request_id == request_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing_request is not None:
        if (
            existing_request.object_key != key
            or int(existing_request.projected_size_bytes) != size_bytes
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Placement request id is already bound to different immutable metadata.",
            )
        if existing_request.lifecycle_state != OBJECT_PENDING:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Placement request id is already terminal "
                    f"({existing_request.lifecycle_state})."
                ),
            )
        placements = list(
            (
                await db.execute(
                    select(ReplicaPlacement).where(
                        ReplicaPlacement.object_id == existing_request.object_id,
                        ReplicaPlacement.status == "pending",
                    )
                )
            )
            .scalars()
            .all()
        )
        servers = await _storage_servers_by_id(
            db, [placement.server_id for placement in placements]
        )
        peers = await _attested_live_peers(db, servers, include_cert=True)
        await db.commit()
        return existing_request, peers

    predecessor = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.volume_id == locked_volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.lifecycle_state == OBJECT_COMMITTED,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    pending_volume_bytes = (
        await db.execute(
            select(func.coalesce(func.sum(StorageObject.projected_size_bytes), 0)).where(
                StorageObject.volume_id == locked_volume.volume_id,
                StorageObject.lifecycle_state == OBJECT_PENDING,
            )
        )
    ).scalar_one()
    volume_limit = min(int(locked_volume.quota_bytes), per_volume_entitlement)
    projected = int(locked_volume.used_bytes) + int(pending_volume_bytes or 0) + size_bytes
    if projected > volume_limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Volume quota exceeded: {projected} > {volume_limit} bytes.",
        )

    aggregate_used = (
        await db.execute(
            select(func.coalesce(func.sum(StorageVolume.used_bytes), 0)).where(
                StorageVolume.user_id == locked_volume.user_id,
                StorageVolume.deleted.is_(False),
            )
        )
    ).scalar_one()
    aggregate_pending = (
        await db.execute(
            select(func.coalesce(func.sum(StorageObject.projected_size_bytes), 0))
            .join(StorageVolume, StorageVolume.volume_id == StorageObject.volume_id)
            .where(
                StorageVolume.user_id == locked_volume.user_id,
                StorageVolume.deleted.is_(False),
                StorageObject.lifecycle_state == OBJECT_PENDING,
            )
        )
    ).scalar_one()
    aggregate_projected = int(aggregate_used or 0) + int(aggregate_pending or 0) + size_bytes
    if aggregate_projected > aggregate_entitlement:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Account storage quota exceeded: {aggregate_projected} > "
                f"{aggregate_entitlement} bytes."
            ),
        )

    obj = StorageObject(
        volume_id=locked_volume.volume_id,
        object_key=key,
        placement_request_id=request_id,
        lifecycle_state=OBJECT_PENDING,
        expected_predecessor_id=(predecessor.object_id if predecessor is not None else None),
        size_bytes=0,
        projected_size_bytes=size_bytes,
        salt=base64.b64encode(secrets.token_bytes(32)).decode(),
        durability_state="pending",
        durable_replica_count=0,
    )
    db.add(obj)
    await db.flush()

    peers = await _pick_replicas(db, locked_volume.replication_factor, size_bytes)

    if not peers:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No fresh attested storage peer has enough unreserved disk while retaining "
                "the configured headroom."
            ),
        )
    servers = await _storage_servers_by_id(db, [peer.server_id for peer in peers])
    server_by_id = {server.server_id: server for server in servers}
    for peer in peers:
        await _upsert_pending_placement(db, obj, server_by_id[peer.server_id])

    await db.commit()
    await db.refresh(obj)
    return obj, peers


async def commit_object(
    db: AsyncSession,
    volume: StorageVolume,
    object_id: str,
    key: str,
    salt: str,
) -> tuple[StorageObject, int]:
    """Atomically CAS using immutable receipts from current attested storage targets."""
    try:
        decoded_salt = base64.b64decode(salt, validate=True)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="salt must be valid base64.",
        ) from exc
    if len(decoded_salt) != 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="salt must decode to exactly 32 bytes.",
        )

    user = await _lock_storage_user(db, volume.user_id)
    per_volume_entitlement, aggregate_entitlement = _effective_storage_quotas(user)
    locked_volume = (
        await db.execute(
            select(StorageVolume)
            .where(
                StorageVolume.volume_id == volume.volume_id,
                StorageVolume.deleted.is_(False),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if locked_volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")

    obj = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.object_id == object_id,
                StorageObject.volume_id == locked_volume.volume_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if obj is None or obj.object_key != key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    if salt != obj.salt:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Commit salt does not match this generation's reserved salt.",
        )

    if obj.lifecycle_state == OBJECT_COMMITTED:
        # A lost commit response is safe to retry.  Recompute current live durability, but never
        # reapply accounting or lifecycle transitions.
        confirmed = await _refresh_object_durability(db, obj, volume=locked_volume)
        await db.commit()
        await db.refresh(obj)
        await db.refresh(volume)
        return obj, confirmed
    if obj.lifecycle_state != OBJECT_PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Generation is no longer pending ({obj.lifecycle_state}).",
        )

    delete_fence = (
        await db.execute(
            select(StorageObjectDeleteFence)
            .where(
                StorageObjectDeleteFence.volume_id == locked_volume.volume_id,
                StorageObjectDeleteFence.object_key == key,
                StorageObjectDeleteFence.cutoff_at >= obj.created_at,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if delete_fence is not None:
        obj.lifecycle_state = OBJECT_TOMBSTONED
        obj.tombstoned_at = datetime.now(timezone.utc)
        await db.flush()
        await _enqueue_erase_tasks_for_generations(
            db,
            [obj],
            reason="object_delete_fence",
            now=obj.tombstoned_at,
        )
        await db.commit()
        await db.refresh(volume)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Generation was created before the owner delete cutoff.",
        )

    current = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.volume_id == locked_volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.lifecycle_state == OBJECT_COMMITTED,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    current_id = current.object_id if current is not None else None
    if current_id != obj.expected_predecessor_id:
        obj.lifecycle_state = OBJECT_TOMBSTONED
        obj.tombstoned_at = datetime.now(timezone.utc)
        await db.flush()
        await _enqueue_erase_tasks_for_generations(
            db,
            [obj],
            reason="stale_generation_cas",
            now=obj.tombstoned_at,
        )
        await db.commit()
        await db.refresh(volume)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Generation compare-and-swap failed: its expected predecessor is no longer current."
            ),
        )

    placements = list(
        (
            await db.execute(
                select(ReplicaPlacement)
                .where(ReplicaPlacement.object_id == object_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    servers = await _storage_servers_by_id(db, [placement.server_id for placement in placements])
    server_by_id = {server.server_id: server for server in servers}
    live_ids = await _live_attested_server_ids(db)
    now = datetime.now(timezone.utc)

    proven: List[ReplicaPlacement] = []
    used_hosts: Set[str] = set()
    for placement in placements:
        server = server_by_id.get(placement.server_id)
        if (
            placement.status != "pending"
            or placement.server_id not in live_ids
            or server is None
            or not _placement_identity_matches(placement, server)
            or not placement.proof_sha256
            or placement.proof_size_bytes is None
            or placement.proof_at is None
            or placement.proof_mode not in ("direct_upload", "replication_capability")
            or placement.pending_deadline is None
            or placement.proof_at > placement.pending_deadline
        ):
            continue
        host = server.host_id or server.server_id
        if host in used_hosts:
            placement.status = "evicted"
            placement.last_error = "duplicate_failure_domain"
            continue
        used_hosts.add(host)
        proven.append(placement)

    if not proven:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "No assigned target supplied fresh mTLS possession evidence for this exact "
                "object generation, certificate, and storage incarnation."
            ),
        )
    proven_hashes = {(placement.proof_sha256 or "").lower() for placement in proven}
    proven_sizes = {int(placement.proof_size_bytes) for placement in proven}
    if len(proven_hashes) != 1 or len(proven_sizes) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Assigned targets did not prove one exact ciphertext hash and byte count for this "
                "immutable generation."
            ),
        )
    sha256 = proven_hashes.pop()
    ciphertext_size_bytes = proven_sizes.pop()

    direct_receipts = [
        placement
        for placement in proven
        if placement.proof_mode == "direct_upload"
        and placement.proof_plaintext_size_bytes is not None
        and placement.proof_plaintext_sha256 is not None
    ]
    if not direct_receipts:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Generation has no attested direct-upload receipt for trusted plaintext accounting."
            ),
        )
    plaintext_sizes = {int(placement.proof_plaintext_size_bytes) for placement in direct_receipts}
    plaintext_hashes = {
        (placement.proof_plaintext_sha256 or "").lower() for placement in direct_receipts
    }
    if len(plaintext_sizes) != 1 or len(plaintext_hashes) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Direct upload targets reported conflicting plaintext receipt evidence.",
        )
    size_bytes = plaintext_sizes.pop()
    plaintext_sha256 = plaintext_hashes.pop()
    if (
        size_bytes != int(obj.projected_size_bytes)
        or size_bytes < 0
        or size_bytes > settings.storage_max_object_bytes
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Attested plaintext byte count does not match this generation's immutable "
                "reservation."
            ),
        )

    predecessor_size = int(current.size_bytes) if current is not None else 0
    new_used_bytes = int(locked_volume.used_bytes) - predecessor_size + size_bytes
    volume_limit = min(int(locked_volume.quota_bytes), per_volume_entitlement)
    if new_used_bytes > volume_limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Volume quota exceeded (would exceed {volume_limit} bytes).",
        )
    aggregate_used = (
        await db.execute(
            select(func.coalesce(func.sum(StorageVolume.used_bytes), 0)).where(
                StorageVolume.user_id == locked_volume.user_id,
                StorageVolume.deleted.is_(False),
            )
        )
    ).scalar_one()
    aggregate_after_commit = int(aggregate_used or 0) - predecessor_size + size_bytes
    if aggregate_after_commit > aggregate_entitlement:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Account storage quota exceeded (would exceed {aggregate_entitlement} bytes)."
            ),
        )
    latest_proof_at = max(
        placement.proof_at for placement in proven if placement.proof_at is not None
    )
    if latest_proof_at > now:
        now = latest_proof_at

    # Retire the exact predecessor first, then publish the new current generation in the same
    # transaction.  MVCC readers see either the complete old mapping or the complete new mapping.
    if current is not None:
        current.lifecycle_state = OBJECT_SUPERSEDED
        current.superseded_at = now
        await db.flush()
        await _enqueue_erase_tasks_for_generations(
            db,
            [current],
            reason="generation_superseded",
            now=now,
        )

    obj.size_bytes = size_bytes
    obj.ciphertext_size_bytes = ciphertext_size_bytes
    obj.sha256 = sha256
    obj.plaintext_sha256 = plaintext_sha256
    obj.lifecycle_state = OBJECT_COMMITTED
    obj.committed_at = now
    await db.flush()
    for placement in proven:
        placement.status = "present"
        placement.confirmed_at = now
        placement.last_error = None
    confirmed = len(proven)
    obj.durable_replica_count = confirmed
    obj.durability_state = _durability_state(confirmed, volume.replication_factor, committed=True)
    obj.durability_updated_at = now
    locked_volume.used_bytes = max(0, new_used_bytes)
    await db.commit()
    await db.refresh(obj)
    await db.refresh(volume)
    replicas_confirmed = confirmed
    if replicas_confirmed < volume.replication_factor:
        logger.warning(
            f"ChuteFS object {object_id} committed under-replicated: {replicas_confirmed}/"
            f"{volume.replication_factor} holders; reconcile will re-replicate."
        )
    return obj, replicas_confirmed


async def _live_attested_server_ids(db: AsyncSession) -> Set[str]:
    """Storage IDs with current disk identity, fresh attestation, and live mTLS activity."""
    all_ids = [
        row[0]
        for row in (
            await db.execute(
                select(Server.server_id).where(
                    Server.storage_role.is_(True),
                    Server.storage_incarnation.is_not(None),
                    Server.attested_cert_pubkey_hash.is_not(None),
                )
            )
        ).all()
    ]
    if not all_ids:
        return set()
    verified = await _verified_storage_ids(db, all_ids)
    live = await _live_storage_ids(all_ids)
    return verified & live


async def _enqueue_inventory_erase_task(
    db: AsyncSession,
    caller: Server,
    volume_id: str,
    object_id: str,
    *,
    placement_id: Optional[str],
    reason: str,
) -> int:
    now = datetime.now(timezone.utc)
    statement = (
        pg_insert(StorageEraseTask)
        .values(
            object_id=object_id,
            volume_id=volume_id,
            placement_id=placement_id,
            server_id=caller.server_id,
            storage_incarnation=caller.storage_incarnation,
            holder_cert_pubkey_hash=_server_pubkey_hash(caller),
            reason=reason,
            state="pending",
            retention_deadline=now + timedelta(seconds=settings.storage_erase_retention_seconds),
        )
        .on_conflict_do_nothing()
    )
    result = await db.execute(statement)
    return int(result.rowcount or 0)


async def _lock_inventory_snapshot_stream(
    db: AsyncSession,
    server_id: str,
    storage_incarnation: str,
) -> None:
    """Serialize page recording and omission reconciliation for one mounted disk."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": (f"chutefs-inventory:{server_id}:{storage_incarnation}")},
    )


async def _lock_model_inventory_snapshot_stream(
    db: AsyncSession,
    server_id: str,
    storage_incarnation: str,
) -> None:
    """Serialize model snapshot completion and reconciliation for one mounted disk."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": (f"chutefs-model-inventory:{server_id}:{storage_incarnation}")},
    )


_MODEL_INVENTORY_ACTIVE_STATES = ("applying", "omitting")


def _model_inventory_snapshot_order(
    snapshot: StorageModelInventorySnapshot,
) -> tuple[datetime, str]:
    return snapshot.started_at, snapshot.snapshot_id


def _server_model_inventory_marker_order(
    server: Server,
    snapshot: StorageModelInventorySnapshot,
) -> Optional[tuple[datetime, str]]:
    if (
        server.model_inventory_storage_incarnation != snapshot.storage_incarnation
        or (server.model_inventory_cert_pubkey_hash or "").lower()
        != snapshot.cert_pubkey_hash.lower()
        or server.model_inventory_snapshot_started_at is None
        or server.model_inventory_snapshot_id is None
    ):
        return None
    return (
        server.model_inventory_snapshot_started_at,
        server.model_inventory_snapshot_id,
    )


def _advance_model_inventory_marker(
    server: Server,
    snapshot: StorageModelInventorySnapshot,
    now: datetime,
) -> None:
    """Record bounded authoritative progress without conflating it with scan start time."""
    server.model_inventory_storage_incarnation = snapshot.storage_incarnation
    server.model_inventory_cert_pubkey_hash = snapshot.cert_pubkey_hash.lower()
    server.model_inventory_snapshot_started_at = snapshot.started_at
    server.model_inventory_snapshot_id = snapshot.snapshot_id
    server.model_inventory_fresh_at = now
    snapshot.last_reconcile_at = now


async def _model_inventory_candidate_ids(
    db: AsyncSession,
    max_snapshots: int,
) -> List[str]:
    """Choose active streams fairly, then the newest waiting snapshot per idle stream."""
    active_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageModelInventorySnapshot.snapshot_id)
                .where(StorageModelInventorySnapshot.state.in_(_MODEL_INVENTORY_ACTIVE_STATES))
                .order_by(
                    StorageModelInventorySnapshot.last_reconcile_at.asc().nullsfirst(),
                    StorageModelInventorySnapshot.application_started_at.asc().nullsfirst(),
                    StorageModelInventorySnapshot.started_at,
                    StorageModelInventorySnapshot.snapshot_id,
                )
                .limit(max_snapshots)
            )
        ).all()
    ]
    remaining_slots = max_snapshots - len(active_ids)
    if remaining_slots <= 0:
        return active_ids

    waiting = aliased(StorageModelInventorySnapshot)
    newer_waiting = aliased(StorageModelInventorySnapshot)
    active = aliased(StorageModelInventorySnapshot)
    waiting_ids = [
        row[0]
        for row in (
            await db.execute(
                select(waiting.snapshot_id)
                .where(
                    waiting.state == "complete",
                    ~exists().where(
                        active.server_id == waiting.server_id,
                        active.storage_incarnation == waiting.storage_incarnation,
                        active.cert_pubkey_hash == waiting.cert_pubkey_hash,
                        active.state.in_(_MODEL_INVENTORY_ACTIVE_STATES),
                    ),
                    ~exists().where(
                        newer_waiting.server_id == waiting.server_id,
                        newer_waiting.storage_incarnation == waiting.storage_incarnation,
                        newer_waiting.cert_pubkey_hash == waiting.cert_pubkey_hash,
                        newer_waiting.state == "complete",
                        tuple_(
                            newer_waiting.started_at,
                            newer_waiting.snapshot_id,
                        )
                        > tuple_(waiting.started_at, waiting.snapshot_id),
                    ),
                )
                .order_by(
                    waiting.completed_at,
                    waiting.started_at,
                    waiting.snapshot_id,
                )
                .limit(remaining_slots)
            )
        ).all()
    ]
    return [*active_ids, *waiting_ids]


async def _supersede_older_model_inventory_snapshots(
    db: AsyncSession,
    active_snapshot: StorageModelInventorySnapshot,
    *,
    limit: int,
    now: datetime,
) -> int:
    """Retire a bounded page of never-started snapshots older than the chosen authority."""
    older_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageModelInventorySnapshot.snapshot_id)
                .where(
                    StorageModelInventorySnapshot.server_id == active_snapshot.server_id,
                    StorageModelInventorySnapshot.storage_incarnation
                    == active_snapshot.storage_incarnation,
                    StorageModelInventorySnapshot.cert_pubkey_hash
                    == active_snapshot.cert_pubkey_hash,
                    StorageModelInventorySnapshot.state == "complete",
                    tuple_(
                        StorageModelInventorySnapshot.started_at,
                        StorageModelInventorySnapshot.snapshot_id,
                    )
                    < _model_inventory_snapshot_order(active_snapshot),
                )
                .order_by(
                    StorageModelInventorySnapshot.started_at.desc(),
                    StorageModelInventorySnapshot.snapshot_id.desc(),
                )
                .limit(limit)
            )
        ).all()
    ]
    if not older_ids:
        return 0
    result = await db.execute(
        update(StorageModelInventorySnapshot)
        .where(
            StorageModelInventorySnapshot.snapshot_id.in_(older_ids),
            StorageModelInventorySnapshot.state == "complete",
        )
        .values(state="reconciled", reconciled_at=now)
    )
    return int(result.rowcount or 0)


async def _reconcile_model_inventory_snapshots(
    db: AsyncSession,
    *,
    max_snapshots: int,
    max_entries: int,
) -> tuple[int, int, int]:
    """Finish active authorities before selecting the newest complete snapshot for an idle stream."""
    snapshot_ids = await _model_inventory_candidate_ids(db, max_snapshots)
    applied = 0
    omitted = 0
    completed = 0
    remaining = max_entries
    for snapshot_id in snapshot_ids:
        if remaining <= 0:
            break
        snapshot_identity = (
            await db.execute(
                select(
                    StorageModelInventorySnapshot.server_id,
                    StorageModelInventorySnapshot.storage_incarnation,
                    StorageModelInventorySnapshot.cert_pubkey_hash,
                ).where(StorageModelInventorySnapshot.snapshot_id == snapshot_id)
            )
        ).first()
        if snapshot_identity is None:
            await db.commit()
            continue
        await _lock_model_inventory_snapshot_stream(
            db,
            snapshot_identity.server_id,
            snapshot_identity.storage_incarnation,
        )
        server = (
            await db.execute(
                select(Server)
                .where(Server.server_id == snapshot_identity.server_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        active_snapshot = (
            await db.execute(
                select(StorageModelInventorySnapshot)
                .where(
                    StorageModelInventorySnapshot.server_id == snapshot_identity.server_id,
                    StorageModelInventorySnapshot.storage_incarnation
                    == snapshot_identity.storage_incarnation,
                    StorageModelInventorySnapshot.cert_pubkey_hash
                    == snapshot_identity.cert_pubkey_hash,
                    StorageModelInventorySnapshot.state.in_(_MODEL_INVENTORY_ACTIVE_STATES),
                )
                .order_by(
                    StorageModelInventorySnapshot.application_started_at,
                    StorageModelInventorySnapshot.started_at,
                    StorageModelInventorySnapshot.snapshot_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        snapshot = active_snapshot
        if snapshot is None:
            snapshot = (
                await db.execute(
                    select(StorageModelInventorySnapshot)
                    .where(
                        StorageModelInventorySnapshot.server_id == snapshot_identity.server_id,
                        StorageModelInventorySnapshot.storage_incarnation
                        == snapshot_identity.storage_incarnation,
                        StorageModelInventorySnapshot.cert_pubkey_hash
                        == snapshot_identity.cert_pubkey_hash,
                        StorageModelInventorySnapshot.state == "complete",
                    )
                    .order_by(
                        StorageModelInventorySnapshot.started_at.desc(),
                        StorageModelInventorySnapshot.snapshot_id.desc(),
                    )
                    .limit(1)
                    .with_for_update()
                )
            ).scalar_one_or_none()
        if snapshot is None:
            await db.commit()
            continue
        current_cert_hash = _server_pubkey_hash(server) if server is not None else None
        now = datetime.now(timezone.utc)
        if (
            server is None
            or server.storage_incarnation != snapshot.storage_incarnation
            or not current_cert_hash
            or current_cert_hash.lower() != snapshot.cert_pubkey_hash.lower()
        ):
            snapshot.state = "reconciled"
            snapshot.reconciled_at = now
            snapshot.last_reconcile_at = now
            completed += 1
            await db.commit()
            continue

        marker_order = _server_model_inventory_marker_order(server, snapshot)
        snapshot_order = _model_inventory_snapshot_order(snapshot)
        newer_applied_snapshot_exists = (
            await db.execute(
                select(
                    exists().where(
                        StorageModelInventorySnapshot.server_id == snapshot.server_id,
                        StorageModelInventorySnapshot.storage_incarnation
                        == snapshot.storage_incarnation,
                        StorageModelInventorySnapshot.cert_pubkey_hash == snapshot.cert_pubkey_hash,
                        StorageModelInventorySnapshot.application_started_at.is_not(None),
                        tuple_(
                            StorageModelInventorySnapshot.started_at,
                            StorageModelInventorySnapshot.snapshot_id,
                        )
                        > snapshot_order,
                    )
                )
            )
        ).scalar_one()
        if newer_applied_snapshot_exists or (
            marker_order is not None
            and (
                marker_order > snapshot_order
                or (snapshot.state == "complete" and marker_order >= snapshot_order)
            )
        ):
            snapshot.state = "reconciled"
            snapshot.reconciled_at = now
            snapshot.last_reconcile_at = now
            completed += 1
            await db.commit()
            continue

        if snapshot.state == "complete":
            snapshot.state = "applying"
            snapshot.application_started_at = now
            await db.flush()
        elif snapshot.application_started_at is None:
            snapshot.application_started_at = now
        completed += await _supersede_older_model_inventory_snapshots(
            db,
            snapshot,
            limit=max_entries,
            now=now,
        )

        if snapshot.state == "applying" and remaining > 0:
            page_limit = remaining
            entry_query = select(StorageModelInventoryEntry).where(
                StorageModelInventoryEntry.snapshot_id == snapshot.snapshot_id
            )
            if (
                snapshot.apply_cursor_repo_id is not None
                and snapshot.apply_cursor_revision is not None
            ):
                entry_query = entry_query.where(
                    tuple_(
                        StorageModelInventoryEntry.repo_id,
                        StorageModelInventoryEntry.revision,
                    )
                    > (
                        snapshot.apply_cursor_repo_id,
                        snapshot.apply_cursor_revision,
                    )
                )
            entries = list(
                (
                    await db.execute(
                        entry_query.order_by(
                            StorageModelInventoryEntry.repo_id,
                            StorageModelInventoryEntry.revision,
                        ).limit(page_limit)
                    )
                )
                .scalars()
                .all()
            )
            if entries:
                application_now = datetime.now(timezone.utc)
                statement = pg_insert(ContentHolding).values(
                    [
                        {
                            "server_id": snapshot.server_id,
                            "repo_id": entry.repo_id,
                            "revision": entry.revision,
                            "bytes": int(entry.bytes),
                            "status": "present",
                            "announced_at": application_now,
                            "last_snapshot_id": snapshot.snapshot_id,
                            "last_snapshot_started_at": snapshot.started_at,
                        }
                        for entry in entries
                    ]
                )
                await db.execute(
                    statement.on_conflict_do_update(
                        index_elements=["server_id", "repo_id", "revision"],
                        set_={
                            "bytes": statement.excluded.bytes,
                            "status": "present",
                            "announced_at": statement.excluded.announced_at,
                            "last_snapshot_id": snapshot.snapshot_id,
                            "last_snapshot_started_at": (
                                statement.excluded.last_snapshot_started_at
                            ),
                        },
                        where=or_(
                            and_(
                                ContentHolding.last_snapshot_started_at.is_(None),
                                tuple_(
                                    ContentHolding.announced_at,
                                    func.coalesce(ContentHolding.last_snapshot_id, ""),
                                )
                                <= snapshot_order,
                            ),
                            tuple_(
                                ContentHolding.last_snapshot_started_at,
                                func.coalesce(ContentHolding.last_snapshot_id, ""),
                            )
                            <= snapshot_order,
                        ),
                    )
                )
                last_entry = entries[-1]
                snapshot.apply_cursor_repo_id = last_entry.repo_id
                snapshot.apply_cursor_revision = last_entry.revision
                snapshot.applied_entries = int(snapshot.applied_entries or 0) + len(entries)
                applied += len(entries)
                remaining -= len(entries)
                _advance_model_inventory_marker(
                    server,
                    snapshot,
                    application_now,
                )
            if len(entries) < page_limit:
                snapshot.state = "omitting"
                snapshot.omit_cursor = None

        if snapshot.state == "omitting" and remaining > 0:
            page_limit = remaining
            holding_query = select(ContentHolding).where(
                ContentHolding.server_id == snapshot.server_id,
            )
            if snapshot.omit_cursor is not None:
                holding_query = holding_query.where(
                    ContentHolding.holding_id > snapshot.omit_cursor
                )
            holdings = list(
                (
                    await db.execute(
                        holding_query.order_by(ContentHolding.holding_id)
                        .limit(page_limit)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            omitted_this_page = 0
            for holding in holdings:
                snapshot.omit_cursor = holding.holding_id
                if holding.last_snapshot_id == snapshot.snapshot_id:
                    continue
                if holding.last_snapshot_started_at is None:
                    source_is_eligible = holding.announced_at <= snapshot.eligibility_cutoff_at
                else:
                    source_is_eligible = (
                        holding.last_snapshot_started_at,
                        holding.last_snapshot_id or "",
                    ) <= snapshot_order
                if source_is_eligible:
                    await db.delete(holding)
                    omitted_this_page += 1
            snapshot.omitted_entries = int(snapshot.omitted_entries or 0) + omitted_this_page
            omitted += omitted_this_page
            remaining -= len(holdings)
            reconcile_now = datetime.now(timezone.utc)
            _advance_model_inventory_marker(server, snapshot, reconcile_now)
            if len(holdings) < page_limit:
                snapshot.state = "reconciled"
                snapshot.reconciled_at = reconcile_now
                completed += 1
        await db.commit()
    return applied, omitted, completed


async def record_inventory_page(
    db: AsyncSession,
    caller: Server,
    snapshot_id: str,
    storage_incarnation: str,
    entries: List[Dict],
    complete: bool,
) -> Dict:
    """Reconcile one bounded finalized-file page without deleting on tracker uncertainty."""
    if len(entries) > settings.storage_inventory_page_size_max:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(f"Inventory page exceeds {settings.storage_inventory_page_size_max} entries."),
        )
    storage_incarnation = _normalize_incarnation(storage_incarnation)
    await _lock_inventory_snapshot_stream(
        db,
        caller.server_id,
        storage_incarnation,
    )
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == caller.server_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    cert_hash = _server_pubkey_hash(server) if server is not None else None
    caller_cert_hash = _server_pubkey_hash(caller)
    if (
        server is None
        or not server.storage_role
        or not server.storage_incarnation
        or server.storage_incarnation != storage_incarnation
        or not cert_hash
        or not caller_cert_hash
        or cert_hash.lower() != caller_cert_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inventory is not bound to this current storage certificate and incarnation.",
        )

    now = datetime.now(timezone.utc)
    snapshot = (
        await db.execute(
            select(StorageInventorySnapshot)
            .where(StorageInventorySnapshot.snapshot_id == snapshot_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if snapshot is None:
        snapshot = StorageInventorySnapshot(
            snapshot_id=snapshot_id,
            server_id=server.server_id,
            storage_incarnation=storage_incarnation,
            cert_pubkey_hash=cert_hash.lower(),
            state="scanning",
            eligibility_cutoff_at=now,
        )
        db.add(snapshot)
        await db.flush()
    elif (
        snapshot.server_id != server.server_id
        or snapshot.storage_incarnation != storage_incarnation
        or snapshot.cert_pubkey_hash.lower() != cert_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Inventory snapshot id is already bound to a different storage identity.",
        )
    elif snapshot.state == "reconciled":
        await db.commit()
        return {
            "snapshot_id": snapshot.snapshot_id,
            "recorded": 0,
            "erase_tasks_enqueued": 0,
            "complete": True,
        }

    recorded = 0
    enqueued = 0
    for entry in entries:
        object_id = entry["object_id"]
        volume_id = entry["volume_id"]
        entry_hash = entry["ciphertext_sha256"].lower()
        entry_size = int(entry["ciphertext_size_bytes"])
        obj = await db.get(StorageObject, object_id)
        placement = (
            await db.execute(
                select(ReplicaPlacement)
                .where(
                    ReplicaPlacement.object_id == object_id,
                    ReplicaPlacement.server_id == server.server_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        volume = await db.get(StorageVolume, volume_id) if obj is not None else None

        active = bool(
            obj is not None
            and obj.volume_id == volume_id
            and volume is not None
            and not volume.deleted
            and obj.lifecycle_state in (OBJECT_PENDING, OBJECT_COMMITTED)
            and placement is not None
            and placement.status in ("pending", "present")
            and _placement_identity_matches(placement, server)
            and (placement.proof_sha256 or "").lower() == entry_hash
            and placement.proof_size_bytes is not None
            and int(placement.proof_size_bytes) == entry_size
            and (
                obj.lifecycle_state == OBJECT_PENDING
                or (
                    (obj.sha256 or "").lower() == entry_hash
                    and obj.ciphertext_size_bytes is not None
                    and int(obj.ciphertext_size_bytes) == entry_size
                )
            )
        )
        if active:
            placement.last_inventory_snapshot_id = snapshot.snapshot_id
            placement.last_inventory_seen_at = now
            recorded += 1
            continue

        if placement is not None and placement.status in ("pending", "present"):
            placement.status = "evicted"
            placement.last_error = "inventory_not_authoritative"
        reason = (
            "inventory_retired_generation"
            if obj is not None and obj.lifecycle_state in (OBJECT_SUPERSEDED, OBJECT_TOMBSTONED)
            else "inventory_untracked_or_mismatched_file"
        )
        enqueued += await _enqueue_inventory_erase_task(
            db,
            server,
            volume_id,
            object_id,
            placement_id=placement.placement_id if placement is not None else None,
            reason=reason,
        )

    snapshot.reported_entries = int(snapshot.reported_entries or 0) + len(entries)
    snapshot.last_page_at = now
    if complete and snapshot.state == "scanning":
        snapshot.state = "complete"
        snapshot.completed_at = now
        snapshot.reconcile_cursor = None
    await db.commit()
    return {
        "snapshot_id": snapshot.snapshot_id,
        "recorded": recorded,
        "erase_tasks_enqueued": enqueued,
        "complete": snapshot.state in ("complete", "reconciled"),
    }


async def claim_erase_tasks(
    db: AsyncSession,
    caller: Server,
    limit: int,
) -> List[Dict]:
    """Lease durable erase work only to the exact current holder incarnation."""
    cert_hash = _server_pubkey_hash(caller)
    if not caller.storage_incarnation or not cert_hash:
        return []
    now = datetime.now(timezone.utc)
    await db.execute(
        update(StorageEraseTask)
        .where(
            StorageEraseTask.server_id == caller.server_id,
            StorageEraseTask.storage_incarnation == caller.storage_incarnation,
            StorageEraseTask.state == "claimed",
            StorageEraseTask.lease_expires_at <= now,
        )
        .values(
            state="pending",
            claimed_at=None,
            lease_expires_at=None,
            claim_cert_pubkey_hash=None,
            last_error="erase_lease_expired",
        )
    )
    tasks = list(
        (
            await db.execute(
                select(StorageEraseTask)
                .where(
                    StorageEraseTask.server_id == caller.server_id,
                    StorageEraseTask.storage_incarnation == caller.storage_incarnation,
                    StorageEraseTask.state == "pending",
                )
                .order_by(StorageEraseTask.created_at, StorageEraseTask.task_id)
                .limit(min(limit, 100))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    lease_expires_at = now + timedelta(seconds=settings.storage_erase_task_lease_seconds)
    result: List[Dict] = []
    for task in tasks:
        task.state = "claimed"
        task.claimed_at = now
        task.lease_expires_at = lease_expires_at
        task.claim_cert_pubkey_hash = cert_hash.lower()
        task.attempt_count = int(task.attempt_count or 0) + 1
        result.append(
            {
                "task_id": task.task_id,
                "object_id": task.object_id,
                "volume_id": task.volume_id,
                "storage_incarnation": task.storage_incarnation,
                "reason": task.reason,
                "lease_expires_at": lease_expires_at.isoformat(),
            }
        )
    await db.commit()
    return result


async def record_erase_task_result(
    db: AsyncSession,
    caller: Server,
    task_id: str,
    result_status: str,
    file_was_present: Optional[bool],
    error: Optional[str],
) -> Dict:
    task = (
        await db.execute(
            select(StorageEraseTask).where(StorageEraseTask.task_id == task_id).with_for_update()
        )
    ).scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Erase task not found.")
    if task.state in ERASE_TERMINAL_STATES:
        await db.commit()
        return {"recorded": True, "task_id": task.task_id, "terminal": True}
    cert_hash = _server_pubkey_hash(caller)
    if (
        task.server_id != caller.server_id
        or not caller.storage_incarnation
        or task.storage_incarnation != caller.storage_incarnation
        or not cert_hash
        or task.claim_cert_pubkey_hash != cert_hash.lower()
        or task.state != "claimed"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Erase task is not leased to this current attested storage identity.",
        )
    now = datetime.now(timezone.utc)
    if task.lease_expires_at is None or task.lease_expires_at <= now:
        task.state = "pending"
        task.claimed_at = None
        task.lease_expires_at = None
        task.claim_cert_pubkey_hash = None
        task.last_error = "erase_result_after_lease_expiry"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Erase task lease expired before acknowledgement.",
        )
    if result_status == "failed":
        task.state = "pending"
        task.claimed_at = None
        task.lease_expires_at = None
        task.claim_cert_pubkey_hash = None
        task.last_error = (error or "erase_failed")[:256]
        await db.commit()
        return {"recorded": True, "task_id": task.task_id, "terminal": False}

    task.state = "erased"
    task.completed_at = now
    task.erased_file_was_present = bool(file_was_present)
    task.last_error = None
    await db.commit()
    return {"recorded": True, "task_id": task.task_id, "terminal": True}


async def administratively_retire_erase_tasks(
    db: AsyncSession,
    administrator_user_id: str,
    task_ids: List[str],
    reason: str,
) -> int:
    if not settings.storage_allow_administrative_erase_retirement:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative erase retirement is disabled by validator policy.",
        )
    now = datetime.now(timezone.utc)
    tasks = list(
        (
            await db.execute(
                select(StorageEraseTask)
                .where(StorageEraseTask.task_id.in_(list(dict.fromkeys(task_ids))))
                .order_by(StorageEraseTask.task_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    found = {task.task_id for task in tasks}
    missing = set(task_ids) - found
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Erase tasks not found: {sorted(missing)}",
        )
    retired = 0
    for task in tasks:
        if task.state in ERASE_TERMINAL_STATES:
            continue
        if task.retention_deadline > now:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Erase task {task.task_id} is still inside mandatory retention.",
            )
        task.state = "retired"
        task.completed_at = now
        task.retired_by_user_id = administrator_user_id
        task.last_error = f"administrator_retired:{reason}"[:256]
        retired += 1
    await db.commit()
    return retired


async def _reconcile_inventory_omissions(
    db: AsyncSession,
    *,
    max_snapshots: int,
    max_placements: int,
) -> tuple[int, int]:
    """Process only completed snapshots; incomplete/outage-interrupted scans have no effect."""
    snapshot_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageInventorySnapshot.snapshot_id)
                .where(StorageInventorySnapshot.state == "complete")
                .order_by(
                    StorageInventorySnapshot.completed_at,
                    StorageInventorySnapshot.snapshot_id,
                )
                .limit(max_snapshots)
            )
        ).all()
    ]
    omitted = 0
    completed = 0
    remaining = max_placements
    for snapshot_id in snapshot_ids:
        if remaining <= 0:
            break
        snapshot_identity = (
            await db.execute(
                select(
                    StorageInventorySnapshot.server_id,
                    StorageInventorySnapshot.storage_incarnation,
                ).where(StorageInventorySnapshot.snapshot_id == snapshot_id)
            )
        ).first()
        if snapshot_identity is None:
            await db.commit()
            continue
        await _lock_inventory_snapshot_stream(
            db,
            snapshot_identity.server_id,
            snapshot_identity.storage_incarnation,
        )
        # The snapshot row is the serialization point. Placement rows are deliberately not read
        # with SKIP LOCKED: skipping one and advancing the keyset cursor would permanently lose it.
        snapshot = (
            await db.execute(
                select(StorageInventorySnapshot)
                .where(
                    StorageInventorySnapshot.snapshot_id == snapshot_id,
                    StorageInventorySnapshot.state == "complete",
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if snapshot is None:
            await db.commit()
            continue
        snapshot_omitted = 0
        query = select(ReplicaPlacement).where(
            ReplicaPlacement.server_id == snapshot.server_id,
            ReplicaPlacement.storage_incarnation == snapshot.storage_incarnation,
            ReplicaPlacement.status == "present",
            ReplicaPlacement.created_at <= snapshot.eligibility_cutoff_at,
            ReplicaPlacement.proof_at.is_not(None),
            ReplicaPlacement.proof_at <= snapshot.eligibility_cutoff_at,
        )
        if snapshot.reconcile_cursor:
            query = query.where(ReplicaPlacement.placement_id > snapshot.reconcile_cursor)
        page_limit = remaining
        placements = list(
            (
                await db.execute(
                    query.order_by(ReplicaPlacement.placement_id)
                    .limit(page_limit)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for placement in placements:
            snapshot.reconcile_cursor = placement.placement_id
            if placement.last_inventory_snapshot_id == snapshot.snapshot_id or (
                placement.last_inventory_seen_at is not None
                and placement.last_inventory_seen_at > snapshot.eligibility_cutoff_at
            ):
                continue
            placement.status = "evicted"
            placement.last_error = "omitted_from_complete_inventory"
            omitted += 1
            snapshot_omitted += 1
            obj = await db.get(StorageObject, placement.object_id)
            if obj is not None and obj.lifecycle_state == OBJECT_COMMITTED:
                obj.durability_updated_at = None
        snapshot.omitted_entries = int(snapshot.omitted_entries or 0) + snapshot_omitted
        remaining -= len(placements)
        if len(placements) < page_limit:
            snapshot.state = "reconciled"
            snapshot.reconciled_at = datetime.now(timezone.utc)
            completed += 1
        await db.commit()
    return omitted, completed


async def _finalize_erasure_batch(
    db: AsyncSession,
    *,
    limit: int,
) -> tuple[int, int]:
    """Bound chain detachment, metadata purge, and deleted-volume key shredding globally."""
    now = datetime.now(timezone.utc)
    purged_objects = 0
    shredded_keys = 0
    remaining = max(1, limit)
    dependent_generation = StorageObject.__table__.alias("dependent_generation")
    retired = list(
        (
            await db.execute(
                select(StorageObject)
                .where(
                    StorageObject.lifecycle_state.in_((OBJECT_SUPERSEDED, OBJECT_TOMBSTONED)),
                    StorageObject.erase_enqueued_at.is_not(None),
                    ~exists(
                        select(1).where(
                            StorageEraseTask.object_id == StorageObject.object_id,
                            StorageEraseTask.state.not_in(ERASE_TERMINAL_STATES),
                        )
                    ),
                    ~exists(
                        select(1)
                        .select_from(dependent_generation)
                        .where(
                            dependent_generation.c.expected_predecessor_id
                            == StorageObject.object_id,
                            dependent_generation.c.lifecycle_state == OBJECT_PENDING,
                        )
                    ),
                )
                .order_by(
                    func.coalesce(
                        StorageObject.tombstoned_at,
                        StorageObject.superseded_at,
                        StorageObject.created_at,
                    ),
                    StorageObject.object_id,
                )
                .limit(remaining)
                .with_for_update(of=StorageObject, skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for obj in retired:
        if remaining <= 0:
            break

        # Non-pending successors no longer need this CAS edge. Detach in bounded pages only after
        # the predecessor's every known holder has a terminal erase task; the trigger independently
        # enforces the same rule and preserves the predecessor id as immutable audit metadata.
        dependent_budget = remaining
        dependents = list(
            (
                await db.execute(
                    select(StorageObject)
                    .where(StorageObject.expected_predecessor_id == obj.object_id)
                    .order_by(StorageObject.object_id)
                    .limit(dependent_budget + 1)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        if any(dependent.lifecycle_state == OBJECT_PENDING for dependent in dependents):
            continue
        for dependent in dependents[:dependent_budget]:
            dependent.detached_predecessor_id = obj.object_id
            dependent.predecessor_detached_at = now
            dependent.expected_predecessor_id = None
            remaining -= 1
        if dependents:
            await db.flush()
        if len(dependents) > dependent_budget:
            continue
        still_referenced = (
            await db.execute(
                select(exists().where(StorageObject.expected_predecessor_id == obj.object_id))
            )
        ).scalar_one()
        if still_referenced or remaining <= 0:
            continue

        placement_ids = [
            row[0]
            for row in (
                await db.execute(
                    select(ReplicaPlacement.placement_id)
                    .where(ReplicaPlacement.object_id == obj.object_id)
                    .order_by(ReplicaPlacement.placement_id)
                    .limit(remaining + 1)
                    .with_for_update()
                )
            ).all()
        ]
        delete_placement_ids = placement_ids[:remaining]
        if delete_placement_ids:
            await db.execute(
                delete(ReplicaPlacement).where(
                    ReplicaPlacement.placement_id.in_(delete_placement_ids)
                )
            )
            remaining -= len(delete_placement_ids)
        if len(placement_ids) > len(delete_placement_ids) or remaining <= 0:
            continue

        task_ids = [
            row[0]
            for row in (
                await db.execute(
                    select(StorageEraseTask.task_id)
                    .where(
                        StorageEraseTask.object_id == obj.object_id,
                        StorageEraseTask.state.in_(ERASE_TERMINAL_STATES),
                        StorageEraseTask.metadata_purged_at.is_(None),
                    )
                    .order_by(StorageEraseTask.task_id)
                    .limit(remaining + 1)
                    .with_for_update()
                )
            ).all()
        ]
        mark_task_ids = task_ids[:remaining]
        if mark_task_ids:
            await db.execute(
                update(StorageEraseTask)
                .where(StorageEraseTask.task_id.in_(mark_task_ids))
                .values(metadata_purged_at=now)
            )
            remaining -= len(mark_task_ids)
        if len(task_ids) > len(mark_task_ids) or remaining <= 0:
            continue

        await db.delete(obj)
        await db.flush()
        purged_objects += 1
        remaining -= 1

    # Terminal tasks can outlive already-purged metadata by design. Mark a bounded orphan page so
    # audit retention and deleted-volume finalization can progress without an unbounded UPDATE.
    if remaining > 0:
        orphan_task_ids = [
            row[0]
            for row in (
                await db.execute(
                    select(StorageEraseTask.task_id)
                    .where(
                        StorageEraseTask.state.in_(ERASE_TERMINAL_STATES),
                        StorageEraseTask.metadata_purged_at.is_(None),
                        ~exists(
                            select(1).where(StorageObject.object_id == StorageEraseTask.object_id)
                        ),
                    )
                    .order_by(StorageEraseTask.object_id, StorageEraseTask.task_id)
                    .limit(remaining)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        ]
        if orphan_task_ids:
            await db.execute(
                update(StorageEraseTask)
                .where(StorageEraseTask.task_id.in_(orphan_task_ids))
                .values(metadata_purged_at=now)
            )
            remaining -= len(orphan_task_ids)

    deleted_volumes = list(
        (
            await db.execute(
                select(StorageVolume)
                .where(
                    StorageVolume.deleted.is_(True),
                    StorageVolume.purged_at.is_(None),
                )
                .order_by(StorageVolume.delete_requested_at, StorageVolume.volume_id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for volume in deleted_volumes:
        blocked = (
            await db.execute(
                select(
                    exists().where(StorageObject.volume_id == volume.volume_id)
                    | exists().where(
                        StorageEraseTask.volume_id == volume.volume_id,
                        or_(
                            StorageEraseTask.state.not_in(ERASE_TERMINAL_STATES),
                            StorageEraseTask.reason != "volume_deleted",
                            StorageEraseTask.metadata_purged_at.is_(None),
                        ),
                    )
                )
            )
        ).scalar_one()
        if blocked:
            continue
        if volume.key_shredded_at is None:
            key_row = await db.get(StorageVolumeKey, volume.volume_id, with_for_update=True)
            if key_row is not None:
                await db.delete(key_row)
            volume.key_shredded_at = now
            shredded_keys += 1
        volume.purged_at = now

    await db.commit()
    return purged_objects, shredded_keys


async def reconcile_storage(db: AsyncSession, max_objects: int = 500) -> Dict[str, int]:
    """Retire stale generations, then reconcile current committed generations independently."""
    max_objects = max(1, min(max_objects, settings.storage_reconcile_batch_size))
    summary = {
        "gc_deleted_object_placements": 0,
        "reaped_abandoned": 0,
        "retired_volume_generations": 0,
        "volume_key_cache_tasks_requeued": 0,
        "object_delete_generations_retired": 0,
        "object_delete_fences_completed": 0,
        "erase_tasks_enqueued": 0,
        "model_holdings_applied": 0,
        "model_holding_omissions": 0,
        "model_inventory_snapshots_reconciled": 0,
        "inventory_omissions": 0,
        "inventory_snapshots_reconciled": 0,
        "purged_objects": 0,
        "shredded_volume_keys": 0,
        "stale_model_holdings_purged": 0,
        "stale_model_inventory_snapshots_purged": 0,
        "stale_inventory_snapshots_purged": 0,
        "erase_audit_rows_purged": 0,
        "reassigned": 0,
        "expired_pending": 0,
        "unfulfillable_pending": 0,
        "under_replicated": 0,
        "irrecoverable": 0,
        "object_failures": 0,
    }

    # Deleted volumes and abandoned uploads are retired in keyset-sized batches. Holder rows remain
    # until their durable erase tasks reach a terminal state.
    deleted_volumes = list(
        (
            await db.execute(
                select(StorageVolume)
                .where(
                    StorageVolume.deleted.is_(True),
                    StorageVolume.purged_at.is_(None),
                )
                .order_by(StorageVolume.delete_requested_at, StorageVolume.volume_id)
                .limit(max_objects)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    remaining_generation_budget = max_objects
    for deleted_volume in deleted_volumes:
        if remaining_generation_budget <= 0:
            break
        retired_count, requeued_count = await _retire_deleted_volume_batch(
            db,
            deleted_volume,
            limit=remaining_generation_budget,
        )
        summary["retired_volume_generations"] += retired_count
        summary["volume_key_cache_tasks_requeued"] += requeued_count
        remaining_generation_budget -= retired_count + requeued_count

    delete_fences = list(
        (
            await db.execute(
                select(StorageObjectDeleteFence)
                .where(StorageObjectDeleteFence.completed_at.is_(None))
                .order_by(
                    StorageObjectDeleteFence.cutoff_at,
                    StorageObjectDeleteFence.fence_id,
                )
                .limit(max_objects)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    remaining_delete_budget = max_objects
    for fence in delete_fences:
        if remaining_delete_budget <= 0:
            break
        generations, completed = await _retire_object_delete_fence_batch(
            db,
            fence,
            limit=remaining_delete_budget,
        )
        summary["object_delete_generations_retired"] += len(generations)
        if completed:
            summary["object_delete_fences_completed"] += 1
        remaining_delete_budget -= len(generations)

    abandon_cutoff = datetime.now(timezone.utc) - timedelta(seconds=_ABANDONED_OBJECT_TTL_SECONDS)
    abandoned = list(
        (
            await db.execute(
                select(StorageObject)
                .where(
                    StorageObject.lifecycle_state == OBJECT_PENDING,
                    StorageObject.created_at < abandon_cutoff,
                )
                .order_by(StorageObject.created_at, StorageObject.object_id)
                .limit(max_objects)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    abandon_now = datetime.now(timezone.utc)
    for obj in abandoned:
        obj.lifecycle_state = OBJECT_TOMBSTONED
        obj.tombstoned_at = abandon_now
        summary["reaped_abandoned"] += 1

    if summary["reaped_abandoned"]:
        await db.flush()
        summary["erase_tasks_enqueued"] += await _enqueue_erase_tasks_for_generations(
            db,
            abandoned,
            reason="abandoned_upload",
            now=abandon_now,
        )

    retired = list(
        (
            await db.execute(
                select(StorageObject)
                .where(
                    StorageObject.lifecycle_state.in_((OBJECT_SUPERSEDED, OBJECT_TOMBSTONED)),
                    StorageObject.erase_enqueued_at.is_(None),
                )
                .order_by(
                    func.coalesce(
                        StorageObject.tombstoned_at,
                        StorageObject.superseded_at,
                        StorageObject.created_at,
                    ),
                    StorageObject.object_id,
                )
                .limit(max_objects)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if retired:
        summary["erase_tasks_enqueued"] += await _enqueue_erase_tasks_for_generations(
            db,
            retired,
            reason="generation_retired",
        )
    await db.commit()

    (
        summary["model_holdings_applied"],
        summary["model_holding_omissions"],
        summary["model_inventory_snapshots_reconciled"],
    ) = await _reconcile_model_inventory_snapshots(
        db,
        max_snapshots=max(1, min(10, max_objects)),
        max_entries=max_objects,
    )
    (
        summary["inventory_omissions"],
        summary["inventory_snapshots_reconciled"],
    ) = await _reconcile_inventory_omissions(
        db,
        max_snapshots=max(1, min(10, max_objects)),
        max_placements=max_objects,
    )
    (
        summary["purged_objects"],
        summary["shredded_volume_keys"],
    ) = await _finalize_erasure_batch(db, limit=max_objects)

    holding_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_model_holding_freshness_seconds
    )
    stale_model_server_ids = (
        select(Server.server_id)
        .where(
            Server.storage_role.is_(True),
            or_(
                Server.model_inventory_fresh_at.is_(None),
                Server.model_inventory_fresh_at < holding_cutoff,
                Server.model_inventory_storage_incarnation.is_distinct_from(
                    Server.storage_incarnation
                ),
                func.lower(Server.model_inventory_cert_pubkey_hash).is_distinct_from(
                    func.lower(Server.attested_cert_pubkey_hash)
                ),
            ),
        )
        .order_by(
            Server.model_inventory_fresh_at.asc().nullsfirst(),
            Server.server_id,
        )
        .limit(max_objects)
    )
    stale_holding_ids = [
        row[0]
        for row in (
            await db.execute(
                select(ContentHolding.holding_id)
                .where(ContentHolding.server_id.in_(stale_model_server_ids))
                .order_by(ContentHolding.server_id, ContentHolding.holding_id)
                .limit(max_objects)
            )
        ).all()
    ]
    if stale_holding_ids:
        summary["stale_model_holdings_purged"] = (
            await db.execute(
                delete(ContentHolding).where(ContentHolding.holding_id.in_(stale_holding_ids))
            )
        ).rowcount or 0

    snapshot_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_inventory_snapshot_retention_seconds
    )
    stale_snapshot_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageInventorySnapshot.snapshot_id)
                .where(
                    StorageInventorySnapshot.last_page_at < snapshot_cutoff,
                    StorageInventorySnapshot.state.in_(("scanning", "reconciled")),
                )
                .order_by(
                    StorageInventorySnapshot.last_page_at,
                    StorageInventorySnapshot.snapshot_id,
                )
                .limit(max_objects)
            )
        ).all()
    ]
    if stale_snapshot_ids:
        summary["stale_inventory_snapshots_purged"] = (
            await db.execute(
                delete(StorageInventorySnapshot).where(
                    StorageInventorySnapshot.snapshot_id.in_(stale_snapshot_ids)
                )
            )
        ).rowcount or 0

    stale_model_snapshot_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageModelInventorySnapshot.snapshot_id)
                .where(
                    StorageModelInventorySnapshot.last_page_at < snapshot_cutoff,
                    StorageModelInventorySnapshot.state.in_(("scanning", "reconciled")),
                )
                .order_by(
                    StorageModelInventorySnapshot.last_page_at,
                    StorageModelInventorySnapshot.snapshot_id,
                )
                .limit(max_objects)
            )
        ).all()
    ]
    if stale_model_snapshot_ids:
        summary["stale_model_inventory_snapshots_purged"] = (
            await db.execute(
                delete(StorageModelInventorySnapshot).where(
                    StorageModelInventorySnapshot.snapshot_id.in_(stale_model_snapshot_ids)
                )
            )
        ).rowcount or 0

    audit_cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.storage_erase_audit_retention_seconds
    )
    stale_task_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageEraseTask.task_id)
                .join(
                    StorageVolume,
                    StorageVolume.volume_id == StorageEraseTask.volume_id,
                )
                .where(
                    StorageVolume.purged_at.is_not(None),
                    StorageEraseTask.metadata_purged_at.is_not(None),
                    StorageEraseTask.completed_at < audit_cutoff,
                    StorageEraseTask.state.in_(ERASE_TERMINAL_STATES),
                )
                .order_by(StorageEraseTask.completed_at, StorageEraseTask.task_id)
                .limit(max_objects)
            )
        ).all()
    ]
    if stale_task_ids:
        summary["erase_audit_rows_purged"] = (
            await db.execute(
                delete(StorageEraseTask).where(StorageEraseTask.task_id.in_(stale_task_ids))
            )
        ).rowcount or 0
    await db.commit()

    object_ids = [
        row[0]
        for row in (
            await db.execute(
                select(StorageObject.object_id)
                .join(StorageVolume, StorageVolume.volume_id == StorageObject.volume_id)
                .where(
                    StorageObject.lifecycle_state == OBJECT_COMMITTED,
                    StorageVolume.deleted.is_(False),
                )
                .order_by(
                    StorageObject.durability_updated_at.asc().nullsfirst(),
                    StorageObject.object_id,
                )
                .limit(max_objects)
            )
        ).all()
    ]
    await db.commit()

    for object_id in object_ids:
        local_reassigned = 0
        local_expired = 0
        local_unfulfillable = 0
        local_under_replicated = 0
        local_irrecoverable = 0
        processed = False
        try:
            async with db.begin_nested():
                row = (
                    await db.execute(
                        select(StorageObject, StorageVolume)
                        .join(
                            StorageVolume,
                            StorageVolume.volume_id == StorageObject.volume_id,
                        )
                        .where(
                            StorageObject.object_id == object_id,
                            StorageObject.lifecycle_state == OBJECT_COMMITTED,
                            StorageVolume.deleted.is_(False),
                        )
                        .with_for_update(of=StorageObject, skip_locked=True)
                    )
                ).first()
                if row is None:
                    continue
                processed = True
                obj, volume = row
                placements = list(
                    (
                        await db.execute(
                            select(ReplicaPlacement)
                            .where(ReplicaPlacement.object_id == object_id)
                            .with_for_update()
                        )
                    )
                    .scalars()
                    .all()
                )
                servers = list(
                    (await db.execute(select(Server).where(Server.storage_role.is_(True))))
                    .scalars()
                    .all()
                )
                server_by_id = {server.server_id: server for server in servers}
                live_ids = await _live_attested_server_ids(db)
                now = datetime.now(timezone.utc)

                for placement in placements:
                    server = server_by_id.get(placement.server_id)
                    identity_valid = server is not None and _placement_identity_matches(
                        placement, server
                    )
                    if placement.status == "present" and not identity_valid:
                        placement.status = "evicted"
                        placement.last_error = "stale_storage_identity"
                    elif placement.status == "pending":
                        expired = (
                            placement.pending_deadline is None
                            or placement.pending_deadline <= now
                            or placement.attempt_count >= MAX_PLACEMENT_ATTEMPTS
                        )
                        unavailable = (
                            server is None
                            or placement.server_id not in live_ids
                            or not identity_valid
                        )
                        if expired or unavailable:
                            placement.status = "evicted"
                            placement.last_error = (
                                "pending_deadline_or_attempts_exhausted"
                                if expired
                                else "pending_target_unavailable"
                            )
                            local_expired += int(expired)
                            local_unfulfillable += int(unavailable)

                present = await _current_durable_placements(
                    db,
                    obj,
                    live_ids=live_ids,
                    placements=placements,
                    servers=servers,
                )
                present_hosts = {
                    (server_by_id[p.server_id].host_id or p.server_id) for p in present
                }

                active_pending: List[ReplicaPlacement] = []
                pending_hosts: Set[str] = set()
                for placement in placements:
                    server = server_by_id.get(placement.server_id)
                    if (
                        placement.status != "pending"
                        or server is None
                        or placement.server_id not in live_ids
                        or not _placement_identity_matches(placement, server)
                        or placement.pending_deadline is None
                        or placement.pending_deadline <= now
                    ):
                        continue
                    host = server.host_id or server.server_id
                    if host in present_hosts or host in pending_hosts:
                        placement.status = "evicted"
                        placement.last_error = "duplicate_failure_domain"
                        local_unfulfillable += 1
                        continue
                    pending_hosts.add(host)
                    active_pending.append(placement)

                if not present:
                    # A target assignment without a live source cannot be repaired. Pending work must
                    # not mask total loss or report a healthy replication factor.
                    for placement in active_pending:
                        placement.status = "evicted"
                        placement.last_error = "no_live_possession_source"
                        local_unfulfillable += 1
                    obj.durable_replica_count = 0
                    obj.durability_state = "irrecoverable"
                    obj.durability_updated_at = func.now()
                    local_under_replicated = 1
                    local_irrecoverable = 1
                    await db.flush()
                else:
                    durable_count = len(present)
                    if durable_count < volume.replication_factor:
                        local_under_replicated = 1

                    pending_budget = max(0, volume.replication_factor - durable_count)
                    if len(active_pending) > pending_budget:
                        active_pending.sort(
                            key=lambda placement: (
                                placement.pending_since
                                or datetime.min.replace(tzinfo=timezone.utc),
                                placement.server_id,
                            )
                        )
                        for placement in active_pending[pending_budget:]:
                            placement.status = "evicted"
                            placement.last_error = "replication_target_already_assigned"
                        active_pending = active_pending[:pending_budget]
                        pending_hosts = {
                            server_by_id[placement.server_id].host_id or placement.server_id
                            for placement in active_pending
                        }

                    needed = max(
                        0,
                        volume.replication_factor - durable_count - len(active_pending),
                    )
                    used_hosts = present_hosts | pending_hosts
                    assigned_servers = {
                        placement.server_id for placement in present + active_pending
                    }
                    existing_by_server = {
                        placement.server_id: placement for placement in placements
                    }
                    projected_size = max(
                        int(obj.projected_size_bytes or 0),
                        int(obj.size_bytes or 0),
                    )
                    candidates = await _capacity_ranked_peers(db, servers, projected_size)
                    for peer in candidates:
                        if needed <= 0:
                            break
                        candidate = server_by_id[peer.server_id]
                        host = candidate.host_id or candidate.server_id
                        prior = existing_by_server.get(candidate.server_id)
                        if (
                            candidate.server_id in assigned_servers
                            or host in used_hosts
                            or (prior is not None and prior.attempt_count >= MAX_PLACEMENT_ATTEMPTS)
                        ):
                            continue
                        # Re-read and lock the target identity used by the upsert. If it changes
                        # concurrently, this object's savepoint fails without affecting any other.
                        candidate = (
                            await db.execute(
                                select(Server)
                                .where(Server.server_id == candidate.server_id)
                                .with_for_update()
                            )
                        ).scalar_one()
                        if (
                            candidate.server_id not in live_ids
                            or not candidate.storage_incarnation
                            or not _server_pubkey_hash(candidate)
                        ):
                            continue
                        await _upsert_pending_placement(db, obj, candidate)
                        assigned_servers.add(candidate.server_id)
                        used_hosts.add(host)
                        needed -= 1
                        local_reassigned += 1

                    obj.durable_replica_count = durable_count
                    obj.durability_state = _durability_state(
                        durable_count,
                        volume.replication_factor,
                        committed=True,
                    )
                    obj.durability_updated_at = func.now()
                    await db.flush()

            if processed:
                await db.commit()
                summary["reassigned"] += local_reassigned
                summary["expired_pending"] += local_expired
                summary["unfulfillable_pending"] += local_unfulfillable
                summary["under_replicated"] += local_under_replicated
                summary["irrecoverable"] += local_irrecoverable
        except Exception as exc:  # noqa: BLE001 - one object cannot poison the fleet pass
            # begin_nested() already rolled back only this object's savepoint. Commit the otherwise
            # clean outer transaction to release locks without undoing or expiring prior objects.
            await db.commit()
            summary["object_failures"] += 1
            logger.warning(f"ChuteFS reconcile failed for object {object_id}: {exc}")

    if any(summary.values()):
        logger.info(f"ChuteFS reconcile: {summary}")
    return summary


async def repair_tasks_for_server(
    db: AsyncSession, server_id: str, max_tasks: int = 25
) -> List[Dict]:
    """Return capability-free repair descriptors for objects this exact source currently holds.

    The source requests a one-use target capability immediately before each transfer. Tokens are not
    minted here, so a serial repair queue cannot age them while earlier objects stream.
    """
    source = await db.get(Server, server_id)
    if source is None or not source.storage_role:
        return []
    live_ids = await _live_attested_server_ids(db)
    if server_id not in live_ids:
        return []
    max_tasks = max(1, min(max_tasks, 100))
    pending_target = ReplicaPlacement.__table__.alias("pending_repair_target")
    held = list(
        (
            await db.execute(
                select(ReplicaPlacement, StorageObject)
                .join(
                    StorageObject,
                    StorageObject.object_id == ReplicaPlacement.object_id,
                )
                .join(
                    StorageVolume,
                    StorageVolume.volume_id == StorageObject.volume_id,
                )
                .where(
                    ReplicaPlacement.server_id == server_id,
                    ReplicaPlacement.status == "present",
                    ReplicaPlacement.storage_incarnation == source.storage_incarnation,
                    func.lower(ReplicaPlacement.target_cert_pubkey_hash)
                    == (_server_pubkey_hash(source) or "").lower(),
                    ReplicaPlacement.proof_mode.in_(
                        (
                            "direct_upload",
                            "replication_capability",
                            "legacy_adoption",
                        )
                    ),
                    func.lower(ReplicaPlacement.proof_sha256) == func.lower(StorageObject.sha256),
                    ReplicaPlacement.proof_size_bytes == StorageObject.ciphertext_size_bytes,
                    StorageObject.lifecycle_state == OBJECT_COMMITTED,
                    StorageObject.sha256.is_not(None),
                    StorageObject.ciphertext_size_bytes.is_not(None),
                    StorageVolume.deleted.is_(False),
                    exists(
                        select(1)
                        .select_from(pending_target)
                        .where(
                            pending_target.c.object_id == StorageObject.object_id,
                            pending_target.c.status == "pending",
                            pending_target.c.server_id != server_id,
                            pending_target.c.attempt_count < MAX_PLACEMENT_ATTEMPTS,
                        )
                    ),
                )
                .order_by(ReplicaPlacement.placement_id)
                .limit(max_tasks)
            )
        ).all()
    )
    tasks: List[Dict] = []
    for source_placement, obj in held:
        object_id = source_placement.object_id
        pending = list(
            (
                await db.execute(
                    select(ReplicaPlacement)
                    .where(
                        ReplicaPlacement.object_id == object_id,
                        ReplicaPlacement.status == "pending",
                        ReplicaPlacement.server_id != server_id,
                        ReplicaPlacement.attempt_count < MAX_PLACEMENT_ATTEMPTS,
                    )
                    .order_by(ReplicaPlacement.placement_id)
                    .limit(10)
                )
            )
            .scalars()
            .all()
        )
        if not pending:
            continue
        target_servers = await _storage_servers_by_id(
            db, [placement.server_id for placement in pending]
        )
        target_by_id = {server.server_id: server for server in target_servers}
        valid_pending = [
            placement
            for placement in pending
            if placement.server_id in live_ids
            and placement.server_id in target_by_id
            and _placement_identity_matches(placement, target_by_id[placement.server_id])
        ]
        peers = await _attested_live_peers(
            db,
            [target_by_id[placement.server_id] for placement in valid_pending],
        )
        if not peers:
            continue
        tasks.append(
            {
                "object_id": object_id,
                "volume_id": obj.volume_id,
                "ciphertext_sha256": obj.sha256.lower(),
                "ciphertext_size_bytes": int(obj.ciphertext_size_bytes),
                "peers": [p.model_dump() for p in peers],
            }
        )
    await db.commit()
    return tasks


def _capability_binding(capability: StorageReplicationCapability) -> Dict:
    return {
        "capability_id": capability.capability_id,
        "object_id": capability.object_id,
        "volume_id": capability.volume_id,
        "source_server_id": capability.source_server_id,
        "source_cert_pubkey_hash": capability.source_cert_pubkey_hash,
        "source_storage_incarnation": capability.source_storage_incarnation,
        "target_server_id": capability.target_server_id,
        "target_cert_pubkey_hash": capability.target_cert_pubkey_hash,
        "target_storage_incarnation": capability.target_storage_incarnation,
        "target_placement_id": capability.target_placement_id,
        "target_placement_attempt": capability.target_placement_attempt,
        "expected_ciphertext_sha256": capability.expected_ciphertext_sha256,
        "expected_ciphertext_size_bytes": int(capability.expected_ciphertext_size_bytes),
        "expires_at": capability.expires_at.isoformat(),
        "transfer_deadline": capability.transfer_deadline.isoformat(),
    }


async def _locked_replication_capability(
    db: AsyncSession, capability_token: str
) -> Optional[StorageReplicationCapability]:
    if not capability_token or len(capability_token) > 512:
        return None
    return (
        await db.execute(
            select(StorageReplicationCapability)
            .where(
                StorageReplicationCapability.token_hash == _replication_token_hash(capability_token)
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _replication_capability_without_lock(
    db: AsyncSession, capability_token: str
) -> Optional[StorageReplicationCapability]:
    if not capability_token or len(capability_token) > 512:
        return None
    return (
        await db.execute(
            select(StorageReplicationCapability).where(
                StorageReplicationCapability.token_hash == _replication_token_hash(capability_token)
            )
        )
    ).scalar_one_or_none()


async def _lock_replication_transfer(
    db: AsyncSession, object_id: str, target_server_id: str
) -> None:
    """Serialize capability lifecycle operations for one immutable target placement."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": f"chutefs-replication:{object_id}:{target_server_id}"},
    )


async def _locked_replication_servers(
    db: AsyncSession, source_server_id: str, target_server_id: str
) -> Dict[str, Server]:
    """Lock both identity rows in stable order so opposite transfers cannot deadlock."""
    rows = list(
        (
            await db.execute(
                select(Server)
                .where(Server.server_id.in_([source_server_id, target_server_id]))
                .order_by(Server.server_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return {server.server_id: server for server in rows}


def _require_capability_target_identity(
    capability: StorageReplicationCapability, caller: Server
) -> None:
    caller_cert_hash = _server_pubkey_hash(caller)
    if (
        caller.server_id != capability.target_server_id
        or not caller.storage_incarnation
        or caller.storage_incarnation != capability.target_storage_incarnation
        or not caller_cert_hash
        or caller_cert_hash.lower() != capability.target_cert_pubkey_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Replication capability is not bound to this current target certificate "
                "and storage incarnation."
            ),
        )


def _capability_failure_caller_is_bound(
    capability: StorageReplicationCapability, caller: Server
) -> bool:
    caller_cert_hash = _server_pubkey_hash(caller)
    if not caller.storage_incarnation or not caller_cert_hash:
        return False
    return bool(
        (
            caller.server_id == capability.target_server_id
            and caller.storage_incarnation == capability.target_storage_incarnation
            and caller_cert_hash.lower() == capability.target_cert_pubkey_hash.lower()
        )
        or (
            caller.server_id == capability.source_server_id
            and caller.storage_incarnation == capability.source_storage_incarnation
            and caller_cert_hash.lower() == capability.source_cert_pubkey_hash.lower()
        )
    )


async def _record_replication_capability_failure(
    db: AsyncSession,
    capability: StorageReplicationCapability,
    error: str,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Persist one terminal capability error without overwriting a newer placement attempt."""
    if capability.completed_at is not None:
        return
    failed_at = now or datetime.now(timezone.utc)
    bounded_error = (error or "replication_failed")[:256]
    if capability.failed_at is None:
        capability.failed_at = failed_at
        capability.last_error = bounded_error
    else:
        bounded_error = capability.last_error or bounded_error
    placement = await db.get(ReplicaPlacement, capability.target_placement_id, with_for_update=True)
    if (
        placement is not None
        and placement.status == "pending"
        and placement.server_id == capability.target_server_id
        and int(placement.attempt_count or 0) == capability.target_placement_attempt
    ):
        placement.last_error = bounded_error
        if int(placement.attempt_count or 0) >= MAX_PLACEMENT_ATTEMPTS:
            placement.status = "evicted"


async def _completed_capability_receipt_is_current(
    db: AsyncSession,
    capability: StorageReplicationCapability,
) -> bool:
    """Whether exact bytes from a completed token still have an authoritative placement receipt."""
    obj = await db.get(StorageObject, capability.object_id, with_for_update=True)
    placement = await db.get(ReplicaPlacement, capability.target_placement_id, with_for_update=True)
    target = (
        await _locked_replication_servers(
            db, capability.target_server_id, capability.target_server_id
        )
    ).get(capability.target_server_id)
    if obj is None or placement is None or target is None:
        return False
    expected_status = "pending" if obj.lifecycle_state == OBJECT_PENDING else "present"
    if (
        obj.volume_id != capability.volume_id
        or obj.lifecycle_state not in (OBJECT_PENDING, OBJECT_COMMITTED)
        or placement.server_id != target.server_id
        or placement.status != expected_status
        or not _placement_identity_matches(placement, target)
        or target.storage_incarnation != capability.target_storage_incarnation
        or (_server_pubkey_hash(target) or "").lower() != capability.target_cert_pubkey_hash.lower()
        or (placement.proof_sha256 or "").lower() != capability.expected_ciphertext_sha256
        or placement.proof_size_bytes is None
        or int(placement.proof_size_bytes) != int(capability.expected_ciphertext_size_bytes)
        or placement.proof_at is None
        or placement.proof_mode
        not in ("direct_upload", "replication_capability", "legacy_adoption")
    ):
        return False
    return not (
        obj.lifecycle_state == OBJECT_COMMITTED
        and (
            (obj.sha256 or "").lower() != capability.expected_ciphertext_sha256
            or obj.ciphertext_size_bytes is None
            or int(obj.ciphertext_size_bytes) != int(capability.expected_ciphertext_size_bytes)
        )
    )


async def issue_replication_capability(
    db: AsyncSession,
    caller: Server,
    object_id: str,
    target_server_id: str,
    ciphertext_sha256: str,
    ciphertext_size_bytes: int,
) -> Dict:
    """Lease one exact transfer after proving the source's current local receipt."""
    ciphertext_sha256 = (ciphertext_sha256 or "").strip().lower()
    if caller.server_id == target_server_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication source and target must be different storage servers.",
        )

    await _lock_replication_transfer(db, object_id, target_server_id)
    now = datetime.now(timezone.utc)
    locked_servers = await _locked_replication_servers(db, caller.server_id, target_server_id)
    source = locked_servers.get(caller.server_id)
    target = locked_servers.get(target_server_id)
    obj = (
        await db.execute(
            select(StorageObject).where(StorageObject.object_id == object_id).with_for_update()
        )
    ).scalar_one_or_none()
    if source is None or target is None or obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Replication source, target, or object generation was not found.",
        )
    if (
        not source.storage_role
        or not target.storage_role
        or obj.lifecycle_state not in (OBJECT_PENDING, OBJECT_COMMITTED)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication source, target, and object generation are not active.",
        )
    if (
        not _server_pubkey_hash(source)
        or not source.storage_incarnation
        or not source.attested_cert
        or source.server_id != caller.server_id
        or _server_pubkey_hash(source).lower() != (_server_pubkey_hash(caller) or "").lower()
        or source.storage_incarnation != caller.storage_incarnation
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication source identity is stale or incomplete.",
        )

    placements = list(
        (
            await db.execute(
                select(ReplicaPlacement)
                .where(
                    ReplicaPlacement.object_id == object_id,
                    ReplicaPlacement.server_id.in_([source.server_id, target.server_id]),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    placement_by_server = {placement.server_id: placement for placement in placements}
    source_placement = placement_by_server.get(source.server_id)
    target_placement = placement_by_server.get(target.server_id)
    source_status = "pending" if obj.lifecycle_state == OBJECT_PENDING else "present"
    if (
        source_placement is None
        or source_placement.status != source_status
        or not _placement_identity_matches(source_placement, source)
        or (source_placement.proof_sha256 or "").lower() != ciphertext_sha256
        or source_placement.proof_size_bytes is None
        or int(source_placement.proof_size_bytes) != ciphertext_size_bytes
        or source_placement.proof_at is None
        or source_placement.proof_mode
        not in ("direct_upload", "replication_capability", "legacy_adoption")
        or (
            source_status == "pending"
            and (
                source_placement.pending_deadline is None
                or source_placement.proof_at > source_placement.pending_deadline
            )
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Source lacks a current exact-hash, exact-size possession receipt for "
                "this generation."
            ),
        )
    if obj.lifecycle_state == OBJECT_COMMITTED and (
        not obj.sha256
        or obj.sha256.lower() != ciphertext_sha256
        or obj.ciphertext_size_bytes is None
        or int(obj.ciphertext_size_bytes) != ciphertext_size_bytes
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Repair source metadata does not match the committed generation.",
        )
    if (
        target_placement is None
        or target_placement.status != "pending"
        or not _placement_identity_matches(target_placement, target)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target has no current pending placement lease for this generation.",
        )
    if target_placement.proof_at is not None:
        if (
            (target_placement.proof_sha256 or "").lower() == ciphertext_sha256
            and target_placement.proof_size_bytes is not None
            and int(target_placement.proof_size_bytes) == ciphertext_size_bytes
            and target_placement.pending_deadline is not None
            and target_placement.proof_at <= target_placement.pending_deadline
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Target already has an exact possession receipt for this generation.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target placement carries conflicting or stale possession evidence.",
        )

    live_ids = await _live_attested_server_ids(db)
    if source.server_id not in live_ids or target.server_id not in live_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication source or target is no longer live and freshly attested.",
        )
    if int(target_placement.attempt_count or 0) >= MAX_PLACEMENT_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target placement exhausted its bounded transfer attempts.",
        )

    active_capabilities = list(
        (
            await db.execute(
                select(StorageReplicationCapability)
                .where(
                    StorageReplicationCapability.target_placement_id
                    == target_placement.placement_id,
                    StorageReplicationCapability.completed_at.is_(None),
                    StorageReplicationCapability.failed_at.is_(None),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for active in active_capabilities:
        if active.consumed_at is not None and active.transfer_deadline > now:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Target placement already has a consumed transfer in progress.",
            )
        if active.consumed_at is None and active.expires_at > now:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Target placement already has an unconsumed capability in progress.",
            )
        active.failed_at = now
        active.last_error = (
            "transfer_lease_expired"
            if active.consumed_at is not None
            else "capability_expired_before_consumption"
        )

    target_placement.attempt_count = int(target_placement.attempt_count or 0) + 1
    transfer_deadline = now + timedelta(seconds=REPLICATION_TRANSFER_LEASE_SECONDS)
    target_placement.pending_deadline = transfer_deadline
    target_placement.last_attempt_at = now
    target_placement.last_error = None
    if source_status == "pending":
        # Initial-copy serial queues use the same JIT lease: current exact possession re-leases the
        # direct-upload source so an old pending deadline cannot expire halfway through fan-out.
        source_placement.pending_deadline = transfer_deadline

    capability_id = str(uuid4())
    capability_token = f"{capability_id}.{secrets.token_urlsafe(48)}"
    expires_at = now + timedelta(seconds=REPLICATION_CAPABILITY_TTL_SECONDS)
    capability = StorageReplicationCapability(
        capability_id=capability_id,
        token_hash=_replication_token_hash(capability_token),
        object_id=obj.object_id,
        volume_id=obj.volume_id,
        source_placement_id=source_placement.placement_id,
        source_server_id=source.server_id,
        source_cert_pubkey_hash=_server_pubkey_hash(source).lower(),
        source_storage_incarnation=source.storage_incarnation,
        target_placement_id=target_placement.placement_id,
        target_placement_attempt=target_placement.attempt_count,
        target_server_id=target.server_id,
        target_cert_pubkey_hash=_server_pubkey_hash(target).lower(),
        target_storage_incarnation=target.storage_incarnation,
        expected_ciphertext_sha256=ciphertext_sha256,
        expected_ciphertext_size_bytes=ciphertext_size_bytes,
        issued_at=now,
        expires_at=expires_at,
        transfer_deadline=transfer_deadline,
    )
    db.add(capability)
    await db.commit()
    return {
        "capability": capability_token,
        "capability_id": capability.capability_id,
        "expires_at": expires_at.isoformat(),
        "transfer_deadline": transfer_deadline.isoformat(),
        "target_placement_attempt": capability.target_placement_attempt,
    }


async def consume_replication_capability(
    db: AsyncSession,
    caller: Server,
    capability_token: str,
    source_signature: str,
) -> Dict:
    """Atomically consume a capability as its exact current target before any body is read."""
    discovered = await _replication_capability_without_lock(db, capability_token)
    if discovered is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    await _lock_replication_transfer(db, discovered.object_id, discovered.target_server_id)
    capability = await _locked_replication_capability(db, capability_token)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    _require_capability_target_identity(capability, caller)
    now = datetime.now(timezone.utc)
    if capability.completed_at is not None or capability.failed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability is already terminal.",
        )
    if capability.consumed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability has already been consumed.",
        )
    if capability.expires_at <= now or capability.transfer_deadline <= now:
        await _record_replication_capability_failure(db, capability, "capability_expired", now=now)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Replication capability expired before consumption.",
        )

    locked_servers = await _locked_replication_servers(
        db, capability.source_server_id, capability.target_server_id
    )
    source = locked_servers.get(capability.source_server_id)
    target = locked_servers.get(capability.target_server_id)
    obj = await db.get(StorageObject, capability.object_id, with_for_update=True)
    source_placement = await db.get(
        ReplicaPlacement, capability.source_placement_id, with_for_update=True
    )
    target_placement = await db.get(
        ReplicaPlacement, capability.target_placement_id, with_for_update=True
    )
    source_status = (
        "pending" if obj is not None and obj.lifecycle_state == OBJECT_PENDING else "present"
    )
    if (
        source is None
        or target is None
        or obj is None
        or obj.volume_id != capability.volume_id
        or obj.lifecycle_state not in (OBJECT_PENDING, OBJECT_COMMITTED)
        or source_placement is None
        or source_placement.status != source_status
        or source_placement.placement_id != capability.source_placement_id
        or not _placement_identity_matches(source_placement, source)
        or source.storage_incarnation != capability.source_storage_incarnation
        or (_server_pubkey_hash(source) or "").lower() != capability.source_cert_pubkey_hash.lower()
        or (source_placement.proof_sha256 or "").lower() != capability.expected_ciphertext_sha256
        or source_placement.proof_size_bytes is None
        or int(source_placement.proof_size_bytes) != int(capability.expected_ciphertext_size_bytes)
        or source_placement.proof_at is None
        or source_placement.proof_mode
        not in ("direct_upload", "replication_capability", "legacy_adoption")
        or (
            source_status == "pending"
            and (
                source_placement.pending_deadline is None
                or source_placement.proof_at > source_placement.pending_deadline
            )
        )
        or target_placement is None
        or target_placement.status != "pending"
        or target_placement.placement_id != capability.target_placement_id
        or int(target_placement.attempt_count or 0) != capability.target_placement_attempt
        or not _placement_identity_matches(target_placement, target)
        or target_placement.pending_deadline is None
        or target_placement.pending_deadline <= now
    ):
        await _record_replication_capability_failure(
            db, capability, "capability_binding_stale", now=now
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability binding is stale.",
        )
    if obj.lifecycle_state == OBJECT_COMMITTED and (
        (obj.sha256 or "").lower() != capability.expected_ciphertext_sha256
        or obj.ciphertext_size_bytes is None
        or int(obj.ciphertext_size_bytes) != int(capability.expected_ciphertext_size_bytes)
    ):
        await _record_replication_capability_failure(
            db, capability, "committed_metadata_changed", now=now
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability no longer matches committed metadata.",
        )
    if not _verify_replication_source_signature(source, capability_token, source_signature):
        await _record_replication_capability_failure(
            db,
            capability,
            "source_attested_key_signature_invalid",
            now=now,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication source did not prove its bound attested certificate key.",
        )

    live_ids = await _live_attested_server_ids(db)
    if source.server_id not in live_ids or target.server_id not in live_ids:
        await _record_replication_capability_failure(
            db, capability, "source_or_target_not_live", now=now
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication source or target is no longer live and freshly attested.",
        )

    capability.consumed_at = now
    await db.commit()
    return _capability_binding(capability)


async def complete_replication_capability(
    db: AsyncSession,
    caller: Server,
    capability_token: str,
    ciphertext_sha256: str,
    ciphertext_size_bytes: int,
) -> Dict:
    """Accept exact target possession only for a consumed capability and current lease."""
    discovered = await _replication_capability_without_lock(db, capability_token)
    if discovered is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    await _lock_replication_transfer(db, discovered.object_id, discovered.target_server_id)
    capability = await _locked_replication_capability(db, capability_token)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    _require_capability_target_identity(capability, caller)
    if (
        capability.completed_at is not None
        and capability.expected_ciphertext_sha256 == ciphertext_sha256
        and int(capability.expected_ciphertext_size_bytes) == ciphertext_size_bytes
    ):
        if await _completed_capability_receipt_is_current(db, capability):
            await db.commit()
            return {"recorded": True, "capability_id": capability.capability_id}
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Completed replication receipt is no longer authoritative.",
        )
    if (
        capability.failed_at is not None
        and capability.consumed_at is not None
        and capability.expected_ciphertext_sha256 == ciphertext_sha256
        and int(capability.expected_ciphertext_size_bytes) == ciphertext_size_bytes
        and await _completed_capability_receipt_is_current(db, capability)
    ):
        # A timed-out transfer may leave a crash journal while a newer attempt subsequently records
        # the same immutable bytes. The old journal is then safe to retire, but it cannot create or
        # alter the newer receipt.
        await db.commit()
        return {"recorded": True, "capability_id": capability.capability_id}
    if capability.failed_at is not None or capability.consumed_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability was not consumed or is already failed.",
        )

    now = datetime.now(timezone.utc)
    locked_servers = await _locked_replication_servers(
        db, capability.source_server_id, capability.target_server_id
    )
    source = locked_servers.get(capability.source_server_id)
    target = locked_servers.get(capability.target_server_id)
    obj = await db.get(StorageObject, capability.object_id, with_for_update=True)
    placement = await db.get(ReplicaPlacement, capability.target_placement_id, with_for_update=True)
    if ciphertext_sha256 != capability.expected_ciphertext_sha256 or ciphertext_size_bytes != int(
        capability.expected_ciphertext_size_bytes
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target receipt does not match the capability's exact ciphertext.",
        )
    if (
        source is None
        or target is None
        or placement is None
        or obj is None
        or obj.volume_id != capability.volume_id
        or obj.lifecycle_state not in (OBJECT_PENDING, OBJECT_COMMITTED)
        or source.storage_incarnation != capability.source_storage_incarnation
        or (_server_pubkey_hash(source) or "").lower() != capability.source_cert_pubkey_hash.lower()
        or target.storage_incarnation != capability.target_storage_incarnation
        or (_server_pubkey_hash(target) or "").lower() != capability.target_cert_pubkey_hash.lower()
        or placement.status != "pending"
        or placement.server_id != target.server_id
        or int(placement.attempt_count or 0) != capability.target_placement_attempt
        or not _placement_identity_matches(placement, target)
        or placement.pending_deadline is None
        or placement.pending_deadline <= now
        or capability.transfer_deadline <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replication capability or placement became stale before receipt.",
        )
    if obj.lifecycle_state == OBJECT_COMMITTED and (
        (obj.sha256 or "").lower() != ciphertext_sha256
        or obj.ciphertext_size_bytes is None
        or int(obj.ciphertext_size_bytes) != ciphertext_size_bytes
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target receipt does not match committed object metadata.",
        )

    capability.completed_at = now
    await db.flush()
    placement.proof_sha256 = ciphertext_sha256
    placement.proof_size_bytes = ciphertext_size_bytes
    placement.proof_capability_id = capability.capability_id
    placement.proof_mode = "replication_capability"
    placement.proof_at = now
    placement.last_error = None
    if obj.lifecycle_state == OBJECT_COMMITTED:
        placement.status = "present"
        placement.confirmed_at = now
    if obj.lifecycle_state == OBJECT_COMMITTED:
        await _refresh_object_durability(db, obj)
    await db.commit()
    return {"recorded": True, "capability_id": capability.capability_id}


async def fail_replication_capability(
    db: AsyncSession,
    caller: Server,
    capability_token: str,
    error: str,
) -> Dict:
    """Record one bound source/target transfer failure and preserve bounded retry accounting."""
    discovered = await _replication_capability_without_lock(db, capability_token)
    if discovered is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    await _lock_replication_transfer(db, discovered.object_id, discovered.target_server_id)
    capability = await _locked_replication_capability(db, capability_token)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Replication capability is invalid.",
        )
    current_caller = (
        await _locked_replication_servers(db, caller.server_id, caller.server_id)
    ).get(caller.server_id)
    if current_caller is None or not _capability_failure_caller_is_bound(
        capability, current_caller
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Replication failure reporter is not the capability's current bound "
                "source or target identity."
            ),
        )
    if capability.completed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Completed replication capability cannot be failed.",
        )
    bounded_error = (error or "replication_failed")[:256]
    await _record_replication_capability_failure(db, capability, bounded_error)
    effective_error = capability.last_error or bounded_error
    placement = await db.get(ReplicaPlacement, capability.target_placement_id, with_for_update=True)
    if (
        placement is not None
        and placement.status == "pending"
        and placement.server_id == capability.target_server_id
        and int(placement.attempt_count or 0) == capability.target_placement_attempt
        and effective_error.startswith("insufficient_storage")
    ):
        placement.status = "evicted"
    await db.commit()
    return {"recorded": True, "capability_id": capability.capability_id}


async def object_replica_peers(db: AsyncSession, object_id: str) -> List[StoragePeer]:
    """The storage peers the validator ASSIGNED for an object (pending or present).

    The primary storage TD replicates to THIS set instead of a client-supplied ``X-ChuteFS-Peers``
    header, so a user cannot pin replicas onto storage nodes of its choosing or collapse them onto
    correlated hosts (M2) -- the tracker's distinct-host placement stays authoritative.
    """
    active_generation = (
        await db.execute(
            select(StorageObject.object_id).where(
                StorageObject.object_id == object_id,
                StorageObject.lifecycle_state.in_((OBJECT_PENDING, OBJECT_COMMITTED)),
            )
        )
    ).scalar_one_or_none()
    if active_generation is None:
        return []
    placements = list(
        (
            await db.execute(
                select(ReplicaPlacement).where(
                    ReplicaPlacement.object_id == object_id,
                    ReplicaPlacement.status.in_(("present", "pending")),
                )
            )
        )
        .scalars()
        .all()
    )
    servers = await _storage_servers_by_id(db, [placement.server_id for placement in placements])
    server_by_id = {server.server_id: server for server in servers}
    valid_servers = []
    used_hosts: Set[str] = set()
    for placement in placements:
        server = server_by_id.get(placement.server_id)
        if server is None or not _placement_identity_matches(placement, server):
            continue
        host = server.host_id or server.server_id
        if host in used_hosts:
            continue
        used_hosts.add(host)
        valid_servers.append(server)
    return await _attested_live_peers(db, valid_servers)


async def replica_authorization(
    db: AsyncSession,
    object_id: str,
    caller: Server,
) -> Dict:
    """Authorize an incoming write only for this exact attested target/disk assignment."""
    obj = (
        await db.execute(
            select(StorageObject).where(
                StorageObject.object_id == object_id,
                StorageObject.lifecycle_state.in_((OBJECT_PENDING, OBJECT_COMMITTED)),
            )
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    placement = (
        await db.execute(
            select(ReplicaPlacement).where(
                ReplicaPlacement.object_id == object_id,
                ReplicaPlacement.server_id == caller.server_id,
                ReplicaPlacement.status == "pending",
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        placement is None
        or not _placement_identity_matches(placement, caller)
        or (
            placement.status == "pending"
            and (placement.pending_deadline is None or placement.pending_deadline <= now)
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The calling storage incarnation has no active assignment for this object.",
        )
    return {
        "object_id": obj.object_id,
        "volume_id": obj.volume_id,
        "placement_status": placement.status,
        "lifecycle_state": obj.lifecycle_state,
        "storage_incarnation": placement.storage_incarnation,
        "projected_size_bytes": max(int(obj.projected_size_bytes or 0), int(obj.size_bytes or 0)),
        "salt": obj.salt,
        "ciphertext_sha256": obj.sha256.lower() if obj.sha256 else None,
        "pending_deadline": (
            placement.pending_deadline.isoformat()
            if placement.pending_deadline is not None
            else None
        ),
    }


async def locate_object(
    db: AsyncSession, volume: StorageVolume, key: str
) -> tuple[StorageObject, List[StoragePeer], int]:
    obj = (
        await db.execute(
            select(StorageObject).where(
                StorageObject.volume_id == volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.lifecycle_state == OBJECT_COMMITTED,
            )
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.")
    placements = list(
        (
            await db.execute(
                select(ReplicaPlacement).where(
                    ReplicaPlacement.object_id == obj.object_id,
                    ReplicaPlacement.status == "present",
                )
            )
        )
        .scalars()
        .all()
    )
    servers = await _storage_servers_by_id(db, [placement.server_id for placement in placements])
    live_ids = await _live_attested_server_ids(db)
    durable = await _current_durable_placements(
        db,
        obj,
        live_ids=live_ids,
        placements=placements,
        servers=servers,
    )
    server_by_id = {server.server_id: server for server in servers}
    peers = [
        peer
        for peer in (
            _to_peer(server_by_id[placement.server_id], include_cert=True) for placement in durable
        )
        if peer is not None
    ]
    obj.durable_replica_count = len(durable)
    obj.durability_state = _durability_state(
        len(durable), volume.replication_factor, committed=True
    )
    obj.durability_updated_at = func.now()
    return obj, peers, len(durable)


async def list_objects(
    db: AsyncSession,
    volume: StorageVolume,
    prefix: Optional[str],
    limit: int,
    after: Optional[str] = None,
) -> List[StorageObject]:
    query = select(StorageObject).where(
        StorageObject.volume_id == volume.volume_id,
        StorageObject.lifecycle_state == OBJECT_COMMITTED,
    )
    if prefix:
        query = query.where(StorageObject.object_key.startswith(prefix, autoescape=True))
    # L4: keyset cursor -- return keys strictly AFTER the caller's last-seen key so a volume with more
    # than `limit` objects can be fully enumerated (page by passing the previous page's last key).
    if after:
        query = query.where(StorageObject.object_key > after)
    query = query.order_by(StorageObject.object_key).limit(limit)
    return list((await db.execute(query)).scalars().all())


async def _retire_object_delete_fence_batch(
    db: AsyncSession,
    fence: StorageObjectDeleteFence,
    *,
    limit: int,
) -> tuple[List[StorageObject], bool]:
    """Retire one key's pre-cutoff generations in a bounded, serialized keyset page."""
    if fence.completed_at is not None or limit <= 0:
        return [], fence.completed_at is not None
    query = select(StorageObject).where(
        StorageObject.volume_id == fence.volume_id,
        StorageObject.object_key == fence.object_key,
        StorageObject.created_at <= fence.cutoff_at,
    )
    if fence.scan_cursor is not None:
        query = query.where(StorageObject.object_id > fence.scan_cursor)
    generations = list(
        (await db.execute(query.order_by(StorageObject.object_id).limit(limit).with_for_update()))
        .scalars()
        .all()
    )
    now = datetime.now(timezone.utc)
    for generation in generations:
        fence.scan_cursor = generation.object_id
        if generation.lifecycle_state != OBJECT_TOMBSTONED:
            generation.lifecycle_state = OBJECT_TOMBSTONED
            generation.tombstoned_at = now
    if generations:
        await db.flush()
        await _enqueue_erase_tasks_for_generations(
            db,
            generations,
            reason="object_deleted",
            now=now,
        )
    if len(generations) < limit:
        fence.completed_at = now
    return generations, fence.completed_at is not None


async def delete_object(
    db: AsyncSession, volume: StorageVolume, key: str
) -> tuple[Optional[StorageObject], int, int]:
    """Fence a key deletion, retire the current generation, then advance one bounded history page."""
    await _lock_storage_user(db, volume.user_id)
    locked_volume = (
        await db.execute(
            select(StorageVolume)
            .where(
                StorageVolume.volume_id == volume.volume_id,
                StorageVolume.deleted.is_(False),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if locked_volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found.")
    now = datetime.now(timezone.utc)
    fence = (
        await db.execute(
            select(StorageObjectDeleteFence)
            .where(
                StorageObjectDeleteFence.volume_id == locked_volume.volume_id,
                StorageObjectDeleteFence.object_key == key,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if fence is None:
        fence = StorageObjectDeleteFence(
            volume_id=locked_volume.volume_id,
            object_key=key,
            cutoff_at=now,
        )
        db.add(fence)
        await db.flush()
    else:
        fence.cutoff_at = now
        fence.scan_cursor = None
        fence.completed_at = None

    current = (
        await db.execute(
            select(StorageObject)
            .where(
                StorageObject.volume_id == locked_volume.volume_id,
                StorageObject.object_key == key,
                StorageObject.lifecycle_state == OBJECT_COMMITTED,
                StorageObject.created_at <= fence.cutoff_at,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    immediate = []
    if current is not None:
        current.lifecycle_state = OBJECT_TOMBSTONED
        current.tombstoned_at = now
        immediate.append(current)
        await db.flush()
        await _enqueue_erase_tasks_for_generations(
            db,
            immediate,
            reason="object_deleted",
            now=now,
        )
        locked_volume.used_bytes = max(0, int(locked_volume.used_bytes) - int(current.size_bytes))

    page_limit = max(
        1,
        settings.storage_reconcile_batch_size - (1 if current is not None else 0),
    )
    page, _complete = await _retire_object_delete_fence_batch(db, fence, limit=page_limit)
    generation_ids = list(
        dict.fromkeys(
            [generation.object_id for generation in immediate]
            + [generation.object_id for generation in page]
        )
    )
    pending_tasks = (
        await db.execute(
            select(func.count())
            .select_from(StorageEraseTask)
            .where(
                StorageEraseTask.object_id.in_(generation_ids or [""]),
                StorageEraseTask.state.not_in(ERASE_TERMINAL_STATES),
            )
        )
    ).scalar_one()
    await db.commit()
    await db.refresh(volume)
    representative = current or (page[0] if page else None)
    return representative, int(volume.used_bytes), int(pending_tasks)


async def legacy_adoption_metadata(
    db: AsyncSession,
    caller: Server,
    object_id: str,
) -> Dict:
    """Return tracker salt/hash only for this current TD's quarantined legacy assignment."""
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == caller.server_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    caller_hash = _server_pubkey_hash(caller)
    server_hash = _server_pubkey_hash(server) if server is not None else None
    if (
        server is None
        or not server.storage_role
        or not server.storage_incarnation
        or not caller_hash
        or not server_hash
        or caller_hash.lower() != server_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Legacy metadata requires this current attested storage identity.",
        )
    row = (
        await db.execute(
            select(StorageObject, ReplicaPlacement)
            .join(
                ReplicaPlacement,
                ReplicaPlacement.object_id == StorageObject.object_id,
            )
            .where(
                StorageObject.object_id == object_id,
                StorageObject.lifecycle_state == OBJECT_COMMITTED,
                StorageObject.ciphertext_size_bytes.is_(None),
                StorageObject.legacy_adopted_at.is_(None),
                StorageObject.sha256.is_not(None),
                ReplicaPlacement.server_id == server.server_id,
                ReplicaPlacement.status == "evicted",
                ReplicaPlacement.proof_at.is_(None),
            )
        )
    ).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No eligible quarantined legacy assignment exists for this object.",
        )
    obj, _placement = row
    return {
        "object_id": obj.object_id,
        "volume_id": obj.volume_id,
        "ciphertext_sha256": obj.sha256.lower(),
        "salt": obj.salt,
    }


def _legacy_adoption_replay_matches(
    obj: StorageObject,
    placement: ReplicaPlacement,
    *,
    server: Server,
    server_cert_hash: str,
    storage_incarnation: str,
    proof_sha256: str,
    proof_size_bytes: object,
    plaintext_size_bytes: object,
    plaintext_sha256: str,
) -> bool:
    """Recognize an exact replay after the original adoption transaction committed."""
    return bool(
        obj.lifecycle_state == OBJECT_COMMITTED
        and obj.legacy_adopted_at is not None
        and obj.legacy_adoption_placement_id == placement.placement_id
        and obj.legacy_adoption_server_id == server.server_id
        and obj.legacy_adoption_cert_pubkey_hash == server_cert_hash
        and obj.legacy_adoption_storage_incarnation == storage_incarnation
        and (obj.sha256 or "").lower() == proof_sha256
        and obj.ciphertext_size_bytes == proof_size_bytes
        and obj.size_bytes == plaintext_size_bytes
        and obj.projected_size_bytes == plaintext_size_bytes
        and (obj.plaintext_sha256 or "").lower() == plaintext_sha256
        and placement.status == "present"
        and placement.storage_incarnation == storage_incarnation
        and (placement.target_cert_pubkey_hash or "").lower() == server_cert_hash
        and (placement.proof_sha256 or "").lower() == proof_sha256
        and placement.proof_size_bytes == proof_size_bytes
        and placement.proof_plaintext_size_bytes == plaintext_size_bytes
        and (placement.proof_plaintext_sha256 or "").lower() == plaintext_sha256
        and placement.proof_mode == "legacy_adoption"
        and placement.proof_at == obj.legacy_adopted_at
    )


def _record_legacy_quarantine(
    placement: ReplicaPlacement,
    *,
    storage_incarnation: str,
    server_cert_hash: str,
    detail: str,
) -> bool:
    """Durably bind a terminal local-quarantine report to this holder identity."""
    error = f"legacy_adoption_quarantined:{detail}"[:256]
    idempotent = bool(
        placement.status == "evicted"
        and placement.storage_incarnation == storage_incarnation
        and (placement.target_cert_pubkey_hash or "").lower() == server_cert_hash
        and placement.last_error == error
    )
    if placement.status == "evicted":
        placement.storage_incarnation = storage_incarnation
        placement.target_cert_pubkey_hash = server_cert_hash
        placement.last_attempt_at = datetime.now(timezone.utc)
        placement.last_error = error
    return idempotent


async def adopt_legacy_replicas(
    db: AsyncSession,
    caller: Server,
    storage_incarnation: str,
    submissions: List[Dict],
) -> List[Dict]:
    """Adopt one intact pre-upgrade committed ciphertext through a current attested assignment.

    Exactly one assigned storage TD may anchor the previously unknown ciphertext size. The adopted
    placement becomes the normal capability source; every later copy uses secure replication.
    """
    storage_incarnation = _normalize_incarnation(storage_incarnation)
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == caller.server_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    caller_cert_hash = _server_pubkey_hash(caller)
    server_cert_hash = _server_pubkey_hash(server) if server is not None else None
    if (
        server is None
        or not server.storage_role
        or not await is_freshly_attested_storage_server(db, server)
        or not settings.require_mtls_client_verify
        or not server.storage_incarnation
        or server.storage_incarnation != storage_incarnation
        or not server_cert_hash
        or not caller_cert_hash
        or server_cert_hash.lower() != caller_cert_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Legacy adoption requires this storage TD's current attested mTLS "
                "certificate and mounted-volume incarnation."
            ),
        )

    await mark_storage_online(server.server_id)
    outcomes: List[Dict] = []
    for submission in submissions:
        object_id = submission["object_id"]
        result = submission.get("result")
        proof_sha256 = (submission.get("ciphertext_sha256") or "").strip().lower()
        proof_size_bytes = submission.get("ciphertext_size_bytes")
        plaintext_size_bytes = submission.get("plaintext_size_bytes")
        plaintext_sha256 = (submission.get("plaintext_sha256") or "").strip().lower()
        outcome_start = len(outcomes)
        try:
            async with db.begin_nested():
                preliminary = await db.get(StorageObject, object_id)
                if preliminary is None:
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "detail": "object_not_tracked",
                        }
                    )
                    continue
                volume = await db.get(StorageVolume, preliminary.volume_id)
                if volume is None or volume.deleted:
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "detail": "volume_not_active",
                        }
                    )
                    continue
                await _lock_storage_user(db, volume.user_id)
                locked_volume = (
                    await db.execute(
                        select(StorageVolume)
                        .where(
                            StorageVolume.volume_id == preliminary.volume_id,
                            StorageVolume.deleted.is_(False),
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if locked_volume is None:
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "detail": "volume_not_active",
                        }
                    )
                    continue
                obj = (
                    await db.execute(
                        select(StorageObject)
                        .where(StorageObject.object_id == object_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                placement = (
                    await db.execute(
                        select(ReplicaPlacement)
                        .where(
                            ReplicaPlacement.object_id == object_id,
                            ReplicaPlacement.server_id == server.server_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if obj is None or placement is None:
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "detail": "assignment_not_tracked",
                        }
                    )
                    continue
                if result == "verified" and _legacy_adoption_replay_matches(
                    obj,
                    placement,
                    server=server,
                    server_cert_hash=server_cert_hash.lower(),
                    storage_incarnation=storage_incarnation,
                    proof_sha256=proof_sha256,
                    proof_size_bytes=proof_size_bytes,
                    plaintext_size_bytes=plaintext_size_bytes,
                    plaintext_sha256=plaintext_sha256,
                ):
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "accepted",
                            "idempotent": True,
                        }
                    )
                    continue
                if (
                    obj.lifecycle_state != OBJECT_COMMITTED
                    or obj.ciphertext_size_bytes is not None
                    or obj.legacy_adopted_at is not None
                ):
                    idempotent = _record_legacy_quarantine(
                        placement,
                        storage_incarnation=storage_incarnation,
                        server_cert_hash=server_cert_hash.lower(),
                        detail="object_no_longer_eligible",
                    )
                    await db.flush()
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "idempotent": idempotent,
                            "detail": "object_no_longer_eligible",
                        }
                    )
                    continue
                if result == "corrupt":
                    detail = (submission.get("error") or "corrupt_ciphertext")[:128]
                    idempotent = _record_legacy_quarantine(
                        placement,
                        storage_incarnation=storage_incarnation,
                        server_cert_hash=server_cert_hash.lower(),
                        detail=detail,
                    )
                    await db.flush()
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "idempotent": idempotent,
                            "detail": detail,
                        }
                    )
                    continue
                if (
                    result != "verified"
                    or not obj.sha256
                    or obj.sha256.lower() != proof_sha256
                    or not isinstance(proof_size_bytes, int)
                    or isinstance(proof_size_bytes, bool)
                    or proof_size_bytes < 0
                    or proof_size_bytes > 9_223_372_036_854_775_807
                    or not isinstance(plaintext_size_bytes, int)
                    or isinstance(plaintext_size_bytes, bool)
                    or plaintext_size_bytes < 0
                    or plaintext_size_bytes > 9_223_372_036_854_775_807
                    or len(plaintext_sha256) != 64
                    or any(character not in "0123456789abcdef" for character in plaintext_sha256)
                ):
                    idempotent = _record_legacy_quarantine(
                        placement,
                        storage_incarnation=storage_incarnation,
                        server_cert_hash=server_cert_hash.lower(),
                        detail="evidence_mismatch",
                    )
                    await db.flush()
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "quarantined",
                            "idempotent": idempotent,
                            "detail": "evidence_mismatch",
                        }
                    )
                    continue
                if placement.status != "evicted":
                    outcomes.append(
                        {
                            "object_id": object_id,
                            "status": "retry",
                            "detail": "assignment_not_quarantined",
                        }
                    )
                    continue

                now = datetime.now(timezone.utc)
                placement.status = "pending"
                placement.storage_incarnation = storage_incarnation
                placement.target_cert_pubkey_hash = server_cert_hash.lower()
                placement.proof_sha256 = None
                placement.proof_size_bytes = None
                placement.proof_plaintext_size_bytes = None
                placement.proof_plaintext_sha256 = None
                placement.proof_capability_id = None
                placement.proof_mode = None
                placement.proof_at = None
                placement.legacy_adoption_started_at = now
                placement.confirmed_at = None
                placement.pending_since = now
                placement.pending_deadline = now + timedelta(seconds=PENDING_PLACEMENT_TTL_SECONDS)
                placement.attempt_count = int(placement.attempt_count or 0) + 1
                placement.last_attempt_at = now
                placement.last_error = None
                # Keep the strict evicted -> pending edge observable before installing proof.
                await db.flush()

                placement.proof_sha256 = proof_sha256
                placement.proof_size_bytes = proof_size_bytes
                placement.proof_plaintext_size_bytes = plaintext_size_bytes
                placement.proof_plaintext_sha256 = plaintext_sha256
                placement.proof_capability_id = None
                placement.proof_mode = "legacy_adoption"
                placement.proof_at = now
                await db.flush()

                historical_size = int(obj.size_bytes)
                obj.size_bytes = plaintext_size_bytes
                obj.projected_size_bytes = plaintext_size_bytes
                obj.plaintext_sha256 = plaintext_sha256
                obj.ciphertext_size_bytes = proof_size_bytes
                obj.legacy_adopted_at = now
                obj.legacy_adoption_placement_id = placement.placement_id
                obj.legacy_adoption_server_id = server.server_id
                obj.legacy_adoption_cert_pubkey_hash = server_cert_hash.lower()
                obj.legacy_adoption_storage_incarnation = storage_incarnation
                locked_volume.used_bytes = max(
                    0,
                    int(locked_volume.used_bytes) - historical_size + plaintext_size_bytes,
                )
                await db.flush()

                placement.status = "present"
                placement.confirmed_at = now
                await db.flush()
                await _refresh_object_durability(db, obj)
                outcomes.append(
                    {
                        "object_id": object_id,
                        "status": "accepted",
                        "idempotent": False,
                    }
                )
        except Exception as exc:  # noqa: BLE001 - isolate each legacy inventory record
            del outcomes[outcome_start:]
            logger.warning(
                f"Legacy replica adoption failed for {object_id}/{server.server_id}: {exc}"
            )
            outcomes.append(
                {
                    "object_id": object_id,
                    "status": "retry",
                    "detail": f"transaction_failed:{type(exc).__name__}",
                }
            )
    await db.commit()
    return outcomes


def _committed_direct_receipt_replay_matches(
    obj: StorageObject,
    placement: ReplicaPlacement,
    server: Server,
    *,
    server_is_fresh: bool,
    proof_sha256: str,
    proof_size_bytes: object,
    plaintext_size_bytes: object,
    plaintext_sha256: str,
) -> bool:
    """Accept only an exact replay of the immutable direct proof recorded before commit."""
    return bool(
        server_is_fresh
        and obj.lifecycle_state == OBJECT_COMMITTED
        and obj.committed_at is not None
        and obj.sha256
        and obj.sha256.lower() == proof_sha256
        and obj.ciphertext_size_bytes is not None
        and isinstance(proof_size_bytes, int)
        and not isinstance(proof_size_bytes, bool)
        and int(obj.ciphertext_size_bytes) == proof_size_bytes
        and isinstance(plaintext_size_bytes, int)
        and not isinstance(plaintext_size_bytes, bool)
        and int(obj.size_bytes) == plaintext_size_bytes
        and int(obj.projected_size_bytes) == plaintext_size_bytes
        and obj.plaintext_sha256
        and obj.plaintext_sha256.lower() == plaintext_sha256
        and placement.object_id == obj.object_id
        and placement.server_id == server.server_id
        and placement.status == "present"
        and placement.confirmed_at is not None
        and _placement_identity_matches(placement, server)
        and placement.proof_mode == "direct_upload"
        and placement.proof_capability_id is None
        and placement.proof_at is not None
        and placement.proof_at <= obj.committed_at
        and placement.pending_deadline is not None
        and placement.proof_at <= placement.pending_deadline
        and (placement.proof_sha256 or "").lower() == proof_sha256
        and placement.proof_size_bytes is not None
        and int(placement.proof_size_bytes) == proof_size_bytes
        and placement.proof_plaintext_size_bytes == plaintext_size_bytes
        and (placement.proof_plaintext_sha256 or "").lower() == plaintext_sha256
    )


async def announce_replicas(
    db: AsyncSession,
    miner_hotkey: str,
    server_id: str,
    caller_server_id: str,
    storage_incarnation: str,
    placements: List[Dict],
) -> int:
    """Accept target-TD possession receipts; a miner signature alone cannot promote a row."""
    server = await _get_storage_server(
        db,
        server_id,
        miner_hotkey,
        caller_server_id=caller_server_id,
        lock=True,
    )
    await _bind_storage_identity(db, server, storage_incarnation)
    server_is_fresh = await is_freshly_attested_storage_server(db, server)
    recorded = 0
    for p in placements:
        object_id = p["object_id"]
        new_status = p.get("status") or "stored"
        try:
            async with db.begin_nested():
                obj = (
                    await db.execute(
                        select(StorageObject)
                        .where(
                            StorageObject.object_id == object_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                existing = (
                    await db.execute(
                        select(ReplicaPlacement)
                        .where(
                            ReplicaPlacement.object_id == object_id,
                            ReplicaPlacement.server_id == server_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if obj is None or existing is None:
                    logger.warning(
                        f"Ignoring unassigned replica announce for object {object_id} "
                        f"from {server_id} (status={new_status})."
                    )
                    continue

                if obj.lifecycle_state in (OBJECT_SUPERSEDED, OBJECT_TOMBSTONED):
                    if existing.status in ("pending", "present"):
                        existing.status = "evicted"
                    existing.last_error = "receipt_for_retired_generation"
                    await db.flush()
                    recorded += 1
                    continue

                if new_status == "evicted":
                    if existing.status in ("pending", "present"):
                        existing.status = "evicted"
                    existing.last_error = p.get("error") or "target_reported_eviction"
                    if obj.lifecycle_state == OBJECT_COMMITTED:
                        await _refresh_object_durability(db, obj)
                    await db.flush()
                    recorded += 1
                    continue

                identity_matches = _placement_identity_matches(existing, server)
                proof_sha256 = (p.get("ciphertext_sha256") or "").strip().lower()
                proof_size_bytes = p.get("ciphertext_size_bytes")
                plaintext_size_bytes = p.get("plaintext_size_bytes")
                plaintext_sha256 = (p.get("plaintext_sha256") or "").strip().lower()
                if obj.lifecycle_state == OBJECT_COMMITTED:
                    # A crash can leave the direct-upload journal after commit. Accept only the
                    # exact immutable proof already recorded by this same current attested target;
                    # capability-free input can never create, alter, or resurrect a placement.
                    if new_status == "stored" and _committed_direct_receipt_replay_matches(
                        obj,
                        existing,
                        server,
                        server_is_fresh=server_is_fresh,
                        proof_sha256=proof_sha256,
                        proof_size_bytes=proof_size_bytes,
                        plaintext_size_bytes=plaintext_size_bytes,
                        plaintext_sha256=plaintext_sha256,
                    ):
                        recorded += 1
                        continue
                    existing.last_error = (
                        "committed_direct_receipt_replay_mismatch"
                        if existing.status == "present" and existing.proof_mode == "direct_upload"
                        else "capability_required_for_committed_replica_receipt"
                    )
                    await db.flush()
                    logger.warning(
                        f"Ignoring capability-free committed receipt for {object_id}/{server_id}."
                    )
                    continue
                if not identity_matches and existing.status in ("pending", "present"):
                    existing.status = "evicted"
                    existing.last_error = "receipt_storage_identity_mismatch"
                    await db.flush()
                if existing.status != "pending":
                    existing.last_error = "receipt_requires_current_pending_assignment"
                    await db.flush()
                    logger.warning(
                        f"Ignoring uncommitted non-pending receipt for {object_id}/{server_id}."
                    )
                    continue

                if len(proof_sha256) != 64 or any(
                    char not in "0123456789abcdef" for char in proof_sha256
                ):
                    existing.last_error = "invalid_possession_hash"
                    await db.flush()
                    continue
                if (
                    not isinstance(proof_size_bytes, int)
                    or isinstance(proof_size_bytes, bool)
                    or proof_size_bytes < 0
                ):
                    existing.last_error = "invalid_possession_size"
                    await db.flush()
                    continue
                if (
                    not isinstance(plaintext_size_bytes, int)
                    or isinstance(plaintext_size_bytes, bool)
                    or plaintext_size_bytes < 0
                    or plaintext_size_bytes > settings.storage_max_object_bytes
                    or len(plaintext_sha256) != 64
                    or any(char not in "0123456789abcdef" for char in plaintext_sha256)
                ):
                    existing.last_error = "invalid_plaintext_receipt"
                    await db.flush()
                    continue
                if plaintext_size_bytes != int(obj.projected_size_bytes):
                    existing.last_error = "plaintext_receipt_reservation_mismatch"
                    await db.flush()
                    continue

                if existing.proof_at is not None:
                    if (
                        (existing.proof_sha256 or "").lower() == proof_sha256
                        and existing.proof_size_bytes is not None
                        and int(existing.proof_size_bytes) == proof_size_bytes
                        and existing.proof_mode == "direct_upload"
                        and existing.proof_plaintext_size_bytes == plaintext_size_bytes
                        and existing.proof_plaintext_sha256 == plaintext_sha256
                        and existing.pending_deadline is not None
                        and existing.proof_at <= existing.pending_deadline
                    ):
                        recorded += 1
                    else:
                        existing.last_error = "conflicting_possession_receipt"
                        await db.flush()
                    continue

                pending_expired = (
                    existing.pending_deadline is None
                    or existing.pending_deadline <= datetime.now(timezone.utc)
                )
                if pending_expired:
                    existing.status = "evicted"
                    existing.last_error = "possession_receipt_after_deadline"
                    await db.flush()
                    logger.warning(
                        f"Ignoring uncommitted expired receipt for {object_id}/{server_id}."
                    )
                    continue
                if not identity_matches:
                    logger.warning(
                        f"Ignoring uncommitted stale-identity receipt for {object_id}/{server_id}."
                    )
                    continue

                existing.proof_sha256 = proof_sha256
                existing.proof_size_bytes = proof_size_bytes
                existing.proof_plaintext_size_bytes = plaintext_size_bytes
                existing.proof_plaintext_sha256 = plaintext_sha256
                existing.proof_capability_id = None
                existing.proof_mode = "direct_upload"
                existing.proof_at = func.now()
                existing.last_error = None
                # Before commit, retain the receipt on pending. commit_object performs the only
                # pending-generation + pending-placement publication transition.
                await _refresh_object_durability(db, obj)
                await db.flush()
                recorded += 1
        except Exception as exc:  # noqa: BLE001 - isolate malformed receipts within the batch
            logger.warning(f"Replica receipt failed for {object_id}/{server_id}: {exc}")
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
    quote = build_runtime_quote(
        quote_b64, (tee_type or "tdx").strip().lower(), snp_cert_chain, vtpm_quote
    )
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
    if not server.storage_incarnation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Storage TD has not announced a mounted encrypted-volume incarnation.",
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
                StorageObject.lifecycle_state.in_((OBJECT_PENDING, OBJECT_COMMITTED)),
                ReplicaPlacement.server_id == server_id,
                or_(
                    (
                        (
                            (ReplicaPlacement.status == "present")
                            | (
                                (ReplicaPlacement.status == "pending")
                                & (ReplicaPlacement.pending_deadline > func.now())
                            )
                        )
                        & (ReplicaPlacement.storage_incarnation == server.storage_incarnation)
                        & (
                            func.lower(ReplicaPlacement.target_cert_pubkey_hash)
                            == expected_cert_hash.lower()
                        )
                    ),
                    (
                        (ReplicaPlacement.status == "evicted")
                        & (StorageObject.lifecycle_state == OBJECT_COMMITTED)
                        & StorageObject.ciphertext_size_bytes.is_(None)
                        & StorageObject.legacy_adopted_at.is_(None)
                        & (ReplicaPlacement.proof_at.is_(None))
                        & (ReplicaPlacement.last_error == "secure_replication_requires_new_receipt")
                    ),
                ),
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume key not found.")
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
