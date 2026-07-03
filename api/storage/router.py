"""ChuteFS storage tracker API.

Endpoint groups + auth:
  - storage-TD ops (announce, replica-announce): owning-miner hotkey signature.
  - peer discovery + cert authority: a verified attested mTLS client cert (request came from inside
    SOME attested TD) -- this is how a chute TD finds model peers and how storage TDs find each other.
  - per-user volume CRUD + object metadata: the volume owner (API key / hotkey user).
  - per-volume key release: attested mTLS cert + a fresh quote bound to a single-use storage_key nonce.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.server.exceptions import AttestationError
from api.server.schemas import Server
from api.server.service import create_nonce, validate_request_nonce
from api.server.util import extract_client_cert_hash
from api.user.schemas import User
from api.user.service import get_current_user
from api.util import extract_ip
from api.storage import service
from api.storage.schemas import (
    AnnounceModelHoldingsRequest,
    AnnounceResponse,
    CommitObjectRequest,
    CommitObjectResponse,
    CreateVolumeRequest,
    DeleteObjectRequest,
    DeleteObjectResponse,
    GrantRequest,
    GrantResponse,
    GrantVerifyRequest,
    GrantVerifyResponse,
    KeyNonceResponse,
    ListObjectsRequest,
    ListObjectsResponse,
    LocateObjectRequest,
    LocateObjectResponse,
    ObjectInfo,
    PeerCertResponse,
    PeerListResponse,
    PlacementRequest,
    PlacementResponse,
    RepairTask,
    RepairTasksResponse,
    ReplicaAnnounceRequest,
    VolumeKeyRequest,
    VolumeKeyResponse,
    VolumeListResponse,
    VolumeResponse,
)

router = APIRouter()

_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


async def require_attested_caller(
    db: AsyncSession = Depends(get_db_session),
    # M4: require a LIVE mTLS handshake (X-Client-Verify==SUCCESS), not just a header-supplied PEM --
    # the attested certs are handed out publicly (peers/cert), so a header match alone is not proof
    # the caller holds the in-TEE key. (The gate is a no-op in the plaintext dev posture.)
    cert_hash: str = Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    """Authenticate that a request comes from inside SOME attested TD (its attested mTLS cert).

    Returns the matching attested Server. Used for peer discovery + the cert authority, which any
    attested chute/storage TD may call (peer info is low-sensitivity; integrity is enforced on fetch).
    """
    server = await service.find_server_by_attested_cert_hash(db, cert_hash)
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Caller is not an attested TEE server (no matching attested cert).",
        )
    return server


def _require_hotkey(hotkey: str | None) -> str:
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing miner hotkey header."
        )
    return hotkey


# --- storage-TD ops (owning-miner signature) ---------------------------------------------------


@router.post("/announce", response_model=AnnounceResponse)
async def announce(
    body: AnnounceModelHoldingsRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        # Accept v1+v2 (not require_v2): already-deployed storage TDs on the fleet sign v1 until they
        # are re-imaged with the v2 tracker; a re-imaged TD's v2 announce binds method+path+body.
        get_current_user(purpose="tee", registered_to=_REGISTERED_TO, raise_not_found=False)
    ),
):
    """A storage TD reports the public model repos it holds + refreshes its free disk (heartbeat)."""
    miner_hotkey = _require_hotkey(hotkey)
    recorded = await service.announce_model_holdings(
        db,
        miner_hotkey,
        body.server_id,
        body.disk_free_gb,
        [h.model_dump() for h in body.holdings],
    )
    return AnnounceResponse(recorded=recorded)


@router.post("/replicas/announce", response_model=AnnounceResponse)
async def announce_replicas(
    body: ReplicaAnnounceRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        # Accept v1+v2 (not require_v2): see announce -- deployed storage TDs sign v1 until re-imaged.
        get_current_user(purpose="tee", registered_to=_REGISTERED_TO, raise_not_found=False)
    ),
):
    """A storage TD reports object replicas it now holds (confirms a replication push)."""
    miner_hotkey = _require_hotkey(hotkey)
    recorded = await service.announce_replicas(
        db, miner_hotkey, body.server_id, [p.model_dump() for p in body.placements]
    )
    return AnnounceResponse(recorded=recorded)


# --- peer discovery + cert authority (attested caller) -----------------------------------------


@router.get("/peers/model", response_model=PeerListResponse)
async def peers_model(
    repo_id: str,
    revision: str = "main",
    db: AsyncSession = Depends(get_db_session),
    _=Depends(require_attested_caller),
):
    """Attested, live storage peers that hold (repo_id, revision) for peer-first model fetch."""
    peers = await service.model_peers(db, repo_id, revision)
    return PeerListResponse(peers=peers)


@router.get("/peers/local", response_model=PeerListResponse)
async def peers_local(
    host_id: str,
    db: AsyncSession = Depends(get_db_session),
    _=Depends(require_attested_caller),
):
    """The attested storage TD on host_id (a chute resolves its same-host storage node here)."""
    peer = await service.local_storage_peer(db, host_id)
    return PeerListResponse(peers=[peer] if peer else [])


@router.get("/peers/attested")
async def peers_attested(
    cert_hash: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Whether a cert pubkey-hash belongs to a registered attested server (M15).

    Public + read-only (attested certs are already handed out via /peers/cert): a storage TD uses it
    to gate the otherwise-unauthenticated /storage/model/ensure so only an attested TD triggers a
    peer/HF fetch. Leaks nothing beyond membership of a public cert hash.
    """
    return {"attested": await service.is_attested_server_cert(db, cert_hash)}


@router.get("/peers/cert/{server_id}", response_model=PeerCertResponse)
async def peer_cert(
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    _=Depends(require_attested_caller),
):
    """The peer-cert authority: a storage TD's attested serving cert (PEM) + pubkey hash, so a peer
    can pin/verify it for mutually-attested TLS (the per-TD certs are self-issued, no shared CA)."""
    pem, pubkey_hash = await service.peer_cert(db, server_id)
    return PeerCertResponse(server_id=server_id, attested_cert=pem, cert_pubkey_hash=pubkey_hash)


@router.get("/objects/{object_id}/replicas", response_model=PeerListResponse)
async def object_replicas(
    object_id: str,
    db: AsyncSession = Depends(get_db_session),
    _=Depends(require_attested_caller),
):
    """The validator-assigned replica peers for an object, so the primary storage TD replicates to the
    tracker's distinct-host placement instead of a client-supplied peer list (M2)."""
    peers = await service.object_replica_peers(db, object_id)
    return PeerListResponse(peers=peers)


@router.get("/repair/tasks", response_model=RepairTasksResponse)
async def repair_tasks(
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_attested_caller),
):
    """Repair work for the calling storage TD (M7): objects it holds that are under-replicated, each
    with a short-lived system put-grant + the newly-assigned target peers to push the ciphertext to."""
    tasks = await service.repair_tasks_for_server(db, caller.server_id)
    return RepairTasksResponse(tasks=[RepairTask(**t) for t in tasks])


# --- confidential volume CRUD (owner) ----------------------------------------------------------


@router.post("/volumes", response_model=VolumeResponse, status_code=status.HTTP_201_CREATED)
async def create_volume(
    body: CreateVolumeRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service.create_volume(
        db, current_user.user_id, body.name, body.replication_factor, body.quota_bytes
    )
    return VolumeResponse(**service._volume_response(volume))


@router.get("/volumes", response_model=VolumeListResponse)
async def list_volumes(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volumes = await service.list_volumes(db, current_user.user_id)
    return VolumeListResponse(volumes=[VolumeResponse(**service._volume_response(v)) for v in volumes])


@router.get("/volumes/{volume_id}", response_model=VolumeResponse)
async def get_volume(
    volume_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    return VolumeResponse(**service._volume_response(volume))


@router.delete("/volumes/{volume_id}")
async def delete_volume(
    volume_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    await service.delete_volume(db, volume_id, current_user.user_id)
    return {"deleted": True}


# --- object metadata: placement / commit / locate / list / delete (owner) ----------------------


@router.post("/volumes/{volume_id}/objects/placement", response_model=PlacementResponse)
async def plan_placement(
    volume_id: str,
    body: PlacementRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    """Quota-check + return the target replica set (N attested TDs on distinct hosts) for an object."""
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    obj, peers = await service.plan_object_placement(db, volume, body.key, body.size_bytes)
    return PlacementResponse(
        object_id=obj.object_id, replicas=peers, replication_factor=volume.replication_factor
    )


@router.post("/volumes/{volume_id}/objects/commit", response_model=CommitObjectResponse)
async def commit_object(
    volume_id: str,
    body: CommitObjectRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    """Finalize an object after its ciphertext has been pushed to the holder TDs (byte accounting)."""
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    obj, replicas_confirmed = await service.commit_object(
        db,
        volume,
        body.object_id,
        body.key,
        body.size_bytes,
        body.sha256,
        body.holder_server_ids,
        salt=body.salt,
        plaintext_sha256=body.plaintext_sha256,
    )
    return CommitObjectResponse(
        object_id=obj.object_id,
        used_bytes=volume.used_bytes,
        quota_bytes=volume.quota_bytes,
        replicas_confirmed=replicas_confirmed,
        replication_factor=volume.replication_factor,
        under_replicated=replicas_confirmed < volume.replication_factor,
    )


@router.post("/volumes/{volume_id}/objects/locate", response_model=LocateObjectResponse)
async def locate_object(
    volume_id: str,
    body: LocateObjectRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    obj, peers = await service.locate_object(db, volume, body.key)
    return LocateObjectResponse(
        object_id=obj.object_id,
        key=obj.object_key,
        size_bytes=obj.size_bytes,
        sha256=obj.sha256,
        # H1: the SDK needs the tracker-anchored salt to decrypt a v3 object and the plaintext hash
        # to verify the bytes end-to-end (both NULL for legacy v1/v2 objects).
        salt=obj.salt,
        plaintext_sha256=obj.plaintext_sha256,
        peers=peers,
    )


@router.post("/volumes/{volume_id}/objects/list", response_model=ListObjectsResponse)
async def list_objects(
    volume_id: str,
    body: ListObjectsRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    objects = await service.list_objects(db, volume, body.prefix, body.limit, after=body.after)
    # L4: a full page implies there may be more; hand back the last key as the next cursor.
    next_cursor = objects[-1].object_key if len(objects) == body.limit else None
    return ListObjectsResponse(
        objects=[
            ObjectInfo(
                object_id=o.object_id,
                key=o.object_key,
                size_bytes=o.size_bytes,
                sha256=o.sha256,
                created_at=o.created_at.isoformat() if o.created_at else "",
            )
            for o in objects
        ],
        next_cursor=next_cursor,
    )


@router.post("/volumes/{volume_id}/objects/delete", response_model=DeleteObjectResponse)
async def delete_object(
    volume_id: str,
    body: DeleteObjectRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    used = await service.delete_object(db, volume, body.key)
    return DeleteObjectResponse(deleted=True, used_bytes=used)


# --- object-op grants --------------------------------------------------------------------------


@router.post("/grant", response_model=GrantResponse)
async def issue_grant(
    body: GrantRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    """A volume owner mints a short-lived grant the storage TDs verify to authorize its object ops."""
    grant = await service.issue_grant(db, current_user.user_id, body.volume_id, body.ops)
    from api.storage.service import GRANT_TTL_SECONDS

    return GrantResponse(grant=grant, expires_in=GRANT_TTL_SECONDS)


@router.post("/grant/verify", response_model=GrantVerifyResponse)
async def verify_grant(
    body: GrantVerifyRequest,
    _=Depends(require_attested_caller),
):
    """A storage TD verifies a presented grant authorizes an object op on a volume."""
    payload = await service.verify_grant(body.grant, body.volume_id, body.op)
    if payload is None:
        return GrantVerifyResponse(ok=False)
    return GrantVerifyResponse(
        ok=True,
        user_id=payload.get("user_id"),
        volume_id=payload.get("volume_id"),
        ops=payload.get("ops", []),
    )


# --- per-volume key release (attested storage TD only) -----------------------------------------


@router.get("/key-nonce", response_model=KeyNonceResponse)
async def key_nonce(request: Request):
    """Mint a single-use nonce the storage TD must embed in its volume-key attestation quote."""
    nonce_info = await create_nonce(extract_ip(request), purpose=NoncePurpose.STORAGE_KEY)
    return KeyNonceResponse(nonce=nonce_info["nonce"])


@router.post("/volumes/{volume_id}/key", response_model=VolumeKeyResponse)
async def release_volume_key(
    volume_id: str,
    body: VolumeKeyRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    expected_cert_hash: str = Depends(extract_client_cert_hash()),
    validated_nonce: str = Depends(validate_request_nonce(NoncePurpose.STORAGE_KEY)),
):
    """Release a confidential volume's app-layer key to an attested storage TD that holds a replica.

    The attested mTLS cert + fresh quote (bound to validated_nonce + the cert pubkey) are the trust
    anchors: an operator holding only the miner hotkey can neither complete the handshake nor pass the
    quote. The key never leaves an attested TD whose measurement matches the pinned storage-TD config.
    """
    miner_hotkey = _require_hotkey(hotkey)
    try:
        key = await service.release_volume_key(
            db,
            volume_id,
            miner_hotkey,
            body.server_id,
            body.quote,
            body.tee_type,
            body.snp_cert_chain,
            body.vtpm_quote,
            validated_nonce,
            expected_cert_hash,
        )
    except AttestationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    return VolumeKeyResponse(volume_id=volume_id, key=key)
