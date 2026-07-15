"""ChuteFS storage tracker API.

Endpoint groups + auth:
  - storage-TD ops (announce, replica-announce): owning-miner hotkey signature.
  - generic peer discovery + cert authority: a verified attested mTLS client cert.
  - non-CPU/GPU model access: a verified launch JWT bound to one instance/chute/model/commit; this
    exposes only one storage target plus a one-use ensure capability, never generic peer/object APIs.
  - per-user volume CRUD + object metadata: the volume owner (API key / hotkey user).
  - per-volume key release: attested mTLS cert + a fresh quote bound to a single-use storage_key nonce.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.constants import AUTHORIZATION_HEADER, HOTKEY_HEADER, NoncePurpose
from api.database import get_db_session
from api.server.exceptions import AttestationError
from api.server.schemas import Server
from api.server.service import create_nonce, validate_request_nonce
from api.server.util import extract_client_cert_hash
from api.permissions import Permissioning
from api.user.schemas import User
from api.user.service import get_current_user
from api.storage import service
from api.storage.schemas import (
    AnnounceModelHoldingsRequest,
    AnnounceModelHoldingsResponse,
    AnnounceResponse,
    AdministrativeEraseRetirementRequest,
    AdministrativeEraseRetirementResponse,
    CommitObjectRequest,
    CommitObjectResponse,
    CreateVolumeRequest,
    DeleteVolumeResponse,
    DeleteObjectRequest,
    DeleteObjectResponse,
    EraseTask,
    EraseTaskResultRequest,
    EraseTaskResultResponse,
    EraseTasksResponse,
    GrantRequest,
    GrantResponse,
    GrantVerifyRequest,
    GrantVerifyResponse,
    KeyNonceResponse,
    InventoryPageRequest,
    InventoryPageResponse,
    LegacyReplicaAdoptionMetadataResponse,
    LegacyReplicaAdoptionResponse,
    LegacyReplicaAdoptionRequest,
    ListObjectsRequest,
    ListObjectsResponse,
    LocateObjectRequest,
    LocateObjectResponse,
    ModelAccessRequest,
    ModelAccessResponse,
    ModelEnsureCapabilityBinding,
    ModelEnsureCapabilityConsumeRequest,
    ModelEnsureCapabilityIssueRequest,
    ModelEnsureCapabilityIssueResponse,
    ObjectInfo,
    PeerCertResponse,
    PeerListResponse,
    PlacementRequest,
    PlacementResponse,
    RepairTask,
    RepairTasksResponse,
    ReplicaAnnounceRequest,
    ReplicaAuthorizationResponse,
    ReplicationCapabilityBinding,
    ReplicationCapabilityCompleteRequest,
    ReplicationCapabilityFailureRequest,
    ReplicationCapabilityIssueRequest,
    ReplicationCapabilityIssueResponse,
    ReplicationCapabilityResult,
    ReplicationCapabilityConsumeRequest,
    VolumeKeyRequest,
    VolumeKeyResponse,
    VolumeListResponse,
    VolumeResponse,
)

router = APIRouter()

_REGISTERED_TO = None if settings.skip_metagraph_check else settings.netuid


async def require_attested_caller(
    db: AsyncSession = Depends(get_db_session),
    # M4: require a LIVE mTLS handshake, not just a header-supplied PEM. nginx reports SUCCESS for a
    # CA-chained cert and FAILED:<reason> for the expected self-signed attested TEE cert under
    # optional_no_ca; both prove CertificateVerify possession. NONE/missing proves no handshake.
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


async def require_fresh_storage_caller(
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_attested_caller),
) -> Server:
    """Require current mTLS cert possession plus a bounded-age accepted storage attestation."""
    if not settings.require_mtls_client_verify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Storage liveness and replica receipts are disabled without a verifying "
                "mTLS terminator."
            ),
        )
    if not caller.storage_role or not await service.is_freshly_attested_storage_server(db, caller):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Storage caller lacks a current successful attestation against an active "
                "storage measurement."
            ),
        )
    # Only this certificate-authenticated dependency may refresh storage liveness. A miner-hotkey
    # heartbeat never reaches this call by itself.
    await service.mark_storage_online(caller.server_id)
    return caller


async def require_storage_administrator(
    current_user: User = Depends(get_current_user(require_v2=True)),
) -> User:
    if not (
        current_user.has_role(Permissioning.chutes_support)
        or current_user.has_role(Permissioning.billing_admin)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Storage erase retirement requires a support or billing administrator.",
        )
    return current_user


def _require_hotkey(hotkey: str | None) -> str:
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey header.",
        )
    return hotkey


# --- storage-TD ops (owning-miner signature) ---------------------------------------------------


@router.post("/announce", response_model=AnnounceModelHoldingsResponse)
async def announce(
    body: AnnounceModelHoldingsRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        # Accept v1+v2 (not require_v2): already-deployed storage TDs on the fleet sign v1 until they
        # are re-imaged with the v2 tracker; a re-imaged TD's v2 announce binds method+path+body.
        get_current_user(purpose="tee", registered_to=_REGISTERED_TO, raise_not_found=False)
    ),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """A storage TD reports the public model repos it holds + refreshes its free disk (heartbeat)."""
    miner_hotkey = _require_hotkey(hotkey)
    result = await service.announce_model_holdings(
        db,
        miner_hotkey,
        body.server_id,
        caller.server_id,
        body.snapshot_id,
        body.page_index,
        body.storage_incarnation,
        body.disk_free_gb,
        [h.model_dump() for h in body.holdings],
        body.complete,
    )
    return AnnounceModelHoldingsResponse(**result)


@router.post("/replicas/announce", response_model=AnnounceResponse)
async def announce_replicas(
    body: ReplicaAnnounceRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User | None = Depends(
        # Accept v1+v2 (not require_v2): see announce -- deployed storage TDs sign v1 until re-imaged.
        get_current_user(purpose="tee", registered_to=_REGISTERED_TO, raise_not_found=False)
    ),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """A storage TD reports object replicas it now holds (confirms a replication push)."""
    miner_hotkey = _require_hotkey(hotkey)
    recorded = await service.announce_replicas(
        db,
        miner_hotkey,
        body.server_id,
        caller.server_id,
        body.storage_incarnation,
        [p.model_dump() for p in body.placements],
    )
    return AnnounceResponse(recorded=recorded)


@router.post("/replicas/adopt-legacy", response_model=LegacyReplicaAdoptionResponse)
async def adopt_legacy_replicas(
    body: LegacyReplicaAdoptionRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Adopt one intact pre-secure-replication file through its current attested assignment."""
    outcomes = await service.adopt_legacy_replicas(
        db,
        caller,
        body.storage_incarnation,
        [submission.model_dump() for submission in body.objects],
    )
    return LegacyReplicaAdoptionResponse(outcomes=outcomes)


@router.get(
    "/replicas/adopt-legacy/{object_id}/metadata",
    response_model=LegacyReplicaAdoptionMetadataResponse,
)
async def legacy_adoption_metadata(
    object_id: str,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Return decryption metadata only for this TD's quarantined legacy assignment."""
    return LegacyReplicaAdoptionMetadataResponse(
        **(await service.legacy_adoption_metadata(db, caller, object_id))
    )


@router.post("/inventory", response_model=InventoryPageResponse)
async def record_inventory(
    body: InventoryPageRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Record one bounded page of a current incarnation's authoritative finalized-file inventory."""
    return InventoryPageResponse(
        **(
            await service.record_inventory_page(
                db,
                caller,
                body.snapshot_id,
                body.storage_incarnation,
                [entry.model_dump() for entry in body.entries],
                body.complete,
            )
        )
    )


@router.get("/erase/tasks", response_model=EraseTasksResponse)
async def claim_erase_tasks(
    limit: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Lease exact-generation erase work to its current attested holder incarnation."""
    tasks = await service.claim_erase_tasks(db, caller, limit)
    return EraseTasksResponse(tasks=[EraseTask(**task) for task in tasks])


@router.post("/erase/tasks/{task_id}/result", response_model=EraseTaskResultResponse)
async def record_erase_result(
    task_id: str,
    body: EraseTaskResultRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Acknowledge an fsync-complete deletion, or release a failed lease for retry."""
    return EraseTaskResultResponse(
        **(
            await service.record_erase_task_result(
                db,
                caller,
                task_id,
                body.status,
                body.file_was_present,
                body.error,
            )
        )
    )


@router.post(
    "/admin/erase/retire",
    response_model=AdministrativeEraseRetirementResponse,
)
async def administratively_retire_erase_tasks(
    body: AdministrativeEraseRetirementRequest,
    db: AsyncSession = Depends(get_db_session),
    administrator: User = Depends(require_storage_administrator),
):
    """Explicitly retire named overdue tasks under the configured retention policy."""
    retired = await service.administratively_retire_erase_tasks(
        db,
        administrator.user_id,
        body.task_ids,
        body.reason,
    )
    return AdministrativeEraseRetirementResponse(retired=retired)


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
    caller: Server = Depends(require_attested_caller),
):
    """The attested storage TD on host_id (a chute resolves its same-host storage node here)."""
    if not caller.host_id or caller.host_id != host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requested local storage host does not match the attested caller.",
        )
    peer = await service.local_storage_peer(db, host_id)
    return PeerListResponse(peers=[peer] if peer else [])


@router.get("/peers/model-target", response_model=PeerListResponse)
async def model_target(
    repo_id: str,
    revision: str,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_attested_caller),
):
    """Choose a live storage target even when no peer holds this cold immutable commit yet."""
    peer = await service.model_ensure_target(
        db,
        repo_id,
        revision,
        preferred_host_id=caller.host_id,
    )
    return PeerListResponse(peers=[peer] if peer else [])


@router.post(
    "/model/capabilities",
    response_model=ModelEnsureCapabilityIssueResponse,
)
async def issue_model_ensure_capability(
    body: ModelEnsureCapabilityIssueRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_attested_caller),
    authorization: str = Header(..., alias=AUTHORIZATION_HEADER),
):
    """Authorize one launch/instance/model target after real requester mTLS possession."""
    requester = await service.authorize_launch_model_request(
        db,
        authorization,
        body.repo_id,
        body.revision,
        body.requested_revision,
        expected_server_id=caller.server_id,
    )
    requester["requester_cert_pubkey_hash"] = (
        (caller.attested_cert_pubkey_hash or "").strip().lower()
    )
    if not requester["requester_cert_pubkey_hash"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Attested requester has no certificate binding.",
        )
    return ModelEnsureCapabilityIssueResponse(
        **(
            await service.issue_model_ensure_capability(
                db,
                requester,
                body.request_id,
                body.target_server_id,
                body.repo_id,
                body.revision,
                body.requested_revision,
            )
        )
    )


@router.post("/model/access", response_model=ModelAccessResponse)
async def issue_launch_model_access(
    body: ModelAccessRequest,
    db: AsyncSession = Depends(get_db_session),
    authorization: str = Header(..., alias=AUTHORIZATION_HEADER),
):
    """Authorize non-CPU/GPU launch instances for public model discovery and one ensure only."""
    requester = await service.authorize_launch_model_request(
        db,
        authorization,
        body.repo_id,
        body.revision,
        body.requested_revision,
    )
    peer = await service.model_ensure_target(db, body.repo_id, body.revision)
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No live attested storage target is available.",
        )
    issued = await service.issue_model_ensure_capability(
        db,
        requester,
        body.request_id,
        peer.server_id,
        body.repo_id,
        body.revision,
        body.requested_revision,
    )
    return ModelAccessResponse(peer=peer, **issued)


@router.post(
    "/model/capabilities/consume",
    response_model=ModelEnsureCapabilityBinding,
)
async def consume_model_ensure_capability(
    body: ModelEnsureCapabilityConsumeRequest,
    target: Server = Depends(require_fresh_storage_caller),
):
    """Consume an exact capability over the selected target's own attested mTLS."""
    return ModelEnsureCapabilityBinding(
        **(
            await service.consume_model_ensure_capability(
                target,
                body.capability,
                body.request_id,
                body.repo_id,
                body.revision,
                body.requested_revision,
            )
        )
    )


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
    _=Depends(require_fresh_storage_caller),
):
    """The validator-assigned replica peers for an object, so the primary storage TD replicates to the
    tracker's distinct-host placement instead of a client-supplied peer list (M2)."""
    peers = await service.object_replica_peers(db, object_id)
    return PeerListResponse(peers=peers)


@router.get(
    "/objects/{object_id}/replica-authorization",
    response_model=ReplicaAuthorizationResponse,
)
async def replica_authorization(
    object_id: str,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Return only the calling target TD's current, incarnation-bound assignment."""
    return ReplicaAuthorizationResponse(
        **(await service.replica_authorization(db, object_id, caller))
    )


@router.get("/repair/tasks", response_model=RepairTasksResponse)
async def repair_tasks(
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Capability-free repair descriptors; each target is leased only when transfer begins."""
    tasks = await service.repair_tasks_for_server(db, caller.server_id)
    return RepairTasksResponse(tasks=[RepairTask(**t) for t in tasks])


@router.post(
    "/replication/capabilities",
    response_model=ReplicationCapabilityIssueResponse,
)
async def issue_replication_capability(
    body: ReplicationCapabilityIssueRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Lease one exact target transfer to a source with a current possession receipt."""
    return ReplicationCapabilityIssueResponse(
        **(
            await service.issue_replication_capability(
                db,
                caller,
                body.object_id,
                body.target_server_id,
                body.ciphertext_sha256,
                body.ciphertext_size_bytes,
            )
        )
    )


@router.post(
    "/replication/capabilities/consume",
    response_model=ReplicationCapabilityBinding,
)
async def consume_replication_capability(
    body: ReplicationCapabilityConsumeRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Atomically consume a one-use capability as its exact current target before body read."""
    return ReplicationCapabilityBinding(
        **(
            await service.consume_replication_capability(
                db, caller, body.capability, body.source_signature
            )
        )
    )


@router.post(
    "/replication/capabilities/complete",
    response_model=ReplicationCapabilityResult,
)
async def complete_replication_capability(
    body: ReplicationCapabilityCompleteRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Record target possession only after durable no-replace publication of exact bytes."""
    return ReplicationCapabilityResult(
        **(
            await service.complete_replication_capability(
                db,
                caller,
                body.capability,
                body.ciphertext_sha256,
                body.ciphertext_size_bytes,
            )
        )
    )


@router.post(
    "/replication/capabilities/fail",
    response_model=ReplicationCapabilityResult,
)
async def fail_replication_capability(
    body: ReplicationCapabilityFailureRequest,
    db: AsyncSession = Depends(get_db_session),
    caller: Server = Depends(require_fresh_storage_caller),
):
    """Record one bounded transfer failure without manufacturing a possession receipt."""
    return ReplicationCapabilityResult(
        **(await service.fail_replication_capability(db, caller, body.capability, body.error))
    )


# --- confidential volume CRUD (owner) ----------------------------------------------------------


@router.post("/volumes", response_model=VolumeResponse, status_code=status.HTTP_201_CREATED)
async def create_volume(
    body: CreateVolumeRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume, aggregate_quota = await service.create_volume(
        db, current_user.user_id, body.name, body.replication_factor
    )
    return VolumeResponse(**service._volume_response(volume, aggregate_quota))


@router.get("/volumes", response_model=VolumeListResponse)
async def list_volumes(
    limit: int = Query(100, ge=1, le=200),
    after: str | None = Query(None, max_length=128),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    effective_limit = min(limit, settings.storage_volume_page_size_max)
    volumes, aggregate_quota = await service.list_volumes(
        db, current_user.user_id, effective_limit, after
    )
    return VolumeListResponse(
        volumes=[
            VolumeResponse(**service._volume_response(volume, aggregate_quota))
            for volume in volumes
        ],
        next_cursor=volumes[-1].volume_id if len(volumes) == effective_limit else None,
    )


@router.get("/volumes/{volume_id}", response_model=VolumeResponse)
async def get_volume(
    volume_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    aggregate_quota = await service.storage_aggregate_quota(db, current_user.user_id)
    return VolumeResponse(**service._volume_response(volume, aggregate_quota))


@router.delete("/volumes/{volume_id}", response_model=DeleteVolumeResponse)
async def delete_volume(
    volume_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    return DeleteVolumeResponse(
        **(await service.delete_volume(db, volume_id, current_user.user_id))
    )


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
    obj, peers = await service.plan_object_placement(
        db, volume, body.request_id, body.key, body.size_bytes
    )
    return PlacementResponse(
        object_id=obj.object_id,
        expected_predecessor_id=obj.expected_predecessor_id,
        lifecycle_state=obj.lifecycle_state,
        salt=obj.salt,
        replicas=peers,
        replication_factor=volume.replication_factor,
        replicas_available=len(peers),
        under_replicated=len(peers) < volume.replication_factor,
        durability_state=obj.durability_state,
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
        salt=body.salt,
    )
    return CommitObjectResponse(
        object_id=obj.object_id,
        lifecycle_state=obj.lifecycle_state,
        size_bytes=obj.size_bytes,
        used_bytes=volume.used_bytes,
        quota_bytes=volume.quota_bytes,
        replicas_confirmed=replicas_confirmed,
        replication_factor=volume.replication_factor,
        under_replicated=replicas_confirmed < volume.replication_factor,
        durability_state=obj.durability_state,
    )


@router.post("/volumes/{volume_id}/objects/locate", response_model=LocateObjectResponse)
async def locate_object(
    volume_id: str,
    body: LocateObjectRequest,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user(require_v2=True)),
):
    volume = await service._get_owned_volume(db, volume_id, current_user.user_id)
    obj, peers, replicas_confirmed = await service.locate_object(db, volume, body.key)
    return LocateObjectResponse(
        object_id=obj.object_id,
        lifecycle_state=obj.lifecycle_state,
        key=obj.object_key,
        size_bytes=obj.size_bytes,
        sha256=obj.sha256,
        # H1: the SDK needs the tracker-anchored salt to decrypt a v3 object and the plaintext hash
        # to verify the bytes end-to-end (both NULL for legacy v1/v2 objects).
        salt=obj.salt,
        plaintext_sha256=obj.plaintext_sha256,
        peers=peers,
        replicas_confirmed=replicas_confirmed,
        replication_factor=volume.replication_factor,
        under_replicated=replicas_confirmed < volume.replication_factor,
        durability_state=obj.durability_state,
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
                lifecycle_state=o.lifecycle_state,
                key=o.object_key,
                size_bytes=o.size_bytes,
                sha256=o.sha256,
                created_at=o.created_at.isoformat() if o.created_at else "",
                replicas_confirmed=o.durable_replica_count,
                replication_factor=volume.replication_factor,
                durability_state=o.durability_state,
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
    obj, used, erase_tasks_pending = await service.delete_object(db, volume, body.key)
    return DeleteObjectResponse(
        deleted=True,
        object_id=obj.object_id if obj is not None else None,
        used_bytes=used,
        erase_tasks_pending=erase_tasks_pending,
        purge_pending=erase_tasks_pending > 0 or obj is not None,
    )


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
    nonce_info = await create_nonce(request.state.client_ip, purpose=NoncePurpose.STORAGE_KEY)
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
