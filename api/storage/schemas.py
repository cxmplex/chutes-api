"""Pydantic request/response models for the ChuteFS storage tracker API (api/storage/router.py)."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# --- model distribution (public, integrity-only) ----------------------------------------------


class ModelHolding(BaseModel):
    """A public model repo@revision a storage TD holds (verified against /misc/hf_repo_info)."""

    repo_id: str = Field(..., description="HuggingFace repo id, e.g. 'meta-llama/Llama-3.1-8B'")
    revision: str = Field("main", description="Repo revision/commit")
    bytes: int = Field(0, ge=0, description="On-disk size of the held snapshot")


class AnnounceModelHoldingsRequest(BaseModel):
    """A storage TD reports the public model repos it currently holds + refreshes free disk."""

    server_id: str = Field(..., description="The announcing storage TD's server id")
    disk_free_gb: Optional[int] = Field(None, ge=0, description="Current free disk (GB) on the TD")
    holdings: List[ModelHolding] = Field(default_factory=list)


class AnnounceResponse(BaseModel):
    recorded: int = Field(..., description="Number of holdings recorded/refreshed")


class StoragePeer(BaseModel):
    """An attested storage TD a peer can reach + mutually verify (cert authority below)."""

    server_id: str
    host: str = Field(..., description="Reachable host (the L0 host's public IP)")
    port: int = Field(..., description="DNAT'd storage-node port (public_ip:port)")
    cert_pubkey_hash: str = Field(
        ..., description="sha256 of the peer's attested serving-cert pubkey (DER SPKI)"
    )
    attested_cert: Optional[str] = Field(
        None,
        description="The peer's attested serving cert (PEM), inlined for the user-facing "
        "placement/locate flows so an off-TD client can pin it for mutual TLS without a separate call.",
    )


class PeerListResponse(BaseModel):
    peers: List[StoragePeer] = Field(default_factory=list)


class PeerCertResponse(BaseModel):
    """The validator's peer-cert authority: a storage TD's attested serving cert (PEM) + pubkey hash.

    A fetching/replicating TD pins the peer it talks to against this (the per-TD certs are
    self-issued, so there is no shared CA; the validator vouches for each attested cert instead).
    """

    server_id: str
    attested_cert: str = Field(..., description="The peer's attestation-bound serving cert (PEM)")
    cert_pubkey_hash: str


# --- confidential per-user volumes -------------------------------------------------------------


class CreateVolumeRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    replication_factor: int = Field(3, ge=1, le=10)
    quota_bytes: int = Field(10_737_418_240, ge=1, description="Soft quota in bytes (default 10 GiB)")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        import re

        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
            raise ValueError("name must be alphanumeric with . _ - (not leading)")
        return v


class VolumeResponse(BaseModel):
    volume_id: str
    name: str
    replication_factor: int
    quota_bytes: int
    used_bytes: int
    created_at: str


class VolumeListResponse(BaseModel):
    volumes: List[VolumeResponse] = Field(default_factory=list)


class PlacementRequest(BaseModel):
    """Ask the validator where to put a new/updated object (N attested TDs on distinct hosts)."""

    key: str = Field(..., min_length=1, max_length=1024)
    size_bytes: int = Field(..., ge=0, description="Plaintext size, for quota enforcement")


class PlacementResponse(BaseModel):
    object_id: str
    replicas: List[StoragePeer] = Field(default_factory=list)
    replication_factor: int


class CommitObjectRequest(BaseModel):
    """Commit an object after its ciphertext has been pushed to the holder TDs."""

    object_id: str
    key: str = Field(..., min_length=1, max_length=1024)
    size_bytes: int = Field(..., ge=0)
    sha256: Optional[str] = Field(None, description="Ciphertext content hash (integrity across replicas)")
    holder_server_ids: List[str] = Field(
        ..., min_length=1, description="Storage TDs that confirmed they stored the ciphertext"
    )


class CommitObjectResponse(BaseModel):
    object_id: str
    used_bytes: int
    quota_bytes: int


class LocateObjectRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=1024)


class LocateObjectResponse(BaseModel):
    object_id: str
    key: str
    size_bytes: int
    sha256: Optional[str] = None
    peers: List[StoragePeer] = Field(default_factory=list)


class ListObjectsRequest(BaseModel):
    prefix: Optional[str] = Field(None, max_length=1024)
    limit: int = Field(1000, ge=1, le=10000)


class ObjectInfo(BaseModel):
    object_id: str
    key: str
    size_bytes: int
    sha256: Optional[str] = None
    created_at: str


class ListObjectsResponse(BaseModel):
    objects: List[ObjectInfo] = Field(default_factory=list)


class DeleteObjectRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=1024)


class DeleteObjectResponse(BaseModel):
    deleted: bool
    used_bytes: int


# --- per-volume key release (attested storage TD only) -----------------------------------------


class KeyNonceResponse(BaseModel):
    nonce: str


class VolumeKeyRequest(BaseModel):
    """An attested storage TD requests a confidential volume's application-layer key.

    Gated on: a fresh quote bound to the storage_key nonce + the TD's serving-cert pubkey hash, the
    server being storage_role + currently attested, and the TD holding (or being assigned) a replica.
    """

    server_id: str
    quote: str = Field(..., description="Base64 runtime attestation bound to the storage_key nonce")
    tee_type: str = Field("tdx", description="'tdx' or 'sev-snp'")
    snp_cert_chain: Optional[str] = None
    vtpm_quote: Optional[Dict[str, Any]] = None


class VolumeKeyResponse(BaseModel):
    volume_id: str
    key: str = Field(..., description="The per-volume application-layer key (base64, 32 bytes)")


class ReplicaPlacementUpdate(BaseModel):
    object_id: str
    status: str = Field("present", description="present | evicted")


class ReplicaAnnounceRequest(BaseModel):
    server_id: str
    placements: List[ReplicaPlacementUpdate] = Field(default_factory=list)


# --- object-op grants (storage-node authorization for confidential object ops) -----------------


VALID_GRANT_OPS = ("put", "get", "list", "delete")


class GrantRequest(BaseModel):
    """A volume owner mints a short-lived grant authorizing storage TDs to serve object ops.

    Callers should request the MINIMAL op set: a put grant is forwarded to replica peers, so a broad
    (get/delete) grant would over-privilege every peer for the grant TTL. Ops are constrained to the
    known operations and de-duplicated.
    """

    volume_id: str
    ops: List[str] = Field(
        ...,
        min_length=1,
        description="Allowed object operations for the grant bearer (subset of put/get/list/delete). "
        "Required and explicit: callers request the minimal set (e.g. put-only for the replica-forwarded "
        "grant) so no request silently mints an all-ops bearer credential.",
    )

    @field_validator("ops")
    @classmethod
    def validate_ops(cls, v: List[str]) -> List[str]:
        unknown = [op for op in v if op not in VALID_GRANT_OPS]
        if unknown:
            raise ValueError(f"Unknown grant ops: {unknown}; allowed: {list(VALID_GRANT_OPS)}")
        if not v:
            raise ValueError("Grant must authorize at least one op.")
        # Preserve order, drop duplicates.
        return list(dict.fromkeys(v))


class GrantResponse(BaseModel):
    grant: str
    expires_in: int


class GrantVerifyRequest(BaseModel):
    grant: str
    volume_id: str
    op: str


class GrantVerifyResponse(BaseModel):
    ok: bool
    user_id: Optional[str] = None
    volume_id: Optional[str] = None
    ops: List[str] = Field(default_factory=list)
