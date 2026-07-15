"""Pydantic request/response models for the ChuteFS storage tracker API (api/storage/router.py)."""

import re
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMMUTABLE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_INT64 = 9_223_372_036_854_775_807


def _canonical_incarnation(value: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("storage_incarnation must be a canonical UUID") from exc


def _canonical_sha256(value: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError("ciphertext sha256 must be exactly 64 lowercase hex characters")
    return normalized


# --- model distribution (public, integrity-only) ----------------------------------------------


class ModelHolding(BaseModel):
    """A public model repo@revision a storage TD holds (verified against /misc/hf_repo_info)."""

    repo_id: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="HuggingFace repo id, e.g. 'meta-llama/Llama-3.1-8B'",
    )
    revision: str = Field("main", min_length=1, max_length=512, description="Repo revision/commit")
    bytes: int = Field(
        0,
        ge=0,
        le=_MAX_INT64,
        strict=True,
        description="On-disk size of the held snapshot",
    )


class AnnounceModelHoldingsRequest(BaseModel):
    """A storage TD reports the public model repos it currently holds + refreshes free disk."""

    server_id: str = Field(..., description="The announcing storage TD's server id")
    snapshot_id: str
    page_index: int = Field(..., ge=0, le=2_147_483_647, strict=True)
    storage_incarnation: str = Field(
        ..., description="UUID persisted inside the mounted encrypted data volume"
    )
    disk_free_gb: Optional[int] = Field(None, ge=0, description="Current free disk (GB) on the TD")
    holdings: List[ModelHolding] = Field(default_factory=list, max_length=1000)
    complete: bool = False

    @field_validator("snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("snapshot_id must be a canonical UUID") from exc

    @field_validator("storage_incarnation")
    @classmethod
    def validate_storage_incarnation(cls, value: str) -> str:
        return _canonical_incarnation(value)


class AnnounceModelHoldingsResponse(BaseModel):
    recorded: int = Field(..., description="Number of holdings recorded/refreshed")
    complete: bool


class AnnounceResponse(BaseModel):
    recorded: int


class StoragePeer(BaseModel):
    """An attested storage TD a peer can reach + mutually verify (cert authority below)."""

    server_id: str
    host: str = Field(..., description="Reachable host (the L0 host's public IP)")
    port: int = Field(..., description="DNAT'd storage-node port (public_ip:port)")
    cert_pubkey_hash: str = Field(
        ..., description="sha256 of the peer's attested serving-cert pubkey (DER SPKI)"
    )
    storage_incarnation: str = Field(
        ..., description="Current encrypted storage-volume incarnation"
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


class ModelEnsureCapabilityIssueRequest(BaseModel):
    """Request one exact model ensure on one selected storage target."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        description="Caller-generated canonical UUID nonce binding this ensure request",
    )
    target_server_id: str = Field(..., min_length=1, max_length=128)
    repo_id: str = Field(..., min_length=1, max_length=512)
    revision: str = Field(
        ...,
        description="Immutable lowercase 40-hex HuggingFace commit",
    )
    requested_revision: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Original branch, tag, or commit whose ref must resolve to revision",
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("request_id must be a canonical UUID") from exc

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _IMMUTABLE_REVISION_RE.fullmatch(normalized):
            raise ValueError("revision must be an immutable lowercase 40-hex commit")
        return normalized

    @field_validator("requested_revision")
    @classmethod
    def validate_requested_revision(cls, value: str) -> str:
        normalized = value.strip()
        if (
            not normalized
            or "\x00" in normalized
            or "\\" in normalized
            or normalized.startswith("/")
            or any(segment in {"", ".", ".."} for segment in normalized.split("/"))
        ):
            raise ValueError("requested_revision must be a safe HuggingFace ref")
        return normalized


class ModelEnsureCapabilityIssueResponse(BaseModel):
    capability: str = Field(..., description="Opaque, short-lived, one-use model ensure capability")
    capability_id: str
    expires_at: str


class ModelEnsureCapabilityConsumeRequest(BaseModel):
    """Target-presented bindings consumed over the target's own attested mTLS."""

    model_config = ConfigDict(extra="forbid")

    capability: str = Field(..., min_length=1, max_length=512)
    request_id: str
    repo_id: str = Field(..., min_length=1, max_length=512)
    revision: str
    requested_revision: str = Field(..., min_length=1, max_length=512)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("request_id must be a canonical UUID") from exc

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _IMMUTABLE_REVISION_RE.fullmatch(normalized):
            raise ValueError("revision must be an immutable lowercase 40-hex commit")
        return normalized

    @field_validator("requested_revision")
    @classmethod
    def validate_requested_revision(cls, value: str) -> str:
        return ModelEnsureCapabilityIssueRequest.validate_requested_revision(value)


class ModelEnsureCapabilityBinding(BaseModel):
    capability_id: str
    request_id: str
    requester_kind: Literal["attested_server", "launch_instance"]
    requester_server_id: Optional[str] = None
    requester_cert_pubkey_hash: Optional[str] = None
    requester_instance_id: str
    requester_config_id: str
    requester_chute_id: str
    requester_deployment_id: Optional[str] = None
    target_server_id: str
    target_cert_pubkey_hash: str
    repo_id: str
    revision: str
    requested_revision: str
    expires_at: str


class ModelAccessRequest(BaseModel):
    """Launch-JWT-authorized discovery plus one exact ensure capability."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    repo_id: str = Field(..., min_length=1, max_length=512)
    revision: str
    requested_revision: str = Field(..., min_length=1, max_length=512)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return ModelEnsureCapabilityIssueRequest.validate_request_id(value)

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, value: str) -> str:
        return ModelEnsureCapabilityIssueRequest.validate_revision(value)

    @field_validator("requested_revision")
    @classmethod
    def validate_requested_revision(cls, value: str) -> str:
        return ModelEnsureCapabilityIssueRequest.validate_requested_revision(value)


class ModelAccessResponse(ModelEnsureCapabilityIssueResponse):
    peer: StoragePeer


# --- confidential per-user volumes -------------------------------------------------------------


class CreateVolumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    replication_factor: int = Field(3, ge=1, le=10)

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
    aggregate_quota_bytes: int
    used_bytes: int
    created_at: str


class VolumeListResponse(BaseModel):
    volumes: List[VolumeResponse] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class DeleteVolumeResponse(BaseModel):
    deleted: Literal[True] = True
    volume_id: str
    erase_tasks_pending: int
    key_shredded: bool
    purge_pending: bool


class PlacementRequest(BaseModel):
    """Ask the validator where to put a new/updated object (N attested TDs on distinct hosts)."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        description="Canonical UUID idempotency key for this immutable placement reservation",
    )
    key: str = Field(..., min_length=1, max_length=1024)
    size_bytes: int = Field(
        ...,
        ge=0,
        le=_MAX_INT64,
        strict=True,
        description="Immutable plaintext reservation; accounting uses the attested node receipt",
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("request_id must be a canonical UUID") from exc


class PlacementResponse(BaseModel):
    object_id: str
    expected_predecessor_id: Optional[str] = None
    lifecycle_state: Literal["pending"]
    salt: str = Field(
        ...,
        description="Reserved generation salt used identically by every failover primary",
    )
    replicas: List[StoragePeer] = Field(default_factory=list)
    replication_factor: int
    replicas_available: int
    under_replicated: bool
    durability_state: str


class CommitObjectRequest(BaseModel):
    """CAS-commit using exact attested target receipts already recorded by the tracker."""

    model_config = ConfigDict(extra="forbid")

    object_id: str
    key: str = Field(..., min_length=1, max_length=1024)
    salt: str = Field(
        ...,
        min_length=1,
        description="Reserved placement salt echoed by the storage target",
    )


class CommitObjectResponse(BaseModel):
    object_id: str
    lifecycle_state: Literal["committed"]
    size_bytes: int
    used_bytes: int
    quota_bytes: int
    # H3: report the ACTUAL durability so a commit is never silently accepted at rf=1. The reconcile
    # loop re-replicates under-target objects; until then the client knows the true replica count.
    replicas_confirmed: int = 1
    replication_factor: int = 1
    under_replicated: bool = False
    durability_state: str


class LocateObjectRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=1024)


class LocateObjectResponse(BaseModel):
    object_id: str
    lifecycle_state: Literal["committed"]
    key: str
    size_bytes: int
    sha256: Optional[str] = None
    # H1: salt to decrypt the v3 container + plaintext hash for end-to-end verification (NULL for
    # legacy v1/v2 objects whose salt is still carried in the file).
    salt: Optional[str] = None
    plaintext_sha256: Optional[str] = None
    peers: List[StoragePeer] = Field(default_factory=list)
    replicas_confirmed: int
    replication_factor: int
    under_replicated: bool
    durability_state: str


class ListObjectsRequest(BaseModel):
    prefix: Optional[str] = Field(None, max_length=1024)
    limit: int = Field(1000, ge=1, le=10000)
    # L4: keyset cursor -- pass the previous page's next_cursor to page through > limit objects.
    after: Optional[str] = Field(None, max_length=1024, description="Return keys after this one")


class ObjectInfo(BaseModel):
    object_id: str
    lifecycle_state: Literal["committed"]
    key: str
    size_bytes: int
    sha256: Optional[str] = None
    created_at: str
    replicas_confirmed: int = 0
    replication_factor: int = 1
    durability_state: str = "pending"


class ListObjectsResponse(BaseModel):
    objects: List[ObjectInfo] = Field(default_factory=list)
    # L4: the key to pass as `after` for the next page, or null when this is the last page.
    next_cursor: Optional[str] = None


class DeleteObjectRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=1024)


class DeleteObjectResponse(BaseModel):
    deleted: Literal[True] = True
    object_id: Optional[str] = None
    used_bytes: int
    erase_tasks_pending: int
    purge_pending: bool


# --- authoritative node inventory + durable physical erasure ---------------------------------


class InventoryObject(BaseModel):
    volume_id: str = Field(..., min_length=1, max_length=128)
    object_id: str = Field(..., min_length=1, max_length=128)
    ciphertext_sha256: str
    ciphertext_size_bytes: int = Field(..., ge=0, le=_MAX_INT64, strict=True)

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)


class InventoryPageRequest(BaseModel):
    snapshot_id: str
    storage_incarnation: str
    entries: List[InventoryObject] = Field(default_factory=list, max_length=250)
    complete: bool = False

    @field_validator("snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("snapshot_id must be a canonical UUID") from exc

    @field_validator("storage_incarnation")
    @classmethod
    def validate_storage_incarnation(cls, value: str) -> str:
        return _canonical_incarnation(value)


class InventoryPageResponse(BaseModel):
    snapshot_id: str
    recorded: int
    erase_tasks_enqueued: int
    complete: bool


class EraseTask(BaseModel):
    task_id: str
    object_id: str
    volume_id: str
    storage_incarnation: str
    reason: str
    lease_expires_at: str


class EraseTasksResponse(BaseModel):
    tasks: List[EraseTask] = Field(default_factory=list)


class EraseTaskResultRequest(BaseModel):
    status: Literal["erased", "failed"]
    file_was_present: Optional[bool] = None
    error: Optional[str] = Field(None, max_length=256)

    @model_validator(mode="after")
    def validate_result(self) -> "EraseTaskResultRequest":
        if self.status == "erased" and self.file_was_present is None:
            raise ValueError("erased acknowledgement requires file_was_present")
        if self.status == "failed" and not self.error:
            raise ValueError("failed acknowledgement requires error")
        return self


class EraseTaskResultResponse(BaseModel):
    recorded: bool
    task_id: str
    terminal: bool


class AdministrativeEraseRetirementRequest(BaseModel):
    task_ids: List[str] = Field(..., min_length=1, max_length=500)
    reason: str = Field(..., min_length=1, max_length=256)


class AdministrativeEraseRetirementResponse(BaseModel):
    retired: int


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


class RepairTask(BaseModel):
    """One repair descriptor; the source leases each target capability immediately before transfer."""

    object_id: str
    volume_id: str
    ciphertext_sha256: str = Field(
        ...,
        description="Tracker-anchored ciphertext hash the source and target must verify",
    )
    ciphertext_size_bytes: int = Field(
        ...,
        ge=0,
        le=_MAX_INT64,
        strict=True,
        description="Exact committed ciphertext byte count",
    )
    peers: List[StoragePeer] = Field(default_factory=list)

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)


class RepairTasksResponse(BaseModel):
    tasks: List[RepairTask] = Field(default_factory=list)


class ReplicaPlacementUpdate(BaseModel):
    object_id: str
    status: Literal["stored", "evicted"] = Field(
        "stored", description="Target possession receipt or explicit target eviction"
    )
    ciphertext_sha256: Optional[str] = Field(
        None,
        description="Required target-computed ciphertext hash for present receipts",
    )
    ciphertext_size_bytes: Optional[int] = Field(
        None,
        ge=0,
        le=_MAX_INT64,
        strict=True,
        description="Required exact target-computed ciphertext byte count for stored receipts",
    )
    plaintext_size_bytes: Optional[int] = Field(
        None,
        ge=0,
        le=_MAX_INT64,
        strict=True,
        description="Required exact plaintext byte count observed by the direct upload target",
    )
    plaintext_sha256: Optional[str] = Field(
        None,
        description="Required target-computed plaintext hash for a direct upload receipt",
    )
    error: Optional[str] = Field(None, max_length=256)

    @model_validator(mode="after")
    def validate_receipt(self) -> "ReplicaPlacementUpdate":
        if self.status == "stored":
            if (
                self.ciphertext_sha256 is None
                or self.ciphertext_size_bytes is None
                or self.plaintext_size_bytes is None
                or self.plaintext_sha256 is None
            ):
                raise ValueError("stored requires exact ciphertext and plaintext receipt evidence")
            self.ciphertext_sha256 = _canonical_sha256(self.ciphertext_sha256)
            self.plaintext_sha256 = _canonical_sha256(self.plaintext_sha256)
        elif self.ciphertext_sha256 is not None:
            self.ciphertext_sha256 = _canonical_sha256(self.ciphertext_sha256)
            if self.plaintext_sha256 is not None:
                self.plaintext_sha256 = _canonical_sha256(self.plaintext_sha256)
        return self


class ReplicaAnnounceRequest(BaseModel):
    server_id: str
    storage_incarnation: str
    placements: List[ReplicaPlacementUpdate] = Field(default_factory=list, max_length=250)

    @field_validator("storage_incarnation")
    @classmethod
    def validate_storage_incarnation(cls, value: str) -> str:
        return _canonical_incarnation(value)


class LegacyReplicaAdoptionReceipt(BaseModel):
    object_id: str = Field(..., min_length=1, max_length=128)
    result: Literal["verified", "corrupt"]
    ciphertext_sha256: str
    ciphertext_size_bytes: int = Field(..., ge=0, le=_MAX_INT64, strict=True)
    plaintext_size_bytes: Optional[int] = Field(None, ge=0, le=_MAX_INT64, strict=True)
    plaintext_sha256: Optional[str] = None
    error: Optional[str] = Field(None, min_length=1, max_length=128)

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)

    @field_validator("plaintext_sha256")
    @classmethod
    def validate_plaintext_sha256(cls, value: Optional[str]) -> Optional[str]:
        return _canonical_sha256(value) if value is not None else None

    @model_validator(mode="after")
    def validate_result_evidence(self) -> "LegacyReplicaAdoptionReceipt":
        if self.result == "verified":
            if self.plaintext_size_bytes is None or self.plaintext_sha256 is None:
                raise ValueError("verified adoption requires exact plaintext evidence")
            if self.error is not None:
                raise ValueError("verified adoption cannot include a corruption error")
        elif (
            self.error is None
            or self.plaintext_size_bytes is not None
            or self.plaintext_sha256 is not None
        ):
            raise ValueError("corrupt adoption requires an error and no plaintext evidence")
        return self


class LegacyReplicaAdoptionRequest(BaseModel):
    storage_incarnation: str
    objects: List[LegacyReplicaAdoptionReceipt] = Field(default_factory=list, max_length=250)

    @field_validator("storage_incarnation")
    @classmethod
    def validate_storage_incarnation(cls, value: str) -> str:
        return _canonical_incarnation(value)

    @model_validator(mode="after")
    def validate_unique_objects(self) -> "LegacyReplicaAdoptionRequest":
        object_ids = [submission.object_id for submission in self.objects]
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("legacy adoption object ids must be unique within a page")
        return self


class LegacyReplicaAdoptionOutcome(BaseModel):
    object_id: str
    status: Literal["accepted", "quarantined", "retry"]
    idempotent: bool = False
    detail: Optional[str] = None


class LegacyReplicaAdoptionResponse(BaseModel):
    outcomes: List[LegacyReplicaAdoptionOutcome] = Field(..., max_length=250)


class LegacyReplicaAdoptionMetadataResponse(BaseModel):
    object_id: str
    volume_id: str
    ciphertext_sha256: str
    salt: Optional[str] = None


class ReplicaAuthorizationResponse(BaseModel):
    """The calling target TD's current assignment for an incoming object write."""

    object_id: str
    volume_id: str
    placement_status: Literal["pending"]
    lifecycle_state: Literal["pending", "committed"]
    storage_incarnation: str
    projected_size_bytes: int
    salt: Optional[str] = None
    ciphertext_sha256: Optional[str] = None
    pending_deadline: Optional[str] = None


# --- one-use secure replication capabilities ---------------------------------------------------


class ReplicationCapabilityIssueRequest(BaseModel):
    object_id: str = Field(..., min_length=1, max_length=128)
    target_server_id: str = Field(..., min_length=1, max_length=128)
    ciphertext_sha256: str
    ciphertext_size_bytes: int = Field(..., ge=0, le=_MAX_INT64, strict=True)

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)


class ReplicationCapabilityIssueResponse(BaseModel):
    capability: str = Field(
        ...,
        description="Opaque one-use capability; never valid for an ordinary owner call",
    )
    capability_id: str
    expires_at: str
    transfer_deadline: str
    target_placement_attempt: int


class ReplicationCapabilityConsumeRequest(BaseModel):
    capability: str = Field(..., min_length=1, max_length=512)
    source_signature: str = Field(
        ...,
        min_length=2,
        max_length=2048,
        description="Hex signature over the capability using the source's attested TLS key",
    )


class ReplicationCapabilityBinding(BaseModel):
    capability_id: str
    object_id: str
    volume_id: str
    source_server_id: str
    source_cert_pubkey_hash: str
    source_storage_incarnation: str
    target_server_id: str
    target_cert_pubkey_hash: str
    target_storage_incarnation: str
    target_placement_id: str
    target_placement_attempt: int
    expected_ciphertext_sha256: str
    expected_ciphertext_size_bytes: int
    expires_at: str
    transfer_deadline: str


class ReplicationCapabilityCompleteRequest(BaseModel):
    capability: str = Field(..., min_length=1, max_length=512)
    ciphertext_sha256: str
    ciphertext_size_bytes: int = Field(..., ge=0, le=_MAX_INT64, strict=True)

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_sha256(cls, value: str) -> str:
        return _canonical_sha256(value)


class ReplicationCapabilityFailureRequest(BaseModel):
    capability: str = Field(..., min_length=1, max_length=512)
    error: str = Field(..., min_length=1, max_length=256)


class ReplicationCapabilityResult(BaseModel):
    recorded: bool
    capability_id: str


# --- object-op grants (storage-node authorization for confidential object ops) -----------------


VALID_GRANT_OPS = ("put", "get", "list")


class GrantRequest(BaseModel):
    """A volume owner mints a short-lived grant authorizing storage TDs to serve object ops.

    Callers should request the minimal operation set. Replication uses a separate one-use validator
    capability and never accepts this owner grant.
    """

    volume_id: str
    ops: List[str] = Field(
        ...,
        min_length=1,
        description="Allowed object operations for the grant bearer (subset of put/get/list). "
        "Required and explicit so no request silently mints an all-ops bearer credential.",
    )

    @field_validator("ops")
    @classmethod
    def validate_ops(cls, v: List[str]) -> List[str]:
        unknown = [op for op in v if op not in VALID_GRANT_OPS]
        if unknown:
            raise ValueError(f"Unknown grant ops: {unknown}; allowed: {list(VALID_GRANT_OPS)}")
        if not v:
            raise ValueError("Grant must authorize at least one op.")
        unique = list(dict.fromkeys(v))
        if len(unique) != 1:
            raise ValueError(
                "Owner grants authorize exactly one operation; request separate grants."
            )
        return unique


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
