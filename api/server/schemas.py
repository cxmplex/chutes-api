"""
ORM definitions for servers and TDX attestations.
"""

import re
import uuid

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from datetime import datetime, timezone
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import (
    Column,
    Integer,
    BigInteger,
    Float,
    String,
    DateTime,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Text,
    Index,
    ForeignKeyConstraint,
    UniqueConstraint,
    case,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import JSONB
from typing import Dict, Any, List, Literal, Optional
from dataclasses import dataclass
from enum import Enum
from api.config import settings
from api.constants import (
    ATTESTATION_PROXY_HEALTH_PATH,
    ATTESTATION_PROXY_PORT,
    ServerHealthStatus,
)
from api.database import Base, generate_uuid
from api.host.schemas import TdQuoteCommitmentV1
from api.node.schemas import NodeArgs


class TeeInstanceEvidence(BaseModel):
    """TEE evidence for a single instance: TDX quote, GPU evidence (per-GPU dicts), and server certificate."""

    quote: str = Field(..., description="Base64-encoded TDX quote")
    gpu_evidence: List[Dict[str, Any]] = Field(
        ...,
        description="Per-GPU evidence: list of dicts (each GPU's evidence/certificate already structured; evidence fields are base64 where applicable)",
    )
    instance_id: Optional[str] = Field(
        None, description="Instance ID (present when part of a chute's evidence list)"
    )
    certificate: str = Field(
        ..., description="Base64-encoded DER format TLS certificate from the server"
    )


class NonceResponse(BaseModel):
    """Response model for nonce generation."""

    nonce: str
    expires_at: str
    context_sha256: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")


class BootAttestationArgs(BaseModel):
    """Request model for boot attestation of an already-registered server."""

    quote: str = Field(..., description="Base64 encoded TDX quote")
    server_id: str = Field(..., description="Registered server identity authorized by the nonce")


class BootAttestationResponse(BaseModel):
    """Capability-only response for successful boot attestation.

    Root/global disk key material is deliberately never returned here. The caller receives
    one exact-identity quote capability for generation-leased volume keys.
    """

    luks_quote_nonce: str


class RuntimeAttestationArgs(BaseModel):
    """Provider-neutral request model for runtime attestation."""

    quote: str = Field(..., description="Base64 encoded TDX quote or SEV-SNP report")
    tee_type: str = Field("tdx", description="'tdx' or 'sev-snp'")
    snp_cert_chain: Optional[str] = Field(
        None,
        description="Base64 SEV-SNP VCEK/ASK/ARK auxiliary chain when supplied by the platform",
    )
    vtpm_quote: Optional[Dict[str, Any]] = Field(
        None, description="GCE vTPM quote required by a GCP SNP measurement"
    )
    gpu_evidence: Optional[List[Dict[str, Any]]] = Field(
        None,
        min_length=1,
        max_length=64,
        description="Fresh NVIDIA evidence for a reservation-owned GPU runtime.",
    )


class RuntimeAttestationNonceContext(BaseModel):
    """Complete registered identity authorized for one runtime quote."""

    server_id: str
    miner_hotkey: str
    vm_name: str
    cert_hash: str
    role: Literal["compute", "storage"]
    compute_type: Literal["cpu", "gpu"]
    tee_type: str
    provider: Literal["gcp", "bare-metal"]
    deployment_model: Literal["gcp-model-a", "bare-metal-model-b", "bare-metal-direct"]
    host_id: Optional[str] = None
    measurement_name: str
    measurement_version: str
    measurement_config_fingerprint: str
    trust_set_fingerprint: str
    gpu_launch_reservation_id: Optional[str] = None
    gpu_allocation_group_id: Optional[str] = None
    gpu_allocation_group_generation: Optional[int] = Field(None, ge=1)
    gpu_host_boot_generation: Optional[int] = Field(None, ge=1)
    gpu_reservation_generation: Optional[int] = Field(None, ge=1)
    gpu_management_mode: Optional[Literal["platform", "miner"]] = None
    gpu_process_incarnation: Optional[str] = None
    gpu_topology_fingerprint: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")
    gpu_release_id: Optional[str] = None
    gpu_profile_id: Optional[str] = None
    gpu_chute_id: Optional[str] = None
    gpu_job_id: Optional[str] = None
    gpu_claims_sha256: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _exact_gpu_lineage(self) -> "RuntimeAttestationNonceContext":
        gpu_required = (
            self.gpu_launch_reservation_id,
            self.gpu_allocation_group_id,
            self.gpu_allocation_group_generation,
            self.gpu_host_boot_generation,
            self.gpu_reservation_generation,
            self.gpu_management_mode,
            self.gpu_process_incarnation,
            self.gpu_topology_fingerprint,
            self.gpu_release_id,
            self.gpu_profile_id,
            self.gpu_claims_sha256,
        )
        if self.compute_type == "gpu":
            present = [value is not None for value in gpu_required]
            if any(present) and not all(present):
                raise ValueError("GPU runtime nonce requires complete reservation lineage")
            if all(present) and (
                self.role != "compute" or self.deployment_model != "bare-metal-model-b"
            ):
                raise ValueError("GPU runtime nonce requires a Model-B compute server")
        elif any(
            value is not None for value in (*gpu_required, self.gpu_chute_id, self.gpu_job_id)
        ):
            raise ValueError("CPU runtime nonce cannot carry GPU reservation lineage")
        return self


class RuntimeAttestationResponse(BaseModel):
    """Response model for runtime attestation."""

    attestation_id: str
    verified_at: str
    status: str
    revocation_status: Dict[str, str]
    luks_quote_nonce: Optional[str] = None
    gpu_evidence_sha256: Optional[str] = None


class LuksCapabilityPurpose(str, Enum):
    """Distinct key-release capabilities; neither namespace is interchangeable."""

    BOOT = "boot_luks"
    STORAGE = "storage_luks"


class BootAttestationNonceContext(BaseModel):
    """Identity authorized by the miner before a boot quote nonce is issued."""

    purpose: Literal["boot_attestation"] = "boot_attestation"
    server_id: str
    miner_hotkey: str
    vm_name: str
    cert_hash: str
    storage_role: bool
    allowed_volumes: List[str]


class LuksCapabilityContext(BaseModel):
    """Server-bound context carried by an opaque LUKS capability."""

    purpose: LuksCapabilityPurpose
    server_id: str
    miner_hotkey: str
    vm_name: str
    cert_hash: str
    measurement_name: str
    measurement_version: str
    measurement_config_fingerprint: str
    trust_set_fingerprint: str
    tee_type: str
    storage_role: bool
    allowed_volumes: List[str]
    issued_volumes: Optional[List[str]] = None
    issued_generations: Optional[Dict[str, int]] = None
    issued_lease_ids: Optional[Dict[str, str]] = None

    @field_validator("allowed_volumes", "issued_volumes")
    @classmethod
    def validate_capability_volumes(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        from api.constants import SUPPORTED_LUKS_VOLUMES

        if not value or len(value) != len(set(value)):
            raise ValueError("capability volumes must be non-empty and unique")
        invalid = [volume for volume in value if volume not in SUPPORTED_LUKS_VOLUMES]
        if invalid:
            raise ValueError(f"unsupported capability volume(s): {invalid}")
        return value

    @model_validator(mode="after")
    def validate_issued_leases(self) -> "LuksCapabilityContext":
        """Keep quote capabilities and generation-confirm capabilities structurally distinct."""
        lease_maps = (self.issued_generations, self.issued_lease_ids)
        if self.issued_volumes is None:
            if any(value is not None for value in lease_maps):
                raise ValueError("quote capability cannot contain issued generation leases")
            return self

        expected = set(self.issued_volumes)
        if any(value is None for value in lease_maps):
            raise ValueError("confirm capability requires generation and lease-id maps")
        if (
            set(self.issued_generations or {}) != expected
            or set(self.issued_lease_ids or {}) != expected
        ):
            raise ValueError("confirm capability lease maps must match issued volumes")
        if any(
            not isinstance(generation, int) or isinstance(generation, bool) or generation < 1
            for generation in (self.issued_generations or {}).values()
        ):
            raise ValueError("issued generations must be positive integers")
        if any(not lease_id for lease_id in (self.issued_lease_ids or {}).values()):
            raise ValueError("issued lease ids must be non-empty")
        return self


class LuksVolumeGenerationLease(BaseModel):
    """Durable exclusive generation lease stored in ``vm_cache_configs`` JSONB."""

    generation: int = Field(..., ge=1)
    lease_id: str = Field(..., min_length=32, max_length=128)
    server_id: str
    miner_hotkey: str
    vm_name: str
    cert_hash: str
    measurement_name: str
    measurement_version: str
    measurement_config_fingerprint: str
    trust_set_fingerprint: str
    tee_type: str
    purpose: LuksCapabilityPurpose
    storage_role: bool
    promotion_required: bool


@dataclass
class LuksVolumeRotation:
    """Internal result of leasing one LUKS volume generation (not an API model)."""

    current: Optional[str]
    """Current active passphrase; None until the first-format pending key is promoted."""
    next: str
    """New pending passphrase the VM should add as a LUKS key slot."""
    generation: int
    """Exclusive generation allocated to this lease."""
    confirmed_generation: int
    """Last durably confirmed generation."""
    lease_id: str
    """Opaque lease identity carried only by the confirm capability."""
    lease_reused: bool
    """Whether this response reissued an unresolved lease instead of allocating a new one."""


@dataclass
class LuksAttestResult:
    """Internal result of process_luks_attest_request (not an API model)."""

    volumes: Dict[str, "LuksVolumeRotation"]
    confirm_nonce: str
    k3s_encryption_key: Optional[str] = None


@dataclass
class LuksConfirmResult:
    """Internal result of process_luks_confirm (not an API model)."""

    volumes: Dict[str, dict]
    """Per-volume outcome: promoted, confirmed, or already_confirmed plus generation."""


class LuksAttestRequest(BaseModel):
    """Request model for the sole LUKS key-release path."""

    quote: str = Field(
        ...,
        description="Base64-encoded runtime attestation (Intel TDX quote with RTMR3 extended, or an "
        "AMD SEV-SNP report), bound to the luks_quote_nonce + serving-cert pubkey hash.",
    )
    tee_type: str = Field(
        "tdx",
        description="TEE provider of the quote: 'tdx' (default) or 'sev-snp'. Selects the verifier so "
        "an SEV-SNP storage TD can obtain its persistent-volume key alongside Intel TDX VMs.",
    )
    snp_cert_chain: Optional[str] = Field(
        None,
        description="Base64 SEV-SNP VCEK->ASK->ARK chain (GCP inline auxblob); absent on bare-metal.",
    )
    vtpm_quote: Optional[Dict[str, Any]] = Field(
        None,
        description="GCE vTPM quote for GCP SNP image identity (absent on bare-metal/TDX).",
    )
    volumes: List[str] = Field(
        ..., description="Volume names requiring exclusive generation leases"
    )

    @field_validator("volumes")
    @classmethod
    def validate_volumes(cls, v: List[str]) -> List[str]:
        from api.constants import SUPPORTED_LUKS_VOLUMES

        if not v:
            raise ValueError("volumes must be non-empty")
        invalid = [vol for vol in v if vol not in SUPPORTED_LUKS_VOLUMES]
        if invalid:
            raise ValueError(
                f"Invalid volume name(s): {invalid}. Supported: {list(SUPPORTED_LUKS_VOLUMES)}"
            )
        return v


class LuksVolumeInfo(BaseModel):
    """Passphrase info for a single volume in the luks/attest response."""

    current: Optional[str] = Field(
        None,
        description="Current passphrase. None while the retained first-format pending key still "
        "requires promotion; on retry the disk may already open with next.",
    )
    next: str = Field(
        ..., description="New pending passphrase the VM should add as a LUKS key slot"
    )
    generation: int = Field(
        ...,
        ge=1,
        description="Exclusive generation allocated to this key-release lease.",
    )
    confirmed_generation: int = Field(
        ...,
        ge=0,
        description="Last durably confirmed generation. The mounted disk must match this floor, "
        "or the issued generation only when this is an unresolved-lease retry.",
    )
    lease_reused: bool = Field(
        ...,
        description="True when the validator retained and reissued the same unresolved key and "
        "generation instead of allocating another generation.",
    )


class LuksAttestResponse(BaseModel):
    """Response model for POST /luks/attest."""

    volumes: Dict[str, LuksVolumeInfo]
    confirm_nonce: str = Field(
        ...,
        description="Short-lived generation-bound nonce for exact, idempotent confirmation",
    )
    k3s_encryption_key: Optional[str] = Field(
        None,
        description="k3s encryption key (base64), returned only for a boot-LUKS capability "
        "that explicitly authorizes the storage volume",
    )


class LuksVolumeConfirmStatus(BaseModel):
    """Confirm status for a single volume."""

    rotated: bool = Field(
        ...,
        description="True if the pending passphrase now opens the volume and must be promoted; "
        "False when the existing current passphrase remains active.",
    )
    generation: int = Field(
        ...,
        ge=1,
        description="Exact leased generation durably written to the encrypted volume.",
    )


class LuksConfirmRequest(BaseModel):
    """Request model for POST /luks/confirm."""

    volumes: Dict[str, LuksVolumeConfirmStatus] = Field(
        ..., description="Per-volume rotation result reported by the VM"
    )


class LuksConfirmResponse(BaseModel):
    """Response model for POST /luks/confirm."""

    status: str
    volumes: Dict[str, Any]


class GpuInfraLeaseRequestV1(BaseModel):
    """Request one exact generation lease for the miner-only infrastructure volume."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-lease-request"] = "chutes.gpu-infra-lease-request"
    version: Literal[1] = 1
    legacy_vm_name: Optional[str] = Field(None, min_length=1, max_length=256)

    @field_validator("legacy_vm_name")
    @classmethod
    def validate_legacy_vm_name(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", value):
            raise ValueError("legacy_vm_name is not canonical")
        return value


class GpuInfraMigrationEntryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    source_volume: Literal["storage", "tdx-cache"]
    source_path: str = Field(..., pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
    destination_name: str = Field(..., pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    kind: Literal["file", "directory"]
    required: bool


class GpuInfraLegacySourceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: Literal["storage", "tdx-cache"]
    hotplug_serial: Literal["gpu-legacy-storage", "gpu-legacy-cache"]
    filesystem_type: Literal["xfs", "ext4"]
    luks_uuid: str = Field(
        ...,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    filesystem_uuid: str = Field(
        ...,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    generation: int = Field(..., ge=0)
    current: Optional[str]
    next: Optional[str]
    lease_generation: Optional[int] = Field(None, ge=1)


class GpuInfraLegacyMigrationV2(BaseModel):
    """One-use, two-volume legacy migration capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    migration_id: str
    legacy_server_id: str
    capability: str = Field(..., min_length=32, max_length=512)
    expires_at: str
    storage: GpuInfraLegacySourceV1
    cache: GpuInfraLegacySourceV1
    postgres_password: str = Field(..., min_length=16, max_length=256)
    required_entries: List[GpuInfraMigrationEntryV1]
    optional_entries: List[GpuInfraMigrationEntryV1]


class GpuInfraLeaseResponseV1(BaseModel):
    """Encrypted-volume keys and lineage for one staged gpu-infra generation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-lease"] = "chutes.gpu-infra-lease"
    version: Literal[1] = 1
    server_id: str
    volume_name: Literal["gpu-infra"] = "gpu-infra"
    lease_id: str
    generation: int = Field(..., ge=1)
    confirmed_generation: int = Field(..., ge=0)
    current: Optional[str]
    next: str
    active_key_slot: Optional[int] = Field(None, ge=0, le=7)
    next_key_slot: int = Field(..., ge=0, le=7)
    lease_expires_at: str
    lease_reused: bool
    awaiting_ack: bool
    rollback_generation: Optional[int] = Field(None, ge=1)
    rollback_key_slot: Optional[int] = Field(None, ge=0, le=7)
    rollback_key: Optional[str] = None
    retire_key_slot: Optional[int] = Field(None, ge=0, le=7)
    k3s_encryption_key: str
    legacy_migration: Optional[GpuInfraLegacyMigrationV2] = None

    @model_validator(mode="after")
    def validate_slots_and_generation(self) -> "GpuInfraLeaseResponseV1":
        if self.generation != self.confirmed_generation + 1:
            raise ValueError("gpu-infra generation must exactly follow the confirmed floor")
        if self.awaiting_ack:
            if self.next is None:
                raise ValueError("awaiting-ack gpu-infra lease must retain its pending key")
        elif self.active_key_slot is None:
            if self.current is not None:
                raise ValueError("first-format gpu-infra lease cannot carry a current key")
        elif self.current is None or self.active_key_slot == self.next_key_slot:
            raise ValueError("gpu-infra rotation key slots are invalid")
        rollback_values = (
            self.rollback_generation,
            self.rollback_key_slot,
            self.rollback_key,
        )
        if any(value is None for value in rollback_values) and any(
            value is not None for value in rollback_values
        ):
            raise ValueError("gpu-infra rollback generation, slot, and key must be paired")
        return self


class GpuInfraConfirmRequestV1(BaseModel):
    """Confirm the staged key and durable generation marker before old-key retirement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-confirm-request"] = "chutes.gpu-infra-confirm-request"
    version: Literal[1] = 1
    lease_id: str = Field(..., min_length=32, max_length=128)
    generation: int = Field(..., ge=1)
    active_key_slot: int = Field(..., ge=0, le=7)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class GpuInfraConfirmResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-confirmed"] = "chutes.gpu-infra-confirmed"
    version: Literal[1] = 1
    server_id: str
    lease_id: str
    generation: int = Field(..., ge=1)
    status: Literal["awaiting_ack"]


class GpuInfraAcknowledgeRequestV1(BaseModel):
    """Acknowledge that the prior key slot is absent after a confirmed rotation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-ack-request"] = "chutes.gpu-infra-ack-request"
    version: Literal[1] = 1
    lease_id: str = Field(..., min_length=32, max_length=128)
    generation: int = Field(..., ge=1)
    active_key_slot: int = Field(..., ge=0, le=7)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class GpuInfraAcknowledgeResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-current"] = "chutes.gpu-infra-current"
    version: Literal[1] = 1
    server_id: str
    generation: int = Field(..., ge=1)
    retire_key_slot: Optional[int] = Field(None, ge=0, le=7)
    status: Literal["current"]


class GpuInfraRetireRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-retire-request"] = "chutes.gpu-infra-retire-request"
    version: Literal[1] = 1
    generation: int = Field(..., ge=1)
    active_key_slot: int = Field(..., ge=0, le=7)
    retired_key_slot: int = Field(..., ge=0, le=7)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class GpuInfraRetireResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-retired"] = "chutes.gpu-infra-retired"
    version: Literal[1] = 1
    server_id: str
    generation: int = Field(..., ge=1)
    status: Literal["current"]


class GpuInfraAbandonRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-abandon-request"] = "chutes.gpu-infra-abandon-request"
    version: Literal[1] = 1
    lease_id: str = Field(..., min_length=32, max_length=128)
    generation: int = Field(..., ge=1)
    restored_generation: int = Field(..., ge=0)
    removed_key_slot: int = Field(..., ge=0, le=7)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class GpuInfraAbandonResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-abandoned"] = "chutes.gpu-infra-abandoned"
    version: Literal[1] = 1
    server_id: str
    confirmed_generation: int = Field(..., ge=0)
    status: Literal["current"]


class GpuInfraCloseRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-close-request"] = "chutes.gpu-infra-close-request"
    version: Literal[1] = 1
    generation: int = Field(..., ge=0)
    filesystem_synced: Literal[True]
    unmounted: Literal[True]
    mapper_closed: Literal[True]


class GpuInfraCloseResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-closed"] = "chutes.gpu-infra-closed"
    version: Literal[1] = 1
    server_id: str
    generation: int = Field(..., ge=0)
    status: Literal["closed"]


class GpuLegacyCloseRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-close-request"] = "chutes.gpu-legacy-close-request"
    version: Literal[1] = 1
    cutover_authorization: str = Field(..., min_length=32, max_length=512)
    target_host_id: str
    storage_luks_uuid: str
    storage_filesystem_uuid: str
    storage_generation: int = Field(..., ge=0)
    cache_luks_uuid: str
    cache_filesystem_uuid: str
    cache_filesystem_type: Literal["xfs", "ext4"]
    cache_generation: int = Field(..., ge=0)
    postgres_password: SecretStr = Field(..., min_length=16, max_length=256)
    workloads_stopped: Literal[True]
    postgres_stopped: Literal[True]
    filesystems_synced: Literal[True]
    filesystems_unmounted: Literal[True]
    storage_mapper_closed: Literal[True]
    cache_mapper_closed: Literal[True]

    @field_validator(
        "storage_luks_uuid",
        "storage_filesystem_uuid",
        "cache_luks_uuid",
        "cache_filesystem_uuid",
    )
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        canonical = str(uuid.UUID(value))
        if canonical != value:
            raise ValueError("legacy volume UUID must be canonical")
        return value


class GpuLegacyCloseResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-closed"] = "chutes.gpu-legacy-closed"
    version: Literal[1] = 1
    migration_id: str
    legacy_server_id: str
    status: Literal["guest_closed"]


class GpuLegacyCutoverAuthorizeRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-cutover-authorize"] = "chutes.gpu-legacy-cutover-authorize"
    version: Literal[1] = 1
    legacy_server_id: str = Field(..., min_length=1, max_length=256)


class GpuLegacyCutoverAuthorizeResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-cutover-authorization"] = (
        "chutes.gpu-legacy-cutover-authorization"
    )
    version: Literal[1] = 1
    authorization_id: str
    cutover_authorization: str
    legacy_server_id: str
    legacy_vm_name: str
    target_server_id: str
    target_host_id: str
    expires_at: str


class GpuLegacyHostConfirmRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-host-confirm"] = "chutes.gpu-legacy-host-confirm"
    version: Literal[1] = 1
    old_qemu_absent: Literal[True]
    storage_source_unowned: Literal[True]
    cache_source_unowned: Literal[True]
    storage_luks_uuid: str
    cache_luks_uuid: str


class GpuLegacyHostConfirmResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-legacy-ready"] = "chutes.gpu-legacy-ready"
    version: Literal[1] = 1
    migration_id: str
    status: Literal["ready"]


class GpuInfraMigrationPromoteRequestV1(BaseModel):
    """Exact durable copy summary, before either legacy source is discarded."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-promote"] = "chutes.gpu-infra-migration-promote"
    version: Literal[1] = 1
    migration_id: str = Field(..., min_length=1, max_length=128)
    capability: str = Field(..., min_length=32, max_length=512)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    marker: Dict[str, Any]
    content_summary: Dict[str, Any]


class GpuInfraMigrationRefreshRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-refresh"] = "chutes.gpu-infra-migration-refresh"
    version: Literal[1] = 1
    migration_id: str = Field(..., min_length=1, max_length=128)


class GpuInfraMigrationRefreshResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-capability"] = (
        "chutes.gpu-infra-migration-capability"
    )
    version: Literal[1] = 1
    server_id: str
    migration_id: str
    capability: str
    expires_at: str
    status: Literal["ready"]


class GpuInfraMigrationPromoteResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-promoted"] = "chutes.gpu-infra-migration-promoted"
    version: Literal[1] = 1
    server_id: str
    migration_id: str
    status: Literal["promoted"]


class GpuInfraMigrationCompleteRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-complete"] = "chutes.gpu-infra-migration-complete"
    version: Literal[1] = 1
    migration_id: str = Field(..., min_length=1, max_length=128)
    capability: str = Field(..., min_length=32, max_length=512)
    marker_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    storage_discarded: Literal[True]
    cache_discarded: Literal[True]


class GpuInfraMigrationCompleteResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal["chutes.gpu-infra-migration-finished"] = "chutes.gpu-infra-migration-finished"
    version: Literal[1] = 1
    server_id: str
    migration_id: str
    status: Literal["completed"]


class GpuAttestationArgs(BaseModel):
    evidence: str = Field(..., description="Base64 encoded GPU evidence")


class GpuAttestationResponse(BaseModel):
    attestation_id: str
    verified_at: str
    gpu_info: Dict[str, Any]  # GPU details from evidence


class NvidiaVerifiedDeviceV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attestation_certificate_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    architecture: str = Field(..., min_length=1, max_length=64)


class NvidiaVerificationResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema: Literal["chutes.nvidia-verification-result"]
    version: Literal[1]
    nonce: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    devices: List[NvidiaVerifiedDeviceV1] = Field(..., min_length=1, max_length=64)

    @model_validator(mode="after")
    def _unique_devices(self) -> "NvidiaVerificationResultV1":
        identities = [item.attestation_certificate_sha256 for item in self.devices]
        if identities != sorted(set(identities)):
            raise ValueError("verified NVIDIA device identities must be sorted unique")
        return self


class CpuServerRegistrationArgs(BaseModel):
    """Request body for 1-click CPU TEE server self-registration (POST /servers/cpu/register).

    The booted server self-submits its own runtime TDX quote + CPU benchmark. The Redis-issued
    attestation nonce travels in the X-Chutes-Nonce header, the owning miner hotkey in
    X-Chutes-Hotkey, and the miner-hotkey signature over
    "{hotkey}:{nonce}:cpu_register:{server_id}:{name}:{cert_hash}:{storage|compute}" (plus the
    release-target-token hash when present) in X-Chutes-Signature. The quote's report_data binds
    nonce || sha256(mTLS client cert pubkey), with the nonce derivation also binding that token.
    """

    model_config = ConfigDict(extra="forbid")

    server_id: str = Field(..., description="Stable server identifier (e.g. VM instance id)")
    name: Optional[str] = Field(None, description="Server name (defaults to server_id)")
    quote: str = Field(
        ...,
        description="Base64-encoded runtime attestation (configfs-tsm): an Intel TDX quote "
        "(tee_type='tdx') or an AMD SEV-SNP report (tee_type='sev-snp').",
    )
    tee_type: str = Field(
        "tdx", description="TEE provider for the quote: 'tdx' (default) or 'sev-snp'."
    )
    external_host: Optional[str] = Field(
        None,
        description="Model B: the public host that reaches this per-chute TD (the L0 host's public IP).",
    )
    external_ports: Optional[dict] = Field(
        None,
        description="Model B: the per-TD DNAT'd external ports (e.g. {'primary':31000,'logging':31001,"
        "'attestation':31002}); the validator advertises public_host:<ext> instead of the in-TD :8000.",
    )
    snp_cert_chain: Optional[str] = Field(
        None,
        description="Base64 SEV-SNP extended-report aux data (GHCB cert table: VCEK->ASK->ARK). "
        "Provided by the hypervisor on GCP; absent on bare-metal (validator fetches VCEK from KDS).",
    )
    vtpm_quote: Optional[Dict[str, Any]] = Field(
        None,
        description="GCE vTPM measured-boot quote for GCP SNP image identity: "
        "{ak_cert, quote_msg, quote_sig (base64), pcrs {idx: hex}, intermediate (base64, optional)}. "
        "Required when the matched SNP measurement config pins vtpm_pcrs (GCP); absent on bare-metal.",
    )
    benchmark: Dict[str, Any] = Field(..., description="sek8s CPU benchmark result JSON")
    endpoints: Optional[Dict[str, Any]] = Field(
        None,
        description="User-attestable reach info advertised by the in-TEE agent: "
        "{host, attest_port, provision_port, ssh_port, wg_port}; CPU/storage health probing is "
        "enabled only when this also contains an integer health_port and absolute health_path. "
        "Discovery convenience only.",
    )
    storage_role: bool = Field(
        False,
        description="ChuteFS: True when this TD is the always-on storage node (excluded from the CPU "
        "scheduler and from host-slot reaping; serves the decentralized storage network).",
    )
    launch_reservation: Optional[str] = Field(
        None,
        min_length=1,
        max_length=4096,
        description=(
            "Opaque one-use validator-created Model-B launch reservation. Model-A omits it."
        ),
    )
    quote_commitment: Optional[TdQuoteCommitmentV1] = Field(
        None,
        description=(
            "Versioned commitment bound into report_data: launch nonce, attested SPKI, "
            "reservation hash, release target, and boot generation."
        ),
    )
    td_signature: Optional[str] = Field(
        None,
        min_length=1,
        max_length=2048,
        description="Base64 signature by the attestation-bound TD serving key.",
    )
    disk_total_gb: Optional[int] = Field(
        None,
        description="ChuteFS storage TD: total durable disk capacity (GB) of its data volume.",
    )
    disk_free_gb: Optional[int] = Field(
        None,
        description="ChuteFS storage TD: currently free disk (GB) on its data volume.",
    )

    @field_validator("endpoints")
    @classmethod
    def validate_optional_health_endpoint(cls, endpoints):
        if not endpoints:
            return endpoints
        has_port = "health_port" in endpoints
        has_path = "health_path" in endpoints
        if has_port != has_path:
            raise ValueError("health_port and health_path must be supplied together")
        if not has_port:
            return endpoints
        port = endpoints["health_port"]
        path = endpoints["health_path"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("health_port must be an integer in 1..65535")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or len(path) > 256
            or any(character.isspace() for character in path)
        ):
            raise ValueError("health_path must be a bounded absolute path without whitespace")
        return endpoints

    @model_validator(mode="after")
    def _complete_model_b_reservation(self):
        values = (
            self.launch_reservation,
            self.quote_commitment,
            self.td_signature,
        )
        if any(value is not None for value in values) and not all(
            value is not None for value in values
        ):
            raise ValueError(
                "launch_reservation, quote_commitment, and td_signature must be supplied together"
            )
        return self


class CpuServerRegistrationResponse(BaseModel):
    """Response for a successful CPU TEE server self-registration."""

    server_id: str
    owner_hotkey: str
    measurement_version: Optional[str] = None
    measurement_name: str
    measurement_config_fingerprint: str
    trust_set_fingerprint: str
    revocation_status: Dict[str, str]
    benchmark_score: float
    verified_at: str
    status: str = "registered"
    # ChuteFS: the single-use nonce a self-registering storage TD must embed in its next quote to
    # call POST /{server_id}/luks/attest for its persistent data-volume key. Minted (and returned) only
    # for storage_role registrations.
    luks_quote_nonce: Optional[str] = None


class GpuRuntimeSessionResponse(BaseModel):
    server_id: str
    owner_hotkey: str
    runtime_session: str
    runtime_session_expires_at: str
    allowed_purposes: List[
        Literal[
            "cache",
            "gpu-infra",
            "instances",
            "launch",
            "miner",
            "nodes",
            "registry",
            "sockets",
        ]
    ]


class UntrustedGpuPciDevice(BaseModel):
    bdf: str = Field(..., pattern=r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
    vendor_id: Literal["10de"] = "10de"
    device_id: str = Field(..., pattern=r"^[0-9a-f]{4}$")

    model_config = ConfigDict(extra="forbid")


class UntrustedGpuInventory(BaseModel):
    configured_profile: str = Field(
        ..., min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )
    devices: List[UntrustedGpuPciDevice] = Field(default_factory=list, max_length=64)
    observed_count: int = Field(0, ge=0, le=64)
    expected_count: Optional[int] = Field(None, ge=1, le=64)
    profile_match: bool

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _count_matches_devices(self):
        if self.observed_count != len(self.devices):
            raise ValueError("observed_count must equal the reported PCI device count")
        return self


class HostRegistrationArgs(BaseModel):
    """Request body for Model-B L0 host registration (POST /hosts/register).

    The enrolled node-agent authenticates with its scoped Ed25519 host key over a server-issued,
    Redis-backed one-use challenge plus the exact method, path, and body hash. The launcher remains
    unattested; workload trust comes from each reservation-bound guest quote.
    """

    host_id: str = Field(
        ..., description="Stable launcher host id (e.g. hostname / GCP instance id)"
    )
    name: Optional[str] = Field(None, description="Host name (defaults to host_id)")
    capacity: int = Field(
        1,
        ge=0,
        le=64,
        description=(
            "Max concurrent per-chute TDs. Zero is valid only when storage_enabled reserves the "
            "host's sole TD slot."
        ),
    )
    storage_enabled: bool = Field(
        False,
        description="Whether this enrolled L0 runs the dedicated ChuteFS storage TD.",
    )
    storage_td_vcpus: Optional[int] = Field(
        None,
        ge=1,
        le=4096,
        description="Storage TD vCPU shape used for validator-owned launch-intent selection.",
    )
    storage_td_mem: Optional[str] = Field(
        None,
        pattern=r"^[1-9][0-9]*(?:G|M)$",
        max_length=32,
        description="Storage TD memory shape used for validator-owned launch-intent selection.",
    )
    default_mem: Optional[str] = Field(
        None,
        pattern=r"^[1-9][0-9]*(?:G|M)$",
        max_length=32,
        description="Default per-TD memory size class, e.g. 8G",
    )
    default_vcpus: Optional[int] = Field(
        None,
        ge=1,
        le=4096,
        description="Default per-TD vCPU size class",
    )
    external_host: Optional[str] = Field(
        None,
        min_length=1,
        max_length=253,
        pattern=r"^[A-Za-z0-9.:-]+$",
        description="Public IP/host advertised for chute TDs",
    )
    tee_type: str = Field(
        "tdx", description="TEE provider the host launches guests with: tdx|sev-snp"
    )
    compute_type: Literal["cpu", "gpu"] = Field(
        "cpu",
        description="Compute-scoped release identity for this enrolled launcher.",
    )
    netuid: Optional[int] = Field(None, description="Subnet netuid (defaults to the validator's)")
    specs: Optional[dict] = Field(
        None,
        description="Host hardware inventory reported by the agent: cpu/memory/baseboard/system/bios",
    )
    untrusted_gpu_inventory: Optional[UntrustedGpuInventory] = Field(
        None,
        description=(
            "GPU L0 host-reported PCI/topology inventory. Telemetry only; it never authorizes "
            "scheduling or substitutes for attested GPU evidence."
        ),
    )
    untrusted_gpu_inventory_ready: Optional[bool] = Field(
        None,
        description=(
            "Whether the untrusted launcher believes its configured GPU profile is present. "
            "Telemetry only."
        ),
    )
    disk_total_gb: Optional[int] = Field(
        None,
        ge=0,
        le=8_589_934_591,
        description="Physical disk capacity (GB) the host can back ChuteFS storage with.",
    )
    disk_free_gb: Optional[int] = Field(
        None,
        ge=0,
        le=8_589_934_591,
        description="Currently free physical disk (GB) on the host.",
    )
    l0_version: Optional[str] = Field(
        None,
        description="L0 host-image version this box is running (from /etc/chutes/l0-version).",
    )
    release_channel: str = Field(
        "stable",
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
        description="Guest-release channel this host follows from its first registration response.",
    )
    manifest_generation: Optional[int] = Field(
        None,
        ge=1,
        description="Last publisher-signed L0 manifest generation accepted by this launcher.",
    )
    host_boot_id: Optional[str] = Field(
        None,
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        description=(
            "Kernel boot UUID signed by the logical host key. The validator converts changes "
            "into a monotonic logical boot fence; this is not physical-host evidence."
        ),
    )

    @model_validator(mode="after")
    def _validate_zero_capacity_storage_enrollment(self):
        if self.compute_type == "gpu" and (
            self.tee_type != "tdx" or self.storage_enabled is not True
        ):
            raise ValueError("GPU hosts require TDX and storage_enabled=true")
        if self.compute_type == "cpu" and (
            self.untrusted_gpu_inventory is not None
            or self.untrusted_gpu_inventory_ready is not None
        ):
            raise ValueError("CPU hosts cannot report GPU L0 readiness telemetry")
        if self.compute_type == "gpu" and (
            self.untrusted_gpu_inventory is None
            or self.untrusted_gpu_inventory_ready is None
            or self.host_boot_id is None
        ):
            raise ValueError("GPU hosts must report explicit inventory readiness and host_boot_id")
        if self.compute_type == "cpu" and self.host_boot_id is not None:
            raise ValueError("CPU host registration must preserve the V1 boot contract")
        if self.capacity == 0 and not self.storage_enabled:
            raise ValueError("capacity=0 is valid only for an enrolled ChuteFS storage host")
        if (self.storage_td_vcpus is None) != (self.storage_td_mem is None):
            raise ValueError("storage_td_vcpus and storage_td_mem must be supplied together")
        if self.default_mem:
            multiplier = 1024**3 if self.default_mem.endswith("G") else 1024**2
            if int(self.default_mem[:-1]) * multiplier > 2**63 - 1:
                raise ValueError("default_mem exceeds the signed-int64 byte range")
        if (
            self.disk_total_gb is not None
            and self.disk_free_gb is not None
            and self.disk_free_gb > self.disk_total_gb
        ):
            raise ValueError("disk_free_gb cannot exceed disk_total_gb")
        return self


class HostRegistrationResponse(BaseModel):
    """Response for a successful L0 host registration."""

    host_id: str
    capacity: int
    status: str = "registered"
    # Fleet image releases: the active guest-image manifest for this host's tee_type, so a booting
    # host converges to the current release immediately (no separate poll on the first boot). None
    # when no release is active for the host's (channel, tee_type). Shape: api.releases.ReleaseManifest.
    release: Optional[Dict[str, Any]] = None
    trusted_storage_ready: Optional[bool] = None
    control_channel_eligible: Optional[bool] = None
    trusted_schedulable: Optional[bool] = None
    trusted_storage_reason: Optional[str] = None
    untrusted_gpu_inventory: Optional[Dict[str, Any]] = None
    untrusted_gpu_inventory_ready: Optional[bool] = None
    host_boot_generation: Optional[int] = Field(None, ge=1)
    gpu_inventory_report_generation: Optional[int] = Field(None, ge=0)


class ServerArgs(BaseModel):
    """Request model for server registration."""

    host: str = Field(..., description="Public IP address or DNS Name of the server")
    id: str = Field(..., description="Server ID (e.g. k8s node uid)")
    name: Optional[str] = Field(None, description="Server name (defaults to server id if omitted)")
    compute_type: str = Field(
        "gpu", description="Compute type for this server: 'gpu' (default) or 'cpu'"
    )
    gpus: Optional[list[NodeArgs]] = Field(
        None, description="GPU info for this server (None/omitted for CPU servers)"
    )

    @field_validator("compute_type")
    def validate_compute_type(cls, value):
        normalized = str(value or "gpu").lower()
        if normalized not in ("gpu", "cpu"):
            raise ValueError(f"Invalid compute_type: {value!r} (must be 'gpu' or 'cpu')")
        return normalized

    @model_validator(mode="after")
    def validate_gpus_for_compute_type(self):
        if self.compute_type == "gpu":
            if not self.gpus:
                raise ValueError("gpus is required for GPU servers (compute_type='gpu')")
        return self


class TeeChuteEvidence(BaseModel):
    """TEE evidence for a chute: list of evidence per instance (from instance evidence endpoints)."""

    evidence: List[TeeInstanceEvidence] = Field(
        ..., description="TEE evidence for each instance of the chute"
    )
    failed_instance_ids: List[str] = Field(
        default_factory=list,
        description="Instance IDs for which evidence could not be retrieved (instances still exist but evidence fetch failed)",
    )


class MaintenanceReason(BaseModel):
    """A single reason why maintenance eligibility was denied."""

    reason: str
    current_version: Optional[str] = None
    target_version: Optional[str] = None
    window_id: Optional[str] = None
    current_slots: Optional[int] = None
    limit: Optional[int] = None
    blocking: Optional[List[dict]] = None


class SoleSurvivorBlock(BaseModel):
    """An instance that is the sole active instance for its chute."""

    chute_id: str
    instance_id: str


class PreflightResult(BaseModel):
    """Result of a maintenance preflight eligibility check."""

    eligible: bool
    denial_reasons: List[MaintenanceReason] = Field(default_factory=list)
    blocking_chute_ids: List[SoleSurvivorBlock] = Field(default_factory=list)
    current_slots: int = 0
    limit: int = 1


class UpgradeWindowInfo(BaseModel):
    """Summary of an upgrade window for API responses."""

    id: str
    target_measurement_version: str
    upgrade_window_start: str
    upgrade_window_end: str
    max_concurrent_per_miner: int = 1


class ConfirmMaintenanceResult(BaseModel):
    """Result of confirming maintenance on a server."""

    server_id: str
    purged_instance_ids: List[str] = Field(default_factory=list)
    window: UpgradeWindowInfo


class ServerUpgradeStatus(BaseModel):
    """A TEE server and its version relative to the upgrade target."""

    server_id: str
    name: Optional[str] = None
    version: Optional[str] = None
    needs_upgrade: bool
    in_maintenance: bool


class MaintenancePolicyResponse(BaseModel):
    """Response for GET /servers/maintenance/policy."""

    active_window: Optional[UpgradeWindowInfo] = None
    window_open: bool = False
    current_slots: int = 0
    servers: List[ServerUpgradeStatus] = Field(default_factory=list)


class TeeMeasurementResponse(BaseModel):
    """Public response model for a single accepted TEE measurement configuration.

    Covers both providers: Intel TDX pins mrtd + boot/runtime RTMRs; AMD SEV-SNP (tee_type
    'sev-snp') pins a single launch measurement + policy + min_tcb (mrtd/rtmrs are empty).
    """

    version: str
    name: str
    tee_type: str = "tdx"
    provider: Optional[str] = None
    mrtd: str
    boot_rtmrs: Dict[str, str]
    runtime_rtmrs: Dict[str, str]
    profile_id: Optional[str] = None
    vcpus: Optional[int] = None
    memory_mib: Optional[int] = None
    expected_gpus: List[str]
    gpu_count: int
    # AMD SEV-SNP fields (null for TDX configs).
    measurement: Optional[str] = None
    policy: Optional[int] = None
    min_tcb: Optional[Dict[str, int]] = None
    processor_model: Optional[str] = None
    expected_vmpl: Optional[int] = None
    id_key_digest: Optional[str] = None
    vtpm_pcrs: Optional[Dict[str, str]] = None
    vtpm_security_flags: Optional[Dict[str, bool]] = None
    debug: bool
    image_sha256: Optional[str] = None
    image_measurement_names: Optional[List[str]] = None
    config_fingerprint: str
    trust_set_fingerprint: str


class BootAttestation(Base):
    """Track boot attestations whose identity was authorized from a registered server."""

    __tablename__ = "boot_attestations"

    attestation_id = Column(String, primary_key=True, default=generate_uuid)
    quote_data = Column(Text, nullable=False)  # Base64 encoded quote
    server_ip = Column(String, nullable=True)  # For later linking to server
    miner_hotkey = Column(String, nullable=True)
    vm_name = Column(String, nullable=True)
    verification_error = Column(String, nullable=True)
    measurement_version = Column(
        String, nullable=True
    )  # Matched TEE measurement config version (audit trail); NULL if verification failed
    measurement_name = Column(
        String, nullable=True
    )  # Exact matched pin name; required for release-completion trust decisions.
    measurement_config_fingerprint = Column(String(64), nullable=True)
    trust_set_fingerprint = Column(String(64), nullable=True)
    revocation_status = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    verified_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_boot_server_id", "server_ip"),
        Index("idx_boot_created", "created_at"),
        Index("idx_boot_verified", "verified_at"),
        Index("idx_boot_miner_vm", "miner_hotkey", "vm_name"),
    )


class TeeUpgradeWindow(Base):
    """Validator-managed maintenance window: one row per coordinated TEE image cutover."""

    __tablename__ = "tee_upgrade_windows"

    id = Column(String, primary_key=True, default=generate_uuid)
    upgrade_window_start = Column(DateTime(timezone=True), nullable=False)
    upgrade_window_end = Column(DateTime(timezone=True), nullable=False)
    target_measurement_version = Column(Text, nullable=False)
    max_concurrent_per_miner = Column(Integer, nullable=False, default=1, server_default="1")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    pending_servers = relationship(
        "Server",
        back_populates="pending_upgrade_window",
        foreign_keys="Server.maintenance_pending_window_id",
    )

    __table_args__ = (
        UniqueConstraint("target_measurement_version", name="uq_tee_upgrade_target"),
        CheckConstraint("upgrade_window_end > upgrade_window_start", name="chk_window_bounds"),
        Index(
            "idx_tee_upgrade_window_bounds",
            "upgrade_window_start",
            "upgrade_window_end",
        ),
    )


class Server(Base):
    """Main server entity (created after boot via CLI)."""

    __tablename__ = "servers"

    server_id = Column(String, primary_key=True)  # Provided by client (e.g. k8s node uid)
    ip = Column(String, nullable=False)  # Links to boot attestations
    miner_hotkey = Column(String, nullable=False)
    name = Column(
        String, nullable=False
    )  # Stable identity for LUKS linkage (unique with miner_hotkey)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    netuid = Column(Integer, nullable=False, default=64, server_default="64")

    is_tee = Column(Boolean, default=False, server_default="false")

    # Compute inventory: "gpu" (default) or "cpu" for GPU-less, CPU-only TEE servers.
    # For CPU servers, GPU Node rows are NOT created; capacity/benchmark live on the Server.
    compute_type = Column(String, nullable=False, default="gpu", server_default="gpu")
    # TEE provider for this server's attestation: "tdx" (default) or "sev-snp" (AMD). Stamped at
    # CPU self-registration; selects the verifier (dcap-qvl vs VCEK chain) for re-attestations.
    tee_type = Column(String, nullable=False, default="tdx", server_default="tdx")
    # Model B (per-chute): the L0 host derived from the consumed launch reservation, NULL for
    # standalone Model-A self-registrations. Guest-supplied host identity is not accepted.
    host_id = Column(String, nullable=True)
    # Seedless Model B: exact durable launch reservation consumed by this attested TD boot.
    # Model A rows remain NULL because they retain their independent miner-auth architecture.
    launch_reservation_id = Column(
        String,
        ForeignKey(
            "td_launch_reservations.reservation_id",
            name="fk_servers_launch_reservation",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    launch_boot_generation = Column(Integer, nullable=True)
    # GPU reservations intentionally use a separate claims/table contract from CPU V1.
    gpu_launch_reservation_id = Column(
        String,
        ForeignKey(
            "gpu_launch_reservations.reservation_id",
            name="fk_servers_gpu_launch_reservation",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    gpu_allocation_group_id = Column(
        String,
        ForeignKey(
            "gpu_allocation_groups.allocation_group_id",
            name="fk_servers_gpu_allocation_group",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    gpu_allocation_group_generation = Column(Integer, nullable=True)
    gpu_management_mode = Column(String, nullable=True)
    gpu_process_incarnation = Column(String, nullable=True)
    gpu_topology_fingerprint = Column(String(64), nullable=True)
    gpu_runtime_session_attestation_id = Column(String, nullable=True)
    gpu_runtime_session_expires_at = Column(DateTime(timezone=True), nullable=True)
    gpu_retired_at = Column(DateTime(timezone=True), nullable=True)
    gpu_retirement_reason = Column(Text, nullable=True)
    # Model B (per-chute): the public host + per-TD DNAT'd external ports (e.g. {"primary":31000,...})
    # reported by the in-guest agent from the config volume. The scheduler deploys with these so the
    # chute advertises the externally reachable public_host:<ext> rather than the in-TD :8000 (which
    # also keeps multiple TDs on one host from colliding on the unique (host, port) instance index).
    external_host = Column(String, nullable=True)
    external_ports = Column(JSONB, nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    ram_gb = Column(Integer, nullable=True)
    # Canonical CPU benchmark composite_score (used for pricing + scheduling); NULL for GPU.
    benchmark_score = Column(Float, nullable=True)
    # Raw CPU benchmark result JSON (sek8s schema); NULL for GPU servers.
    benchmark = Column(JSONB, nullable=True)

    # Maintenance: set at confirm, cleared on successful boot completion or lazily when window closes.
    maintenance_pending_window_id = Column(
        String,
        ForeignKey("tee_upgrade_windows.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Current attested measurement version, updated on every successful boot attestation.
    version = Column(Text, nullable=True)
    # Exact latest matched pin name. Version alone is not a release identity because multiple
    # providers, roles, images, and vCPU classes can share a version string.
    measurement_name = Column(Text, nullable=True)
    # Canonical identity of every security field in the exact matched pin, and of the full active
    # trust set at verification time. Legacy rows remain NULL and are never treated as current.
    measurement_config_fingerprint = Column(String(64), nullable=True)
    trust_set_fingerprint = Column(String(64), nullable=True)
    # Latest successful quote's authenticated revocation outcomes. The explicit
    # revocation_not_advertised value is auditable and never represented as a successful check.
    attestation_revocation_status = Column(JSONB, nullable=True)

    # True for 1-click CPU servers that self-registered via POST /servers/cpu/register
    # (the server attested + checked in itself), vs servers advertised by a miner control plane.
    self_registered = Column(Boolean, default=False, server_default="false")

    # Attestation-bound TLS serving cert (PEM) for self-registered CPU TEE servers. The cert's
    # public-key hash is bound into the registration TDX quote report_data (verify_quote), so it is
    # the attested TLS identity of the TD. Pinned as the instance cacert so the validator<->chute
    # user-data transport is TLS terminated inside the attested TD (host cannot MITM/read/tamper).
    attested_cert = Column(Text, nullable=True)

    # User-attestable instance reach info advertised by the in-TEE agent at registration:
    # {"host": <public ip/host>, "attest_port", "provision_port", "ssh_port", "wg_port"}. The
    # owner-authenticated GET /servers/cpu/{id}/connection returns this (plus a minted provision
    # token + manifest) so `chutes ssh/connect <id>` can find + attest the instance with no flags.
    # Pure discovery convenience -- trust still comes from the client-side attestation, not this.
    tee_endpoints = Column(JSONB, nullable=True)

    # sha256 of the attestation-bound serving-cert pubkey (DER SPKI), == the report_data cert hash
    # verified at registration. Indexed so a peer presenting its attested mTLS cert maps to its row
    # (ChuteFS peer directory / cert authority / attested-caller auth).
    attested_cert_pubkey_hash = Column(String, nullable=True)
    # ChuteFS: True for the always-on attested "storage TD" that runs on every bare-metal L0 host
    # and serves the decentralized storage network. A storage-role server is NEVER a candidate for
    # the CPU scheduler (it is not a user-chute slot) and is exempt from the host-slot reconcile
    # reaping; it advertises durable disk capacity below.
    storage_role = Column(Boolean, nullable=False, default=False, server_default="false")
    # Durable disk capacity (GB) of the storage TD's persistent ChuteFS data volume. disk_free_gb is
    # refreshed on announce/heartbeat so the tracker can place replicas on TDs with room.
    disk_total_gb = Column(Integer, nullable=True)
    disk_free_gb = Column(Integer, nullable=True)
    # Generated once and persisted inside the encrypted ChuteFS filesystem. A replacement/wiped disk
    # therefore gets a new value even when the storage TD reuses the same deterministic server_id.
    storage_incarnation = Column(String, nullable=True)
    storage_incarnation_announced_at = Column(DateTime(timezone=True), nullable=True)
    # Reconciliation alone advances model-directory identity/order. An exact-identity authenticated
    # inventory heartbeat may refresh freshness without letting a replacement cert or disk inherit it.
    model_inventory_storage_incarnation = Column(String, nullable=True)
    model_inventory_cert_pubkey_hash = Column(String, nullable=True)
    model_inventory_snapshot_started_at = Column(DateTime(timezone=True), nullable=True)
    model_inventory_snapshot_id = Column(String, nullable=True)
    model_inventory_fresh_at = Column(DateTime(timezone=True), nullable=True)
    last_health_at = Column(DateTime(timezone=True), nullable=True)

    @property
    def in_maintenance(self) -> bool:
        return self.maintenance_pending_window_id is not None

    @property
    def health_check_url(self) -> Optional[str]:
        """Return only a health endpoint represented for this server's role.

        Legacy GPU TEE servers use the historical attestation-proxy endpoint. CPU and
        storage rows are never sent there implicitly; they must advertise an explicit
        health_port and health_path in tee_endpoints.
        """
        if self.compute_type == "gpu" and self.gpu_retired_at is not None:
            return None
        if self.compute_type == "cpu" or self.storage_role:
            endpoints = self.tee_endpoints or {}
            port = endpoints.get("health_port")
            path = endpoints.get("health_path")
            if (
                not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65535
                or not isinstance(path, str)
                or not path.startswith("/")
                or path.startswith("//")
            ):
                return None
            return f"https://{self.ip}:{port}{path}"
        return f"https://{self.ip}:{ATTESTATION_PROXY_PORT}{ATTESTATION_PROXY_HEALTH_PATH}"

    @hybrid_property
    def health_status(self) -> ServerHealthStatus:
        if self.last_health_at is None:
            return ServerHealthStatus.UNKNOWN
        observed_at = self.last_health_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - observed_at).total_seconds()
        if age >= settings.server_health_offline_threshold_seconds:
            return ServerHealthStatus.OFFLINE
        if age >= settings.server_health_degraded_threshold_seconds:
            return ServerHealthStatus.DEGRADED
        return ServerHealthStatus.HEALTHY

    @health_status.expression
    def health_status(cls):
        age = func.extract("epoch", func.now() - cls.last_health_at)
        return case(
            (cls.last_health_at.is_(None), ServerHealthStatus.UNKNOWN.value),
            (
                age >= settings.server_health_offline_threshold_seconds,
                ServerHealthStatus.OFFLINE.value,
            ),
            (
                age >= settings.server_health_degraded_threshold_seconds,
                ServerHealthStatus.DEGRADED.value,
            ),
            else_=ServerHealthStatus.HEALTHY.value,
        )

    # Relationships
    nodes = relationship("Node", back_populates="server", cascade="all, delete-orphan")
    runtime_attestations = relationship(
        "ServerAttestation", back_populates="server", cascade="all, delete-orphan"
    )
    miner = relationship("MetagraphNode", back_populates="servers")
    pending_upgrade_window = relationship(
        "TeeUpgradeWindow",
        back_populates="pending_servers",
        foreign_keys=[maintenance_pending_window_id],
    )

    __table_args__ = (
        Index("idx_server_miner", "miner_hotkey"),
        Index("idx_servers_miner_name", "miner_hotkey", "name", unique=True),
        Index(
            "uq_servers_attested_pubkey",
            func.lower(attested_cert_pubkey_hash),
            unique=True,
            postgresql_where=attested_cert_pubkey_hash.isnot(None),
        ),
        Index(
            "idx_servers_maintenance_pending",
            "miner_hotkey",
            postgresql_where=maintenance_pending_window_id.isnot(None),
        ),
        Index(
            "idx_servers_model_inventory_fresh",
            "model_inventory_fresh_at",
            "server_id",
            postgresql_where=storage_role.is_(True),
        ),
        Index("idx_servers_last_health", "last_health_at"),
        Index(
            "uq_servers_launch_reservation",
            "launch_reservation_id",
            unique=True,
            postgresql_where=launch_reservation_id.isnot(None),
        ),
        Index(
            "uq_servers_gpu_launch_reservation",
            "gpu_launch_reservation_id",
            unique=True,
            postgresql_where=gpu_launch_reservation_id.isnot(None),
        ),
        CheckConstraint(
            "(launch_reservation_id IS NULL AND launch_boot_generation IS NULL) OR "
            "(launch_reservation_id IS NOT NULL AND launch_boot_generation > 0)",
            name="ck_servers_launch_reservation_generation",
        ),
        CheckConstraint(
            "(gpu_launch_reservation_id IS NULL "
            "AND gpu_allocation_group_id IS NULL "
            "AND gpu_allocation_group_generation IS NULL "
            "AND gpu_management_mode IS NULL "
            "AND gpu_process_incarnation IS NULL "
            "AND gpu_topology_fingerprint IS NULL) OR "
            "(compute_type = 'gpu' AND gpu_launch_reservation_id IS NOT NULL "
            "AND gpu_allocation_group_id IS NOT NULL "
            "AND gpu_allocation_group_generation > 0 "
            "AND gpu_management_mode IN ('platform', 'miner') "
            "AND gpu_process_incarnation IS NOT NULL "
            "AND gpu_topology_fingerprint ~ '^[0-9a-f]{64}$')",
            name="ck_servers_gpu_launch_identity",
        ),
        CheckConstraint(
            "(gpu_runtime_session_attestation_id IS NULL "
            "AND gpu_runtime_session_expires_at IS NULL) OR "
            "(gpu_launch_reservation_id IS NOT NULL "
            "AND gpu_runtime_session_attestation_id IS NOT NULL "
            "AND gpu_runtime_session_expires_at IS NOT NULL)",
            name="ck_servers_gpu_runtime_session",
        ),
        CheckConstraint(
            "("
            "model_inventory_fresh_at IS NULL "
            "AND model_inventory_storage_incarnation IS NULL "
            "AND model_inventory_cert_pubkey_hash IS NULL "
            "AND model_inventory_snapshot_started_at IS NULL "
            "AND model_inventory_snapshot_id IS NULL"
            ") OR ("
            "model_inventory_fresh_at IS NOT NULL "
            "AND model_inventory_storage_incarnation IS NOT NULL "
            "AND model_inventory_cert_pubkey_hash IS NOT NULL "
            "AND model_inventory_snapshot_started_at IS NOT NULL "
            "AND model_inventory_snapshot_id IS NOT NULL"
            ")",
            name="ck_servers_model_inventory_marker",
        ),
        ForeignKeyConstraint(
            ["netuid", "miner_hotkey"],
            ["metagraph_nodes.netuid", "metagraph_nodes.hotkey"],
        ),
    )


class Host(Base):
    """Model B: a bare-metal L0 launcher host (the one-click-miner appliance / node-agent).

    A host is NOT attested -- it is a launcher only. One-use miner enrollment establishes scoped,
    persistent logical-host keys; those cloneable credentials never prove physical placement.
    Workload trust comes from each launched TD's reservation-bound attestation.
    """

    __tablename__ = "hosts"

    host_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    miner_hotkey = Column(String, nullable=False)
    netuid = Column(Integer, nullable=False, default=64, server_default="64")
    # TEE provider this host launches per-chute guests with: "tdx" | "sev-snp".
    tee_type = Column(String, nullable=False, default="tdx", server_default="tdx")
    # Release/scheduler compute stream. Existing Model-B hosts are CPU launchers; GPU L0s use a
    # distinct stream even when both are TDX and follow the same named channel.
    compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    # Max concurrent per-chute TDs (slot pool size on the node-agent).
    capacity = Column(Integer, nullable=False, default=1, server_default="1")
    # Raw host-requested capacity. GPU capacity remains validator-clamped to zero until the exact
    # CPU/storage sibling reservation, attestation, incarnation, and liveness are current.
    reported_capacity = Column(Integer, nullable=False, default=1, server_default="1")
    # Signed L0 enrollment state. Allows a one-slot storage appliance to advertise zero schedulable
    # chute slots without letting ordinary compute hosts misuse capacity=0 registration.
    storage_enabled = Column(Boolean, nullable=False, default=False, server_default="false")
    storage_td_vcpus = Column(Integer, nullable=True)
    storage_td_mem = Column(String, nullable=True)
    # Desired-state channel followed by this logical L0 target. Release activation snapshots only
    # hosts enrolled in the release's channel.
    release_channel = Column(String, nullable=False, default="stable", server_default="stable")
    # Default per-TD size class (overridable per launch); must match a pinned per-size-class measurement.
    default_mem = Column(String, nullable=True)
    default_vcpus = Column(Integer, nullable=True)
    # Public IP/host the host advertises for its chute TDs (DNAT'd per-slot ports).
    external_host = Column(String, nullable=True)
    # Auto-discovered hardware inventory reported by the node-agent (NOT attested -- informational).
    # cpu_cores/ram_gb are denormalized for querying; full detail (cpu/memory/baseboard/system/bios)
    # lives in the specs JSONB.
    cpu_cores = Column(Integer, nullable=True)
    ram_gb = Column(Integer, nullable=True)
    specs = Column(JSONB, nullable=True)
    untrusted_gpu_inventory = Column(JSONB, nullable=True)
    untrusted_gpu_inventory_ready = Column(Boolean, nullable=True)
    # Physical disk inventory (GB) reported by the node-agent (informational; the host is not
    # attested). Tells the validator how much durable storage this host can back for ChuteFS.
    disk_total_gb = Column(Integer, nullable=True)
    disk_free_gb = Column(Integer, nullable=True)
    # Fleet image releases: the guest-image digests this host most recently reported it has staged
    # (from the node-agent heartbeat), e.g. {"chute": {"sha256": ...}, "storage": {"sha256": ...}}.
    # Untrusted telemetry only (the host is not attested). Fresh exact ServerAttestation identities
    # can establish aggregate role/measurement counts, but neither this field nor guest-supplied
    # Server.host_id proves physical-host convergence or makes prior pins safe to prune.
    staged_images = Column(JSONB, nullable=True)
    # The L0 host-image version this box is running (from /etc/chutes/l0-version, reported at
    # registration + heartbeat) -- lets the validator tell which L0 a box booted and drive re-netboot
    # updates (publish a new squashfs + reboot -> box comes up reporting the new version).
    l0_version = Column(String, nullable=True)
    # Seedless logical-host enrollment state. These fields describe a cloneable credential, never
    # a physical host or trusted placement identity.
    enrollment_generation = Column(Integer, nullable=True)
    active_key_generation = Column(Integer, nullable=True)
    provisioning_state = Column(String, nullable=False, default="legacy", server_default="legacy")
    last_accepted_manifest_generation = Column(Integer, nullable=True)
    enrolled_at = Column(DateTime(timezone=True), nullable=True)
    identity_durable_at = Column(DateTime(timezone=True), nullable=True)
    identity_metadata_sha256 = Column(String(64), nullable=True)
    steady_config_sha256 = Column(String(64), nullable=True)
    provisioning_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    provisioning_status = Column(JSONB, nullable=True)
    # Signed logical-host telemetry. boot_generation is validator-owned but, like the
    # enrolled host key, does not establish physical-host placement.
    boot_id = Column(String, nullable=True)
    boot_generation = Column(Integer, nullable=False, default=0, server_default="0")
    gpu_inventory_report_generation = Column(Integer, nullable=False, default=0, server_default="0")
    gpu_inventory_fingerprint = Column(String(64), nullable=True)
    gpu_inventory_reconciled_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("capacity >= 0", name="ck_hosts_capacity_nonnegative"),
        CheckConstraint(
            "reported_capacity BETWEEN 0 AND 64",
            name="ck_hosts_reported_capacity",
        ),
        CheckConstraint(
            "capacity > 0 OR storage_enabled IS TRUE",
            name="ck_hosts_zero_capacity_storage_only",
        ),
        CheckConstraint(
            "(storage_td_vcpus IS NULL AND storage_td_mem IS NULL) OR "
            "(storage_td_vcpus BETWEEN 1 AND 4096 "
            "AND storage_td_mem ~ '^[1-9][0-9]*(G|M)$')",
            name="ck_hosts_storage_td_profile",
        ),
        Index("idx_hosts_miner", "miner_hotkey"),
        Index(
            "idx_hosts_release_targeting",
            "release_channel",
            "tee_type",
            "compute_type",
        ),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu')",
            name="ck_hosts_compute_type",
        ),
        CheckConstraint(
            "compute_type = 'cpu' OR tee_type = 'tdx'",
            name="ck_hosts_gpu_tdx",
        ),
        CheckConstraint(
            "provisioning_state IN ('legacy', 'unclaimed', 'persisting_identity', "
            "'awaiting_pcs', 'ready', 'revoked')",
            name="ck_hosts_provisioning_state",
        ),
        CheckConstraint(
            "(identity_durable_at IS NULL AND identity_metadata_sha256 IS NULL "
            "AND steady_config_sha256 IS NULL) OR "
            "(identity_durable_at IS NOT NULL "
            "AND identity_metadata_sha256 ~ '^[0-9a-f]{64}$' "
            "AND steady_config_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_hosts_identity_durability",
        ),
        CheckConstraint(
            "(enrollment_generation IS NULL AND active_key_generation IS NULL) OR "
            "(enrollment_generation > 0 AND active_key_generation > 0)",
            name="ck_hosts_enrollment_generations",
        ),
        CheckConstraint(
            "(boot_id IS NULL AND boot_generation = 0) OR "
            "(boot_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            "[0-9a-f]{4}-[0-9a-f]{12}$' AND boot_generation > 0)",
            name="ck_hosts_boot_generation",
        ),
        CheckConstraint(
            "gpu_inventory_report_generation >= 0 "
            "AND (gpu_inventory_fingerprint IS NULL "
            "OR gpu_inventory_fingerprint ~ '^[0-9a-f]{64}$')",
            name="ck_hosts_gpu_inventory_generation",
        ),
    )


class ServerAttestation(Base):
    """Track runtime attestations (post-registration)."""

    __tablename__ = "server_attestations"

    attestation_id = Column(String, primary_key=True, default=generate_uuid)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    quote_data = Column(Text, nullable=True)  # Base64 encoded quote
    verification_error = Column(String, nullable=True)
    measurement_version = Column(
        String, nullable=True
    )  # Matched TEE measurement config version (audit trail); NULL if verification failed
    measurement_name = Column(
        String, nullable=True
    )  # Exact matched pin name; NULL when no config matched or verification failed early.
    measurement_config_fingerprint = Column(String(64), nullable=True)
    trust_set_fingerprint = Column(String(64), nullable=True)
    revocation_status = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    verified_at = Column(DateTime(timezone=True), nullable=True)
    gpu_retired_at = Column(DateTime(timezone=True), nullable=True)
    gpu_evidence = Column(JSONB, nullable=True)
    gpu_evidence_sha256 = Column(String(64), nullable=True)
    gpu_evidence_certificate_sha256s = Column(JSONB, nullable=True)
    gpu_launch_reservation_id = Column(String, nullable=True)
    gpu_allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=True,
    )
    gpu_allocation_group_generation = Column(Integer, nullable=True)
    gpu_host_boot_generation = Column(Integer, nullable=True)
    gpu_reservation_generation = Column(Integer, nullable=True)
    gpu_management_mode = Column(String, nullable=True)
    gpu_process_incarnation = Column(String, nullable=True)
    gpu_topology_fingerprint = Column(String(64), nullable=True)
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    gpu_profile_id = Column(String, nullable=True)
    gpu_chute_id = Column(String, nullable=True)
    gpu_job_id = Column(String, nullable=True)
    gpu_claims_sha256 = Column(String(64), nullable=True)

    server = relationship("Server", back_populates="runtime_attestations")

    __table_args__ = (
        Index("idx_attestation_server", "server_id"),
        Index("idx_attestation_created", "created_at"),
        Index("idx_attestation_verified", "verified_at"),
        Index(
            "idx_server_attestations_release_identity",
            server_id,
            created_at.desc(),
            attestation_id.desc(),
            postgresql_include=[
                "measurement_name",
                "measurement_version",
                "measurement_config_fingerprint",
                "trust_set_fingerprint",
                "verification_error",
                "verified_at",
            ],
        ),
        CheckConstraint(
            "(gpu_launch_reservation_id IS NULL "
            "AND gpu_allocation_group_id IS NULL "
            "AND gpu_allocation_group_generation IS NULL "
            "AND gpu_host_boot_generation IS NULL "
            "AND gpu_reservation_generation IS NULL "
            "AND gpu_management_mode IS NULL "
            "AND gpu_process_incarnation IS NULL "
            "AND gpu_topology_fingerprint IS NULL "
            "AND gpu_release_id IS NULL "
            "AND gpu_profile_id IS NULL "
            "AND gpu_chute_id IS NULL "
            "AND gpu_job_id IS NULL "
            "AND gpu_claims_sha256 IS NULL "
            "AND gpu_evidence IS NULL "
            "AND gpu_evidence_sha256 IS NULL "
            "AND gpu_evidence_certificate_sha256s IS NULL) OR "
            "(gpu_launch_reservation_id IS NOT NULL "
            "AND gpu_allocation_group_id IS NOT NULL "
            "AND gpu_allocation_group_generation > 0 "
            "AND gpu_host_boot_generation > 0 "
            "AND gpu_reservation_generation > 0 "
            "AND gpu_management_mode IN ('platform', 'miner') "
            "AND gpu_process_incarnation IS NOT NULL "
            "AND gpu_topology_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND gpu_release_id IS NOT NULL "
            "AND gpu_profile_id IS NOT NULL "
            "AND gpu_claims_sha256 ~ '^[0-9a-f]{64}$' "
            "AND gpu_evidence IS NOT NULL "
            "AND gpu_evidence_sha256 ~ '^[0-9a-f]{64}$' "
            "AND jsonb_typeof(gpu_evidence_certificate_sha256s) = 'array' "
            "AND (verification_error IS NOT NULL "
            "OR jsonb_array_length(gpu_evidence_certificate_sha256s) > 0))",
            name="ck_server_attestation_gpu_lineage",
        ),
        Index(
            "idx_server_attestations_gpu_lineage",
            "gpu_launch_reservation_id",
            "gpu_allocation_group_id",
            created_at.desc(),
            postgresql_where=gpu_launch_reservation_id.isnot(None),
        ),
    )


class VmCacheConfig(Base):
    """Track LUKS volume encryption passphrases by VM configuration (JSONB: volume name -> encrypted passphrase)."""

    __tablename__ = "vm_cache_configs"

    miner_hotkey = Column(String, primary_key=True)
    vm_name = Column(String, primary_key=True)
    volume_passphrases = Column(JSONB, nullable=False, default=dict)
    # Last-confirmed monotonic generation floor {volume_name: int}.
    volume_epochs = Column(JSONB, nullable=False, default=dict, server_default="{}")
    # Exclusive unresolved generation leases. Each entry binds generation + pending passphrase
    # custody to the registered server, attested cert capability, and exact measurement.
    volume_generation_leases = Column(JSONB, nullable=False, default=dict, server_default="{}")
    k3s_encryption_key = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_boot_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_vm_cache_miner", "miner_hotkey"),
        Index("idx_vm_cache_last_boot", "last_boot_at"),
    )


class GpuMinerIdentity(Base):
    """Validator-owned logical identity for one miner-managed whole GPU fabric."""

    __tablename__ = "gpu_miner_identities"

    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), primary_key=True)
    server_id = Column(String, nullable=False, unique=True)
    owner_hotkey = Column(String, nullable=False)
    legacy_vm_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class GpuLegacyCutoverAuthorization(Base):
    __tablename__ = "gpu_legacy_cutover_authorizations"

    authorization_id = Column(String, primary_key=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    owner_hotkey = Column(String, nullable=False)
    legacy_server_id = Column(
        String,
        ForeignKey("servers.server_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    legacy_vm_name = Column(String, nullable=False)
    target_server_id = Column(String, nullable=False, unique=True)
    state = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    migration_id = Column(
        String,
        ForeignKey("gpu_legacy_migrations.migration_id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "(state = 'issued' AND consumed_at IS NULL AND migration_id IS NULL) OR "
            "(state = 'consumed' AND consumed_at IS NOT NULL AND migration_id IS NOT NULL)",
            name="ck_gpu_legacy_cutover_state",
        ),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_legacy_cutover_hash",
        ),
    )


class GpuLegacyMigration(Base):
    __tablename__ = "gpu_legacy_migrations"

    migration_id = Column(String, primary_key=True)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    owner_hotkey = Column(String, nullable=False)
    legacy_server_id = Column(
        String,
        ForeignKey("servers.server_id", ondelete="RESTRICT"),
        nullable=False,
    )
    legacy_vm_name = Column(String, nullable=False)
    target_server_id = Column(String, nullable=False)
    state = Column(String, nullable=False)
    close_attestation_id = Column(
        String,
        ForeignKey("server_attestations.attestation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    close_cert_hash = Column(String(64), nullable=False)
    storage_luks_uuid = Column(String, nullable=False)
    storage_filesystem_uuid = Column(String, nullable=False)
    storage_generation = Column(Integer, nullable=False)
    storage_current_passphrase = Column(Text, nullable=True)
    storage_pending_passphrase = Column(Text, nullable=True)
    storage_lease = Column(JSONB, nullable=True)
    cache_luks_uuid = Column(String, nullable=False)
    cache_filesystem_uuid = Column(String, nullable=False)
    cache_filesystem_type = Column(String, nullable=False)
    cache_generation = Column(Integer, nullable=False)
    cache_current_passphrase = Column(Text, nullable=True)
    cache_pending_passphrase = Column(Text, nullable=True)
    cache_lease = Column(JSONB, nullable=True)
    k3s_encryption_key = Column(Text, nullable=True)
    postgres_password = Column(Text, nullable=True)
    required_entries = Column(JSONB, nullable=False)
    optional_entries = Column(JSONB, nullable=False)
    guest_closed_at = Column(DateTime(timezone=True), nullable=False)
    host_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    source_capability_hash = Column(String(64), nullable=True)
    source_capability_expires_at = Column(DateTime(timezone=True), nullable=True)
    source_capability_consumed_at = Column(DateTime(timezone=True), nullable=True)
    promoted_marker_sha256 = Column(String(64), nullable=True)
    promoted_summary = Column(JSONB, nullable=True)
    promoted_at = Column(DateTime(timezone=True), nullable=True)
    discarded_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "owner_hotkey",
            "legacy_server_id",
            name="uq_gpu_legacy_migration_source",
        ),
        UniqueConstraint(
            "target_server_id",
            name="uq_gpu_legacy_migration_target",
        ),
        CheckConstraint(
            "state IN ('guest_closed', 'ready', 'leased', 'promoted', 'completed', 'abandoned')",
            name="ck_gpu_legacy_migration_state",
        ),
        CheckConstraint(
            "storage_generation >= 0 AND cache_generation >= 0",
            name="ck_gpu_legacy_migration_generations",
        ),
        CheckConstraint(
            "close_cert_hash ~ '^[0-9a-f]{64}$' "
            "AND storage_luks_uuid ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND storage_filesystem_uuid ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND cache_luks_uuid ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND cache_filesystem_uuid ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND cache_filesystem_type IN ('xfs', 'ext4') "
            "AND (source_capability_hash IS NULL "
            "OR source_capability_hash ~ '^[0-9a-f]{64}$') "
            "AND (promoted_marker_sha256 IS NULL "
            "OR promoted_marker_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_legacy_migration_digests",
        ),
        CheckConstraint(
            "jsonb_typeof(required_entries) = 'array' "
            "AND jsonb_array_length(required_entries) > 0 "
            "AND jsonb_typeof(optional_entries) = 'array'",
            name="ck_gpu_legacy_migration_entries",
        ),
        CheckConstraint(
            "(state = 'guest_closed' AND host_confirmed_at IS NULL) "
            "OR (state IN ('ready', 'leased') AND host_confirmed_at IS NOT NULL) "
            "OR (state = 'promoted' AND promoted_at IS NOT NULL "
            "AND promoted_marker_sha256 IS NOT NULL AND promoted_summary IS NOT NULL) "
            "OR (state = 'completed' AND promoted_at IS NOT NULL "
            "AND discarded_at IS NOT NULL AND completed_at IS NOT NULL "
            "AND storage_current_passphrase IS NULL "
            "AND storage_pending_passphrase IS NULL AND storage_lease IS NULL "
            "AND cache_current_passphrase IS NULL "
            "AND cache_pending_passphrase IS NULL AND cache_lease IS NULL "
            "AND k3s_encryption_key IS NULL AND postgres_password IS NULL "
            "AND source_capability_hash IS NULL "
            "AND source_capability_expires_at IS NULL) "
            "OR state = 'abandoned'",
            name="ck_gpu_legacy_migration_progress",
        ),
        Index("idx_gpu_legacy_migrations_host_state", "host_id", "state"),
    )


class GpuInfraCustody(Base):
    """Exact-lineage, generation-leased key custody for miner infrastructure."""

    __tablename__ = "gpu_infra_custodies"

    server_id = Column(
        String,
        ForeignKey("servers.server_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    owner_hotkey = Column(String, nullable=False)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    reservation_generation = Column(Integer, nullable=False)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    management_mode = Column(String, nullable=False)
    volume_name = Column(String, nullable=False, default="gpu-infra", server_default="gpu-infra")
    current_passphrase = Column(Text, nullable=True)
    pending_passphrase = Column(Text, nullable=True)
    retiring_passphrase = Column(Text, nullable=True)
    retiring_key_slot = Column(Integer, nullable=True)
    k3s_encryption_key = Column(Text, nullable=False)
    confirmed_generation = Column(Integer, nullable=False, default=0, server_default="0")
    active_key_slot = Column(Integer, nullable=True)
    pending_key_slot = Column(Integer, nullable=True)
    lease_id = Column(String, nullable=True)
    lease_generation = Column(Integer, nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    lease_attestation_id = Column(
        String,
        ForeignKey("server_attestations.attestation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    lease_cert_hash = Column(String(64), nullable=True)
    lease_session_jti = Column(String, nullable=True)
    pending_marker_sha256 = Column(String(64), nullable=True)
    state = Column(String, nullable=False, default="current", server_default="current")
    rollback_generation = Column(Integer, nullable=True)
    rollback_key_slot = Column(Integer, nullable=True)
    rollback_passphrase = Column(Text, nullable=True)
    sealed_at = Column(DateTime(timezone=True), nullable=True)
    guest_closed_generation = Column(Integer, nullable=True)
    guest_closed_at = Column(DateTime(timezone=True), nullable=True)
    migration_id = Column(
        String,
        ForeignKey("gpu_legacy_migrations.migration_id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "management_mode = 'miner' AND volume_name = 'gpu-infra'",
            name="ck_gpu_infra_mode",
        ),
        CheckConstraint(
            "host_boot_generation > 0 AND reservation_generation > 0 "
            "AND allocation_group_generation > 0 AND confirmed_generation >= 0 "
            "AND (lease_generation IS NULL OR lease_generation = confirmed_generation + 1) "
            "AND (rollback_generation IS NULL "
            "OR rollback_generation = confirmed_generation + 1) "
            "AND (guest_closed_generation IS NULL "
            "OR guest_closed_generation = confirmed_generation)",
            name="ck_gpu_infra_generations",
        ),
        CheckConstraint(
            "(active_key_slot IS NULL OR active_key_slot BETWEEN 0 AND 7) "
            "AND (pending_key_slot IS NULL OR pending_key_slot BETWEEN 0 AND 7) "
            "AND (retiring_key_slot IS NULL OR retiring_key_slot BETWEEN 0 AND 7) "
            "AND (rollback_key_slot IS NULL OR rollback_key_slot BETWEEN 0 AND 7) "
            "AND (active_key_slot IS NULL OR pending_key_slot IS NULL "
            "OR active_key_slot <> pending_key_slot)",
            name="ck_gpu_infra_slots",
        ),
        CheckConstraint(
            "state IN ('current', 'leased', 'awaiting_ack', 'sealed', 'conflict')",
            name="ck_gpu_infra_state",
        ),
        CheckConstraint(
            "((state IN ('leased', 'awaiting_ack') "
            "AND pending_passphrase IS NOT NULL AND pending_key_slot IS NOT NULL "
            "AND lease_id IS NOT NULL "
            "AND lease_generation = confirmed_generation + 1 "
            "AND lease_expires_at IS NOT NULL AND lease_attestation_id IS NOT NULL "
            "AND lease_cert_hash ~ '^[0-9a-f]{64}$' AND lease_session_jti IS NOT NULL "
            "AND (pending_marker_sha256 IS NULL "
            "OR pending_marker_sha256 ~ '^[0-9a-f]{64}$')) "
            "OR (state IN ('current', 'sealed', 'conflict') "
            "AND pending_passphrase IS NULL AND pending_key_slot IS NULL "
            "AND lease_id IS NULL AND lease_generation IS NULL "
            "AND lease_expires_at IS NULL AND lease_attestation_id IS NULL "
            "AND lease_cert_hash IS NULL AND lease_session_jti IS NULL "
            "AND pending_marker_sha256 IS NULL))",
            name="ck_gpu_infra_lease_shape",
        ),
        CheckConstraint(
            "(rollback_generation IS NULL AND rollback_key_slot IS NULL "
            "AND rollback_passphrase IS NULL) OR "
            "(rollback_generation = confirmed_generation + 1 "
            "AND rollback_key_slot IS NOT NULL AND rollback_passphrase IS NOT NULL)",
            name="ck_gpu_infra_rollback_shape",
        ),
        CheckConstraint(
            "(state = 'sealed' AND sealed_at IS NOT NULL) "
            "OR (state <> 'sealed' AND sealed_at IS NULL)",
            name="ck_gpu_infra_seal_shape",
        ),
        Index(
            "idx_gpu_infra_host",
            "host_id",
            "allocation_group_id",
            "allocation_group_generation",
        ),
        Index("idx_gpu_infra_reservation", "reservation_id", "reservation_generation"),
        Index(
            "idx_gpu_infra_lease_expiry",
            "lease_expires_at",
            postgresql_where=lease_expires_at.isnot(None),
        ),
    )


class ContentHolding(Base):
    """ChuteFS: a public model repo@revision currently held by a storage-role TD (integrity-only).

    The model-distribution registry. A chute TD queries it to find attested peers that already hold
    the weights it needs (avoiding a slow HuggingFace cold-pull); a storage TD inserts/updates a row
    after it has fetched + verified a repo against the /misc/hf_repo_info manifest.
    """

    __tablename__ = "content_holdings"

    holding_id = Column(String, primary_key=True, default=generate_uuid)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    repo_id = Column(String, nullable=False)
    revision = Column(String, nullable=False, default="main", server_default="main")
    bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    status = Column(String, nullable=False, default="present", server_default="present")
    announced_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_snapshot_id = Column(String, nullable=True)
    last_snapshot_started_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("server_id", "repo_id", "revision", name="uq_content_holding"),
        Index("idx_content_holdings_repo", "repo_id", "revision"),
        Index("idx_content_holdings_server", "server_id"),
        Index(
            "idx_content_holdings_snapshot_omission",
            "server_id",
            "holding_id",
        ),
        CheckConstraint(
            "bytes BETWEEN 0 AND 9223372036854775807",
            name="ck_content_holding_signed_bytes",
        ),
    )


class StorageVolume(Base):
    """ChuteFS: a user-owned confidential storage volume (objects replicated across attested TDs)."""

    __tablename__ = "storage_volumes"

    volume_id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    replication_factor = Column(Integer, nullable=False, default=3, server_default="3")
    quota_bytes = Column(
        BigInteger, nullable=False, default=10737418240, server_default="10737418240"
    )
    used_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    deleted = Column(Boolean, nullable=False, default=False, server_default="false")
    delete_requested_at = Column(DateTime(timezone=True), nullable=True)
    key_shredded_at = Column(DateTime(timezone=True), nullable=True)
    purged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    objects = relationship("StorageObject", back_populates="volume", cascade="all, delete-orphan")

    __table_args__ = (
        # Name uniqueness scoped to non-deleted volumes (a soft-deleted name can be reused).
        Index(
            "uq_storage_volume_user_name",
            "user_id",
            "name",
            unique=True,
            postgresql_where=deleted.is_(False),
        ),
        Index("idx_storage_volumes_user", "user_id", postgresql_where=deleted.is_(False)),
        Index(
            "idx_storage_volumes_deleted_work",
            "delete_requested_at",
            "volume_id",
            postgresql_where=(deleted.is_(True) & purged_at.is_(None)),
        ),
    )


class DefaultChuteFSVolumeBinding(Base):
    """Durable default volume identity for one exact owner/chute pair.

    ``chute_id`` intentionally has no foreign key: chute deletion revokes launches but must not
    cascade into durable storage.  Ownership and volume identity are immutable in PostgreSQL.
    """

    __tablename__ = "default_chutefs_volume_bindings"

    binding_id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    chute_id = Column(String, nullable=False)
    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    lifecycle_state = Column(String, nullable=False, default="active", server_default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    retired_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "uq_default_chutefs_binding_active",
            "user_id",
            "chute_id",
            unique=True,
            postgresql_where=lifecycle_state == "active",
        ),
        Index(
            "idx_default_chutefs_binding_owner",
            "user_id",
            "chute_id",
            created_at.desc(),
        ),
        CheckConstraint(
            "(lifecycle_state = 'active' AND retired_at IS NULL) OR "
            "(lifecycle_state = 'retired' AND retired_at IS NOT NULL)",
            name="ck_default_chutefs_binding_lifecycle",
        ),
    )


class ChuteFSLaunchSession(Base):
    """Opaque rotating session restricted to one verified launch's default volume."""

    __tablename__ = "chutefs_launch_sessions"

    session_id = Column(String, primary_key=True)
    config_id = Column(
        String,
        ForeignKey("launch_configs.config_id", ondelete="CASCADE"),
        nullable=False,
    )
    instance_id = Column(
        String,
        ForeignKey("instances.instance_id", ondelete="CASCADE"),
        nullable=False,
    )
    # Audit identity only: the predecessor row may be pruned after its replay
    # window while this digest remains immutable on the successor.
    rotated_from_session_id = Column(String, nullable=True)
    rotated_from_session_sha256 = Column(String(64), nullable=True)
    binding_id = Column(
        String,
        ForeignKey("default_chutefs_volume_bindings.binding_id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id = Column(String, nullable=False)
    chute_id = Column(String, nullable=False)
    job_id = Column(String, nullable=True)
    compute_type = Column(String, nullable=False)
    management_mode = Column(String, nullable=False)
    server_id = Column(String, nullable=False)
    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="RESTRICT"),
        nullable=False,
    )
    reservation_id = Column(String, nullable=True)
    allocation_group_id = Column(String, nullable=True)
    allocation_group_generation = Column(Integer, nullable=True)
    process_incarnation = Column(String, nullable=True)
    attestation_id = Column(String, nullable=True)
    attested_cert_pubkey_hash = Column(String, nullable=True)
    allowed_operations = Column(JSONB, nullable=False)
    generation = Column(Integer, nullable=False, default=1, server_default="1")
    access_token_hash = Column(String(64), nullable=False, unique=True)
    refresh_token_hash = Column(String(64), nullable=False, unique=True)
    access_expires_at = Column(DateTime(timezone=True), nullable=False)
    refresh_expires_at = Column(DateTime(timezone=True), nullable=False)
    rotation_request_sha256 = Column(String(64), nullable=True)
    token_seed = Column(String(64), nullable=True)
    token_key_id = Column(
        String,
        ForeignKey(
            "chutefs_token_key_epochs.key_id",
            name="fk_chutefs_launch_session_token_key",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    response_replay_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    rotated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "idx_chutefs_launch_sessions_expiry",
            "access_expires_at",
            postgresql_where=revoked_at.is_(None),
        ),
        Index(
            "idx_chutefs_launch_sessions_server",
            "server_id",
            postgresql_where=revoked_at.is_(None),
        ),
        Index(
            "uq_chutefs_launch_session_active_config",
            "config_id",
            unique=True,
            postgresql_where=revoked_at.is_(None),
        ),
        Index(
            "uq_chutefs_launch_session_active_instance",
            "instance_id",
            unique=True,
            postgresql_where=revoked_at.is_(None),
        ),
        Index(
            "uq_chutefs_launch_session_successor",
            "rotated_from_session_id",
            unique=True,
            postgresql_where=rotated_from_session_id.is_not(None),
        ),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu') "
            "AND management_mode IN ('platform', 'miner') "
            "AND jsonb_typeof(allowed_operations) = 'array' "
            'AND allowed_operations = \'["put", "get", "list", "delete"]\'::jsonb '
            "AND generation > 0 "
            "AND access_expires_at <= refresh_expires_at "
            "AND attested_cert_pubkey_hash ~ '^[0-9a-f]{64}$' "
            "AND ((compute_type = 'cpu' AND management_mode = 'platform' "
            "AND reservation_id IS NULL AND allocation_group_id IS NULL "
            "AND allocation_group_generation IS NULL AND process_incarnation IS NULL) "
            "OR (compute_type = 'gpu' AND reservation_id IS NOT NULL "
            "AND allocation_group_id IS NOT NULL AND allocation_group_generation > 0 "
            "AND process_incarnation IS NOT NULL AND attestation_id IS NOT NULL))",
            name="ck_chutefs_launch_session_scope",
        ),
        CheckConstraint(
            "access_token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_chutefs_launch_session_access_hash",
        ),
        CheckConstraint(
            "refresh_token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_chutefs_launch_session_refresh_hash",
        ),
        CheckConstraint(
            "((token_seed IS NULL AND token_key_id IS NULL "
            "AND rotation_request_sha256 IS NULL AND response_replay_until IS NULL "
            "AND rotated_from_session_id IS NULL "
            "AND rotated_from_session_sha256 IS NULL) OR "
            "(token_seed ~ '^[0-9a-f]{64}$' AND token_key_id IS NOT NULL "
            "AND token_key_id <> '' "
            "AND rotation_request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND response_replay_until IS NOT NULL "
            "AND response_replay_until <= refresh_expires_at "
            "AND ((rotated_from_session_id IS NULL "
            "AND rotated_from_session_sha256 IS NULL) OR "
            "(rotated_from_session_id IS NOT NULL "
            "AND rotated_from_session_sha256 ~ '^[0-9a-f]{64}$'))))",
            name="ck_chutefs_launch_session_rotation_replay",
        ),
    )


class ChuteFSTokenKeyEpoch(Base):
    """Non-secret database authority for coordinated ChuteFS token-key rotation."""

    __tablename__ = "chutefs_token_key_epochs"

    key_id = Column(String, primary_key=True)
    predecessor_key_id = Column(
        String,
        ForeignKey("chutefs_token_key_epochs.key_id", ondelete="RESTRICT"),
        nullable=True,
    )
    state = Column(String, nullable=False)
    required_replica_ids = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    retiring_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "uq_chutefs_token_key_epoch_active",
            "state",
            unique=True,
            postgresql_where=state == "active",
        ),
        CheckConstraint(
            "state IN ('staged', 'active', 'retiring', 'retired')",
            name="ck_chutefs_token_key_epoch_state",
        ),
        CheckConstraint(
            "jsonb_typeof(required_replica_ids) = 'array' "
            "AND jsonb_array_length(required_replica_ids) > 0",
            name="ck_chutefs_token_key_epoch_replicas",
        ),
        CheckConstraint(
            "(state = 'staged' AND activated_at IS NULL "
            "AND retiring_at IS NULL AND retired_at IS NULL) OR "
            "(state = 'active' AND activated_at IS NOT NULL "
            "AND retiring_at IS NULL AND retired_at IS NULL) OR "
            "(state = 'retiring' AND activated_at IS NOT NULL "
            "AND retiring_at IS NOT NULL AND retired_at IS NULL) OR "
            "(state = 'retired' AND activated_at IS NOT NULL "
            "AND retiring_at IS NOT NULL AND retired_at IS NOT NULL)",
            name="ck_chutefs_token_key_epoch_timestamps",
        ),
    )


class ChuteFSTokenKeyReplicaAck(Base):
    """One serving replica's acknowledgement of a staged non-secret key epoch."""

    __tablename__ = "chutefs_token_key_replica_acks"

    replica_id = Column(String, primary_key=True)
    key_id = Column(
        String,
        ForeignKey("chutefs_token_key_epochs.key_id", ondelete="CASCADE"),
        primary_key=True,
    )
    key_ids = Column(JSONB, nullable=False)
    key_fingerprints = Column(JSONB, nullable=False)
    keyring_sha256 = Column(String(64), nullable=False)
    acknowledged_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "jsonb_typeof(key_ids) = 'array' "
            "AND key_ids ? key_id "
            "AND jsonb_typeof(key_fingerprints) = 'object' "
            "AND key_fingerprints ? key_id "
            "AND keyring_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_chutefs_token_key_replica_ack",
        ),
    )


class ChuteFSTokenKeyEpochOperation(Base):
    """Immutable idempotency and administrator audit record for one epoch CAS."""

    __tablename__ = "chutefs_token_key_epoch_operations"

    request_id = Column(String, primary_key=True)
    request_sha256 = Column(String(64), nullable=False)
    operation_type = Column(String, nullable=False)
    key_id = Column(
        String,
        ForeignKey("chutefs_token_key_epochs.key_id", ondelete="RESTRICT"),
        nullable=False,
    )
    predecessor_key_id = Column(String, nullable=True)
    requested_by_user_id = Column(String, nullable=False)
    # Preserve Python ``None`` as SQL NULL so the operation-shape check can
    # distinguish transition records from a JSON ``null`` payload.
    required_replica_ids = Column(JSONB(none_as_null=True), nullable=True)
    response_json = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND operation_type IN ('stage', 'activate', 'retire') "
            "AND ((operation_type = 'stage' "
            "AND jsonb_typeof(required_replica_ids) = 'array' "
            "AND jsonb_array_length(required_replica_ids) > 0) "
            "OR (operation_type IN ('activate', 'retire') "
            "AND required_replica_ids IS NULL))",
            name="ck_chutefs_token_key_epoch_operation",
        ),
    )


class StorageVolumeKey(Base):
    """ChuteFS: the Fernet-encrypted per-volume application-layer encryption key.

    Generated when the volume is created; released ONLY to an attested storage TD that passes a fresh
    quote verification AND holds a replica of the volume (so a replica on an untrusted host is still
    host-blind). Encrypted at rest with CACHE_PASSPHRASE_KEY (same primitive as LUKS passphrases).
    """

    __tablename__ = "storage_volume_keys"

    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"),
        primary_key=True,
    )
    encrypted_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class StorageObject(Base):
    """One immutable upload generation for a key inside a confidential ChuteFS volume.

    Placement always creates a fresh pending row.  Commit atomically compare-and-swaps it into the
    one current committed generation for ``(volume_id, object_key)`` and retires its predecessor.
    """

    __tablename__ = "storage_objects"

    object_id = Column(String, primary_key=True, default=generate_uuid)
    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"),
        nullable=False,
    )
    object_key = Column(String, nullable=False)
    lifecycle_state = Column(String, nullable=False, default="pending", server_default="pending")
    placement_request_id = Column(String, nullable=True)
    expected_predecessor_id = Column(
        String,
        ForeignKey("storage_objects.object_id", ondelete="RESTRICT"),
        nullable=True,
    )
    size_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    # Placement-time reservation. Unlike size_bytes, this is populated before commit.
    projected_size_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    # Exact sealed-container byte count. It is established by target possession receipts and becomes
    # immutable at commit; replication capabilities bind this value rather than the plaintext quota
    # size above.
    ciphertext_size_bytes = Column(BigInteger, nullable=True)
    # One-time upgrade audit for legacy committed bytes adopted from an intact, currently attested
    # assigned storage TD. These fields are immutable after their atomic NULL -> populated transition.
    legacy_adopted_at = Column(DateTime(timezone=True), nullable=True)
    legacy_adoption_placement_id = Column(String, nullable=True)
    legacy_adoption_server_id = Column(String, nullable=True)
    legacy_adoption_cert_pubkey_hash = Column(String, nullable=True)
    legacy_adoption_storage_incarnation = Column(String, nullable=True)
    sha256 = Column(String, nullable=True)  # ciphertext hash (cross-replica integrity)
    # H1: the v3 at-rest container's HKDF salt (base64) is anchored here, not in the host-controlled
    # object file, and plaintext_sha256 lets the SDK verify the decrypted bytes end-to-end on get().
    salt = Column(String, nullable=True)
    plaintext_sha256 = Column(String, nullable=True)
    durability_state = Column(String, nullable=False, default="pending", server_default="pending")
    durable_replica_count = Column(Integer, nullable=False, default=0, server_default="0")
    durability_updated_at = Column(DateTime(timezone=True), nullable=True)
    committed_at = Column(DateTime(timezone=True), nullable=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)
    tombstoned_at = Column(DateTime(timezone=True), nullable=True)
    erase_enqueued_at = Column(DateTime(timezone=True), nullable=True)
    detached_predecessor_id = Column(String, nullable=True)
    predecessor_detached_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    volume = relationship("StorageVolume", back_populates="objects")
    replicas = relationship(
        "ReplicaPlacement", back_populates="object", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # A key may have concurrent pending attempts and retired history, but only one current
        # committed generation.
        Index(
            "uq_storage_object_current",
            "volume_id",
            "object_key",
            unique=True,
            postgresql_where=lifecycle_state == "committed",
        ),
        Index(
            "uq_storage_object_placement_request",
            "volume_id",
            "placement_request_id",
            unique=True,
            postgresql_where=placement_request_id.isnot(None),
        ),
        Index(
            "idx_storage_objects_current",
            "volume_id",
            "object_key",
            postgresql_where=lifecycle_state == "committed",
        ),
        Index(
            "idx_storage_objects_pending",
            "created_at",
            "object_id",
            postgresql_where=lifecycle_state == "pending",
        ),
        Index(
            "idx_storage_objects_reconcile",
            "durability_updated_at",
            "object_id",
            postgresql_where=lifecycle_state == "committed",
        ),
        Index(
            "idx_storage_objects_gc",
            "tombstoned_at",
            "superseded_at",
            "object_id",
            postgresql_where=lifecycle_state.in_(("superseded", "tombstoned")),
        ),
        Index(
            "idx_storage_objects_erase_queue",
            func.coalesce(tombstoned_at, superseded_at, created_at),
            "object_id",
            postgresql_where=lifecycle_state.in_(("superseded", "tombstoned")),
        ),
        Index(
            "idx_storage_objects_terminal_erase",
            func.coalesce(tombstoned_at, superseded_at, created_at),
            "object_id",
            postgresql_where=(
                lifecycle_state.in_(("superseded", "tombstoned")) & erase_enqueued_at.isnot(None)
            ),
        ),
        Index(
            "idx_storage_objects_expected_predecessor",
            "expected_predecessor_id",
            "object_id",
            postgresql_where=expected_predecessor_id.isnot(None),
        ),
        Index(
            "idx_storage_objects_delete_fence",
            "volume_id",
            "object_key",
            "object_id",
            "created_at",
        ),
        Index(
            "idx_storage_objects_deleted_volume_retire",
            "volume_id",
            "object_id",
            postgresql_where=lifecycle_state.in_(("pending", "committed", "superseded")),
        ),
        Index("idx_storage_objects_volume", "volume_id", "object_id"),
        CheckConstraint(
            "lifecycle_state IN ('pending', 'committed', 'superseded', 'tombstoned')",
            name="ck_storage_object_lifecycle_state",
        ),
        CheckConstraint(
            "durability_state IN "
            "('pending', 'healthy', 'under_replicated', 'at_risk', 'irrecoverable')",
            name="ck_storage_object_durability_state",
        ),
        CheckConstraint(
            "durable_replica_count >= 0",
            name="ck_storage_object_durable_replica_count",
        ),
        CheckConstraint(
            "size_bytes BETWEEN 0 AND 9223372036854775807 "
            "AND projected_size_bytes BETWEEN 0 AND 9223372036854775807 "
            "AND (ciphertext_size_bytes IS NULL OR "
            "ciphertext_size_bytes BETWEEN 0 AND 9223372036854775807)",
            name="ck_storage_object_signed_sizes",
        ),
        CheckConstraint(
            "(detached_predecessor_id IS NULL AND predecessor_detached_at IS NULL) "
            "OR (detached_predecessor_id IS NOT NULL "
            "AND predecessor_detached_at IS NOT NULL "
            "AND detached_predecessor_id <> object_id)",
            name="ck_storage_object_detached_predecessor",
        ),
    )


class StorageObjectDeleteFence(Base):
    """A bounded owner-delete cutoff for every generation of one object key."""

    __tablename__ = "storage_object_delete_fences"

    fence_id = Column(String, primary_key=True, default=generate_uuid)
    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"),
        nullable=False,
    )
    object_key = Column(String, nullable=False)
    cutoff_at = Column(DateTime(timezone=True), nullable=False)
    scan_cursor = Column(String, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("volume_id", "object_key", name="uq_storage_object_delete_fence"),
        Index(
            "idx_storage_object_delete_fence_work",
            "cutoff_at",
            "fence_id",
            postgresql_where=completed_at.is_(None),
        ),
    )


class ReplicaPlacement(Base):
    """ChuteFS: which storage TDs hold a replica of a given object (replication + peer lookup)."""

    __tablename__ = "replica_placement"

    placement_id = Column(String, primary_key=True, default=generate_uuid)
    object_id = Column(
        String,
        ForeignKey("storage_objects.object_id", ondelete="CASCADE"),
        nullable=False,
    )
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False, default="pending", server_default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    storage_incarnation = Column(String, nullable=True)
    target_cert_pubkey_hash = Column(String, nullable=True)
    proof_sha256 = Column(String, nullable=True)
    proof_size_bytes = Column(BigInteger, nullable=True)
    proof_plaintext_size_bytes = Column(BigInteger, nullable=True)
    proof_plaintext_sha256 = Column(String, nullable=True)
    # Set only for a replica received through a consumed one-use validator capability. The initial
    # direct-upload target has no capability id while its generation remains pending.
    proof_capability_id = Column(String, nullable=True)
    proof_mode = Column(String, nullable=True)
    proof_at = Column(DateTime(timezone=True), nullable=True)
    legacy_adoption_started_at = Column(DateTime(timezone=True), nullable=True)
    pending_since = Column(DateTime(timezone=True), nullable=True)
    pending_deadline = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)
    last_inventory_snapshot_id = Column(String, nullable=True)
    last_inventory_seen_at = Column(DateTime(timezone=True), nullable=True)

    object = relationship("StorageObject", back_populates="replicas")

    __table_args__ = (
        UniqueConstraint("object_id", "server_id", name="uq_replica_object_server"),
        Index("idx_replica_placement_object", "object_id", "placement_id"),
        Index("idx_replica_placement_server", "server_id"),
        Index(
            "idx_replica_pending_deadline",
            "pending_deadline",
            postgresql_where=status == "pending",
        ),
        Index(
            "idx_replica_server_incarnation",
            "server_id",
            "storage_incarnation",
        ),
        Index(
            "idx_replica_inventory_snapshot",
            "server_id",
            "storage_incarnation",
            "status",
            "placement_id",
            "created_at",
            "proof_at",
            "last_inventory_seen_at",
            "last_inventory_snapshot_id",
            postgresql_where=status == "present",
        ),
        Index(
            "idx_replica_repair_source",
            "server_id",
            "placement_id",
            postgresql_where=status == "present",
        ),
        CheckConstraint(
            "status IN ('pending', 'present', 'evicted')",
            name="ck_replica_placement_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_replica_placement_attempt_count",
        ),
        CheckConstraint(
            "proof_mode IS NULL OR proof_mode IN "
            "('direct_upload', 'replication_capability', 'legacy_adoption')",
            name="ck_replica_placement_proof_mode",
        ),
        CheckConstraint(
            "proof_size_bytes IS NULL OR proof_size_bytes BETWEEN 0 AND 9223372036854775807",
            name="ck_replica_ciphertext_size",
        ),
        CheckConstraint(
            "proof_plaintext_size_bytes IS NULL "
            "OR proof_plaintext_size_bytes BETWEEN 0 AND 9223372036854775807",
            name="ck_replica_plaintext_size",
        ),
        CheckConstraint(
            "proof_plaintext_sha256 IS NULL OR proof_plaintext_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_replica_plaintext_hash",
        ),
    )


class StorageReplicationCapability(Base):
    """One-use, identity- and generation-bound authorization for one replica transfer."""

    __tablename__ = "storage_replication_capabilities"

    capability_id = Column(String, primary_key=True, default=generate_uuid)
    token_hash = Column(String, nullable=False, unique=True)
    object_id = Column(
        String,
        ForeignKey("storage_objects.object_id", ondelete="CASCADE"),
        nullable=False,
    )
    volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"),
        nullable=False,
    )
    source_placement_id = Column(
        String,
        ForeignKey("replica_placement.placement_id", ondelete="CASCADE"),
        nullable=False,
    )
    source_server_id = Column(
        String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False
    )
    source_cert_pubkey_hash = Column(String, nullable=False)
    source_storage_incarnation = Column(String, nullable=False)
    target_placement_id = Column(
        String,
        ForeignKey("replica_placement.placement_id", ondelete="CASCADE"),
        nullable=False,
    )
    target_placement_attempt = Column(Integer, nullable=False)
    target_server_id = Column(
        String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False
    )
    target_cert_pubkey_hash = Column(String, nullable=False)
    target_storage_incarnation = Column(String, nullable=False)
    expected_ciphertext_sha256 = Column(String, nullable=False)
    expected_ciphertext_size_bytes = Column(BigInteger, nullable=False)
    issued_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    transfer_deadline = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)

    __table_args__ = (
        Index(
            "idx_replication_capability_target",
            "target_server_id",
            "target_placement_id",
            "target_placement_attempt",
        ),
        Index("idx_replication_capability_source", "source_server_id", "object_id"),
        Index(
            "idx_replication_capability_expiry",
            "expires_at",
            postgresql_where=(consumed_at.is_(None) & completed_at.is_(None) & failed_at.is_(None)),
        ),
        Index(
            "uq_replication_capability_active_target",
            "target_placement_id",
            unique=True,
            postgresql_where=(completed_at.is_(None) & failed_at.is_(None)),
        ),
        CheckConstraint(
            "expected_ciphertext_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_replication_capability_hash",
        ),
        CheckConstraint(
            "expected_ciphertext_size_bytes BETWEEN 0 AND 9223372036854775807",
            name="ck_replication_capability_size",
        ),
        CheckConstraint(
            "target_placement_attempt > 0",
            name="ck_replication_capability_attempt",
        ),
        CheckConstraint(
            "issued_at < expires_at AND expires_at <= transfer_deadline",
            name="ck_replication_capability_deadlines",
        ),
        CheckConstraint(
            "NOT (completed_at IS NOT NULL AND failed_at IS NOT NULL)",
            name="ck_replication_capability_terminal",
        ),
    )


class StorageInventorySnapshot(Base):
    """A page-wise, attested inventory snapshot for one mounted storage incarnation."""

    __tablename__ = "storage_inventory_snapshots"

    snapshot_id = Column(String, primary_key=True)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    storage_incarnation = Column(String, nullable=False)
    cert_pubkey_hash = Column(String, nullable=False)
    state = Column(String, nullable=False, default="scanning", server_default="scanning")
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    eligibility_cutoff_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_page_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    reconciled_at = Column(DateTime(timezone=True), nullable=True)
    reconcile_cursor = Column(String, nullable=True)
    reported_entries = Column(BigInteger, nullable=False, default=0, server_default="0")
    omitted_entries = Column(BigInteger, nullable=False, default=0, server_default="0")

    __table_args__ = (
        Index(
            "idx_storage_inventory_reconcile",
            "state",
            "completed_at",
            "snapshot_id",
        ),
        Index(
            "idx_storage_inventory_server",
            "server_id",
            "storage_incarnation",
            "started_at",
        ),
        Index(
            "idx_storage_inventory_stale",
            "last_page_at",
            "snapshot_id",
            postgresql_where=state.in_(("scanning", "reconciled")),
        ),
        CheckConstraint(
            "state IN ('scanning', 'complete', 'reconciled')",
            name="ck_storage_inventory_state",
        ),
        CheckConstraint(
            "reported_entries >= 0 AND omitted_entries >= 0",
            name="ck_storage_inventory_counts",
        ),
    )


class StorageModelInventorySnapshot(Base):
    """A staged, page-wise authoritative model-holding inventory."""

    __tablename__ = "storage_model_inventory_snapshots"

    snapshot_id = Column(String, primary_key=True)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    storage_incarnation = Column(String, nullable=False)
    cert_pubkey_hash = Column(String, nullable=False)
    state = Column(String, nullable=False, default="scanning", server_default="scanning")
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    eligibility_cutoff_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_page_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    reconciled_at = Column(DateTime(timezone=True), nullable=True)
    application_started_at = Column(DateTime(timezone=True), nullable=True)
    last_reconcile_at = Column(DateTime(timezone=True), nullable=True)
    apply_cursor_repo_id = Column(String, nullable=True)
    apply_cursor_revision = Column(String, nullable=True)
    omit_cursor = Column(String, nullable=True)
    next_page_index = Column(Integer, nullable=False, default=0, server_default="0")
    reported_entries = Column(BigInteger, nullable=False, default=0, server_default="0")
    applied_entries = Column(BigInteger, nullable=False, default=0, server_default="0")
    omitted_entries = Column(BigInteger, nullable=False, default=0, server_default="0")

    __table_args__ = (
        Index(
            "idx_storage_model_inventory_reconcile",
            "state",
            "last_reconcile_at",
            started_at.desc(),
            snapshot_id.desc(),
            postgresql_where=state.in_(("complete", "applying", "omitting")),
        ),
        Index(
            "uq_storage_model_inventory_active_identity",
            "server_id",
            "storage_incarnation",
            "cert_pubkey_hash",
            unique=True,
            postgresql_where=state.in_(("applying", "omitting")),
        ),
        Index(
            "idx_storage_model_inventory_waiting",
            "server_id",
            "storage_incarnation",
            "cert_pubkey_hash",
            started_at.desc(),
            snapshot_id.desc(),
            postgresql_where=state == "complete",
        ),
        Index(
            "idx_storage_model_inventory_stale",
            "last_page_at",
            "snapshot_id",
            postgresql_where=state.in_(("scanning", "reconciled")),
        ),
        Index(
            "idx_storage_model_inventory_server_order",
            "server_id",
            "storage_incarnation",
            "cert_pubkey_hash",
            "started_at",
            "snapshot_id",
        ),
        CheckConstraint(
            "state IN ('scanning', 'complete', 'applying', 'omitting', 'reconciled')",
            name="ck_storage_model_inventory_state",
        ),
        CheckConstraint(
            "next_page_index >= 0 "
            "AND reported_entries BETWEEN 0 AND 9223372036854775807 "
            "AND applied_entries BETWEEN 0 AND 9223372036854775807 "
            "AND omitted_entries BETWEEN 0 AND 9223372036854775807",
            name="ck_storage_model_inventory_counts",
        ),
    )


class StorageModelInventoryEntry(Base):
    """One staged model holding in an authoritative snapshot."""

    __tablename__ = "storage_model_inventory_entries"

    snapshot_id = Column(
        String,
        ForeignKey("storage_model_inventory_snapshots.snapshot_id", ondelete="CASCADE"),
        primary_key=True,
    )
    repo_id = Column(String, primary_key=True)
    revision = Column(String, primary_key=True)
    bytes = Column(BigInteger, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "bytes BETWEEN 0 AND 9223372036854775807",
            name="ck_storage_model_inventory_entry_bytes",
        ),
    )


class StorageEraseTask(Base):
    """Durable per-holder erasure of one exact immutable object generation."""

    __tablename__ = "storage_erase_tasks"

    task_id = Column(String, primary_key=True, default=generate_uuid)
    object_id = Column(String, nullable=False)
    volume_id = Column(String, nullable=False)
    placement_id = Column(String, nullable=True)
    server_id = Column(String, nullable=False)
    storage_incarnation = Column(String, nullable=True)
    holder_cert_pubkey_hash = Column(String, nullable=True)
    reason = Column(String, nullable=False)
    state = Column(String, nullable=False, default="pending", server_default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    retention_deadline = Column(DateTime(timezone=True), nullable=False)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    claim_cert_pubkey_hash = Column(String, nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    completed_at = Column(DateTime(timezone=True), nullable=True)
    erased_file_was_present = Column(Boolean, nullable=True)
    retired_by_user_id = Column(String, nullable=True)
    last_error = Column(String, nullable=True)
    metadata_purged_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "uq_storage_erase_generation_holder",
            "object_id",
            "server_id",
            func.coalesce(storage_incarnation, ""),
            unique=True,
        ),
        Index(
            "idx_storage_erase_claim",
            "server_id",
            "storage_incarnation",
            "state",
            "lease_expires_at",
            "created_at",
        ),
        Index("idx_storage_erase_object", "object_id", "state"),
        Index("idx_storage_erase_volume", "volume_id", "state"),
        Index(
            "idx_storage_erase_retention",
            "retention_deadline",
            "task_id",
            postgresql_where=state.in_(("pending", "claimed")),
        ),
        Index(
            "idx_storage_erase_volume_reason",
            "volume_id",
            "reason",
            "task_id",
        ),
        Index(
            "idx_storage_erase_volume_finalize",
            "volume_id",
            "state",
            "reason",
            "metadata_purged_at",
        ),
        Index(
            "idx_storage_erase_terminal_unpurged",
            "object_id",
            "task_id",
            postgresql_where=(state.in_(("erased", "retired")) & metadata_purged_at.is_(None)),
        ),
        Index(
            "idx_storage_erase_terminal_audit",
            "completed_at",
            "task_id",
            "volume_id",
            postgresql_where=(state.in_(("erased", "retired")) & metadata_purged_at.isnot(None)),
        ),
        CheckConstraint(
            "state IN ('pending', 'claimed', 'erased', 'retired')",
            name="ck_storage_erase_task_state",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_storage_erase_task_attempts"),
        CheckConstraint(
            "(state IN ('erased', 'retired') AND completed_at IS NOT NULL) "
            "OR (state IN ('pending', 'claimed') AND completed_at IS NULL)",
            name="ck_storage_erase_task_terminal",
        ),
    )
