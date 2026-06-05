"""
ORM definitions for servers and TDX attestations.
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import (
    Column,
    Integer,
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
)
from sqlalchemy.dialects.postgresql import JSONB
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from api.database import Base, generate_uuid
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


class BootAttestationArgs(BaseModel):
    """Request model for boot attestation."""

    quote: str = Field(..., description="Base64 encoded TDX quote")
    miner_hotkey: str = Field(..., description="Miner hotkey that owns this VM")
    vm_name: str = Field(..., description="VM name/identifier")


class BootAttestationResponse(BaseModel):
    """Response model for successful boot attestation."""

    key: str
    boot_token: Optional[str] = None
    luks_quote_nonce: Optional[str] = None


class RuntimeAttestationArgs(BaseModel):
    """Request model for runtime attestation."""

    quote: str = Field(..., description="Base64 encoded TDX quote")


class RuntimeAttestationResponse(BaseModel):
    """Response model for runtime attestation."""

    attestation_id: str
    verified_at: str
    status: str


@dataclass
class LuksVolumeRotation:
    """Internal result of rotating a single LUKS volume's passphrase (not an API model)."""

    current: Optional[str]
    """Current active passphrase. None on first boot — VM should run luksFormat."""
    next: str
    """New pending passphrase the VM should add as a LUKS key slot."""

    @property
    def is_first_boot(self) -> bool:
        return self.current is None


@dataclass
class LuksAttestResult:
    """Internal result of process_luks_attest_request (not an API model)."""

    volumes: Dict[str, "LuksVolumeRotation"]
    confirm_nonce: str
    k3s_encryption_key: str


@dataclass
class LuksConfirmResult:
    """Internal result of process_luks_confirm (not an API model)."""

    volumes: Dict[str, dict]
    """Per-volume outcome: {"result": "promoted"|"discarded"|"no_pending"}."""


class LuksPassphraseRequest(BaseModel):
    """Request model for LUKS POST: VM sends volume list, API returns keys (existing/new/rekey), prunes others."""

    volumes: List[str] = Field(
        ..., description="Volume names the VM is managing (defines full set)"
    )
    rekey: Optional[List[str]] = Field(
        None,
        description="Volume names that must receive new passphrases (no reuse); must be subset of volumes",
    )


class LuksAttestRequest(BaseModel):
    """Request model for POST /luks/attest (new VMs, version >= 1.3.0)."""

    quote: str = Field(..., description="Base64-encoded TDX quote (runtime type, RTMR3 extended)")
    volumes: List[str] = Field(..., description="Volume names to rotate passphrases for")

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
        description="Current passphrase (None on first boot — VM must luksFormat before luksOpen)",
    )
    next: str = Field(
        ..., description="New pending passphrase the VM should add as a LUKS key slot"
    )


class LuksAttestResponse(BaseModel):
    """Response model for POST /luks/attest."""

    volumes: Dict[str, LuksVolumeInfo]
    confirm_nonce: str = Field(..., description="Single-use nonce for the confirm endpoint")
    k3s_encryption_key: str = Field(..., description="k3s encryption key (base64)")


class LuksVolumeConfirmStatus(BaseModel):
    """Confirm status for a single volume."""

    rotated: bool = Field(
        ...,
        description="True if passphrase rotation succeeded for this volume; False to discard pending",
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


class GpuAttestationArgs(BaseModel):
    evidence: str = Field(..., description="Base64 encoded GPU evidence")


class GpuAttestationResponse(BaseModel):
    attestation_id: str
    verified_at: str
    gpu_info: Dict[str, Any]  # GPU details from evidence


class CpuServerRegistrationArgs(BaseModel):
    """Request body for 1-click CPU TEE server self-registration (POST /servers/cpu/register).

    The booted server self-submits its own runtime TDX quote + CPU benchmark. The Redis-issued
    attestation nonce travels in the X-Chutes-Nonce header, the owning miner hotkey in
    X-Chutes-Hotkey, and the miner-hotkey signature over "{hotkey}:{nonce}:cpu_register" in
    X-Chutes-Signature. The quote's report_data binds nonce || sha256(mTLS client cert pubkey).
    """

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
    host_id: Optional[str] = Field(
        None,
        description="Model B: the L0 launcher host (hosts.host_id) that launched this per-chute TD; "
        "absent for standalone single-VM self-registrations. Enables per-host capacity accounting.",
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
        "{host, attest_port, provision_port, ssh_port, wg_port}. Discovery convenience only.",
    )


class CpuServerRegistrationResponse(BaseModel):
    """Response for a successful CPU TEE server self-registration."""

    server_id: str
    measurement_version: Optional[str] = None
    benchmark_score: float
    verified_at: str
    status: str = "registered"


class HostRegistrationArgs(BaseModel):
    """Request body for Model-B L0 host registration (POST /hosts/register).

    The node-agent registers its launcher host (hotkey-authed, NOT attested) so the validator can
    dispatch per-chute TD launches to it. The signed message is "{hotkey}:{nonce}:host_register"
    with a recent unix-timestamp nonce (the host is not yet known, so there is no server-issued nonce).
    """

    host_id: str = Field(..., description="Stable launcher host id (e.g. hostname / GCP instance id)")
    name: Optional[str] = Field(None, description="Host name (defaults to host_id)")
    capacity: int = Field(1, ge=1, description="Max concurrent per-chute TDs this host can run")
    default_mem: Optional[str] = Field(None, description="Default per-TD memory size class, e.g. 8G")
    default_vcpus: Optional[int] = Field(None, description="Default per-TD vCPU size class")
    external_host: Optional[str] = Field(None, description="Public IP/host advertised for chute TDs")
    tee_type: str = Field("tdx", description="TEE provider the host launches guests with: tdx|sev-snp")
    netuid: Optional[int] = Field(None, description="Subnet netuid (defaults to the validator's)")


class HostRegistrationResponse(BaseModel):
    """Response for a successful L0 host registration."""

    host_id: str
    capacity: int
    status: str = "registered"


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
    mrtd: str
    boot_rtmrs: Dict[str, str]
    runtime_rtmrs: Dict[str, str]
    expected_gpus: List[str]
    gpu_count: int
    # AMD SEV-SNP fields (null for TDX configs).
    measurement: Optional[str] = None
    policy: Optional[int] = None
    min_tcb: Optional[Dict[str, int]] = None
    processor_model: Optional[str] = None


class BootAttestation(Base):
    """Track anonymous boot attestations (pre-registration)."""

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
        Index("idx_tee_upgrade_window_bounds", "upgrade_window_start", "upgrade_window_end"),
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
    # Model B (per-chute): the L0 host (hosts.host_id) that launched this per-chute TD, NULL for
    # standalone single-VM self-registrations. Lets the validator account per-host capacity + tear
    # down a host's TDs. Set by the in-guest agent from the config-volume CHUTES_HOST_ID at register.
    host_id = Column(String, nullable=True)
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

    @property
    def in_maintenance(self) -> bool:
        return self.maintenance_pending_window_id is not None

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
            "idx_servers_maintenance_pending",
            "miner_hotkey",
            postgresql_where=maintenance_pending_window_id.isnot(None),
        ),
        ForeignKeyConstraint(
            ["netuid", "miner_hotkey"], ["metagraph_nodes.netuid", "metagraph_nodes.hotkey"]
        ),
    )


class Host(Base):
    """Model B: a bare-metal L0 launcher host (the one-click-miner appliance / node-agent).

    A host is NOT attested -- it is a launcher only, registered purely by miner-hotkey signature.
    The validator records it so the CPU scheduler can dispatch per-chute TD launches to it over the
    control channel; all workload trust comes from each launched TD's own attestation, never the
    host. Per-host capacity is the number of concurrent per-chute TDs it can run; usage is the count
    of self-registered CPU Servers stamped with this host_id.
    """

    __tablename__ = "hosts"

    host_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    miner_hotkey = Column(String, nullable=False)
    netuid = Column(Integer, nullable=False, default=64, server_default="64")
    # TEE provider this host launches per-chute guests with: "tdx" | "sev-snp".
    tee_type = Column(String, nullable=False, default="tdx", server_default="tdx")
    # Max concurrent per-chute TDs (slot pool size on the node-agent).
    capacity = Column(Integer, nullable=False, default=1, server_default="1")
    # Default per-TD size class (overridable per launch); must match a pinned per-size-class measurement.
    default_mem = Column(String, nullable=True)
    default_vcpus = Column(Integer, nullable=True)
    # Public IP/host the host advertises for its chute TDs (DNAT'd per-slot ports).
    external_host = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (Index("idx_hosts_miner", "miner_hotkey"),)


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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    verified_at = Column(DateTime(timezone=True), nullable=True)

    server = relationship("Server", back_populates="runtime_attestations")

    __table_args__ = (
        Index("idx_attestation_server", "server_id"),
        Index("idx_attestation_created", "created_at"),
        Index("idx_attestation_verified", "verified_at"),
    )


class VmCacheConfig(Base):
    """Track LUKS volume encryption passphrases by VM configuration (JSONB: volume name -> encrypted passphrase)."""

    __tablename__ = "vm_cache_configs"

    miner_hotkey = Column(String, primary_key=True)
    vm_name = Column(String, primary_key=True)
    volume_passphrases = Column(JSONB, nullable=False, default=dict)
    k3s_encryption_key = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_boot_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_vm_cache_miner", "miner_hotkey"),
        Index("idx_vm_cache_last_boot", "last_boot_at"),
    )
