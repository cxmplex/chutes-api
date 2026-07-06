"""
ORM definitions for servers and TDX attestations.
"""

from pydantic import BaseModel, Field, field_validator, model_validator
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
    # M16: last-confirmed monotonic freshness epoch per volume. The TD refuses to serve a volume
    # whose on-disk epoch is OLDER than this (a host that re-presents an old raw-disk snapshot rolls
    # the whole volume back in time under the still-valid passphrase); plain LUKS cannot detect it.
    volume_epochs: Dict[str, int] = None


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
        None, description="GCE vTPM quote for GCP SNP image identity (absent on bare-metal/TDX)."
    )
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
    epoch: int = Field(
        0,
        description="M16 anti-rollback floor: the last-confirmed freshness epoch for this volume. "
        "The TD refuses to serve if the epoch stored inside the encrypted volume is older than this.",
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
    epoch: Optional[int] = Field(
        None,
        description="M16: the new freshness epoch the TD wrote inside the encrypted volume on this "
        "open; the validator advances its stored floor to this so the next boot detects a rollback.",
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
    storage_role: bool = Field(
        False,
        description="ChuteFS: True when this TD is the always-on storage node (excluded from the CPU "
        "scheduler and from host-slot reaping; serves the decentralized storage network).",
    )
    disk_total_gb: Optional[int] = Field(
        None, description="ChuteFS storage TD: total durable disk capacity (GB) of its data volume."
    )
    disk_free_gb: Optional[int] = Field(
        None, description="ChuteFS storage TD: currently free disk (GB) on its data volume."
    )


class CpuServerRegistrationResponse(BaseModel):
    """Response for a successful CPU TEE server self-registration."""

    server_id: str
    measurement_version: Optional[str] = None
    benchmark_score: float
    verified_at: str
    status: str = "registered"
    # ChuteFS: the single-use nonce a self-registering storage TD must embed in its next quote to
    # call POST /{vm_name}/luks/attest for its persistent data-volume key. Minted (and returned) only
    # for storage_role registrations whose measurement version supports the attest flow (>= 1.3.0).
    luks_quote_nonce: Optional[str] = None


class HostRegistrationArgs(BaseModel):
    """Request body for Model-B L0 host registration (POST /hosts/register).

    The node-agent registers its launcher host (hotkey-authed, NOT attested) so the validator can
    dispatch per-chute TD launches to it. The signed message is "{hotkey}:{nonce}:host_register"
    with a recent unix-timestamp nonce (the host is not yet known, so there is no server-issued nonce).
    """

    host_id: str = Field(..., description="Stable launcher host id (e.g. hostname / GCP instance id)")
    name: Optional[str] = Field(None, description="Host name (defaults to host_id)")
    capacity: int = Field(1, ge=1, description="Max concurrent per-chute TDs (auto-discovered by agent)")
    default_mem: Optional[str] = Field(None, description="Default per-TD memory size class, e.g. 8G")
    default_vcpus: Optional[int] = Field(None, description="Default per-TD vCPU size class")
    external_host: Optional[str] = Field(None, description="Public IP/host advertised for chute TDs")
    tee_type: str = Field("tdx", description="TEE provider the host launches guests with: tdx|sev-snp")
    netuid: Optional[int] = Field(None, description="Subnet netuid (defaults to the validator's)")
    specs: Optional[dict] = Field(
        None,
        description="Host hardware inventory reported by the agent: cpu/memory/baseboard/system/bios",
    )
    disk_total_gb: Optional[int] = Field(
        None, description="Physical disk capacity (GB) the host can back ChuteFS storage with."
    )
    disk_free_gb: Optional[int] = Field(
        None, description="Currently free physical disk (GB) on the host."
    )
    l0_version: Optional[str] = Field(
        None, description="L0 host-image version this box is running (from /etc/chutes/l0-version)."
    )


class HostRegistrationResponse(BaseModel):
    """Response for a successful L0 host registration."""

    host_id: str
    capacity: int
    status: str = "registered"
    # Fleet image releases: the active guest-image manifest for this host's tee_type, so a booting
    # host converges to the current release immediately (no separate poll on the first boot). None
    # when no release is active for the host's (channel, tee_type). Shape: api.releases.ReleaseManifest.
    release: Optional[Dict[str, Any]] = None


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
    # Auto-discovered hardware inventory reported by the node-agent (NOT attested -- informational).
    # cpu_cores/ram_gb are denormalized for querying; full detail (cpu/memory/baseboard/system/bios)
    # lives in the specs JSONB.
    cpu_cores = Column(Integer, nullable=True)
    ram_gb = Column(Integer, nullable=True)
    specs = Column(JSONB, nullable=True)
    # Physical disk inventory (GB) reported by the node-agent (informational; the host is not
    # attested). Tells the validator how much durable storage this host can back for ChuteFS.
    disk_total_gb = Column(Integer, nullable=True)
    disk_free_gb = Column(Integer, nullable=True)
    # Fleet image releases: the guest-image digests this host most recently reported it has staged
    # (from the node-agent heartbeat), e.g. {"chute": {"sha256": ...}, "storage": {"sha256": ...}}.
    # Informational (the host is not attested) -- powers GET /releases/{id}/status convergence.
    staged_images = Column(JSONB, nullable=True)
    # The L0 host-image version this box is running (from /etc/chutes/l0-version, reported at
    # registration + heartbeat) -- lets the validator tell which L0 a box booted and drive re-netboot
    # updates (publish a new squashfs + reboot -> box comes up reporting the new version).
    l0_version = Column(String, nullable=True)
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
    # M16: per-volume monotonic freshness epoch {volume_name: int}, advanced on each confirmed open,
    # so the TD can detect a host re-presenting an older raw-disk snapshot (rollback) of a volume.
    volume_epochs = Column(JSONB, nullable=False, default=dict, server_default="{}")
    k3s_encryption_key = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_boot_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_vm_cache_miner", "miner_hotkey"),
        Index("idx_vm_cache_last_boot", "last_boot_at"),
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

    __table_args__ = (
        UniqueConstraint("server_id", "repo_id", "revision", name="uq_content_holding"),
        Index("idx_content_holdings_repo", "repo_id", "revision"),
        Index("idx_content_holdings_server", "server_id"),
    )


class StorageVolume(Base):
    """ChuteFS: a user-owned confidential storage volume (objects replicated across attested TDs)."""

    __tablename__ = "storage_volumes"

    volume_id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    replication_factor = Column(Integer, nullable=False, default=3, server_default="3")
    quota_bytes = Column(BigInteger, nullable=False, default=10737418240, server_default="10737418240")
    used_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    deleted = Column(Boolean, nullable=False, default=False, server_default="false")
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
    )


class StorageVolumeKey(Base):
    """ChuteFS: the Fernet-encrypted per-volume application-layer encryption key.

    Generated when the volume is created; released ONLY to an attested storage TD that passes a fresh
    quote verification AND holds a replica of the volume (so a replica on an untrusted host is still
    host-blind). Encrypted at rest with CACHE_PASSPHRASE_KEY (same primitive as LUKS passphrases).
    """

    __tablename__ = "storage_volume_keys"

    volume_id = Column(
        String, ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class StorageObject(Base):
    """ChuteFS: an object (key -> ciphertext bytes) inside a confidential volume.

    The validator tracks only metadata + the ciphertext integrity hash; the bytes themselves live
    on the storage TDs. size_bytes is the plaintext size, used for per-volume byte accounting.
    """

    __tablename__ = "storage_objects"

    object_id = Column(String, primary_key=True, default=generate_uuid)
    volume_id = Column(
        String, ForeignKey("storage_volumes.volume_id", ondelete="CASCADE"), nullable=False
    )
    object_key = Column(String, nullable=False)
    size_bytes = Column(BigInteger, nullable=False, default=0, server_default="0")
    sha256 = Column(String, nullable=True)  # ciphertext hash (cross-replica integrity)
    # H1: the v3 at-rest container's HKDF salt (base64) is anchored here, not in the host-controlled
    # object file, and plaintext_sha256 lets the SDK verify the decrypted bytes end-to-end on get().
    salt = Column(String, nullable=True)
    plaintext_sha256 = Column(String, nullable=True)
    deleted = Column(Boolean, nullable=False, default=False, server_default="false")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    volume = relationship("StorageVolume", back_populates="objects")
    replicas = relationship(
        "ReplicaPlacement", back_populates="object", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Key uniqueness scoped to non-deleted objects (matches storage_volumes) so a soft-deleted
        # key can be re-PUT; an unconditional UNIQUE made delete-then-reupload a permanent 500.
        Index(
            "uq_storage_object_key",
            "volume_id",
            "object_key",
            unique=True,
            postgresql_where=deleted.is_(False),
        ),
        Index("idx_storage_objects_volume", "volume_id", postgresql_where=deleted.is_(False)),
    )


class ReplicaPlacement(Base):
    """ChuteFS: which storage TDs hold a replica of a given object (replication + peer lookup)."""

    __tablename__ = "replica_placement"

    placement_id = Column(String, primary_key=True, default=generate_uuid)
    object_id = Column(
        String, ForeignKey("storage_objects.object_id", ondelete="CASCADE"), nullable=False
    )
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False, default="present", server_default="present")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    object = relationship("StorageObject", back_populates="replicas")

    __table_args__ = (
        UniqueConstraint("object_id", "server_id", name="uq_replica_object_server"),
        Index("idx_replica_placement_object", "object_id"),
        Index("idx_replica_placement_server", "server_id"),
    )
