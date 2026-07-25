"""Fleet image release registry: ORM + request/response models.

A "guest release" is the validator-owned desired state for the guest images an L0 host boots its
TDs from -- a per-(channel, tee_type, compute_type) manifest. CPU releases contain the independently
versioned chute/storage roles. GPU releases contain one direct-TDX GPU artifact with two signed
management-mode command lines. L0 node-agents converge only to the ACTIVE release for their exact
compute stream.
"""

import base64
import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Literal, Optional, Union
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from api.database import Base, generate_uuid
from api.host.schemas import canonical_json_bytes, canonical_sha256

RELEASE_CHANNEL_DEFAULT = "stable"
RELEASE_STATUS_DRAFT = "draft"
RELEASE_STATUS_ACTIVE = "active"
RELEASE_STATUS_SUPERSEDED = "superseded"
_VALID_TEE_TYPES = ("sev-snp", "tdx")
_VALID_COMPUTE_TYPES = ("cpu", "gpu")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_REJECTED_DNS_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".test",
)
_SHELL_METACHARACTERS = frozenset("$`'\";\\|&<>(){}")


def validate_release_image_url(value: str) -> str:
    """Validate a direct public qcow2 URL without URL-parser ambiguity.

    Release artifacts are fetched by root on L0 hosts. They must therefore be simple, direct public
    object URLs: no credentials, redirects, query/fragment indirection, non-standard ports, local
    origins, encoded characters, or shell syntax. Plain HTTP remains allowed only for the path-style
    Google Cloud Storage origin used by the deployed fleet; other origins must use HTTPS.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("url must be a non-empty string")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError("url must contain only visible ASCII characters")
    if any(char in _SHELL_METACHARACTERS for char in value):
        raise ValueError("url contains a forbidden metacharacter")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("url has an invalid host or port") from exc

    if parsed.scheme not in {"http", "https"} or not value.startswith(f"{parsed.scheme}://"):
        raise ValueError("url scheme must be http or https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("url must include a host")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("url must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("url must not contain a query or fragment")

    host = parsed.hostname
    if host.endswith("."):
        raise ValueError("url host must not have a trailing dot")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ":" in host:
            raise ValueError("url has an invalid host")
        if len(host) > 253:
            raise ValueError("url host is too long")
        labels = host.split(".")
        if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
            raise ValueError("url must use a valid fully-qualified DNS host")
        if labels[-1].isdigit():
            raise ValueError("url host must not use an ambiguous numeric address")
        lowered_host = host.lower()
        if lowered_host == "localhost" or lowered_host.endswith(_REJECTED_DNS_SUFFIXES):
            raise ValueError("url host is not a suitable public artifact origin")
        authority_host = host
    else:
        if not address.is_global:
            raise ValueError("url IP host must be globally routable")
        authority_host = f"[{host}]" if address.version == 6 else host

    allowed_port = 80 if parsed.scheme == "http" else 443
    if port is not None and port != allowed_port:
        raise ValueError(f"url port must be {allowed_port} for {parsed.scheme}")
    expected_authority = authority_host if port is None else f"{authority_host}:{port}"
    if parsed.netloc.lower() != expected_authority.lower():
        raise ValueError("url has a non-canonical or invalid authority")

    path = parsed.path
    if (
        not path.startswith("/")
        or not path.endswith(".qcow2")
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]+", path)
    ):
        raise ValueError("url must have a simple ASCII path ending in .qcow2")
    segments = path.split("/")[1:]
    if any(not segment or segment in {".", ".."} for segment in segments):
        raise ValueError("url path must not contain empty or dot segments")
    if len(segments[-1]) <= len(".qcow2"):
        raise ValueError("url must name a qcow2 artifact")

    if parsed.scheme == "http" and host.lower() != "storage.googleapis.com":
        raise ValueError("plain HTTP release URLs are only allowed on storage.googleapis.com")
    return value


def validate_l0_artifact_url(value: str) -> str:
    """Validate one immutable public L0 artifact URL.

    L0 artifacts have several file types, so this applies the same origin and
    parser-ambiguity restrictions as guest images without imposing ``.qcow2``.
    """

    if not isinstance(value, str) or not value:
        raise ValueError("url must be a non-empty string")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError("url must contain only visible ASCII characters")
    if any(char in _SHELL_METACHARACTERS for char in value):
        raise ValueError("url contains a forbidden metacharacter")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("url has an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not value.startswith(f"{parsed.scheme}://"):
        raise ValueError("url scheme must be http or https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("url must include a host")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("url must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("url must not contain a query or fragment")
    host = parsed.hostname
    if host.endswith("."):
        raise ValueError("url host must not have a trailing dot")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ":" in host or len(host) > 253:
            raise ValueError("url has an invalid host")
        labels = host.split(".")
        if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
            raise ValueError("url must use a valid fully-qualified DNS host")
        if labels[-1].isdigit():
            raise ValueError("url host must not use an ambiguous numeric address")
        lowered_host = host.lower()
        if lowered_host == "localhost" or lowered_host.endswith(_REJECTED_DNS_SUFFIXES):
            raise ValueError("url host is not a suitable public artifact origin")
        authority_host = host
    else:
        if not address.is_global:
            raise ValueError("url IP host must be globally routable")
        authority_host = f"[{host}]" if address.version == 6 else host
    allowed_port = 80 if parsed.scheme == "http" else 443
    if port is not None and port != allowed_port:
        raise ValueError(f"url port must be {allowed_port} for {parsed.scheme}")
    expected_authority = authority_host if port is None else f"{authority_host}:{port}"
    if parsed.netloc.lower() != expected_authority.lower():
        raise ValueError("url has a non-canonical or invalid authority")
    path = parsed.path
    if not path.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._~/-]+", path):
        raise ValueError("url must have a simple absolute ASCII path")
    segments = path.split("/")[1:]
    if any(not segment or segment in {".", ".."} for segment in segments):
        raise ValueError("url path must not contain empty or dot segments")
    if parsed.scheme == "http" and host.lower() != "storage.googleapis.com":
        raise ValueError("plain HTTP artifact URLs are only allowed on storage.googleapis.com")
    return value


class GuestRelease(Base):
    """A published set of guest images for one compute-scoped release stream."""

    __tablename__ = "guest_releases"
    __table_args__ = (
        Index(
            "uq_guest_release_active",
            "channel",
            "tee_type",
            "compute_type",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        Index(
            "idx_guest_releases_l0_generation",
            "tee_type",
            "channel",
            "compute_type",
            "l0_manifest_generation",
            postgresql_where=text("l0_manifest_generation IS NOT NULL"),
        ),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu')",
            name="ck_guest_releases_compute_type",
        ),
        CheckConstraint(
            "compute_type = 'cpu' OR tee_type = 'tdx'",
            name="ck_guest_releases_gpu_tdx",
        ),
        CheckConstraint(
            "(l0_manifest IS NULL AND l0_manifest_digest IS NULL "
            "AND l0_manifest_generation IS NULL AND l0_manifest_key_id IS NULL "
            "AND l0_manifest_key_epoch IS NULL) OR "
            "(l0_manifest IS NOT NULL AND l0_manifest_digest ~ '^[0-9a-f]{64}$' "
            "AND l0_manifest_generation > 0 AND l0_manifest_key_id IS NOT NULL "
            "AND l0_manifest_key_epoch > 0)",
            name="ck_guest_releases_l0_manifest_audit",
        ),
    )

    release_id = Column(String, primary_key=True, default=generate_uuid)
    channel = Column(
        String,
        nullable=False,
        default=RELEASE_CHANNEL_DEFAULT,
        server_default=RELEASE_CHANNEL_DEFAULT,
    )
    tee_type = Column(String, nullable=False)
    compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    status = Column(
        String,
        nullable=False,
        default=RELEASE_STATUS_DRAFT,
        server_default=RELEASE_STATUS_DRAFT,
    )
    # {"chute": {url, sha256, debug, version, measurement_names:[...]}, "storage": {...} (optional)}
    images = Column(JSONB, nullable=False, default=dict, server_default="{}")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    # Immutable logical rollout target snapshot. Rows in guest_release_targets are captured once at
    # activation (or first rollout for a legacy active release), including an intentionally empty set.
    targets_captured_at = Column(DateTime(timezone=True), nullable=True)
    # Publisher-authenticated L0 bootstrap audit. Historical guest releases may be NULL, but every
    # newly activated seedless Model-B release carrying an L0 slot must populate all four fields.
    l0_manifest = Column(JSONB, nullable=True)
    l0_manifest_digest = Column(String(64), nullable=True)
    l0_manifest_generation = Column(Integer, nullable=True)
    l0_manifest_key_id = Column(String, nullable=True)
    l0_manifest_key_epoch = Column(Integer, nullable=True)


class L0BootstrapPublication(Base):
    """One admitted publisher-signed L0 generation for a compute-scoped slot."""

    __tablename__ = "l0_bootstrap_publications"

    tee_type = Column(String, primary_key=True)
    channel = Column(String, primary_key=True)
    compute_type = Column(
        String,
        primary_key=True,
        default="cpu",
        server_default="cpu",
    )
    generation = Column(Integer, primary_key=True)
    manifest_digest = Column(String(64), nullable=False)
    key_id = Column(String, nullable=False)
    key_epoch = Column(Integer, nullable=False)
    l0_version = Column(String, nullable=False)
    squashfs_sha256 = Column(String(64), nullable=False)
    signed_manifest = Column(JSONB, nullable=False)
    source_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    admission_status = Column(
        String,
        nullable=False,
        default="staged",
        server_default="staged",
    )
    admitted_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        PrimaryKeyConstraint(
            "tee_type",
            "channel",
            "compute_type",
            "generation",
            name="pk_l0_bootstrap_publications",
        ),
        UniqueConstraint(
            "tee_type",
            "channel",
            "compute_type",
            "manifest_digest",
            name="uq_l0_bootstrap_slot_digest",
        ),
        CheckConstraint("tee_type IN ('sev-snp', 'tdx')", name="ck_l0_publication_tee"),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu')",
            name="ck_l0_publication_compute_type",
        ),
        CheckConstraint(
            "compute_type = 'cpu' OR tee_type = 'tdx'",
            name="ck_l0_publication_gpu_tdx",
        ),
        CheckConstraint("generation > 0 AND key_epoch > 0", name="ck_l0_publication_generation"),
        CheckConstraint(
            "manifest_digest ~ '^[0-9a-f]{64}$' AND squashfs_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_l0_publication_digests",
        ),
        CheckConstraint(
            "admission_status IN ('staged', 'active')",
            name="ck_l0_publication_status",
        ),
        Index(
            "idx_l0_publication_slot_latest",
            "tee_type",
            "channel",
            "compute_type",
            "generation",
        ),
    )


class GuestReleaseTarget(Base):
    """One role on one enrolled logical L0 target captured for a release rollout.

    The L0 is untrusted, so ``host_id`` is deliberately a logical routing/accounting label, never a
    claim about a physical failure domain. A same-miner L0 can transfer this bearer token between
    logical hosts. Each monotonically increasing token generation is consumed once by an exact
    attested guest and records the current logical binding, not physical placement.
    """

    __tablename__ = "guest_release_targets"

    target_id = Column(String, primary_key=True, default=generate_uuid)
    release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="CASCADE"),
        nullable=False,
    )
    host_id = Column(String, nullable=False)
    miner_hotkey = Column(String, nullable=False)
    tee_type = Column(String, nullable=False)
    compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    role = Column(String, nullable=False)
    current_generation = Column(Integer, nullable=False, default=1, server_default="1")
    current_token_id = Column(String, nullable=False, default=generate_uuid)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    consumed_server_id = Column(String, nullable=True)
    consumed_attestation_id = Column(String, nullable=True)
    consumed_cert_pubkey_hash = Column(String, nullable=True)
    consumed_measurement_name = Column(String, nullable=True)
    consumed_measurement_version = Column(String, nullable=True)
    consumed_measurement_config_fingerprint = Column(String(64), nullable=True)
    consumed_trust_set_fingerprint = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "release_id",
            "host_id",
            "role",
            "compute_type",
            name="uq_guest_release_logical_target",
        ),
        UniqueConstraint(
            "current_token_id",
            name="uq_guest_release_target_current_token",
        ),
        UniqueConstraint(
            "consumed_attestation_id",
            name="uq_guest_release_target_attestation",
        ),
        CheckConstraint(
            "role IN ('chute', 'storage', 'gpu')",
            name="ck_guest_release_target_role",
        ),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu')",
            name="ck_guest_release_target_compute_type",
        ),
        CheckConstraint(
            "(compute_type = 'cpu' AND role IN ('chute', 'storage')) OR "
            "(compute_type = 'gpu' AND tee_type = 'tdx' AND role = 'gpu')",
            name="ck_guest_release_target_compute_role",
        ),
        CheckConstraint(
            "current_generation > 0",
            name="ck_guest_release_target_generation",
        ),
        CheckConstraint(
            "(consumed_at IS NULL AND consumed_server_id IS NULL "
            "AND consumed_attestation_id IS NULL AND consumed_cert_pubkey_hash IS NULL "
            "AND consumed_measurement_name IS NULL AND consumed_measurement_version IS NULL "
            "AND consumed_measurement_config_fingerprint IS NULL "
            "AND consumed_trust_set_fingerprint IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_server_id IS NOT NULL "
            "AND consumed_attestation_id IS NOT NULL AND consumed_cert_pubkey_hash IS NOT NULL "
            "AND consumed_measurement_name IS NOT NULL AND consumed_measurement_version IS NOT NULL "
            "AND consumed_measurement_config_fingerprint IS NOT NULL "
            "AND consumed_trust_set_fingerprint IS NOT NULL)",
            name="ck_guest_release_target_consumption",
        ),
        Index("idx_guest_release_targets_release", "release_id", "role", "host_id"),
        Index("idx_guest_release_targets_server", "consumed_server_id"),
    )


class GuestReleaseTargetTokenGeneration(Base):
    """Audit row for one one-use generation of a transferable logical-target token."""

    __tablename__ = "guest_release_target_token_generations"

    target_id = Column(
        String,
        ForeignKey("guest_release_targets.target_id", ondelete="CASCADE"),
        primary_key=True,
    )
    generation = Column(Integer, primary_key=True)
    token_id = Column(String, nullable=False, default=generate_uuid)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    consumed_server_id = Column(String, nullable=True)
    consumed_attestation_id = Column(String, nullable=True)
    consumed_cert_pubkey_hash = Column(String, nullable=True)
    consumed_measurement_name = Column(String, nullable=True)
    consumed_measurement_version = Column(String, nullable=True)
    consumed_measurement_config_fingerprint = Column(String(64), nullable=True)
    consumed_trust_set_fingerprint = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "token_id",
            name="uq_guest_release_target_token_id",
        ),
        UniqueConstraint(
            "consumed_attestation_id",
            name="uq_guest_release_target_token_attestation",
        ),
        CheckConstraint(
            "generation > 0",
            name="ck_guest_release_target_token_generation",
        ),
        CheckConstraint(
            "invalidated_at IS NULL OR invalidated_at >= issued_at",
            name="ck_guest_release_target_token_invalidation",
        ),
        CheckConstraint(
            "(consumed_at IS NULL AND consumed_server_id IS NULL "
            "AND consumed_attestation_id IS NULL AND consumed_cert_pubkey_hash IS NULL "
            "AND consumed_measurement_name IS NULL AND consumed_measurement_version IS NULL "
            "AND consumed_measurement_config_fingerprint IS NULL "
            "AND consumed_trust_set_fingerprint IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_server_id IS NOT NULL "
            "AND consumed_attestation_id IS NOT NULL AND consumed_cert_pubkey_hash IS NOT NULL "
            "AND consumed_measurement_name IS NOT NULL AND consumed_measurement_version IS NOT NULL "
            "AND consumed_measurement_config_fingerprint IS NOT NULL "
            "AND consumed_trust_set_fingerprint IS NOT NULL)",
            name="ck_guest_release_target_token_consumption",
        ),
        Index(
            "idx_guest_release_target_token_current",
            "target_id",
            "generation",
        ),
        Index(
            "idx_guest_release_target_token_server",
            "consumed_server_id",
        ),
    )


class _ReleaseImageCommon(BaseModel):
    """Fields shared by CPU/storage and GPU release images."""

    url: str = Field(
        ...,
        description=(
            "Direct public HTTP(S) URL of the qcow2 (sidecars resolved as <base>.vmlinuz etc.)"
        ),
    )
    sha256: str = Field(
        ...,
        description="Expected sha256 of the qcow2 (mandatory; the fetch fails closed on mismatch)",
    )
    debug: StrictBool = Field(
        ...,
        description=(
            "Build posture from the image provenance. Debug images require the validator's explicit "
            "ALLOW_DEBUG_MEASUREMENTS opt-in and cannot be relabeled as hardened."
        ),
    )
    version: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
        description="Exact image version bound by signed provenance, e.g. 1.7.0",
    )
    measurement_names: List[str] = Field(
        ...,
        min_length=1,
        description=(
            "Complete pinned measurement-name matrix this image attests as "
            "(direct TDX requires all 16 vCPU/RAM profiles)."
        ),
    )
    kernel_sha256: Optional[str] = Field(
        None, description="Signed direct-boot kernel sidecar sha256."
    )
    initrd_sha256: Optional[str] = Field(
        None, description="Signed direct-boot initrd sidecar sha256."
    )
    provenance_payload: Optional[str] = Field(
        None,
        exclude=True,
        description=(
            "Canonical provenance JSON bytes encoded as a JSON string. Production activation "
            "requires this plus provenance_signature and verifies it with cosign."
        ),
    )
    provenance_signature: Optional[str] = Field(
        None,
        exclude=True,
        description="Detached cosign sign-blob signature for provenance_payload.",
    )

    @field_validator("sha256")
    @classmethod
    def _valid_sha(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("sha256 must be 64 hex chars")
        return v

    @field_validator("kernel_sha256", "initrd_sha256")
    @classmethod
    def _valid_optional_sha(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = v.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("direct-boot sidecar sha256 must be 64 hex chars")
        return normalized

    @field_validator("url")
    @classmethod
    def _valid_url(cls, v: str) -> str:
        return validate_release_image_url(v)


class ReleaseImage(_ReleaseImageCommon):
    """One CPU chute or storage image, preserving the direct-TDX v2 contract."""

    cmdline_sha256: Optional[str] = Field(
        None, description="Signed direct-boot command-line sidecar sha256."
    )

    @field_validator("cmdline_sha256")
    @classmethod
    def _valid_cmdline_sha(cls, value: Optional[str]) -> Optional[str]:
        return cls._valid_optional_sha(value)


class GpuCmdlineHashes(BaseModel):
    """Exactly the two measured management-mode command-line sidecars."""

    platform: str
    miner: str

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator("platform", "miner")
    @classmethod
    def _valid_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("GPU cmdline sha256 must be 64 lowercase hex characters")
        return normalized

    @model_validator(mode="after")
    def _distinct_modes(self):
        if self.platform == self.miner:
            raise ValueError("GPU platform and miner cmdline hashes must differ")
        return self


class GpuReleaseImage(_ReleaseImageCommon):
    """One direct-TDX GPU artifact with two independently measured boot modes."""

    kernel_sha256: str
    initrd_sha256: str
    cmdline_sha256: GpuCmdlineHashes

    model_config = {"extra": "forbid"}


class RoleLaunchBinaryContract(BaseModel):
    """Exact QEMU/TDVF identity for one measured direct-TDX role."""

    role: Literal["storage", "gpu"]
    qemu_binary: str = Field(..., min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/+:-]+$")
    qemu_package: str = Field(
        ..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9.+:-]*$"
    )
    qemu_package_version: str = Field(..., min_length=1, max_length=128)
    qemu_binary_sha256: str
    machine_type: str = Field(..., pattern=r"^pc-q35-[0-9]+\.[0-9]+$")
    firmware_filename: str = Field("OVMF.inteltdx.fd", pattern=r"^OVMF\.inteltdx\.fd$")
    firmware_sha256: str

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator("qemu_binary_sha256", "firmware_sha256")
    @classmethod
    def _valid_launch_digest(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("launch binary digest must be 64 lowercase hex characters")
        return normalized

    @field_validator("qemu_package_version")
    @classmethod
    def _valid_package_version(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 0x21 or ord(character) > 0x7E for character in value
        ):
            raise ValueError("qemu_package_version must be visible ASCII without whitespace")
        return value


class GpuStorageSibling(BaseModel):
    """Exact CPU/storage desired state logically routed through one GPU L0.

    The storage artifact and its launch environment retain their independent CPU
    release identity. This descriptor is not a physical co-location claim.
    """

    schema: Literal["chutes.gpu-storage-sibling"] = "chutes.gpu-storage-sibling"
    version: Literal[1] = 1
    source_compute_type: Literal["cpu"] = "cpu"
    source_release_id: str = Field(..., min_length=1, max_length=256)
    active_cpu_release_id: str = Field(..., min_length=1, max_length=256)
    profile_id: str = Field(..., min_length=1, max_length=256)
    image: ReleaseImage
    launch_contract: RoleLaunchBinaryContract
    physical_co_location_trusted: Literal[False] = False

    model_config = {"extra": "forbid", "frozen": True}

    @model_validator(mode="after")
    def _exact_storage_role(self):
        if self.launch_contract.role != "storage":
            raise ValueError("GPU storage sibling must carry a storage launch contract")
        if self.profile_id not in self.image.measurement_names:
            raise ValueError("GPU storage sibling profile is not in the CPU storage release")
        for field in ("kernel_sha256", "initrd_sha256", "cmdline_sha256"):
            if not getattr(self.image, field):
                raise ValueError(f"GPU storage sibling direct-TDX image is missing {field}")
        return self


class GpuL0StorageClosure(BaseModel):
    """Exact independently signed CPU/storage launch closure baked into a GPU L0."""

    schema: Literal["chutes.gpu-l0-storage-closure"] = "chutes.gpu-l0-storage-closure"
    version: Literal[1] = 1
    source_release_id: str = Field(..., min_length=1, max_length=256)
    image_version: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
    )
    image_sha256: str
    kernel_sha256: str
    initrd_sha256: str
    cmdline_sha256: str
    measurement_names: List[str] = Field(..., min_length=1)
    launch_contract: RoleLaunchBinaryContract

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator(
        "image_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "cmdline_sha256",
    )
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("GPU L0 storage closure digest must be lowercase sha256")
        return normalized

    @field_validator("measurement_names")
    @classmethod
    def _valid_measurement_names(cls, value: List[str]) -> List[str]:
        if len(value) != len(set(value)) or any(
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}", name)
            for name in value
        ):
            raise ValueError("GPU L0 storage closure measurements must be unique canonical names")
        return value

    @model_validator(mode="after")
    def _storage_role(self):
        if self.launch_contract.role != "storage":
            raise ValueError("GPU L0 storage closure requires a storage launch contract")
        return self


class L0ArtifactV1(BaseModel):
    """One exact immutable object named by a signed L0 bootstrap manifest."""

    url: str
    size: int = Field(..., ge=1, le=2**63 - 1)
    sha256: str

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        return validate_l0_artifact_url(value)

    @field_validator("sha256")
    @classmethod
    def _valid_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return normalized


class L0BootstrapManifestV1(BaseModel):
    """Canonical publisher-authenticated L0 artifact contract.

    This authenticates release bytes for miners and release tooling.  It does
    not attest the L0, prove physical placement, or authorize guests/secrets.
    """

    schema: str = Field("chutes.l0-bootstrap", pattern=r"^chutes\.l0-bootstrap$")
    version: int = Field(1, ge=1, le=1)
    tee_type: str
    channel: str = Field(..., min_length=1, max_length=32)
    generation: int = Field(..., ge=1)
    key_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    key_epoch: int = Field(..., ge=1)
    l0_version: str = Field(
        ..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$"
    )
    kernel: L0ArtifactV1
    initrd: L0ArtifactV1
    cmdline: L0ArtifactV1
    squashfs: L0ArtifactV1
    validator_ca_sha256: str
    issued_at: datetime
    expires_at: datetime
    release_id: Optional[str] = Field(None, min_length=1, max_length=256)

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator("tee_type")
    @classmethod
    def _valid_tee(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _VALID_TEE_TYPES:
            raise ValueError(f"tee_type must be one of {_VALID_TEE_TYPES}")
        return normalized

    @field_validator("channel")
    @classmethod
    def _valid_channel(cls, value: str) -> str:
        if not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$", value):
            raise ValueError("channel has an invalid format")
        return value

    @field_validator("validator_ca_sha256")
    @classmethod
    def _valid_ca_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("validator_ca_sha256 must be 64 lowercase hex characters")
        return normalized

    @model_validator(mode="after")
    def _valid_contract(self):
        if "release_id" in self.model_fields_set and self.release_id is None:
            raise ValueError("release_id must be omitted rather than null")
        if self.expires_at <= self.issued_at:
            raise ValueError("manifest expiry must be after issuance")
        urls = [
            self.kernel.url,
            self.initrd.url,
            self.cmdline.url,
            self.squashfs.url,
        ]
        if len(set(urls)) != len(urls):
            raise ValueError("each L0 artifact must have a distinct URL")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def digest(self) -> str:
        return canonical_sha256(self)


class SignedL0BootstrapManifestV1(BaseModel):
    manifest: L0BootstrapManifestV1
    signature: str = Field(..., min_length=88, max_length=88)

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator("signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("signature must be canonical base64") from exc
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("signature must be a canonical Ed25519 signature")
        return value


class L0BootstrapManifestV2(L0BootstrapManifestV1):
    """GPU L0 bootstrap contract with an explicit compute-stream identity."""

    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"
    storage_closure: GpuL0StorageClosure
    gpu_profile_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    gpu_qemu_sha256s: List[str] = Field(..., min_length=1)
    gpu_tdvf_sha256s: List[str] = Field(..., min_length=1)
    gpu_launch_public_key_id: str
    gpu_launch_public_key_epoch: int = Field(..., ge=1)
    gpu_build_inputs_sha256: str

    @field_validator(
        "gpu_launch_public_key_id",
        "gpu_build_inputs_sha256",
    )
    @classmethod
    def _gpu_digest(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("GPU L0 closure identities must be lowercase sha256")
        return normalized

    @field_validator("gpu_qemu_sha256s", "gpu_tdvf_sha256s")
    @classmethod
    def _gpu_digest_list(cls, value: List[str]) -> List[str]:
        if value != sorted(set(value)) or any(
            not re.fullmatch(r"[0-9a-f]{64}", item) for item in value
        ):
            raise ValueError("GPU launch closure hashes must be sorted unique sha256")
        return value

    @model_validator(mode="after")
    def _gpu_tdx_only(self):
        if self.tee_type != "tdx":
            raise ValueError("L0 bootstrap manifest v2 is reserved for GPU TDX")
        return self


class SignedL0BootstrapManifestV2(BaseModel):
    manifest: L0BootstrapManifestV2
    signature: str = Field(..., min_length=88, max_length=88)

    model_config = {"extra": "forbid", "frozen": True}

    @field_validator("signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return SignedL0BootstrapManifestV1._valid_signature(value)


SignedL0BootstrapManifest = Union[
    SignedL0BootstrapManifestV1,
    SignedL0BootstrapManifestV2,
]


class ReleaseL0(BaseModel):
    """The L0 host netboot set for a release (the RAM-root appliance the box re-netboots into).

    Unlike the guest images this carries NO measurement (the L0 host is unattested by design), so it
    is not part of the activation measurement gate. It exists so the validator can pin the desired L0
    version + squashfs digest, tell which L0 a box is running (host reports /etc/chutes/l0-version),
    and drive re-netboot updates. Applying it is a REBOOT (the box re-fetches the squashfs), so it is
    never rolled by the guest-image upgrade path -- only by an explicit reboot or opt-in auto-reboot.
    """

    version: str = Field(..., description="L0 image version stamped at /etc/chutes/l0-version.")
    squashfs_sha256: Optional[str] = Field(
        None,
        description="Expected sha256 of filesystem.squashfs (informational; the ipxe fetch is not sha-pinned).",
    )
    netboot_base_url: Optional[str] = Field(
        None,
        description="Override the l0/<tee>/ netboot base URL (else the box's baked default).",
    )
    bootstrap: Optional[SignedL0BootstrapManifest] = Field(
        None,
        description=(
            "Publisher-signed canonical L0 artifact contract. Required for activation of a "
            "seedless release; nullable only so immutable historical release rows remain readable."
        ),
    )

    @field_validator("squashfs_sha256")
    @classmethod
    def _valid_sha(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("squashfs_sha256 must be 64 hex chars")
        return v

    @model_validator(mode="after")
    def _matches_signed_manifest(self):
        if self.bootstrap is None:
            return self
        manifest = self.bootstrap.manifest
        if self.version != manifest.l0_version:
            raise ValueError("l0 version does not match the signed bootstrap manifest")
        if self.squashfs_sha256 != manifest.squashfs.sha256:
            raise ValueError("squashfs digest does not match the signed bootstrap manifest")
        return self


class CreateReleaseRequest(BaseModel):
    """Create one explicit CPU or GPU release stream."""

    tee_type: str = Field(..., description="Target fleet: sev-snp | tdx")
    compute_type: Literal["cpu", "gpu"] = Field(
        ...,
        description="Compute-scoped desired-state stream.",
    )
    channel: str = Field(RELEASE_CHANNEL_DEFAULT, description="Release channel (default 'stable')")
    chute: Optional[ReleaseImage] = Field(
        None,
        description=(
            "The per-chute guest image manifest. Omit it for a storage-only release; an omitted "
            "slot preserves the currently staged chute image."
        ),
    )
    storage: Optional[ReleaseImage] = Field(
        None,
        description=(
            "The always-on storage-TD image manifest. Omit it for a chute-only release; an "
            "omitted slot preserves the currently staged storage image."
        ),
    )
    gpu: Optional[GpuReleaseImage] = Field(
        None,
        description=(
            "The single direct-TDX GPU artifact, including both platform and miner cmdline hashes."
        ),
    )
    l0: Optional[ReleaseL0] = Field(
        None,
        description="The L0 host netboot set (applied by re-netboot; no measurement gate)",
    )
    notes: Optional[str] = Field(None, description="Freeform release notes")
    activate: bool = Field(
        False,
        description="Activate immediately after create (subject to the measurement gate)",
    )

    @field_validator("tee_type")
    @classmethod
    def _valid_tee(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in _VALID_TEE_TYPES:
            raise ValueError(f"tee_type must be one of {_VALID_TEE_TYPES}")
        return v

    @model_validator(mode="after")
    def _guest_role_required(self):
        if self.compute_type == "cpu":
            if self.gpu is not None:
                raise ValueError("CPU releases cannot contain a gpu image slot")
            if self.chute is None and self.storage is None:
                raise ValueError("CPU releases require at least one of chute or storage")
        else:
            if self.tee_type != "tdx":
                raise ValueError("GPU releases are TDX-only")
            if self.chute is not None or self.storage is not None:
                raise ValueError("GPU releases cannot contain CPU chute or storage image slots")
            if self.gpu is None:
                raise ValueError("GPU releases require exactly one gpu image slot")
        return self


class RolloutRequest(BaseModel):
    """Nudge online hosts in the immutable activation target set."""

    host_ids: Optional[List[str]] = Field(
        None,
        description=(
            "Restrict this immediate dispatch to these logical host IDs. This does not narrow the "
            "immutable activation telemetry target set; use a dedicated release channel for a true "
            "canary target set. Automatic status never authorizes pin pruning."
        ),
    )
    reboot_l0: bool = Field(
        False,
        description=(
            "Also send a `reboot` (re-netboot) to apply the release's L0 slot. DISRUPTIVE -- every TD "
            "on the host goes down for the ~2-4 min re-netboot. Requires the release to carry an `l0` "
            "slot; the release's l0.version is passed as target_l0_version so already-updated hosts skip."
        ),
    )


class ReleaseManifest(BaseModel):
    """The host-facing manifest a node-agent converges to (returned by /releases/current and rollout)."""

    release_id: str
    channel: str
    tee_type: str
    compute_type: Literal["cpu", "gpu"]
    chute: Optional[ReleaseImage] = None
    storage: Optional[ReleaseImage] = None
    gpu: Optional[GpuReleaseImage] = None
    storage_sibling: Optional[GpuStorageSibling] = None
    l0: Optional[ReleaseL0] = None


class ReleaseResponse(BaseModel):
    release_id: str
    channel: str
    tee_type: str
    compute_type: Literal["cpu", "gpu"]
    status: str
    images: Dict
    notes: Optional[str] = None
    created_at: Optional[str] = None
    activated_at: Optional[str] = None


class RolloutHostResult(BaseModel):
    host_id: str
    dispatched: bool
    detail: str


class RolloutResponse(BaseModel):
    release_id: str
    dispatched: int
    hosts: List[RolloutHostResult]


class UntrustedReleaseHostStatus(BaseModel):
    """Host-reported staging and L0 telemetry; none of it is quote-bound."""

    untrusted_host_id: str
    untrusted_online: bool
    untrusted_staged_chute_sha: Optional[str] = None
    untrusted_staged_storage_sha: Optional[str] = None
    untrusted_staged_gpu_sha: Optional[str] = None
    untrusted_stage_matches_release: bool
    untrusted_running_l0_version: Optional[str] = None
    untrusted_l0_matches_release: Optional[bool] = None
    untrusted_gpu_inventory: Optional[Dict] = None
    untrusted_gpu_inventory_ready: Optional[bool] = None


class LogicalReleaseTargetStatus(BaseModel):
    """Operational status for one transferable logical target, never a physical-host claim."""

    target_id: str
    logical_host_id: str
    role: str
    logical_online: bool
    launch_boot_generation: int = Field(..., ge=1)
    launch_reservation_consumed: bool
    fresh_exact_attestation: bool
    fresh_role_health: bool
    exact_staged_digest: bool
    old_process_exit_confirmed: bool
    running_image_sha256: Optional[str] = None
    running_image_version: Optional[str] = None
    running_process_incarnation: Optional[str] = None
    running_storage_incarnation: Optional[str] = None
    allocation_group_id: Optional[str] = None
    allocation_group_generation: Optional[int] = Field(None, ge=1)
    management_mode: Optional[Literal["platform", "miner"]] = None
    storage_sibling_ready: Optional[bool] = None
    runtime_session_ready: Optional[bool] = None
    gpu_evidence_sha256: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")
    host_credential_cloneable: bool = Field(
        True,
        description=(
            "Always true for Model B: host keys are cloneable logical credentials and never prove "
            "physical placement."
        ),
    )
    physical_placement_trusted: bool = Field(
        False,
        description="Always false: this row contains no trusted physical-host or failure-domain proof.",
    )
    server_id: Optional[str] = None
    measurement_name: Optional[str] = None


class ReleaseStatusResponse(BaseModel):
    release_id: str
    status: str
    tee_type: str
    compute_type: Literal["cpu", "gpu"]
    required_roles: List[str] = Field(default_factory=list)
    required_chute_measurement_names: List[str] = Field(default_factory=list)
    required_storage_measurement_names: List[str] = Field(default_factory=list)
    required_gpu_measurement_names: List[str] = Field(default_factory=list)
    gpu_storage_siblings: List[Dict] = Field(default_factory=list)
    all_gpu_storage_siblings_ready: bool = False
    runtime_convergence_supported: bool = Field(
        True,
        description="True when the release has reservation-bound runtime convergence telemetry.",
    )
    source_staged_only: bool = Field(
        False,
        description="True when status can prove only source staging, not runtime convergence.",
    )
    runtime_convergence_state: Literal["tracked",]
    attestation_max_age_seconds: int
    untrusted_hosts: List[UntrustedReleaseHostStatus]
    trusted_measurement_counts: Dict[str, int] = Field(default_factory=dict)
    trusted_role_counts: Dict[str, int] = Field(default_factory=dict)
    trusted_tee_counts: Dict[str, int] = Field(default_factory=dict)
    trusted_roles_observed: Dict[str, bool] = Field(default_factory=dict)
    all_required_roles_observed: bool = Field(
        False,
        description=(
            "True when every captured logical target for every required release role has exact staged "
            "bytes, confirmed old-process exit, fresh role health, and a token-bound exact attestation. "
            "This is transferable logical telemetry, not physical placement evidence."
        ),
    )
    trusted_attestations_on_release: int = Field(
        0,
        description=(
            "Fresh self-registered servers whose exact latest measurement name, version, role and "
            "TEE match this release's verified provenance. Server.host_id is deliberately ignored."
        ),
    )
    fresh_relevant_attestations_not_on_release: int = 0
    targets_captured_at: Optional[str] = None
    logical_rollout_targets: List[LogicalReleaseTargetStatus] = Field(default_factory=list)
    logical_target_counts: Dict[str, int] = Field(default_factory=dict)
    logical_target_completed_counts: Dict[str, int] = Field(default_factory=dict)
    all_logical_targets_healthy: bool = False
    logical_rollout_converged: bool = Field(
        False,
        description=(
            "True only when every immutable enrolled logical target has exact staged bytes, confirmed "
            "old-process exit, fresh running role health/incarnation, and an exact role/TEE/image "
            "attestation bound through its one-use release token. This remains same-miner-transferable "
            "operational telemetry, not physical-host convergence."
        ),
    )
    logical_rollout_telemetry_only: bool = Field(
        True,
        description="Always true: logical convergence is operational telemetry only.",
    )
    logical_host_credentials_cloneable: bool = Field(
        True,
        description=(
            "Always true: logical host keys are cloneable and do not establish a physical machine."
        ),
    )
    physical_host_convergence_proven: bool = Field(
        False,
        description=(
            "Always false: physical host identity is not bound into the guest quote or trusted "
            "release status."
        ),
    )
    pin_pruning_safe: bool = Field(
        False,
        description=(
            "Always false in automatic release status. Pin pruning requires an explicit external "
            "operator validation of physical failure-domain convergence outside this endpoint."
        ),
    )
