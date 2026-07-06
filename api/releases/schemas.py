"""Fleet image release registry: ORM + request/response models.

A "guest release" is the validator-owned desired state for the guest images an L0 host boots its
TDs from -- a per-(channel, tee_type) manifest of the chute image and (optionally) the storage-TD
image, each with its URL, sha256, version and the measurement names those images attest as. L0
node-agents converge to the ACTIVE release for their tee_type (registration response + periodic poll
+ a control-channel rollout nudge). Activation is gated on the referenced measurements already being
pinned on the validator, so a release can never outrun its attestation pins.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from api.database import Base, generate_uuid

RELEASE_CHANNEL_DEFAULT = "stable"
RELEASE_STATUS_DRAFT = "draft"
RELEASE_STATUS_ACTIVE = "active"
RELEASE_STATUS_SUPERSEDED = "superseded"
_VALID_TEE_TYPES = ("sev-snp", "tdx")


class GuestRelease(Base):
    """A published set of guest images for one (channel, tee_type), and its lifecycle status."""

    __tablename__ = "guest_releases"

    release_id = Column(String, primary_key=True, default=generate_uuid)
    channel = Column(String, nullable=False, default=RELEASE_CHANNEL_DEFAULT, server_default=RELEASE_CHANNEL_DEFAULT)
    tee_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default=RELEASE_STATUS_DRAFT, server_default=RELEASE_STATUS_DRAFT)
    # {"chute": {url, sha256, version, measurement_names:[...]}, "storage": {...} (optional)}
    images = Column(JSONB, nullable=False, default=dict, server_default="{}")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)


class ReleaseImage(BaseModel):
    """One image in a release manifest (the chute image or the storage-TD image)."""

    url: str = Field(..., description="Public https URL of the qcow2 (sidecars resolved as <base>.vmlinuz etc.)")
    sha256: str = Field(..., description="Expected sha256 of the qcow2 (mandatory; the fetch fails closed on mismatch)")
    version: Optional[str] = Field(None, description="Human version tag, e.g. 1.6.1")
    measurement_names: List[str] = Field(
        default_factory=list,
        description="Names of the pinned tee_measurements entries this image attests as (gate at activation).",
    )

    @field_validator("sha256")
    @classmethod
    def _valid_sha(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("sha256 must be 64 hex chars")
        return v

    @field_validator("url")
    @classmethod
    def _valid_url(cls, v: str) -> str:
        v = (v or "").strip()
        if not (v.startswith("http://") or v.startswith("https://")) or not v.endswith(".qcow2"):
            raise ValueError("url must be an http(s) .qcow2 URL")
        return v


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
        None, description="Expected sha256 of filesystem.squashfs (informational; the ipxe fetch is not sha-pinned)."
    )
    netboot_base_url: Optional[str] = Field(
        None, description="Override the l0/<tee>/ netboot base URL (else the box's baked default)."
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


class CreateReleaseRequest(BaseModel):
    """Create a draft release. tee_type selects the target fleet; chute image is required, storage optional."""

    tee_type: str = Field(..., description="Target fleet: sev-snp | tdx")
    channel: str = Field(RELEASE_CHANNEL_DEFAULT, description="Release channel (default 'stable')")
    chute: ReleaseImage = Field(..., description="The per-chute guest image manifest")
    storage: Optional[ReleaseImage] = Field(None, description="The always-on storage-TD image manifest (optional)")
    l0: Optional[ReleaseL0] = Field(None, description="The L0 host netboot set (applied by re-netboot; no measurement gate)")
    notes: Optional[str] = Field(None, description="Freeform release notes")
    activate: bool = Field(False, description="Activate immediately after create (subject to the measurement gate)")

    @field_validator("tee_type")
    @classmethod
    def _valid_tee(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in _VALID_TEE_TYPES:
            raise ValueError(f"tee_type must be one of {_VALID_TEE_TYPES}")
        return v


class RolloutRequest(BaseModel):
    """Dispatch to online hosts of the release's tee_type. host_ids scopes a canary."""

    host_ids: Optional[List[str]] = Field(
        None, description="Restrict the rollout to these host_ids (canary); None = all online hosts of the tee_type."
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
    chute: Optional[ReleaseImage] = None
    storage: Optional[ReleaseImage] = None
    l0: Optional[ReleaseL0] = None


class ReleaseResponse(BaseModel):
    release_id: str
    channel: str
    tee_type: str
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


class ReleaseHostStatus(BaseModel):
    host_id: str
    online: bool
    converged: bool
    staged_chute_sha: Optional[str] = None
    staged_storage_sha: Optional[str] = None
    running_l0_version: Optional[str] = None
    l0_converged: Optional[bool] = None


class ReleaseStatusResponse(BaseModel):
    release_id: str
    status: str
    tee_type: str
    chute_sha: Optional[str] = None
    storage_sha: Optional[str] = None
    l0_version: Optional[str] = None
    hosts: List[ReleaseHostStatus]
    servers_on_release: int = Field(
        0, description="Self-registered servers currently attesting with this release's measurement versions."
    )
