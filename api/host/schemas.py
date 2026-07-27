"""Seedless Model-B host, launch, and registry contracts.

The L0 host is deliberately an untrusted launcher.  Enrollment establishes only a
cloneable logical host credential owned by a miner; workload trust continues to
come from guest attestation.  Every wire model in this module is versioned and
forbids unknown fields so clients cannot accidentally sign different semantics.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import warnings
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from api.database import Base, generate_uuid

warnings.filterwarnings(
    "ignore",
    message=r'Field name "schema" in ".*" shadows an attribute in parent ".*"',
    category=UserWarning,
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
_GPU_UUID_RE = re.compile(r"^GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PROCESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_OCI_REPOSITORY_RE = re.compile(
    r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$"
)
_TEE_TYPES = {"sev-snp", "tdx"}
_ROLES = {"chute", "storage"}


def canonical_json_bytes(value: BaseModel | Dict[str, Any]) -> bytes:
    """Return the only byte representation accepted for protocol signatures."""

    document = (
        value.model_dump(mode="json", exclude_none=True) if isinstance(value, BaseModel) else value
    )
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def canonical_sha256(value: BaseModel | Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_b64_32(value: str, field_name: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field_name} must be canonical base64") from exc
    if len(decoded) != 32:
        raise ValueError(f"{field_name} must encode exactly 32 bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} must use canonical padded base64")
    return value


def _validate_b64(value: str, field_name: str, minimum: int, maximum: int) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field_name} must be canonical base64") from exc
    if not minimum <= len(decoded) <= maximum:
        raise ValueError(f"{field_name} must encode between {minimum} and {maximum} bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} must use canonical padded base64")
    return value


class FrozenWireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EnrollmentVoucherClaimsV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment"] = "chutes.host-enrollment"
    version: Literal[1] = 1
    voucher_id: str = Field(default_factory=generate_uuid)
    owner_hotkey: str = Field(..., min_length=1, max_length=128)
    host_id: str = Field(..., min_length=1, max_length=256)
    tee_type: Literal["sev-snp", "tdx"]
    channel: str = Field("stable", min_length=1, max_length=32)
    enrollment_generation: int = Field(..., ge=1)
    issued_at: datetime
    expires_at: datetime
    provider: Optional[str] = Field(None, min_length=1, max_length=64)
    source: Optional[str] = Field(None, min_length=1, max_length=128)
    source_metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("voucher_id", "host_id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value):
            raise ValueError("identifier has an invalid format")
        return value

    @field_validator("channel")
    @classmethod
    def _valid_channel(cls, value: str) -> str:
        if not _CHANNEL_RE.fullmatch(value):
            raise ValueError("channel has an invalid format")
        return value

    @field_validator("source_metadata")
    @classmethod
    def _bounded_metadata(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) > 16:
            raise ValueError("source_metadata may contain at most 16 entries")
        for key, item in value.items():
            if not 1 <= len(key) <= 64 or not 1 <= len(item) <= 256:
                raise ValueError("source_metadata keys or values exceed their bounds")
        return value

    @model_validator(mode="after")
    def _valid_lifetime(self) -> "EnrollmentVoucherClaimsV1":
        if self.expires_at <= self.issued_at:
            raise ValueError("voucher expiry must be after issuance")
        return self


class EnrollmentVoucherClaimsV2(EnrollmentVoucherClaimsV1):
    """GPU enrollment identity; CPU retains the byte-exact V1 claim."""

    version: Literal[2] = 2
    tee_type: Literal["tdx"] = "tdx"
    compute_type: Literal["gpu"] = "gpu"
    storage_enabled: Literal[True] = True


class EnrollmentVoucherMintRequestV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-mint"] = "chutes.host-enrollment-mint"
    version: Literal[1] = 1
    host_id: str = Field(..., min_length=1, max_length=256)
    tee_type: Literal["sev-snp", "tdx"]
    channel: str = Field("stable", min_length=1, max_length=32)
    expires_in_seconds: int = Field(900, ge=60, le=3600)
    provider: Optional[str] = Field(None, min_length=1, max_length=64)
    source: Optional[str] = Field(None, min_length=1, max_length=128)
    source_metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("host_id")
    @classmethod
    def _valid_host_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value):
            raise ValueError("host_id has an invalid format")
        return value

    @field_validator("channel")
    @classmethod
    def _valid_channel(cls, value: str) -> str:
        if not _CHANNEL_RE.fullmatch(value):
            raise ValueError("channel has an invalid format")
        return value


class EnrollmentVoucherMintRequestV2(EnrollmentVoucherMintRequestV1):
    version: Literal[2] = 2
    tee_type: Literal["tdx"] = "tdx"
    compute_type: Literal["gpu"] = "gpu"
    storage_enabled: Literal[True] = True


class EnrollmentVoucherResponseV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-voucher"] = "chutes.host-enrollment-voucher"
    version: Literal[1] = 1
    voucher: str = Field(..., min_length=67, max_length=512)
    claims: EnrollmentVoucherClaimsV1


class EnrollmentVoucherResponseV2(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-voucher"] = "chutes.host-enrollment-voucher"
    version: Literal[2] = 2
    voucher: str = Field(..., min_length=67, max_length=512)
    claims: EnrollmentVoucherClaimsV2


class EnrollmentKeyChallengeRequestV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-key-challenge"] = "chutes.host-enrollment-key-challenge"
    version: Literal[1] = 1
    voucher: str = Field(..., min_length=67, max_length=512)
    ed25519_public_key: str
    x25519_public_key: str
    ed25519_signature: str

    @field_validator("ed25519_public_key", "x25519_public_key")
    @classmethod
    def _valid_public_key(cls, value: str, info) -> str:
        return _validate_b64_32(value, info.field_name)

    @field_validator("ed25519_signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return _validate_b64(value, "ed25519_signature", 64, 64)

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": self.schema,
                "version": self.version,
                "voucher_sha256": hashlib.sha256(self.voucher.encode("ascii")).hexdigest(),
                "ed25519_public_key": self.ed25519_public_key,
                "x25519_public_key": self.x25519_public_key,
            }
        )


class EnrollmentKeyChallengeRequestV2(EnrollmentKeyChallengeRequestV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": self.schema,
                "version": self.version,
                "compute_type": self.compute_type,
                "voucher_sha256": hashlib.sha256(self.voucher.encode("ascii")).hexdigest(),
                "ed25519_public_key": self.ed25519_public_key,
                "x25519_public_key": self.x25519_public_key,
            }
        )


class EnrollmentKeyChallengeResponseV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-key-proof"] = "chutes.host-enrollment-key-proof"
    version: Literal[1] = 1
    challenge_id: str = Field(default_factory=generate_uuid)
    server_ephemeral_public_key: str
    nonce: str
    ciphertext: str
    expires_at: datetime

    @field_validator("server_ephemeral_public_key")
    @classmethod
    def _valid_ephemeral_key(cls, value: str) -> str:
        return _validate_b64_32(value, "server_ephemeral_public_key")

    @field_validator("nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        return _validate_b64(value, "nonce", 12, 12)

    @field_validator("ciphertext")
    @classmethod
    def _valid_ciphertext(cls, value: str) -> str:
        return _validate_b64(value, "ciphertext", 17, 1024)


class EnrollmentKeyChallengeResponseV2(EnrollmentKeyChallengeResponseV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"


class HostEnrollmentRedemptionV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-redemption"] = "chutes.host-enrollment-redemption"
    version: Literal[1] = 1
    voucher: str = Field(..., min_length=67, max_length=512)
    challenge_id: str = Field(..., min_length=1, max_length=256)
    challenge_plaintext: str
    ed25519_public_key: str
    x25519_public_key: str
    ed25519_signature: str

    @field_validator("challenge_plaintext")
    @classmethod
    def _valid_challenge(cls, value: str) -> str:
        return _validate_b64(value, "challenge_plaintext", 32, 32)

    @field_validator("ed25519_public_key", "x25519_public_key")
    @classmethod
    def _valid_public_key(cls, value: str, info) -> str:
        return _validate_b64_32(value, info.field_name)

    @field_validator("ed25519_signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return _validate_b64(value, "ed25519_signature", 64, 64)

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": self.schema,
                "version": self.version,
                "voucher_sha256": hashlib.sha256(self.voucher.encode("ascii")).hexdigest(),
                "challenge_id": self.challenge_id,
                "challenge_plaintext": self.challenge_plaintext,
                "ed25519_public_key": self.ed25519_public_key,
                "x25519_public_key": self.x25519_public_key,
            }
        )


class HostEnrollmentRedemptionV2(HostEnrollmentRedemptionV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": self.schema,
                "version": self.version,
                "compute_type": self.compute_type,
                "voucher_sha256": hashlib.sha256(self.voucher.encode("ascii")).hexdigest(),
                "challenge_id": self.challenge_id,
                "challenge_plaintext": self.challenge_plaintext,
                "ed25519_public_key": self.ed25519_public_key,
                "x25519_public_key": self.x25519_public_key,
            }
        )


class HostEnrollmentResponseV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-result"] = "chutes.host-enrollment-result"
    version: Literal[1] = 1
    host_id: str
    owner_hotkey: str
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    provisioning_state: Literal["persisting_identity", "awaiting_pcs", "ready"]


class HostEnrollmentResponseV2(HostEnrollmentResponseV1):
    version: Literal[2] = 2
    tee_type: Literal["tdx"] = "tdx"
    compute_type: Literal["gpu"] = "gpu"
    storage_enabled: Literal[True] = True


class HostEnrollmentStatusV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-status"] = "chutes.host-enrollment-status"
    version: Literal[1] = 1
    host_id: str
    owner_hotkey: str
    tee_type: Literal["sev-snp", "tdx"]
    channel: str
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    provisioning_state: Literal[
        "persisting_identity",
        "awaiting_pcs",
        "ready",
        "revoked",
    ]
    x25519_public_key: str
    x25519_fingerprint: str
    enrolled_at: datetime


class HostEnrollmentStatusV2(HostEnrollmentStatusV1):
    version: Literal[2] = 2
    tee_type: Literal["tdx"] = "tdx"
    compute_type: Literal["gpu"] = "gpu"
    storage_enabled: Literal[True] = True


class HostIdentityDurabilityAckV1(FrozenWireModel):
    schema: Literal["chutes.host-identity-durable"] = "chutes.host-identity-durable"
    version: Literal[1] = 1
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    identity_metadata_sha256: str
    steady_config_sha256: str

    @field_validator("identity_metadata_sha256", "steady_config_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("durability digests must be lowercase sha256 values")
        return value


class HostProvisioningHeartbeatV1(FrozenWireModel):
    schema: Literal["chutes.host-provisioning-heartbeat"] = "chutes.host-provisioning-heartbeat"
    version: Literal[1] = 1
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    provisioning_state: Literal["persisting_identity", "awaiting_pcs"]
    observed_at: datetime


class HostProvisioningStatusV1(FrozenWireModel):
    schema: Literal["chutes.host-provisioning-status"] = "chutes.host-provisioning-status"
    version: Literal[1] = 1
    host_id: str
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    provisioning_state: Literal[
        "persisting_identity",
        "awaiting_pcs",
        "ready",
    ]
    accepted_at: datetime


class HostRevocationRequestV1(FrozenWireModel):
    schema: Literal["chutes.host-revocation"] = "chutes.host-revocation"
    version: Literal[1] = 1
    reason: str = Field(..., min_length=1, max_length=500)


class PcsMailboxAckV1(FrozenWireModel):
    schema: Literal["chutes.pcs-mailbox-ack"] = "chutes.pcs-mailbox-ack"
    version: Literal[1] = 1
    message_id: str
    envelope_sha256: str

    @field_validator("envelope_sha256")
    @classmethod
    def _valid_envelope_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("envelope_sha256 must be a sha256 digest")
        return value


class HostSigningEnvelopeV1(FrozenWireModel):
    schema: Literal["chutes.host-signature"] = "chutes.host-signature"
    version: Literal[1] = 1
    host_id: str = Field(..., min_length=1, max_length=256)
    key_generation: int = Field(..., ge=1)
    challenge_id: str = Field(..., min_length=1, max_length=256)
    challenge: str = Field(..., min_length=32, max_length=256)
    method: str = Field(..., pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    target: str = Field(..., min_length=1, max_length=2048)
    body_sha256: str
    issued_at: datetime

    @field_validator("body_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("body_sha256 must be 64 lowercase hex characters")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class HostSigningEnvelopeV2(HostSigningEnvelopeV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"


class HostAuthChallengeV1(FrozenWireModel):
    schema: Literal["chutes.host-http-challenge"] = "chutes.host-http-challenge"
    version: Literal[1] = 1
    challenge_id: str
    host_id: str
    key_generation: int = Field(..., ge=1)
    challenge: str
    expires_at: datetime


class HostSocketChallengeV1(FrozenWireModel):
    schema: Literal["chutes.host-socket-challenge"] = "chutes.host-socket-challenge"
    version: Literal[1] = 1
    challenge_id: str
    session_id: str
    host_id: str
    key_generation: int = Field(..., ge=1)
    challenge: str
    expires_at: datetime


class HostSocketAuthenticationV1(FrozenWireModel):
    schema: Literal["chutes.host-socket-authentication"] = "chutes.host-socket-authentication"
    version: Literal[1] = 1
    challenge_id: str
    session_id: str
    host_id: str
    key_generation: int = Field(..., ge=1)
    challenge: str
    issued_at: datetime
    signature: str

    @field_validator("signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return _validate_b64(value, "signature", 64, 64)

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
        )


class HostSocketAuthenticationV2(HostSocketAuthenticationV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"


class TdSocketChallengeV1(FrozenWireModel):
    schema: Literal["chutes.td-socket-challenge"] = "chutes.td-socket-challenge"
    version: Literal[1] = 1
    challenge_id: str
    session_id: str
    server_id: str
    attested_spki_sha256: str
    challenge: str
    expires_at: datetime
    launch_reservation_id: Optional[str] = None
    gpu_launch_reservation_id: Optional[str] = None
    gpu_claims_sha256: Optional[str] = None
    gpu_allocation_group_id: Optional[str] = None
    gpu_allocation_group_generation: Optional[int] = Field(None, ge=1)
    gpu_process_incarnation: Optional[str] = None


class TdSocketAuthenticationV1(FrozenWireModel):
    schema: Literal["chutes.td-socket-authentication"] = "chutes.td-socket-authentication"
    version: Literal[1] = 1
    challenge_id: str
    session_id: str
    server_id: str
    attested_spki_sha256: str
    challenge: str
    issued_at: datetime
    signature: str
    launch_reservation_id: Optional[str] = None
    gpu_launch_reservation_id: Optional[str] = None
    gpu_claims_sha256: Optional[str] = None
    gpu_allocation_group_id: Optional[str] = None
    gpu_allocation_group_generation: Optional[int] = Field(None, ge=1)
    gpu_process_incarnation: Optional[str] = None

    @field_validator("attested_spki_sha256")
    @classmethod
    def _valid_spki(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("attested_spki_sha256 must be a sha256 digest")
        return value

    @field_validator("signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return _validate_b64(value, "signature", 64, 1024)

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", exclude={"signature"}, exclude_none=True)
        )


class PcsMailboxAadV1(FrozenWireModel):
    schema: Literal["chutes.pcs-mailbox-aad"] = "chutes.pcs-mailbox-aad"
    version: Literal[1] = 1
    owner_hotkey: str
    host_id: str
    recipient_fingerprint: str
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    message_id: str
    purpose: Literal["intel-pcs-provisioning"] = "intel-pcs-provisioning"
    issued_at: datetime
    expires_at: datetime

    @field_validator("recipient_fingerprint")
    @classmethod
    def _valid_fingerprint(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("recipient_fingerprint must be a sha256 digest")
        return value

    @model_validator(mode="after")
    def _valid_time_order(self) -> "PcsMailboxAadV1":
        if self.expires_at <= self.issued_at:
            raise ValueError("PCS mailbox expiry must be after issuance")
        return self


class PcsMailboxAadV2(PcsMailboxAadV1):
    version: Literal[2] = 2
    compute_type: Literal["gpu"] = "gpu"


class PcsMailboxEnvelopeV1(FrozenWireModel):
    schema: Literal["chutes.pcs-mailbox"] = "chutes.pcs-mailbox"
    version: Literal[1] = 1
    algorithm: Literal["X25519-HKDF-SHA256-CHACHA20POLY1305"] = (
        "X25519-HKDF-SHA256-CHACHA20POLY1305"
    )
    kdf_label: Literal["chutes/model-b/pcs-mailbox/v1"] = "chutes/model-b/pcs-mailbox/v1"
    sender_ephemeral_public_key: str
    nonce: str
    ciphertext: str
    aad: PcsMailboxAadV1
    miner_signature: str

    @field_validator("sender_ephemeral_public_key")
    @classmethod
    def _valid_ephemeral_key(cls, value: str) -> str:
        return _validate_b64_32(value, "sender_ephemeral_public_key")

    @field_validator("nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        return _validate_b64(value, "nonce", 12, 12)

    @field_validator("ciphertext")
    @classmethod
    def _valid_ciphertext(cls, value: str) -> str:
        return _validate_b64(value, "ciphertext", 17, 4096)

    @field_validator("miner_signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        return _validate_b64(value, "miner_signature", 32, 128)

    def miner_signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", exclude={"miner_signature"}, exclude_none=True)
        )


class PcsMailboxEnvelopeV2(PcsMailboxEnvelopeV1):
    version: Literal[2] = 2
    kdf_label: Literal["chutes/model-b/pcs-mailbox/v2"] = "chutes/model-b/pcs-mailbox/v2"
    aad: PcsMailboxAadV2


class TdLaunchReservationClaimsV1(FrozenWireModel):
    schema: Literal["chutes.td-launch-reservation"] = "chutes.td-launch-reservation"
    version: Literal[1] = 1
    reservation_id: str
    token_id: str
    owner_hotkey: str
    host_id: str
    host_key_generation: int = Field(..., ge=1)
    server_id: str
    role: Literal["chute", "storage"]
    compute_type: Literal["cpu"] = "cpu"
    tee_type: Literal["sev-snp", "tdx"]
    process_incarnation: str
    boot_generation: int = Field(..., ge=1)
    release_id: str
    image_sha256: str
    image_version: str
    profile_id: str
    chute_id: Optional[str] = None
    job_id: Optional[str] = None
    container_repository: Optional[str] = None
    container_manifest_digest: Optional[str] = None
    storage_intent_id: Optional[str] = None
    storage_intent_generation: Optional[int] = Field(None, ge=1)
    launch_nonce: str
    release_target_sha256: str
    issued_at: datetime
    expires_at: datetime

    @field_validator("image_sha256", "release_target_sha256")
    @classmethod
    def _valid_sha(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("digest must be 64 lowercase hex characters")
        return value

    @field_validator("launch_nonce")
    @classmethod
    def _valid_launch_nonce(cls, value: str) -> str:
        return _validate_b64(value, "launch_nonce", 32, 32)

    @field_validator("container_manifest_digest")
    @classmethod
    def _valid_container_digest(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("container_manifest_digest must be canonical sha256")
        return value

    @model_validator(mode="after")
    def _role_claims(self) -> "TdLaunchReservationClaimsV1":
        if self.role == "chute" and (
            not self.chute_id or not self.container_repository or not self.container_manifest_digest
        ):
            raise ValueError("chute reservations require exact chute image intent")
        if self.role == "chute" and (
            self.storage_intent_id is not None or self.storage_intent_generation is not None
        ):
            raise ValueError("chute reservations must not contain storage launch intent")
        if self.role == "storage" and any(
            value is not None
            for value in (
                self.chute_id,
                self.job_id,
                self.container_repository,
                self.container_manifest_digest,
            )
        ):
            raise ValueError("storage reservations must not contain chute workload intent")
        if self.role == "storage" and (
            not self.storage_intent_id or self.storage_intent_generation is None
        ):
            raise ValueError("storage reservations require a validator-owned launch intent")
        if self.expires_at <= self.issued_at:
            raise ValueError("reservation expiry must be after issuance")
        return self


class TdLaunchReservationClaimsV2(TdLaunchReservationClaimsV1):
    """CPU/storage reservation logically routed through a GPU-scoped L0."""

    version: Literal[2] = 2
    host_compute_type: Literal["gpu"] = "gpu"
    gpu_release_id: str
    active_cpu_release_id: str

    @model_validator(mode="after")
    def _gpu_storage_sibling_claims(self) -> "TdLaunchReservationClaimsV2":
        if self.role != "storage" or self.tee_type != "tdx":
            raise ValueError("reservation v2 is reserved for TDX GPU-host storage siblings")
        return self


class StorageLaunchIntentClaimV1(FrozenWireModel):
    schema: Literal["chutes.storage-launch-intent-claim"] = "chutes.storage-launch-intent-claim"
    version: Literal[1] = 1


class LaunchReservationResponseV1(FrozenWireModel):
    schema: Literal["chutes.launch-reservation-result"] = "chutes.launch-reservation-result"
    version: Literal[1] = 1
    token: str
    claims: TdLaunchReservationClaimsV1
    claims_sha256: str

    @field_validator("claims_sha256")
    @classmethod
    def _valid_claims_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("claims_sha256 must be a lowercase sha256 digest")
        return value


class LaunchReservationResponseV2(LaunchReservationResponseV1):
    version: Literal[2] = 2
    claims: TdLaunchReservationClaimsV2


class GpuHostStorageReadinessV1(FrozenWireModel):
    """Validator-derived GPU L0 storage gate; never a physical-placement claim."""

    schema: Literal["chutes.gpu-host-storage-readiness"] = "chutes.gpu-host-storage-readiness"
    version: Literal[1] = 1
    host_id: str
    trusted_storage_ready: bool
    control_channel_eligible: bool = False
    trusted_schedulable: bool
    allocation_group_available: bool = False
    reason: str
    gpu_release_id: Optional[str] = None
    active_cpu_release_id: Optional[str] = None
    source_storage_release_id: Optional[str] = None
    storage_intent_id: Optional[str] = None
    storage_intent_generation: Optional[int] = Field(None, ge=0)
    storage_reservation_id: Optional[str] = None
    storage_server_id: Optional[str] = None
    storage_incarnation: Optional[str] = None
    physical_co_location_trusted: Literal[False] = False


class GpuInventoryDeviceV1(FrozenWireModel):
    bdf: str
    uuid: str
    gpu_identifier: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    model: str = Field(..., min_length=1, max_length=256)
    vram_mib: int = Field(..., ge=1, le=2**31 - 1)
    pci_vendor_id: Literal["10de"] = "10de"
    pci_device_id: str = Field(..., pattern=r"^[0-9a-f]{4}$")
    iommu_group: int = Field(..., ge=0, le=2**31 - 1)
    iommu_members: List[str] = Field(..., min_length=1, max_length=256)
    reset_domain: str = Field(..., min_length=1, max_length=256)
    reset_members: List[str] = Field(..., min_length=1, max_length=256)
    numa_node: int = Field(..., ge=-1, le=2**31 - 1)
    original_driver: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.+-]+$")
    attestation_certificate_sha256: str

    @field_validator("bdf")
    @classmethod
    def _valid_bdf(cls, value: str) -> str:
        value = value.lower()
        if not _BDF_RE.fullmatch(value):
            raise ValueError("GPU BDF must use canonical domain:bus:device.function")
        return value

    @field_validator("uuid")
    @classmethod
    def _valid_uuid(cls, value: str) -> str:
        if not _GPU_UUID_RE.fullmatch(value):
            raise ValueError("GPU UUID must use canonical NVIDIA GPU-uuid form")
        return value

    @field_validator("attestation_certificate_sha256")
    @classmethod
    def _valid_attestation_certificate(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("GPU attestation certificate identity must be sha256")
        return value

    @field_validator("iommu_members", "reset_members")
    @classmethod
    def _canonical_member_list(cls, value: List[str]) -> List[str]:
        normalized = [item.lower() for item in value]
        if normalized != sorted(set(normalized)) or any(
            not _BDF_RE.fullmatch(item) for item in normalized
        ):
            raise ValueError("PCI domain members must be sorted unique canonical BDFs")
        return normalized

    @model_validator(mode="after")
    def _device_is_in_domains(self) -> "GpuInventoryDeviceV1":
        if self.bdf not in self.iommu_members or self.bdf not in self.reset_members:
            raise ValueError("GPU must be a member of its IOMMU and reset domains")
        return self


class GpuInventoryNvlinkEdgeV1(FrozenWireModel):
    source_uuid: str
    target_uuid: str
    link_count: int = Field(..., ge=1, le=64)

    @field_validator("source_uuid", "target_uuid")
    @classmethod
    def _valid_uuid(cls, value: str) -> str:
        return GpuInventoryDeviceV1._valid_uuid(value)

    @model_validator(mode="after")
    def _canonical_edge(self) -> "GpuInventoryNvlinkEdgeV1":
        if self.source_uuid >= self.target_uuid:
            raise ValueError("NVLink edges must be ordered source_uuid < target_uuid")
        return self


class GpuInventoryNvSwitchV1(FrozenWireModel):
    bdf: str
    pci_vendor_id: Literal["10de"] = "10de"
    pci_device_id: str = Field(..., pattern=r"^[0-9a-f]{4}$")
    iommu_group: int = Field(..., ge=0, le=2**31 - 1)
    iommu_members: List[str] = Field(..., min_length=1, max_length=256)
    reset_domain: str = Field(..., min_length=1, max_length=256)
    reset_members: List[str] = Field(..., min_length=1, max_length=256)
    original_driver: str = Field(..., pattern=r"^[A-Za-z0-9_.-]{1,128}$")

    @field_validator("bdf")
    @classmethod
    def _valid_bdf(cls, value: str) -> str:
        return GpuInventoryDeviceV1._valid_bdf(value)

    @field_validator("iommu_members", "reset_members")
    @classmethod
    def _canonical_members(cls, value: List[str]) -> List[str]:
        return GpuInventoryDeviceV1._canonical_member_list(value)

    @model_validator(mode="after")
    def _in_domains(self) -> "GpuInventoryNvSwitchV1":
        if self.bdf not in self.iommu_members or self.bdf not in self.reset_members:
            raise ValueError("NVSwitch must belong to its IOMMU/reset domains")
        return self


class GpuInventoryInfinibandDeviceV1(FrozenWireModel):
    bdf: str
    pci_vendor_id: Literal["15b3"] = "15b3"
    pci_device_id: str = Field(..., pattern=r"^[0-9a-f]{4}$")
    iommu_group: int = Field(..., ge=0, le=2**31 - 1)
    iommu_members: List[str] = Field(..., min_length=1, max_length=256)
    reset_domain: str = Field(..., min_length=1, max_length=256)
    reset_members: List[str] = Field(..., min_length=1, max_length=256)
    original_driver: str = Field(..., pattern=r"^[A-Za-z0-9_.-]{1,128}$")

    @field_validator("bdf")
    @classmethod
    def _valid_bdf(cls, value: str) -> str:
        return GpuInventoryDeviceV1._valid_bdf(value)

    @field_validator("iommu_members", "reset_members")
    @classmethod
    def _canonical_members(cls, value: List[str]) -> List[str]:
        return GpuInventoryDeviceV1._canonical_member_list(value)

    @model_validator(mode="after")
    def _in_domains(self) -> "GpuInventoryInfinibandDeviceV1":
        if self.bdf not in self.iommu_members or self.bdf not in self.reset_members:
            raise ValueError("InfiniBand device must belong to its IOMMU/reset domains")
        return self


class GpuInventoryFabricV1(FrozenWireModel):
    fabric_id: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    gpu_uuids: List[str] = Field(..., min_length=1, max_length=64)
    nvswitch_bdfs: List[str] = Field(default_factory=list, max_length=64)

    @field_validator("gpu_uuids")
    @classmethod
    def _canonical_uuids(cls, value: List[str]) -> List[str]:
        if value != sorted(set(value)) or any(not _GPU_UUID_RE.fullmatch(item) for item in value):
            raise ValueError("fabric GPU UUIDs must be sorted and unique")
        return value

    @field_validator("nvswitch_bdfs")
    @classmethod
    def _canonical_switches(cls, value: List[str]) -> List[str]:
        normalized = [item.lower() for item in value]
        if normalized != sorted(set(normalized)) or any(
            not _BDF_RE.fullmatch(item) for item in normalized
        ):
            raise ValueError("fabric NVSwitch BDFs must be sorted and unique")
        return normalized

    @model_validator(mode="after")
    def _canonical_identity(self) -> "GpuInventoryFabricV1":
        if (
            canonical_sha256(
                {
                    "gpu_uuids": self.gpu_uuids,
                    "nvswitch_bdfs": self.nvswitch_bdfs,
                }
            )
            != self.fabric_id
        ):
            raise ValueError("fabric_id does not match canonical GPU/NVSwitch membership")
        return self


class GpuInventoryResourceBudgetV1(FrozenWireModel):
    logical_cpus: int = Field(..., ge=1, le=4096)
    memory_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    data_disk_total_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    data_disk_free_mib: int = Field(..., ge=0, le=(2**63 - 1) // (1024**2))
    storage_vcpus: int = Field(..., ge=1, le=4096)
    storage_memory_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    storage_overhead_mib: int = Field(..., ge=0, le=(2**63 - 1) // (1024**2))
    gpu_overhead_mib: int = Field(..., ge=0, le=(2**63 - 1) // (1024**2))
    storage_disk_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    storage_scratch_disk_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    gpu_infra_disk_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    gpu_scratch_disk_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    disk_allocation_shortfall_mib: int = Field(..., ge=0, le=(2**63 - 1) // (1024**2))
    l0_reserved_vcpus: int = Field(..., ge=1, le=4096)
    l0_reserved_memory_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    qemu_max_vcpus: int = Field(..., ge=1, le=4096)
    qemu_max_memory_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    mmio64_aperture_mib: int = Field(..., ge=1, le=(2**63 - 1) // (1024**2))
    physical_address_bits: int = Field(..., ge=36, le=63)

    @model_validator(mode="after")
    def _free_not_above_total(self) -> "GpuInventoryResourceBudgetV1":
        if self.data_disk_free_mib > self.data_disk_total_mib:
            raise ValueError("free data-disk capacity cannot exceed total capacity")
        return self


class GpuInventoryGroupV1(FrozenWireModel):
    reported_profile_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    model: str = Field(..., min_length=1, max_length=128)
    host_numa_nodes: int = Field(..., ge=1, le=256)
    devices: List[GpuInventoryDeviceV1] = Field(..., min_length=1, max_length=64)
    nvswitches: List[GpuInventoryNvSwitchV1] = Field(default_factory=list, max_length=64)
    infiniband_devices: List[GpuInventoryInfinibandDeviceV1] = Field(
        default_factory=list, max_length=64
    )
    nvlink_edges: List[GpuInventoryNvlinkEdgeV1] = Field(default_factory=list, max_length=4096)
    fabrics: List[GpuInventoryFabricV1] = Field(..., min_length=1, max_length=64)
    topology_fingerprint: str

    @field_validator("topology_fingerprint")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("topology_fingerprint must be a lowercase sha256")
        return value

    @model_validator(mode="after")
    def _canonical_group(self) -> "GpuInventoryGroupV1":
        bdfs = [item.bdf for item in self.devices]
        uuids = [item.uuid for item in self.devices]
        switch_bdfs = [item.bdf for item in self.nvswitches]
        ib_bdfs = [item.bdf for item in self.infiniband_devices]
        edge_keys = [
            (item.source_uuid, item.target_uuid, item.link_count) for item in self.nvlink_edges
        ]
        fabric_ids = [item.fabric_id for item in self.fabrics]
        if bdfs != sorted(set(bdfs)) or len(uuids) != len(set(uuids)):
            raise ValueError("GPU devices must be sorted by BDF with unique UUIDs")
        if switch_bdfs != sorted(set(switch_bdfs)):
            raise ValueError("NVSwitch devices must be sorted and unique")
        if ib_bdfs != sorted(set(ib_bdfs)):
            raise ValueError("InfiniBand devices must be sorted and unique")
        if edge_keys != sorted(set(edge_keys)):
            raise ValueError("NVLink edges must be sorted and unique")
        if fabric_ids != sorted(set(fabric_ids)):
            raise ValueError("fabric entries must be sorted and unique")
        device_uuids = set(uuids)
        if any(
            edge.source_uuid not in device_uuids or edge.target_uuid not in device_uuids
            for edge in self.nvlink_edges
        ):
            raise ValueError("NVLink edges may reference only GPUs in this group")
        if (
            len(self.fabrics) != 1
            or self.fabrics[0].gpu_uuids != sorted(uuids)
            or self.fabrics[0].nvswitch_bdfs != switch_bdfs
        ):
            raise ValueError(
                "whole-fabric allocation requires one fabric containing exact GPUs/NVSwitches"
            )
        expected_edges = len(uuids) * (len(uuids) - 1) // 2
        if len(self.nvlink_edges) != expected_edges:
            raise ValueError("whole-fabric NVLink graph must be complete and connected")
        allowed_bdfs = set(bdfs) | set(switch_bdfs) | set(ib_bdfs)
        domain_devices = [
            *self.devices,
            *self.nvswitches,
            *self.infiniband_devices,
        ]
        by_bdf = {item.bdf: item for item in domain_devices}
        iommu_memberships: Dict[int, tuple[str, ...]] = {}
        reset_memberships: Dict[str, tuple[str, ...]] = {}
        for item in domain_devices:
            if not set(item.iommu_members).issubset(allowed_bdfs) or not set(
                item.reset_members
            ).issubset(allowed_bdfs):
                raise ValueError("IOMMU/reset domain contains an unassigned or unsafe PCI function")
            iommu_tuple = tuple(item.iommu_members)
            reset_tuple = tuple(item.reset_members)
            if (
                item.iommu_group in iommu_memberships
                and iommu_memberships[item.iommu_group] != iommu_tuple
            ):
                raise ValueError("equal IOMMU domain IDs report contradictory membership")
            if (
                item.reset_domain in reset_memberships
                and reset_memberships[item.reset_domain] != reset_tuple
            ):
                raise ValueError("equal reset-domain IDs report contradictory membership")
            iommu_memberships[item.iommu_group] = iommu_tuple
            reset_memberships[item.reset_domain] = reset_tuple
            if any(
                by_bdf[member].iommu_group != item.iommu_group
                or tuple(by_bdf[member].iommu_members) != iommu_tuple
                for member in item.iommu_members
            ):
                raise ValueError("IOMMU domain membership is not reciprocal")
            if any(
                by_bdf[member].reset_domain != item.reset_domain
                or tuple(by_bdf[member].reset_members) != reset_tuple
                for member in item.reset_members
            ):
                raise ValueError("reset-domain membership is not reciprocal")
        fingerprint_document = self.model_dump(mode="json", exclude={"topology_fingerprint"})
        if canonical_sha256(fingerprint_document) != self.topology_fingerprint:
            raise ValueError("topology_fingerprint does not match canonical group fields")
        return self


class GpuInventoryReportV1(FrozenWireModel):
    schema: Literal["chutes.gpu-inventory-report"] = "chutes.gpu-inventory-report"
    version: Literal[1] = 1
    report_id: str = Field(default_factory=generate_uuid)
    report_generation: int = Field(..., ge=1)
    host_id: str
    host_key_generation: int = Field(..., ge=1)
    host_boot_id: str
    host_boot_generation: int = Field(..., ge=1)
    l0_version: str = Field(..., min_length=1, max_length=256)
    l0_manifest_generation: int = Field(..., ge=1)
    l0_manifest_sha256: str
    gpu_release_id: str
    gpu_image_sha256: str
    profile_contract_sha256: str
    observed_at: datetime
    resources: GpuInventoryResourceBudgetV1
    groups: List[GpuInventoryGroupV1] = Field(..., min_length=1, max_length=64)
    physical_host_trusted: Literal[False] = False

    @field_validator("l0_manifest_sha256", "gpu_image_sha256", "profile_contract_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("inventory identities must be lowercase sha256 values")
        return value

    @field_validator("host_boot_id")
    @classmethod
    def _valid_boot_id(cls, value: str) -> str:
        value = value.lower()
        if not _BOOT_ID_RE.fullmatch(value):
            raise ValueError("host_boot_id must be a canonical UUID")
        return value

    @model_validator(mode="after")
    def _one_whole_fabric_for_v1(self) -> "GpuInventoryReportV1":
        if len(self.groups) != 1:
            raise ValueError(
                "GPU inventory report v1 accepts one signed-profile whole-fabric group"
            )
        return self


class GpuInventoryReconcileResponseV1(FrozenWireModel):
    schema: Literal["chutes.gpu-inventory-reconciliation"] = "chutes.gpu-inventory-reconciliation"
    version: Literal[1] = 1
    report_id: str
    report_generation: int = Field(..., ge=1)
    host_boot_generation: int = Field(..., ge=1)
    status: Literal["accepted", "rejected", "quarantined"]
    allocation_group_id: Optional[str] = None
    allocation_group_generation: Optional[int] = Field(None, ge=1)
    topology_fingerprint: str
    reason: Optional[str] = None
    physical_host_trusted: Literal[False] = False


class GpuPlatformReservationRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-platform-reservation-request"] = (
        "chutes.gpu-platform-reservation-request"
    )
    version: Literal[1] = 1
    server_id: str = Field(..., min_length=1, max_length=256)
    process_incarnation: str = Field(..., min_length=1, max_length=256)
    gpu_identifier: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    gpu_count: int = Field(..., ge=1, le=64)
    minimum_vram_mib: int = Field(..., ge=1, le=2**31 - 1)
    chute_id: str = Field(..., min_length=1, max_length=256)
    job_id: Optional[str] = Field(None, min_length=1, max_length=256)

    @field_validator("server_id", "chute_id", "job_id")
    @classmethod
    def _valid_ids(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _ID_RE.fullmatch(value):
            raise ValueError("GPU workload identifier has an invalid format")
        return value

    @field_validator("process_incarnation")
    @classmethod
    def _valid_process(cls, value: str) -> str:
        if not _PROCESS_RE.fullmatch(value):
            raise ValueError("GPU process_incarnation has an invalid format")
        return value


class GpuMinerReservationRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-miner-reservation-request"] = "chutes.gpu-miner-reservation-request"
    version: Literal[1] = 1
    gpu_identifier: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    gpu_count: int = Field(..., ge=1, le=64)
    minimum_vram_mib: int = Field(..., ge=1, le=2**31 - 1)
    miner_hourly_cost: float = Field(..., gt=0, allow_inf_nan=False)
    legacy_vm_name: Optional[str] = Field(None, min_length=1, max_length=256)

    @field_validator("legacy_vm_name")
    @classmethod
    def _valid_legacy_vm_name(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _ID_RE.fullmatch(value):
            raise ValueError("legacy GPU VM identity has an invalid format")
        return value


class GpuMinerStopRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-miner-stop-request"] = "chutes.gpu-miner-stop-request"
    version: Literal[1] = 1
    reason: str = Field(..., min_length=1, max_length=2000)


class GpuMinerStopResponseV1(FrozenWireModel):
    schema: Literal["chutes.gpu-miner-stop-result"] = "chutes.gpu-miner-stop-result"
    version: Literal[1] = 1
    server_id: str
    reservation_id: str
    status: Literal["teardown_requested", "released"]


class GpuLaunchReservationClaimsV1(FrozenWireModel):
    schema: Literal["chutes.gpu-launch-reservation"] = "chutes.gpu-launch-reservation"
    version: Literal[1] = 1
    reservation_id: str
    token_id: str
    owner_hotkey: str
    workload_owner: str
    host_id: str
    host_key_generation: int = Field(..., ge=1)
    host_boot_generation: int = Field(..., ge=1)
    compute_type: Literal["gpu"] = "gpu"
    tee_type: Literal["tdx"] = "tdx"
    management_mode: Literal["platform", "miner"]
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    reservation_generation: int = Field(..., ge=1)
    gpu_bdfs: List[str] = Field(..., min_length=1, max_length=64)
    gpu_uuids: List[str] = Field(..., min_length=1, max_length=64)
    gpu_identifiers: List[str] = Field(..., min_length=1, max_length=64)
    gpu_attestation_certificate_sha256s: List[str] = Field(..., min_length=1, max_length=64)
    topology_fingerprint: str
    gpu_release_id: str
    gpu_profile_id: str
    profile_contract_sha256: str
    measurement_name: str
    kernel_measurement_mode: Literal["qemu-patched", "efi-image-as-is"]
    qemu_binary_sha256: str
    qemu_package_version: str
    machine_type: str
    tdvf_sha256: str
    image_sha256: str
    image_version: str
    kernel_sha256: str
    initrd_sha256: str
    mode_cmdline_sha256: str
    release_target_sha256: str
    server_id: str
    process_incarnation: str
    legacy_vm_name: Optional[str] = None
    legacy_migration_id: Optional[str] = None
    chute_id: Optional[str] = None
    job_id: Optional[str] = None
    container_repository: Optional[str] = None
    container_manifest_digest: Optional[str] = None
    descriptor_closure_sha256: Optional[str] = None
    allowed_manifests: List[str] = Field(default_factory=list)
    allowed_blobs: List[str] = Field(default_factory=list)
    allowed_manifest_tags: List[str] = Field(default_factory=list)
    manifest_tag_digests: Dict[str, str] = Field(default_factory=dict)
    miner_hourly_cost: Optional[float] = Field(None, gt=0, allow_inf_nan=False)
    launch_nonce: str
    issued_at: datetime
    expires_at: datetime

    @field_validator(
        "topology_fingerprint",
        "profile_contract_sha256",
        "qemu_binary_sha256",
        "tdvf_sha256",
        "image_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "mode_cmdline_sha256",
        "release_target_sha256",
    )
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("GPU launch identity digest must be lowercase sha256")
        return value

    @field_validator("descriptor_closure_sha256")
    @classmethod
    def _valid_optional_closure_digest(
        cls,
        value: Optional[str],
    ) -> Optional[str]:
        if value is None:
            return None
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("GPU descriptor closure must be lowercase sha256")
        return value

    @field_validator("gpu_bdfs")
    @classmethod
    def _canonical_bdfs(cls, value: List[str]) -> List[str]:
        normalized = [item.lower() for item in value]
        if normalized != sorted(set(normalized)) or any(
            not _BDF_RE.fullmatch(item) for item in normalized
        ):
            raise ValueError("assigned GPU BDFs must be sorted and unique")
        return normalized

    @field_validator("gpu_uuids")
    @classmethod
    def _canonical_gpu_uuids(cls, value: List[str]) -> List[str]:
        if value != sorted(set(value)) or any(not _GPU_UUID_RE.fullmatch(item) for item in value):
            raise ValueError("assigned GPU UUIDs must be sorted and unique")
        return value

    @field_validator("gpu_identifiers")
    @classmethod
    def _canonical_identifiers(cls, value: List[str]) -> List[str]:
        if value != sorted(value) or any(
            not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item) for item in value
        ):
            raise ValueError("assigned GPU identifiers must use canonical order")
        return value

    @field_validator("gpu_attestation_certificate_sha256s")
    @classmethod
    def _canonical_attestation_certificates(cls, value: List[str]) -> List[str]:
        normalized = [item.lower() for item in value]
        if normalized != sorted(set(normalized)) or any(
            not _HEX_64_RE.fullmatch(item) for item in normalized
        ):
            raise ValueError("GPU attestation certificate identities must be sorted unique sha256")
        return normalized

    @field_validator("launch_nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        return _validate_b64(value, "launch_nonce", 32, 32)

    @field_validator(
        "reservation_id",
        "token_id",
        "host_id",
        "allocation_group_id",
        "gpu_release_id",
        "server_id",
        "chute_id",
        "job_id",
    )
    @classmethod
    def _valid_ids(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _ID_RE.fullmatch(value):
            raise ValueError("GPU reservation identifier has an invalid format")
        return value

    @field_validator("process_incarnation")
    @classmethod
    def _valid_process(cls, value: str) -> str:
        if not _PROCESS_RE.fullmatch(value):
            raise ValueError("GPU process_incarnation has an invalid format")
        return value

    @field_validator("container_manifest_digest")
    @classmethod
    def _valid_optional_container_digest(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("container manifest must be a canonical sha256 digest")
        return value

    @field_validator("container_repository")
    @classmethod
    def _valid_optional_repository(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _OCI_REPOSITORY_RE.fullmatch(value):
            raise ValueError("container repository is not a canonical OCI name")
        return value

    @model_validator(mode="after")
    def _exact_workload_shape(self) -> "GpuLaunchReservationClaimsV1":
        if not (
            len(self.gpu_bdfs)
            == len(self.gpu_uuids)
            == len(self.gpu_identifiers)
            == len(self.gpu_attestation_certificate_sha256s)
        ):
            raise ValueError(
                "GPU BDF, UUID, identifier, and attestation-certificate sets must have equal size"
            )
        if self.management_mode == "platform":
            if (
                self.miner_hourly_cost is not None
                or self.legacy_vm_name is not None
                or self.legacy_migration_id is not None
                or not self.chute_id
                or not self.container_repository
                or not self.container_manifest_digest
                or not self.descriptor_closure_sha256
                or not self.allowed_manifests
                or not self.allowed_blobs
                or not self.allowed_manifest_tags
                or set(self.manifest_tag_digests) != set(self.allowed_manifest_tags)
                or any(
                    digest not in self.allowed_manifests
                    for digest in self.manifest_tag_digests.values()
                )
            ):
                raise ValueError("platform GPU reservations require exact chute image intent")
            closure = {
                "schema": "chutes.oci-descriptor-closure",
                "version": 1,
                "root_manifest": self.container_manifest_digest,
                "manifests": self.allowed_manifests,
                "blobs": self.allowed_blobs,
                "manifest_tags": self.allowed_manifest_tags,
                "manifest_tag_digests": self.manifest_tag_digests,
            }
            if canonical_sha256(closure) != self.descriptor_closure_sha256:
                raise ValueError("platform GPU descriptor closure digest is invalid")
        elif self.miner_hourly_cost is None or any(
            (
                self.chute_id,
                self.job_id,
                self.container_repository,
                self.container_manifest_digest,
                self.descriptor_closure_sha256,
                self.allowed_manifests,
                self.allowed_blobs,
                self.allowed_manifest_tags,
                self.manifest_tag_digests,
            )
        ):
            raise ValueError(
                "miner GPU reservations require positive cost and cannot carry platform workload intent"
            )
        if (self.legacy_vm_name is None) != (self.legacy_migration_id is None):
            raise ValueError("miner legacy VM and migration identity must be paired")
        if self.expires_at <= self.issued_at:
            raise ValueError("GPU reservation expiry must be after issuance")
        return self


class GpuLaunchReservationResponseV1(FrozenWireModel):
    schema: Literal["chutes.gpu-launch-reservation-result"] = "chutes.gpu-launch-reservation-result"
    version: Literal[1] = 1
    token: str
    claims: GpuLaunchReservationClaimsV1
    claims_sha256: str

    @field_validator("claims_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("claims_sha256 must be lowercase sha256")
        return value


class GpuSignedLaunchClaimsEnvelopeV1(FrozenWireModel):
    """Validator-signed claims copied to the untrusted per-TD config disk.

    The frozen GPU claims remain unchanged.  This detached envelope lets the
    measured pre-service guest gate authenticate those exact canonical bytes
    before either management stack can start.
    """

    schema: Literal["chutes.gpu-signed-launch-claims"] = "chutes.gpu-signed-launch-claims"
    version: Literal[1] = 1
    algorithm: Literal["ES256"] = "ES256"
    key_id: str
    key_epoch: int = Field(..., ge=1)
    claims: GpuLaunchReservationClaimsV1
    claims_sha256: str
    signature: str

    @field_validator("key_id", "claims_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("signed GPU claim identity must be lowercase sha256")
        return value

    @field_validator("signature")
    @classmethod
    def _valid_signature(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("GPU claim signature must be canonical base64") from exc
        if not 64 <= len(decoded) <= 80 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("GPU claim signature must be a canonical DER ECDSA signature")
        return value

    @model_validator(mode="after")
    def _matches_claims(self) -> "GpuSignedLaunchClaimsEnvelopeV1":
        if canonical_sha256(self.claims) != self.claims_sha256:
            raise ValueError("signed GPU claims digest differs from canonical claims")
        return self


class GpuQuoteCommitmentV1(FrozenWireModel):
    schema: Literal["chutes.gpu-quote-commitment"] = "chutes.gpu-quote-commitment"
    version: Literal[1] = 1
    reservation_sha256: str
    release_target_sha256: str
    launch_nonce: str
    attested_spki_sha256: str
    claims: GpuLaunchReservationClaimsV1

    @field_validator(
        "reservation_sha256",
        "release_target_sha256",
        "attested_spki_sha256",
    )
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("GPU quote commitment digest must be lowercase sha256")
        return value

    @field_validator("launch_nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        return _validate_b64(value, "launch_nonce", 32, 32)

    @model_validator(mode="after")
    def _matches_claims(self) -> "GpuQuoteCommitmentV1":
        if (
            self.release_target_sha256 != self.claims.release_target_sha256
            or self.launch_nonce != self.claims.launch_nonce
        ):
            raise ValueError("GPU quote commitment differs from its claims")
        return self

    def report_data_nonce(self) -> str:
        return canonical_sha256(self)


class GpuRegistrationSignatureV1(FrozenWireModel):
    schema: Literal["chutes.gpu-registration-signature"] = "chutes.gpu-registration-signature"
    version: Literal[1] = 1
    server_id: str
    request_nonce: str
    quote_commitment: GpuQuoteCommitmentV1

    @field_validator("request_nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("request_nonce must be lowercase sha256")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class GpuReservationClaimRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-reservation-claim"] = "chutes.gpu-reservation-claim"
    version: Literal[1] = 1
    token: str = Field(..., min_length=67, max_length=512)
    claims_sha256: str

    @field_validator("claims_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        return GpuLaunchReservationResponseV1._valid_digest(value)


class GpuReservationStateRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-reservation-state"] = "chutes.gpu-reservation-state"
    version: Literal[1] = 1
    reservation_id: str
    claims_sha256: str
    process_incarnation: str

    @field_validator("claims_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        return GpuLaunchReservationResponseV1._valid_digest(value)


class GpuReservationQuarantineRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-reservation-quarantine"] = "chutes.gpu-reservation-quarantine"
    version: Literal[1] = 1
    reservation_id: str
    claims_sha256: str
    process_incarnation: str
    failure_code: str = Field(..., min_length=1, max_length=128)
    failure_reason: str = Field(..., min_length=1, max_length=2000)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("claims_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        return GpuLaunchReservationResponseV1._valid_digest(value)


class GpuRecoveryAuthorizeRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-recovery-authorize"] = "chutes.gpu-recovery-authorize"
    version: Literal[1] = 1
    report_id: str
    reason: str = Field(..., min_length=1, max_length=2000)


class GpuHostLossFinalizeRequestV1(FrozenWireModel):
    """Administrator authorization to retire an unrecoverable phase-two host."""

    schema: Literal["chutes.gpu-host-loss-finalize.v1"] = (
        "chutes.gpu-host-loss-finalize.v1"
    )
    version: Literal[1] = 1
    operation_id: str
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    receipt_sha256: str
    reason: str = Field(..., min_length=1, max_length=2000)

    @field_validator("receipt_sha256")
    @classmethod
    def _valid_receipt_sha256(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("receipt_sha256 must be 64 lowercase hexadecimal characters")
        return value


class TdQuoteCommitmentV1(FrozenWireModel):
    schema: Literal["chutes.td-quote-commitment"] = "chutes.td-quote-commitment"
    version: Literal[1] = 1
    reservation_sha256: str
    launch_nonce: str
    attested_spki_sha256: str
    release_target_sha256: str
    boot_generation: int = Field(..., ge=1)

    @field_validator("reservation_sha256", "attested_spki_sha256", "release_target_sha256")
    @classmethod
    def _valid_sha(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("commitment digest must be 64 lowercase hex characters")
        return value

    @field_validator("launch_nonce")
    @classmethod
    def _valid_nonce(cls, value: str) -> str:
        return _validate_b64(value, "launch_nonce", 32, 32)

    def report_data_nonce(self) -> str:
        return canonical_sha256(self)


class TdRegistrationSignatureV1(FrozenWireModel):
    schema: Literal["chutes.td-registration-signature"] = "chutes.td-registration-signature"
    version: Literal[1] = 1
    server_id: str
    request_nonce: str
    tee_type: Literal["sev-snp", "tdx"]
    storage_role: bool
    quote_commitment: TdQuoteCommitmentV1

    @field_validator("request_nonce")
    @classmethod
    def _valid_request_nonce(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("request_nonce must be 64 lowercase hex characters")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class RegistrySessionClaimsV1(FrozenWireModel):
    schema: Literal["chutes.registry-session"] = "chutes.registry-session"
    version: Literal[1] = 1
    session_id: str
    server_id: str
    scope_id: str
    launch_config_id: Optional[str] = None
    attested_cert_sha256: str
    repository: str = Field(..., min_length=3, max_length=255)
    actions: List[Literal["pull"]]
    manifest_digest: str
    descriptor_closure_sha256: str
    issued_at: datetime
    expires_at: datetime

    @field_validator("attested_cert_sha256")
    @classmethod
    def _valid_cert_hash(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("attested_cert_sha256 must be a sha256 digest")
        return value

    @field_validator("descriptor_closure_sha256")
    @classmethod
    def _valid_closure_hash(cls, value: str) -> str:
        value = value.lower()
        if not _HEX_64_RE.fullmatch(value):
            raise ValueError("descriptor_closure_sha256 must be a sha256 digest")
        return value

    @field_validator("repository")
    @classmethod
    def _valid_repository(cls, value: str) -> str:
        if not _OCI_REPOSITORY_RE.fullmatch(value):
            raise ValueError("repository is not a canonical OCI distribution name")
        return value

    @field_validator("manifest_digest")
    @classmethod
    def _valid_manifest_digest(cls, value: str) -> str:
        value = value.lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("manifest_digest must be an exact sha256 OCI digest")
        return value

    @field_validator("actions")
    @classmethod
    def _one_pull_action(cls, value: List[str]) -> List[str]:
        if value != ["pull"]:
            raise ValueError("registry sessions authorize exactly the pull action")
        return value


class RegistrySessionRequestV1(FrozenWireModel):
    schema: Literal["chutes.registry-session-request"] = "chutes.registry-session-request"
    version: Literal[1] = 1
    repository: str = Field(..., min_length=3, max_length=255)
    action: Literal["pull"] = "pull"
    manifest_digest: str
    launch_config_id: Optional[str] = None

    @field_validator("manifest_digest")
    @classmethod
    def _valid_manifest_digest(cls, value: str) -> str:
        value = value.lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("manifest_digest must be an exact sha256 OCI digest")
        return value

    @field_validator("repository")
    @classmethod
    def _valid_repository(cls, value: str) -> str:
        if not _OCI_REPOSITORY_RE.fullmatch(value):
            raise ValueError("repository is not a canonical OCI distribution name")
        return value


class RegistrySessionResponseV1(FrozenWireModel):
    schema: Literal["chutes.registry-session-result"] = "chutes.registry-session-result"
    version: Literal[1] = 1
    token: str
    expires_at: datetime
    launch_config_id: Optional[str] = None
    repository: str
    manifest_digest: str
    descriptor_closure_sha256: str
    allowed_manifests: List[str]
    allowed_blobs: List[str]
    allowed_manifest_tags: List[str]
    manifest_tag_digests: Dict[str, str]


class HostEnrollmentVoucher(Base):
    __tablename__ = "host_enrollment_vouchers"

    voucher_id = Column(String, primary_key=True, default=generate_uuid)
    voucher_hash = Column(String(64), nullable=False, unique=True)
    owner_hotkey = Column(String, nullable=False)
    host_id = Column(String, nullable=False)
    tee_type = Column(String, nullable=False)
    compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    channel = Column(String, nullable=False)
    enrollment_generation = Column(Integer, nullable=False)
    claims = Column(JSONB, nullable=False)
    provider = Column(String, nullable=True)
    source = Column(String, nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    consumed_key_generation = Column(Integer, nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "enrollment_generation",
            name="uq_host_enrollment_generation",
        ),
        CheckConstraint("tee_type IN ('sev-snp', 'tdx')", name="ck_host_voucher_tee_type"),
        CheckConstraint(
            "(compute_type = 'cpu') OR (compute_type = 'gpu' AND tee_type = 'tdx')",
            name="ck_host_voucher_compute_type",
        ),
        CheckConstraint("enrollment_generation > 0", name="ck_host_voucher_generation"),
        CheckConstraint("expires_at > issued_at", name="ck_host_voucher_expiry"),
        CheckConstraint(
            "(consumed_at IS NULL AND consumed_key_generation IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_key_generation > 0)",
            name="ck_host_voucher_consumption",
        ),
        Index(
            "idx_host_vouchers_owner_active",
            "owner_hotkey",
            "host_id",
            postgresql_where=text("consumed_at IS NULL AND invalidated_at IS NULL"),
        ),
    )


class HostKeyGeneration(Base):
    __tablename__ = "host_key_generations"

    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="CASCADE"), primary_key=True)
    generation = Column(Integer, primary_key=True)
    enrollment_generation = Column(Integer, nullable=False)
    ed25519_public_key = Column(String, nullable=False)
    ed25519_fingerprint = Column(String(64), nullable=False)
    x25519_public_key = Column(String, nullable=False)
    x25519_fingerprint = Column(String(64), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("ed25519_fingerprint", name="uq_host_key_ed25519_fingerprint"),
        UniqueConstraint("x25519_fingerprint", name="uq_host_key_x25519_fingerprint"),
        CheckConstraint("generation > 0", name="ck_host_key_generation"),
        CheckConstraint("enrollment_generation > 0", name="ck_host_key_enrollment_generation"),
        Index(
            "uq_host_key_active",
            "host_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class HostEnrollmentChallenge(Base):
    __tablename__ = "host_enrollment_challenges"

    challenge_id = Column(String, primary_key=True, default=generate_uuid)
    voucher_id = Column(
        String,
        ForeignKey("host_enrollment_vouchers.voucher_id", ondelete="CASCADE"),
        nullable=False,
    )
    ed25519_public_key = Column(String, nullable=False)
    x25519_public_key = Column(String, nullable=False)
    challenge_hash = Column(String(64), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="ck_host_enrollment_challenge_expiry"),
        Index("idx_host_enrollment_challenge_voucher", "voucher_id", "expires_at"),
    )


class HostPcsMailbox(Base):
    __tablename__ = "host_pcs_mailboxes"

    message_id = Column(String, primary_key=True, default=generate_uuid)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="CASCADE"), nullable=False)
    owner_hotkey = Column(String, nullable=False)
    enrollment_generation = Column(Integer, nullable=False)
    key_generation = Column(Integer, nullable=False)
    recipient_fingerprint = Column(String(64), nullable=False)
    envelope = Column(JSONB, nullable=False)
    envelope_sha256 = Column(String(64), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "enrollment_generation > 0 AND key_generation > 0",
            name="ck_host_pcs_mailbox_generations",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_host_pcs_mailbox_expiry"),
        Index(
            "uq_host_pcs_mailbox_active",
            "host_id",
            unique=True,
            postgresql_where=text("consumed_at IS NULL AND invalidated_at IS NULL"),
        ),
    )


class StorageLaunchIntent(Base):
    """Validator-owned authorization to launch one immutable storage target."""

    __tablename__ = "storage_launch_intents"

    intent_id = Column(String, primary_key=True, default=generate_uuid)
    target_id = Column(
        String,
        ForeignKey("guest_release_targets.target_id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    tee_type = Column(String, nullable=False)
    channel = Column(String, nullable=False)
    host_id = Column(
        String,
        ForeignKey("hosts.host_id", ondelete="RESTRICT"),
        nullable=False,
    )
    owner_hotkey = Column(String, nullable=False)
    server_id = Column(String, nullable=False)
    process_incarnation = Column(String, nullable=False)
    profile_id = Column(String, nullable=False)
    image_sha256 = Column(String(64), nullable=False)
    image_version = Column(String, nullable=False)
    host_compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    active_cpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    kernel_sha256 = Column(String(64), nullable=True)
    initrd_sha256 = Column(String(64), nullable=True)
    cmdline_sha256 = Column(String(64), nullable=True)
    launch_contract = Column(JSONB, nullable=True)
    state = Column(String, nullable=False, default="active", server_default="active")
    claim_generation = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_claimed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "tee_type IN ('sev-snp', 'tdx')",
            name="ck_storage_launch_intent_tee",
        ),
        CheckConstraint(
            "state IN ('active', 'superseded')",
            name="ck_storage_launch_intent_state",
        ),
        CheckConstraint(
            "claim_generation >= 0",
            name="ck_storage_launch_intent_generation",
        ),
        CheckConstraint(
            "image_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_storage_launch_intent_image_sha",
        ),
        CheckConstraint(
            "(host_compute_type = 'cpu' AND target_id IS NOT NULL "
            "AND gpu_release_id IS NULL AND active_cpu_release_id IS NULL "
            "AND kernel_sha256 IS NULL AND initrd_sha256 IS NULL "
            "AND cmdline_sha256 IS NULL AND launch_contract IS NULL) OR "
            "(host_compute_type = 'gpu' AND tee_type = 'tdx' AND target_id IS NULL "
            "AND gpu_release_id IS NOT NULL AND active_cpu_release_id IS NOT NULL "
            "AND kernel_sha256 ~ '^[0-9a-f]{64}$' "
            "AND initrd_sha256 ~ '^[0-9a-f]{64}$' "
            "AND cmdline_sha256 ~ '^[0-9a-f]{64}$' "
            "AND launch_contract IS NOT NULL)",
            name="ck_storage_launch_intent_host_scope",
        ),
        Index(
            "idx_storage_launch_intents_slot",
            "tee_type",
            "channel",
            "host_compute_type",
            "state",
            "host_id",
        ),
        Index(
            "uq_storage_launch_intent_active_host",
            "tee_type",
            "channel",
            "host_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
    )


class TdLaunchReservation(Base):
    __tablename__ = "td_launch_reservations"

    reservation_id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, nullable=False, unique=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    owner_hotkey = Column(String, nullable=False)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    server_id = Column(String, nullable=False)
    role = Column(String, nullable=False)
    compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    claims_version = Column(Integer, nullable=False, default=1, server_default="1")
    host_compute_type = Column(String, nullable=False, default="cpu", server_default="cpu")
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    active_cpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    tee_type = Column(String, nullable=False)
    process_incarnation = Column(String, nullable=False)
    boot_generation = Column(Integer, nullable=False)
    release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    image_sha256 = Column(String(64), nullable=False)
    image_version = Column(String, nullable=False)
    profile_id = Column(String, nullable=False)
    chute_id = Column(String, nullable=True)
    job_id = Column(String, nullable=True)
    container_repository = Column(String, nullable=True)
    container_manifest_digest = Column(String, nullable=True)
    storage_intent_id = Column(
        String,
        ForeignKey("storage_launch_intents.intent_id", ondelete="RESTRICT"),
        nullable=True,
    )
    storage_intent_generation = Column(Integer, nullable=True)
    launch_nonce = Column(String, nullable=False)
    release_target_sha256 = Column(String(64), nullable=False)
    claims = Column(JSONB, nullable=False)
    claims_sha256 = Column(String(64), nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    handed_to_host_at = Column(DateTime(timezone=True), nullable=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    consumed_attestation_id = Column(String, nullable=True)
    consumed_cert_pubkey_hash = Column(String(64), nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "boot_generation",
            name="uq_td_launch_reservation_boot",
        ),
        UniqueConstraint(
            "consumed_attestation_id",
            name="uq_td_launch_reservation_attestation",
        ),
        CheckConstraint("role IN ('chute', 'storage')", name="ck_td_reservation_role"),
        CheckConstraint("compute_type = 'cpu'", name="ck_td_reservation_compute_type"),
        CheckConstraint(
            "(claims_version = 1 AND host_compute_type = 'cpu' "
            "AND gpu_release_id IS NULL AND active_cpu_release_id IS NULL) OR "
            "(claims_version = 2 AND role = 'storage' AND host_compute_type = 'gpu' "
            "AND tee_type = 'tdx' AND gpu_release_id IS NOT NULL "
            "AND active_cpu_release_id IS NOT NULL)",
            name="ck_td_reservation_claim_version",
        ),
        CheckConstraint("tee_type IN ('sev-snp', 'tdx')", name="ck_td_reservation_tee_type"),
        CheckConstraint(
            "host_key_generation > 0 AND boot_generation > 0",
            name="ck_td_reservation_generations",
        ),
        CheckConstraint(
            "(role = 'storage' AND chute_id IS NULL AND job_id IS NULL "
            "AND container_repository IS NULL AND container_manifest_digest IS NULL) OR "
            "(role = 'chute' AND chute_id IS NOT NULL "
            "AND container_repository IS NOT NULL "
            "AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$')",
            name="ck_td_reservation_chute_role",
        ),
        CheckConstraint(
            "(storage_intent_id IS NULL AND storage_intent_generation IS NULL) OR "
            "(role = 'storage' AND storage_intent_id IS NOT NULL "
            "AND storage_intent_generation > 0)",
            name="ck_td_reservation_storage_intent",
        ),
        CheckConstraint(
            "claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_td_reservation_claims_sha",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_td_reservation_expiry"),
        CheckConstraint(
            "(consumed_at IS NULL AND consumed_attestation_id IS NULL "
            "AND consumed_cert_pubkey_hash IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_attestation_id IS NOT NULL "
            "AND consumed_cert_pubkey_hash ~ '^[0-9a-f]{64}$')",
            name="ck_td_reservation_consumption",
        ),
        Index(
            "idx_td_reservation_host_active",
            "host_id",
            "role",
            postgresql_where=text("consumed_at IS NULL AND invalidated_at IS NULL"),
        ),
        Index(
            "uq_td_reservation_storage_intent_generation",
            "storage_intent_id",
            "storage_intent_generation",
            unique=True,
            postgresql_where=text("storage_intent_id IS NOT NULL"),
        ),
    )


class GpuInventoryReport(Base):
    __tablename__ = "gpu_inventory_reports"

    report_id = Column(String, primary_key=True, default=generate_uuid)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    report_generation = Column(Integer, nullable=False)
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    profile_contract_sha256 = Column(String(64), nullable=False)
    topology_fingerprint = Column(String(64), nullable=False)
    claims = Column(JSONB, nullable=False)
    claims_sha256 = Column(String(64), nullable=False)
    reconciliation_status = Column(String, nullable=False)
    failure_reason = Column(Text, nullable=True)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    accepted_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "host_boot_generation",
            "report_generation",
            name="uq_gpu_inventory_report_generation",
        ),
        ForeignKeyConstraint(
            ["host_id", "host_key_generation"],
            ["host_key_generations.host_id", "host_key_generations.generation"],
            name="fk_gpu_inventory_report_host_key",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 AND report_generation > 0",
            name="ck_gpu_inventory_report_generations",
        ),
        CheckConstraint(
            "profile_contract_sha256 ~ '^[0-9a-f]{64}$' "
            "AND topology_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND claims_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_inventory_report_digests",
        ),
        CheckConstraint(
            "reconciliation_status IN ('accepted', 'rejected', 'quarantined')",
            name="ck_gpu_inventory_report_status",
        ),
        CheckConstraint(
            "(reconciliation_status = 'accepted' AND accepted_at IS NOT NULL "
            "AND failure_reason IS NULL) OR "
            "(reconciliation_status <> 'accepted' AND accepted_at IS NULL "
            "AND failure_reason IS NOT NULL)",
            name="ck_gpu_inventory_report_acceptance",
        ),
        Index(
            "idx_gpu_inventory_reports_host",
            "host_id",
            "host_boot_generation",
            "report_generation",
        ),
    )


class GpuAllocationGroup(Base):
    __tablename__ = "gpu_allocation_groups"

    allocation_group_id = Column(String, primary_key=True, default=generate_uuid)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    generation = Column(Integer, nullable=False)
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    profile_id = Column(String, nullable=False)
    profile_contract_sha256 = Column(String(64), nullable=False)
    topology_fingerprint = Column(String(64), nullable=False)
    gpu_bdfs = Column(JSONB, nullable=False)
    gpu_uuids = Column(JSONB, nullable=False)
    gpu_identifiers = Column(JSONB, nullable=False)
    gpu_attestation_certificate_sha256s = Column(JSONB, nullable=False)
    iommu_domains = Column(JSONB, nullable=False)
    reset_domains = Column(JSONB, nullable=False)
    nvlink_edges = Column(JSONB, nullable=False)
    nvswitch_fabric = Column(JSONB, nullable=False)
    model = Column(String, nullable=False)
    gpu_count = Column(Integer, nullable=False)
    vram_mib = Column(Integer, nullable=False)
    state = Column(String, nullable=False)
    management_mode = Column(String, nullable=True)
    reservation_owner = Column(String, nullable=True)
    reservation_id = Column(
        String,
        ForeignKey(
            "gpu_launch_reservations.reservation_id",
            ondelete="RESTRICT",
            use_alter=True,
            name="fk_gpu_allocation_group_reservation",
        ),
        nullable=True,
    )
    reservation_generation = Column(Integer, nullable=False, default=0, server_default="0")
    process_incarnation = Column(String, nullable=True)
    last_report_id = Column(
        String,
        ForeignKey("gpu_inventory_reports.report_id", ondelete="RESTRICT"),
        nullable=False,
    )
    recovery_authorization_id = Column(String, nullable=True)
    recovery_report_id = Column(
        String,
        ForeignKey("gpu_inventory_reports.report_id", ondelete="RESTRICT"),
        nullable=True,
    )
    recovery_nonce_hash = Column(String(64), nullable=True)
    recovery_authorized_by = Column(String, nullable=True)
    recovery_authorized_at = Column(DateTime(timezone=True), nullable=True)
    recovery_started_at = Column(DateTime(timezone=True), nullable=True)
    recovery_completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_reason = Column(Text, nullable=True)
    failure_metadata = Column(JSONB(none_as_null=True), nullable=True)
    discovered_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    available_at = Column(DateTime(timezone=True), nullable=True)
    reserved_at = Column(DateTime(timezone=True), nullable=True)
    launching_at = Column(DateTime(timezone=True), nullable=True)
    running_at = Column(DateTime(timezone=True), nullable=True)
    resetting_at = Column(DateTime(timezone=True), nullable=True)
    quarantined_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "host_id",
            "profile_id",
            "topology_fingerprint",
            name="uq_gpu_allocation_group_host_topology",
        ),
        ForeignKeyConstraint(
            ["host_id", "host_key_generation"],
            ["host_key_generations.host_id", "host_key_generations.generation"],
            name="fk_gpu_allocation_group_host_key",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 "
            "AND generation > 0 AND reservation_generation >= 0",
            name="ck_gpu_allocation_group_generations",
        ),
        CheckConstraint(
            "profile_contract_sha256 ~ '^[0-9a-f]{64}$' "
            "AND topology_fingerprint ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_allocation_group_digests",
        ),
        CheckConstraint(
            "gpu_count > 0 AND vram_mib > 0 "
            "AND jsonb_typeof(gpu_bdfs) = 'array' "
            "AND jsonb_array_length(gpu_bdfs) = gpu_count "
            "AND jsonb_typeof(gpu_uuids) = 'array' "
            "AND jsonb_array_length(gpu_uuids) = gpu_count "
            "AND jsonb_typeof(gpu_identifiers) = 'array' "
            "AND jsonb_array_length(gpu_identifiers) = gpu_count "
            "AND jsonb_typeof(gpu_attestation_certificate_sha256s) = 'array' "
            "AND jsonb_array_length(gpu_attestation_certificate_sha256s) = gpu_count "
            "AND jsonb_typeof(iommu_domains) = 'array' "
            "AND jsonb_typeof(reset_domains) = 'array' "
            "AND jsonb_typeof(nvlink_edges) = 'array' "
            "AND jsonb_typeof(nvswitch_fabric) = 'array'",
            name="ck_gpu_allocation_group_shape",
        ),
        CheckConstraint(
            "state IN ('discovered', 'available', 'reserved', 'launching', "
            "'running', 'resetting', 'release_pending', 'recovery_required', "
            "'quarantined', 'retired')",
            name="ck_gpu_allocation_group_state",
        ),
        CheckConstraint(
            "(state IN ('discovered', 'available', 'retired') "
            "AND management_mode IS NULL AND reservation_owner IS NULL "
            "AND reservation_id IS NULL AND process_incarnation IS NULL) "
            "OR state = 'quarantined' OR "
            "(state IN ('reserved', 'launching', 'running', 'resetting', "
            "'release_pending', 'recovery_required') "
            "AND management_mode IN ('platform', 'miner') "
            "AND reservation_owner IS NOT NULL AND reservation_id IS NOT NULL "
            "AND reservation_generation > 0 AND process_incarnation IS NOT NULL) OR "
            "(state IN ('resetting', 'release_pending') AND management_mode IS NULL "
            "AND reservation_owner IS NULL AND reservation_id IS NULL "
            "AND process_incarnation IS NULL)",
            name="ck_gpu_allocation_group_owner",
        ),
        CheckConstraint(
            "(recovery_authorization_id IS NULL AND recovery_report_id IS NULL "
            "AND recovery_nonce_hash IS NULL AND recovery_authorized_by IS NULL "
            "AND recovery_authorized_at IS NULL AND recovery_started_at IS NULL "
            "AND recovery_completed_at IS NULL) OR "
            "(recovery_authorization_id IS NOT NULL AND recovery_report_id IS NOT NULL "
            "AND recovery_nonce_hash ~ '^[0-9a-f]{64}$' "
            "AND recovery_authorized_by IS NOT NULL AND recovery_authorized_at IS NOT NULL "
            "AND (recovery_started_at IS NULL "
            "OR recovery_started_at >= recovery_authorized_at) "
            "AND (recovery_completed_at IS NULL OR "
            "(recovery_started_at IS NOT NULL "
            "AND recovery_completed_at >= recovery_started_at)))",
            name="ck_gpu_allocation_group_recovery",
        ),
        CheckConstraint(
            "(state = 'quarantined' AND quarantined_at IS NOT NULL "
            "AND failure_code IS NOT NULL AND failure_reason IS NOT NULL) OR "
            "(state <> 'quarantined' AND quarantined_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL "
            "AND failure_metadata IS NULL)",
            name="ck_gpu_allocation_group_failure",
        ),
        Index(
            "idx_gpu_allocation_groups_match",
            "state",
            "profile_id",
            "model",
            "gpu_count",
            "vram_mib",
        ),
        Index(
            "idx_gpu_allocation_groups_host",
            "host_id",
            "host_boot_generation",
            "state",
        ),
    )


class GpuLaunchReservation(Base):
    __tablename__ = "gpu_launch_reservations"

    reservation_id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, nullable=False, unique=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    claims_version = Column(Integer, nullable=False, default=1, server_default="1")
    claims = Column(JSONB, nullable=False)
    claims_sha256 = Column(String(64), nullable=False)
    owner_hotkey = Column(String, nullable=False)
    workload_owner = Column(String, nullable=False)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    reservation_generation = Column(Integer, nullable=False)
    management_mode = Column(String, nullable=False)
    server_id = Column(String, nullable=False)
    process_incarnation = Column(String, nullable=False)
    gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=False,
    )
    profile_id = Column(String, nullable=False)
    profile_contract_sha256 = Column(String(64), nullable=False)
    measurement_name = Column(String, nullable=False)
    kernel_measurement_mode = Column(String, nullable=False)
    topology_fingerprint = Column(String(64), nullable=False)
    gpu_bdfs = Column(JSONB, nullable=False)
    gpu_uuids = Column(JSONB, nullable=False)
    gpu_identifiers = Column(JSONB, nullable=False)
    gpu_attestation_certificate_sha256s = Column(JSONB, nullable=False)
    qemu_binary_sha256 = Column(String(64), nullable=False)
    qemu_package_version = Column(String, nullable=False)
    machine_type = Column(String, nullable=False)
    tdvf_sha256 = Column(String(64), nullable=False)
    image_sha256 = Column(String(64), nullable=False)
    image_version = Column(String, nullable=False)
    kernel_sha256 = Column(String(64), nullable=False)
    initrd_sha256 = Column(String(64), nullable=False)
    mode_cmdline_sha256 = Column(String(64), nullable=False)
    release_target_sha256 = Column(String(64), nullable=False)
    legacy_vm_name = Column(String, nullable=True)
    legacy_migration_id = Column(
        String,
        ForeignKey("gpu_legacy_migrations.migration_id", ondelete="RESTRICT"),
        nullable=True,
    )
    chute_id = Column(String, nullable=True)
    job_id = Column(String, nullable=True)
    container_repository = Column(String, nullable=True)
    container_manifest_digest = Column(String, nullable=True)
    chute_version = Column(String, nullable=True)
    descriptor_closure_sha256 = Column(String(64), nullable=True)
    allowed_manifests = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_blobs = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_manifest_tags = Column(JSONB, nullable=False, default=list, server_default="[]")
    manifest_tag_digests = Column(JSONB, nullable=False, default=dict, server_default="{}")
    launch_nonce = Column(String, nullable=False)
    state = Column(String, nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    guest_consumed_at = Column(DateTime(timezone=True), nullable=True)
    launching_at = Column(DateTime(timezone=True), nullable=True)
    running_at = Column(DateTime(timezone=True), nullable=True)
    teardown_started_at = Column(DateTime(timezone=True), nullable=True)
    reset_completed_at = Column(DateTime(timezone=True), nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=True)
    expired_at = Column(DateTime(timezone=True), nullable=True)
    quarantined_at = Column(DateTime(timezone=True), nullable=True)
    registration_attestation_id = Column(
        String,
        ForeignKey("server_attestations.attestation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    launch_command_id = Column(String, nullable=True)
    launch_dispatched_at = Column(DateTime(timezone=True), nullable=True)
    launch_ack_at = Column(DateTime(timezone=True), nullable=True)
    launch_ack_status = Column(String, nullable=True)
    launch_ack_detail = Column(Text, nullable=True)
    workload_dispatched_at = Column(DateTime(timezone=True), nullable=True)
    workload_command_id = Column(String, nullable=True)
    teardown_command_id = Column(String, nullable=True)
    teardown_dispatched_at = Column(DateTime(timezone=True), nullable=True)
    teardown_requested_at = Column(DateTime(timezone=True), nullable=True)
    teardown_reason = Column(Text, nullable=True)
    teardown_ack_at = Column(DateTime(timezone=True), nullable=True)
    teardown_ack_status = Column(String, nullable=True)
    teardown_ack_detail = Column(Text, nullable=True)
    last_reconciled_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_reason = Column(Text, nullable=True)
    failure_metadata = Column(JSONB(none_as_null=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "allocation_group_id",
            "reservation_generation",
            name="uq_gpu_launch_group_generation",
        ),
        ForeignKeyConstraint(
            ["host_id", "host_key_generation"],
            ["host_key_generations.host_id", "host_key_generations.generation"],
            name="fk_gpu_launch_reservation_host_key",
            ondelete="RESTRICT",
        ),
        CheckConstraint("claims_version = 1", name="ck_gpu_launch_claims_version"),
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 "
            "AND allocation_group_generation > 0 AND reservation_generation > 0",
            name="ck_gpu_launch_generations",
        ),
        CheckConstraint(
            "management_mode IN ('platform', 'miner')",
            name="ck_gpu_launch_mode",
        ),
        CheckConstraint(
            "state IN ('reserved', 'claimed', 'launching', 'running', "
            "'resetting', 'released', 'expired', 'quarantined')",
            name="ck_gpu_launch_state",
        ),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$' "
            "AND claims_sha256 ~ '^[0-9a-f]{64}$' "
            "AND profile_contract_sha256 ~ '^[0-9a-f]{64}$' "
            "AND topology_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND qemu_binary_sha256 ~ '^[0-9a-f]{64}$' "
            "AND tdvf_sha256 ~ '^[0-9a-f]{64}$' "
            "AND image_sha256 ~ '^[0-9a-f]{64}$' "
            "AND kernel_sha256 ~ '^[0-9a-f]{64}$' "
            "AND initrd_sha256 ~ '^[0-9a-f]{64}$' "
            "AND mode_cmdline_sha256 ~ '^[0-9a-f]{64}$' "
            "AND release_target_sha256 ~ '^[0-9a-f]{64}$' "
            "AND jsonb_typeof(gpu_attestation_certificate_sha256s) = 'array' "
            "AND jsonb_array_length(gpu_attestation_certificate_sha256s) = "
            "jsonb_array_length(gpu_uuids) "
            "AND (container_manifest_digest IS NULL "
            "OR container_manifest_digest ~ '^sha256:[0-9a-f]{64}$')",
            name="ck_gpu_launch_digests",
        ),
        CheckConstraint(
            "(management_mode = 'platform' AND chute_id IS NOT NULL "
            "AND legacy_vm_name IS NULL AND legacy_migration_id IS NULL "
            "AND chute_version IS NOT NULL "
            "AND container_repository IS NOT NULL "
            "AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$' "
            "AND descriptor_closure_sha256 ~ '^[0-9a-f]{64}$' "
            "AND jsonb_typeof(allowed_manifests) = 'array' "
            "AND jsonb_array_length(allowed_manifests) > 0 "
            "AND jsonb_typeof(allowed_blobs) = 'array' "
            "AND jsonb_array_length(allowed_blobs) > 0 "
            "AND jsonb_typeof(allowed_manifest_tags) = 'array' "
            "AND jsonb_array_length(allowed_manifest_tags) > 0 "
            "AND jsonb_typeof(manifest_tag_digests) = 'object' "
            "AND manifest_tag_digests <> '{}'::jsonb) OR "
            "(management_mode = 'miner' "
            "AND ((legacy_vm_name IS NULL AND legacy_migration_id IS NULL) OR "
            "(legacy_vm_name IS NOT NULL AND legacy_migration_id IS NOT NULL)) "
            "AND chute_id IS NULL AND job_id IS NULL "
            "AND chute_version IS NULL "
            "AND container_repository IS NULL AND container_manifest_digest IS NULL "
            "AND descriptor_closure_sha256 IS NULL "
            "AND allowed_manifests = '[]'::jsonb "
            "AND allowed_blobs = '[]'::jsonb "
            "AND allowed_manifest_tags = '[]'::jsonb "
            "AND manifest_tag_digests = '{}'::jsonb)",
            name="ck_gpu_launch_workload",
        ),
        CheckConstraint(
            "(launch_ack_at IS NULL AND launch_ack_status IS NULL "
            "AND launch_ack_detail IS NULL) OR "
            "(launch_command_id IS NOT NULL AND launch_dispatched_at IS NOT NULL "
            "AND launch_ack_at IS NOT NULL AND launch_ack_status IS NOT NULL)",
            name="ck_gpu_launch_command_ack",
        ),
        CheckConstraint(
            "(teardown_requested_at IS NULL AND teardown_command_id IS NULL "
            "AND teardown_dispatched_at IS NULL "
            "AND teardown_reason IS NULL AND teardown_ack_at IS NULL "
            "AND teardown_ack_status IS NULL AND teardown_ack_detail IS NULL) OR "
            "(teardown_requested_at IS NOT NULL AND teardown_reason IS NOT NULL "
            "AND ((teardown_command_id IS NULL AND teardown_dispatched_at IS NULL "
            "AND teardown_ack_at IS NULL "
            "AND teardown_ack_status IS NULL AND teardown_ack_detail IS NULL) OR "
            "(teardown_command_id IS NOT NULL AND teardown_dispatched_at IS NOT NULL "
            "AND teardown_ack_at IS NOT NULL "
            "AND teardown_ack_status IS NOT NULL) OR "
            "(teardown_command_id IS NOT NULL AND teardown_dispatched_at IS NOT NULL "
            "AND teardown_ack_at IS NULL "
            "AND teardown_ack_status IS NULL AND teardown_ack_detail IS NULL)))",
            name="ck_gpu_teardown_command_ack",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_gpu_launch_expiry"),
        CheckConstraint(
            "(state = 'quarantined' AND quarantined_at IS NOT NULL "
            "AND failure_code IS NOT NULL AND failure_reason IS NOT NULL) "
            "OR state <> 'quarantined'",
            name="ck_gpu_launch_terminal_failure",
        ),
        Index(
            "uq_gpu_launch_reservation_active_group",
            "allocation_group_id",
            unique=True,
            postgresql_where=text(
                "state IN ('reserved', 'claimed', 'launching', 'running', 'resetting')"
            ),
        ),
        Index(
            "idx_gpu_launch_reservations_host",
            "host_id",
            "state",
            "expires_at",
        ),
    )


class RegistrySession(Base):
    __tablename__ = "registry_sessions"

    session_id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, nullable=False, unique=True)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    scope_id = Column(String, nullable=False)
    launch_config_id = Column(
        String,
        ForeignKey("launch_configs.config_id", ondelete="CASCADE"),
        nullable=True,
    )
    attested_cert_pubkey_hash = Column(String(64), nullable=False)
    repository = Column(String, nullable=False)
    actions = Column(JSONB, nullable=False)
    manifest_digest = Column(String, nullable=False)
    allowed_manifests = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_blobs = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_manifest_tags = Column(JSONB, nullable=False, default=list, server_default="[]")
    manifest_tag_digests = Column(JSONB, nullable=False, default=dict, server_default="{}")
    descriptor_closure_sha256 = Column(String(64), nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "scope_id",
            name="uq_registry_session_server_scope",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_registry_session_expiry"),
        CheckConstraint(
            "jsonb_typeof(allowed_manifests) = 'array' "
            "AND jsonb_typeof(allowed_blobs) = 'array' "
            "AND jsonb_typeof(allowed_manifest_tags) = 'array' "
            "AND jsonb_typeof(manifest_tag_digests) = 'object' "
            "AND (descriptor_closure_sha256 IS NULL "
            "OR descriptor_closure_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_registry_session_closure",
        ),
        Index(
            "idx_registry_session_server_active",
            "server_id",
            "expires_at",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )
