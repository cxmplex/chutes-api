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


class EnrollmentVoucherResponseV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-voucher"] = "chutes.host-enrollment-voucher"
    version: Literal[1] = 1
    voucher: str = Field(..., min_length=67, max_length=512)
    claims: EnrollmentVoucherClaimsV1


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


class HostEnrollmentResponseV1(FrozenWireModel):
    schema: Literal["chutes.host-enrollment-result"] = "chutes.host-enrollment-result"
    version: Literal[1] = 1
    host_id: str
    owner_hotkey: str
    enrollment_generation: int = Field(..., ge=1)
    key_generation: int = Field(..., ge=1)
    provisioning_state: Literal["persisting_identity", "awaiting_pcs", "ready"]


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


class TdSocketChallengeV1(FrozenWireModel):
    schema: Literal["chutes.td-socket-challenge"] = "chutes.td-socket-challenge"
    version: Literal[1] = 1
    challenge_id: str
    session_id: str
    server_id: str
    attested_spki_sha256: str
    challenge: str
    expires_at: datetime


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


class HostEnrollmentVoucher(Base):
    __tablename__ = "host_enrollment_vouchers"

    voucher_id = Column(String, primary_key=True, default=generate_uuid)
    voucher_hash = Column(String(64), nullable=False, unique=True)
    owner_hotkey = Column(String, nullable=False)
    host_id = Column(String, nullable=False)
    tee_type = Column(String, nullable=False)
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
        nullable=False,
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
        Index(
            "idx_storage_launch_intents_slot",
            "tee_type",
            "channel",
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


class RegistrySession(Base):
    __tablename__ = "registry_sessions"

    session_id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, nullable=False, unique=True)
    server_id = Column(String, ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False)
    attested_cert_pubkey_hash = Column(String(64), nullable=False)
    repository = Column(String, nullable=False)
    actions = Column(JSONB, nullable=False)
    manifest_digest = Column(String, nullable=False)
    allowed_manifests = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_blobs = Column(JSONB, nullable=False, default=list, server_default="[]")
    allowed_manifest_tags = Column(JSONB, nullable=False, default=list, server_default="[]")
    descriptor_closure_sha256 = Column(String(64), nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("server_id", name="uq_registry_session_server"),
        CheckConstraint("expires_at > issued_at", name="ck_registry_session_expiry"),
        CheckConstraint(
            "jsonb_typeof(allowed_manifests) = 'array' "
            "AND jsonb_typeof(allowed_blobs) = 'array' "
            "AND jsonb_typeof(allowed_manifest_tags) = 'array' "
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
