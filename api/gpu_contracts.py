"""Versioned, canonical GPU registration and physical-lifecycle wire contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from api.host.schemas import (
    FrozenWireModel,
    GpuLaunchReservationClaimsV1,
    GpuMinerReservationRequestV1,
    GpuQuoteCommitmentV1,
    canonical_json_bytes,
    canonical_sha256,
)

_HEX = r"^[0-9a-f]{64}$"
_LUKS_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
LifecycleOperationType = Literal[
    "pre_slot_claim_quarantine",
    "launch_rollback",
    "release_rollover",
    "normal_delete",
    "ownerless_group_recovery",
    "forced_dead_guest_recovery",
]
LifecyclePhase = Literal[
    "intent",
    "physical_result",
    "receipt_accepted",
    "local_release_acked",
    "finalized",
    "quarantined",
]
GpuRegistrationFailureCode = Literal[
    "gpu_registration_verification_failed",
    "gpu_registration_lineage_ended",
    "gpu_registration_nonce_revoked",
    "gpu_legacy_hotplug_custody_mismatch",
    "gpu_legacy_hotplug_failed",
    "gpu_registration_generation_superseded",
]


def gpu_registration_client_request_id(
    reservation_id: str,
    server_id: str,
    attested_spki_sha256: str,
    request_generation: int,
) -> str:
    """Domain-separated deterministic nonce-request identity for reboot recovery."""

    spki = attested_spki_sha256.lower()
    if not reservation_id or not server_id or request_generation < 1:
        raise ValueError("GPU registration nonce request identity is incomplete")
    import re

    if not re.fullmatch(_HEX, spki):
        raise ValueError("GPU registration nonce request SPKI must be lowercase sha256")
    digest = canonical_sha256(
        {
            "schema": "chutes.gpu-registration-nonce-request-id.v1",
            "version": 1,
            "reservation_id": reservation_id,
            "server_id": server_id,
            "attested_spki_sha256": spki,
            "request_generation": request_generation,
        }
    )
    return f"gpu-registration-v2-{digest}"


class GpuRegistrationNonceRequestV2(FrozenWireModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )
    schema: Literal["chutes.gpu-registration-nonce.v2"] = "chutes.gpu-registration-nonce.v2"
    version: Literal[2] = 2
    client_request_id: str = Field(..., min_length=1, max_length=256)
    request_generation: int = Field(..., ge=1, le=1024)
    launch_reservation: str = Field(..., min_length=67, max_length=4096)
    claims_sha256: str = Field(..., pattern=_HEX)
    server_id: str = Field(..., min_length=1, max_length=256)

    @field_validator("version", mode="before")
    @classmethod
    def _exact_integer_version(cls, value: Any) -> int:
        if type(value) is not int or value != 2:
            raise ValueError("GPU registration nonce request version must be integer 2")
        return value


class GpuRegistrationNonceV2(FrozenWireModel):
    schema: Literal["chutes.gpu-registration-nonce.v2"] = "chutes.gpu-registration-nonce.v2"
    version: Literal[2] = 2
    client_request_id: str
    request_generation: int = Field(..., ge=1, le=1024)
    nonce_id: str
    reservation_id: str
    nonce: str = Field(..., pattern=_HEX)
    expires_at: datetime
    claimed_attempt_id: Optional[str] = None
    status_url: Optional[str] = None

    @model_validator(mode="after")
    def _claimed_shape(self) -> "GpuRegistrationNonceV2":
        if (self.claimed_attempt_id is None) != (self.status_url is None):
            raise ValueError("claimed_attempt_id and status_url must be present or absent together")
        if self.claimed_attempt_id is not None and self.status_url != (
            f"/servers/gpu/registration/attempts/{self.claimed_attempt_id}"
        ):
            raise ValueError("claimed registration status_url is not canonical")
        return self


class GpuRegistrationRequestV2(FrozenWireModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )
    schema: Literal["chutes.gpu-registration-request.v2"] = "chutes.gpu-registration-request.v2"
    version: Literal[2] = 2
    nonce_id: str
    nonce: str = Field(..., pattern=_HEX)
    server_id: str
    quote: str
    gpu_evidence: List[Dict[str, Any]] = Field(..., min_length=1, max_length=64)
    gpu_uuids: List[str] = Field(..., min_length=1, max_length=64)
    launch_reservation: str = Field(..., min_length=67, max_length=4096)
    quote_commitment: GpuQuoteCommitmentV1
    td_signature: str = Field(..., min_length=1, max_length=2048)
    external_host: Optional[str] = None
    external_ports: Optional[Dict[str, int]] = None
    endpoints: Optional[Dict[str, Any]] = None

    @field_validator("version", mode="before")
    @classmethod
    def _exact_integer_version(cls, value: Any) -> int:
        if type(value) is not int or value != 2:
            raise ValueError("GPU registration request version must be integer 2")
        return value

    @field_validator("gpu_uuids")
    @classmethod
    def _canonical_gpu_uuids(cls, value: List[str]) -> List[str]:
        return GpuLaunchReservationClaimsV1._canonical_gpu_uuids(value)

    @model_validator(mode="after")
    def _matches_commitment(self) -> "GpuRegistrationRequestV2":
        claims = self.quote_commitment.claims
        if self.server_id != claims.server_id:
            raise ValueError("GPU registration server differs from its commitment")
        selected = set(self.gpu_uuids)
        reserved = set(claims.gpu_uuids)
        if claims.management_mode == "platform":
            valid_selection = self.gpu_uuids == claims.gpu_uuids
        else:
            valid_selection = bool(selected) and selected.issubset(reserved)
        if not valid_selection:
            raise ValueError("GPU registration UUID selection does not match its management mode")
        return self

    def signing_bytes(self) -> bytes:
        """The signature covers every request field except the signature itself."""
        return canonical_json_bytes(
            self.model_dump(mode="json", exclude={"td_signature"}, exclude_none=True)
        )

    def request_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude_none=True))


class GpuRegistrationResponseV2(FrozenWireModel):
    schema: Literal["chutes.gpu-registration-response.v2"] = "chutes.gpu-registration-response.v2"
    version: Literal[2] = 2
    attempt_id: str
    state: Literal["processing", "completed", "failed"]
    status_url: str
    retry_after_seconds: Optional[int] = Field(None, ge=1, le=300)
    failure_code: Optional[GpuRegistrationFailureCode] = None
    failure_detail: Optional[str] = None
    server_id: Optional[str] = None
    owner_hotkey: Optional[str] = None
    reservation_id: Optional[str] = None
    claims_sha256: Optional[str] = Field(None, pattern=_HEX)
    allocation_group_id: Optional[str] = None
    allocation_group_generation: Optional[int] = Field(None, ge=1)
    process_incarnation: Optional[str] = None
    gpu_uuids: Optional[List[str]] = None
    gpu_identifiers: Optional[List[str]] = None
    management_mode: Optional[Literal["platform", "miner"]] = None
    measurement_version: Optional[str] = None
    measurement_name: Optional[str] = None
    measurement_config_fingerprint: Optional[str] = Field(None, pattern=_HEX)
    trust_set_fingerprint: Optional[str] = Field(None, pattern=_HEX)
    registration_id: Optional[str] = None
    attestation_id: Optional[str] = None
    verified_at: Optional[datetime] = None
    runtime_session: Optional[str] = None
    runtime_session_expires_at: Optional[datetime] = None
    registration_replay_until: Optional[datetime] = None
    status: Optional[Literal["registered"]] = None

    @model_validator(mode="after")
    def _state_shape(self) -> "GpuRegistrationResponseV2":
        completed = (
            self.server_id,
            self.owner_hotkey,
            self.reservation_id,
            self.claims_sha256,
            self.allocation_group_id,
            self.allocation_group_generation,
            self.process_incarnation,
            self.gpu_uuids,
            self.gpu_identifiers,
            self.management_mode,
            self.measurement_version,
            self.measurement_name,
            self.measurement_config_fingerprint,
            self.trust_set_fingerprint,
            self.registration_id,
            self.attestation_id,
            self.verified_at,
            self.runtime_session,
            self.runtime_session_expires_at,
            self.registration_replay_until,
            self.status,
        )
        if self.state == "processing":
            if (
                self.retry_after_seconds is None
                or any(value is not None for value in completed)
                or self.failure_code
                or self.failure_detail
            ):
                raise ValueError("processing registration response has invalid fields")
        elif self.state == "completed":
            if (
                any(value is None for value in completed)
                or self.retry_after_seconds is not None
                or self.failure_code
                or self.failure_detail
            ):
                raise ValueError("completed registration response is incomplete")
        elif (
            not self.failure_code
            or not self.failure_detail
            or any(value is not None for value in completed)
            or self.retry_after_seconds is not None
        ):
            raise ValueError("failed registration response has invalid fields")
        return self


class GpuLifecycleOperationV1(FrozenWireModel):
    schema: Literal["chutes.gpu-lifecycle-operation.v1"] = "chutes.gpu-lifecycle-operation.v1"
    version: Literal[1] = 1
    operation_id: str
    operation_type: LifecycleOperationType
    phase: LifecyclePhase = "intent"
    host_id: str
    host_key_generation: int = Field(..., ge=1)
    host_boot_generation: int = Field(..., ge=1)
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    reservation_id: Optional[str] = None
    reservation_generation: Optional[int] = Field(None, ge=1)
    claims_sha256: Optional[str] = Field(None, pattern=_HEX)
    process_incarnation: Optional[str] = None
    topology_fingerprint: str = Field(..., pattern=_HEX)
    gpu_bdfs: List[str]
    gpu_uuids: List[str]
    owner_hotkey: str
    stable_server_id: Optional[str] = None
    management_mode: Optional[Literal["platform", "miner"]] = None
    migration_id: Optional[str] = None
    recovery_authorization_id: Optional[str] = None
    current_gpu_release_id: Optional[str] = None
    desired_gpu_release_id: Optional[str] = None
    desired_release_target_sha256: Optional[str] = Field(None, pattern=_HEX)
    group_state: Optional[
        Literal[
            "discovered",
            "resetting",
            "release_pending",
            "available",
            "recovery_required",
            "quarantined",
        ]
    ] = None
    physical_result_sha256: Optional[str] = Field(None, pattern=_HEX)
    result_outcome: Optional[Literal["accepted", "quarantined"]] = None
    receipt_id: Optional[str] = None
    receipt_sha256: Optional[str] = Field(None, pattern=_HEX)
    local_release_ack_sha256: Optional[str] = Field(None, pattern=_HEX)
    failure_code: Optional[str] = Field(None, min_length=1, max_length=128)
    failure_reason: Optional[str] = Field(None, min_length=1, max_length=2000)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None

    @field_validator("operation_id")
    @classmethod
    def _canonical_operation_id(cls, value: str) -> str:
        try:
            parsed = UUID(value)
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("lifecycle operation_id must be a UUID") from exc
        if str(parsed) != value:
            raise ValueError("lifecycle operation_id must be a bare canonical lowercase UUID")
        return value

    @field_validator("gpu_bdfs")
    @classmethod
    def _bdfs(cls, value: List[str]) -> List[str]:
        return GpuLaunchReservationClaimsV1._canonical_bdfs(value)

    @field_validator("gpu_uuids")
    @classmethod
    def _uuids(cls, value: List[str]) -> List[str]:
        return GpuLaunchReservationClaimsV1._canonical_gpu_uuids(value)

    @model_validator(mode="after")
    def _reservation_shape(self) -> "GpuLifecycleOperationV1":
        lineage = (
            self.reservation_id,
            self.reservation_generation,
            self.claims_sha256,
            self.process_incarnation,
        )
        present = [value is not None for value in lineage]
        if self.operation_type == "ownerless_group_recovery":
            if any(present):
                raise ValueError("ownerless recovery cannot carry reservation lineage")
        elif self.operation_type == "pre_slot_claim_quarantine":
            if any(present) and not all(present):
                raise ValueError("pre-slot lineage must be either absent or complete")
        elif not all(present):
            raise ValueError("reservation-backed lifecycle intent requires complete lineage")
        rollover = (
            self.current_gpu_release_id,
            self.desired_gpu_release_id,
            self.desired_release_target_sha256,
        )
        if self.operation_type == "release_rollover":
            if any(value is None for value in rollover):
                raise ValueError("release rollover requires immutable old/new release identity")
            if self.current_gpu_release_id == self.desired_gpu_release_id:
                raise ValueError("release rollover requires distinct old/new releases")
        elif any(value is not None for value in rollover):
            raise ValueError("only release rollover may carry old/new release identity")
        if self.phase == "quarantined":
            if not self.failure_code or not self.failure_reason:
                raise ValueError(
                    "quarantined lifecycle response requires a durable failure code and reason"
                )
        elif self.failure_code is not None or self.failure_reason is not None:
            raise ValueError("only a quarantined lifecycle response may carry failure details")
        if (self.receipt_id is None) != (self.receipt_sha256 is None):
            raise ValueError("lifecycle receipt id and digest must be present together")
        if self.local_release_ack_sha256 is not None and self.receipt_id is None:
            raise ValueError("lifecycle local-release ACK requires a durable receipt")
        terminal = self.phase in {"finalized", "quarantined"}
        if terminal != (self.finalized_at is not None):
            raise ValueError("lifecycle finalized_at must be present exactly for terminal phases")
        return self


class GpuReleaseRolloverEnsureRequestV1(FrozenWireModel):
    """Exact old/new release identity used to create or replay a rollover intent."""

    schema: Literal["chutes.gpu-release-rollover-ensure.v1"] = (
        "chutes.gpu-release-rollover-ensure.v1"
    )
    version: Literal[1] = 1
    reservation_id: str
    reservation_generation: int = Field(..., ge=1)
    claims_sha256: str = Field(..., pattern=_HEX)
    current_gpu_release_id: str
    desired_gpu_release_id: str
    desired_release_target_sha256: str = Field(..., pattern=_HEX)

    @model_validator(mode="after")
    def _release_changed(self) -> "GpuReleaseRolloverEnsureRequestV1":
        if self.current_gpu_release_id == self.desired_gpu_release_id:
            raise ValueError("GPU release rollover requires distinct current and desired releases")
        return self


class GpuReleaseRolloverResponseV1(FrozenWireModel):
    """Durable release-rollover envelope embedded in dispatch and poll responses."""

    schema: Literal["chutes.gpu-release-rollover.v1"] = "chutes.gpu-release-rollover.v1"
    version: Literal[1] = 1
    host_id: str
    reservation_id: str
    reservation_generation: int = Field(..., ge=1)
    claims_sha256: str = Field(..., pattern=_HEX)
    current_gpu_release_id: str
    desired_gpu_release_id: str
    desired_release_target_sha256: str = Field(..., pattern=_HEX)
    operation: GpuLifecycleOperationV1

    @model_validator(mode="after")
    def _exact_operation(self) -> "GpuReleaseRolloverResponseV1":
        operation = self.operation
        if (
            operation.operation_type != "release_rollover"
            or operation.host_id != self.host_id
            or operation.reservation_id != self.reservation_id
            or operation.reservation_generation != self.reservation_generation
            or operation.claims_sha256 != self.claims_sha256
            or operation.current_gpu_release_id != self.current_gpu_release_id
            or operation.desired_gpu_release_id != self.desired_gpu_release_id
            or operation.desired_release_target_sha256 != self.desired_release_target_sha256
        ):
            raise ValueError("GPU release rollover response has mismatched lifecycle lineage")
        if self.current_gpu_release_id == self.desired_gpu_release_id:
            raise ValueError("GPU release rollover requires distinct current and desired releases")
        return self


class GpuSourceReaderSourceV1(FrozenWireModel):
    namespace: Literal["storage", "tdx-cache"]
    source_path_sha256: str = Field(..., pattern=_HEX)
    reader_pids: List[int] = Field(default_factory=list)

    @field_validator("reader_pids")
    @classmethod
    def _canonical_reader_pids(cls, value: List[int]) -> List[int]:
        if value != sorted(set(value)) or any(pid < 0 for pid in value):
            raise ValueError(
                "forced recovery source-reader PIDs must be sorted unique nonnegative integers"
            )
        return value


class GpuSourceReaderResultV1(FrozenWireModel):
    schema: Literal["chutes.gpu-source-reader-result.v1"] = "chutes.gpu-source-reader-result.v1"
    version: Literal[1] = 1
    migration_id: Optional[str] = None
    readers_absent: bool
    sources: List[GpuSourceReaderSourceV1]

    @model_validator(mode="after")
    def _exact_sources(self) -> "GpuSourceReaderResultV1":
        if [item.namespace for item in self.sources] != ["storage", "tdx-cache"]:
            raise ValueError("forced recovery requires exact storage and tdx-cache sources")
        no_readers = all(not item.reader_pids for item in self.sources)
        if self.readers_absent != no_readers:
            raise ValueError(
                "source-reader absence must exactly match the captured reader PID lists"
            )
        return self


class GpuPhysicalResultV1(FrozenWireModel):
    schema: Literal["chutes.gpu-physical-result.v1"] = "chutes.gpu-physical-result.v1"
    version: Literal[1] = 1
    operation_id: str
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    reservation_id: Optional[str] = None
    reservation_generation: Optional[int] = Field(None, ge=1)
    claims_sha256: Optional[str] = Field(None, pattern=_HEX)
    process_incarnation: Optional[str] = None
    topology_fingerprint: str = Field(..., pattern=_HEX)
    gpu_bdfs: List[str]
    gpu_uuids: List[str]
    qemu_absent: bool
    reset_succeeded: bool
    original_drivers_restored: bool
    guest_shutdown_clean: Optional[bool] = None
    source_reader_result: Optional[GpuSourceReaderResultV1] = None
    failure_code: Optional[str] = Field(None, min_length=1, max_length=128)
    failure_reason: Optional[str] = Field(None, min_length=1, max_length=2000)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("gpu_bdfs")
    @classmethod
    def _bdfs(cls, value: List[str]) -> List[str]:
        return GpuLaunchReservationClaimsV1._canonical_bdfs(value)

    @field_validator("gpu_uuids")
    @classmethod
    def _uuids(cls, value: List[str]) -> List[str]:
        return GpuLaunchReservationClaimsV1._canonical_gpu_uuids(value)

    @model_validator(mode="after")
    def _failure_shape(self) -> "GpuPhysicalResultV1":
        success = (
            self.qemu_absent
            and self.reset_succeeded
            and self.original_drivers_restored
            and (self.source_reader_result is None or self.source_reader_result.readers_absent)
        )
        if success and (self.failure_code is not None or self.failure_reason is not None):
            raise ValueError("successful physical result cannot carry failure metadata")
        if not success and (not self.failure_code or not self.failure_reason):
            raise ValueError("failed physical result requires exact failure metadata")
        return self


class GpuResetReceiptV1(FrozenWireModel):
    schema: Literal["chutes.gpu-reset-receipt.v1"] = "chutes.gpu-reset-receipt.v1"
    version: Literal[1] = 1
    operation_id: str
    receipt_id: str
    result_sha256: str = Field(..., pattern=_HEX)
    outcome: Literal["accepted", "quarantined"]
    local_release_required: bool
    phase: Literal["receipt_accepted", "quarantined"]
    accepted_at: datetime

    @model_validator(mode="after")
    def _outcome_shape(self) -> "GpuResetReceiptV1":
        if (self.outcome == "accepted") != (self.phase == "receipt_accepted"):
            raise ValueError("reset receipt outcome and phase differ")
        if self.local_release_required != (self.outcome == "accepted"):
            raise ValueError("only an accepted result requires local release")
        return self


class GpuLocalReleaseAckV1(FrozenWireModel):
    schema: Literal["chutes.gpu-local-release-ack.v1"] = "chutes.gpu-local-release-ack.v1"
    version: Literal[1] = 1
    operation_id: str
    receipt_id: str
    result_sha256: str = Field(..., pattern=_HEX)
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    reservation_id: Optional[str] = None
    process_incarnation: Optional[str] = None
    local_owner_absent: Literal[True]
    local_claim_absent: Literal[True]
    local_slot_absent: Literal[True]
    local_state_sha256: str = Field(..., pattern=_HEX)
    observed_at: datetime


class GpuRecoveryAuthorizationEnvelopeV1(FrozenWireModel):
    schema: Literal["chutes.gpu-recovery-authorization.v1"] = "chutes.gpu-recovery-authorization.v1"
    version: Literal[1] = 1
    authorization_id: str
    operation: GpuLifecycleOperationV1
    inventory_report_id: str
    inventory_report_sha256: str = Field(..., pattern=_HEX)
    recovery_nonce: str = Field(..., pattern=_HEX)
    expires_at: datetime


class GpuRecoveryReclaimRequestV1(FrozenWireModel):
    schema: Literal["chutes.gpu-recovery-reclaim.v1"] = "chutes.gpu-recovery-reclaim.v1"
    version: Literal[1] = 1
    authorization_id: str
    reservation: GpuMinerReservationRequestV1


class GpuRecoveryEventV1(FrozenWireModel):
    schema: Literal["chutes.gpu-recovery-event.v1"] = "chutes.gpu-recovery-event.v1"
    version: Literal[1] = 1
    event_id: str
    authorization_id: str
    operation_id: str
    state: Literal[
        "authorized",
        "started",
        "reset_reported",
        "receipt_accepted",
        "local_release_acked",
        "completed",
        "quarantined",
        "revoked",
        "reclaimed",
    ]
    reset_result_sha256: Optional[str] = Field(None, pattern=_HEX)
    source_reader_result_sha256: Optional[str] = Field(None, pattern=_HEX)
    receipt_id: Optional[str] = None
    receipt_sha256: Optional[str] = Field(None, pattern=_HEX)
    local_release_ack_sha256: Optional[str] = Field(None, pattern=_HEX)
    reclaim_reservation_id: Optional[str] = None
    reclaim_reservation_generation: Optional[int] = Field(None, ge=1)
    current_inventory_report_id: Optional[str] = None
    current_inventory_report_sha256: Optional[str] = Field(None, pattern=_HEX)
    current_host_key_generation: Optional[int] = Field(None, ge=1)
    current_host_boot_generation: Optional[int] = Field(None, ge=1)
    completed_at: Optional[datetime] = None

    @model_validator(mode="after")
    def _reclaim_binding(self) -> "GpuRecoveryEventV1":
        values = (
            self.reclaim_reservation_id,
            self.reclaim_reservation_generation,
            self.current_inventory_report_id,
            self.current_inventory_report_sha256,
            self.current_host_key_generation,
            self.current_host_boot_generation,
            self.completed_at,
        )
        if self.state == "reclaimed":
            if any(value is None for value in values):
                raise ValueError(
                    "reclaimed recovery event requires exact current inventory and host binding"
                )
        elif any(
            value is not None
            for value in (
                self.reclaim_reservation_id,
                self.reclaim_reservation_generation,
                self.current_inventory_report_id,
                self.current_inventory_report_sha256,
                self.current_host_key_generation,
                self.current_host_boot_generation,
            )
        ):
            raise ValueError("only reclaimed recovery event may carry current reclaim binding")
        return self


class GpuHotplugPayloadV1(FrozenWireModel):
    server_id: str
    reservation_id: str
    reservation_claims_sha256: str = Field(..., pattern=_HEX)
    process_incarnation: str
    legacy_migration_id: str


class GpuHotplugCommandV1(FrozenWireModel):
    schema: Literal["chutes.gpu-hotplug-command.v1"] = "chutes.gpu-hotplug-command.v1"
    version: Literal[1] = 1
    command_id: str
    host_id: str
    host_key_generation: int = Field(..., ge=1)
    host_boot_generation: int = Field(..., ge=1)
    reservation_id: str
    reservation_generation: int = Field(..., ge=1)
    claims_sha256: str = Field(..., pattern=_HEX)
    allocation_group_id: str
    allocation_group_generation: int = Field(..., ge=1)
    process_incarnation: str
    stable_server_id: str
    migration_id: str
    payload: GpuHotplugPayloadV1
    payload_sha256: str = Field(..., pattern=_HEX)

    def identity_document(self) -> Dict[str, Any]:
        return {
            "schema": "chutes.gpu-hotplug-command-identity.v1",
            "version": 1,
            "command_type": "hotplug_gpu_legacy",
            "host_id": self.host_id,
            "host_key_generation": self.host_key_generation,
            "host_boot_generation": self.host_boot_generation,
            "reservation_id": self.reservation_id,
            "reservation_generation": self.reservation_generation,
            "claims_sha256": self.claims_sha256,
            "allocation_group_id": self.allocation_group_id,
            "allocation_group_generation": self.allocation_group_generation,
            "process_incarnation": self.process_incarnation,
            "stable_server_id": self.stable_server_id,
            "migration_id": self.migration_id,
            "payload_sha256": self.payload_sha256,
        }

    @model_validator(mode="after")
    def _identity(self) -> "GpuHotplugCommandV1":
        if canonical_sha256(self.payload) != self.payload_sha256:
            raise ValueError("GPU hotplug payload digest differs from canonical payload")
        if self.command_id != f"gpu-hotplug-{canonical_sha256(self.identity_document())}":
            raise ValueError("GPU hotplug command id differs from deterministic identity")
        if (
            self.payload.server_id != self.stable_server_id
            or self.payload.reservation_id != self.reservation_id
            or self.payload.reservation_claims_sha256 != self.claims_sha256
            or self.payload.process_incarnation != self.process_incarnation
            or self.payload.legacy_migration_id != self.migration_id
        ):
            raise ValueError("GPU hotplug payload differs from command lineage")
        return self


class _StrictGpuHotplugWireModel(FrozenWireModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )


class GpuHotplugSourceIdentityV1(_StrictGpuHotplugWireModel):
    schema: Literal["chutes.gpu-hotplug-source-identity.v1"] = Field(...)
    version: Literal[1] = Field(...)
    filesystem_uuid: StrictStr = Field(..., pattern=_LUKS_UUID)
    inode: StrictInt = Field(..., ge=1)
    size_bytes: StrictInt = Field(..., ge=1)
    luks_uuid: StrictStr = Field(..., pattern=_LUKS_UUID)


class GpuHotplugObjectStateV1(_StrictGpuHotplugWireModel):
    namespace: Literal["storage", "tdx-cache"]
    block_node_name: StrictStr
    device_id: StrictStr
    serial: StrictStr
    source_identity: GpuHotplugSourceIdentityV1
    block_node_present: StrictBool
    device_present: StrictBool
    device_bound: StrictBool


class GpuHotplugCommandAckV1(_StrictGpuHotplugWireModel):
    schema: Literal["chutes.gpu-hotplug-command-ack.v1"] = Field(...)
    version: Literal[1] = Field(...)
    command_id: StrictStr
    payload_sha256: StrictStr = Field(..., pattern=_HEX)
    state: Literal["acked", "failed"]
    objects: List[GpuHotplugObjectStateV1]
    ack_sha256: StrictStr = Field(..., pattern=_HEX)
    failure_code: Optional[StrictStr] = None
    failure_reason: Optional[StrictStr] = None

    @model_validator(mode="after")
    def _ack_shape(self) -> "GpuHotplugCommandAckV1":
        namespaces = [item.namespace for item in self.objects]
        expected_bindings = [
            (
                "storage",
                "gpu-legacy-storage-node",
                "gpu-legacy-storage-device",
                "gpu-legacy-storage",
            ),
            (
                "tdx-cache",
                "gpu-legacy-cache-node",
                "gpu-legacy-cache-device",
                "gpu-legacy-cache",
            ),
        ]
        observed_bindings = [
            (item.namespace, item.block_node_name, item.device_id, item.serial)
            for item in self.objects
        ]
        if observed_bindings != expected_bindings:
            raise ValueError("GPU hotplug ACK namespace binding tuple differs")
        if self.objects[0].source_identity == self.objects[1].source_identity:
            raise ValueError("GPU hotplug ACK source identities must be distinct")
        exact = bool(
            namespaces == ["storage", "tdx-cache"]
            and all(
                item.block_node_present and item.device_present and item.device_bound
                for item in self.objects
            )
        )
        if self.state == "acked" and (not exact or self.failure_code or self.failure_reason):
            raise ValueError("successful hotplug ACK requires both exact backend/frontend bindings")
        if self.state == "failed" and (not self.failure_code or not self.failure_reason):
            raise ValueError("failed hotplug ACK requires failure metadata")
        document = self.model_dump(mode="json", exclude={"ack_sha256"}, exclude_none=True)
        if canonical_sha256(document) != self.ack_sha256:
            raise ValueError("GPU hotplug ACK digest differs from canonical ACK")
        return self
