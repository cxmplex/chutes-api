"""Durable database authority for GPU registration and physical ownership transitions."""

from sqlalchemy import (
    CheckConstraint,
    Column,
    DDL,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from api.database import Base, generate_uuid


class GpuRegistrationNonce(Base):
    __tablename__ = "gpu_registration_nonces"

    nonce_id = Column(String, primary_key=True, default=generate_uuid)
    client_request_id = Column(String, nullable=False)
    request_generation = Column(Integer, nullable=False)
    registration_generation = Column(Integer, nullable=False, default=1, server_default="1")
    peer_spki_sha256 = Column(String(64), nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    server_ip = Column(String, nullable=False)
    nonce_value = Column(String(64), nullable=True)
    nonce_hash = Column(String(64), nullable=False)
    state = Column(String, nullable=False, default="issued", server_default="issued")
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    claimed_attempt_id = Column(
        String,
        ForeignKey(
            "gpu_registration_attempts.attempt_id",
            ondelete="RESTRICT",
            use_alter=True,
            name="fk_gpu_registration_nonce_attempt",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "reservation_id",
            "client_request_id",
            name="uq_gpu_registration_nonce_request",
        ),
        CheckConstraint(
            "state IN ('issued', 'claimed', 'expired', 'revoked')",
            name="ck_gpu_registration_nonce_state",
        ),
        CheckConstraint(
            "nonce_hash ~ '^[0-9a-f]{64}$' AND peer_spki_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_registration_nonce_digest",
        ),
        CheckConstraint(
            "request_generation > 0 AND request_generation <= 1024 "
            "AND registration_generation > 0 AND registration_generation <= 1024",
            name="ck_gpu_registration_nonce_generation",
        ),
        CheckConstraint(
            "(state IN ('issued', 'claimed') AND nonce_value ~ '^[0-9a-f]{64}$') OR "
            "(state IN ('expired', 'revoked') AND nonce_value IS NULL)",
            name="ck_gpu_registration_nonce_value",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_gpu_registration_nonce_expiry"),
        CheckConstraint(
            "(state = 'claimed' AND claimed_attempt_id IS NOT NULL) OR "
            "(state = 'issued' AND claimed_attempt_id IS NULL) OR "
            "state IN ('expired', 'revoked')",
            name="ck_gpu_registration_nonce_claim",
        ),
        Index(
            "uq_gpu_registration_nonce_issued_reservation",
            "reservation_id",
            unique=True,
            postgresql_where=text("state = 'issued'"),
        ),
        Index(
            "idx_gpu_registration_nonce_expiry",
            "expires_at",
            postgresql_where=text("state IN ('issued', 'claimed')"),
        ),
    )


class GpuRegistrationAttempt(Base):
    __tablename__ = "gpu_registration_attempts"

    attempt_id = Column(String, primary_key=True, default=generate_uuid)
    nonce_id = Column(
        String,
        ForeignKey("gpu_registration_nonces.nonce_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    registration_generation = Column(Integer, nullable=False, default=1, server_default="1")
    registration_id = Column(String, nullable=True, unique=True)
    request_sha256 = Column(String(64), nullable=False)
    request_payload_ciphertext = Column(Text, nullable=True)
    request_payload_key_id = Column(
        String(64),
        ForeignKey(
            "gpu_registration_recovery_key_epochs.key_id",
            ondelete="RESTRICT",
            name="fk_gpu_registration_attempt_recovery_key",
        ),
        nullable=True,
    )
    peer_certificate_pem = Column(Text, nullable=False)
    peer_certificate_sha256 = Column(String(64), nullable=False)
    peer_spki_sha256 = Column(String(64), nullable=False)
    state = Column(String, nullable=False, default="processing", server_default="processing")
    processing_lease_owner = Column(String, nullable=True)
    processing_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attestation_id = Column(
        String,
        ForeignKey("server_attestations.attestation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    stable_response = Column(JSONB, nullable=True)
    stable_response_sha256 = Column(String(64), nullable=True)
    response_ready_at = Column(DateTime(timezone=True), nullable=True)
    registration_replay_until = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "state IN ('processing', 'completed', 'failed')",
            name="ck_gpu_registration_attempt_state",
        ),
        CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND peer_certificate_sha256 ~ '^[0-9a-f]{64}$' "
            "AND peer_spki_sha256 ~ '^[0-9a-f]{64}$' "
            "AND (request_payload_key_id IS NULL OR "
            "request_payload_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') "
            "AND (stable_response_sha256 IS NULL OR stable_response_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_registration_attempt_digests",
        ),
        CheckConstraint(
            "registration_generation > 0 AND registration_generation <= 1024",
            name="ck_gpu_registration_attempt_generation",
        ),
        CheckConstraint(
            "(processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL) OR "
            "(processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)",
            name="ck_gpu_registration_attempt_lease",
        ),
        CheckConstraint(
            "(state = 'processing' AND request_payload_ciphertext IS NOT NULL "
            "AND request_payload_key_id IS NOT NULL "
            "AND registration_id IS NULL AND attestation_id IS NULL "
            "AND stable_response IS NULL AND stable_response_sha256 IS NULL "
            "AND response_ready_at IS NULL "
            "AND registration_replay_until IS NULL AND completed_at IS NULL "
            "AND failure_code IS NULL AND failure_detail IS NULL) OR "
            "(state = 'completed' AND registration_id IS NOT NULL "
            "AND attestation_id IS NOT NULL AND stable_response IS NOT NULL "
            "AND stable_response_sha256 ~ '^[0-9a-f]{64}$' "
            "AND completed_at IS NOT NULL "
            "AND ((response_ready_at IS NULL AND registration_replay_until IS NULL) "
            "OR (response_ready_at IS NOT NULL "
            "AND response_ready_at >= completed_at "
            "AND registration_replay_until > response_ready_at)) "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL "
            "AND request_payload_ciphertext IS NULL "
            "AND request_payload_key_id IS NULL "
            "AND failure_code IS NULL AND failure_detail IS NULL) OR "
            "(state = 'failed' AND registration_id IS NULL "
            "AND attestation_id IS NULL AND stable_response IS NULL "
            "AND stable_response_sha256 IS NULL AND failure_code IS NOT NULL "
            "AND failure_detail IS NOT NULL AND completed_at IS NOT NULL "
            "AND registration_replay_until > completed_at "
            "AND response_ready_at IS NULL "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL "
            "AND request_payload_ciphertext IS NULL "
            "AND request_payload_key_id IS NULL)",
            name="ck_gpu_registration_attempt_result",
        ),
        Index(
            "idx_gpu_registration_attempt_reservation",
            "reservation_id",
            created_at.desc(),
        ),
        Index(
            "idx_gpu_registration_attempt_processing",
            "processing_lease_expires_at",
            postgresql_where=text("state = 'processing'"),
        ),
    )


class GpuRegistrationConflict(Base):
    __tablename__ = "gpu_registration_conflicts"

    conflict_id = Column(String, primary_key=True, default=generate_uuid)
    attempt_id = Column(
        String,
        ForeignKey("gpu_registration_attempts.attempt_id", ondelete="RESTRICT"),
        nullable=False,
    )
    nonce_id = Column(
        String,
        ForeignKey("gpu_registration_nonces.nonce_id", ondelete="RESTRICT"),
        nullable=False,
    )
    request_sha256 = Column(String(64), nullable=False)
    request_payload_ciphertext = Column(Text, nullable=True)
    request_payload_key_id = Column(
        String(64),
        ForeignKey(
            "gpu_registration_recovery_key_epochs.key_id",
            ondelete="RESTRICT",
            name="fk_gpu_registration_conflict_recovery_key",
        ),
        nullable=True,
    )
    peer_certificate_pem = Column(Text, nullable=False)
    peer_certificate_sha256 = Column(String(64), nullable=False)
    peer_spki_sha256 = Column(String(64), nullable=False)
    quote_sha256 = Column(String(64), nullable=False)
    evidence_sha256 = Column(String(64), nullable=False)
    signature_sha256 = Column(String(64), nullable=False)
    state = Column(String, nullable=False, default="recorded", server_default="recorded")
    processing_lease_owner = Column(String, nullable=True)
    processing_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    verification_attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at = Column(DateTime(timezone=True), nullable=True, server_default=func.now())
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    last_transient_error_code = Column(String, nullable=True)
    last_transient_error_detail = Column(Text, nullable=True)
    last_transient_error_at = Column(DateTime(timezone=True), nullable=True)
    verification_detail = Column(Text, nullable=True)
    fence_state = Column(String, nullable=True)
    fence_operation_id = Column(String, nullable=True)
    fence_recorded_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    verified_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "nonce_id",
            "request_sha256",
            "peer_spki_sha256",
            "peer_certificate_sha256",
            name="uq_gpu_registration_conflict",
        ),
        CheckConstraint(
            "state IN ('recorded', 'verifying', 'invalid', 'verified_competitor', 'dismissed')",
            name="ck_gpu_registration_conflict_state",
        ),
        CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND peer_certificate_sha256 ~ '^[0-9a-f]{64}$' "
            "AND peer_spki_sha256 ~ '^[0-9a-f]{64}$' "
            "AND quote_sha256 ~ '^[0-9a-f]{64}$' "
            "AND evidence_sha256 ~ '^[0-9a-f]{64}$' "
            "AND signature_sha256 ~ '^[0-9a-f]{64}$' "
            "AND (request_payload_key_id IS NULL OR "
            "request_payload_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')",
            name="ck_gpu_registration_conflict_digests",
        ),
        CheckConstraint(
            "(processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL) OR "
            "(processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)",
            name="ck_gpu_registration_conflict_lease",
        ),
        CheckConstraint(
            "verification_attempt_count >= 0 AND ((last_transient_error_code IS NULL "
            "AND last_transient_error_detail IS NULL AND last_transient_error_at IS NULL) "
            "OR (last_transient_error_code IS NOT NULL "
            "AND last_transient_error_detail IS NOT NULL "
            "AND last_transient_error_at IS NOT NULL))",
            name="ck_gpu_registration_conflict_retry_audit",
        ),
        CheckConstraint(
            "(state = 'recorded' AND request_payload_ciphertext IS NOT NULL "
            "AND request_payload_key_id IS NOT NULL "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL AND verified_at IS NULL "
            "AND verification_detail IS NULL AND next_attempt_at IS NOT NULL "
            "AND fence_state IS NULL AND fence_operation_id IS NULL "
            "AND fence_recorded_at IS NULL) OR "
            "(state = 'verifying' AND request_payload_ciphertext IS NOT NULL "
            "AND request_payload_key_id IS NOT NULL "
            "AND processing_lease_owner IS NOT NULL "
            "AND processing_lease_expires_at IS NOT NULL AND verified_at IS NULL "
            "AND verification_attempt_count > 0 AND last_attempt_at IS NOT NULL "
            "AND next_attempt_at IS NULL AND verification_detail IS NULL "
            "AND fence_state IS NULL AND fence_operation_id IS NULL "
            "AND fence_recorded_at IS NULL) OR "
            "(state IN ('invalid', 'dismissed') "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL AND verified_at IS NOT NULL "
            "AND request_payload_ciphertext IS NULL "
            "AND request_payload_key_id IS NULL "
            "AND next_attempt_at IS NULL AND verification_detail IS NOT NULL "
            "AND fence_state IS NULL AND fence_operation_id IS NULL "
            "AND fence_recorded_at IS NULL) OR "
            "(state = 'verified_competitor' "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL AND verified_at IS NOT NULL "
            "AND request_payload_ciphertext IS NULL "
            "AND request_payload_key_id IS NULL "
            "AND next_attempt_at IS NULL AND verification_detail IS NOT NULL "
            "AND ((fence_state = 'pending' AND fence_operation_id IS NULL "
            "AND fence_recorded_at IS NULL) OR "
            "(fence_state = 'requested' AND fence_operation_id IS NOT NULL "
            "AND fence_recorded_at IS NOT NULL) OR "
            "(fence_state = 'custody_ended' AND fence_operation_id IS NULL "
            "AND fence_recorded_at IS NOT NULL)))",
            name="ck_gpu_registration_conflict_shape",
        ),
        Index(
            "idx_gpu_registration_conflict_due",
            "state",
            "next_attempt_at",
            "processing_lease_expires_at",
            "created_at",
        ),
        Index(
            "idx_gpu_registration_conflict_fence",
            "state",
            "fence_state",
            "verified_at",
        ),
    )


class GpuRegistrationRecoveryKeyEpoch(Base):
    """Non-secret database authority for Registration V2 recovery keys."""

    __tablename__ = "gpu_registration_recovery_key_epochs"

    key_id = Column(String(64), primary_key=True)
    key_sha256 = Column(String(64), nullable=False)
    predecessor_key_id = Column(
        String(64),
        ForeignKey(
            "gpu_registration_recovery_key_epochs.key_id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    state = Column(String, nullable=False)
    cohort_id = Column(String(128), nullable=False)
    required_ack_count = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    retiring_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "uq_gpu_registration_recovery_key_active",
            "state",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
        Index(
            "uq_gpu_registration_recovery_key_staged_successor",
            "predecessor_key_id",
            unique=True,
            postgresql_where=text("state = 'staged'"),
        ),
        CheckConstraint(
            "key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' AND key_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_registration_recovery_key_epoch_identity",
        ),
        CheckConstraint(
            "state IN ('staged', 'active', 'retiring', 'retired', 'cancelled')",
            name="ck_gpu_registration_recovery_key_epoch_state",
        ),
        CheckConstraint(
            "cohort_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND required_ack_count BETWEEN 1 AND 256",
            name="ck_gpu_registration_recovery_key_epoch_replicas",
        ),
        CheckConstraint(
            "(state = 'staged' AND activated_at IS NULL "
            "AND retiring_at IS NULL AND retired_at IS NULL "
            "AND cancelled_at IS NULL) OR "
            "(state = 'active' AND activated_at IS NOT NULL "
            "AND retiring_at IS NULL AND retired_at IS NULL "
            "AND cancelled_at IS NULL) OR "
            "(state = 'retiring' AND activated_at IS NOT NULL "
            "AND retiring_at IS NOT NULL AND retired_at IS NULL "
            "AND cancelled_at IS NULL) OR "
            "(state = 'retired' AND activated_at IS NOT NULL "
            "AND retiring_at IS NOT NULL AND retired_at IS NOT NULL "
            "AND cancelled_at IS NULL) OR "
            "(state = 'cancelled' AND activated_at IS NULL "
            "AND retiring_at IS NULL AND retired_at IS NULL "
            "AND cancelled_at IS NOT NULL)",
            name="ck_gpu_registration_recovery_key_epoch_timestamps",
        ),
    )


class GpuRegistrationRecoveryKeyReplicaAck(Base):
    """One serving replica's non-secret recovery-key fingerprint ACK."""

    __tablename__ = "gpu_registration_recovery_key_replica_acks"

    replica_id = Column(String(128), primary_key=True)
    cohort_id = Column(String(128), nullable=False)
    key_id = Column(
        String(64),
        ForeignKey(
            "gpu_registration_recovery_key_epochs.key_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    key_ids = Column(JSONB, nullable=False)
    key_fingerprints = Column(JSONB, nullable=False)
    keyring_sha256 = Column(String(64), nullable=False)
    acknowledged_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "replica_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' "
            "AND cohort_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' "
            "AND jsonb_typeof(key_ids) = 'array' AND key_ids ? key_id "
            "AND jsonb_typeof(key_fingerprints) = 'object' "
            "AND key_fingerprints ? key_id "
            "AND keyring_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_registration_recovery_key_replica_ack",
        ),
    )


class GpuRegistrationRecoveryKeyEpochOperation(Base):
    """Immutable idempotency/audit record for an administrator epoch CAS."""

    __tablename__ = "gpu_registration_recovery_key_epoch_operations"

    request_id = Column(String, primary_key=True)
    request_sha256 = Column(String(64), nullable=False)
    operation_type = Column(String, nullable=False)
    key_id = Column(
        String(64),
        ForeignKey(
            "gpu_registration_recovery_key_epochs.key_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    predecessor_key_id = Column(String(64), nullable=True)
    requested_by_user_id = Column(String, nullable=False)
    cohort_id = Column(String(128), nullable=True)
    required_ack_count = Column(Integer, nullable=True)
    reason = Column(String, nullable=True)
    response_json = Column(JSONB, nullable=False)
    response_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    replay_expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND response_sha256 ~ '^[0-9a-f]{64}$' "
            "AND operation_type IN ('stage', 'activate', 'retire', 'cancel') "
            "AND replay_expires_at > created_at "
            "AND ((operation_type = 'stage' "
            "AND cohort_id IS NOT NULL "
            "AND required_ack_count BETWEEN 1 AND 256 "
            "AND reason IS NULL) "
            "OR (operation_type IN ('activate', 'retire') "
            "AND cohort_id IS NULL AND required_ack_count IS NULL AND reason IS NULL) "
            "OR (operation_type = 'cancel' "
            "AND cohort_id IS NULL AND required_ack_count IS NULL "
            "AND length(reason) BETWEEN 1 AND 2000))",
            name="ck_gpu_registration_recovery_key_epoch_operation",
        ),
    )


class GpuLifecycleOperation(Base):
    __tablename__ = "gpu_lifecycle_operations"

    operation_id = Column(String, primary_key=True)
    operation_type = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="intent", server_default="intent")
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    reservation_generation = Column(Integer, nullable=True)
    claims_sha256 = Column(String(64), nullable=True)
    process_incarnation = Column(String, nullable=True)
    topology_fingerprint = Column(String(64), nullable=False)
    gpu_bdfs = Column(JSONB, nullable=False)
    gpu_uuids = Column(JSONB, nullable=False)
    owner_hotkey = Column(String, nullable=False)
    stable_server_id = Column(String, nullable=True)
    management_mode = Column(String, nullable=True)
    migration_id = Column(String, nullable=True)
    recovery_authorization_id = Column(String, nullable=True)
    current_gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    desired_gpu_release_id = Column(
        String,
        ForeignKey("guest_releases.release_id", ondelete="RESTRICT"),
        nullable=True,
    )
    desired_release_target_sha256 = Column(String(64), nullable=True)
    intent = Column(JSONB, nullable=False)
    intent_sha256 = Column(String(64), nullable=False)
    physical_result = Column(JSONB, nullable=True)
    physical_result_sha256 = Column(String(64), nullable=True)
    result_outcome = Column(String, nullable=True)
    reporting_state = Column(String, nullable=False, default="pending", server_default="pending")
    receipt_id = Column(String, nullable=True, unique=True)
    receipt_sha256 = Column(String(64), nullable=True)
    receipt_accepted_at = Column(DateTime(timezone=True), nullable=True)
    local_release_ack = Column(JSONB, nullable=True)
    local_release_ack_sha256 = Column(String(64), nullable=True)
    local_release_acked_at = Column(DateTime(timezone=True), nullable=True)
    lease_owner = Column(String, nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finalized_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "operation_type IN ('pre_slot_claim_quarantine', 'launch_rollback', "
            "'release_rollover', 'normal_delete', 'ownerless_group_recovery', "
            "'forced_dead_guest_recovery')",
            name="ck_gpu_lifecycle_type",
        ),
        CheckConstraint(
            "phase IN ('intent', 'physical_result', 'receipt_accepted', "
            "'local_release_acked', 'finalized', 'quarantined')",
            name="ck_gpu_lifecycle_phase",
        ),
        CheckConstraint(
            "reporting_state IN ('pending', 'physical_result', 'receipt_accepted', "
            "'local_release_acked', 'finalized', 'quarantined') AND ("
            "(phase = 'intent' AND reporting_state = 'pending') OR "
            "(phase <> 'intent' AND reporting_state = phase))",
            name="ck_gpu_lifecycle_reporting_state",
        ),
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 "
            "AND allocation_group_generation > 0 "
            "AND (reservation_generation IS NULL OR reservation_generation > 0)",
            name="ck_gpu_lifecycle_generations",
        ),
        CheckConstraint(
            "topology_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND intent_sha256 ~ '^[0-9a-f]{64}$' "
            "AND (claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (physical_result_sha256 IS NULL OR physical_result_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (local_release_ack_sha256 IS NULL OR local_release_ack_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_lifecycle_digests",
        ),
        CheckConstraint(
            "(reservation_id IS NULL AND reservation_generation IS NULL "
            "AND claims_sha256 IS NULL AND process_incarnation IS NULL "
            "AND operation_type IN ('pre_slot_claim_quarantine', 'ownerless_group_recovery')) "
            "OR (reservation_id IS NOT NULL AND reservation_generation > 0 "
            "AND claims_sha256 ~ '^[0-9a-f]{64}$' AND process_incarnation IS NOT NULL "
            "AND operation_type <> 'ownerless_group_recovery')",
            name="ck_gpu_lifecycle_reservation_shape",
        ),
        CheckConstraint(
            "management_mode IS NULL OR management_mode IN ('platform', 'miner')",
            name="ck_gpu_lifecycle_mode",
        ),
        CheckConstraint(
            "(operation_type = 'release_rollover' "
            "AND current_gpu_release_id IS NOT NULL "
            "AND desired_gpu_release_id IS NOT NULL "
            "AND current_gpu_release_id <> desired_gpu_release_id "
            "AND desired_release_target_sha256 ~ '^[0-9a-f]{64}$') OR "
            "(operation_type <> 'release_rollover' "
            "AND current_gpu_release_id IS NULL "
            "AND desired_gpu_release_id IS NULL "
            "AND desired_release_target_sha256 IS NULL)",
            name="ck_gpu_lifecycle_release_rollover",
        ),
        CheckConstraint(
            "(phase = 'intent' AND physical_result IS NULL AND physical_result_sha256 IS NULL "
            "AND result_outcome IS NULL AND receipt_id IS NULL "
            "AND receipt_sha256 IS NULL AND receipt_accepted_at IS NULL "
            "AND local_release_ack IS NULL AND local_release_ack_sha256 IS NULL "
            "AND local_release_acked_at IS NULL AND failure_code IS NULL "
            "AND failure_reason IS NULL AND finalized_at IS NULL) OR "
            "(phase = 'physical_result' AND physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' "
            "AND result_outcome IS NULL AND receipt_id IS NULL "
            "AND receipt_sha256 IS NULL AND receipt_accepted_at IS NULL "
            "AND local_release_ack IS NULL AND local_release_ack_sha256 IS NULL "
            "AND local_release_acked_at IS NULL AND failure_code IS NULL "
            "AND failure_reason IS NULL AND finalized_at IS NULL) OR "
            "(phase = 'receipt_accepted' AND physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' "
            "AND result_outcome = 'accepted' "
            "AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND receipt_accepted_at IS NOT NULL AND local_release_ack IS NULL "
            "AND local_release_ack_sha256 IS NULL AND local_release_acked_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL "
            "AND finalized_at IS NULL) OR "
            "(phase = 'local_release_acked' AND physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' "
            "AND result_outcome = 'accepted' "
            "AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND receipt_accepted_at IS NOT NULL "
            "AND local_release_ack IS NOT NULL "
            "AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$' "
            "AND local_release_acked_at IS NOT NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL "
            "AND finalized_at IS NULL) OR "
            "(phase = 'finalized' AND physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' "
            "AND result_outcome = 'accepted' "
            "AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND receipt_accepted_at IS NOT NULL "
            "AND local_release_ack IS NOT NULL "
            "AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$' "
            "AND local_release_acked_at IS NOT NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL "
            "AND finalized_at IS NOT NULL) OR "
            "(phase = 'quarantined' AND failure_code IS NOT NULL "
            "AND failure_reason IS NOT NULL AND finalized_at IS NOT NULL AND "
            "((physical_result IS NULL AND physical_result_sha256 IS NULL "
            "AND result_outcome IS NULL AND receipt_id IS NULL "
            "AND receipt_sha256 IS NULL AND receipt_accepted_at IS NULL "
            "AND local_release_ack IS NULL AND local_release_ack_sha256 IS NULL "
            "AND local_release_acked_at IS NULL) OR "
            "(physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' "
            "AND result_outcome IN ('accepted', 'quarantined') "
            "AND receipt_id IS NOT NULL "
            "AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND receipt_accepted_at IS NOT NULL "
            "AND ((local_release_ack IS NULL "
            "AND local_release_ack_sha256 IS NULL "
            "AND local_release_acked_at IS NULL) OR "
            "(local_release_ack IS NOT NULL "
            "AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$' "
            "AND local_release_acked_at IS NOT NULL)))))",
            name="ck_gpu_lifecycle_result",
        ),
        Index(
            "uq_gpu_lifecycle_active_group_generation",
            "allocation_group_id",
            "allocation_group_generation",
            unique=True,
            postgresql_where=text("phase NOT IN ('finalized', 'quarantined')"),
        ),
        Index(
            "idx_gpu_lifecycle_host_reporting",
            "host_id",
            "reporting_state",
            "updated_at",
        ),
    )


class GpuRecoveryAuthorization(Base):
    __tablename__ = "gpu_recovery_authorizations"

    authorization_id = Column(String, primary_key=True, default=generate_uuid)
    operation_id = Column(
        String,
        ForeignKey("gpu_lifecycle_operations.operation_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    prior_host_key_generation = Column(Integer, nullable=False)
    prior_host_boot_generation = Column(Integer, nullable=False)
    inventory_report_id = Column(
        String,
        ForeignKey("gpu_inventory_reports.report_id", ondelete="RESTRICT"),
        nullable=False,
    )
    inventory_report_sha256 = Column(String(64), nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    reservation_generation = Column(Integer, nullable=True)
    claims_sha256 = Column(String(64), nullable=True)
    process_incarnation = Column(String, nullable=True)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    topology_fingerprint = Column(String(64), nullable=False)
    gpu_bdfs = Column(JSONB, nullable=False)
    gpu_uuids = Column(JSONB, nullable=False)
    owner_hotkey = Column(String, nullable=False)
    stable_server_id = Column(String, nullable=True)
    management_mode = Column(String, nullable=True)
    migration_id = Column(String, nullable=True)
    recovery_nonce = Column(String(128), nullable=False)
    recovery_nonce_hash = Column(String(64), nullable=False)
    authorized_by = Column(String, nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 "
            "AND prior_host_key_generation > 0 "
            "AND prior_host_boot_generation > 0",
            name="ck_gpu_recovery_authorization_generations",
        ),
        CheckConstraint(
            "inventory_report_sha256 ~ '^[0-9a-f]{64}$' "
            "AND topology_fingerprint ~ '^[0-9a-f]{64}$' "
            "AND recovery_nonce ~ '^[0-9a-f]{64}$' "
            "AND recovery_nonce_hash ~ '^[0-9a-f]{64}$' "
            "AND (claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_recovery_authorization_digests",
        ),
        CheckConstraint(
            "expires_at > issued_at",
            name="ck_gpu_recovery_authorization_expiry",
        ),
        CheckConstraint(
            "management_mode IS NULL OR management_mode IN ('platform', 'miner')",
            name="ck_gpu_recovery_authorization_mode",
        ),
        Index(
            "idx_gpu_recovery_authorization_expiry",
            "expires_at",
        ),
    )


class GpuHostLossEvent(Base):
    """Immutable administrator authorization for a permanently lost L0 host."""

    __tablename__ = "gpu_host_loss_events"

    event_id = Column(String, primary_key=True, default=generate_uuid)
    operation_id = Column(
        String,
        ForeignKey("gpu_lifecycle_operations.operation_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    receipt_sha256 = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    authorized_by = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "allocation_group_generation > 0 "
            "AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND length(reason) BETWEEN 1 AND 2000",
            name="ck_gpu_host_loss_event_shape",
        ),
    )


class GpuRecoveryEvent(Base):
    __tablename__ = "gpu_recovery_events"

    event_id = Column(String, primary_key=True, default=generate_uuid)
    authorization_id = Column(
        String,
        ForeignKey("gpu_recovery_authorizations.authorization_id", ondelete="RESTRICT"),
        nullable=False,
    )
    operation_id = Column(
        String,
        ForeignKey("gpu_lifecycle_operations.operation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    state = Column(String, nullable=False)
    reset_result = Column(JSONB, nullable=True)
    reset_result_sha256 = Column(String(64), nullable=True)
    source_reader_result = Column(JSONB, nullable=True)
    source_reader_result_sha256 = Column(String(64), nullable=True)
    receipt_id = Column(String, nullable=True)
    receipt_sha256 = Column(String(64), nullable=True)
    local_release_ack = Column(JSONB, nullable=True)
    local_release_ack_sha256 = Column(String(64), nullable=True)
    reclaim_reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    reclaim_reservation_generation = Column(Integer, nullable=True)
    reclaim_request_sha256 = Column(String(64), nullable=True)
    reclaim_response_sha256 = Column(String(64), nullable=True)
    reclaim_replay_until = Column(DateTime(timezone=True), nullable=True)
    current_inventory_report_id = Column(
        String,
        ForeignKey("gpu_inventory_reports.report_id", ondelete="RESTRICT"),
        nullable=True,
    )
    current_inventory_report_sha256 = Column(String(64), nullable=True)
    current_host_key_generation = Column(Integer, nullable=True)
    current_host_boot_generation = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "operation_id",
            "state",
            name="uq_gpu_recovery_event_operation_state",
        ),
        CheckConstraint(
            "state IN ('authorized', 'started', 'reset_reported', 'receipt_accepted', "
            "'local_release_acked', 'completed', 'quarantined', 'revoked', 'reclaimed')",
            name="ck_gpu_recovery_event_state",
        ),
        CheckConstraint(
            "(state = 'reclaimed' AND reclaim_reservation_id IS NOT NULL "
            "AND reclaim_reservation_generation > 0 "
            "AND reclaim_request_sha256 ~ '^[0-9a-f]{64}$' "
            "AND reclaim_response_sha256 ~ '^[0-9a-f]{64}$' "
            "AND reclaim_replay_until > completed_at "
            "AND current_inventory_report_id IS NOT NULL "
            "AND current_inventory_report_sha256 ~ '^[0-9a-f]{64}$' "
            "AND current_host_key_generation > 0 "
            "AND current_host_boot_generation > 0 "
            "AND completed_at IS NOT NULL) OR "
            "(state <> 'reclaimed' AND reclaim_reservation_id IS NULL "
            "AND reclaim_reservation_generation IS NULL "
            "AND reclaim_request_sha256 IS NULL "
            "AND reclaim_response_sha256 IS NULL "
            "AND reclaim_replay_until IS NULL "
            "AND current_inventory_report_id IS NULL "
            "AND current_inventory_report_sha256 IS NULL "
            "AND current_host_key_generation IS NULL "
            "AND current_host_boot_generation IS NULL)",
            name="ck_gpu_recovery_event_reclaim",
        ),
        CheckConstraint(
            "(reset_result_sha256 IS NULL OR reset_result_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (source_reader_result_sha256 IS NULL "
            "OR source_reader_result_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[0-9a-f]{64}$') "
            "AND (local_release_ack_sha256 IS NULL "
            "OR local_release_ack_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_recovery_event_digests",
        ),
    )


class GpuHotplugCommand(Base):
    __tablename__ = "gpu_hotplug_commands"

    command_id = Column(String, primary_key=True)
    host_id = Column(String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False)
    host_key_generation = Column(Integer, nullable=False)
    host_boot_generation = Column(Integer, nullable=False)
    reservation_id = Column(
        String,
        ForeignKey("gpu_launch_reservations.reservation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    reservation_generation = Column(Integer, nullable=False)
    claims_sha256 = Column(String(64), nullable=False)
    allocation_group_id = Column(
        String,
        ForeignKey("gpu_allocation_groups.allocation_group_id", ondelete="RESTRICT"),
        nullable=False,
    )
    allocation_group_generation = Column(Integer, nullable=False)
    process_incarnation = Column(String, nullable=False)
    stable_server_id = Column(String, nullable=False)
    migration_id = Column(String, nullable=False)
    payload = Column(JSONB, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    state = Column(String, nullable=False, default="pending", server_default="pending")
    dispatch_lease_owner = Column(String, nullable=True)
    dispatch_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    alerted_at = Column(DateTime(timezone=True), nullable=True)
    last_dispatch_error = Column(Text, nullable=True)
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    ack = Column(JSONB, nullable=True)
    ack_sha256 = Column(String(64), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "reservation_id",
            "allocation_group_generation",
            "process_incarnation",
            "stable_server_id",
            "migration_id",
            name="uq_gpu_hotplug_identity",
        ),
        CheckConstraint(
            "state IN ('pending', 'leased', 'dispatched', 'acked', 'failed')",
            name="ck_gpu_hotplug_state",
        ),
        CheckConstraint(
            "host_key_generation > 0 AND host_boot_generation > 0 "
            "AND reservation_generation > 0 AND allocation_group_generation > 0",
            name="ck_gpu_hotplug_generations",
        ),
        CheckConstraint(
            "claims_sha256 ~ '^[0-9a-f]{64}$' "
            "AND payload_sha256 ~ '^[0-9a-f]{64}$' "
            "AND (ack_sha256 IS NULL OR ack_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_hotplug_digests",
        ),
        CheckConstraint(
            "(dispatch_lease_owner IS NULL AND dispatch_lease_expires_at IS NULL) OR "
            "(dispatch_lease_owner IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL)",
            name="ck_gpu_hotplug_lease",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND ("
            "(state = 'pending' AND dispatch_lease_owner IS NULL "
            "AND dispatch_lease_expires_at IS NULL AND dispatched_at IS NULL "
            "AND ack IS NULL AND ack_sha256 IS NULL AND acknowledged_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL) OR "
            "(state = 'leased' AND dispatch_lease_owner IS NOT NULL "
            "AND dispatch_lease_expires_at IS NOT NULL AND ack IS NULL "
            "AND ack_sha256 IS NULL AND acknowledged_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL) OR "
            "(state = 'dispatched' AND dispatch_lease_owner IS NULL "
            "AND dispatch_lease_expires_at IS NULL AND dispatched_at IS NOT NULL "
            "AND ack IS NULL AND ack_sha256 IS NULL AND acknowledged_at IS NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL) OR "
            "(state = 'acked' AND dispatch_lease_owner IS NULL "
            "AND dispatch_lease_expires_at IS NULL AND ack IS NOT NULL "
            "AND ack_sha256 ~ '^[0-9a-f]{64}$' AND acknowledged_at IS NOT NULL "
            "AND failure_code IS NULL AND failure_reason IS NULL) OR "
            "(state = 'failed' AND dispatch_lease_owner IS NULL "
            "AND dispatch_lease_expires_at IS NULL AND failure_code IS NOT NULL "
            "AND failure_reason IS NOT NULL AND ((ack IS NULL AND ack_sha256 IS NULL "
            "AND acknowledged_at IS NULL) OR (ack IS NOT NULL "
            "AND ack_sha256 ~ '^[0-9a-f]{64}$' AND acknowledged_at IS NOT NULL))))",
            name="ck_gpu_hotplug_result_shape",
        ),
        Index(
            "idx_gpu_hotplug_dispatch",
            "state",
            "next_attempt_at",
            "dispatch_lease_expires_at",
            "created_at",
        ),
    )


_GPU_REGISTRATION_RECOVERY_KEY_TRANSITION_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION enforce_gpu_registration_recovery_key_transition()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'GPU registration recovery-key epochs cannot be deleted';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.state <> 'staged'
               OR NEW.activated_at IS NOT NULL
               OR NEW.retiring_at IS NOT NULL
               OR NEW.retired_at IS NOT NULL
               OR NEW.cancelled_at IS NOT NULL
            THEN
                RAISE EXCEPTION 'GPU registration recovery-key epochs must begin staged';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.key_id IS DISTINCT FROM OLD.key_id
           OR NEW.key_sha256 IS DISTINCT FROM OLD.key_sha256
           OR NEW.predecessor_key_id IS DISTINCT FROM OLD.predecessor_key_id
           OR NEW.cohort_id IS DISTINCT FROM OLD.cohort_id
           OR NEW.required_ack_count IS DISTINCT FROM OLD.required_ack_count
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
        THEN
            RAISE EXCEPTION 'GPU registration recovery-key epoch identity is immutable';
        END IF;
        IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
            IF NEW.activated_at IS DISTINCT FROM OLD.activated_at
               OR NEW.retiring_at IS DISTINCT FROM OLD.retiring_at
               OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
               OR NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at
            THEN
                RAISE EXCEPTION 'GPU registration recovery-key timestamps are immutable';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.state = 'staged' AND NEW.state = 'active'
           AND OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL
           AND NEW.retiring_at IS NULL AND NEW.retired_at IS NULL
           AND NEW.cancelled_at IS NULL
        THEN
            IF (
                NEW.predecessor_key_id IS NULL
                AND EXISTS (
                    SELECT 1 FROM gpu_registration_recovery_key_epochs epoch
                     WHERE epoch.key_id <> NEW.key_id
                )
            ) OR (
                NEW.predecessor_key_id IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1 FROM gpu_registration_recovery_key_epochs predecessor
                     WHERE predecessor.key_id = NEW.predecessor_key_id
                       AND predecessor.state = 'retiring'
                       AND predecessor.key_sha256 IS NOT NULL
                       AND predecessor.activated_at IS NOT NULL
                       AND predecessor.retiring_at IS NOT NULL
                       AND predecessor.retired_at IS NULL
                )
            ) THEN
                RAISE EXCEPTION 'GPU registration recovery-key activation has no exact retiring predecessor';
            END IF;
            IF NEW.predecessor_key_id IS NOT NULL AND (
                (
                    SELECT COUNT(*)
                      FROM gpu_registration_recovery_key_replica_acks ack
                     WHERE ack.key_id = NEW.key_id
                       AND ack.cohort_id = NEW.cohort_id
                       AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                       AND ack.key_ids ? NEW.key_id
                       AND ack.key_ids ? NEW.predecessor_key_id
                       AND ack.key_fingerprints ->> NEW.key_id = NEW.key_sha256
                       AND ack.key_fingerprints ->> NEW.predecessor_key_id = (
                           SELECT predecessor.key_sha256
                             FROM gpu_registration_recovery_key_epochs predecessor
                            WHERE predecessor.key_id = NEW.predecessor_key_id
                       )
                ) < NEW.required_ack_count
                OR EXISTS (
                    SELECT 1
                      FROM gpu_registration_recovery_key_replica_acks ack
                     WHERE ack.key_id = NEW.key_id
                       AND ack.cohort_id = NEW.cohort_id
                       AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                       AND (
                           NOT (ack.key_ids ? NEW.key_id)
                           OR NOT (ack.key_ids ? NEW.predecessor_key_id)
                           OR ack.key_fingerprints ->> NEW.key_id IS DISTINCT FROM NEW.key_sha256
                           OR ack.key_fingerprints ->> NEW.predecessor_key_id IS DISTINCT FROM (
                               SELECT predecessor.key_sha256
                                 FROM gpu_registration_recovery_key_epochs predecessor
                                WHERE predecessor.key_id = NEW.predecessor_key_id
                           )
                       )
                )
                OR (
                    SELECT COUNT(DISTINCT (
                        ack.key_ids::text || E'\n' || ack.key_fingerprints::text
                        || E'\n' || ack.keyring_sha256
                    ))
                      FROM gpu_registration_recovery_key_replica_acks ack
                     WHERE ack.key_id = NEW.key_id
                       AND ack.cohort_id = NEW.cohort_id
                       AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                ) <> 1
            ) THEN
                RAISE EXCEPTION 'GPU registration recovery-key activation lacks exact fresh replica ACKs';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.state = 'active' AND NEW.state = 'retiring'
           AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at
           AND OLD.retiring_at IS NULL AND NEW.retiring_at IS NOT NULL
           AND NEW.retired_at IS NULL AND NEW.cancelled_at IS NULL
        THEN
            IF (
                SELECT COUNT(*)
                  FROM gpu_registration_recovery_key_epochs successor
                 WHERE successor.state = 'staged'
                   AND successor.predecessor_key_id = OLD.key_id
                   AND (
                       SELECT COUNT(*)
                         FROM gpu_registration_recovery_key_replica_acks ack
                        WHERE ack.key_id = successor.key_id
                          AND ack.cohort_id = successor.cohort_id
                          AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                          AND ack.key_ids ? successor.key_id
                          AND ack.key_ids ? OLD.key_id
                          AND ack.key_fingerprints ->> successor.key_id = successor.key_sha256
                          AND ack.key_fingerprints ->> OLD.key_id = OLD.key_sha256
                   ) >= successor.required_ack_count
                   AND NOT EXISTS (
                       SELECT 1
                         FROM gpu_registration_recovery_key_replica_acks ack
                        WHERE ack.key_id = successor.key_id
                          AND ack.cohort_id = successor.cohort_id
                          AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                          AND (
                              NOT (ack.key_ids ? successor.key_id)
                              OR NOT (ack.key_ids ? OLD.key_id)
                              OR ack.key_fingerprints ->> successor.key_id
                                  IS DISTINCT FROM successor.key_sha256
                              OR ack.key_fingerprints ->> OLD.key_id
                                  IS DISTINCT FROM OLD.key_sha256
                          )
                   )
                   AND (
                       SELECT COUNT(DISTINCT (
                           ack.key_ids::text || E'\n' || ack.key_fingerprints::text
                           || E'\n' || ack.keyring_sha256
                       ))
                         FROM gpu_registration_recovery_key_replica_acks ack
                        WHERE ack.key_id = successor.key_id
                          AND ack.cohort_id = successor.cohort_id
                          AND ack.acknowledged_at >= NOW() - INTERVAL '120 seconds'
                   ) = 1
            ) <> 1 THEN
                RAISE EXCEPTION 'GPU registration recovery-key retirement lacks one exact ACKed successor';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.state = 'retiring' AND NEW.state = 'retired'
           AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at
           AND NEW.retiring_at IS NOT DISTINCT FROM OLD.retiring_at
           AND OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL
           AND NEW.cancelled_at IS NULL
        THEN
            IF EXISTS (
                SELECT 1 FROM gpu_registration_attempts
                 WHERE state = 'processing' AND request_payload_key_id = OLD.key_id
            ) OR EXISTS (
                SELECT 1 FROM gpu_registration_conflicts
                 WHERE state IN ('recorded', 'verifying')
                   AND request_payload_key_id = OLD.key_id
            ) THEN
                RAISE EXCEPTION 'GPU registration recovery key still has nonterminal references';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.state = 'staged' AND NEW.state = 'cancelled'
           AND NEW.activated_at IS NULL
           AND NEW.retiring_at IS NULL
           AND NEW.retired_at IS NULL
           AND OLD.cancelled_at IS NULL
           AND NEW.cancelled_at IS NOT NULL
        THEN
            IF EXISTS (
                SELECT 1
                  FROM gpu_registration_recovery_key_replica_acks ack
                 WHERE ack.key_id = OLD.key_id
            ) THEN
                RAISE EXCEPTION 'cancelled GPU registration recovery key still has replica ACKs';
            END IF;
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'invalid GPU registration recovery-key transition %% -> %%',
            OLD.state, NEW.state;
    END;
    $$
    """
).execute_if(dialect="postgresql")

event.listen(
    GpuRegistrationRecoveryKeyEpoch.__table__,
    "after_create",
    _GPU_REGISTRATION_RECOVERY_KEY_TRANSITION_FUNCTION,
)

_GPU_REGISTRATION_RECOVERY_KEY_ACK_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION enforce_gpu_registration_recovery_key_replica_ack()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
              FROM gpu_registration_recovery_key_epochs epoch
             WHERE epoch.key_id = NEW.key_id
               AND epoch.state IN ('staged', 'active', 'retiring')
        ) THEN
            RAISE EXCEPTION 'GPU registration recovery-key epoch is not ACK-eligible';
        END IF;
        RETURN NEW;
    END;
    $$
    """
).execute_if(dialect="postgresql")
event.listen(
    GpuRegistrationRecoveryKeyReplicaAck.__table__,
    "after_create",
    _GPU_REGISTRATION_RECOVERY_KEY_ACK_FUNCTION,
)
event.listen(
    GpuRegistrationRecoveryKeyReplicaAck.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_registration_recovery_key_replica_ack
        BEFORE INSERT OR UPDATE ON gpu_registration_recovery_key_replica_acks
        FOR EACH ROW EXECUTE FUNCTION enforce_gpu_registration_recovery_key_replica_ack()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    GpuRegistrationRecoveryKeyEpoch.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_registration_recovery_key_transition
        BEFORE INSERT OR UPDATE OR DELETE ON gpu_registration_recovery_key_epochs
        FOR EACH ROW EXECUTE FUNCTION enforce_gpu_registration_recovery_key_transition()
        """
    ).execute_if(dialect="postgresql"),
)

_GPU_REGISTRATION_RECOVERY_KEY_CLOSURE_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION enforce_gpu_registration_recovery_key_authority_closure()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF (SELECT COUNT(*) FROM gpu_registration_recovery_key_epochs
             WHERE state = 'active') <> 1
        THEN
            RAISE EXCEPTION 'GPU registration recovery-key authority requires exactly one active epoch';
        END IF;
        RETURN NULL;
    END;
    $$
    """
).execute_if(dialect="postgresql")
event.listen(
    GpuRegistrationRecoveryKeyEpoch.__table__,
    "after_create",
    _GPU_REGISTRATION_RECOVERY_KEY_CLOSURE_FUNCTION,
)
event.listen(
    GpuRegistrationRecoveryKeyEpoch.__table__,
    "after_create",
    DDL(
        """
        CREATE CONSTRAINT TRIGGER trg_gpu_registration_recovery_key_closure
        AFTER INSERT OR UPDATE OR DELETE ON gpu_registration_recovery_key_epochs
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION enforce_gpu_registration_recovery_key_authority_closure()
        """
    ).execute_if(dialect="postgresql"),
)

_GPU_REGISTRATION_RECOVERY_KEY_OPERATION_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION prevent_gpu_registration_recovery_key_operation_mutation()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'GPU registration recovery-key epoch operation audit is immutable';
    END;
    $$
    """
).execute_if(dialect="postgresql")
event.listen(
    GpuRegistrationRecoveryKeyEpochOperation.__table__,
    "after_create",
    _GPU_REGISTRATION_RECOVERY_KEY_OPERATION_FUNCTION,
)
event.listen(
    GpuRegistrationRecoveryKeyEpochOperation.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_registration_recovery_key_operation_immutable
        BEFORE UPDATE OR DELETE ON gpu_registration_recovery_key_epoch_operations
        FOR EACH ROW EXECUTE FUNCTION prevent_gpu_registration_recovery_key_operation_mutation()
        """
    ).execute_if(dialect="postgresql"),
)


_GPU_LIFECYCLE_TRANSITION_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION enforce_gpu_lifecycle_transition()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
            RAISE EXCEPTION 'GPU lifecycle operations are immutable audit rows';
        END IF;
        IF TG_OP = 'INSERT' THEN
            IF NEW.phase <> 'intent' OR NEW.reporting_state <> 'pending' THEN
                RAISE EXCEPTION 'GPU lifecycle operations must begin at intent';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.phase IN ('finalized', 'quarantined')
           AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD)
        THEN
            RAISE EXCEPTION 'terminal GPU lifecycle evidence is immutable';
        END IF;
        IF NEW.operation_id IS DISTINCT FROM OLD.operation_id
           OR NEW.operation_type IS DISTINCT FROM OLD.operation_type
           OR NEW.host_id IS DISTINCT FROM OLD.host_id
           OR NEW.host_key_generation IS DISTINCT FROM OLD.host_key_generation
           OR NEW.host_boot_generation IS DISTINCT FROM OLD.host_boot_generation
           OR NEW.allocation_group_id IS DISTINCT FROM OLD.allocation_group_id
           OR NEW.allocation_group_generation IS DISTINCT FROM OLD.allocation_group_generation
           OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
           OR NEW.reservation_generation IS DISTINCT FROM OLD.reservation_generation
           OR NEW.claims_sha256 IS DISTINCT FROM OLD.claims_sha256
           OR NEW.process_incarnation IS DISTINCT FROM OLD.process_incarnation
           OR NEW.topology_fingerprint IS DISTINCT FROM OLD.topology_fingerprint
           OR NEW.gpu_bdfs IS DISTINCT FROM OLD.gpu_bdfs
           OR NEW.gpu_uuids IS DISTINCT FROM OLD.gpu_uuids
           OR NEW.owner_hotkey IS DISTINCT FROM OLD.owner_hotkey
           OR NEW.stable_server_id IS DISTINCT FROM OLD.stable_server_id
           OR NEW.management_mode IS DISTINCT FROM OLD.management_mode
           OR NEW.migration_id IS DISTINCT FROM OLD.migration_id
           OR NEW.recovery_authorization_id IS DISTINCT FROM OLD.recovery_authorization_id
           OR NEW.current_gpu_release_id IS DISTINCT FROM OLD.current_gpu_release_id
           OR NEW.desired_gpu_release_id IS DISTINCT FROM OLD.desired_gpu_release_id
           OR NEW.desired_release_target_sha256 IS DISTINCT FROM OLD.desired_release_target_sha256
           OR NEW.intent IS DISTINCT FROM OLD.intent
           OR NEW.intent_sha256 IS DISTINCT FROM OLD.intent_sha256
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
        THEN
            RAISE EXCEPTION 'GPU lifecycle intent identity is immutable';
        END IF;
        IF OLD.physical_result_sha256 IS NOT NULL AND (
            NEW.physical_result IS DISTINCT FROM OLD.physical_result
            OR NEW.physical_result_sha256 IS DISTINCT FROM OLD.physical_result_sha256
        ) THEN
            RAISE EXCEPTION 'GPU lifecycle physical result is immutable';
        END IF;
        IF OLD.receipt_sha256 IS NOT NULL AND (
            NEW.result_outcome IS DISTINCT FROM OLD.result_outcome
            OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id
            OR NEW.receipt_sha256 IS DISTINCT FROM OLD.receipt_sha256
            OR NEW.receipt_accepted_at IS DISTINCT FROM OLD.receipt_accepted_at
        ) THEN
            RAISE EXCEPTION 'GPU lifecycle receipt is immutable';
        END IF;
        IF OLD.local_release_ack_sha256 IS NOT NULL AND (
            NEW.local_release_ack IS DISTINCT FROM OLD.local_release_ack
            OR NEW.local_release_ack_sha256 IS DISTINCT FROM OLD.local_release_ack_sha256
            OR NEW.local_release_acked_at IS DISTINCT FROM OLD.local_release_acked_at
        ) THEN
            RAISE EXCEPTION 'GPU lifecycle local-release ACK is immutable';
        END IF;
        IF OLD.finalized_at IS NOT NULL
           AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
        THEN
            RAISE EXCEPTION 'GPU lifecycle finalization time is immutable';
        END IF;
        IF OLD.failure_code IS NOT NULL AND (
            NEW.failure_code IS DISTINCT FROM OLD.failure_code
            OR NEW.failure_reason IS DISTINCT FROM OLD.failure_reason
        ) THEN
            RAISE EXCEPTION 'GPU lifecycle failure evidence is immutable';
        END IF;
        IF NEW.phase IS DISTINCT FROM OLD.phase AND NOT (
            (OLD.phase = 'intent' AND NEW.phase IN ('physical_result', 'quarantined'))
            OR (OLD.phase = 'physical_result' AND NEW.phase IN ('receipt_accepted', 'quarantined'))
            OR (OLD.phase = 'receipt_accepted' AND NEW.phase IN ('local_release_acked', 'quarantined'))
            OR (OLD.phase = 'local_release_acked' AND NEW.phase IN ('finalized', 'quarantined'))
        ) THEN
            RAISE EXCEPTION 'invalid GPU lifecycle phase transition %% -> %%', OLD.phase, NEW.phase;
        END IF;
        IF NEW.phase = 'quarantined' AND NEW.phase IS DISTINCT FROM OLD.phase THEN
            IF OLD.phase = 'intent' AND (
                NEW.physical_result IS NOT NULL
                OR NEW.physical_result_sha256 IS NOT NULL
                OR NEW.result_outcome IS NOT NULL
                OR NEW.receipt_id IS NOT NULL
                OR NEW.receipt_sha256 IS NOT NULL
                OR NEW.receipt_accepted_at IS NOT NULL
                OR NEW.local_release_ack IS NOT NULL
                OR NEW.local_release_ack_sha256 IS NOT NULL
                OR NEW.local_release_acked_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'intent quarantine cannot acquire lifecycle closure evidence';
            ELSIF OLD.phase = 'physical_result' AND (
                NEW.result_outcome IS DISTINCT FROM 'quarantined'
                OR NEW.local_release_ack IS NOT NULL
                OR NEW.local_release_ack_sha256 IS NOT NULL
                OR NEW.local_release_acked_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'physical-result quarantine has invalid receipt or ACK evidence';
            ELSIF OLD.phase = 'receipt_accepted' AND (
                NEW.result_outcome IS DISTINCT FROM 'accepted'
                OR NEW.local_release_ack IS NOT NULL
                OR NEW.local_release_ack_sha256 IS NOT NULL
                OR NEW.local_release_acked_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'receipt quarantine changed accepted closure evidence';
            ELSIF OLD.phase = 'local_release_acked' AND (
                NEW.result_outcome IS DISTINCT FROM 'accepted'
                OR NEW.local_release_ack IS NULL
                OR NEW.local_release_ack_sha256 IS NULL
                OR NEW.local_release_acked_at IS NULL
            ) THEN
                RAISE EXCEPTION 'local-release quarantine lost accepted closure evidence';
            END IF;
        END IF;
        RETURN NEW;
    END;
    $$
    """
).execute_if(dialect="postgresql")

event.listen(
    GpuLifecycleOperation.__table__,
    "after_create",
    _GPU_LIFECYCLE_TRANSITION_FUNCTION,
)
event.listen(
    GpuLifecycleOperation.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_lifecycle_transition
        BEFORE INSERT OR UPDATE OR DELETE ON gpu_lifecycle_operations
        FOR EACH ROW EXECUTE FUNCTION enforce_gpu_lifecycle_transition()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    GpuLifecycleOperation.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_lifecycle_truncate
        BEFORE TRUNCATE ON gpu_lifecycle_operations
        FOR EACH STATEMENT EXECUTE FUNCTION enforce_gpu_lifecycle_transition()
        """
    ).execute_if(dialect="postgresql"),
)


_GPU_RECOVERY_AUDIT_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION forbid_gpu_recovery_audit_mutation()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'GPU recovery audit rows are immutable';
    END;
    $$
    """
).execute_if(dialect="postgresql")


event.listen(
    GpuLifecycleOperation.__table__,
    "after_create",
    _GPU_RECOVERY_AUDIT_FUNCTION,
)
event.listen(
    GpuRecoveryAuthorization.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_recovery_authorizations_immutable
        BEFORE UPDATE OR DELETE ON gpu_recovery_authorizations
        FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    GpuRecoveryEvent.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_recovery_events_immutable
        BEFORE UPDATE OR DELETE ON gpu_recovery_events
        FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
event.listen(
    GpuHostLossEvent.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_gpu_host_loss_events_immutable
        BEFORE UPDATE OR DELETE ON gpu_host_loss_events
        FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation()
        """
    ).execute_if(dialect="postgresql"),
)
