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
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
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
            "request_generation > 0 AND request_generation <= 1024",
            name="ck_gpu_registration_nonce_generation",
        ),
        CheckConstraint(
            "(state IN ('issued', 'claimed') AND nonce_value ~ '^[0-9a-f]{64}$') OR "
            "(state IN ('expired', 'revoked') AND nonce_value IS NULL)",
            name="ck_gpu_registration_nonce_value",
        ),
        CheckConstraint(
            "expires_at > issued_at", name="ck_gpu_registration_nonce_expiry"
        ),
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
    registration_id = Column(String, nullable=True, unique=True)
    request_sha256 = Column(String(64), nullable=False)
    request_payload = Column(JSONB, nullable=True)
    peer_certificate_pem = Column(Text, nullable=False)
    peer_certificate_sha256 = Column(String(64), nullable=False)
    peer_spki_sha256 = Column(String(64), nullable=False)
    state = Column(
        String, nullable=False, default="processing", server_default="processing"
    )
    processing_lease_owner = Column(String, nullable=True)
    processing_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attestation_id = Column(
        String,
        ForeignKey("server_attestations.attestation_id", ondelete="RESTRICT"),
        nullable=True,
    )
    stable_response = Column(JSONB, nullable=True)
    stable_response_sha256 = Column(String(64), nullable=True)
    registration_replay_until = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_detail = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
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
            "AND (stable_response_sha256 IS NULL OR stable_response_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_gpu_registration_attempt_digests",
        ),
        CheckConstraint(
            "(processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL) OR "
            "(processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)",
            name="ck_gpu_registration_attempt_lease",
        ),
        CheckConstraint(
            "(state = 'processing' AND request_payload IS NOT NULL "
            "AND registration_id IS NULL AND attestation_id IS NULL "
            "AND stable_response IS NULL AND stable_response_sha256 IS NULL "
            "AND registration_replay_until IS NULL AND completed_at IS NULL "
            "AND failure_code IS NULL AND failure_detail IS NULL) OR "
            "(state = 'completed' AND registration_id IS NOT NULL "
            "AND attestation_id IS NOT NULL AND stable_response IS NOT NULL "
            "AND stable_response_sha256 ~ '^[0-9a-f]{64}$' "
            "AND registration_replay_until > completed_at AND completed_at IS NOT NULL "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL "
            "AND failure_code IS NULL AND failure_detail IS NULL) OR "
            "(state = 'failed' AND registration_id IS NULL "
            "AND attestation_id IS NULL AND stable_response IS NULL "
            "AND stable_response_sha256 IS NULL AND failure_code IS NOT NULL "
            "AND failure_detail IS NOT NULL AND completed_at IS NOT NULL "
            "AND registration_replay_until > completed_at "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL)",
            name="ck_gpu_registration_attempt_result",
        ),
        Index(
            "idx_gpu_registration_attempt_reservation", "reservation_id", "created_at"
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
    request_payload = Column(JSONB, nullable=True)
    peer_certificate_pem = Column(Text, nullable=False)
    peer_certificate_sha256 = Column(String(64), nullable=False)
    peer_spki_sha256 = Column(String(64), nullable=False)
    quote_sha256 = Column(String(64), nullable=False)
    evidence_sha256 = Column(String(64), nullable=False)
    signature_sha256 = Column(String(64), nullable=False)
    state = Column(
        String, nullable=False, default="recorded", server_default="recorded"
    )
    processing_lease_owner = Column(String, nullable=True)
    processing_lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    verification_detail = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
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
            "AND signature_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_gpu_registration_conflict_digests",
        ),
        CheckConstraint(
            "(processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL) OR "
            "(processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)",
            name="ck_gpu_registration_conflict_lease",
        ),
        CheckConstraint(
            "(state = 'recorded' AND request_payload IS NOT NULL "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL AND verified_at IS NULL "
            "AND verification_detail IS NULL) OR "
            "(state = 'verifying' AND request_payload IS NOT NULL "
            "AND processing_lease_owner IS NOT NULL "
            "AND processing_lease_expires_at IS NOT NULL AND verified_at IS NULL) OR "
            "(state IN ('invalid', 'verified_competitor', 'dismissed') "
            "AND processing_lease_owner IS NULL "
            "AND processing_lease_expires_at IS NULL AND verified_at IS NOT NULL "
            "AND verification_detail IS NOT NULL)",
            name="ck_gpu_registration_conflict_shape",
        ),
    )


class GpuLifecycleOperation(Base):
    __tablename__ = "gpu_lifecycle_operations"

    operation_id = Column(String, primary_key=True)
    operation_type = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="intent", server_default="intent")
    host_id = Column(
        String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False
    )
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
    intent = Column(JSONB, nullable=False)
    intent_sha256 = Column(String(64), nullable=False)
    physical_result = Column(JSONB, nullable=True)
    physical_result_sha256 = Column(String(64), nullable=True)
    result_outcome = Column(String, nullable=True)
    reporting_state = Column(
        String, nullable=False, default="pending", server_default="pending"
    )
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
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
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
            "'local_release_acked', 'finalized', 'quarantined')",
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
            "(phase = 'intent' AND physical_result IS NULL AND physical_result_sha256 IS NULL "
            "AND receipt_id IS NULL AND local_release_ack IS NULL AND finalized_at IS NULL) OR "
            "(phase = 'physical_result' AND physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$' AND receipt_id IS NULL "
            "AND local_release_ack IS NULL AND finalized_at IS NULL) OR "
            "(phase = 'receipt_accepted' AND physical_result IS NOT NULL "
            "AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$' "
            "AND receipt_accepted_at IS NOT NULL AND local_release_ack IS NULL "
            "AND finalized_at IS NULL) OR "
            "(phase = 'local_release_acked' AND receipt_id IS NOT NULL "
            "AND local_release_ack IS NOT NULL "
            "AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$' "
            "AND local_release_acked_at IS NOT NULL AND finalized_at IS NULL) OR "
            "(phase = 'finalized' AND receipt_id IS NOT NULL "
            "AND local_release_ack IS NOT NULL AND local_release_acked_at IS NOT NULL "
            "AND finalized_at IS NOT NULL) OR "
            "(phase = 'quarantined' AND failure_code IS NOT NULL "
            "AND failure_reason IS NOT NULL AND finalized_at IS NOT NULL AND "
            "((physical_result IS NULL AND physical_result_sha256 IS NULL "
            "AND receipt_id IS NULL AND local_release_ack IS NULL) OR "
            "(physical_result IS NOT NULL "
            "AND physical_result_sha256 ~ '^[0-9a-f]{64}$')))",
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
    host_id = Column(
        String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False
    )
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
    recovery_nonce = Column(String, nullable=False)
    recovery_nonce_hash = Column(String(64), nullable=False)
    state = Column(String, nullable=False, default="issued", server_default="issued")
    authorized_by = Column(String, nullable=False)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "state = 'issued' AND consumed_at IS NULL",
            name="ck_gpu_recovery_authorization_state",
        ),
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
            postgresql_where=text("state = 'issued'"),
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
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
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
    host_id = Column(
        String, ForeignKey("hosts.host_id", ondelete="RESTRICT"), nullable=False
    )
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
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    ack = Column(JSONB, nullable=True)
    ack_sha256 = Column(String(64), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String, nullable=True)
    failure_reason = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

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
            "dispatch_lease_expires_at",
            "created_at",
        ),
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
    GpuRecoveryAuthorization.__table__,
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
