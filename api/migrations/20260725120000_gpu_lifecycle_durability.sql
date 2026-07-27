-- migrate:up

-- Freeze the predecessor lineage while deriving the new exact node snapshot.
LOCK TABLE gpu_allocation_groups IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_inventory_reports IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_launch_reservations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE servers IN ACCESS EXCLUSIVE MODE;

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS gpu_process_incarnation VARCHAR;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS gpu_inventory_report_id VARCHAR;

-- Active rows must resolve through the exact current Server, reservation, and
-- group projection. Merely sharing a group id/generation is not sufficient.
UPDATE nodes AS node
   SET gpu_launch_reservation_id = server.gpu_launch_reservation_id,
       gpu_process_incarnation = server.gpu_process_incarnation,
       gpu_inventory_report_id = allocation_group.last_report_id
  FROM servers AS server,
       gpu_allocation_groups AS allocation_group,
       gpu_launch_reservations AS reservation
 WHERE node.server_id = server.server_id
   AND node.gpu_allocation_group_id = allocation_group.allocation_group_id
   AND node.gpu_allocation_group_generation = allocation_group.generation
   AND server.gpu_allocation_group_id = allocation_group.allocation_group_id
   AND server.gpu_allocation_group_generation = allocation_group.generation
   AND reservation.reservation_id = server.gpu_launch_reservation_id
   AND reservation.allocation_group_id = allocation_group.allocation_group_id
   AND reservation.allocation_group_generation = allocation_group.generation
   AND reservation.server_id = server.server_id
   AND reservation.process_incarnation = server.gpu_process_incarnation
   AND reservation.gpu_uuids ? node.uuid
   AND node.gpu_retired_at IS NULL
   AND node.gpu_allocation_group_id IS NOT NULL
   AND node.gpu_launch_reservation_id IS NULL;

-- A retired row is never schedulable, but retain its historical projection
-- when one and only one immutable reservation resolves the old group/server/
-- device lineage and the group is still at that generation.
WITH retired_candidates AS (
    SELECT node.uuid,
           MIN(reservation.reservation_id) AS reservation_id,
           MIN(reservation.process_incarnation) AS process_incarnation,
           MIN(allocation_group.last_report_id) AS inventory_report_id,
           COUNT(*) AS candidate_count
      FROM nodes AS node
      JOIN gpu_allocation_groups AS allocation_group
        ON allocation_group.allocation_group_id = node.gpu_allocation_group_id
       AND allocation_group.generation = node.gpu_allocation_group_generation
      JOIN gpu_launch_reservations AS reservation
        ON reservation.allocation_group_id = node.gpu_allocation_group_id
       AND reservation.allocation_group_generation = node.gpu_allocation_group_generation
       AND reservation.server_id = node.server_id
       AND reservation.gpu_uuids ? node.uuid
     WHERE node.gpu_retired_at IS NOT NULL
       AND node.gpu_allocation_group_id IS NOT NULL
       AND node.gpu_launch_reservation_id IS NULL
     GROUP BY node.uuid
)
UPDATE nodes AS node
   SET gpu_launch_reservation_id = candidate.reservation_id,
       gpu_process_incarnation = candidate.process_incarnation,
       gpu_inventory_report_id = candidate.inventory_report_id
  FROM retired_candidates AS candidate
 WHERE node.uuid = candidate.uuid
   AND candidate.candidate_count = 1;

-- An unresolved retired projection carries no live ownership and cannot be
-- made exact without inventing history. Clear only that incomplete projection;
-- active ambiguity remains a hard rollout failure below.
UPDATE nodes
   SET gpu_allocation_group_id = NULL,
       gpu_allocation_group_generation = NULL,
       gpu_launch_reservation_id = NULL,
       gpu_process_incarnation = NULL,
       gpu_inventory_report_id = NULL
 WHERE gpu_retired_at IS NOT NULL
   AND gpu_allocation_group_id IS NOT NULL
   AND (gpu_launch_reservation_id IS NULL
        OR gpu_process_incarnation IS NULL
        OR gpu_inventory_report_id IS NULL);

DO $$
DECLARE
    unresolved TEXT;
BEGIN
    SELECT string_agg(uuid::text, ', ' ORDER BY uuid::text)
      INTO unresolved
     FROM nodes
     WHERE gpu_allocation_group_id IS NOT NULL
       AND gpu_retired_at IS NULL
       AND (gpu_launch_reservation_id IS NULL
            OR gpu_process_incarnation IS NULL
            OR gpu_inventory_report_id IS NULL);
    IF unresolved IS NOT NULL THEN
        RAISE EXCEPTION
            'cannot establish exact GPU node reservation/process/inventory lineage for nodes: %',
            unresolved;
    END IF;
END
$$;

ALTER TABLE nodes DROP CONSTRAINT IF EXISTS ck_nodes_gpu_allocation_identity;
ALTER TABLE nodes ADD CONSTRAINT ck_nodes_gpu_allocation_identity CHECK (
    (gpu_allocation_group_id IS NULL
     AND gpu_allocation_group_generation IS NULL
     AND gpu_launch_reservation_id IS NULL
     AND gpu_process_incarnation IS NULL
     AND gpu_inventory_report_id IS NULL)
    OR (gpu_allocation_group_id IS NOT NULL
        AND gpu_allocation_group_generation > 0
        AND gpu_launch_reservation_id IS NOT NULL
        AND gpu_process_incarnation IS NOT NULL
        AND gpu_inventory_report_id IS NOT NULL)
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_nodes_gpu_launch_reservation') THEN
        ALTER TABLE nodes ADD CONSTRAINT fk_nodes_gpu_launch_reservation
            FOREIGN KEY (gpu_launch_reservation_id)
            REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_nodes_gpu_inventory_report') THEN
        ALTER TABLE nodes ADD CONSTRAINT fk_nodes_gpu_inventory_report
            FOREIGN KEY (gpu_inventory_report_id)
            REFERENCES gpu_inventory_reports(report_id) ON DELETE RESTRICT;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS gpu_registration_nonces (
    nonce_id VARCHAR PRIMARY KEY,
    client_request_id VARCHAR NOT NULL,
    request_generation INTEGER NOT NULL,
    peer_spki_sha256 VARCHAR(64) NOT NULL,
    reservation_id VARCHAR NOT NULL REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    server_ip VARCHAR NOT NULL,
    nonce_value VARCHAR(64),
    nonce_hash VARCHAR(64) NOT NULL,
    state VARCHAR NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_attempt_id VARCHAR,
    CONSTRAINT uq_gpu_registration_nonce_request UNIQUE (reservation_id, client_request_id),
    CONSTRAINT ck_gpu_registration_nonce_state CHECK (state IN ('issued', 'claimed', 'expired', 'revoked')),
    CONSTRAINT ck_gpu_registration_nonce_digest CHECK (
        nonce_hash ~ '^[0-9a-f]{64}$'
        AND peer_spki_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_gpu_registration_nonce_generation CHECK (
        request_generation > 0 AND request_generation <= 1024
    ),
    CONSTRAINT ck_gpu_registration_nonce_value CHECK (
        (state IN ('issued', 'claimed') AND nonce_value ~ '^[0-9a-f]{64}$')
        OR (state IN ('expired', 'revoked') AND nonce_value IS NULL)
    ),
    CONSTRAINT ck_gpu_registration_nonce_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_gpu_registration_nonce_claim CHECK (
        (state = 'claimed' AND claimed_attempt_id IS NOT NULL)
        OR (state = 'issued' AND claimed_attempt_id IS NULL)
        OR state IN ('expired', 'revoked')
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_gpu_registration_nonce_issued_reservation
    ON gpu_registration_nonces(reservation_id) WHERE state = 'issued';
CREATE INDEX IF NOT EXISTS idx_gpu_registration_nonce_expiry
    ON gpu_registration_nonces(expires_at) WHERE state IN ('issued', 'claimed');

CREATE TABLE IF NOT EXISTS gpu_registration_attempts (
    attempt_id VARCHAR PRIMARY KEY,
    nonce_id VARCHAR NOT NULL UNIQUE REFERENCES gpu_registration_nonces(nonce_id) ON DELETE RESTRICT,
    reservation_id VARCHAR NOT NULL REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    registration_id VARCHAR UNIQUE,
    request_sha256 VARCHAR(64) NOT NULL,
    request_payload_ciphertext TEXT,
    request_payload_key_id VARCHAR(64),
    peer_certificate_pem TEXT NOT NULL,
    peer_certificate_sha256 VARCHAR(64) NOT NULL,
    peer_spki_sha256 VARCHAR(64) NOT NULL,
    state VARCHAR NOT NULL,
    processing_lease_owner VARCHAR,
    processing_lease_expires_at TIMESTAMPTZ,
    attestation_id VARCHAR REFERENCES server_attestations(attestation_id) ON DELETE RESTRICT,
    stable_response JSONB,
    stable_response_sha256 VARCHAR(64),
    registration_replay_until TIMESTAMPTZ,
    failure_code VARCHAR,
    failure_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_gpu_registration_attempt_state CHECK (state IN ('processing', 'completed', 'failed')),
    CONSTRAINT ck_gpu_registration_attempt_digests CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND peer_certificate_sha256 ~ '^[0-9a-f]{64}$'
        AND peer_spki_sha256 ~ '^[0-9a-f]{64}$'
        AND (request_payload_key_id IS NULL
             OR request_payload_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
        AND (stable_response_sha256 IS NULL OR stable_response_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT ck_gpu_registration_attempt_lease CHECK (
        (processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL)
        OR (processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT ck_gpu_registration_attempt_result CHECK (
        (state = 'processing' AND request_payload_ciphertext IS NOT NULL
         AND request_payload_key_id IS NOT NULL
         AND registration_id IS NULL AND attestation_id IS NULL
         AND stable_response IS NULL AND stable_response_sha256 IS NULL
         AND registration_replay_until IS NULL AND completed_at IS NULL
         AND failure_code IS NULL AND failure_detail IS NULL)
        OR (state = 'completed' AND registration_id IS NOT NULL AND attestation_id IS NOT NULL
         AND stable_response IS NOT NULL AND stable_response_sha256 ~ '^[0-9a-f]{64}$'
         AND registration_replay_until > completed_at AND completed_at IS NOT NULL
         AND processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL
         AND request_payload_ciphertext IS NULL AND request_payload_key_id IS NULL
         AND failure_code IS NULL AND failure_detail IS NULL)
        OR (state = 'failed' AND registration_id IS NULL AND attestation_id IS NULL
         AND stable_response IS NULL AND stable_response_sha256 IS NULL
         AND failure_code IS NOT NULL AND failure_detail IS NOT NULL
         AND completed_at IS NOT NULL AND registration_replay_until > completed_at
         AND processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL
         AND request_payload_ciphertext IS NULL AND request_payload_key_id IS NULL)
    )
);
ALTER TABLE gpu_registration_nonces
    DROP CONSTRAINT IF EXISTS fk_gpu_registration_nonce_attempt,
    ADD CONSTRAINT fk_gpu_registration_nonce_attempt
    FOREIGN KEY (claimed_attempt_id) REFERENCES gpu_registration_attempts(attempt_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX IF NOT EXISTS idx_gpu_registration_attempt_reservation
    ON gpu_registration_attempts(reservation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gpu_registration_attempt_processing
    ON gpu_registration_attempts(processing_lease_expires_at) WHERE state = 'processing';

CREATE TABLE IF NOT EXISTS gpu_registration_conflicts (
    conflict_id VARCHAR PRIMARY KEY,
    attempt_id VARCHAR NOT NULL REFERENCES gpu_registration_attempts(attempt_id) ON DELETE RESTRICT,
    nonce_id VARCHAR NOT NULL REFERENCES gpu_registration_nonces(nonce_id) ON DELETE RESTRICT,
    request_sha256 VARCHAR(64) NOT NULL,
    request_payload_ciphertext TEXT,
    request_payload_key_id VARCHAR(64),
    peer_certificate_pem TEXT NOT NULL,
    peer_certificate_sha256 VARCHAR(64) NOT NULL,
    peer_spki_sha256 VARCHAR(64) NOT NULL,
    quote_sha256 VARCHAR(64) NOT NULL,
    evidence_sha256 VARCHAR(64) NOT NULL,
    signature_sha256 VARCHAR(64) NOT NULL,
    state VARCHAR NOT NULL DEFAULT 'recorded',
    processing_lease_owner VARCHAR,
    processing_lease_expires_at TIMESTAMPTZ,
    verification_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    CONSTRAINT uq_gpu_registration_conflict UNIQUE (
        nonce_id, request_sha256, peer_spki_sha256, peer_certificate_sha256
    ),
    CONSTRAINT ck_gpu_registration_conflict_state CHECK (
        state IN ('recorded', 'verifying', 'invalid', 'verified_competitor', 'dismissed')
    ),
    CONSTRAINT ck_gpu_registration_conflict_digests CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND peer_certificate_sha256 ~ '^[0-9a-f]{64}$'
        AND peer_spki_sha256 ~ '^[0-9a-f]{64}$'
        AND quote_sha256 ~ '^[0-9a-f]{64}$'
        AND evidence_sha256 ~ '^[0-9a-f]{64}$'
        AND signature_sha256 ~ '^[0-9a-f]{64}$'
        AND (request_payload_key_id IS NULL
             OR request_payload_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    ),
    CONSTRAINT ck_gpu_registration_conflict_lease CHECK (
        (processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL)
        OR (processing_lease_owner IS NOT NULL AND processing_lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT ck_gpu_registration_conflict_shape CHECK (
        (state = 'recorded' AND request_payload_ciphertext IS NOT NULL
         AND request_payload_key_id IS NOT NULL
         AND processing_lease_owner IS NULL
         AND processing_lease_expires_at IS NULL AND verified_at IS NULL
         AND verification_detail IS NULL)
        OR (state = 'verifying' AND request_payload_ciphertext IS NOT NULL
            AND request_payload_key_id IS NOT NULL
            AND processing_lease_owner IS NOT NULL
            AND processing_lease_expires_at IS NOT NULL AND verified_at IS NULL)
        OR (state IN ('invalid', 'verified_competitor', 'dismissed')
            AND processing_lease_owner IS NULL AND processing_lease_expires_at IS NULL
            AND request_payload_ciphertext IS NULL AND request_payload_key_id IS NULL
            AND verified_at IS NOT NULL AND verification_detail IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS gpu_lifecycle_operations (
    operation_id VARCHAR PRIMARY KEY,
    operation_type VARCHAR NOT NULL,
    phase VARCHAR NOT NULL,
    host_id VARCHAR NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    allocation_group_id VARCHAR NOT NULL REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    reservation_id VARCHAR REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    reservation_generation INTEGER,
    claims_sha256 VARCHAR(64),
    process_incarnation VARCHAR,
    topology_fingerprint VARCHAR(64) NOT NULL,
    gpu_bdfs JSONB NOT NULL,
    gpu_uuids JSONB NOT NULL,
    owner_hotkey VARCHAR NOT NULL,
    stable_server_id VARCHAR,
    management_mode VARCHAR,
    migration_id VARCHAR,
    recovery_authorization_id VARCHAR,
    intent JSONB NOT NULL,
    intent_sha256 VARCHAR(64) NOT NULL,
    physical_result JSONB,
    physical_result_sha256 VARCHAR(64),
    result_outcome VARCHAR,
    reporting_state VARCHAR NOT NULL DEFAULT 'pending',
    receipt_id VARCHAR UNIQUE,
    receipt_sha256 VARCHAR(64),
    receipt_accepted_at TIMESTAMPTZ,
    local_release_ack JSONB,
    local_release_ack_sha256 VARCHAR(64),
    local_release_acked_at TIMESTAMPTZ,
    lease_owner VARCHAR,
    lease_expires_at TIMESTAMPTZ,
    failure_code VARCHAR,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at TIMESTAMPTZ,
    CONSTRAINT ck_gpu_lifecycle_type CHECK (operation_type IN (
        'pre_slot_claim_quarantine', 'launch_rollback', 'release_rollover',
        'normal_delete', 'ownerless_group_recovery', 'forced_dead_guest_recovery'
    )),
    CONSTRAINT ck_gpu_lifecycle_phase CHECK (phase IN (
        'intent', 'physical_result', 'receipt_accepted', 'local_release_acked',
        'finalized', 'quarantined'
    )),
    CONSTRAINT ck_gpu_lifecycle_reporting_state CHECK (reporting_state IN (
        'pending', 'physical_result', 'receipt_accepted',
        'local_release_acked', 'finalized', 'quarantined'
    ) AND (
        (phase = 'intent' AND reporting_state = 'pending')
        OR (phase <> 'intent' AND reporting_state = phase)
    )),
    CONSTRAINT ck_gpu_lifecycle_generations CHECK (
        host_key_generation > 0 AND host_boot_generation > 0
        AND allocation_group_generation > 0
        AND (reservation_generation IS NULL OR reservation_generation > 0)
    ),
    CONSTRAINT ck_gpu_lifecycle_digests CHECK (
        topology_fingerprint ~ '^[0-9a-f]{64}$'
        AND intent_sha256 ~ '^[0-9a-f]{64}$'
        AND (claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$')
        AND (physical_result_sha256 IS NULL OR physical_result_sha256 ~ '^[0-9a-f]{64}$')
        AND (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[0-9a-f]{64}$')
        AND (local_release_ack_sha256 IS NULL OR local_release_ack_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT ck_gpu_lifecycle_reservation_shape CHECK (
        (reservation_id IS NULL AND reservation_generation IS NULL
         AND claims_sha256 IS NULL AND process_incarnation IS NULL
         AND operation_type IN ('pre_slot_claim_quarantine', 'ownerless_group_recovery'))
        OR (reservation_id IS NOT NULL AND reservation_generation > 0
         AND claims_sha256 ~ '^[0-9a-f]{64}$' AND process_incarnation IS NOT NULL
         AND operation_type <> 'ownerless_group_recovery')
    ),
    CONSTRAINT ck_gpu_lifecycle_mode CHECK (management_mode IS NULL OR management_mode IN ('platform', 'miner')),
    CONSTRAINT ck_gpu_lifecycle_result CHECK (
        (phase = 'intent' AND physical_result IS NULL AND physical_result_sha256 IS NULL
         AND receipt_id IS NULL AND local_release_ack IS NULL AND finalized_at IS NULL)
        OR (phase = 'physical_result' AND physical_result IS NOT NULL
         AND physical_result_sha256 ~ '^[0-9a-f]{64}$'
         AND result_outcome IS NULL AND receipt_id IS NULL
         AND receipt_sha256 IS NULL AND receipt_accepted_at IS NULL
         AND local_release_ack IS NULL AND finalized_at IS NULL)
        OR (phase = 'receipt_accepted' AND physical_result IS NOT NULL
         AND physical_result_sha256 ~ '^[0-9a-f]{64}$'
         AND result_outcome = 'accepted'
         AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$'
         AND receipt_accepted_at IS NOT NULL AND local_release_ack IS NULL
         AND local_release_ack_sha256 IS NULL AND local_release_acked_at IS NULL
         AND finalized_at IS NULL)
        OR (phase = 'local_release_acked' AND physical_result IS NOT NULL
         AND physical_result_sha256 ~ '^[0-9a-f]{64}$'
         AND result_outcome = 'accepted'
         AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$'
         AND receipt_accepted_at IS NOT NULL
         AND local_release_ack IS NOT NULL
         AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$'
         AND local_release_acked_at IS NOT NULL AND finalized_at IS NULL)
        OR (phase = 'finalized' AND physical_result IS NOT NULL
         AND physical_result_sha256 ~ '^[0-9a-f]{64}$'
         AND result_outcome = 'accepted'
         AND receipt_id IS NOT NULL AND receipt_sha256 ~ '^[0-9a-f]{64}$'
         AND receipt_accepted_at IS NOT NULL
         AND local_release_ack IS NOT NULL
         AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$'
         AND local_release_acked_at IS NOT NULL
         AND finalized_at IS NOT NULL)
        OR (phase = 'quarantined' AND failure_code IS NOT NULL
         AND failure_reason IS NOT NULL AND finalized_at IS NOT NULL
         AND ((physical_result IS NULL AND physical_result_sha256 IS NULL
          AND result_outcome IS NULL AND receipt_id IS NULL
          AND receipt_sha256 IS NULL AND receipt_accepted_at IS NULL
          AND local_release_ack IS NULL)
          OR (physical_result IS NOT NULL
           AND physical_result_sha256 ~ '^[0-9a-f]{64}$'
           AND result_outcome IN ('accepted', 'quarantined')
           AND receipt_id IS NOT NULL
           AND receipt_sha256 ~ '^[0-9a-f]{64}$'
           AND receipt_accepted_at IS NOT NULL
           AND ((local_release_ack IS NULL
             AND local_release_ack_sha256 IS NULL
             AND local_release_acked_at IS NULL)
            OR (local_release_ack IS NOT NULL
             AND local_release_ack_sha256 ~ '^[0-9a-f]{64}$'
             AND local_release_acked_at IS NOT NULL)))))
    )
);

CREATE OR REPLACE FUNCTION enforce_gpu_lifecycle_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'intent' OR NEW.reporting_state <> 'pending' THEN
            RAISE EXCEPTION 'GPU lifecycle operations must begin at intent';
        END IF;
        RETURN NEW;
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
        RAISE EXCEPTION 'invalid GPU lifecycle phase transition % -> %', OLD.phase, NEW.phase;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_gpu_lifecycle_transition ON gpu_lifecycle_operations;
CREATE TRIGGER trg_gpu_lifecycle_transition
BEFORE INSERT OR UPDATE ON gpu_lifecycle_operations
FOR EACH ROW EXECUTE FUNCTION enforce_gpu_lifecycle_transition();

CREATE UNIQUE INDEX IF NOT EXISTS uq_gpu_lifecycle_active_group_generation
    ON gpu_lifecycle_operations(allocation_group_id, allocation_group_generation)
    WHERE phase NOT IN ('finalized', 'quarantined');
CREATE INDEX IF NOT EXISTS idx_gpu_lifecycle_host_reporting
    ON gpu_lifecycle_operations(host_id, reporting_state, updated_at);

CREATE TABLE IF NOT EXISTS gpu_recovery_authorizations (
    authorization_id VARCHAR PRIMARY KEY,
    operation_id VARCHAR NOT NULL UNIQUE REFERENCES gpu_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    host_id VARCHAR NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    prior_host_key_generation INTEGER NOT NULL,
    prior_host_boot_generation INTEGER NOT NULL,
    inventory_report_id VARCHAR NOT NULL REFERENCES gpu_inventory_reports(report_id) ON DELETE RESTRICT,
    inventory_report_sha256 VARCHAR(64) NOT NULL,
    reservation_id VARCHAR REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    reservation_generation INTEGER,
    claims_sha256 VARCHAR(64),
    process_incarnation VARCHAR,
    allocation_group_id VARCHAR NOT NULL REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    topology_fingerprint VARCHAR(64) NOT NULL,
    gpu_bdfs JSONB NOT NULL,
    gpu_uuids JSONB NOT NULL,
    owner_hotkey VARCHAR NOT NULL,
    stable_server_id VARCHAR,
    management_mode VARCHAR,
    migration_id VARCHAR,
    recovery_nonce VARCHAR(128) NOT NULL,
    recovery_nonce_hash VARCHAR(64) NOT NULL,
    authorized_by VARCHAR NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_gpu_recovery_authorization_generations CHECK (
        host_key_generation > 0 AND host_boot_generation > 0
        AND prior_host_key_generation > 0 AND prior_host_boot_generation > 0
    ),
    CONSTRAINT ck_gpu_recovery_authorization_digests CHECK (
        inventory_report_sha256 ~ '^[0-9a-f]{64}$'
        AND topology_fingerprint ~ '^[0-9a-f]{64}$'
        AND recovery_nonce ~ '^[0-9a-f]{64}$'
        AND recovery_nonce_hash ~ '^[0-9a-f]{64}$'
        AND (claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT ck_gpu_recovery_authorization_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_gpu_recovery_authorization_mode CHECK (
        management_mode IS NULL OR management_mode IN ('platform', 'miner')
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_recovery_authorization_expiry
    ON gpu_recovery_authorizations(expires_at);

CREATE TABLE IF NOT EXISTS gpu_host_loss_events (
    event_id VARCHAR PRIMARY KEY,
    operation_id VARCHAR NOT NULL UNIQUE
        REFERENCES gpu_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    host_id VARCHAR NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    allocation_group_id VARCHAR NOT NULL
        REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    reservation_id VARCHAR
        REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    receipt_sha256 VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    authorized_by VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_gpu_host_loss_event_shape CHECK (
        allocation_group_generation > 0
        AND receipt_sha256 ~ '^[0-9a-f]{64}$'
        AND length(reason) BETWEEN 1 AND 2000
    )
);

CREATE TABLE IF NOT EXISTS gpu_recovery_events (
    event_id VARCHAR PRIMARY KEY,
    authorization_id VARCHAR NOT NULL REFERENCES gpu_recovery_authorizations(authorization_id) ON DELETE RESTRICT,
    operation_id VARCHAR NOT NULL REFERENCES gpu_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    state VARCHAR NOT NULL,
    reset_result JSONB,
    reset_result_sha256 VARCHAR(64),
    source_reader_result JSONB,
    source_reader_result_sha256 VARCHAR(64),
    receipt_id VARCHAR,
    receipt_sha256 VARCHAR(64),
    local_release_ack JSONB,
    local_release_ack_sha256 VARCHAR(64),
    reclaim_reservation_id VARCHAR REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    reclaim_reservation_generation INTEGER,
    reclaim_request_sha256 VARCHAR(64),
    reclaim_response_sha256 VARCHAR(64),
    reclaim_replay_until TIMESTAMPTZ,
    current_inventory_report_id VARCHAR REFERENCES gpu_inventory_reports(report_id) ON DELETE RESTRICT,
    current_inventory_report_sha256 VARCHAR(64),
    current_host_key_generation INTEGER,
    current_host_boot_generation INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_gpu_recovery_event_operation_state UNIQUE (operation_id, state),
    CONSTRAINT ck_gpu_recovery_event_state CHECK (
        state IN ('authorized', 'started', 'reset_reported', 'receipt_accepted', 'local_release_acked', 'completed', 'quarantined', 'revoked', 'reclaimed')
    ),
    CONSTRAINT ck_gpu_recovery_event_reclaim CHECK (
        (state = 'reclaimed' AND reclaim_reservation_id IS NOT NULL
         AND reclaim_reservation_generation > 0
         AND reclaim_request_sha256 ~ '^[0-9a-f]{64}$'
         AND reclaim_response_sha256 ~ '^[0-9a-f]{64}$'
         AND reclaim_replay_until > completed_at
         AND current_inventory_report_id IS NOT NULL
         AND current_inventory_report_sha256 ~ '^[0-9a-f]{64}$'
         AND current_host_key_generation > 0
         AND current_host_boot_generation > 0
         AND completed_at IS NOT NULL)
        OR (state <> 'reclaimed' AND reclaim_reservation_id IS NULL
            AND reclaim_reservation_generation IS NULL
            AND reclaim_request_sha256 IS NULL
            AND reclaim_response_sha256 IS NULL
            AND reclaim_replay_until IS NULL
            AND current_inventory_report_id IS NULL
            AND current_inventory_report_sha256 IS NULL
            AND current_host_key_generation IS NULL
            AND current_host_boot_generation IS NULL)
    ),
    CONSTRAINT ck_gpu_recovery_event_digests CHECK (
        (reset_result_sha256 IS NULL OR reset_result_sha256 ~ '^[0-9a-f]{64}$')
        AND (source_reader_result_sha256 IS NULL OR source_reader_result_sha256 ~ '^[0-9a-f]{64}$')
        AND (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[0-9a-f]{64}$')
        AND (local_release_ack_sha256 IS NULL OR local_release_ack_sha256 ~ '^[0-9a-f]{64}$')
    )
);

CREATE OR REPLACE FUNCTION forbid_gpu_recovery_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'GPU recovery audit rows are immutable';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_gpu_recovery_authorizations_immutable'
          AND tgrelid = 'gpu_recovery_authorizations'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER trg_gpu_recovery_authorizations_immutable
            BEFORE UPDATE OR DELETE ON gpu_recovery_authorizations
            FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_gpu_recovery_events_immutable'
          AND tgrelid = 'gpu_recovery_events'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER trg_gpu_recovery_events_immutable
            BEFORE UPDATE OR DELETE ON gpu_recovery_events
            FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_gpu_host_loss_events_immutable'
          AND tgrelid = 'gpu_host_loss_events'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER trg_gpu_host_loss_events_immutable
            BEFORE UPDATE OR DELETE ON gpu_host_loss_events
            FOR EACH ROW EXECUTE FUNCTION forbid_gpu_recovery_audit_mutation();
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS gpu_hotplug_commands (
    command_id VARCHAR PRIMARY KEY,
    host_id VARCHAR NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    reservation_id VARCHAR NOT NULL REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    reservation_generation INTEGER NOT NULL,
    claims_sha256 VARCHAR(64) NOT NULL,
    allocation_group_id VARCHAR NOT NULL REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    process_incarnation VARCHAR NOT NULL,
    stable_server_id VARCHAR NOT NULL,
    migration_id VARCHAR NOT NULL,
    payload JSONB NOT NULL,
    payload_sha256 VARCHAR(64) NOT NULL,
    state VARCHAR NOT NULL DEFAULT 'pending',
    dispatch_lease_owner VARCHAR,
    dispatch_lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alerted_at TIMESTAMPTZ,
    last_dispatch_error TEXT,
    dispatched_at TIMESTAMPTZ,
    ack JSONB,
    ack_sha256 VARCHAR(64),
    acknowledged_at TIMESTAMPTZ,
    failure_code VARCHAR,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gpu_hotplug_identity UNIQUE (
        reservation_id, allocation_group_generation, process_incarnation, stable_server_id, migration_id
    ),
    CONSTRAINT ck_gpu_hotplug_state CHECK (state IN ('pending', 'leased', 'dispatched', 'acked', 'failed')),
    CONSTRAINT ck_gpu_hotplug_generations CHECK (
        host_key_generation > 0 AND host_boot_generation > 0
        AND reservation_generation > 0 AND allocation_group_generation > 0
    ),
    CONSTRAINT ck_gpu_hotplug_digests CHECK (
        claims_sha256 ~ '^[0-9a-f]{64}$' AND payload_sha256 ~ '^[0-9a-f]{64}$'
        AND (ack_sha256 IS NULL OR ack_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT ck_gpu_hotplug_lease CHECK (
        (dispatch_lease_owner IS NULL AND dispatch_lease_expires_at IS NULL)
        OR (dispatch_lease_owner IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT ck_gpu_hotplug_result_shape CHECK (
        attempt_count >= 0 AND (
        (state = 'pending' AND dispatch_lease_owner IS NULL
         AND dispatch_lease_expires_at IS NULL AND dispatched_at IS NULL
         AND ack IS NULL AND ack_sha256 IS NULL AND acknowledged_at IS NULL
         AND failure_code IS NULL AND failure_reason IS NULL)
        OR (state = 'leased' AND dispatch_lease_owner IS NOT NULL
            AND dispatch_lease_expires_at IS NOT NULL AND ack IS NULL
            AND ack_sha256 IS NULL AND acknowledged_at IS NULL
            AND failure_code IS NULL AND failure_reason IS NULL)
        OR (state = 'dispatched' AND dispatch_lease_owner IS NULL
            AND dispatch_lease_expires_at IS NULL AND dispatched_at IS NOT NULL
            AND ack IS NULL AND ack_sha256 IS NULL AND acknowledged_at IS NULL
            AND failure_code IS NULL AND failure_reason IS NULL)
        OR (state = 'acked' AND dispatch_lease_owner IS NULL
            AND dispatch_lease_expires_at IS NULL AND ack IS NOT NULL
            AND ack_sha256 ~ '^[0-9a-f]{64}$' AND acknowledged_at IS NOT NULL
            AND failure_code IS NULL AND failure_reason IS NULL)
        OR (state = 'failed' AND dispatch_lease_owner IS NULL
            AND dispatch_lease_expires_at IS NULL AND failure_code IS NOT NULL
            AND failure_reason IS NOT NULL AND ((ack IS NULL AND ack_sha256 IS NULL
            AND acknowledged_at IS NULL) OR (ack IS NOT NULL
            AND ack_sha256 ~ '^[0-9a-f]{64}$' AND acknowledged_at IS NOT NULL))))
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_hotplug_dispatch
    ON gpu_hotplug_commands(state, next_attempt_at, dispatch_lease_expires_at, created_at);

ALTER TABLE gpu_allocation_groups DROP CONSTRAINT IF EXISTS ck_gpu_allocation_group_state;
ALTER TABLE gpu_allocation_groups ADD CONSTRAINT ck_gpu_allocation_group_state CHECK (
    state IN ('discovered', 'available', 'reserved', 'launching', 'running', 'resetting',
              'release_pending', 'recovery_required', 'quarantined', 'retired')
);
ALTER TABLE gpu_allocation_groups DROP CONSTRAINT IF EXISTS ck_gpu_allocation_group_owner;
ALTER TABLE gpu_allocation_groups ADD CONSTRAINT ck_gpu_allocation_group_owner CHECK (
    (state IN ('discovered', 'available', 'retired')
     AND management_mode IS NULL AND reservation_owner IS NULL
     AND reservation_id IS NULL AND process_incarnation IS NULL)
    OR state = 'quarantined'
    OR (state IN ('reserved', 'launching', 'running', 'resetting', 'release_pending', 'recovery_required')
        AND management_mode IN ('platform', 'miner')
        AND reservation_owner IS NOT NULL AND reservation_id IS NOT NULL
        AND reservation_generation > 0 AND process_incarnation IS NOT NULL)
    OR (state IN ('resetting', 'release_pending') AND management_mode IS NULL
        AND reservation_owner IS NULL AND reservation_id IS NULL
        AND process_incarnation IS NULL)
);

-- migrate:down

LOCK TABLE gpu_allocation_groups IN ACCESS EXCLUSIVE MODE;
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_hotplug_commands IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_host_loss_events IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_lifecycle_operations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_recovery_authorizations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_recovery_events IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_registration_attempts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_registration_conflicts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_registration_nonces IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM gpu_registration_nonces)
       OR EXISTS (SELECT 1 FROM gpu_registration_attempts)
       OR EXISTS (SELECT 1 FROM gpu_registration_conflicts)
       OR EXISTS (SELECT 1 FROM gpu_lifecycle_operations)
       OR EXISTS (SELECT 1 FROM gpu_recovery_authorizations)
       OR EXISTS (SELECT 1 FROM gpu_recovery_events)
       OR EXISTS (SELECT 1 FROM gpu_host_loss_events)
       OR EXISTS (SELECT 1 FROM gpu_hotplug_commands)
       OR EXISTS (
           SELECT 1 FROM nodes
            WHERE gpu_launch_reservation_id IS NOT NULL
               OR gpu_process_incarnation IS NOT NULL
               OR gpu_inventory_report_id IS NOT NULL
       )
       OR EXISTS (
           SELECT 1 FROM gpu_allocation_groups
            WHERE state IN ('release_pending', 'recovery_required')
       )
    THEN
        RAISE EXCEPTION 'cannot roll back durable GPU lifecycle state';
    END IF;
END
$$;

ALTER TABLE gpu_allocation_groups DROP CONSTRAINT IF EXISTS ck_gpu_allocation_group_owner;
ALTER TABLE gpu_allocation_groups ADD CONSTRAINT ck_gpu_allocation_group_owner CHECK (
    (state IN ('discovered', 'available', 'retired')
     AND management_mode IS NULL AND reservation_owner IS NULL
     AND reservation_id IS NULL AND process_incarnation IS NULL)
    OR state = 'quarantined'
    OR (state IN ('reserved', 'launching', 'running', 'resetting')
        AND management_mode IN ('platform', 'miner')
        AND reservation_owner IS NOT NULL AND reservation_id IS NOT NULL
        AND reservation_generation > 0 AND process_incarnation IS NOT NULL)
    OR (state = 'resetting' AND management_mode IS NULL
        AND reservation_owner IS NULL AND reservation_id IS NULL
        AND process_incarnation IS NULL AND recovery_started_at IS NOT NULL)
);
ALTER TABLE gpu_allocation_groups DROP CONSTRAINT IF EXISTS ck_gpu_allocation_group_state;
ALTER TABLE gpu_allocation_groups ADD CONSTRAINT ck_gpu_allocation_group_state CHECK (
    state IN ('discovered', 'available', 'reserved', 'launching', 'running',
              'resetting', 'quarantined', 'retired')
);

ALTER TABLE nodes DROP CONSTRAINT IF EXISTS ck_nodes_gpu_allocation_identity;
ALTER TABLE nodes ADD CONSTRAINT ck_nodes_gpu_allocation_identity CHECK (
    (gpu_allocation_group_id IS NULL AND gpu_allocation_group_generation IS NULL)
    OR (gpu_allocation_group_id IS NOT NULL AND gpu_allocation_group_generation > 0)
);
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS fk_nodes_gpu_launch_reservation;
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS fk_nodes_gpu_inventory_report;
ALTER TABLE nodes DROP COLUMN gpu_launch_reservation_id;
ALTER TABLE nodes DROP COLUMN gpu_process_incarnation;
ALTER TABLE nodes DROP COLUMN gpu_inventory_report_id;

DROP TABLE gpu_hotplug_commands;
DROP TABLE gpu_recovery_events;
DROP TABLE gpu_host_loss_events;
DROP TABLE gpu_recovery_authorizations;
DROP FUNCTION forbid_gpu_recovery_audit_mutation();
DROP TRIGGER IF EXISTS trg_gpu_lifecycle_transition ON gpu_lifecycle_operations;
DROP FUNCTION IF EXISTS enforce_gpu_lifecycle_transition();
DROP TABLE gpu_lifecycle_operations;
ALTER TABLE gpu_registration_nonces DROP CONSTRAINT fk_gpu_registration_nonce_attempt;
DROP TABLE gpu_registration_conflicts;
DROP TABLE gpu_registration_attempts;
DROP TABLE gpu_registration_nonces;
