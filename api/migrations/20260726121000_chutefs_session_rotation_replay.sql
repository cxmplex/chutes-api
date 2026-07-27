-- migrate:up

ALTER TABLE chutefs_launch_sessions
    ADD COLUMN IF NOT EXISTS rotated_from_session_id TEXT,
    ADD COLUMN IF NOT EXISTS rotated_from_session_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS rotation_request_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS token_seed TEXT,
    ADD COLUMN IF NOT EXISTS token_key_id TEXT,
    ADD COLUMN IF NOT EXISTS response_replay_until TIMESTAMPTZ;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS chutefs_launch_sessions_rotated_from_session_id_fkey;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS chutefs_launch_sessions_config_id_key,
    DROP CONSTRAINT IF EXISTS chutefs_launch_sessions_instance_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_active_config
    ON chutefs_launch_sessions(config_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_active_instance
    ON chutefs_launch_sessions(instance_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_successor
    ON chutefs_launch_sessions(rotated_from_session_id)
    WHERE rotated_from_session_id IS NOT NULL;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS ck_chutefs_launch_session_rotation_replay;

ALTER TABLE chutefs_launch_sessions
    ADD CONSTRAINT ck_chutefs_launch_session_rotation_replay CHECK (
        (
            token_seed IS NULL
            AND token_key_id IS NULL
            AND rotation_request_sha256 IS NULL
            AND response_replay_until IS NULL
            AND rotated_from_session_id IS NULL
            AND rotated_from_session_sha256 IS NULL
        )
        OR
        (
            token_seed ~ '^[0-9a-f]{64}$'
            AND token_key_id IS NOT NULL
            AND token_key_id <> ''
            AND rotation_request_sha256 ~ '^[0-9a-f]{64}$'
            AND response_replay_until IS NOT NULL
            AND response_replay_until <= refresh_expires_at
            AND (
                (rotated_from_session_id IS NULL
                 AND rotated_from_session_sha256 IS NULL)
                OR (rotated_from_session_id IS NOT NULL
                    AND rotated_from_session_sha256 ~ '^[0-9a-f]{64}$')
            )
        )
    );

-- This replacement is deliberately in the migration that introduces replay
-- columns; the predecessor migration cannot reference columns that do not yet
-- exist. Only revoked_at remains mutable after insertion.
CREATE OR REPLACE FUNCTION enforce_chutefs_launch_session_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.config_id IS DISTINCT FROM OLD.config_id
        OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.chute_id IS DISTINCT FROM OLD.chute_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.compute_type IS DISTINCT FROM OLD.compute_type
        OR NEW.management_mode IS DISTINCT FROM OLD.management_mode
        OR NEW.server_id IS DISTINCT FROM OLD.server_id
        OR NEW.volume_id IS DISTINCT FROM OLD.volume_id
        OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
        OR NEW.allocation_group_id IS DISTINCT FROM OLD.allocation_group_id
        OR NEW.allocation_group_generation IS DISTINCT FROM OLD.allocation_group_generation
        OR NEW.process_incarnation IS DISTINCT FROM OLD.process_incarnation
        OR NEW.attestation_id IS DISTINCT FROM OLD.attestation_id
        OR NEW.attested_cert_pubkey_hash IS DISTINCT FROM OLD.attested_cert_pubkey_hash
        OR NEW.allowed_operations IS DISTINCT FROM OLD.allowed_operations
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.access_token_hash IS DISTINCT FROM OLD.access_token_hash
        OR NEW.refresh_token_hash IS DISTINCT FROM OLD.refresh_token_hash
        OR NEW.access_expires_at IS DISTINCT FROM OLD.access_expires_at
        OR NEW.refresh_expires_at IS DISTINCT FROM OLD.refresh_expires_at
        OR NEW.rotated_from_session_id IS DISTINCT FROM OLD.rotated_from_session_id
        OR NEW.rotated_from_session_sha256 IS DISTINCT FROM OLD.rotated_from_session_sha256
        OR NEW.rotation_request_sha256 IS DISTINCT FROM OLD.rotation_request_sha256
        OR NEW.token_seed IS DISTINCT FROM OLD.token_seed
        OR NEW.token_key_id IS DISTINCT FROM OLD.token_key_id
        OR NEW.response_replay_until IS DISTINCT FROM OLD.response_replay_until
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
    ) THEN
        RAISE EXCEPTION 'launch-bound ChuteFS session authority is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE IF NOT EXISTS chutefs_token_key_epochs (
    key_id VARCHAR PRIMARY KEY,
    predecessor_key_id VARCHAR REFERENCES chutefs_token_key_epochs(key_id) ON DELETE RESTRICT,
    state VARCHAR NOT NULL,
    required_replica_ids JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    retiring_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    CONSTRAINT ck_chutefs_token_key_epoch_state CHECK (
        state IN ('staged', 'active', 'retiring', 'retired')
    ),
    CONSTRAINT ck_chutefs_token_key_epoch_replicas CHECK (
        jsonb_typeof(required_replica_ids) = 'array'
        AND jsonb_array_length(required_replica_ids) > 0
    ),
    CONSTRAINT ck_chutefs_token_key_epoch_timestamps CHECK (
        (state = 'staged' AND activated_at IS NULL
         AND retiring_at IS NULL AND retired_at IS NULL)
        OR (state = 'active' AND activated_at IS NOT NULL
            AND retiring_at IS NULL AND retired_at IS NULL)
        OR (state = 'retiring' AND activated_at IS NOT NULL
            AND retiring_at IS NOT NULL AND retired_at IS NULL)
        OR (state = 'retired' AND activated_at IS NOT NULL
            AND retiring_at IS NOT NULL AND retired_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_token_key_epoch_active
    ON chutefs_token_key_epochs((state)) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS chutefs_token_key_replica_acks (
    replica_id VARCHAR NOT NULL,
    key_id VARCHAR NOT NULL REFERENCES chutefs_token_key_epochs(key_id) ON DELETE CASCADE,
    key_ids JSONB NOT NULL,
    key_fingerprints JSONB NOT NULL,
    keyring_sha256 VARCHAR(64) NOT NULL,
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (replica_id, key_id),
    CONSTRAINT ck_chutefs_token_key_replica_ack CHECK (
        jsonb_typeof(key_ids) = 'array'
        AND key_ids ? key_id
        AND jsonb_typeof(key_fingerprints) = 'object'
        AND key_fingerprints ? key_id
        AND keyring_sha256 ~ '^[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS chutefs_token_key_epoch_operations (
    request_id VARCHAR PRIMARY KEY,
    request_sha256 VARCHAR(64) NOT NULL,
    operation_type VARCHAR NOT NULL,
    key_id VARCHAR NOT NULL REFERENCES chutefs_token_key_epochs(key_id) ON DELETE RESTRICT,
    predecessor_key_id VARCHAR,
    requested_by_user_id VARCHAR NOT NULL,
    required_replica_ids JSONB,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_chutefs_token_key_epoch_operation CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND operation_type IN ('stage', 'activate', 'retire')
        AND (
            (operation_type = 'stage'
             AND jsonb_typeof(required_replica_ids) = 'array'
             AND jsonb_array_length(required_replica_ids) > 0)
            OR (operation_type IN ('activate', 'retire')
                AND required_replica_ids IS NULL)
        )
    )
);

CREATE OR REPLACE FUNCTION prevent_chutefs_token_key_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ChuteFS token key epoch operation audit is immutable';
END
$$;

DROP TRIGGER IF EXISTS trg_chutefs_token_key_operation_immutable
    ON chutefs_token_key_epoch_operations;
CREATE TRIGGER trg_chutefs_token_key_operation_immutable
BEFORE UPDATE OR DELETE ON chutefs_token_key_epoch_operations
FOR EACH ROW EXECUTE FUNCTION prevent_chutefs_token_key_operation_mutation();

CREATE OR REPLACE FUNCTION enforce_chutefs_token_key_epoch_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    required_replica TEXT;
    acknowledged_key_ids JSONB;
    acknowledged_key_fingerprints JSONB;
    acknowledged_keyring_sha256 VARCHAR;
    expected_key_ids JSONB;
    expected_key_fingerprints JSONB;
    expected_keyring_sha256 VARCHAR;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.predecessor_key_id IS DISTINCT FROM OLD.predecessor_key_id
        OR NEW.required_replica_ids IS DISTINCT FROM OLD.required_replica_ids
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION 'ChuteFS token key epoch identity is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'staged' AND NEW.state = 'active')
        OR (OLD.state = 'active' AND NEW.state = 'retiring')
        OR (OLD.state = 'retiring' AND NEW.state = 'retired')
    ) THEN
        RAISE EXCEPTION 'invalid ChuteFS token key epoch transition % -> %', OLD.state, NEW.state;
    END IF;
    IF NEW.state = 'active' AND (TG_OP = 'INSERT' OR OLD.state IS DISTINCT FROM 'active') THEN
        FOR required_replica IN
            SELECT jsonb_array_elements_text(NEW.required_replica_ids)
        LOOP
            SELECT ack.key_ids, ack.key_fingerprints, ack.keyring_sha256
              INTO acknowledged_key_ids, acknowledged_key_fingerprints,
                   acknowledged_keyring_sha256
              FROM chutefs_token_key_replica_acks ack
             WHERE ack.replica_id = required_replica
               AND ack.key_id = NEW.key_id;
            IF acknowledged_key_ids IS NULL
               OR acknowledged_keyring_sha256 IS NULL
               OR NOT acknowledged_key_ids ? NEW.key_id
               OR (NEW.predecessor_key_id IS NOT NULL
                   AND NOT acknowledged_key_ids ? NEW.predecessor_key_id)
               OR NOT EXISTS (
                   SELECT 1
                     FROM chutefs_token_key_replica_acks fresh_ack
                    WHERE fresh_ack.replica_id = required_replica
                      AND fresh_ack.key_id = NEW.key_id
                      AND fresh_ack.acknowledged_at >= NOW() - INTERVAL '2 minutes'
               )
            THEN
                RAISE EXCEPTION
                    'replica % has not acknowledged ChuteFS key transition % -> %',
                    required_replica, NEW.predecessor_key_id, NEW.key_id;
            END IF;
            IF expected_key_ids IS NULL THEN
                expected_key_ids := acknowledged_key_ids;
                expected_key_fingerprints := acknowledged_key_fingerprints;
                expected_keyring_sha256 := acknowledged_keyring_sha256;
            ELSIF acknowledged_key_ids IS DISTINCT FROM expected_key_ids
               OR acknowledged_key_fingerprints IS DISTINCT FROM expected_key_fingerprints
               OR acknowledged_keyring_sha256 IS DISTINCT FROM expected_keyring_sha256
            THEN
                RAISE EXCEPTION
                    'ChuteFS token key replicas do not acknowledge the same full keyring';
            END IF;
        END LOOP;
    END IF;
    IF NEW.state = 'retired' AND EXISTS (
        SELECT 1
         FROM chutefs_launch_sessions session
         WHERE session.token_key_id = NEW.key_id
           AND (
               session.access_expires_at > NOW()
               OR session.refresh_expires_at > NOW()
               OR COALESCE(
                   session.response_replay_until,
                   session.refresh_expires_at
               ) > NOW()
           )
    ) THEN
        RAISE EXCEPTION 'ChuteFS token key is still referenced by replayable sessions';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_chutefs_token_key_epoch_transition
    ON chutefs_token_key_epochs;
CREATE TRIGGER trg_chutefs_token_key_epoch_transition
BEFORE INSERT OR UPDATE ON chutefs_token_key_epochs
FOR EACH ROW EXECUTE FUNCTION enforce_chutefs_token_key_epoch_transition();

-- migrate:down

LOCK TABLE chutefs_launch_sessions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_token_key_epochs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_token_key_replica_acks IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_token_key_epoch_operations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         WHERE rotated_from_session_id IS NOT NULL
            OR rotated_from_session_sha256 IS NOT NULL
            OR rotation_request_sha256 IS NOT NULL
            OR token_seed IS NOT NULL
            OR token_key_id IS NOT NULL
            OR response_replay_until IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM chutefs_token_key_epochs
    ) OR EXISTS (
        SELECT 1 FROM chutefs_token_key_replica_acks
    ) OR EXISTS (
        SELECT 1 FROM chutefs_token_key_epoch_operations
    ) THEN
        RAISE EXCEPTION
            'cannot remove ChuteFS rotation replay state after it has been used';
    ELSIF EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         GROUP BY config_id
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         GROUP BY instance_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot restore one-session uniqueness while session history exists';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_chutefs_token_key_epoch_transition
    ON chutefs_token_key_epochs;
DROP FUNCTION IF EXISTS enforce_chutefs_token_key_epoch_transition();
DROP TRIGGER IF EXISTS trg_chutefs_token_key_operation_immutable
    ON chutefs_token_key_epoch_operations;
DROP FUNCTION IF EXISTS prevent_chutefs_token_key_operation_mutation();
DROP TABLE IF EXISTS chutefs_token_key_epoch_operations;
DROP TABLE IF EXISTS chutefs_token_key_replica_acks;
DROP TABLE IF EXISTS chutefs_token_key_epochs;

DROP INDEX IF EXISTS uq_chutefs_launch_session_successor;
DROP INDEX IF EXISTS uq_chutefs_launch_session_active_instance;
DROP INDEX IF EXISTS uq_chutefs_launch_session_active_config;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS ck_chutefs_launch_session_rotation_replay;

ALTER TABLE chutefs_launch_sessions
    ADD CONSTRAINT chutefs_launch_sessions_config_id_key UNIQUE (config_id),
    ADD CONSTRAINT chutefs_launch_sessions_instance_id_key UNIQUE (instance_id);

-- Restore the predecessor trigger body before removing replay columns that the
-- upgraded implementation references.
CREATE OR REPLACE FUNCTION enforce_chutefs_launch_session_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.config_id IS DISTINCT FROM OLD.config_id
        OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.chute_id IS DISTINCT FROM OLD.chute_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.compute_type IS DISTINCT FROM OLD.compute_type
        OR NEW.management_mode IS DISTINCT FROM OLD.management_mode
        OR NEW.server_id IS DISTINCT FROM OLD.server_id
        OR NEW.volume_id IS DISTINCT FROM OLD.volume_id
        OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
        OR NEW.allocation_group_id IS DISTINCT FROM OLD.allocation_group_id
        OR NEW.allocation_group_generation IS DISTINCT FROM OLD.allocation_group_generation
        OR NEW.process_incarnation IS DISTINCT FROM OLD.process_incarnation
        OR NEW.attestation_id IS DISTINCT FROM OLD.attestation_id
        OR NEW.attested_cert_pubkey_hash IS DISTINCT FROM OLD.attested_cert_pubkey_hash
        OR NEW.allowed_operations IS DISTINCT FROM OLD.allowed_operations
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.access_token_hash IS DISTINCT FROM OLD.access_token_hash
        OR NEW.refresh_token_hash IS DISTINCT FROM OLD.refresh_token_hash
        OR NEW.access_expires_at IS DISTINCT FROM OLD.access_expires_at
        OR NEW.refresh_expires_at IS DISTINCT FROM OLD.refresh_expires_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
    ) THEN
        RAISE EXCEPTION 'launch-bound ChuteFS session identity is immutable';
    END IF;
    RETURN NEW;
END
$$;

ALTER TABLE chutefs_launch_sessions
    DROP COLUMN IF EXISTS response_replay_until,
    DROP COLUMN IF EXISTS token_key_id,
    DROP COLUMN IF EXISTS token_seed,
    DROP COLUMN IF EXISTS rotation_request_sha256,
    DROP COLUMN IF EXISTS rotated_from_session_sha256,
    DROP COLUMN IF EXISTS rotated_from_session_id;
