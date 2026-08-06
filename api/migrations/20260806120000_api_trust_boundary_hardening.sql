-- migrate:up

-- Storage grants and immutable object generations.
LOCK TABLE storage_volumes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE storage_objects IN ACCESS EXCLUSIVE MODE;

ALTER TABLE storage_volumes
    ADD COLUMN IF NOT EXISTS grant_revocation_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE storage_volumes
    DROP CONSTRAINT IF EXISTS ck_storage_volume_grant_revocation_epoch;
ALTER TABLE storage_volumes
    ADD CONSTRAINT ck_storage_volume_grant_revocation_epoch
        CHECK (grant_revocation_epoch >= 0);

CREATE OR REPLACE FUNCTION enforce_storage_volume_grant_epoch_monotonic()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.grant_revocation_epoch < OLD.grant_revocation_epoch THEN
        RAISE EXCEPTION 'storage volume grant revocation epoch cannot decrease'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_storage_volume_grant_epoch_monotonic ON storage_volumes;
CREATE TRIGGER trg_storage_volume_grant_epoch_monotonic
BEFORE UPDATE OF grant_revocation_epoch ON storage_volumes
FOR EACH ROW EXECUTE FUNCTION enforce_storage_volume_grant_epoch_monotonic();

ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS generation VARCHAR;
UPDATE storage_objects SET generation = object_id WHERE generation IS NULL;
ALTER TABLE storage_objects
    ALTER COLUMN generation SET DEFAULT gen_random_uuid()::text,
    ALTER COLUMN generation SET NOT NULL,
    DROP CONSTRAINT IF EXISTS uq_storage_object_volume_generation,
    DROP CONSTRAINT IF EXISTS ck_storage_object_generation;
ALTER TABLE storage_objects
    ADD CONSTRAINT uq_storage_object_volume_generation UNIQUE (volume_id, generation),
    ADD CONSTRAINT ck_storage_object_generation CHECK (length(generation) > 0);

CREATE OR REPLACE FUNCTION prevent_storage_object_generation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation IS DISTINCT FROM OLD.generation THEN
        RAISE EXCEPTION 'storage object generation is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_storage_object_generation_immutable ON storage_objects;
CREATE TRIGGER trg_storage_object_generation_immutable
BEFORE UPDATE OF generation ON storage_objects
FOR EACH ROW EXECUTE FUNCTION prevent_storage_object_generation_mutation();

-- Release-rollover operations persist old/new release identity in the same immutable intent.
LOCK TABLE gpu_lifecycle_operations IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM gpu_lifecycle_operations WHERE operation_type = 'release_rollover'
    ) THEN
        RAISE EXCEPTION
            'cannot add exact release-rollover identity while legacy rollover operations exist';
    END IF;
END
$$;
ALTER TABLE gpu_lifecycle_operations
    ADD COLUMN IF NOT EXISTS current_gpu_release_id VARCHAR,
    ADD COLUMN IF NOT EXISTS desired_gpu_release_id VARCHAR,
    ADD COLUMN IF NOT EXISTS desired_release_target_sha256 VARCHAR(64);
ALTER TABLE gpu_lifecycle_operations
    DROP CONSTRAINT IF EXISTS fk_gpu_lifecycle_current_release,
    DROP CONSTRAINT IF EXISTS fk_gpu_lifecycle_desired_release,
    DROP CONSTRAINT IF EXISTS gpu_lifecycle_operations_current_gpu_release_id_fkey,
    DROP CONSTRAINT IF EXISTS gpu_lifecycle_operations_desired_gpu_release_id_fkey,
    DROP CONSTRAINT IF EXISTS ck_gpu_lifecycle_release_rollover;
ALTER TABLE gpu_lifecycle_operations
    ADD CONSTRAINT fk_gpu_lifecycle_current_release
        FOREIGN KEY (current_gpu_release_id) REFERENCES guest_releases(release_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT fk_gpu_lifecycle_desired_release
        FOREIGN KEY (desired_gpu_release_id) REFERENCES guest_releases(release_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT ck_gpu_lifecycle_release_rollover CHECK (
        (operation_type = 'release_rollover'
         AND current_gpu_release_id IS NOT NULL
         AND desired_gpu_release_id IS NOT NULL
         AND current_gpu_release_id <> desired_gpu_release_id
         AND desired_release_target_sha256 ~ '^[0-9a-f]{64}$')
        OR
        (operation_type <> 'release_rollover'
         AND current_gpu_release_id IS NULL
         AND desired_gpu_release_id IS NULL
         AND desired_release_target_sha256 IS NULL)
    );

CREATE OR REPLACE FUNCTION prevent_gpu_rollover_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.current_gpu_release_id IS DISTINCT FROM OLD.current_gpu_release_id
       OR NEW.desired_gpu_release_id IS DISTINCT FROM OLD.desired_gpu_release_id
       OR NEW.desired_release_target_sha256 IS DISTINCT FROM OLD.desired_release_target_sha256
    THEN
        RAISE EXCEPTION 'GPU release-rollover identity is immutable';
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_gpu_rollover_identity_immutable ON gpu_lifecycle_operations;
CREATE TRIGGER trg_gpu_rollover_identity_immutable
BEFORE UPDATE OF current_gpu_release_id, desired_gpu_release_id,
                 desired_release_target_sha256
ON gpu_lifecycle_operations
FOR EACH ROW EXECUTE FUNCTION prevent_gpu_rollover_identity_mutation();

-- Preserve the exact pre-retirement certificate that may retrieve only the immutable
-- decommission ACK after the short-lived runtime JWT itself expires.
ALTER TABLE gpu_server_decommissions
    ADD COLUMN IF NOT EXISTS replay_attested_spki_sha256 VARCHAR(64);
ALTER TABLE gpu_server_decommissions
    DROP CONSTRAINT IF EXISTS ck_gpu_server_decommission_audit;
ALTER TABLE gpu_server_decommissions
    ADD CONSTRAINT ck_gpu_server_decommission_audit CHECK (
        length(reason) BETWEEN 1 AND 2000
        AND jsonb_typeof(migration_ids) = 'array'
        AND jsonb_typeof(response_json) = 'object'
        AND ((reservation_id IS NULL AND reservation_generation IS NULL)
             OR (reservation_id IS NOT NULL AND reservation_generation > 0))
        AND ((allocation_group_id IS NULL AND allocation_group_generation IS NULL)
             OR (allocation_group_id IS NOT NULL AND allocation_group_generation > 0))
        AND (replay_attested_spki_sha256 IS NULL
             OR replay_attested_spki_sha256 ~ '^[0-9a-f]{64}$')
    );

-- Exact certificate-rebind and disk-incarnation retirement audits.
CREATE TABLE IF NOT EXISTS storage_replica_cert_rebind_audits (
    request_id VARCHAR PRIMARY KEY,
    request_sha256 VARCHAR(64) NOT NULL,
    server_id VARCHAR NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    storage_incarnation VARCHAR NOT NULL,
    old_cert_pubkey_hash VARCHAR(64) NOT NULL,
    new_cert_pubkey_hash VARCHAR(64) NOT NULL,
    object_bindings JSONB NOT NULL,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_storage_replica_cert_rebind_audit CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND old_cert_pubkey_hash ~ '^[0-9a-f]{64}$'
        AND new_cert_pubkey_hash ~ '^[0-9a-f]{64}$'
        AND old_cert_pubkey_hash <> new_cert_pubkey_hash
        AND jsonb_typeof(object_bindings) = 'array'
        AND jsonb_typeof(response_json) = 'object'
    )
);
CREATE INDEX IF NOT EXISTS idx_storage_replica_cert_rebind_server
    ON storage_replica_cert_rebind_audits(server_id, storage_incarnation, created_at);

CREATE TABLE IF NOT EXISTS storage_incarnation_retirement_audits (
    audit_id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    server_id VARCHAR NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    previous_storage_incarnation VARCHAR NOT NULL,
    replacement_storage_incarnation VARCHAR NOT NULL,
    replacement_cert_pubkey_hash VARCHAR(64) NOT NULL,
    retired_task_ids JSONB NOT NULL,
    retired_holder_cert_pubkey_hashes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_storage_incarnation_retirement_transition UNIQUE (
        server_id, previous_storage_incarnation, replacement_storage_incarnation
    ),
    CONSTRAINT ck_storage_incarnation_retirement_audit CHECK (
        previous_storage_incarnation <> replacement_storage_incarnation
        AND replacement_cert_pubkey_hash ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(retired_task_ids) = 'array'
        AND jsonb_typeof(retired_holder_cert_pubkey_hashes) = 'array'
    )
);
CREATE INDEX IF NOT EXISTS idx_storage_incarnation_retirement_server
    ON storage_incarnation_retirement_audits(server_id, created_at);

CREATE OR REPLACE FUNCTION prevent_storage_identity_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'storage identity audit rows are immutable';
END
$$;
DROP TRIGGER IF EXISTS trg_storage_replica_cert_rebind_audit_immutable
    ON storage_replica_cert_rebind_audits;
CREATE TRIGGER trg_storage_replica_cert_rebind_audit_immutable
BEFORE UPDATE OR DELETE ON storage_replica_cert_rebind_audits
FOR EACH ROW EXECUTE FUNCTION prevent_storage_identity_audit_mutation();
DROP TRIGGER IF EXISTS trg_storage_incarnation_retirement_audit_immutable
    ON storage_incarnation_retirement_audits;
CREATE TRIGGER trg_storage_incarnation_retirement_audit_immutable
BEFORE UPDATE OR DELETE ON storage_incarnation_retirement_audits
FOR EACH ROW EXECUTE FUNCTION prevent_storage_identity_audit_mutation();

CREATE OR REPLACE FUNCTION prevent_retired_storage_incarnation_rebind()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.storage_incarnation IS DISTINCT FROM OLD.storage_incarnation
       AND NEW.storage_incarnation IS NOT NULL
       AND EXISTS (
            SELECT 1
              FROM storage_incarnation_retirement_audits audit
             WHERE audit.server_id = NEW.server_id
               AND audit.previous_storage_incarnation = NEW.storage_incarnation
       )
    THEN
        RAISE EXCEPTION
            'storage incarnation was permanently retired and cannot be rebound'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_server_retired_storage_incarnation_fence ON servers;
CREATE TRIGGER trg_server_retired_storage_incarnation_fence
BEFORE UPDATE OF storage_incarnation ON servers
FOR EACH ROW EXECUTE FUNCTION prevent_retired_storage_incarnation_rebind();

ALTER TABLE storage_erase_tasks
    ADD COLUMN IF NOT EXISTS retirement_audit_id VARCHAR;
ALTER TABLE storage_erase_tasks
    DROP CONSTRAINT IF EXISTS fk_storage_erase_task_retirement_audit,
    DROP CONSTRAINT IF EXISTS storage_erase_tasks_retirement_audit_id_fkey;
ALTER TABLE storage_erase_tasks
    ADD CONSTRAINT fk_storage_erase_task_retirement_audit
        FOREIGN KEY (retirement_audit_id)
        REFERENCES storage_incarnation_retirement_audits(audit_id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_storage_erase_retirement_audit
    ON storage_erase_tasks(retirement_audit_id)
    WHERE retirement_audit_id IS NOT NULL;

-- The pre-existing placement trigger remains authoritative for every transition except an exact
-- present->present certificate-only rebind. A second trigger admits that one change only when the
-- transaction points at the immutable audit inserted by the service.
CREATE OR REPLACE FUNCTION enforce_replica_cert_rebind()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    authority_request_id VARCHAR;
    authorized BOOLEAN;
BEGIN
    IF OLD.target_cert_pubkey_hash IS NOT DISTINCT FROM NEW.target_cert_pubkey_hash THEN
        RETURN NEW;
    END IF;
    IF OLD.status <> 'present' OR NEW.status <> 'present'
       OR (to_jsonb(NEW) - 'target_cert_pubkey_hash')
          IS DISTINCT FROM (to_jsonb(OLD) - 'target_cert_pubkey_hash')
    THEN
        RAISE EXCEPTION 'replica certificate rebind must be an exact present cert-only update'
            USING ERRCODE = '23514';
    END IF;
    authority_request_id := current_setting('chutes.storage_cert_rebind_request_id', true);
    SELECT EXISTS (
        SELECT 1
          FROM storage_replica_cert_rebind_audits audit
          JOIN servers server ON server.server_id = audit.server_id
         WHERE audit.request_id = authority_request_id
           AND audit.server_id = NEW.server_id
           AND audit.storage_incarnation = NEW.storage_incarnation
           AND lower(audit.old_cert_pubkey_hash) = lower(OLD.target_cert_pubkey_hash)
           AND lower(audit.new_cert_pubkey_hash) = lower(NEW.target_cert_pubkey_hash)
           AND server.storage_incarnation = NEW.storage_incarnation
           AND lower(server.attested_cert_pubkey_hash) = lower(NEW.target_cert_pubkey_hash)
           AND audit.object_bindings @> jsonb_build_array(jsonb_build_object(
                'object_id', NEW.object_id,
                'ciphertext_sha256', lower(NEW.proof_sha256),
                'ciphertext_size_bytes', NEW.proof_size_bytes
           ))
    ) INTO authorized;
    IF NOT authorized THEN
        RAISE EXCEPTION 'replica certificate rebind lacks exact immutable audit authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_replica_placement_transition ON replica_placement;
DROP TRIGGER IF EXISTS trg_replica_placement_transition_insert ON replica_placement;
DROP TRIGGER IF EXISTS trg_replica_placement_transition_update ON replica_placement;
DROP TRIGGER IF EXISTS trg_replica_placement_cert_rebind_guard ON replica_placement;
CREATE TRIGGER trg_replica_placement_transition_insert
BEFORE INSERT ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_placement_transition();
CREATE TRIGGER trg_replica_placement_transition_update
BEFORE UPDATE ON replica_placement
FOR EACH ROW
WHEN (NOT (
    OLD.status = 'present' AND NEW.status = 'present'
    AND OLD.target_cert_pubkey_hash IS DISTINCT FROM NEW.target_cert_pubkey_hash
    AND (to_jsonb(NEW) - 'target_cert_pubkey_hash')
        = (to_jsonb(OLD) - 'target_cert_pubkey_hash')
))
EXECUTE FUNCTION enforce_replica_placement_transition();
CREATE TRIGGER trg_replica_placement_cert_rebind_guard
BEFORE UPDATE OF target_cert_pubkey_hash ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_cert_rebind();

-- Stable-cohort ChuteFS token-key epochs with bounded idempotency replay and cancellation.
LOCK TABLE chutefs_token_key_epochs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_token_key_replica_acks IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_token_key_epoch_operations IN ACCESS EXCLUSIVE MODE;

ALTER TABLE chutefs_token_key_epochs
    ADD COLUMN IF NOT EXISTS cohort_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS required_ack_count INTEGER,
    ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'chutefs_token_key_epochs'::regclass
           AND attname = 'required_replica_ids' AND attnum > 0 AND NOT attisdropped
    ) THEN
        EXECUTE $sql$
            UPDATE chutefs_token_key_epochs
               SET cohort_id = COALESCE(cohort_id, 'api'),
                   required_ack_count = COALESCE(
                       required_ack_count,
                       GREATEST(1, jsonb_array_length(required_replica_ids))
                   )
        $sql$;
    ELSE
        UPDATE chutefs_token_key_epochs
           SET cohort_id = COALESCE(cohort_id, 'api'),
               required_ack_count = COALESCE(required_ack_count, 1);
    END IF;
END
$$;
ALTER TABLE chutefs_token_key_epochs
    ALTER COLUMN cohort_id SET DEFAULT 'api',
    ALTER COLUMN cohort_id SET NOT NULL,
    ALTER COLUMN required_ack_count SET DEFAULT 1,
    ALTER COLUMN required_ack_count SET NOT NULL,
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_epoch_state,
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_epoch_replicas,
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_epoch_timestamps;
ALTER TABLE chutefs_token_key_epochs DROP COLUMN IF EXISTS required_replica_ids;
ALTER TABLE chutefs_token_key_epochs
    ADD CONSTRAINT ck_chutefs_token_key_epoch_state CHECK (
        state IN ('staged', 'active', 'retiring', 'retired', 'cancelled')
        AND key_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT ck_chutefs_token_key_epoch_replicas CHECK (
        cohort_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND required_ack_count BETWEEN 1 AND 256
    ),
    ADD CONSTRAINT ck_chutefs_token_key_epoch_timestamps CHECK (
        (state = 'staged' AND activated_at IS NULL
         AND retiring_at IS NULL AND retired_at IS NULL AND cancelled_at IS NULL)
        OR (state = 'active' AND activated_at IS NOT NULL
            AND retiring_at IS NULL AND retired_at IS NULL AND cancelled_at IS NULL)
        OR (state = 'retiring' AND activated_at IS NOT NULL
            AND retiring_at IS NOT NULL AND retired_at IS NULL AND cancelled_at IS NULL)
        OR (state = 'retired' AND activated_at IS NOT NULL
            AND retiring_at IS NOT NULL AND retired_at IS NOT NULL AND cancelled_at IS NULL)
        OR (state = 'cancelled' AND activated_at IS NULL
            AND retiring_at IS NULL AND retired_at IS NULL AND cancelled_at IS NOT NULL)
    );
CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_token_key_epoch_staged_successor
    ON chutefs_token_key_epochs(predecessor_key_id) WHERE state = 'staged';

ALTER TABLE chutefs_token_key_replica_acks
    ADD COLUMN IF NOT EXISTS cohort_id VARCHAR(128);
UPDATE chutefs_token_key_replica_acks SET cohort_id = 'api' WHERE cohort_id IS NULL;
ALTER TABLE chutefs_token_key_replica_acks
    ALTER COLUMN cohort_id SET DEFAULT 'api',
    ALTER COLUMN cohort_id SET NOT NULL,
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_replica_ack;
ALTER TABLE chutefs_token_key_replica_acks
    ADD CONSTRAINT ck_chutefs_token_key_replica_ack CHECK (
        cohort_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND jsonb_typeof(key_ids) = 'array'
        AND key_ids ? key_id
        AND jsonb_typeof(key_fingerprints) = 'object'
        AND key_fingerprints ? key_id
        AND keyring_sha256 ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE chutefs_token_key_epoch_operations
    ADD COLUMN IF NOT EXISTS cohort_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS required_ack_count INTEGER,
    ADD COLUMN IF NOT EXISTS reason VARCHAR,
    ADD COLUMN IF NOT EXISTS response_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS replay_expires_at TIMESTAMPTZ;
DROP TRIGGER IF EXISTS trg_chutefs_token_key_operation_immutable
    ON chutefs_token_key_epoch_operations;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = 'chutefs_token_key_epoch_operations'::regclass
           AND attname = 'required_replica_ids' AND attnum > 0 AND NOT attisdropped
    ) THEN
        EXECUTE $sql$
            UPDATE chutefs_token_key_epoch_operations
               SET cohort_id = CASE WHEN operation_type = 'stage' THEN 'api' ELSE NULL END,
                   required_ack_count = CASE
                       WHEN operation_type = 'stage'
                       THEN GREATEST(1, jsonb_array_length(required_replica_ids))
                       ELSE NULL
                   END,
                   response_sha256 = COALESCE(response_sha256, repeat('0', 64)),
                   replay_expires_at = COALESCE(
                       replay_expires_at,
                       created_at + INTERVAL '1 microsecond'
                   )
        $sql$;
    ELSE
        UPDATE chutefs_token_key_epoch_operations
           SET cohort_id = CASE WHEN operation_type = 'stage' THEN 'api' ELSE NULL END,
               required_ack_count = CASE WHEN operation_type = 'stage' THEN 1 ELSE NULL END,
               response_sha256 = COALESCE(response_sha256, repeat('0', 64)),
               replay_expires_at = COALESCE(
                   replay_expires_at,
                   created_at + INTERVAL '1 microsecond'
               );
    END IF;
END
$$;
ALTER TABLE chutefs_token_key_epoch_operations
    ALTER COLUMN response_sha256 SET NOT NULL,
    ALTER COLUMN replay_expires_at SET NOT NULL,
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_epoch_operation;
ALTER TABLE chutefs_token_key_epoch_operations DROP COLUMN IF EXISTS required_replica_ids;
ALTER TABLE chutefs_token_key_epoch_operations
    ADD CONSTRAINT ck_chutefs_token_key_epoch_operation CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND response_sha256 ~ '^[0-9a-f]{64}$'
        AND replay_expires_at > created_at
        AND operation_type IN ('stage', 'activate', 'retire', 'cancel')
        AND ((operation_type = 'stage'
              AND cohort_id IS NOT NULL AND required_ack_count BETWEEN 1 AND 256
              AND reason IS NULL)
             OR (operation_type IN ('activate', 'retire')
                 AND cohort_id IS NULL AND required_ack_count IS NULL AND reason IS NULL)
             OR (operation_type = 'cancel'
                 AND cohort_id IS NULL AND required_ack_count IS NULL
                 AND length(reason) BETWEEN 1 AND 2000))
    );
CREATE TRIGGER trg_chutefs_token_key_operation_immutable
BEFORE UPDATE OR DELETE ON chutefs_token_key_epoch_operations
FOR EACH ROW EXECUTE FUNCTION prevent_chutefs_token_key_operation_mutation();

CREATE OR REPLACE FUNCTION enforce_chutefs_token_key_epoch_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    acknowledgement RECORD;
    acknowledgement_count INTEGER := 0;
    expected_key_ids JSONB;
    expected_key_fingerprints JSONB;
    expected_keyring_sha256 VARCHAR;
    predecessor_sha256 VARCHAR;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.predecessor_key_id IS DISTINCT FROM OLD.predecessor_key_id
        OR NEW.key_sha256 IS DISTINCT FROM OLD.key_sha256
        OR NEW.cohort_id IS DISTINCT FROM OLD.cohort_id
        OR NEW.required_ack_count IS DISTINCT FROM OLD.required_ack_count
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION 'ChuteFS token key epoch identity is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'staged' AND NEW.state IN ('active', 'cancelled'))
        OR (OLD.state = 'active' AND NEW.state = 'retiring')
        OR (OLD.state = 'retiring' AND NEW.state = 'retired')
    ) THEN
        RAISE EXCEPTION 'invalid ChuteFS token key epoch transition % -> %', OLD.state, NEW.state;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.state = 'active' AND OLD.state IS DISTINCT FROM 'active' THEN
        IF NEW.predecessor_key_id IS NOT NULL THEN
            SELECT key_sha256 INTO predecessor_sha256
              FROM chutefs_token_key_epochs
             WHERE key_id = NEW.predecessor_key_id;
        END IF;
        FOR acknowledgement IN
            SELECT ack.*
              FROM chutefs_token_key_replica_acks ack
             WHERE ack.key_id = NEW.key_id
               AND ack.cohort_id = NEW.cohort_id
               AND ack.acknowledged_at >= NOW() - INTERVAL '2 minutes'
             ORDER BY ack.replica_id
        LOOP
            IF NOT acknowledgement.key_ids ? NEW.key_id
               OR acknowledgement.key_fingerprints ->> NEW.key_id
                    IS DISTINCT FROM NEW.key_sha256
               OR (NEW.predecessor_key_id IS NOT NULL AND (
                    NOT acknowledgement.key_ids ? NEW.predecessor_key_id
                    OR acknowledgement.key_fingerprints ->> NEW.predecessor_key_id
                        IS DISTINCT FROM predecessor_sha256
               ))
            THEN
                RAISE EXCEPTION 'serving replica has not acknowledged exact ChuteFS keyring';
            END IF;
            IF acknowledgement_count = 0 THEN
                expected_key_ids := acknowledgement.key_ids;
                expected_key_fingerprints := acknowledgement.key_fingerprints;
                expected_keyring_sha256 := acknowledgement.keyring_sha256;
            ELSIF acknowledgement.key_ids IS DISTINCT FROM expected_key_ids
               OR acknowledgement.key_fingerprints IS DISTINCT FROM expected_key_fingerprints
               OR acknowledgement.keyring_sha256 IS DISTINCT FROM expected_keyring_sha256
            THEN
                RAISE EXCEPTION 'ChuteFS token key replicas disagree on the complete keyring';
            END IF;
            acknowledgement_count := acknowledgement_count + 1;
        END LOOP;
        IF acknowledgement_count < NEW.required_ack_count THEN
            RAISE EXCEPTION 'stable ChuteFS cohort has insufficient fresh acknowledgements';
        END IF;
    END IF;
    IF NEW.state = 'retired' AND EXISTS (
        SELECT 1 FROM chutefs_launch_sessions session
         WHERE session.token_key_id = NEW.key_id
           AND (session.access_expires_at > NOW()
                OR session.refresh_expires_at > NOW()
                OR session.response_replay_until > NOW())
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

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM storage_replica_cert_rebind_audits)
       OR EXISTS (SELECT 1 FROM storage_incarnation_retirement_audits)
       OR EXISTS (SELECT 1 FROM storage_volumes WHERE grant_revocation_epoch <> 0)
       OR EXISTS (SELECT 1 FROM storage_objects WHERE generation <> object_id)
       OR EXISTS (
            SELECT 1 FROM chutefs_token_key_epochs
             WHERE state = 'cancelled' OR cohort_id <> 'api' OR required_ack_count <> 1
       )
       OR EXISTS (SELECT 1 FROM chutefs_token_key_epochs)
       OR EXISTS (SELECT 1 FROM chutefs_token_key_replica_acks)
       OR EXISTS (SELECT 1 FROM chutefs_token_key_epoch_operations)
       OR EXISTS (
            SELECT 1 FROM gpu_lifecycle_operations
             WHERE operation_type = 'release_rollover'
       )
       OR EXISTS (
            SELECT 1 FROM gpu_server_decommissions
             WHERE replay_attested_spki_sha256 IS NOT NULL
       )
    THEN
        RAISE EXCEPTION 'cannot downgrade after trust-boundary hardening state has been used';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_chutefs_token_key_epoch_transition
    ON chutefs_token_key_epochs;
DROP TRIGGER IF EXISTS trg_chutefs_token_key_operation_immutable
    ON chutefs_token_key_epoch_operations;
DROP INDEX IF EXISTS uq_chutefs_token_key_epoch_staged_successor;
ALTER TABLE chutefs_token_key_epoch_operations
    DROP CONSTRAINT IF EXISTS ck_chutefs_token_key_epoch_operation;
ALTER TABLE chutefs_token_key_epoch_operations
    DROP COLUMN replay_expires_at,
    DROP COLUMN response_sha256,
    DROP COLUMN reason,
    DROP COLUMN required_ack_count,
    DROP COLUMN cohort_id,
    ADD COLUMN required_replica_ids JSONB;
UPDATE chutefs_token_key_epoch_operations
   SET required_replica_ids = CASE
       WHEN operation_type = 'stage' THEN '["legacy-api"]'::jsonb ELSE NULL END;
ALTER TABLE chutefs_token_key_epoch_operations
    ADD CONSTRAINT ck_chutefs_token_key_epoch_operation CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND operation_type IN ('stage', 'activate', 'retire')
        AND ((operation_type = 'stage'
              AND jsonb_typeof(required_replica_ids) = 'array'
              AND jsonb_array_length(required_replica_ids) > 0)
             OR (operation_type IN ('activate', 'retire')
                 AND required_replica_ids IS NULL))
    );
CREATE TRIGGER trg_chutefs_token_key_operation_immutable
BEFORE UPDATE OR DELETE ON chutefs_token_key_epoch_operations
FOR EACH ROW EXECUTE FUNCTION prevent_chutefs_token_key_operation_mutation();
ALTER TABLE chutefs_token_key_replica_acks
    DROP CONSTRAINT ck_chutefs_token_key_replica_ack,
    DROP COLUMN cohort_id;
ALTER TABLE chutefs_token_key_replica_acks
    ADD CONSTRAINT ck_chutefs_token_key_replica_ack CHECK (
        jsonb_typeof(key_ids) = 'array' AND key_ids ? key_id
        AND jsonb_typeof(key_fingerprints) = 'object' AND key_fingerprints ? key_id
        AND keyring_sha256 ~ '^[0-9a-f]{64}$'
    );
ALTER TABLE chutefs_token_key_epochs
    DROP CONSTRAINT ck_chutefs_token_key_epoch_timestamps,
    DROP CONSTRAINT ck_chutefs_token_key_epoch_replicas,
    DROP CONSTRAINT ck_chutefs_token_key_epoch_state,
    DROP COLUMN cancelled_at,
    DROP COLUMN required_ack_count,
    DROP COLUMN cohort_id,
    ADD COLUMN required_replica_ids JSONB;
UPDATE chutefs_token_key_epochs
   SET required_replica_ids = '["legacy-api"]'::jsonb;
ALTER TABLE chutefs_token_key_epochs ALTER COLUMN required_replica_ids SET NOT NULL;
ALTER TABLE chutefs_token_key_epochs
    ADD CONSTRAINT ck_chutefs_token_key_epoch_state CHECK (
        state IN ('staged', 'active', 'retiring', 'retired')
        AND key_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT ck_chutefs_token_key_epoch_replicas CHECK (
        jsonb_typeof(required_replica_ids) = 'array'
        AND jsonb_array_length(required_replica_ids) > 0
    ),
    ADD CONSTRAINT ck_chutefs_token_key_epoch_timestamps CHECK (
        (state = 'staged' AND activated_at IS NULL AND retiring_at IS NULL AND retired_at IS NULL)
        OR (state = 'active' AND activated_at IS NOT NULL AND retiring_at IS NULL AND retired_at IS NULL)
        OR (state = 'retiring' AND activated_at IS NOT NULL AND retiring_at IS NOT NULL AND retired_at IS NULL)
        OR (state = 'retired' AND activated_at IS NOT NULL AND retiring_at IS NOT NULL AND retired_at IS NOT NULL)
    );

CREATE OR REPLACE FUNCTION enforce_chutefs_token_key_epoch_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
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
        OR NEW.key_sha256 IS DISTINCT FROM OLD.key_sha256
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
               OR acknowledged_key_fingerprints ->> NEW.key_id
                    IS DISTINCT FROM NEW.key_sha256
               OR (NEW.predecessor_key_id IS NOT NULL AND (
                    NOT acknowledged_key_ids ? NEW.predecessor_key_id
                    OR acknowledged_key_fingerprints ->> NEW.predecessor_key_id
                        IS DISTINCT FROM (
                            SELECT predecessor.key_sha256
                              FROM chutefs_token_key_epochs predecessor
                             WHERE predecessor.key_id = NEW.predecessor_key_id
                        )
               ))
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
        SELECT 1 FROM chutefs_launch_sessions session
         WHERE session.token_key_id = NEW.key_id
           AND (session.access_expires_at > NOW()
                OR session.refresh_expires_at > NOW()
                OR session.response_replay_until > NOW())
    ) THEN
        RAISE EXCEPTION 'ChuteFS token key is still referenced by replayable sessions';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER trg_chutefs_token_key_epoch_transition
BEFORE INSERT OR UPDATE ON chutefs_token_key_epochs
FOR EACH ROW EXECUTE FUNCTION enforce_chutefs_token_key_epoch_transition();

DROP TRIGGER IF EXISTS trg_replica_placement_cert_rebind_guard ON replica_placement;
DROP TRIGGER IF EXISTS trg_replica_placement_transition_update ON replica_placement;
DROP TRIGGER IF EXISTS trg_replica_placement_transition_insert ON replica_placement;
CREATE TRIGGER trg_replica_placement_transition
BEFORE INSERT OR UPDATE ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_placement_transition();
DROP FUNCTION IF EXISTS enforce_replica_cert_rebind();

ALTER TABLE storage_erase_tasks DROP CONSTRAINT fk_storage_erase_task_retirement_audit;
DROP INDEX IF EXISTS idx_storage_erase_retirement_audit;
ALTER TABLE storage_erase_tasks DROP COLUMN retirement_audit_id;
DROP TRIGGER IF EXISTS trg_storage_incarnation_retirement_audit_immutable
    ON storage_incarnation_retirement_audits;
DROP TRIGGER IF EXISTS trg_storage_replica_cert_rebind_audit_immutable
    ON storage_replica_cert_rebind_audits;
DROP TRIGGER IF EXISTS trg_server_retired_storage_incarnation_fence ON servers;
DROP FUNCTION IF EXISTS prevent_retired_storage_incarnation_rebind();
DROP FUNCTION IF EXISTS prevent_storage_identity_audit_mutation();
DROP TABLE storage_incarnation_retirement_audits;
DROP TABLE storage_replica_cert_rebind_audits;

DROP TRIGGER IF EXISTS trg_gpu_rollover_identity_immutable ON gpu_lifecycle_operations;
DROP FUNCTION IF EXISTS prevent_gpu_rollover_identity_mutation();
ALTER TABLE gpu_lifecycle_operations
    DROP CONSTRAINT ck_gpu_lifecycle_release_rollover,
    DROP CONSTRAINT fk_gpu_lifecycle_desired_release,
    DROP CONSTRAINT fk_gpu_lifecycle_current_release,
    DROP COLUMN desired_release_target_sha256,
    DROP COLUMN desired_gpu_release_id,
    DROP COLUMN current_gpu_release_id;

ALTER TABLE gpu_server_decommissions
    DROP CONSTRAINT ck_gpu_server_decommission_audit,
    DROP COLUMN replay_attested_spki_sha256;
ALTER TABLE gpu_server_decommissions
    ADD CONSTRAINT ck_gpu_server_decommission_audit CHECK (
        length(reason) BETWEEN 1 AND 2000
        AND jsonb_typeof(migration_ids) = 'array'
        AND jsonb_typeof(response_json) = 'object'
        AND ((reservation_id IS NULL AND reservation_generation IS NULL)
             OR (reservation_id IS NOT NULL AND reservation_generation > 0))
        AND ((allocation_group_id IS NULL AND allocation_group_generation IS NULL)
             OR (allocation_group_id IS NOT NULL AND allocation_group_generation > 0))
    );

DROP TRIGGER IF EXISTS trg_storage_object_generation_immutable ON storage_objects;
DROP FUNCTION IF EXISTS prevent_storage_object_generation_mutation();
ALTER TABLE storage_objects
    DROP CONSTRAINT uq_storage_object_volume_generation,
    DROP CONSTRAINT ck_storage_object_generation,
    DROP COLUMN generation;
DROP TRIGGER IF EXISTS trg_storage_volume_grant_epoch_monotonic ON storage_volumes;
DROP FUNCTION IF EXISTS enforce_storage_volume_grant_epoch_monotonic();
ALTER TABLE storage_volumes
    DROP CONSTRAINT ck_storage_volume_grant_revocation_epoch,
    DROP COLUMN grant_revocation_epoch;
