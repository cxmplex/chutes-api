-- migrate:up

-- Storage quotas are account entitlements controlled by the validator. NULL means use the
-- configured server default; callers never choose either value.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS storage_volume_quota_bytes BIGINT;
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS storage_aggregate_quota_bytes BIGINT;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS ck_users_storage_volume_quota;
ALTER TABLE users
    ADD CONSTRAINT ck_users_storage_volume_quota
    CHECK (storage_volume_quota_bytes IS NULL OR storage_volume_quota_bytes > 0);
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS ck_users_storage_aggregate_quota;
ALTER TABLE users
    ADD CONSTRAINT ck_users_storage_aggregate_quota
    CHECK (storage_aggregate_quota_bytes IS NULL OR storage_aggregate_quota_bytes > 0);

-- A deleted volume remains as a minimal owner-scoped tombstone so DELETE is idempotent. Its
-- application key is removed only after every generation has reached terminal physical-erasure
-- state; purged_at records when object/placement metadata was subsequently removed.
ALTER TABLE storage_volumes
    ADD COLUMN IF NOT EXISTS delete_requested_at TIMESTAMPTZ;
ALTER TABLE storage_volumes
    ADD COLUMN IF NOT EXISTS key_shredded_at TIMESTAMPTZ;
ALTER TABLE storage_volumes
    ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ;
UPDATE storage_volumes
SET delete_requested_at = COALESCE(updated_at, created_at, statement_timestamp())
WHERE deleted IS true
  AND delete_requested_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_storage_volumes_deleted_work
    ON storage_volumes (delete_requested_at, volume_id)
    WHERE deleted IS true AND purged_at IS NULL;

-- Placement retries use a caller-generated UUID as an idempotency key. Erase enqueue time is
-- separate from lifecycle retirement: it proves all known holder identities were materialized as
-- durable tasks before placement metadata can be removed.
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS placement_request_id VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS erase_enqueued_at TIMESTAMPTZ;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS detached_predecessor_id VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS predecessor_detached_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_object_placement_request
    ON storage_objects (volume_id, placement_request_id)
    WHERE placement_request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_storage_objects_erase_queue
    ON storage_objects (
        COALESCE(tombstoned_at, superseded_at, created_at),
        object_id
    )
    WHERE lifecycle_state IN ('superseded', 'tombstoned');
CREATE INDEX IF NOT EXISTS idx_storage_objects_terminal_erase
    ON storage_objects (
        COALESCE(tombstoned_at, superseded_at, created_at),
        object_id
    )
    WHERE lifecycle_state IN ('superseded', 'tombstoned')
      AND erase_enqueued_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_storage_objects_expected_predecessor
    ON storage_objects (expected_predecessor_id, object_id)
    WHERE expected_predecessor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_storage_objects_delete_fence
    ON storage_objects (volume_id, object_key, object_id, created_at);
CREATE INDEX IF NOT EXISTS idx_storage_objects_deleted_volume_retire
    ON storage_objects (volume_id, object_id)
    WHERE lifecycle_state IN ('pending', 'committed', 'superseded');
CREATE INDEX IF NOT EXISTS idx_storage_objects_volume
    ON storage_objects (volume_id, object_id);
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS ck_storage_object_signed_sizes;
ALTER TABLE storage_objects
    ADD CONSTRAINT ck_storage_object_signed_sizes
    CHECK (
        size_bytes BETWEEN 0 AND 9223372036854775807
        AND projected_size_bytes BETWEEN 0 AND 9223372036854775807
        AND (
            ciphertext_size_bytes IS NULL
            OR ciphertext_size_bytes BETWEEN 0 AND 9223372036854775807
        )
    );
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS ck_storage_object_detached_predecessor;
ALTER TABLE storage_objects
    ADD CONSTRAINT ck_storage_object_detached_predecessor
    CHECK (
        (
            detached_predecessor_id IS NULL
            AND predecessor_detached_at IS NULL
        )
        OR (
            detached_predecessor_id IS NOT NULL
            AND predecessor_detached_at IS NOT NULL
            AND detached_predecessor_id <> object_id
        )
    );

-- DELETE is fenced at one timestamp per key. The endpoint and reconciler retire generations at or
-- before the fence in bounded pages; a stale pending generation cannot commit after the owner saw
-- DELETE succeed, while a later PUT (created after the cutoff) remains valid.
CREATE TABLE IF NOT EXISTS storage_object_delete_fences (
    fence_id        VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    volume_id       VARCHAR NOT NULL
        REFERENCES storage_volumes (volume_id) ON DELETE CASCADE,
    object_key      VARCHAR NOT NULL,
    cutoff_at       TIMESTAMPTZ NOT NULL,
    scan_cursor     VARCHAR,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_storage_object_delete_fence UNIQUE (volume_id, object_key)
);
CREATE INDEX IF NOT EXISTS idx_storage_object_delete_fence_work
    ON storage_object_delete_fences (cutoff_at, fence_id)
    WHERE completed_at IS NULL;

-- Only the attested direct-upload target observes plaintext. These immutable receipt fields are
-- the source of billable/quota bytes and plaintext integrity metadata; the owner commit request is
-- deliberately not trusted for either value.
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_plaintext_size_bytes BIGINT;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_plaintext_sha256 VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS last_inventory_snapshot_id VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS last_inventory_seen_at TIMESTAMPTZ;
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_ciphertext_size;
ALTER TABLE replica_placement
    ADD CONSTRAINT ck_replica_ciphertext_size
    CHECK (
        proof_size_bytes IS NULL
        OR proof_size_bytes BETWEEN 0 AND 9223372036854775807
    );
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_plaintext_size;
ALTER TABLE replica_placement
    ADD CONSTRAINT ck_replica_plaintext_size
    CHECK (
        proof_plaintext_size_bytes IS NULL
        OR proof_plaintext_size_bytes BETWEEN 0 AND 9223372036854775807
    );
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_plaintext_hash;
ALTER TABLE replica_placement
    ADD CONSTRAINT ck_replica_plaintext_hash
    CHECK (
        proof_plaintext_sha256 IS NULL
        OR proof_plaintext_sha256 ~ '^[0-9a-f]{64}$'
    );
DROP INDEX IF EXISTS idx_replica_inventory_snapshot;
CREATE INDEX idx_replica_inventory_snapshot
    ON replica_placement (
        server_id,
        storage_incarnation,
        status,
        placement_id,
        created_at,
        proof_at,
        last_inventory_seen_at,
        last_inventory_snapshot_id
    )
    WHERE status = 'present';
DROP INDEX IF EXISTS idx_replica_placement_object;
CREATE INDEX idx_replica_placement_object
    ON replica_placement (object_id, placement_id);
CREATE INDEX IF NOT EXISTS idx_replica_repair_source
    ON replica_placement (server_id, placement_id)
    WHERE status = 'present';

ALTER TABLE storage_replication_capabilities
    DROP CONSTRAINT IF EXISTS ck_replication_capability_size;
ALTER TABLE storage_replication_capabilities
    ADD CONSTRAINT ck_replication_capability_size
    CHECK (
        expected_ciphertext_size_bytes BETWEEN 0 AND 9223372036854775807
    );

-- A server-wide marker keeps a large authoritative model snapshot discoverable while its rows are
-- applied and omissions are scanned in bounded pages. Identity binding prevents a replacement disk
-- or attested certificate from inheriting freshness or snapshot ordering.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS model_inventory_storage_incarnation VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS model_inventory_cert_pubkey_hash VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS model_inventory_snapshot_started_at TIMESTAMPTZ;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS model_inventory_snapshot_id VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS model_inventory_fresh_at TIMESTAMPTZ;
ALTER TABLE servers
    DROP CONSTRAINT IF EXISTS ck_servers_model_inventory_marker;
ALTER TABLE servers
    ADD CONSTRAINT ck_servers_model_inventory_marker
    CHECK (
        (
            model_inventory_fresh_at IS NULL
            AND model_inventory_storage_incarnation IS NULL
            AND model_inventory_cert_pubkey_hash IS NULL
            AND model_inventory_snapshot_started_at IS NULL
            AND model_inventory_snapshot_id IS NULL
        )
        OR (
            model_inventory_fresh_at IS NOT NULL
            AND model_inventory_storage_incarnation IS NOT NULL
            AND model_inventory_cert_pubkey_hash IS NOT NULL
            AND model_inventory_snapshot_started_at IS NOT NULL
            AND model_inventory_snapshot_id IS NOT NULL
        )
    );
CREATE INDEX IF NOT EXISTS idx_servers_model_inventory_fresh
    ON servers (model_inventory_fresh_at, server_id)
    WHERE storage_role IS true;

ALTER TABLE content_holdings
    ADD COLUMN IF NOT EXISTS last_snapshot_id VARCHAR;
ALTER TABLE content_holdings
    ADD COLUMN IF NOT EXISTS last_snapshot_started_at TIMESTAMPTZ;
ALTER TABLE content_holdings
    DROP CONSTRAINT IF EXISTS ck_content_holding_signed_bytes;
ALTER TABLE content_holdings
    ADD CONSTRAINT ck_content_holding_signed_bytes
    CHECK (bytes BETWEEN 0 AND 9223372036854775807);
CREATE INDEX IF NOT EXISTS idx_content_holdings_snapshot_omission
    ON content_holdings (
        server_id,
        holding_id
    );

-- One bounded inventory snapshot is populated page-by-page by a current attested storage
-- incarnation. Omission processing begins only after the final page is acknowledged, so a tracker
-- outage or interrupted scan can never make valid data disappear.
CREATE TABLE IF NOT EXISTS storage_inventory_snapshots (
    snapshot_id              VARCHAR PRIMARY KEY,
    server_id                VARCHAR NOT NULL
        REFERENCES servers (server_id) ON DELETE CASCADE,
    storage_incarnation      VARCHAR NOT NULL,
    cert_pubkey_hash         VARCHAR NOT NULL,
    state                    VARCHAR NOT NULL DEFAULT 'scanning',
    started_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    eligibility_cutoff_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_page_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at             TIMESTAMPTZ,
    reconciled_at            TIMESTAMPTZ,
    reconcile_cursor         VARCHAR,
    reported_entries         BIGINT NOT NULL DEFAULT 0,
    omitted_entries          BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_storage_inventory_state
        CHECK (state IN ('scanning', 'complete', 'reconciled')),
    CONSTRAINT ck_storage_inventory_counts
        CHECK (reported_entries >= 0 AND omitted_entries >= 0)
);
ALTER TABLE storage_inventory_snapshots
    ADD COLUMN IF NOT EXISTS eligibility_cutoff_at TIMESTAMPTZ;
UPDATE storage_inventory_snapshots
SET eligibility_cutoff_at = started_at
WHERE eligibility_cutoff_at IS NULL;
ALTER TABLE storage_inventory_snapshots
    ALTER COLUMN eligibility_cutoff_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_storage_inventory_reconcile
    ON storage_inventory_snapshots (state, completed_at, snapshot_id);
CREATE INDEX IF NOT EXISTS idx_storage_inventory_server
    ON storage_inventory_snapshots (server_id, storage_incarnation, started_at);
CREATE INDEX IF NOT EXISTS idx_storage_inventory_stale
    ON storage_inventory_snapshots (last_page_at, snapshot_id)
    WHERE state IN ('scanning', 'reconciled');

-- Model holdings use a staged authoritative snapshot. Scanning pages never touch the live holding
-- directory. After the final page, reconciliation applies staged entries and only then removes
-- omissions, both with bounded keyset cursors.
CREATE TABLE IF NOT EXISTS storage_model_inventory_snapshots (
    snapshot_id              VARCHAR PRIMARY KEY,
    server_id                VARCHAR NOT NULL
        REFERENCES servers (server_id) ON DELETE CASCADE,
    storage_incarnation      VARCHAR NOT NULL,
    cert_pubkey_hash         VARCHAR NOT NULL,
    state                    VARCHAR NOT NULL DEFAULT 'scanning',
    started_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    eligibility_cutoff_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_page_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at             TIMESTAMPTZ,
    reconciled_at            TIMESTAMPTZ,
    application_started_at   TIMESTAMPTZ,
    last_reconcile_at        TIMESTAMPTZ,
    apply_cursor_repo_id     VARCHAR,
    apply_cursor_revision    VARCHAR,
    omit_cursor              VARCHAR,
    next_page_index          INTEGER NOT NULL DEFAULT 0,
    reported_entries         BIGINT NOT NULL DEFAULT 0,
    applied_entries          BIGINT NOT NULL DEFAULT 0,
    omitted_entries          BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT ck_storage_model_inventory_state
        CHECK (state IN ('scanning', 'complete', 'applying', 'omitting', 'reconciled')),
    CONSTRAINT ck_storage_model_inventory_counts
        CHECK (
            next_page_index >= 0
            AND
            reported_entries BETWEEN 0 AND 9223372036854775807
            AND applied_entries BETWEEN 0 AND 9223372036854775807
            AND omitted_entries BETWEEN 0 AND 9223372036854775807
        )
);
ALTER TABLE storage_model_inventory_snapshots
    ADD COLUMN IF NOT EXISTS application_started_at TIMESTAMPTZ;
ALTER TABLE storage_model_inventory_snapshots
    ADD COLUMN IF NOT EXISTS last_reconcile_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS storage_model_inventory_entries (
    snapshot_id VARCHAR NOT NULL
        REFERENCES storage_model_inventory_snapshots (snapshot_id) ON DELETE CASCADE,
    repo_id     VARCHAR NOT NULL,
    revision    VARCHAR NOT NULL,
    bytes       BIGINT NOT NULL,
    PRIMARY KEY (snapshot_id, repo_id, revision),
    CONSTRAINT ck_storage_model_inventory_entry_bytes
        CHECK (bytes BETWEEN 0 AND 9223372036854775807)
);
DROP INDEX IF EXISTS idx_storage_model_inventory_reconcile;
CREATE INDEX idx_storage_model_inventory_reconcile
    ON storage_model_inventory_snapshots (
        state,
        last_reconcile_at,
        started_at DESC,
        snapshot_id DESC
    )
    WHERE state IN ('complete', 'applying', 'omitting');
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_model_inventory_active_identity
    ON storage_model_inventory_snapshots (
        server_id,
        storage_incarnation,
        cert_pubkey_hash
    )
    WHERE state IN ('applying', 'omitting');
CREATE INDEX IF NOT EXISTS idx_storage_model_inventory_waiting
    ON storage_model_inventory_snapshots (
        server_id,
        storage_incarnation,
        cert_pubkey_hash,
        started_at DESC,
        snapshot_id DESC
    )
    WHERE state = 'complete';
CREATE INDEX IF NOT EXISTS idx_storage_model_inventory_stale
    ON storage_model_inventory_snapshots (last_page_at, snapshot_id)
    WHERE state IN ('scanning', 'reconciled');
CREATE INDEX IF NOT EXISTS idx_storage_model_inventory_server_order
    ON storage_model_inventory_snapshots (
        server_id,
        storage_incarnation,
        cert_pubkey_hash,
        started_at,
        snapshot_id
    );

-- Every known or inventory-discovered immutable generation gets one durable task per physical
-- holder incarnation. Tasks survive placement/object purge and remain pending while a holder is
-- offline. "retired" is an explicit administrator action allowed only after retention_deadline.
CREATE TABLE IF NOT EXISTS storage_erase_tasks (
    task_id                    VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    object_id                  VARCHAR NOT NULL,
    volume_id                  VARCHAR NOT NULL,
    placement_id               VARCHAR,
    server_id                  VARCHAR NOT NULL,
    storage_incarnation        VARCHAR,
    holder_cert_pubkey_hash    VARCHAR,
    reason                     VARCHAR NOT NULL,
    state                      VARCHAR NOT NULL DEFAULT 'pending',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_deadline         TIMESTAMPTZ NOT NULL,
    claimed_at                 TIMESTAMPTZ,
    lease_expires_at           TIMESTAMPTZ,
    claim_cert_pubkey_hash     VARCHAR,
    attempt_count              INTEGER NOT NULL DEFAULT 0,
    completed_at               TIMESTAMPTZ,
    erased_file_was_present    BOOLEAN,
    retired_by_user_id         VARCHAR,
    last_error                 VARCHAR,
    metadata_purged_at         TIMESTAMPTZ,
    CONSTRAINT ck_storage_erase_task_state
        CHECK (state IN ('pending', 'claimed', 'erased', 'retired')),
    CONSTRAINT ck_storage_erase_task_attempts
        CHECK (attempt_count >= 0),
    CONSTRAINT ck_storage_erase_task_terminal
        CHECK (
            (state IN ('erased', 'retired') AND completed_at IS NOT NULL)
            OR (state IN ('pending', 'claimed') AND completed_at IS NULL)
        )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_erase_generation_holder
    ON storage_erase_tasks (
        object_id,
        server_id,
        COALESCE(storage_incarnation, '')
    );
CREATE INDEX IF NOT EXISTS idx_storage_erase_claim
    ON storage_erase_tasks (server_id, storage_incarnation, state, lease_expires_at, created_at);
CREATE INDEX IF NOT EXISTS idx_storage_erase_object
    ON storage_erase_tasks (object_id, state);
CREATE INDEX IF NOT EXISTS idx_storage_erase_volume
    ON storage_erase_tasks (volume_id, state);
CREATE INDEX IF NOT EXISTS idx_storage_erase_volume_reason
    ON storage_erase_tasks (volume_id, reason, task_id);
CREATE INDEX IF NOT EXISTS idx_storage_erase_volume_finalize
    ON storage_erase_tasks (volume_id, state, reason, metadata_purged_at);
CREATE INDEX IF NOT EXISTS idx_storage_erase_retention
    ON storage_erase_tasks (retention_deadline, task_id)
    WHERE state IN ('pending', 'claimed');
CREATE INDEX IF NOT EXISTS idx_storage_erase_terminal_unpurged
    ON storage_erase_tasks (object_id, task_id)
    WHERE state IN ('erased', 'retired')
      AND metadata_purged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_storage_erase_terminal_audit
    ON storage_erase_tasks (completed_at, task_id, volume_id)
    WHERE state IN ('erased', 'retired')
      AND metadata_purged_at IS NOT NULL;

-- Synchronize names created by the original unnamed UNIQUE declarations with the ORM names. If an
-- ORM bootstrap already created the canonical constraint, remove only the redundant legacy one.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'replica_placement'::regclass
          AND conname = 'replica_placement_object_id_server_id_key'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'replica_placement'::regclass
              AND conname = 'uq_replica_object_server'
        ) THEN
            ALTER TABLE replica_placement
                DROP CONSTRAINT replica_placement_object_id_server_id_key;
        ELSE
            ALTER TABLE replica_placement
                RENAME CONSTRAINT replica_placement_object_id_server_id_key
                TO uq_replica_object_server;
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'content_holdings'::regclass
          AND conname = 'content_holdings_server_id_repo_id_revision_key'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'content_holdings'::regclass
              AND conname = 'uq_content_holding'
        ) THEN
            ALTER TABLE content_holdings
                DROP CONSTRAINT content_holdings_server_id_repo_id_revision_key;
        ELSE
            ALTER TABLE content_holdings
                RENAME CONSTRAINT content_holdings_server_id_repo_id_revision_key
                TO uq_content_holding;
        END IF;
    END IF;
END
$$;

-- The canonical case-folded unique index covers every attested-certificate lookup and makes the
-- older case-sensitive non-unique index redundant.
DROP INDEX IF EXISTS idx_servers_attested_pubkey;

-- Existing attested certificate hashes were looked up with scalar_one_or_none(), so duplicate
-- non-NULL values are already an invalid security state. Fail the migration loudly rather than
-- silently choosing or deleting an identity.
DO $$
DECLARE
    duplicate_hash VARCHAR;
BEGIN
    SELECT lower(attested_cert_pubkey_hash)
    INTO duplicate_hash
    FROM servers
    WHERE attested_cert_pubkey_hash IS NOT NULL
    GROUP BY lower(attested_cert_pubkey_hash)
    HAVING count(*) > 1
    LIMIT 1;
    IF duplicate_hash IS NOT NULL THEN
        RAISE EXCEPTION
            'duplicate attested certificate pubkey hash prevents storage hygiene migration: %',
            duplicate_hash
            USING ERRCODE = '23505';
    END IF;
END
$$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_attested_pubkey
    ON servers (lower(attested_cert_pubkey_hash))
    WHERE attested_cert_pubkey_hash IS NOT NULL;

-- Preserve the existing generation/placement triggers and layer the additional immutable receipt
-- and placement-request invariants independently.
CREATE OR REPLACE FUNCTION enforce_storage_hygiene_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    predecessor_state VARCHAR;
    predecessor_erase_enqueued_at TIMESTAMPTZ;
BEGIN
    IF TG_TABLE_NAME = 'storage_objects' THEN
        IF TG_OP = 'UPDATE'
           AND OLD.placement_request_id IS DISTINCT FROM NEW.placement_request_id THEN
            RAISE EXCEPTION 'storage placement request identity is immutable'
                USING ERRCODE = '23514';
        END IF;

        IF TG_OP = 'UPDATE'
           AND OLD.expected_predecessor_id IS DISTINCT FROM
               NEW.expected_predecessor_id THEN
            IF OLD.expected_predecessor_id IS NULL
               OR NEW.expected_predecessor_id IS NOT NULL
               OR OLD.lifecycle_state = 'pending'
               OR NEW.lifecycle_state = 'pending'
               OR OLD.detached_predecessor_id IS NOT NULL
               OR NEW.detached_predecessor_id IS DISTINCT FROM
                   OLD.expected_predecessor_id
               OR NEW.predecessor_detached_at IS NULL THEN
                RAISE EXCEPTION 'invalid storage generation predecessor detachment'
                    USING ERRCODE = '23514';
            END IF;

            SELECT lifecycle_state, erase_enqueued_at
            INTO predecessor_state, predecessor_erase_enqueued_at
            FROM storage_objects
            WHERE object_id = OLD.expected_predecessor_id
            FOR SHARE;

            IF predecessor_state IS NULL
               OR predecessor_state NOT IN ('superseded', 'tombstoned')
               OR predecessor_erase_enqueued_at IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM storage_erase_tasks
                   WHERE object_id = OLD.expected_predecessor_id
                     AND state NOT IN ('erased', 'retired')
               )
               OR EXISTS (
                   SELECT 1
                   FROM replica_placement AS holder
                   WHERE holder.object_id = OLD.expected_predecessor_id
                     AND NOT EXISTS (
                         SELECT 1
                         FROM storage_erase_tasks AS erase_task
                         WHERE erase_task.object_id = holder.object_id
                           AND erase_task.server_id = holder.server_id
                           AND COALESCE(erase_task.storage_incarnation, '') =
                               COALESCE(holder.storage_incarnation, '')
                           AND erase_task.state IN ('erased', 'retired')
                     )
               ) THEN
                RAISE EXCEPTION 'predecessor holders are not terminally erased'
                    USING ERRCODE = '23514';
            END IF;

            -- The generation trigger installed by 20260713170000 consumes this row-specific,
            -- transaction-local validation marker and otherwise keeps the predecessor immutable.
            PERFORM set_config(
                'chutefs.validated_predecessor_detachment',
                NEW.object_id,
                true
            );
        ELSIF TG_OP = 'UPDATE'
           AND (
               OLD.detached_predecessor_id IS DISTINCT FROM
                   NEW.detached_predecessor_id
               OR OLD.predecessor_detached_at IS DISTINCT FROM
                   NEW.predecessor_detached_at
           ) THEN
            RAISE EXCEPTION 'detached predecessor audit metadata is immutable'
                USING ERRCODE = '23514';
        END IF;

        IF TG_OP = 'UPDATE'
           AND OLD.legacy_adopted_at IS NULL
           AND NEW.legacy_adopted_at IS NOT NULL
           AND NOT EXISTS (
               SELECT 1
               FROM replica_placement AS placement
               WHERE placement.placement_id = NEW.legacy_adoption_placement_id
                 AND placement.object_id = NEW.object_id
                 AND placement.proof_mode = 'legacy_adoption'
                 AND placement.proof_at = NEW.legacy_adopted_at
                 AND placement.proof_size_bytes = NEW.ciphertext_size_bytes
                 AND placement.proof_plaintext_size_bytes = NEW.size_bytes
                 AND placement.proof_plaintext_sha256 =
                     lower(NEW.plaintext_sha256)
           ) THEN
            RAISE EXCEPTION 'legacy adoption lacks trusted plaintext receipt evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.proof_at IS NOT NULL
       AND (
           OLD.proof_plaintext_size_bytes IS DISTINCT FROM
               NEW.proof_plaintext_size_bytes
           OR OLD.proof_plaintext_sha256 IS DISTINCT FROM
               NEW.proof_plaintext_sha256
       ) THEN
        RAISE EXCEPTION 'recorded plaintext receipt evidence is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.proof_mode IN ('direct_upload', 'legacy_adoption')
       AND NEW.proof_at IS NOT NULL THEN
        IF NEW.proof_plaintext_size_bytes IS NULL
           OR NEW.proof_plaintext_size_bytes NOT BETWEEN 0 AND 9223372036854775807
           OR NEW.proof_plaintext_sha256 IS NULL
           OR NEW.proof_plaintext_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'plaintext-observing proof requires exact plaintext evidence'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.proof_plaintext_size_bytes IS NOT NULL
       OR NEW.proof_plaintext_sha256 IS NOT NULL THEN
        RAISE EXCEPTION 'proof mode may not carry plaintext evidence'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_storage_hygiene_object ON storage_objects;
CREATE TRIGGER trg_storage_hygiene_object
BEFORE UPDATE ON storage_objects
FOR EACH ROW EXECUTE FUNCTION enforce_storage_hygiene_receipt();

DROP TRIGGER IF EXISTS trg_storage_hygiene_receipt ON replica_placement;
CREATE TRIGGER trg_storage_hygiene_receipt
BEFORE INSERT OR UPDATE ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_storage_hygiene_receipt();

-- migrate:down

DROP TRIGGER IF EXISTS trg_storage_hygiene_receipt ON replica_placement;
DROP TRIGGER IF EXISTS trg_storage_hygiene_object ON storage_objects;
DROP FUNCTION IF EXISTS enforce_storage_hygiene_receipt();

DROP INDEX IF EXISTS uq_servers_attested_pubkey;
CREATE INDEX IF NOT EXISTS idx_servers_attested_pubkey
    ON servers (attested_cert_pubkey_hash)
    WHERE attested_cert_pubkey_hash IS NOT NULL;
DROP TABLE IF EXISTS storage_erase_tasks;
DROP TABLE IF EXISTS storage_model_inventory_entries;
DROP TABLE IF EXISTS storage_model_inventory_snapshots;
DROP TABLE IF EXISTS storage_inventory_snapshots;

DROP INDEX IF EXISTS idx_replica_placement_object;
CREATE INDEX IF NOT EXISTS idx_replica_placement_object
    ON replica_placement (object_id);
DROP INDEX IF EXISTS idx_content_holdings_snapshot_omission;
ALTER TABLE content_holdings
    DROP CONSTRAINT IF EXISTS ck_content_holding_signed_bytes;
ALTER TABLE content_holdings DROP COLUMN IF EXISTS last_snapshot_started_at;
ALTER TABLE content_holdings DROP COLUMN IF EXISTS last_snapshot_id;

DROP INDEX IF EXISTS idx_servers_model_inventory_fresh;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_model_inventory_marker;
ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_fresh_at;
ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_snapshot_id;
ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_snapshot_started_at;
ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_cert_pubkey_hash;
ALTER TABLE servers DROP COLUMN IF EXISTS model_inventory_storage_incarnation;

DROP INDEX IF EXISTS idx_replica_repair_source;
DROP INDEX IF EXISTS idx_replica_inventory_snapshot;
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_plaintext_hash;
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_plaintext_size;
ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_ciphertext_size;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_inventory_seen_at;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_inventory_snapshot_id;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_plaintext_sha256;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_plaintext_size_bytes;

ALTER TABLE storage_replication_capabilities
    DROP CONSTRAINT IF EXISTS ck_replication_capability_size;
ALTER TABLE storage_replication_capabilities
    ADD CONSTRAINT ck_replication_capability_size
    CHECK (expected_ciphertext_size_bytes >= 0);

DROP TABLE IF EXISTS storage_object_delete_fences;
DROP INDEX IF EXISTS idx_storage_objects_deleted_volume_retire;
DROP INDEX IF EXISTS idx_storage_objects_volume;
DROP INDEX IF EXISTS idx_storage_objects_delete_fence;
DROP INDEX IF EXISTS idx_storage_objects_expected_predecessor;
DROP INDEX IF EXISTS idx_storage_objects_terminal_erase;
DROP INDEX IF EXISTS idx_storage_objects_erase_queue;
DROP INDEX IF EXISTS uq_storage_object_placement_request;
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS ck_storage_object_detached_predecessor;
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS ck_storage_object_signed_sizes;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS predecessor_detached_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS detached_predecessor_id;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS erase_enqueued_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS placement_request_id;

DROP INDEX IF EXISTS idx_storage_volumes_deleted_work;
ALTER TABLE storage_volumes DROP COLUMN IF EXISTS purged_at;
ALTER TABLE storage_volumes DROP COLUMN IF EXISTS key_shredded_at;
ALTER TABLE storage_volumes DROP COLUMN IF EXISTS delete_requested_at;

ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_storage_aggregate_quota;
ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_storage_volume_quota;
ALTER TABLE users DROP COLUMN IF EXISTS storage_aggregate_quota_bytes;
ALTER TABLE users DROP COLUMN IF EXISTS storage_volume_quota_bytes;
