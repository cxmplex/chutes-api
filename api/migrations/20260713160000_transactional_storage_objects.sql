-- migrate:up

-- Every storage_objects row is now one immutable upload generation.  A key may have many pending,
-- superseded, or tombstoned generations, but at most one committed (current) generation.
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS expected_predecessor_id VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS committed_at TIMESTAMPTZ;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ;

-- Upgrade the mutable-row model in place.  Real stored objects become current committed
-- generations.  Deleted rows and incomplete legacy reservations become tombstones; an incomplete
-- reservation cannot be resumed safely because the old protocol had no immutable upload salt.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'storage_objects'
          AND column_name = 'deleted'
    ) THEN
        EXECUTE $upgrade$
            UPDATE storage_objects
            SET lifecycle_state = CASE
                    WHEN deleted THEN 'tombstoned'
                    WHEN sha256 IS NOT NULL THEN 'committed'
                    ELSE 'tombstoned'
                END,
                committed_at = CASE
                    WHEN sha256 IS NOT NULL
                        THEN COALESCE(updated_at, created_at, statement_timestamp())
                    ELSE NULL
                END,
                tombstoned_at = CASE
                    WHEN deleted OR sha256 IS NULL
                        THEN COALESCE(updated_at, created_at, statement_timestamp())
                    ELSE NULL
                END,
                projected_size_bytes = CASE
                    WHEN sha256 IS NOT NULL THEN size_bytes
                    ELSE projected_size_bytes
                END
            WHERE lifecycle_state IS NULL
        $upgrade$;
    ELSE
        UPDATE storage_objects
        SET lifecycle_state = CASE
                WHEN sha256 IS NOT NULL THEN 'committed'
                ELSE 'tombstoned'
            END,
            committed_at = CASE
                WHEN sha256 IS NOT NULL
                    THEN COALESCE(updated_at, created_at, statement_timestamp())
                ELSE NULL
            END,
            tombstoned_at = CASE
                WHEN sha256 IS NULL
                    THEN COALESCE(updated_at, created_at, statement_timestamp())
                ELSE NULL
            END,
            projected_size_bytes = CASE
                WHEN sha256 IS NOT NULL THEN size_bytes
                ELSE projected_size_bytes
            END
        WHERE lifecycle_state IS NULL;
    END IF;
END
$$;

ALTER TABLE storage_objects
    ALTER COLUMN lifecycle_state SET DEFAULT 'pending';
ALTER TABLE storage_objects
    ALTER COLUMN lifecycle_state SET NOT NULL;

ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS fk_storage_object_expected_predecessor;
ALTER TABLE storage_objects
    ADD CONSTRAINT fk_storage_object_expected_predecessor
    FOREIGN KEY (expected_predecessor_id)
    REFERENCES storage_objects (object_id)
    ON DELETE RESTRICT;

ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS ck_storage_object_lifecycle_state;
ALTER TABLE storage_objects
    ADD CONSTRAINT ck_storage_object_lifecycle_state
    CHECK (lifecycle_state IN ('pending', 'committed', 'superseded', 'tombstoned'));

-- The former live-row index made concurrent upload attempts impossible.  Currentness is now an
-- explicit committed state, protected by a partial unique index.
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS storage_objects_volume_id_object_key_key;
ALTER TABLE storage_objects
    DROP CONSTRAINT IF EXISTS uq_storage_object_key;
DROP INDEX IF EXISTS uq_storage_object_key;
DROP INDEX IF EXISTS idx_storage_objects_volume;
DROP INDEX IF EXISTS idx_storage_objects_reconcile;
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_object_current
    ON storage_objects (volume_id, object_key)
    WHERE lifecycle_state = 'committed';
CREATE INDEX IF NOT EXISTS idx_storage_objects_current
    ON storage_objects (volume_id, object_key)
    WHERE lifecycle_state = 'committed';
CREATE INDEX IF NOT EXISTS idx_storage_objects_pending
    ON storage_objects (created_at, object_id)
    WHERE lifecycle_state = 'pending';
CREATE INDEX IF NOT EXISTS idx_storage_objects_reconcile
    ON storage_objects (durability_updated_at, object_id)
    WHERE lifecycle_state = 'committed';
CREATE INDEX IF NOT EXISTS idx_storage_objects_gc
    ON storage_objects (tombstoned_at, superseded_at, object_id)
    WHERE lifecycle_state IN ('superseded', 'tombstoned');

-- `deleted` represented both key visibility and an upload reservation.  Keeping it beside the
-- lifecycle state would create two conflicting sources of truth, so migrate and remove it.
ALTER TABLE storage_objects DROP COLUMN IF EXISTS deleted;

-- Recompute accounting from the one current generation per key.  Pending and retired generations
-- reserve placement capacity but are never billable volume contents.
UPDATE storage_volumes AS volume
SET used_bytes = totals.used_bytes
FROM (
    SELECT candidate.volume_id, COALESCE(SUM(candidate.size_bytes), 0)::BIGINT AS used_bytes
    FROM storage_objects AS candidate
    WHERE candidate.lifecycle_state = 'committed'
    GROUP BY candidate.volume_id
) AS totals
WHERE volume.volume_id = totals.volume_id;
UPDATE storage_volumes AS volume
SET used_bytes = 0
WHERE NOT EXISTS (
    SELECT 1
    FROM storage_objects AS candidate
    WHERE candidate.volume_id = volume.volume_id
      AND candidate.lifecycle_state = 'committed'
);

CREATE OR REPLACE FUNCTION enforce_storage_object_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle_state <> 'pending' THEN
            RAISE EXCEPTION 'new storage object generations must start pending'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF OLD.object_id IS DISTINCT FROM NEW.object_id
           OR OLD.volume_id IS DISTINCT FROM NEW.volume_id
           OR OLD.object_key IS DISTINCT FROM NEW.object_key
           OR OLD.expected_predecessor_id IS DISTINCT FROM NEW.expected_predecessor_id
           OR OLD.salt IS DISTINCT FROM NEW.salt
           OR OLD.projected_size_bytes IS DISTINCT FROM NEW.projected_size_bytes THEN
            RAISE EXCEPTION 'storage object generation identity is immutable'
                USING ERRCODE = '23514';
        END IF;

        IF OLD.lifecycle_state <> NEW.lifecycle_state
           AND NOT (
               (OLD.lifecycle_state = 'pending'
                    AND NEW.lifecycle_state IN ('committed', 'tombstoned'))
               OR (OLD.lifecycle_state = 'committed'
                    AND NEW.lifecycle_state IN ('superseded', 'tombstoned'))
               OR (OLD.lifecycle_state = 'superseded'
                    AND NEW.lifecycle_state = 'tombstoned')
           ) THEN
            RAISE EXCEPTION 'illegal storage object lifecycle transition: % -> %',
                OLD.lifecycle_state, NEW.lifecycle_state
                USING ERRCODE = '23514';
        END IF;

        IF OLD.lifecycle_state <> 'pending'
           AND (
               OLD.size_bytes IS DISTINCT FROM NEW.size_bytes
               OR OLD.sha256 IS DISTINCT FROM NEW.sha256
               OR OLD.plaintext_sha256 IS DISTINCT FROM NEW.plaintext_sha256
               OR OLD.committed_at IS DISTINCT FROM NEW.committed_at
           ) THEN
            RAISE EXCEPTION 'committed storage object generation metadata is immutable'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.lifecycle_state = 'pending' THEN
        IF NEW.salt IS NULL OR NEW.sha256 IS NOT NULL OR NEW.committed_at IS NOT NULL THEN
            RAISE EXCEPTION 'pending generation requires a reserved salt and no committed metadata'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.lifecycle_state = 'committed' THEN
        IF NEW.sha256 IS NULL
           OR NEW.sha256 !~ '^[0-9a-f]{64}$'
           OR NEW.committed_at IS NULL
           OR NEW.size_bytes <> NEW.projected_size_bytes THEN
            RAISE EXCEPTION 'committed generation metadata is incomplete'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.lifecycle_state = 'superseded' THEN
        IF NEW.sha256 IS NULL OR NEW.committed_at IS NULL OR NEW.superseded_at IS NULL THEN
            RAISE EXCEPTION 'superseded generation must have committed history'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.lifecycle_state = 'tombstoned' AND NEW.tombstoned_at IS NULL THEN
        RAISE EXCEPTION 'tombstoned generation requires tombstoned_at'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_storage_object_generation ON storage_objects;
CREATE TRIGGER trg_storage_object_generation
BEFORE INSERT OR UPDATE ON storage_objects
FOR EACH ROW EXECUTE FUNCTION enforce_storage_object_generation();

-- A possession receipt is durable only after the exact generation has committed.  Before commit,
-- proof fields may be recorded on the pending placement but pending -> present is forbidden.
CREATE OR REPLACE FUNCTION enforce_replica_placement_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_sha256 VARCHAR;
    object_lifecycle VARCHAR;
    current_incarnation VARCHAR;
    current_cert_hash VARCHAR;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'new replica placements must start pending'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.status <> NEW.status THEN
        IF NOT (
            (OLD.status = 'pending' AND NEW.status IN ('present', 'evicted'))
            OR (OLD.status = 'present' AND NEW.status = 'evicted')
            OR (OLD.status = 'evicted' AND NEW.status = 'pending')
        ) THEN
            RAISE EXCEPTION 'illegal replica placement transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.status = 'pending' THEN
        IF NEW.pending_since IS NULL OR NEW.pending_deadline IS NULL THEN
            RAISE EXCEPTION 'pending replica placement requires a durable deadline'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.storage_incarnation IS NULL OR NEW.target_cert_pubkey_hash IS NULL THEN
            RAISE EXCEPTION 'pending replica placement requires target incarnation and certificate'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'INSERT' OR OLD.status = 'evicted' THEN
            IF NEW.confirmed_at IS NOT NULL OR NEW.proof_sha256 IS NOT NULL OR NEW.proof_at IS NOT NULL THEN
                RAISE EXCEPTION 'new/retried pending placement cannot retain a possession receipt'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF NEW.status = 'present' THEN
        IF NEW.confirmed_at IS NULL OR NEW.proof_at IS NULL OR NEW.proof_sha256 IS NULL THEN
            RAISE EXCEPTION 'present replica placement requires a possession receipt'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.proof_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'present replica placement has an invalid ciphertext hash'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'UPDATE'
           AND OLD.status = 'pending'
           AND NEW.pending_deadline IS NOT NULL
           AND NEW.pending_deadline < statement_timestamp() THEN
            RAISE EXCEPTION 'expired pending replica placement cannot become present'
                USING ERRCODE = '23514';
        END IF;

        SELECT lower(sha256), lifecycle_state
        INTO expected_sha256, object_lifecycle
        FROM storage_objects
        WHERE object_id = NEW.object_id;
        IF object_lifecycle <> 'committed' THEN
            RAISE EXCEPTION 'possession cannot become present before its generation commits'
                USING ERRCODE = '23514';
        END IF;
        IF expected_sha256 IS NULL OR expected_sha256 <> NEW.proof_sha256 THEN
            RAISE EXCEPTION 'possession receipt does not match the committed ciphertext hash'
                USING ERRCODE = '23514';
        END IF;

        SELECT storage_incarnation, lower(attested_cert_pubkey_hash)
        INTO current_incarnation, current_cert_hash
        FROM servers
        WHERE server_id = NEW.server_id;
        IF current_incarnation IS NULL
           OR current_incarnation <> NEW.storage_incarnation
           OR current_cert_hash IS NULL
           OR current_cert_hash <> lower(NEW.target_cert_pubkey_hash) THEN
            RAISE EXCEPTION 'possession receipt is not bound to the current storage identity'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_replica_placement_transition ON replica_placement;
CREATE TRIGGER trg_replica_placement_transition
BEFORE INSERT OR UPDATE ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_placement_transition();

-- migrate:down

DROP TRIGGER IF EXISTS trg_storage_object_generation ON storage_objects;
DROP FUNCTION IF EXISTS enforce_storage_object_generation();

CREATE OR REPLACE FUNCTION enforce_replica_placement_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_sha256 VARCHAR;
    current_incarnation VARCHAR;
    current_cert_hash VARCHAR;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'new replica placements must start pending'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.status <> NEW.status THEN
        IF NOT (
            (OLD.status = 'pending' AND NEW.status IN ('present', 'evicted'))
            OR (OLD.status = 'present' AND NEW.status = 'evicted')
            OR (OLD.status = 'evicted' AND NEW.status = 'pending')
        ) THEN
            RAISE EXCEPTION 'illegal replica placement transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.status = 'pending' THEN
        IF NEW.pending_since IS NULL OR NEW.pending_deadline IS NULL THEN
            RAISE EXCEPTION 'pending replica placement requires a durable deadline'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.storage_incarnation IS NULL OR NEW.target_cert_pubkey_hash IS NULL THEN
            RAISE EXCEPTION 'pending replica placement requires target incarnation and certificate'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'INSERT' OR OLD.status = 'evicted' THEN
            IF NEW.confirmed_at IS NOT NULL OR NEW.proof_sha256 IS NOT NULL OR NEW.proof_at IS NOT NULL THEN
                RAISE EXCEPTION 'new/retried pending placement cannot retain a possession receipt'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF NEW.status = 'present' THEN
        IF NEW.confirmed_at IS NULL OR NEW.proof_at IS NULL OR NEW.proof_sha256 IS NULL THEN
            RAISE EXCEPTION 'present replica placement requires a possession receipt'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.proof_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'present replica placement has an invalid ciphertext hash'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'UPDATE'
           AND OLD.status = 'pending'
           AND NEW.pending_deadline IS NOT NULL
           AND NEW.pending_deadline < statement_timestamp() THEN
            RAISE EXCEPTION 'expired pending replica placement cannot become present'
                USING ERRCODE = '23514';
        END IF;

        SELECT lower(sha256)
        INTO expected_sha256
        FROM storage_objects
        WHERE object_id = NEW.object_id;
        IF expected_sha256 IS NULL OR expected_sha256 <> NEW.proof_sha256 THEN
            RAISE EXCEPTION 'possession receipt does not match the committed ciphertext hash'
                USING ERRCODE = '23514';
        END IF;

        SELECT storage_incarnation, lower(attested_cert_pubkey_hash)
        INTO current_incarnation, current_cert_hash
        FROM servers
        WHERE server_id = NEW.server_id;
        IF current_incarnation IS NULL
           OR current_incarnation <> NEW.storage_incarnation
           OR current_cert_hash IS NULL
           OR current_cert_hash <> lower(NEW.target_cert_pubkey_hash) THEN
            RAISE EXCEPTION 'possession receipt is not bound to the current storage identity'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END
$$;

ALTER TABLE storage_objects ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false;
UPDATE storage_objects
SET deleted = lifecycle_state <> 'committed';

DROP INDEX IF EXISTS idx_storage_objects_gc;
DROP INDEX IF EXISTS idx_storage_objects_pending;
DROP INDEX IF EXISTS idx_storage_objects_current;
DROP INDEX IF EXISTS uq_storage_object_current;
DROP INDEX IF EXISTS idx_storage_objects_reconcile;
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_object_key
    ON storage_objects (volume_id, object_key)
    WHERE deleted IS false;
CREATE INDEX IF NOT EXISTS idx_storage_objects_volume
    ON storage_objects (volume_id)
    WHERE deleted IS false;
CREATE INDEX IF NOT EXISTS idx_storage_objects_reconcile
    ON storage_objects (durability_updated_at, object_id)
    WHERE deleted IS false;

ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_lifecycle_state;
ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS fk_storage_object_expected_predecessor;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS tombstoned_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS superseded_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS committed_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS expected_predecessor_id;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS lifecycle_state;
