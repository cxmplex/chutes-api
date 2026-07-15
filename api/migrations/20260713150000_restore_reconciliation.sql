-- migrate:up

-- A storage server's stable server_id identifies the TD slot, not the encrypted disk currently
-- attached to it.  The incarnation is generated and persisted inside that encrypted filesystem.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS storage_incarnation VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS storage_incarnation_announced_at TIMESTAMPTZ;

-- Keep the placement-time size reservation even before an object is committed, and persist the
-- durability result so list/status APIs never imply that pending work is a durable copy.
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS projected_size_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS durability_state VARCHAR NOT NULL DEFAULT 'pending';
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS durable_replica_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS durability_updated_at TIMESTAMPTZ;

-- A placement is a durable state machine.  Pending work has a deadline and durable attempt state;
-- present requires a target-TD receipt bound to the exact ciphertext, volume incarnation, and
-- attested certificate that was assigned.
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS storage_incarnation VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS target_cert_pubkey_hash VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_sha256 VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_at TIMESTAMPTZ;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS pending_since TIMESTAMPTZ;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS pending_deadline TIMESTAMPTZ;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS last_error VARCHAR;

-- Existing rows predate possession receipts and disk incarnations.  Fail closed: a new measured
-- storage-node release must announce its incarnation and prove each local ciphertext before any old
-- placement can count again.
UPDATE replica_placement
SET status = 'evicted',
    confirmed_at = NULL,
    storage_incarnation = NULL,
    target_cert_pubkey_hash = NULL,
    proof_sha256 = NULL,
    proof_at = NULL,
    pending_since = NULL,
    pending_deadline = NULL,
    last_error = 'migration_requires_possession_proof'
WHERE status IN ('pending', 'present')
  AND (
      storage_incarnation IS NULL
      OR target_cert_pubkey_hash IS NULL
      OR (status = 'present' AND (proof_sha256 IS NULL OR proof_at IS NULL))
  );

UPDATE storage_objects
SET projected_size_bytes = GREATEST(projected_size_bytes, size_bytes),
    durability_state = CASE WHEN sha256 IS NOT NULL THEN 'irrecoverable' ELSE 'pending' END,
    durable_replica_count = 0,
    durability_updated_at = now()
WHERE durability_updated_at IS NULL;

ALTER TABLE replica_placement ALTER COLUMN status SET DEFAULT 'pending';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_replica_placement_status'
          AND conrelid = 'replica_placement'::regclass
    ) THEN
        ALTER TABLE replica_placement
            ADD CONSTRAINT ck_replica_placement_status
            CHECK (status IN ('pending', 'present', 'evicted'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_replica_placement_attempt_count'
          AND conrelid = 'replica_placement'::regclass
    ) THEN
        ALTER TABLE replica_placement
            ADD CONSTRAINT ck_replica_placement_attempt_count
            CHECK (attempt_count >= 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_storage_object_durability_state'
          AND conrelid = 'storage_objects'::regclass
    ) THEN
        ALTER TABLE storage_objects
            ADD CONSTRAINT ck_storage_object_durability_state
            CHECK (
                durability_state IN (
                    'pending',
                    'healthy',
                    'under_replicated',
                    'at_risk',
                    'irrecoverable'
                )
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_storage_object_durable_replica_count'
          AND conrelid = 'storage_objects'::regclass
    ) THEN
        ALTER TABLE storage_objects
            ADD CONSTRAINT ck_storage_object_durable_replica_count
            CHECK (durable_replica_count >= 0);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_replica_pending_deadline
    ON replica_placement (pending_deadline)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_replica_server_incarnation
    ON replica_placement (server_id, storage_incarnation);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'storage_objects'
          AND column_name = 'deleted'
    ) THEN
        EXECUTE $index$
            CREATE INDEX IF NOT EXISTS idx_storage_objects_reconcile
            ON storage_objects (durability_updated_at, object_id)
            WHERE deleted IS false
        $index$;
    ELSE
        EXECUTE $index$
            CREATE INDEX IF NOT EXISTS idx_storage_objects_reconcile
            ON storage_objects (durability_updated_at, object_id)
            WHERE lifecycle_state = 'committed'
        $index$;
    END IF;
END
$$;

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

DROP TRIGGER IF EXISTS trg_replica_placement_transition ON replica_placement;
CREATE TRIGGER trg_replica_placement_transition
BEFORE INSERT OR UPDATE ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_placement_transition();

-- migrate:down

DROP TRIGGER IF EXISTS trg_replica_placement_transition ON replica_placement;
DROP FUNCTION IF EXISTS enforce_replica_placement_transition();

ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_durable_replica_count;
ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS ck_storage_object_durability_state;
ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_placement_attempt_count;
ALTER TABLE replica_placement DROP CONSTRAINT IF EXISTS ck_replica_placement_status;

DROP INDEX IF EXISTS idx_storage_objects_reconcile;
DROP INDEX IF EXISTS idx_replica_server_incarnation;
DROP INDEX IF EXISTS idx_replica_pending_deadline;

ALTER TABLE replica_placement ALTER COLUMN status SET DEFAULT 'present';
ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_error;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS last_attempt_at;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS attempt_count;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS pending_deadline;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS pending_since;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_at;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_sha256;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS target_cert_pubkey_hash;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS storage_incarnation;

ALTER TABLE storage_objects DROP COLUMN IF EXISTS durability_updated_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS durable_replica_count;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS durability_state;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS projected_size_bytes;

ALTER TABLE servers DROP COLUMN IF EXISTS storage_incarnation_announced_at;
ALTER TABLE servers DROP COLUMN IF EXISTS storage_incarnation;
