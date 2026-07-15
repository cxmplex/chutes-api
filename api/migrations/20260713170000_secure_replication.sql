-- migrate:up

-- ST-05/ST-08: replica writes are authorized by one-use validator capabilities, never by a
-- volume-owner put grant.  The capability is bound to both attested storage identities, the exact
-- immutable generation and ciphertext, and the target placement attempt that leased the transfer.
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS ciphertext_size_bytes BIGINT;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS legacy_adopted_at TIMESTAMPTZ;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS legacy_adoption_placement_id VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS legacy_adoption_server_id VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS legacy_adoption_cert_pubkey_hash VARCHAR;
ALTER TABLE storage_objects
    ADD COLUMN IF NOT EXISTS legacy_adoption_storage_incarnation VARCHAR;

ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_size_bytes BIGINT;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_capability_id VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS proof_mode VARCHAR;
ALTER TABLE replica_placement
    ADD COLUMN IF NOT EXISTS legacy_adoption_started_at TIMESTAMPTZ;

-- Existing placements predate exact ciphertext-size/capability evidence. Quarantine by evidence,
-- not by whether an ORM bootstrap happened to pre-create the capability table. The predicate is
-- idempotent: a repeated migration cannot evict a later valid direct/capability/legacy receipt.
UPDATE replica_placement AS placement
SET status = 'evicted',
    confirmed_at = NULL,
    proof_sha256 = NULL,
    proof_size_bytes = NULL,
    proof_capability_id = NULL,
    proof_mode = NULL,
    proof_at = NULL,
    legacy_adoption_started_at = NULL,
    pending_since = NULL,
    pending_deadline = NULL,
    last_error = 'secure_replication_requires_new_receipt'
FROM storage_objects AS object_row
WHERE object_row.object_id = placement.object_id
  AND (
      (
          object_row.lifecycle_state = 'committed'
          AND object_row.ciphertext_size_bytes IS NULL
      )
      OR (
          placement.proof_sha256 IS NOT NULL
          AND (
              placement.proof_size_bytes IS NULL
              OR placement.proof_mode IS NULL
          )
      )
      OR (
          placement.proof_at IS NOT NULL
          AND placement.proof_mode IS NULL
      )
  );

UPDATE storage_objects
SET durable_replica_count = 0,
    durability_state = 'irrecoverable',
    durability_updated_at = statement_timestamp()
WHERE lifecycle_state = 'committed'
  AND ciphertext_size_bytes IS NULL;

CREATE TABLE IF NOT EXISTS storage_replication_capabilities (
    capability_id                  VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash                     VARCHAR NOT NULL UNIQUE,
    object_id                      VARCHAR NOT NULL
        REFERENCES storage_objects (object_id) ON DELETE CASCADE,
    volume_id                      VARCHAR NOT NULL
        REFERENCES storage_volumes (volume_id) ON DELETE CASCADE,
    source_placement_id            VARCHAR NOT NULL
        REFERENCES replica_placement (placement_id) ON DELETE CASCADE,
    source_server_id               VARCHAR NOT NULL
        REFERENCES servers (server_id) ON DELETE CASCADE,
    source_cert_pubkey_hash        VARCHAR NOT NULL,
    source_storage_incarnation     VARCHAR NOT NULL,
    target_placement_id            VARCHAR NOT NULL
        REFERENCES replica_placement (placement_id) ON DELETE CASCADE,
    target_placement_attempt       INTEGER NOT NULL,
    target_server_id               VARCHAR NOT NULL
        REFERENCES servers (server_id) ON DELETE CASCADE,
    target_cert_pubkey_hash        VARCHAR NOT NULL,
    target_storage_incarnation     VARCHAR NOT NULL,
    expected_ciphertext_sha256     VARCHAR NOT NULL,
    expected_ciphertext_size_bytes BIGINT NOT NULL,
    issued_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                     TIMESTAMPTZ NOT NULL,
    transfer_deadline              TIMESTAMPTZ NOT NULL,
    consumed_at                    TIMESTAMPTZ,
    completed_at                   TIMESTAMPTZ,
    failed_at                      TIMESTAMPTZ,
    last_error                     VARCHAR,
    CONSTRAINT ck_replication_capability_hash
        CHECK (expected_ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_replication_capability_size
        CHECK (expected_ciphertext_size_bytes >= 0),
    CONSTRAINT ck_replication_capability_attempt
        CHECK (target_placement_attempt > 0),
    CONSTRAINT ck_replication_capability_deadlines
        CHECK (issued_at < expires_at AND expires_at <= transfer_deadline),
    CONSTRAINT ck_replication_capability_terminal
        CHECK (NOT (completed_at IS NOT NULL AND failed_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_replication_capability_target
    ON storage_replication_capabilities
        (target_server_id, target_placement_id, target_placement_attempt);
CREATE INDEX IF NOT EXISTS idx_replication_capability_source
    ON storage_replication_capabilities (source_server_id, object_id);
CREATE INDEX IF NOT EXISTS idx_replication_capability_expiry
    ON storage_replication_capabilities (expires_at)
    WHERE consumed_at IS NULL AND completed_at IS NULL AND failed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_replication_capability_active_target
    ON storage_replication_capabilities (target_placement_id)
    WHERE completed_at IS NULL AND failed_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_replica_placement_proof_mode'
          AND conrelid = 'replica_placement'::regclass
    ) THEN
        ALTER TABLE replica_placement
            ADD CONSTRAINT ck_replica_placement_proof_mode
            CHECK (
                proof_mode IS NULL
                OR proof_mode IN (
                    'direct_upload',
                    'replication_capability',
                    'legacy_adoption'
                )
            );
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION enforce_storage_object_generation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    is_legacy_adoption BOOLEAN := false;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        is_legacy_adoption := (
            OLD.lifecycle_state = 'committed'
            AND NEW.lifecycle_state = 'committed'
            AND OLD.ciphertext_size_bytes IS NULL
            AND NEW.ciphertext_size_bytes IS NOT NULL
            AND NEW.ciphertext_size_bytes >= 0
            AND NEW.size_bytes >= 0
            AND NEW.projected_size_bytes = NEW.size_bytes
            AND NEW.plaintext_sha256 ~ '^[0-9a-f]{64}$'
            AND OLD.legacy_adopted_at IS NULL
            AND OLD.legacy_adoption_placement_id IS NULL
            AND OLD.legacy_adoption_server_id IS NULL
            AND OLD.legacy_adoption_cert_pubkey_hash IS NULL
            AND OLD.legacy_adoption_storage_incarnation IS NULL
            AND NEW.legacy_adopted_at IS NOT NULL
            AND NEW.legacy_adoption_placement_id IS NOT NULL
            AND NEW.legacy_adoption_server_id IS NOT NULL
            AND NEW.legacy_adoption_cert_pubkey_hash IS NOT NULL
            AND NEW.legacy_adoption_storage_incarnation IS NOT NULL
            AND EXISTS (
                SELECT 1
                FROM replica_placement AS placement
                JOIN servers AS server_row
                  ON server_row.server_id = placement.server_id
                WHERE placement.placement_id = NEW.legacy_adoption_placement_id
                  AND placement.object_id = NEW.object_id
                  AND placement.server_id = NEW.legacy_adoption_server_id
                  AND placement.status = 'pending'
                  AND placement.proof_mode = 'legacy_adoption'
                  AND placement.proof_capability_id IS NULL
                  AND placement.proof_sha256 = lower(NEW.sha256)
                  AND placement.proof_size_bytes = NEW.ciphertext_size_bytes
                  AND placement.proof_at = NEW.legacy_adopted_at
                  AND placement.legacy_adoption_started_at =
                      NEW.legacy_adopted_at
                  AND placement.storage_incarnation =
                      NEW.legacy_adoption_storage_incarnation
                  AND lower(placement.target_cert_pubkey_hash) =
                      lower(NEW.legacy_adoption_cert_pubkey_hash)
                  AND server_row.storage_incarnation =
                      NEW.legacy_adoption_storage_incarnation
                  AND lower(server_row.attested_cert_pubkey_hash) =
                      lower(NEW.legacy_adoption_cert_pubkey_hash)
            )
        );
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle_state <> 'pending' THEN
            RAISE EXCEPTION 'new storage object generations must start pending'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF OLD.object_id IS DISTINCT FROM NEW.object_id
           OR OLD.volume_id IS DISTINCT FROM NEW.volume_id
           OR OLD.object_key IS DISTINCT FROM NEW.object_key
           OR OLD.salt IS DISTINCT FROM NEW.salt
           OR (
               OLD.expected_predecessor_id IS DISTINCT FROM NEW.expected_predecessor_id
               AND NOT (
                   OLD.expected_predecessor_id IS NOT NULL
                   AND NEW.expected_predecessor_id IS NULL
                   AND current_setting(
                       'chutefs.validated_predecessor_detachment',
                       true
                   ) = NEW.object_id
               )
           )
           OR (
               OLD.projected_size_bytes IS DISTINCT FROM NEW.projected_size_bytes
               AND NOT is_legacy_adoption
           ) THEN
            RAISE EXCEPTION 'storage object generation identity is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.expected_predecessor_id IS DISTINCT FROM NEW.expected_predecessor_id THEN
            PERFORM set_config(
                'chutefs.validated_predecessor_detachment',
                '',
                true
            );
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
               (
                   OLD.size_bytes IS DISTINCT FROM NEW.size_bytes
                   AND NOT is_legacy_adoption
               )
               OR OLD.sha256 IS DISTINCT FROM NEW.sha256
               OR (
                   OLD.plaintext_sha256 IS DISTINCT FROM NEW.plaintext_sha256
                   AND NOT is_legacy_adoption
               )
               OR OLD.committed_at IS DISTINCT FROM NEW.committed_at
               OR (
                   (
                       OLD.ciphertext_size_bytes IS DISTINCT FROM
                           NEW.ciphertext_size_bytes
                       OR OLD.legacy_adopted_at IS DISTINCT FROM NEW.legacy_adopted_at
                       OR OLD.legacy_adoption_placement_id IS DISTINCT FROM
                           NEW.legacy_adoption_placement_id
                       OR OLD.legacy_adoption_server_id IS DISTINCT FROM
                           NEW.legacy_adoption_server_id
                       OR OLD.legacy_adoption_cert_pubkey_hash IS DISTINCT FROM
                           NEW.legacy_adoption_cert_pubkey_hash
                       OR OLD.legacy_adoption_storage_incarnation IS DISTINCT FROM
                           NEW.legacy_adoption_storage_incarnation
                   )
                   AND NOT is_legacy_adoption
               )
           ) THEN
            RAISE EXCEPTION 'committed storage object generation metadata is immutable'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.legacy_adopted_at IS NULL THEN
        IF NEW.legacy_adoption_placement_id IS NOT NULL
           OR NEW.legacy_adoption_server_id IS NOT NULL
           OR NEW.legacy_adoption_cert_pubkey_hash IS NOT NULL
           OR NEW.legacy_adoption_storage_incarnation IS NOT NULL THEN
            RAISE EXCEPTION 'legacy adoption audit metadata must be set atomically'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.legacy_adoption_placement_id IS NULL
       OR NEW.legacy_adoption_server_id IS NULL
       OR NEW.legacy_adoption_cert_pubkey_hash IS NULL
       OR NEW.legacy_adoption_cert_pubkey_hash !~ '^[0-9a-f]{64}$'
       OR NEW.legacy_adoption_storage_incarnation IS NULL
       OR NEW.ciphertext_size_bytes IS NULL
       OR NEW.lifecycle_state = 'pending' THEN
        RAISE EXCEPTION 'legacy adoption audit metadata is incomplete'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.lifecycle_state = 'pending' THEN
        IF NEW.salt IS NULL
           OR NEW.sha256 IS NOT NULL
           OR NEW.committed_at IS NOT NULL
           OR NEW.legacy_adopted_at IS NOT NULL THEN
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
        -- Existing committed rows predate exact ciphertext-size receipts. Only the constrained
        -- committed NULL -> exact-size legacy adoption above may populate them after upgrade.
        -- Every new pending -> committed transition requires an exact size directly.
        IF (TG_OP = 'INSERT' OR OLD.lifecycle_state <> 'committed')
           AND (NEW.ciphertext_size_bytes IS NULL OR NEW.ciphertext_size_bytes < 0) THEN
            RAISE EXCEPTION 'new committed generation requires exact ciphertext size'
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

CREATE OR REPLACE FUNCTION enforce_replica_placement_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_sha256 VARCHAR;
    expected_size BIGINT;
    object_lifecycle VARCHAR;
    object_committed_at TIMESTAMPTZ;
    legacy_adopted_at TIMESTAMPTZ;
    legacy_adoption_placement_id VARCHAR;
    legacy_adoption_server_id VARCHAR;
    legacy_adoption_cert_hash VARCHAR;
    legacy_adoption_incarnation VARCHAR;
    current_incarnation VARCHAR;
    current_cert_hash VARCHAR;
    capability_valid BOOLEAN := false;
BEGIN
    SELECT
        lower(sha256),
        ciphertext_size_bytes,
        lifecycle_state,
        committed_at,
        storage_objects.legacy_adopted_at,
        storage_objects.legacy_adoption_placement_id,
        storage_objects.legacy_adoption_server_id,
        storage_objects.legacy_adoption_cert_pubkey_hash,
        storage_objects.legacy_adoption_storage_incarnation
    INTO
        expected_sha256,
        expected_size,
        object_lifecycle,
        object_committed_at,
        legacy_adopted_at,
        legacy_adoption_placement_id,
        legacy_adoption_server_id,
        legacy_adoption_cert_hash,
        legacy_adoption_incarnation
    FROM storage_objects
    WHERE object_id = NEW.object_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'replica placement object does not exist'
            USING ERRCODE = '23503';
    END IF;

    SELECT storage_incarnation, lower(attested_cert_pubkey_hash)
    INTO current_incarnation, current_cert_hash
    FROM servers
    WHERE server_id = NEW.server_id;

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

    IF TG_OP = 'UPDATE'
       AND OLD.status IN ('pending', 'present')
       AND (
           OLD.storage_incarnation IS DISTINCT FROM NEW.storage_incarnation
           OR OLD.target_cert_pubkey_hash IS DISTINCT FROM NEW.target_cert_pubkey_hash
       ) THEN
        RAISE EXCEPTION 'active replica placement identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' AND NEW.legacy_adoption_started_at IS NOT NULL THEN
        RAISE EXCEPTION 'new placement cannot start a legacy adoption'
            USING ERRCODE = '23514';
    ELSIF TG_OP = 'UPDATE'
       AND OLD.legacy_adoption_started_at IS DISTINCT FROM
           NEW.legacy_adoption_started_at
       AND NOT (OLD.status = 'evicted' AND NEW.status = 'pending') THEN
        RAISE EXCEPTION 'legacy adoption marker may change only on evicted to pending'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.status IN ('pending', 'present')
       AND OLD.proof_at IS NOT NULL
       AND (
           OLD.proof_sha256 IS DISTINCT FROM NEW.proof_sha256
           OR OLD.proof_size_bytes IS DISTINCT FROM NEW.proof_size_bytes
           OR OLD.proof_capability_id IS DISTINCT FROM NEW.proof_capability_id
           OR OLD.proof_mode IS DISTINCT FROM NEW.proof_mode
           OR OLD.proof_at IS DISTINCT FROM NEW.proof_at
       ) THEN
        RAISE EXCEPTION 'recorded replica possession evidence is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.status = 'present'
       AND OLD.confirmed_at IS DISTINCT FROM NEW.confirmed_at THEN
        RAISE EXCEPTION 'present replica confirmation is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.proof_mode IS NULL THEN
        IF NEW.proof_sha256 IS NOT NULL
           OR NEW.proof_size_bytes IS NOT NULL
           OR NEW.proof_capability_id IS NOT NULL
           OR NEW.proof_at IS NOT NULL THEN
            RAISE EXCEPTION 'replica possession evidence requires an explicit proof mode'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.proof_sha256 IS NULL
       OR NEW.proof_size_bytes IS NULL
       OR NEW.proof_size_bytes < 0
       OR NEW.proof_at IS NULL THEN
        RAISE EXCEPTION 'replica proof mode requires exact possession evidence'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.proof_mode = 'replication_capability'
       AND NEW.status <> 'evicted' THEN
        IF NEW.proof_capability_id IS NULL THEN
            RAISE EXCEPTION 'replication capability proof requires its capability id'
                USING ERRCODE = '23514';
        END IF;
        SELECT EXISTS (
            SELECT 1
            FROM storage_replication_capabilities AS capability
            WHERE capability.capability_id = NEW.proof_capability_id
              AND capability.object_id = NEW.object_id
              AND capability.volume_id = (
                  SELECT object_row.volume_id
                  FROM storage_objects AS object_row
                  WHERE object_row.object_id = NEW.object_id
              )
              AND capability.target_placement_id = NEW.placement_id
              AND capability.target_placement_attempt = NEW.attempt_count
              AND capability.target_server_id = NEW.server_id
              AND capability.target_cert_pubkey_hash =
                  lower(NEW.target_cert_pubkey_hash)
              AND capability.target_storage_incarnation = NEW.storage_incarnation
              AND capability.expected_ciphertext_sha256 = NEW.proof_sha256
              AND capability.expected_ciphertext_size_bytes = NEW.proof_size_bytes
              AND capability.consumed_at IS NOT NULL
              AND capability.completed_at IS NOT NULL
              AND capability.failed_at IS NULL
        ) INTO capability_valid;
        IF NOT capability_valid THEN
            RAISE EXCEPTION 'replica possession capability is absent, stale, or incomplete'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.proof_mode <> 'replication_capability'
       AND NEW.proof_capability_id IS NOT NULL THEN
        RAISE EXCEPTION 'only capability proof mode may carry a capability id'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.proof_mode IN ('direct_upload', 'replication_capability')
       AND NEW.legacy_adoption_started_at IS NOT NULL THEN
        RAISE EXCEPTION 'normal possession proof cannot carry a legacy adoption marker'
            USING ERRCODE = '23514';
    ELSIF NEW.proof_mode = 'legacy_adoption'
       AND (
           NEW.legacy_adoption_started_at IS NULL
           OR NEW.legacy_adoption_started_at <> NEW.proof_at
       ) THEN
        RAISE EXCEPTION 'legacy adoption proof requires its evicted to pending marker'
            USING ERRCODE = '23514';
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
        IF NEW.legacy_adoption_started_at IS NOT NULL
           AND NEW.pending_since <> NEW.legacy_adoption_started_at THEN
            RAISE EXCEPTION 'legacy adoption marker must bind the pending lease'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'INSERT' OR OLD.status = 'evicted' THEN
            IF NEW.confirmed_at IS NOT NULL
               OR NEW.proof_sha256 IS NOT NULL
               OR NEW.proof_size_bytes IS NOT NULL
               OR NEW.proof_at IS NOT NULL
               OR NEW.proof_capability_id IS NOT NULL
               OR NEW.proof_mode IS NOT NULL THEN
                RAISE EXCEPTION 'new/retried pending placement cannot retain a possession receipt'
                    USING ERRCODE = '23514';
            END IF;
        END IF;

        IF NEW.proof_at IS NOT NULL
           AND NEW.proof_at > NEW.pending_deadline THEN
            RAISE EXCEPTION 'replica possession receipt arrived outside its placement lease'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.proof_mode = 'direct_upload'
           AND object_lifecycle <> 'pending' THEN
            RAISE EXCEPTION 'direct upload proof is valid only before generation commit'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.proof_mode = 'legacy_adoption'
           AND (
               object_lifecycle <> 'committed'
               OR expected_sha256 IS NULL
               OR expected_sha256 <> NEW.proof_sha256
               OR expected_size IS NOT NULL
               OR legacy_adopted_at IS NOT NULL
               OR legacy_adoption_placement_id IS NOT NULL
               OR current_incarnation IS NULL
               OR current_incarnation <> NEW.storage_incarnation
               OR current_cert_hash IS NULL
               OR current_cert_hash <> lower(NEW.target_cert_pubkey_hash)
           ) THEN
            RAISE EXCEPTION 'legacy adoption proof is not eligible for this committed object'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.status = 'present' THEN
        IF NEW.confirmed_at IS NULL
           OR NEW.proof_at IS NULL
           OR NEW.proof_sha256 IS NULL
           OR NEW.proof_size_bytes IS NULL
           OR NEW.proof_size_bytes < 0
           OR NEW.proof_mode IS NULL THEN
            RAISE EXCEPTION 'present replica placement requires exact possession evidence'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.proof_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'present replica placement has an invalid ciphertext hash'
                USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'UPDATE'
           AND OLD.status = 'pending'
           AND (
               NEW.pending_deadline IS NULL
               OR NEW.proof_at IS NULL
               OR NEW.proof_at > NEW.pending_deadline
           ) THEN
            RAISE EXCEPTION 'replica possession receipt arrived outside its placement lease'
                USING ERRCODE = '23514';
        END IF;

        IF object_lifecycle <> 'committed' THEN
            RAISE EXCEPTION 'possession cannot become present before its generation commits'
                USING ERRCODE = '23514';
        END IF;
        IF expected_sha256 IS NULL OR expected_sha256 <> NEW.proof_sha256 THEN
            RAISE EXCEPTION 'possession receipt does not match the committed ciphertext hash'
                USING ERRCODE = '23514';
        END IF;
        IF expected_size IS NULL OR expected_size <> NEW.proof_size_bytes THEN
            RAISE EXCEPTION 'possession receipt does not match the committed ciphertext size'
                USING ERRCODE = '23514';
        END IF;

        IF current_incarnation IS NULL
           OR current_incarnation <> NEW.storage_incarnation
           OR current_cert_hash IS NULL
           OR current_cert_hash <> lower(NEW.target_cert_pubkey_hash) THEN
            RAISE EXCEPTION 'possession receipt is not bound to the current storage identity'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.proof_mode = 'direct_upload'
           AND (
               NEW.proof_capability_id IS NOT NULL
               OR object_committed_at IS NULL
               OR NEW.proof_at > object_committed_at
               OR legacy_adopted_at IS NOT NULL
           ) THEN
            RAISE EXCEPTION 'direct upload proof was not recorded before generation commit'
                USING ERRCODE = '23514';
        ELSIF NEW.proof_mode = 'legacy_adoption'
           AND (
               NEW.proof_capability_id IS NOT NULL
               OR legacy_adopted_at IS NULL
               OR legacy_adoption_placement_id <> NEW.placement_id
               OR legacy_adoption_server_id <> NEW.server_id
               OR lower(legacy_adoption_cert_hash) <>
                   lower(NEW.target_cert_pubkey_hash)
               OR legacy_adoption_incarnation <> NEW.storage_incarnation
               OR legacy_adopted_at <> NEW.proof_at
               OR legacy_adopted_at <> NEW.legacy_adoption_started_at
           ) THEN
            RAISE EXCEPTION 'legacy adoption proof does not match immutable object audit'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END
$$;

-- migrate:down

DROP TABLE IF EXISTS storage_replication_capabilities;

DROP TRIGGER IF EXISTS trg_replica_placement_transition ON replica_placement;
DROP TRIGGER IF EXISTS trg_storage_object_generation ON storage_objects;

ALTER TABLE replica_placement
    DROP CONSTRAINT IF EXISTS ck_replica_placement_proof_mode;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS legacy_adoption_started_at;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_mode;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_capability_id;
ALTER TABLE replica_placement DROP COLUMN IF EXISTS proof_size_bytes;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_storage_incarnation;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_cert_pubkey_hash;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_server_id;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adoption_placement_id;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS legacy_adopted_at;
ALTER TABLE storage_objects DROP COLUMN IF EXISTS ciphertext_size_bytes;

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

CREATE TRIGGER trg_storage_object_generation
BEFORE INSERT OR UPDATE ON storage_objects
FOR EACH ROW EXECUTE FUNCTION enforce_storage_object_generation();

CREATE TRIGGER trg_replica_placement_transition
BEFORE INSERT OR UPDATE ON replica_placement
FOR EACH ROW EXECUTE FUNCTION enforce_replica_placement_transition();
