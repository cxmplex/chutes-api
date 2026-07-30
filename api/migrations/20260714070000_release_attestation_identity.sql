-- migrate:up

-- A measurement version is not a unique image identity: provider, TEE, role and vCPU classes can
-- share version strings. Persist the exact matched pin name so release completion can be authorized
-- only by fresh attestations for the release's signed provenance.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS measurement_name TEXT;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS measurement_name VARCHAR;

-- Runtime attestations are immutable audit records. Their attribution must survive deletion of the
-- operational Server row, while a first reservation-authenticated Model-B failure must be recordable
-- before any Server exists. Preserve a separate immutable subject identity instead of weakening the
-- audit foreign key or creating an operational Server stub.
CREATE TABLE IF NOT EXISTS server_attestation_subjects (
    server_id VARCHAR PRIMARY KEY,
    owner_hotkey VARCHAR NOT NULL,
    compute_type VARCHAR NOT NULL,
    tee_type VARCHAR NOT NULL,
    deployment_model VARCHAR NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_server_attestation_subject_owner
        UNIQUE (server_id, owner_hotkey),
    CONSTRAINT ck_server_attestation_subject_compute_type
        CHECK (compute_type IN ('cpu', 'gpu')),
    CONSTRAINT ck_server_attestation_subject_tee_type
        CHECK (tee_type IN ('tdx', 'sev-snp')),
    CONSTRAINT ck_server_attestation_subject_deployment_model
        CHECK (deployment_model IN ('cpu-model-a', 'cpu-model-b', 'gpu'))
);

-- Compare PostgreSQL's canonical definitions, rather than trusting constraint names or the
-- column numbers alone. The temporary table makes the comparison independent of harmless
-- formatting differences between supported PostgreSQL versions.
CREATE TEMPORARY TABLE expected_server_attestation_subjects_shape (
    server_id VARCHAR,
    owner_hotkey VARCHAR NOT NULL,
    compute_type VARCHAR NOT NULL,
    tee_type VARCHAR NOT NULL,
    deployment_model VARCHAR NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT server_attestation_subjects_pkey PRIMARY KEY (server_id),
    CONSTRAINT uq_server_attestation_subject_owner
        UNIQUE (server_id, owner_hotkey),
    CONSTRAINT ck_server_attestation_subject_compute_type
        CHECK (compute_type IN ('cpu', 'gpu')),
    CONSTRAINT ck_server_attestation_subject_tee_type
        CHECK (tee_type IN ('tdx', 'sev-snp')),
    CONSTRAINT ck_server_attestation_subject_deployment_model
        CHECK (deployment_model IN ('cpu-model-a', 'cpu-model-b', 'gpu'))
);

-- create_all installs the final table before dbmate, while production reaches this migration
-- without it. Accept either exact catalog and reject a partial or same-name/wrong-shape table.
DO $$
DECLARE
    actual_columns TEXT[];
    actual_constraints TEXT[];
BEGIN
    SELECT array_agg(attribute.attname::TEXT ORDER BY attribute.attnum)
      INTO actual_columns
      FROM pg_attribute AS attribute
     WHERE attribute.attrelid = 'server_attestation_subjects'::regclass
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped;
    IF actual_columns IS DISTINCT FROM ARRAY[
        'server_id',
        'owner_hotkey',
        'compute_type',
        'tee_type',
        'deployment_model',
        'first_seen_at'
    ]::TEXT[] THEN
        RAISE EXCEPTION
            'server_attestation_subjects has invalid columns: %',
            actual_columns;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('server_id', 'character varying', TRUE, NULL::TEXT),
                ('owner_hotkey', 'character varying', TRUE, NULL::TEXT),
                ('compute_type', 'character varying', TRUE, NULL::TEXT),
                ('tee_type', 'character varying', TRUE, NULL::TEXT),
                ('deployment_model', 'character varying', TRUE, NULL::TEXT),
                ('first_seen_at', 'timestamp with time zone', TRUE, 'now()'::TEXT)
          ) AS expected(column_name, data_type, is_not_null, default_expression)
          LEFT JOIN pg_attribute AS attribute
            ON attribute.attrelid = 'server_attestation_subjects'::regclass
           AND attribute.attname = expected.column_name
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = attribute.attrelid
           AND attribute_default.adnum = attribute.attnum
         WHERE attribute.attname IS NULL
            OR format_type(attribute.atttypid, attribute.atttypmod)
                IS DISTINCT FROM expected.data_type
            OR attribute.attnotnull IS DISTINCT FROM expected.is_not_null
            OR CASE
                WHEN expected.default_expression IS NULL
                    THEN attribute_default.oid IS NOT NULL
                ELSE pg_get_expr(attribute_default.adbin, attribute_default.adrelid)
                    IS DISTINCT FROM expected.default_expression
               END
    ) THEN
        RAISE EXCEPTION 'server_attestation_subjects has invalid column definitions';
    END IF;

    SELECT array_agg(constraint_row.conname::TEXT ORDER BY constraint_row.conname)
      INTO actual_constraints
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestation_subjects'::regclass;
    IF actual_constraints IS DISTINCT FROM ARRAY[
        'ck_server_attestation_subject_compute_type',
        'ck_server_attestation_subject_deployment_model',
        'ck_server_attestation_subject_tee_type',
        'server_attestation_subjects_pkey',
        'uq_server_attestation_subject_owner'
    ]::TEXT[] THEN
        RAISE EXCEPTION
            'server_attestation_subjects has invalid constraints: %',
            actual_constraints;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestation_subjects'::regclass
           AND constraint_row.conname = 'server_attestation_subjects_pkey'
           AND constraint_row.contype = 'p'
           AND NOT constraint_row.condeferrable
           AND NOT constraint_row.condeferred
           AND constraint_row.convalidated
           AND constraint_row.conkey = ARRAY[(
                SELECT attnum
                  FROM pg_attribute
                 WHERE attrelid = 'server_attestation_subjects'::regclass
                   AND attname = 'server_id'
           )]::SMALLINT[]
    ) OR NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestation_subjects'::regclass
           AND constraint_row.conname = 'uq_server_attestation_subject_owner'
           AND constraint_row.contype = 'u'
           AND NOT constraint_row.condeferrable
           AND NOT constraint_row.condeferred
           AND constraint_row.convalidated
           AND constraint_row.conkey = ARRAY[
                (
                    SELECT attnum
                      FROM pg_attribute
                     WHERE attrelid = 'server_attestation_subjects'::regclass
                       AND attname = 'server_id'
                ),
                (
                    SELECT attnum
                      FROM pg_attribute
                     WHERE attrelid = 'server_attestation_subjects'::regclass
                       AND attname = 'owner_hotkey'
                )
           ]::SMALLINT[]
    ) OR EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestation_subjects'::regclass
           AND constraint_row.contype = 'c'
           AND (
                NOT constraint_row.convalidated
                OR constraint_row.condeferrable
                OR constraint_row.condeferred
                OR constraint_row.conkey IS NULL
                OR cardinality(constraint_row.conkey) <> 1
           )
    ) THEN
        RAISE EXCEPTION 'server_attestation_subjects has invalid constraint shapes';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_constraint AS actual
          JOIN pg_constraint AS expected
            ON expected.conrelid =
                'expected_server_attestation_subjects_shape'::regclass
           AND expected.conname = actual.conname
         WHERE actual.conrelid = 'server_attestation_subjects'::regclass
           AND lower(
                regexp_replace(
                    pg_get_constraintdef(actual.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           ) IS DISTINCT FROM lower(
                regexp_replace(
                    pg_get_constraintdef(expected.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           )
    ) THEN
        RAISE EXCEPTION
            'server_attestation_subjects has non-canonical constraint definitions';
    END IF;
END
$$;
DROP TABLE expected_server_attestation_subjects_shape;
INSERT INTO server_attestation_subjects (
    server_id,
    owner_hotkey,
    compute_type,
    tee_type,
    deployment_model
)
SELECT
    server_id,
    miner_hotkey,
    compute_type,
    tee_type,
    CASE
        WHEN compute_type = 'gpu' THEN 'gpu'
        WHEN (to_jsonb(servers)->>'launch_reservation_id') IS NOT NULL
            THEN 'cpu-model-b'
        ELSE 'cpu-model-a'
    END
FROM servers
ON CONFLICT (server_id) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM servers AS server_row
          LEFT JOIN server_attestation_subjects AS subject
            ON subject.server_id = server_row.server_id
         WHERE subject.server_id IS NULL
            OR subject.owner_hotkey IS DISTINCT FROM server_row.miner_hotkey
            OR subject.compute_type IS DISTINCT FROM server_row.compute_type
            OR subject.tee_type IS DISTINCT FROM server_row.tee_type
            OR subject.deployment_model IS DISTINCT FROM CASE
                WHEN server_row.compute_type = 'gpu' THEN 'gpu'
                WHEN (to_jsonb(server_row)->>'launch_reservation_id') IS NOT NULL
                    THEN 'cpu-model-b'
                ELSE 'cpu-model-a'
            END
    ) THEN
        RAISE EXCEPTION
            'existing server conflicts with immutable server attestation subject';
    END IF;
END
$$;

-- Production has one CASCADE FK to servers; create_all already has one RESTRICT FK to the
-- immutable subject table. Transition only the exact legacy shape, accept only the exact final
-- shape, and reject missing, duplicated, or hybrid authority.
DO $$
DECLARE
    server_id_fks TEXT[];
    current_fk pg_constraint%ROWTYPE;
BEGIN
    -- Count every one-column FK sourced from server_id before inspecting its target. A wrong
    -- target, wrong referenced column, or extra hybrid FK must not disappear from discovery.
    SELECT array_agg(constraint_row.conname::TEXT ORDER BY constraint_row.conname)
      INTO server_id_fks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.contype = 'f'
       AND constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.conkey = ARRAY[(
            SELECT attnum
              FROM pg_attribute
             WHERE attrelid = 'server_attestations'::regclass
               AND attname = 'server_id'
       )]::SMALLINT[];

    IF COALESCE(cardinality(server_id_fks), 0) <> 1 THEN
        RAISE EXCEPTION
            'expected exact legacy or final server attestation FK shape; found % server_id FKs',
            COALESCE(cardinality(server_id_fks), 0);
    END IF;

    SELECT *
      INTO STRICT current_fk
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.conname = server_id_fks[1];

    IF current_fk.confrelid = 'servers'::regclass THEN
        IF current_fk.confkey IS DISTINCT FROM ARRAY[(
                SELECT attnum
                  FROM pg_attribute
                 WHERE attrelid = 'servers'::regclass
                   AND attname = 'server_id'
           )]::SMALLINT[]
           OR current_fk.confdeltype <> 'c'
           OR current_fk.confupdtype <> 'a'
           OR current_fk.confmatchtype <> 's'
           OR current_fk.condeferrable
           OR current_fk.condeferred
           OR NOT current_fk.convalidated THEN
            RAISE EXCEPTION
                'legacy server_attestations(server_id) FK has invalid shape: %',
                current_fk.conname;
        END IF;
        EXECUTE format(
            'ALTER TABLE server_attestations DROP CONSTRAINT %I',
            current_fk.conname
        );
        EXECUTE
            'ALTER TABLE server_attestations '
            'ADD CONSTRAINT fk_server_attestations_subject '
            'FOREIGN KEY (server_id) '
            'REFERENCES server_attestation_subjects(server_id) ON DELETE RESTRICT';
    ELSIF current_fk.confrelid <> 'server_attestation_subjects'::regclass THEN
        RAISE EXCEPTION
            'server_attestations(server_id) FK has unexpected target: %',
            current_fk.confrelid::regclass;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname = 'fk_server_attestations_subject'
           AND constraint_row.contype = 'f'
           AND constraint_row.confrelid = 'server_attestation_subjects'::regclass
           AND constraint_row.confdeltype = 'r'
           AND constraint_row.confupdtype = 'a'
           AND constraint_row.confmatchtype = 's'
           AND NOT constraint_row.condeferrable
           AND NOT constraint_row.condeferred
           AND constraint_row.convalidated
           AND constraint_row.conkey = ARRAY[(
                SELECT attnum
                  FROM pg_attribute
                 WHERE attrelid = 'server_attestations'::regclass
                   AND attname = 'server_id'
           )]::SMALLINT[]
           AND constraint_row.confkey = ARRAY[(
                SELECT attnum
                  FROM pg_attribute
                 WHERE attrelid = 'server_attestation_subjects'::regclass
                   AND attname = 'server_id'
           )]::SMALLINT[]
           AND lower(
                regexp_replace(
                    pg_get_constraintdef(constraint_row.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           ) = 'foreignkey(server_id)referencesserver_attestation_subjects(server_id)ondeleterestrict'
    ) THEN
        RAISE EXCEPTION 'final server attestation subject FK has invalid shape';
    END IF;
END
$$;

-- created_at can collide and UUID order is unrelated to attempt order. Backfill the deployed
-- history deterministically, then allocate every new attempt from one database sequence. The
-- sequence is assigned when the result row is inserted, so reverse transaction commit order cannot
-- make an older attempt sort after a newer one.
DO $$
DECLARE
    has_column BOOLEAN;
    sequence_oid OID := to_regclass('server_attestation_attempt_sequence');
    index_oid OID := to_regclass('idx_server_attestations_attempt_sequence');
    attempt_attnum SMALLINT;
    ownership_count INTEGER;
    sequence_last_value BIGINT;
    sequence_is_called BOOLEAN;
    maximum_attempt BIGINT;
BEGIN
    SELECT EXISTS (
        SELECT 1
          FROM pg_attribute
         WHERE attrelid = 'server_attestations'::regclass
           AND attname = 'attempt_sequence'
           AND attnum > 0
           AND NOT attisdropped
    ) INTO has_column;

    IF NOT has_column AND sequence_oid IS NULL AND index_oid IS NULL THEN
        EXECUTE 'CREATE SEQUENCE server_attestation_attempt_sequence';
        EXECUTE
            'ALTER TABLE server_attestations '
            'ADD COLUMN attempt_sequence BIGINT';
        WITH ranked AS (
            SELECT
                attestation_id,
                ROW_NUMBER() OVER (
                    -- Exact inverse of the deployed latest-attempt ordering.
                    ORDER BY created_at ASC NULLS LAST, attestation_id ASC
                ) AS attempt_sequence
            FROM server_attestations
        )
        UPDATE server_attestations AS attestation
           SET attempt_sequence = ranked.attempt_sequence
          FROM ranked
         WHERE attestation.attestation_id = ranked.attestation_id;
        EXECUTE
            'ALTER TABLE server_attestations '
            'ALTER COLUMN attempt_sequence '
            'SET DEFAULT nextval(''server_attestation_attempt_sequence''::regclass)';
        EXECUTE
            'ALTER SEQUENCE server_attestation_attempt_sequence '
            'OWNED BY server_attestations.attempt_sequence';
        PERFORM setval(
            'server_attestation_attempt_sequence'::regclass,
            COALESCE((SELECT MAX(attempt_sequence) FROM server_attestations), 1),
            EXISTS (SELECT 1 FROM server_attestations)
        );
        EXECUTE
            'ALTER TABLE server_attestations '
            'ALTER COLUMN attempt_sequence SET NOT NULL';
        EXECUTE
            'CREATE UNIQUE INDEX idx_server_attestations_attempt_sequence '
            'ON server_attestations (attempt_sequence)';
        sequence_oid := to_regclass('server_attestation_attempt_sequence');
        index_oid := to_regclass('idx_server_attestations_attempt_sequence');
        has_column := TRUE;
    ELSIF NOT has_column OR sequence_oid IS NULL OR index_oid IS NULL THEN
        RAISE EXCEPTION
            'partial server attestation attempt sequence catalog is not recoverable in place';
    END IF;

    SELECT attnum
      INTO STRICT attempt_attnum
      FROM pg_attribute
     WHERE attrelid = 'server_attestations'::regclass
       AND attname = 'attempt_sequence'
       AND attnum > 0
       AND NOT attisdropped;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_attribute AS attribute
          JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = attribute.attrelid
           AND attribute_default.adnum = attribute.attnum
         WHERE attribute.attrelid = 'server_attestations'::regclass
           AND attribute.attnum = attempt_attnum
           AND format_type(attribute.atttypid, attribute.atttypmod) = 'bigint'
           AND attribute.attnotnull
           AND pg_get_expr(attribute_default.adbin, attribute_default.adrelid) =
               'nextval(''server_attestation_attempt_sequence''::regclass)'
    ) THEN
        RAISE EXCEPTION 'attempt_sequence has invalid type, nullability, or default';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_class AS sequence_relation
          JOIN pg_sequence AS sequence_definition
            ON sequence_definition.seqrelid = sequence_relation.oid
         WHERE sequence_relation.oid = sequence_oid
           AND sequence_relation.relkind = 'S'
           AND sequence_definition.seqtypid = 'bigint'::regtype
           AND sequence_definition.seqstart = 1
           AND sequence_definition.seqincrement = 1
           AND sequence_definition.seqmin = 1
           AND sequence_definition.seqmax = 9223372036854775807
           AND sequence_definition.seqcache = 1
           AND NOT sequence_definition.seqcycle
    ) THEN
        RAISE EXCEPTION 'server_attestation_attempt_sequence has invalid identity';
    END IF;

    SELECT COUNT(*)
      INTO ownership_count
      FROM pg_depend AS dependency
     WHERE dependency.classid = 'pg_class'::regclass
       AND dependency.objid = sequence_oid
       AND dependency.objsubid = 0
       AND dependency.refclassid = 'pg_class'::regclass
       AND dependency.deptype IN ('a', 'i');
    IF ownership_count = 0 THEN
        -- SQLAlchemy create_all creates the explicit Sequence and default but does not attach
        -- OWNED BY. This is the only safe final-shape completion performed in this branch.
        EXECUTE
            'ALTER SEQUENCE server_attestation_attempt_sequence '
            'OWNED BY server_attestations.attempt_sequence';
    END IF;
    SELECT COUNT(*)
      INTO ownership_count
      FROM pg_depend AS dependency
     WHERE dependency.classid = 'pg_class'::regclass
       AND dependency.objid = sequence_oid
       AND dependency.objsubid = 0
       AND dependency.refclassid = 'pg_class'::regclass
       AND dependency.deptype IN ('a', 'i');
    IF ownership_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_depend AS dependency
         WHERE dependency.classid = 'pg_class'::regclass
           AND dependency.objid = sequence_oid
           AND dependency.objsubid = 0
           AND dependency.refclassid = 'pg_class'::regclass
           AND dependency.refobjid = 'server_attestations'::regclass
           AND dependency.refobjsubid = attempt_attnum
           AND dependency.deptype IN ('a', 'i')
    ) THEN
        RAISE EXCEPTION 'server_attestation_attempt_sequence has invalid ownership';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_index AS index_definition
          JOIN pg_class AS index_relation
            ON index_relation.oid = index_definition.indexrelid
          JOIN pg_am AS access_method
            ON access_method.oid = index_relation.relam
         WHERE index_definition.indexrelid = index_oid
           AND index_definition.indrelid = 'server_attestations'::regclass
           AND index_relation.relkind = 'i'
           AND access_method.amname = 'btree'
           AND index_definition.indisunique
           AND NOT index_definition.indisprimary
           AND NOT index_definition.indisexclusion
           AND index_definition.indimmediate
           AND index_definition.indisvalid
           AND index_definition.indisready
           AND index_definition.indislive
           AND index_definition.indnkeyatts = 1
           AND index_definition.indnatts = 1
           AND index_definition.indkey::TEXT = attempt_attnum::TEXT
           AND index_definition.indoption::TEXT = '0'
           AND index_definition.indexprs IS NULL
           AND index_definition.indpred IS NULL
    ) THEN
        RAISE EXCEPTION 'idx_server_attestations_attempt_sequence has invalid definition';
    END IF;

    EXECUTE
        'SELECT last_value, is_called '
        'FROM server_attestation_attempt_sequence'
        INTO sequence_last_value, sequence_is_called;
    SELECT MAX(attempt_sequence)
      INTO maximum_attempt
      FROM server_attestations;
    IF maximum_attempt IS NOT NULL
       AND (NOT sequence_is_called OR sequence_last_value < maximum_attempt) THEN
        RAISE EXCEPTION
            'server_attestation_attempt_sequence is behind persisted attempts';
    END IF;
END
$$;

ALTER TABLE boot_attestations
    ADD COLUMN IF NOT EXISTS measurement_name VARCHAR;

CREATE INDEX IF NOT EXISTS idx_server_attestations_release_identity
    ON server_attestations (server_id, attempt_sequence DESC)
    INCLUDE (measurement_name, measurement_version, verification_error, verified_at);

CREATE OR REPLACE FUNCTION preserve_server_attestation_subject_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'server attestation subjects are immutable';
END
$$;
DO $$
DECLARE
    related_trigger_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestation_subjects'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'preserve_server_attestation_subject_identity'
            OR trigger_row.tgfoid = to_regprocedure(
                'preserve_server_attestation_subject_identity()'
            )
       );
    IF related_trigger_count = 0 THEN
        EXECUTE 'CREATE TRIGGER preserve_server_attestation_subject_identity '
                'BEFORE UPDATE OR DELETE ON server_attestation_subjects '
                'FOR EACH ROW EXECUTE FUNCTION preserve_server_attestation_subject_identity()';
    END IF;
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestation_subjects'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'preserve_server_attestation_subject_identity'
            OR trigger_row.tgfoid = to_regprocedure(
                'preserve_server_attestation_subject_identity()'
            )
       );
    IF related_trigger_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_trigger AS trigger_row
         WHERE trigger_row.tgrelid = 'server_attestation_subjects'::regclass
           AND trigger_row.tgname = 'preserve_server_attestation_subject_identity'
           AND NOT trigger_row.tgisinternal
           AND trigger_row.tgfoid = to_regprocedure(
                'preserve_server_attestation_subject_identity()'
           )
           AND trigger_row.tgtype = 27
           AND trigger_row.tgenabled = 'O'
           AND trigger_row.tgqual IS NULL
    ) THEN
        RAISE EXCEPTION
            'preserve_server_attestation_subject_identity has invalid trigger shape';
    END IF;
END
$$;

-- Old binaries insert attestations only after a Server exists. Copy and validate that exact live
-- identity. A pre-Server row is accepted only when new code has already created the subject from an
-- authenticated reservation and the later composite attribution FKs are populated.
CREATE OR REPLACE FUNCTION enforce_server_attestation_subject()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    subject_row server_attestation_subjects%ROWTYPE;
    live_owner TEXT;
    live_compute_type TEXT;
    live_tee_type TEXT;
    live_deployment_model TEXT;
    attributed_owner TEXT;
    attributed_reservation TEXT;
BEGIN
    SELECT * INTO subject_row
      FROM server_attestation_subjects
     WHERE server_id = NEW.server_id;

    SELECT
        miner_hotkey,
        compute_type,
        tee_type,
        CASE
            WHEN compute_type = 'gpu' THEN 'gpu'
            WHEN (to_jsonb(servers)->>'launch_reservation_id') IS NOT NULL
                THEN 'cpu-model-b'
            ELSE 'cpu-model-a'
        END
      INTO live_owner, live_compute_type, live_tee_type, live_deployment_model
      FROM servers
     WHERE server_id = NEW.server_id;

    IF subject_row.server_id IS NULL THEN
        IF live_owner IS NULL THEN
            RAISE EXCEPTION
                'attestation subject % must be created from authenticated reservation identity',
                NEW.server_id;
        END IF;
        INSERT INTO server_attestation_subjects (
            server_id, owner_hotkey, compute_type, tee_type, deployment_model
        ) VALUES (
            NEW.server_id,
            live_owner,
            live_compute_type,
            live_tee_type,
            live_deployment_model
        )
        ON CONFLICT (server_id) DO NOTHING;
        SELECT * INTO subject_row
          FROM server_attestation_subjects
         WHERE server_id = NEW.server_id
           FOR UPDATE;
    END IF;

    IF live_owner IS NOT NULL THEN
        IF subject_row.owner_hotkey IS DISTINCT FROM live_owner
           OR subject_row.compute_type IS DISTINCT FROM live_compute_type
           OR subject_row.tee_type IS DISTINCT FROM live_tee_type
           OR subject_row.deployment_model IS DISTINCT FROM live_deployment_model THEN
            RAISE EXCEPTION 'server % conflicts with immutable attestation subject', NEW.server_id;
        END IF;
    ELSE
        attributed_owner := to_jsonb(NEW)->>'attribution_owner_hotkey';
        attributed_reservation := to_jsonb(NEW)->>'attribution_reservation_id';
        IF attributed_owner IS NULL
           OR attributed_reservation IS NULL
           OR attributed_owner IS DISTINCT FROM subject_row.owner_hotkey THEN
            RAISE EXCEPTION
                'pre-registration attestation % lacks exact reservation attribution',
                NEW.attestation_id;
        END IF;
    END IF;
    RETURN NEW;
END
$$;
DO $$
DECLARE
    related_trigger_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestations'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'enforce_server_attestation_subject'
            OR trigger_row.tgfoid = to_regprocedure('enforce_server_attestation_subject()')
       );
    IF related_trigger_count = 0 THEN
        EXECUTE 'CREATE TRIGGER enforce_server_attestation_subject '
                'BEFORE INSERT ON server_attestations '
                'FOR EACH ROW EXECUTE FUNCTION enforce_server_attestation_subject()';
    END IF;
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestations'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'enforce_server_attestation_subject'
            OR trigger_row.tgfoid = to_regprocedure('enforce_server_attestation_subject()')
       );
    IF related_trigger_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_trigger AS trigger_row
         WHERE trigger_row.tgrelid = 'server_attestations'::regclass
           AND trigger_row.tgname = 'enforce_server_attestation_subject'
           AND NOT trigger_row.tgisinternal
           AND trigger_row.tgfoid = to_regprocedure('enforce_server_attestation_subject()')
           AND trigger_row.tgtype = 7
           AND trigger_row.tgenabled = 'O'
           AND trigger_row.tgqual IS NULL
    ) THEN
        RAISE EXCEPTION 'enforce_server_attestation_subject has invalid trigger shape';
    END IF;
END
$$;

-- A legacy mapper may still issue delete-orphan DELETEs before deleting a Server. Silently keep the
-- audit row so the parent delete remains compatible while history is never erased.
CREATE OR REPLACE FUNCTION preserve_server_attestation_audit()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN NULL;
    END IF;
    IF NEW.attestation_id IS DISTINCT FROM OLD.attestation_id
       OR NEW.server_id IS DISTINCT FROM OLD.server_id
       OR NEW.attempt_sequence IS DISTINCT FROM OLD.attempt_sequence
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (to_jsonb(NEW)->'attribution_reservation_id')
            IS DISTINCT FROM (to_jsonb(OLD)->'attribution_reservation_id')
       OR (to_jsonb(NEW)->'attribution_owner_hotkey')
            IS DISTINCT FROM (to_jsonb(OLD)->'attribution_owner_hotkey') THEN
        RAISE EXCEPTION 'server attestation audit identity is immutable';
    END IF;
    RETURN NEW;
END
$$;
DO $$
DECLARE
    related_trigger_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestations'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'preserve_server_attestation_audit'
            OR trigger_row.tgfoid = to_regprocedure('preserve_server_attestation_audit()')
       );
    IF related_trigger_count = 0 THEN
        EXECUTE 'CREATE TRIGGER preserve_server_attestation_audit '
                'BEFORE UPDATE OR DELETE ON server_attestations '
                'FOR EACH ROW EXECUTE FUNCTION preserve_server_attestation_audit()';
    END IF;
    SELECT COUNT(*) INTO related_trigger_count
      FROM pg_trigger AS trigger_row
     WHERE trigger_row.tgrelid = 'server_attestations'::regclass
       AND NOT trigger_row.tgisinternal
       AND (
            trigger_row.tgname = 'preserve_server_attestation_audit'
            OR trigger_row.tgfoid = to_regprocedure('preserve_server_attestation_audit()')
       );
    IF related_trigger_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_trigger AS trigger_row
         WHERE trigger_row.tgrelid = 'server_attestations'::regclass
           AND trigger_row.tgname = 'preserve_server_attestation_audit'
           AND NOT trigger_row.tgisinternal
           AND trigger_row.tgfoid = to_regprocedure('preserve_server_attestation_audit()')
           AND trigger_row.tgtype = 27
           AND trigger_row.tgenabled = 'O'
           AND trigger_row.tgqual IS NULL
    ) THEN
        RAISE EXCEPTION 'preserve_server_attestation_audit has invalid trigger shape';
    END IF;
END
$$;

-- migrate:down

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM server_attestations AS attestation
          LEFT JOIN servers AS server_row
            ON server_row.server_id = attestation.server_id
         WHERE server_row.server_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot restore legacy attestation FK while pre-registration/deleted-server audits exist';
    END IF;
END
$$;
DROP TRIGGER IF EXISTS preserve_server_attestation_audit ON server_attestations;
DROP FUNCTION IF EXISTS preserve_server_attestation_audit();
DROP TRIGGER IF EXISTS enforce_server_attestation_subject ON server_attestations;
DROP FUNCTION IF EXISTS enforce_server_attestation_subject();
DROP TRIGGER IF EXISTS preserve_server_attestation_subject_identity
    ON server_attestation_subjects;
DROP FUNCTION IF EXISTS preserve_server_attestation_subject_identity();
ALTER TABLE server_attestations
    DROP CONSTRAINT IF EXISTS fk_server_attestations_subject;
ALTER TABLE server_attestations
    ADD CONSTRAINT server_attestations_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE CASCADE;
DROP TABLE server_attestation_subjects;

DROP INDEX IF EXISTS idx_server_attestations_release_identity;
DROP INDEX IF EXISTS idx_server_attestations_attempt_sequence;
ALTER TABLE boot_attestations DROP COLUMN IF EXISTS measurement_name;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS attempt_sequence;
DROP SEQUENCE IF EXISTS server_attestation_attempt_sequence;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS measurement_name;
ALTER TABLE servers DROP COLUMN IF EXISTS measurement_name;
