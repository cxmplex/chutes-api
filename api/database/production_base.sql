-- Immutable production-base catalog completion.
--
-- The 64 historical dbmate versions predate serialized startup and are represented by the
-- production ORM base.  Some of those versions also created raw PostgreSQL objects that ORM
-- create_all cannot represent.  This DDL-only contract runs under the migration advisory lock
-- before those 64 ledger rows are recorded.  It never fabricates historical rows or replays the
-- historical data backfills.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
DO $production_base$
DECLARE
    extension_schema TEXT;
    extension_version TEXT;
    extension_relocatable BOOLEAN;
    owner_is_current BOOLEAN;
    digest_contract_count INTEGER;
BEGIN
    SELECT namespace.nspname,
           extension_control.extversion,
           extension_control.extrelocatable,
           pg_get_userbyid(extension_control.extowner) = current_user
      INTO extension_schema, extension_version, extension_relocatable, owner_is_current
      FROM pg_extension AS extension_control
      JOIN pg_namespace AS namespace ON namespace.oid = extension_control.extnamespace
     WHERE extension_control.extname = 'pgcrypto';
    IF extension_schema IS DISTINCT FROM 'public' THEN
        RAISE EXCEPTION
            'pgcrypto exists in schema %, expected public; refusing database-global relocation',
            extension_schema;
    END IF;
    IF extension_version IS DISTINCT FROM '1.3'
       OR extension_relocatable IS NOT TRUE
       OR owner_is_current IS NOT TRUE THEN
        RAISE EXCEPTION
            'pgcrypto metadata differs from the reviewed contract: version=%, relocatable=%, owner_current=%',
            extension_version, extension_relocatable, owner_is_current;
    END IF;
    SELECT count(*) INTO digest_contract_count
      FROM pg_proc AS procedure
      JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
      JOIN pg_depend AS dependency
        ON dependency.classid = 'pg_proc'::regclass
       AND dependency.objid = procedure.oid
       AND dependency.refclassid = 'pg_extension'::regclass
       AND dependency.deptype = 'e'
      JOIN pg_extension AS extension_control ON extension_control.oid = dependency.refobjid
     WHERE namespace.nspname = 'public'
       AND extension_control.extname = 'pgcrypto'
       AND procedure.proname = 'digest'
       AND oidvectortypes(procedure.proargtypes) IN ('bytea, text', 'text, text');
    IF digest_contract_count <> 2 OR encode(
        public.digest('chutes-production-base-smoke'::TEXT, 'sha256'::TEXT), 'hex'
    ) IS DISTINCT FROM
        'fca24eba804cb4cd921491500548de501b77501cf91e24a9757942c186e48a00'
    THEN
        RAISE EXCEPTION 'pgcrypto digest signature/known-answer contract failed';
    END IF;
END
$production_base$;

CREATE TABLE IF NOT EXISTS audit_entries (
    entry_id VARCHAR PRIMARY KEY,
    hotkey VARCHAR NOT NULL,
    block BIGINT NOT NULL,
    path VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_entries (path);
CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_entries (start_time);

CREATE TABLE IF NOT EXISTS bounties (
    chute_id TEXT PRIMARY KEY REFERENCES chutes(chute_id) ON DELETE CASCADE,
    bounty INTEGER NOT NULL DEFAULT 100,
    previous_bounty INTEGER NOT NULL DEFAULT 100,
    last_increased_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bounty_history (
    bounty_id TEXT PRIMARY KEY,
    chute_id TEXT NOT NULL,
    version TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_by TEXT
);

CREATE TABLE IF NOT EXISTS chute_manual_boosts (
    chute_id TEXT PRIMARY KEY,
    boost DOUBLE PRECISION NOT NULL DEFAULT 1.0
);

DO $production_base$
DECLARE
    actual_columns TEXT[];
BEGIN
    IF to_regclass(format('%I.instance_audit', current_schema())) IS NULL THEN
        CREATE TABLE instance_audit (
            instance_id TEXT PRIMARY KEY,
            chute_id TEXT NOT NULL,
            version TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            verified_at TIMESTAMP,
            deleted_at TIMESTAMP,
            deletion_reason TEXT,
            miner_uid TEXT NOT NULL,
            miner_hotkey TEXT NOT NULL,
            region TEXT,
            valid_termination BOOLEAN,
            activated_at TIMESTAMP WITH TIME ZONE,
            stop_billing_at TIMESTAMP,
            billed_to TEXT,
            compute_multiplier DOUBLE PRECISION,
            hourly_rate DOUBLE PRECISION,
            bounty BOOLEAN
        );
    ELSE
        SELECT array_agg(attribute.attname ORDER BY attribute.attnum)
          INTO actual_columns
          FROM pg_attribute AS attribute
         WHERE attribute.attrelid = format('%I.instance_audit', current_schema())::regclass
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped;

        IF actual_columns = ARRAY[
            'instance_id', 'chute_id', 'version', 'created_at', 'verified_at', 'deleted_at',
            'deletion_reason', 'miner_uid', 'miner_hotkey', 'region', 'valid_termination'
        ] THEN
            ALTER TABLE instance_audit
                ADD COLUMN activated_at TIMESTAMP WITH TIME ZONE,
                ADD COLUMN stop_billing_at TIMESTAMP,
                ADD COLUMN billed_to TEXT,
                ADD COLUMN compute_multiplier DOUBLE PRECISION,
                ADD COLUMN hourly_rate DOUBLE PRECISION,
                ADD COLUMN bounty BOOLEAN;
        ELSIF actual_columns IS DISTINCT FROM ARRAY[
            'instance_id', 'chute_id', 'version', 'created_at', 'verified_at', 'deleted_at',
            'deletion_reason', 'miner_uid', 'miner_hotkey', 'region', 'valid_termination',
            'activated_at', 'stop_billing_at', 'billed_to', 'compute_multiplier', 'hourly_rate',
            'bounty'
        ] THEN
            RAISE EXCEPTION
                'instance_audit is neither the exact deployed 11-column shape nor final shape: %',
                actual_columns;
        END IF;
    END IF;
END
$production_base$;

CREATE INDEX IF NOT EXISTS idx_instance_audit_ts
    ON instance_audit (verified_at, deleted_at);
CREATE INDEX IF NOT EXISTS idx_instance_audit_miner
    ON instance_audit (miner_hotkey, miner_uid);
CREATE INDEX IF NOT EXISTS idx_billing_ia
    ON instance_audit (activated_at, stop_billing_at, billed_to, deleted_at);

CREATE TABLE IF NOT EXISTS instance_compute_history (
    id BIGSERIAL PRIMARY KEY,
    instance_id TEXT NOT NULL,
    compute_multiplier DOUBLE PRECISION NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ich_instance_time
    ON instance_compute_history (instance_id, started_at, ended_at);
CREATE INDEX IF NOT EXISTS idx_ich_time_range
    ON instance_compute_history (started_at, ended_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ich_instance_open
    ON instance_compute_history (instance_id) WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS partitioned_invocations (
    invocation_id TEXT NOT NULL,
    chute_id TEXT NOT NULL,
    chute_user_id TEXT NOT NULL,
    function_name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    image_id TEXT NOT NULL,
    image_user_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    miner_uid INTEGER NOT NULL,
    miner_hotkey TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    error_message TEXT,
    request_path TEXT,
    response_path TEXT,
    compute_multiplier DOUBLE PRECISION NOT NULL,
    bounty INTEGER NOT NULL,
    parent_invocation_id TEXT,
    metrics JSONB
) PARTITION BY RANGE (started_at);
CREATE INDEX IF NOT EXISTS idx_inv_id ON partitioned_invocations (invocation_id);
CREATE INDEX IF NOT EXISTS idx_inv_chute_err
    ON partitioned_invocations (started_at, chute_id, error_message);
CREATE INDEX IF NOT EXISTS idx_inv_response
    ON partitioned_invocations (started_at, response_path);
CREATE INDEX IF NOT EXISTS idx_parent_inv_id
    ON partitioned_invocations (parent_invocation_id);

DO $production_base$
DECLARE
    relation_kind "char";
    definition_md5 TEXT;
BEGIN
    SELECT relation.relkind,
           md5(regexp_replace(replace(pg_get_viewdef(relation.oid, true),
               current_schema() || '.', ''), '[[:space:]]+', ' ', 'g'))
      INTO relation_kind, definition_md5
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema() AND relation.relname = 'invocations';
    IF relation_kind IS NOT NULL
       AND (relation_kind <> 'v' OR definition_md5 <> '0a673cd6e5d435a9d8fad74efc1c2ab3')
    THEN
        RAISE EXCEPTION 'unknown invocations relation before replacement: kind=%, md5=%',
            relation_kind, definition_md5;
    END IF;
END
$production_base$;

CREATE OR REPLACE VIEW invocations AS SELECT * FROM partitioned_invocations;

ALTER TABLE chute_history ADD COLUMN IF NOT EXISTS jobs JSONB;
CREATE INDEX IF NOT EXISTS idx_chute_history_chute_id ON chute_history (chute_id);
CREATE INDEX IF NOT EXISTS idx_image_history_image_id ON image_history (image_id);

CREATE TABLE IF NOT EXISTS node_history (
    entry_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    miner_hotkey TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_node_history_node_id ON node_history (node_id);

CREATE TABLE IF NOT EXISTS instance_node_history (
    instance_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    miner_hotkey TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (instance_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_instance_node_history_hk_node
    ON instance_node_history (miner_hotkey, node_id);
CREATE INDEX IF NOT EXISTS idx_instance_node_history_instance_id
    ON instance_node_history (instance_id);
CREATE INDEX IF NOT EXISTS idx_instance_node_history_node_id
    ON instance_node_history (node_id);
CREATE INDEX IF NOT EXISTS idx_instance_node_history_miner_hotkey
    ON instance_node_history (miner_hotkey);

CREATE TABLE IF NOT EXISTS p_llm_metrics (
    chute_id TEXT NOT NULL,
    name VARCHAR,
    date DATE NOT NULL,
    total_requests BIGINT DEFAULT 0,
    total_input_tokens BIGINT DEFAULT 0,
    total_output_tokens BIGINT DEFAULT 0,
    average_tps NUMERIC DEFAULT 0,
    average_ttft NUMERIC DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (chute_id, date)
) PARTITION BY RANGE (date);
CREATE INDEX IF NOT EXISTS idx_p_llm_metrics_date ON p_llm_metrics (date);

CREATE TABLE IF NOT EXISTS vllm_metrics (
    chute_id TEXT NOT NULL,
    name VARCHAR,
    date DATE NOT NULL,
    total_requests BIGINT DEFAULT 0,
    total_input_tokens BIGINT DEFAULT 0,
    total_output_tokens BIGINT DEFAULT 0,
    average_tps NUMERIC DEFAULT 0,
    average_ttft NUMERIC DEFAULT 0
);

CREATE TABLE IF NOT EXISTS diffusion_metrics (
    chute_id TEXT NOT NULL,
    name VARCHAR,
    date DATE NOT NULL,
    total_steps BIGINT NOT NULL DEFAULT 0,
    total_requests BIGINT NOT NULL DEFAULT 0,
    average_sps NUMERIC NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inference_sponsorships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE,
    daily_threshold DOUBLE PRECISION NOT NULL,
    description TEXT
);
CREATE TABLE IF NOT EXISTS sponsorship_chutes (
    sponsorship_id UUID NOT NULL REFERENCES inference_sponsorships(id) ON DELETE CASCADE,
    chute_id TEXT NOT NULL,
    PRIMARY KEY (sponsorship_id, chute_id)
);

CREATE OR REPLACE FUNCTION insert_invocation()
RETURNS TRIGGER AS $production_base_function$
DECLARE
    partition_start TIMESTAMP;
    partition_end TIMESTAMP;
    partition_name TEXT;
    partition_relation REGCLASS;
    expected_bound TEXT;
BEGIN
    partition_start := date_trunc('week', NEW.started_at);
    partition_end := partition_start + INTERVAL '1 week';
    partition_name := 'partitioned_invocations_' || to_char(partition_start, 'IYYY_IW');
    expected_bound := format(
        'FOR VALUES FROM (%L) TO (%L)', partition_start, partition_end
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(TG_TABLE_SCHEMA || '.partitioned_invocations:' || partition_name, 0)
    );
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE relation.relname = partition_name
           AND namespace.nspname = TG_TABLE_SCHEMA
    ) THEN
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.partitioned_invocations '
            'FOR VALUES FROM (%L) TO (%L)',
            TG_TABLE_SCHEMA,
            partition_name,
            TG_TABLE_SCHEMA,
            partition_start,
            partition_end
        );
    END IF;
    partition_relation := to_regclass(format('%I.%I', TG_TABLE_SCHEMA, partition_name));
    IF partition_relation IS NULL
       OR NOT (SELECT relation.relispartition FROM pg_class AS relation
                WHERE relation.oid = partition_relation)
       OR pg_partition_root(partition_relation)
            <> format('%I.partitioned_invocations', TG_TABLE_SCHEMA)::regclass
       OR pg_get_expr(
            (SELECT relation.relpartbound FROM pg_class AS relation
              WHERE relation.oid = partition_relation), partition_relation, true
          ) IS DISTINCT FROM expected_bound
    THEN
        RAISE EXCEPTION 'invocation partition % has an invalid parent/bound', partition_name;
    END IF;
    EXECUTE format('INSERT INTO %I.partitioned_invocations SELECT ($1).*', TG_TABLE_SCHEMA)
        USING NEW;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION version_numbers(ver TEXT)
RETURNS BIGINT AS $production_base_function$
DECLARE
    nums INTEGER[];
    result BIGINT;
BEGIN
    nums := (
        SELECT array_agg(num::INTEGER)
          FROM (SELECT (regexp_matches(ver, '(\d+)', 'g'))[1] AS num) AS numbers
    );
    result := (COALESCE(nums[1], 0) * 1000000)
        + (COALESCE(nums[2], 0) * 1000)
        + COALESCE(nums[3], 0);
    RETURN result;
END
$production_base_function$ LANGUAGE plpgsql;

-- Keep the deployed input parameter name.  PostgreSQL rejects CREATE OR REPLACE when only an
-- input parameter name changes, while function identity itself is increase_bounty(text).
CREATE OR REPLACE FUNCTION increase_bounty(target_chute_id TEXT)
RETURNS TABLE(bounty INTEGER, last_increased_at TIMESTAMP, was_increased BOOLEAN)
AS $production_base_function$
DECLARE
    current_version TEXT;
    bounty_id_today TEXT;
    history_exists BOOLEAN;
    bounty_exists BOOLEAN;
    initial_bounty INTEGER;
    initial_last_increased_at TIMESTAMP;
    final_bounty INTEGER;
    final_last_increased_at TIMESTAMP;
    increased BOOLEAN := FALSE;
    check_history BOOLEAN := TRUE;
BEGIN
    SELECT chute.chutes_version
      INTO current_version
      FROM chutes AS chute
     WHERE chute.chute_id = target_chute_id;
    IF NOT FOUND OR current_version IS NULL THEN
        RETURN QUERY SELECT NULL::INTEGER, NULL::TIMESTAMP, FALSE;
        RETURN;
    END IF;

    IF current_version ~ '^([1-9]\d*|0\.([3-9]\d*|[1-9]\d+))\.'
       OR current_version = '0.3.0'
       OR current_version ~ '^0\.3\.[0-9]+'
    THEN
        check_history := FALSE;
    END IF;

    bounty_id_today := encode(
        public.digest(
            target_chute_id || current_version || to_char(CURRENT_DATE, 'YYYY-MM-DD'), 'sha256'
        ),
        'hex'
    );
    IF check_history THEN
        SELECT EXISTS (
            SELECT 1 FROM bounty_history WHERE bounty_id = bounty_id_today
        ) INTO history_exists;
    ELSE
        history_exists := FALSE;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM bounties WHERE chute_id = target_chute_id
    ) INTO bounty_exists;

    IF bounty_exists THEN
        SELECT current.bounty, current.last_increased_at
          INTO initial_bounty, initial_last_increased_at
          FROM bounties AS current
         WHERE current.chute_id = target_chute_id;
        UPDATE bounties
           SET previous_bounty = bounties.bounty,
               bounty = CASE
                   WHEN CURRENT_TIMESTAMP - bounties.last_increased_at >= INTERVAL '30 seconds'
                    AND bounties.bounty + LEAST(300, bounties.previous_bounty) <= 86400
                   THEN bounties.bounty + LEAST(300, bounties.previous_bounty)
                   ELSE bounties.bounty
               END,
               last_increased_at = CASE
                   WHEN CURRENT_TIMESTAMP - bounties.last_increased_at >= INTERVAL '30 seconds'
                    AND bounties.bounty + LEAST(300, bounties.previous_bounty) <= 86400
                   THEN CURRENT_TIMESTAMP
                   ELSE bounties.last_increased_at
               END
         WHERE bounties.chute_id = target_chute_id;
        SELECT current.bounty, current.last_increased_at
          INTO final_bounty, final_last_increased_at
          FROM bounties AS current
         WHERE current.chute_id = target_chute_id;
        IF final_bounty <> initial_bounty THEN
            increased := TRUE;
            IF check_history AND NOT history_exists THEN
                INSERT INTO bounty_history (bounty_id, chute_id, version, created_at)
                VALUES (bounty_id_today, target_chute_id, current_version, CURRENT_TIMESTAMP)
                ON CONFLICT (bounty_id) DO NOTHING;
            END IF;
        END IF;
    ELSIF NOT check_history OR NOT history_exists THEN
        INSERT INTO bounties (chute_id, bounty, previous_bounty, last_increased_at)
        VALUES (target_chute_id, 100, 100, CURRENT_TIMESTAMP);
        final_bounty := 100;
        final_last_increased_at := CURRENT_TIMESTAMP;
        increased := TRUE;
        IF check_history THEN
            INSERT INTO bounty_history (bounty_id, chute_id, version, created_at)
            VALUES (bounty_id_today, target_chute_id, current_version, CURRENT_TIMESTAMP)
            ON CONFLICT (bounty_id) DO NOTHING;
        END IF;
    ELSE
        final_bounty := NULL;
        final_last_increased_at := NULL;
    END IF;
    RETURN QUERY SELECT final_bounty, final_last_increased_at, increased;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION initialize_bounty()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    PERFORM increase_bounty(NEW.chute_id);
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_instance_audit_insert()
RETURNS TRIGGER AS $production_base_function$
DECLARE
    deployed_version TEXT;
BEGIN
    SELECT chute.version INTO deployed_version
      FROM chutes AS chute
     WHERE chute.chute_id = NEW.chute_id;
    INSERT INTO instance_audit (
        instance_id, chute_id, version, miner_uid, miner_hotkey, region,
        billed_to, stop_billing_at, compute_multiplier, hourly_rate, bounty
    ) VALUES (
        NEW.instance_id, NEW.chute_id, deployed_version, NEW.miner_uid, NEW.miner_hotkey,
        NEW.region, NEW.billed_to, NEW.stop_billing_at, NEW.compute_multiplier,
        NEW.hourly_rate, NEW.bounty
    );
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_instance_audit_update()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    IF NEW.last_verified_at IS NOT NULL AND OLD.last_verified_at IS NULL THEN
        UPDATE instance_audit SET verified_at = NEW.last_verified_at
         WHERE instance_id = NEW.instance_id AND verified_at IS NULL;
    END IF;
    IF NEW.activated_at IS NOT NULL AND OLD.activated_at IS NULL THEN
        UPDATE instance_audit SET activated_at = NEW.activated_at
         WHERE instance_id = NEW.instance_id AND activated_at IS NULL;
    END IF;
    IF NEW.billed_to IS DISTINCT FROM OLD.billed_to AND NEW.billed_to IS NOT NULL THEN
        UPDATE instance_audit SET billed_to = NEW.billed_to
         WHERE instance_id = NEW.instance_id;
    END IF;
    IF NEW.hourly_rate IS DISTINCT FROM OLD.hourly_rate AND NEW.hourly_rate IS NOT NULL THEN
        UPDATE instance_audit SET hourly_rate = NEW.hourly_rate
         WHERE instance_id = NEW.instance_id;
    END IF;
    IF NEW.stop_billing_at IS DISTINCT FROM OLD.stop_billing_at THEN
        UPDATE instance_audit SET stop_billing_at = NEW.stop_billing_at
         WHERE instance_id = NEW.instance_id;
    END IF;
    IF NEW.compute_multiplier IS DISTINCT FROM OLD.compute_multiplier THEN
        UPDATE instance_audit SET compute_multiplier = NEW.compute_multiplier
         WHERE instance_id = NEW.instance_id;
    END IF;
    IF NEW.bounty IS DISTINCT FROM OLD.bounty THEN
        UPDATE instance_audit SET bounty = NEW.bounty
         WHERE instance_id = NEW.instance_id;
    END IF;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_instance_audit_delete()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    UPDATE instance_audit SET deleted_at = NOW()
     WHERE instance_id = OLD.instance_id AND deleted_at IS NULL;
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_instance_compute_history_update()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    IF NEW.activated_at IS NOT NULL AND OLD.activated_at IS NULL THEN
        IF NEW.compute_multiplier IS NOT NULL THEN
            UPDATE instance_compute_history SET ended_at = NOW()
             WHERE instance_id = NEW.instance_id AND ended_at IS NULL;
            INSERT INTO instance_compute_history (instance_id, compute_multiplier, started_at)
            VALUES (NEW.instance_id, NEW.compute_multiplier, NEW.activated_at);
        END IF;
    ELSIF NEW.compute_multiplier IS DISTINCT FROM OLD.compute_multiplier
          AND NEW.compute_multiplier IS NOT NULL THEN
        UPDATE instance_compute_history SET ended_at = NOW()
         WHERE instance_id = NEW.instance_id AND ended_at IS NULL;
        INSERT INTO instance_compute_history (instance_id, compute_multiplier, started_at)
        VALUES (NEW.instance_id, NEW.compute_multiplier, NOW());
    END IF;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_instance_compute_history_delete()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    UPDATE instance_compute_history SET ended_at = NOW()
     WHERE instance_id = OLD.instance_id AND ended_at IS NULL;
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_chute_history_insert()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    INSERT INTO chute_history (
        entry_id, chute_id, user_id, version, name, tagline, readme, tool_description,
        image_id, logo_id, public, standard_template, cords, jobs, node_selector, slug,
        code, filename, ref_str, chutes_version, openrouter, discount, created_at, updated_at
    ) VALUES (
        gen_random_uuid()::TEXT, NEW.chute_id, NEW.user_id, NEW.version, NEW.name,
        NEW.tagline, NEW.readme, NEW.tool_description, NEW.image_id, NEW.logo_id, NEW.public,
        NEW.standard_template, NEW.cords, NEW.jobs, NEW.node_selector, NEW.slug, NEW.code,
        NEW.filename, NEW.ref_str, NEW.chutes_version, NEW.openrouter, NEW.discount,
        NEW.created_at, NEW.updated_at
    );
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_chute_history_update()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    IF OLD.updated_at IS DISTINCT FROM NEW.updated_at THEN
        INSERT INTO chute_history (
            entry_id, chute_id, user_id, version, name, tagline, readme, tool_description,
            image_id, logo_id, public, standard_template, cords, jobs, node_selector, slug,
            code, filename, ref_str, chutes_version, openrouter, discount, created_at, updated_at
        ) VALUES (
            gen_random_uuid()::TEXT, NEW.chute_id, NEW.user_id, NEW.version, NEW.name,
            NEW.tagline, NEW.readme, NEW.tool_description, NEW.image_id, NEW.logo_id,
            NEW.public, NEW.standard_template, NEW.cords, NEW.jobs, NEW.node_selector, NEW.slug,
            NEW.code, NEW.filename, NEW.ref_str, NEW.chutes_version, NEW.openrouter,
            NEW.discount, NEW.created_at, NEW.updated_at
        );
    END IF;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_chute_history_delete()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    UPDATE chute_history SET deleted_at = NOW()
     WHERE chute_id = OLD.chute_id
       AND version = OLD.version
       AND entry_id = (
           SELECT entry_id FROM chute_history
            WHERE chute_id = OLD.chute_id AND version = OLD.version
            ORDER BY created_at DESC LIMIT 1
       );
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_image_history_insert()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    INSERT INTO image_history (
        entry_id, image_id, user_id, name, tag, readme, logo_id, public, status,
        chutes_version, build_started_at, build_completed_at, created_at
    ) VALUES (
        gen_random_uuid()::TEXT, NEW.image_id, NEW.user_id, NEW.name, NEW.tag, NEW.readme,
        NEW.logo_id, NEW.public, NEW.status, NEW.chutes_version, NEW.build_started_at,
        NEW.build_completed_at, NEW.created_at
    );
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_image_history_update()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    INSERT INTO image_history (
        entry_id, image_id, user_id, name, tag, readme, logo_id, public, status,
        chutes_version, build_started_at, build_completed_at, created_at
    ) VALUES (
        gen_random_uuid()::TEXT, NEW.image_id, NEW.user_id, NEW.name, NEW.tag, NEW.readme,
        NEW.logo_id, NEW.public, NEW.status, NEW.chutes_version, NEW.build_started_at,
        NEW.build_completed_at, NEW.created_at
    );
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_image_history_delete()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    UPDATE image_history SET deleted_at = NOW()
     WHERE image_id = OLD.image_id
       AND entry_id = (
           SELECT entry_id FROM image_history
            WHERE image_id = OLD.image_id ORDER BY created_at DESC LIMIT 1
       );
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_node_history_insert()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    INSERT INTO node_history (entry_id, node_id, miner_hotkey, created_at)
    VALUES (gen_random_uuid()::TEXT, NEW.uuid, NEW.miner_hotkey, NEW.created_at);
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_node_history_delete()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    UPDATE node_history SET deleted_at = NOW()
     WHERE node_id = OLD.uuid
       AND miner_hotkey = OLD.miner_hotkey
       AND entry_id = (
           SELECT entry_id FROM node_history
            WHERE node_id = OLD.uuid AND miner_hotkey = OLD.miner_hotkey
            ORDER BY created_at DESC LIMIT 1
       );
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION track_instance_node_assignment()
RETURNS TRIGGER AS $production_base_function$
DECLARE
    assigned_miner_hotkey TEXT;
BEGIN
    SELECT miner_hotkey INTO assigned_miner_hotkey
      FROM instances WHERE instance_id = NEW.instance_id;
    IF assigned_miner_hotkey IS NOT NULL THEN
        INSERT INTO instance_node_history (instance_id, node_id, miner_hotkey)
        VALUES (NEW.instance_id, NEW.node_id, assigned_miner_hotkey)
        ON CONFLICT (instance_id, node_id) DO NOTHING;
    END IF;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_reset_job_assignment()
RETURNS TRIGGER AS $production_base_function$
BEGIN
    IF OLD.job_id IS NOT NULL
       AND (NEW.failed_at IS NOT NULL OR NEW.verification_error IS NOT NULL)
    THEN
        UPDATE jobs SET miner_hotkey = NULL, miner_coldkey = NULL, instance_id = NULL
         WHERE job_id = OLD.job_id;
    END IF;
    RETURN NEW;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION create_llm_metrics_part(partition_date DATE)
RETURNS VOID AS $production_base_function$
DECLARE
    partition_name TEXT := 'p_llm_metrics_' || to_char(partition_date, 'YYYYMMDD');
    partition_relation REGCLASS;
    expected_bound TEXT := format(
        'FOR VALUES FROM (%L) TO (%L)', partition_date, partition_date + 1
    );
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(current_schema() || '.p_llm_metrics:' || partition_name, 0)
    );
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.p_llm_metrics '
        'FOR VALUES FROM (%L) TO (%L)',
        current_schema(), partition_name, current_schema(), partition_date,
        partition_date + 1
    );
    partition_relation := to_regclass(format('%I.%I', current_schema(), partition_name));
    IF partition_relation IS NULL
       OR NOT (SELECT relation.relispartition FROM pg_class AS relation
                WHERE relation.oid = partition_relation)
       OR pg_partition_root(partition_relation)
            <> format('%I.p_llm_metrics', current_schema())::regclass
       OR pg_get_expr(
            (SELECT relation.relpartbound FROM pg_class AS relation
              WHERE relation.oid = partition_relation), partition_relation, true
          ) IS DISTINCT FROM expected_bound
    THEN
        RAISE EXCEPTION 'LLM metrics partition % has an invalid parent/bound', partition_name;
    END IF;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION gen_llm_metrics_for_day(target_date DATE)
RETURNS TABLE (
    out_chute_id TEXT,
    out_name VARCHAR,
    out_date DATE,
    out_total_requests BIGINT,
    out_total_input_tokens BIGINT,
    out_total_output_tokens BIGINT,
    out_average_tps NUMERIC,
    out_average_ttft NUMERIC
) AS $production_base_function$
BEGIN
    IF target_date + INTERVAL '1 day' < CURRENT_DATE + INTERVAL '23 hours' THEN
        IF NOT EXISTS (SELECT 1 FROM p_llm_metrics WHERE date = target_date) THEN
            PERFORM create_llm_metrics_part(target_date);
            INSERT INTO p_llm_metrics (
                chute_id, name, date, total_requests, total_input_tokens,
                total_output_tokens, average_tps, average_ttft
            )
            WITH metrics_for_day AS (
                SELECT invocation.chute_id,
                       COUNT(*)::BIGINT AS total_requests,
                       SUM((invocation.metrics->>'it')::INTEGER)::BIGINT AS total_input_tokens,
                       SUM((invocation.metrics->>'ot')::INTEGER)::BIGINT AS total_output_tokens,
                       AVG(CASE
                           WHEN invocation.metrics->>'otps' IS NOT NULL
                           THEN (invocation.metrics->>'otps')::DOUBLE PRECISION
                           WHEN invocation.metrics->>'ot' IS NOT NULL
                            AND invocation.metrics->>'ttft' IS NOT NULL
                            AND extract(EPOCH FROM invocation.completed_at - invocation.started_at)
                                - (invocation.metrics->>'ttft')::DOUBLE PRECISION > 0
                           THEN (invocation.metrics->>'ot')::INTEGER /
                                (extract(EPOCH FROM invocation.completed_at - invocation.started_at)
                                 - (invocation.metrics->>'ttft')::DOUBLE PRECISION)
                           ELSE NULL
                       END)::NUMERIC AS average_tps,
                       AVG((invocation.metrics->>'ttft')::DOUBLE PRECISION)::NUMERIC
                           AS average_ttft
                  FROM invocations AS invocation
                 WHERE invocation.started_at >= target_date
                   AND invocation.started_at < target_date + INTERVAL '1 day'
                   AND invocation.metrics->>'it' IS NOT NULL
                   AND invocation.completed_at IS NOT NULL
                   AND invocation.error_message IS NULL
                 GROUP BY invocation.chute_id
            ), latest_names AS (
                SELECT DISTINCT ON (history.chute_id)
                       history.chute_id, COALESCE(history.name, '[unknown]') AS name
                  FROM chute_history AS history
                 WHERE history.created_at <= target_date + INTERVAL '1 day'
                 ORDER BY history.chute_id, history.created_at DESC
            )
            SELECT metric.chute_id, COALESCE(latest.name, '[unknown]'), target_date,
                   metric.total_requests, metric.total_input_tokens, metric.total_output_tokens,
                   metric.average_tps, metric.average_ttft
              FROM metrics_for_day AS metric
              LEFT JOIN latest_names AS latest ON latest.chute_id = metric.chute_id
            ON CONFLICT (chute_id, date) DO NOTHING;
        END IF;
        RETURN QUERY
        SELECT metric.chute_id, metric.name, metric.date, metric.total_requests,
               metric.total_input_tokens, metric.total_output_tokens,
               metric.average_tps, metric.average_ttft
          FROM p_llm_metrics AS metric WHERE metric.date = target_date;
    ELSE
        RETURN QUERY
        WITH metrics_for_day AS (
            SELECT invocation.chute_id,
                   COUNT(*)::BIGINT AS total_requests,
                   SUM((invocation.metrics->>'it')::INTEGER)::BIGINT AS total_input_tokens,
                   SUM((invocation.metrics->>'ot')::INTEGER)::BIGINT AS total_output_tokens,
                   AVG(CASE
                       WHEN invocation.metrics->>'otps' IS NOT NULL
                       THEN (invocation.metrics->>'otps')::DOUBLE PRECISION
                       WHEN invocation.metrics->>'ot' IS NOT NULL
                        AND invocation.metrics->>'ttft' IS NOT NULL
                        AND extract(EPOCH FROM invocation.completed_at - invocation.started_at)
                            - (invocation.metrics->>'ttft')::DOUBLE PRECISION > 0
                       THEN (invocation.metrics->>'ot')::INTEGER /
                            (extract(EPOCH FROM invocation.completed_at - invocation.started_at)
                             - (invocation.metrics->>'ttft')::DOUBLE PRECISION)
                       ELSE NULL
                   END)::NUMERIC AS average_tps,
                   AVG((invocation.metrics->>'ttft')::DOUBLE PRECISION)::NUMERIC AS average_ttft
              FROM invocations AS invocation
             WHERE invocation.started_at >= target_date
               AND invocation.started_at < target_date + INTERVAL '1 day'
               AND invocation.metrics->>'it' IS NOT NULL
               AND invocation.completed_at IS NOT NULL
               AND invocation.error_message IS NULL
             GROUP BY invocation.chute_id
        ), latest_names AS (
            SELECT DISTINCT ON (history.chute_id)
                   history.chute_id, COALESCE(history.name, '[unknown]') AS name
              FROM chute_history AS history
             ORDER BY history.chute_id, history.created_at DESC
        )
        SELECT metric.chute_id, COALESCE(latest.name, '[unknown]')::VARCHAR, target_date,
               metric.total_requests, metric.total_input_tokens, metric.total_output_tokens,
               metric.average_tps, metric.average_ttft
          FROM metrics_for_day AS metric
          LEFT JOIN latest_names AS latest ON latest.chute_id = metric.chute_id;
    END IF;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_llm_metrics(start_date DATE, end_date DATE)
RETURNS TABLE (
    chute_id TEXT,
    name VARCHAR,
    date DATE,
    total_requests BIGINT,
    total_input_tokens BIGINT,
    total_output_tokens BIGINT,
    average_tps NUMERIC,
    average_ttft NUMERIC
) AS $production_base_function$
DECLARE
    current_date_value DATE := start_date;
BEGIN
    WHILE current_date_value <= end_date LOOP
        RETURN QUERY SELECT * FROM gen_llm_metrics_for_day(current_date_value);
        current_date_value := current_date_value + 1;
    END LOOP;
END
$production_base_function$ LANGUAGE plpgsql;

-- Compatibility contract for the deployed e0dd84a cacher.  Newer callers may aggregate this
-- data inline, but rolling old binaries continue to execute this exact two-date function.
CREATE OR REPLACE FUNCTION get_diffusion_metrics(start_date DATE, end_date DATE)
RETURNS TABLE (
    chute_id TEXT,
    name VARCHAR,
    date DATE,
    total_steps BIGINT,
    total_requests BIGINT,
    average_sps NUMERIC
) AS $production_base_function$
    WITH date_series AS (
        SELECT generate_series(start_date, end_date, '1 day'::INTERVAL)::DATE AS date
    ), all_chutes AS (
        SELECT chute.chute_id, chute.name
          FROM chutes AS chute
         WHERE chute.standard_template = 'diffusion'
    ), chute_dates AS (
        SELECT chute.chute_id, chute.name, day.date
          FROM all_chutes AS chute
          CROSS JOIN date_series AS day
    ), metrics_data AS (
        SELECT chute.chute_id,
               chute.name,
               DATE(invocation.started_at) AS date,
               SUM((invocation.metrics->>'steps')::DOUBLE PRECISION)::BIGINT AS total_steps,
               COUNT(*)::BIGINT AS total_requests,
               AVG((invocation.metrics->>'sps')::DOUBLE PRECISION)::NUMERIC AS average_sps
          FROM invocations AS invocation
          JOIN chutes AS chute ON invocation.chute_id = chute.chute_id
         WHERE chute.standard_template = 'diffusion'
           AND invocation.metrics->>'steps' IS NOT NULL
           AND invocation.error_message IS NULL
           AND invocation.completed_at IS NOT NULL
           AND invocation.started_at >= start_date
           AND invocation.started_at < end_date + INTERVAL '1 day'
         GROUP BY chute.chute_id, chute.name, DATE(invocation.started_at)
    )
    SELECT date_grid.chute_id,
           date_grid.name,
           date_grid.date,
           COALESCE(metric.total_steps, 0)::BIGINT,
           COALESCE(metric.total_requests, 0)::BIGINT,
           COALESCE(metric.average_sps, 0)::NUMERIC
      FROM chute_dates AS date_grid
      LEFT JOIN metrics_data AS metric
        ON metric.chute_id = date_grid.chute_id
       AND metric.date = date_grid.date
     ORDER BY date_grid.date DESC, date_grid.name
$production_base_function$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION populate_llm_metrics_for_day(target_date DATE)
RETURNS INTEGER AS $production_base_function$
DECLARE
    before_count INTEGER;
    after_count INTEGER;
BEGIN
    IF target_date >= CURRENT_DATE - INTERVAL '1 day' THEN
        RETURN 0;
    END IF;
    SELECT COUNT(*) INTO before_count FROM p_llm_metrics WHERE date = target_date;
    PERFORM * FROM gen_llm_metrics_for_day(target_date);
    SELECT COUNT(*) INTO after_count FROM p_llm_metrics WHERE date = target_date;
    RETURN after_count - before_count;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION backfill_llm_metrics(
    start_date DATE,
    end_date DATE DEFAULT CURRENT_DATE - INTERVAL '2 days'
)
RETURNS VOID AS $production_base_function$
DECLARE
    current_date_value DATE := start_date;
    maximum_date DATE := CURRENT_DATE - INTERVAL '2 days';
BEGIN
    IF end_date > maximum_date THEN
        end_date := maximum_date;
    END IF;
    WHILE current_date_value <= end_date LOOP
        PERFORM populate_llm_metrics_for_day(current_date_value);
        current_date_value := current_date_value + 1;
    END LOOP;
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION refresh_llm_metrics_for_day(target_date DATE)
RETURNS VOID AS $production_base_function$
BEGIN
    IF target_date + INTERVAL '1 day' >= CURRENT_DATE + INTERVAL '23 hours' THEN
        RAISE EXCEPTION
            'Cannot cache metrics for dates within 1 hour of midnight; query live data instead';
    END IF;
    DELETE FROM p_llm_metrics WHERE date = target_date;
    PERFORM * FROM gen_llm_metrics_for_day(target_date);
END
$production_base_function$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_balance_on_instance_delete()
RETURNS TRIGGER AS $production_base_function$
DECLARE
    billed_user_id TEXT;
    is_public BOOLEAN;
    user_permissions BIGINT;
    has_job BOOLEAN;
    total_cost DECIMAL(10, 2);
    billing_start TIMESTAMP;
    billing_end TIMESTAMP;
    current_date_value DATE;
    daily_hours DECIMAL(10, 6);
    daily_cost DECIMAL(10, 2);
BEGIN
    IF OLD.billed_to IS NULL THEN
        RETURN OLD;
    END IF;
    billed_user_id := OLD.billed_to;
    SELECT chute.public, account.permissions_bitmask,
           EXISTS(SELECT 1 FROM jobs WHERE instance_id = OLD.instance_id)
      INTO is_public, user_permissions, has_job
      FROM chutes AS chute
      JOIN users AS account ON account.user_id = billed_user_id
     WHERE chute.chute_id = OLD.chute_id;

    UPDATE instance_audit SET stop_billing_at = NOW()
     WHERE instance_id = OLD.instance_id AND stop_billing_at > NOW();
    IF (user_permissions & 16) = 16 OR (NOT has_job AND is_public) THEN
        RETURN OLD;
    END IF;

    IF OLD.activated_at IS NOT NULL AND OLD.hourly_rate IS NOT NULL THEN
        billing_start := OLD.activated_at;
        billing_end := LEAST(COALESCE(OLD.stop_billing_at, NOW()), NOW());
        total_cost := EXTRACT(EPOCH FROM (billing_end - billing_start)) / 3600.0
            * OLD.hourly_rate;
        UPDATE users SET balance = balance - total_cost WHERE user_id = billed_user_id;

        current_date_value := DATE(billing_start);
        WHILE current_date_value <= DATE(billing_end) LOOP
            IF DATE(billing_start) = current_date_value
               AND DATE(billing_end) = current_date_value THEN
                daily_hours := EXTRACT(EPOCH FROM (billing_end - billing_start)) / 3600.0;
            ELSIF DATE(billing_start) = current_date_value THEN
                daily_hours := EXTRACT(EPOCH FROM (
                    date_trunc('day', billing_start) + INTERVAL '1 day' - billing_start
                )) / 3600.0;
            ELSIF DATE(billing_end) = current_date_value THEN
                daily_hours := EXTRACT(EPOCH FROM (
                    billing_end - date_trunc('day', billing_end)
                )) / 3600.0;
            ELSE
                daily_hours := 24.0;
            END IF;
            daily_cost := daily_hours * OLD.hourly_rate;
            IF daily_cost > 0 THEN
                INSERT INTO usage_data (user_id, bucket, chute_id, amount, count)
                VALUES (
                    billed_user_id, date_trunc('day', current_date_value)::TIMESTAMP,
                    OLD.chute_id, daily_cost, 1
                )
                ON CONFLICT (user_id, bucket, chute_id) DO UPDATE
                SET amount = usage_data.amount + EXCLUDED.amount,
                    count = usage_data.count + EXCLUDED.count;
            END IF;
            current_date_value := current_date_value + 1;
        END LOOP;
    END IF;
    RETURN OLD;
END
$production_base_function$ LANGUAGE plpgsql;

DO $production_base$
DECLARE
    relation_kind "char";
    relation_catalog TEXT;
    column_signature TEXT;
    constraint_signatures TEXT[];
    index_signatures TEXT[];
    trigger_count BIGINT;
    rule_count BIGINT;
    policy_count BIGINT;
    inheritance_count BIGINT;
BEGIN
    SELECT relation.relkind,
           relation.relpersistence::TEXT || ':'
           || access_method.amname || ':'
           || relation.relrowsecurity::TEXT || ':'
           || relation.relforcerowsecurity::TEXT || ':'
           || COALESCE(array_to_string(relation.reloptions, ','), '<null>') || ':'
           || relation.relreplident::TEXT || ':'
           || relation.reltablespace::TEXT || ':'
           || COALESCE(array_to_string(relation.relacl, ','), '<null>') || ':'
           || (pg_get_userbyid(relation.relowner) = current_user)::TEXT || ':'
           || relation.relispartition::TEXT || ':'
           || relation.relispopulated::TEXT || ':'
           || COALESCE(obj_description(relation.oid, 'pg_class'), '<null>')
      INTO relation_kind, relation_catalog
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      LEFT JOIN pg_am AS access_method ON access_method.oid = relation.relam
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'user_current_balance';
    IF relation_kind = 'r' THEN
        IF relation_catalog IS DISTINCT FROM
           'p:heap:false:false:<null>:d:0:<null>:true:false:true:<null>' THEN
            RAISE EXCEPTION
                'user_current_balance ordinary table has unknown relation metadata: %',
                relation_catalog;
        END IF;
        SELECT string_agg(
                   attribute.attnum::TEXT || ':' || attribute.attname || ':'
                   || format_type(attribute.atttypid, attribute.atttypmod) || ':'
                   || attribute.attnotnull::TEXT || ':'
                   || COALESCE(NULLIF(attribute.attidentity::TEXT, ''), '<empty>') || ':'
                   || COALESCE(NULLIF(attribute.attgenerated::TEXT, ''), '<empty>') || ':'
                   || attribute.attstorage::TEXT || ':'
                   || COALESCE(NULLIF(attribute.attcompression::TEXT, ''), '<empty>') || ':'
                   || attribute.attstattarget::TEXT || ':'
                   || COALESCE(array_to_string(attribute.attoptions, ','), '<null>') || ':'
                   || COALESCE(array_to_string(attribute.attfdwoptions, ','), '<null>') || ':'
                   || (attribute.attacl IS NULL)::TEXT || ':'
                   || (attribute.attcollation = type_row.typcollation)::TEXT || ':'
                   || attribute.attislocal::TEXT || ':'
                   || attribute.attinhcount::TEXT || ':'
                   || attribute.attisdropped::TEXT || ':'
                   || COALESCE(
                       pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true),
                       '<null>'
                   ),
                   '|' ORDER BY attribute.attnum
               )
          INTO column_signature
          FROM pg_attribute AS attribute
          JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = attribute.attrelid
           AND attribute_default.adnum = attribute.attnum
         WHERE attribute.attrelid = format('%I.user_current_balance', current_schema())::regclass
           AND attribute.attnum > 0;

        SELECT array_agg(
                   constraint_row.contype::TEXT || ':'
                   || constraint_row.convalidated::TEXT || ':'
                   || constraint_row.condeferrable::TEXT || ':'
                   || constraint_row.condeferred::TEXT || ':'
                   || pg_get_constraintdef(constraint_row.oid, true)
                   ORDER BY constraint_row.contype, constraint_row.conname
               )
          INTO constraint_signatures
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid =
               format('%I.user_current_balance', current_schema())::regclass;

        SELECT array_agg(
                   index_relation.relname || ':'
                   || index_relation.relpersistence::TEXT || ':'
                   || (pg_get_userbyid(index_relation.relowner) = current_user)::TEXT || ':'
                   || (index_relation.relacl IS NULL)::TEXT || ':'
                   || index_relation.reltablespace::TEXT || ':'
                   || COALESCE(array_to_string(index_relation.reloptions, ','), '<null>') || ':'
                   || index_row.indisunique::TEXT || ':'
                   || index_row.indisprimary::TEXT || ':'
                   || index_row.indisexclusion::TEXT || ':'
                   || index_row.indimmediate::TEXT || ':'
                   || index_row.indisclustered::TEXT || ':'
                   || index_row.indisvalid::TEXT || ':'
                   || index_row.indisready::TEXT || ':'
                   || index_row.indislive::TEXT || ':'
                   || index_row.indisreplident::TEXT || ':'
                   || index_row.indnullsnotdistinct::TEXT || ':'
                   || index_row.indnatts::TEXT || ':'
                   || index_row.indnkeyatts::TEXT || ':'
                   || access_method.amname || ':'
                   || COALESCE(
                       pg_get_expr(index_row.indexprs, index_row.indrelid, true), '<null>'
                   ) || ':'
                   || COALESCE(
                       pg_get_expr(index_row.indpred, index_row.indrelid, true), '<null>'
                   ) || ':'
                   || (
                       SELECT array_agg(attribute.attname ORDER BY key_column.position)::TEXT
                         FROM unnest(index_row.indkey) WITH ORDINALITY
                              AS key_column(attribute_number, position)
                         JOIN pg_attribute AS attribute
                           ON attribute.attrelid = index_row.indrelid
                          AND attribute.attnum = key_column.attribute_number
                   ) || ':'
                   || (
                       SELECT array_agg(
                                  namespace.nspname || '.' || operator_class.opcname
                                  ORDER BY class_column.position
                              )::TEXT
                         FROM unnest(index_row.indclass) WITH ORDINALITY
                              AS class_column(operator_class_oid, position)
                         JOIN pg_opclass AS operator_class
                           ON operator_class.oid = class_column.operator_class_oid
                         JOIN pg_namespace AS namespace
                           ON namespace.oid = operator_class.opcnamespace
                   ) || ':'
                   || index_row.indoption::TEXT || ':'
                   || (
                       SELECT bool_and(
                                  index_row.indcollation[key_column.position - 1]
                                  = attribute.attcollation
                              )::TEXT
                         FROM unnest(index_row.indkey) WITH ORDINALITY
                              AS key_column(attribute_number, position)
                         JOIN pg_attribute AS attribute
                           ON attribute.attrelid = index_row.indrelid
                          AND attribute.attnum = key_column.attribute_number
                   ) || ':'
                   || replace(
                       pg_get_indexdef(index_row.indexrelid, 0, true),
                       current_schema() || '.', ''
                   )
                   ORDER BY index_relation.relname
               )
          INTO index_signatures
          FROM pg_index AS index_row
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_am AS access_method ON access_method.oid = index_relation.relam
         WHERE index_row.indrelid =
               format('%I.user_current_balance', current_schema())::regclass;

        SELECT count(*) INTO trigger_count
          FROM pg_trigger
         WHERE tgrelid = format('%I.user_current_balance', current_schema())::regclass
           AND NOT tgisinternal;
        SELECT count(*) INTO rule_count
          FROM pg_rewrite
         WHERE ev_class = format('%I.user_current_balance', current_schema())::regclass
           AND rulename <> '_RETURN';
        SELECT count(*) INTO policy_count
          FROM pg_policy
         WHERE polrelid = format('%I.user_current_balance', current_schema())::regclass;
        SELECT count(*) INTO inheritance_count
          FROM pg_inherits
         WHERE inhrelid = format('%I.user_current_balance', current_schema())::regclass
            OR inhparent = format('%I.user_current_balance', current_schema())::regclass;

        IF column_signature IS DISTINCT FROM
               '1:user_id:character varying:true:<empty>:<empty>:x:<empty>:-1:'
               '<null>:<null>:true:true:true:0:false:<null>|'
               '2:stored_balance:double precision:false:<empty>:<empty>:p:<empty>:-1:'
               '<null>:<null>:true:true:true:0:false:<null>|'
               '3:total_instance_costs:double precision:false:<empty>:<empty>:p:<empty>:-1:'
               '<null>:<null>:true:true:true:0:false:<null>|'
               '4:effective_balance:double precision:false:<empty>:<empty>:p:<empty>:-1:'
               '<null>:<null>:true:true:true:0:false:<null>'
           OR constraint_signatures IS DISTINCT FROM ARRAY[
               'p:true:false:false:PRIMARY KEY (user_id)'
           ]
           OR index_signatures IS DISTINCT FROM ARRAY[
               'user_current_balance_pkey:p:true:true:0:<null>:'
               'true:true:false:true:false:true:true:true:false:false:1:1:btree:'
               '<null>:<null>:{user_id}:{pg_catalog.text_ops}:0:true:'
               'CREATE UNIQUE INDEX user_current_balance_pkey '
               'ON user_current_balance USING btree (user_id)'
           ]
           OR trigger_count <> 0 OR rule_count <> 0 OR policy_count <> 0
           OR inheritance_count <> 0 THEN
            RAISE EXCEPTION
                'user_current_balance ordinary table has an unknown catalog: columns=%, constraints=%, indexes=%, triggers=%, rules=%, policies=%, inheritance=%',
                column_signature, constraint_signatures, index_signatures, trigger_count,
                rule_count, policy_count, inheritance_count;
        END IF;
        IF EXISTS (SELECT 1 FROM user_current_balance) THEN
            RAISE EXCEPTION
                'nonempty user_current_balance cache table requires audited replacement before startup';
        END IF;
        DROP TABLE user_current_balance;
        relation_kind := NULL;
    ELSIF relation_kind IS NOT NULL AND relation_kind <> 'm' THEN
        RAISE EXCEPTION 'user_current_balance must be a materialized view, found relkind %',
            relation_kind;
    END IF;
    IF relation_kind IS NULL THEN
        EXECUTE $production_base_view$
            CREATE MATERIALIZED VIEW user_current_balance AS
            SELECT users.user_id,
                   users.balance AS stored_balance,
                   COALESCE(SUM(CASE
                       WHEN instances.activated_at IS NOT NULL
                        AND instances.stop_billing_at > NOW()
                        AND (users.permissions_bitmask & 16) <> 16
                       THEN EXTRACT(EPOCH FROM (
                           LEAST(COALESCE(instances.stop_billing_at, NOW()), NOW())
                           - instances.activated_at
                       )) / 3600.0 * instances.hourly_rate
                       ELSE 0
                   END), 0) AS total_instance_costs,
                   users.balance - COALESCE(SUM(CASE
                       WHEN instances.activated_at IS NOT NULL
                        AND instances.stop_billing_at > NOW()
                        AND (users.permissions_bitmask & 16) <> 16
                       THEN EXTRACT(EPOCH FROM (
                           LEAST(COALESCE(instances.stop_billing_at, NOW()), NOW())
                           - instances.activated_at
                       )) / 3600.0 * instances.hourly_rate
                       ELSE 0
                   END), 0) AS effective_balance
              FROM users
              LEFT JOIN instances ON instances.billed_to = users.user_id
             GROUP BY users.user_id, users.balance, users.permissions_bitmask
        $production_base_view$;
    END IF;
END
$production_base$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_current_balance_user_id
    ON user_current_balance (user_id);

DO $production_base$
DECLARE
    relation_kind "char";
BEGIN
    SELECT relation.relkind INTO relation_kind
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'daily_instance_revenue';
    IF relation_kind IS NOT NULL AND relation_kind <> 'm' THEN
        RAISE EXCEPTION 'daily_instance_revenue must be a materialized view, found relkind %',
            relation_kind;
    END IF;
    IF relation_kind IS NULL THEN
        EXECUTE $production_base_view$
            CREATE MATERIALIZED VIEW daily_instance_revenue AS
            WITH date_series AS (
                SELECT generate_series(
                    (SELECT MIN(DATE(activated_at)) FROM instance_audit
                      WHERE billed_to IS NOT NULL),
                    CURRENT_DATE,
                    '1 day'::INTERVAL
                )::DATE AS date
            ), instance_daily_costs AS (
                SELECT day.date, audit.instance_id, audit.billed_to, audit.hourly_rate,
                       CASE
                           WHEN DATE(audit.activated_at) < day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) > day.date THEN 24.0
                           WHEN DATE(audit.activated_at) = day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) = day.date
                           THEN EXTRACT(EPOCH FROM (
                               COALESCE(audit.stop_billing_at, NOW()) - audit.activated_at
                           )) / 3600.0
                           WHEN DATE(audit.activated_at) = day.date
                           THEN EXTRACT(EPOCH FROM (
                               date_trunc('day', audit.activated_at) + INTERVAL '1 day'
                               - audit.activated_at
                           )) / 3600.0
                           WHEN DATE(COALESCE(audit.stop_billing_at, NOW())) = day.date
                           THEN EXTRACT(EPOCH FROM (
                               COALESCE(audit.stop_billing_at, NOW())
                               - date_trunc('day', COALESCE(audit.stop_billing_at, NOW()))
                           )) / 3600.0
                           ELSE 0
                       END AS hours_on_day,
                       CASE
                           WHEN DATE(audit.activated_at) < day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) > day.date
                           THEN 24.0 * audit.hourly_rate
                           WHEN DATE(audit.activated_at) = day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) = day.date
                           THEN EXTRACT(EPOCH FROM (
                               COALESCE(audit.stop_billing_at, NOW()) - audit.activated_at
                           )) / 3600.0 * audit.hourly_rate
                           WHEN DATE(audit.activated_at) = day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) > day.date
                           THEN EXTRACT(EPOCH FROM (
                               date_trunc('day', audit.activated_at) + INTERVAL '1 day'
                               - audit.activated_at
                           )) / 3600.0 * audit.hourly_rate
                           WHEN DATE(audit.activated_at) < day.date
                            AND DATE(COALESCE(audit.stop_billing_at, NOW())) = day.date
                           THEN EXTRACT(EPOCH FROM (
                               COALESCE(audit.stop_billing_at, NOW())
                               - date_trunc('day', COALESCE(audit.stop_billing_at, NOW()))
                           )) / 3600.0 * audit.hourly_rate
                           ELSE 0
                       END AS daily_revenue
                  FROM date_series AS day
                  CROSS JOIN instance_audit AS audit
                 WHERE audit.billed_to IS NOT NULL
                   AND audit.deleted_at IS NULL
                   AND audit.activated_at IS NOT NULL
                   AND day.date >= DATE(audit.activated_at)
                   AND day.date <= DATE(COALESCE(audit.stop_billing_at, NOW()))
            )
            SELECT date, COUNT(DISTINCT instance_id) AS active_instance_count,
                   SUM(hours_on_day) AS total_instance_hours,
                   SUM(daily_revenue) AS instance_revenue
              FROM instance_daily_costs
             WHERE daily_revenue > 0
             GROUP BY date ORDER BY date DESC
        $production_base_view$;
    END IF;
END
$production_base$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_daily_instance_revenue_date
    ON daily_instance_revenue (date);

DO $production_base$
DECLARE
    relation_kind "char";
    definition_md5 TEXT;
    summary_comment TEXT;
BEGIN
    SELECT relation.relkind,
           md5(regexp_replace(
               replace(pg_get_viewdef(relation.oid, true), current_schema() || '.', ''),
               '[[:space:]]+', ' ', 'g'
           )),
           obj_description(relation.oid, 'pg_class')
      INTO relation_kind, definition_md5, summary_comment
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'daily_revenue_summary';
    IF relation_kind IS NOT NULL AND relation_kind <> 'm' THEN
        RAISE EXCEPTION 'daily_revenue_summary must be a materialized view, found relkind %',
            relation_kind;
    END IF;
    IF relation_kind = 'm'
       AND definition_md5 NOT IN (
           '1ead487721cab340a03ffc40397ea6e5',
           '28b48c70fa0ae3e981725220432a63e8'
       ) THEN
        RAISE EXCEPTION
            'daily_revenue_summary has an unknown definition and cannot be replaced: %',
            definition_md5;
    END IF;
    IF relation_kind = 'm'
       AND definition_md5 = '1ead487721cab340a03ffc40397ea6e5' THEN
        RAISE EXCEPTION
            'historical daily_revenue_summary is blocked until subscription_history catalog '
            'and producer provenance are pinned from an authoritative production snapshot';
    END IF;
    IF relation_kind = 'm'
       AND definition_md5 = '28b48c70fa0ae3e981725220432a63e8'
       AND summary_comment IS DISTINCT FROM
           'Compatibility cache only: current paid invocation-quota activations; '
           'not authoritative historical subscription revenue.' THEN
        RAISE EXCEPTION
            'quota-derived daily_revenue_summary is missing its approximation custody label';
    END IF;
    IF relation_kind IS NULL THEN
        EXECUTE $production_base_view$
            CREATE MATERIALIZED VIEW daily_revenue_summary AS
            SELECT COALESCE(subscription.date, paygo.date, instance.date, sponsored.date) AS date,
                   COALESCE(subscription.new_subscriber_count, 0) AS new_subscriber_count,
                   COALESCE(subscription.new_subscriber_revenue, 0) AS new_subscriber_revenue,
                   COALESCE(paygo.paygo_revenue, 0) AS paygo_revenue,
                   COALESCE(instance.instance_revenue, 0) AS instance_revenue,
                   COALESCE(sponsored.sponsored_inference, 0) AS sponsored_inference
              FROM (
                  SELECT DATE(COALESCE(effective_date, updated_at)) AS date,
                         COUNT(*) AS new_subscriber_count,
                         SUM(CASE
                             WHEN quota IN (300, 301) THEN 3
                             WHEN quota IN (2000, 2001) THEN 10
                             WHEN quota IN (5000, 5001) THEN 20
                             ELSE 0
                         END) AS new_subscriber_revenue
                    FROM invocation_quotas
                   WHERE chute_id = '*'
                     AND quota IN (300, 301, 2000, 2001, 5000, 5001)
                   GROUP BY DATE(COALESCE(effective_date, updated_at))
              ) AS subscription
              FULL OUTER JOIN (
                  SELECT DATE(bucket) AS date, SUM(amount) AS paygo_revenue
                    FROM usage_data
                   WHERE user_id <> '5682c3e0-3635-58f7-b7f5-694962450dfc'
                   GROUP BY DATE(bucket)
              ) AS paygo ON subscription.date = paygo.date
              FULL OUTER JOIN (
                  SELECT date, instance_revenue FROM daily_instance_revenue
              ) AS instance ON COALESCE(subscription.date, paygo.date) = instance.date
              FULL OUTER JOIN (
                  SELECT DATE(usage.bucket) AS date,
                         SUM(usage.amount) - MAX(sponsorship.daily_threshold)
                             AS sponsored_inference
                    FROM usage_data AS usage
                    JOIN inference_sponsorships AS sponsorship
                      ON usage.user_id = sponsorship.user_id
                     AND DATE(usage.bucket) >= sponsorship.start_date
                     AND (sponsorship.end_date IS NULL
                          OR DATE(usage.bucket) <= sponsorship.end_date)
                    JOIN sponsorship_chutes AS chute
                      ON chute.sponsorship_id = sponsorship.id
                     AND chute.chute_id = usage.chute_id
                   GROUP BY DATE(usage.bucket)
              ) AS sponsored
                ON COALESCE(subscription.date, paygo.date, instance.date) = sponsored.date
             ORDER BY date DESC
        $production_base_view$;
        COMMENT ON MATERIALIZED VIEW daily_revenue_summary IS
            'Compatibility cache only: current paid invocation-quota activations; '
            'not authoritative historical subscription revenue.';
    END IF;
END
$production_base$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_daily_revenue_summary_date
    ON daily_revenue_summary (date);

CREATE INDEX IF NOT EXISTS idx_user_fingerprint_hash ON users (fingerprint_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_aliases_user_alias_lower
    ON model_aliases (user_id, LOWER(alias));
DO $production_base$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = format('%I.model_aliases', current_schema())::regclass
           AND constraint_row.conname = 'alias_ascii_no_colon'
    ) THEN
        IF EXISTS (SELECT 1 FROM model_aliases WHERE alias !~ '^[\x21-\x39\x3B-\x7E]+$') THEN
            RAISE EXCEPTION 'model_aliases contains aliases outside the canonical ASCII contract';
        END IF;
        ALTER TABLE model_aliases ADD CONSTRAINT alias_ascii_no_colon
            CHECK (alias ~ '^[\x21-\x39\x3B-\x7E]+$');
    END IF;
END
$production_base$;

DROP TRIGGER IF EXISTS invocations_insert_trigger ON invocations;
CREATE TRIGGER invocations_insert_trigger
    INSTEAD OF INSERT ON invocations
    FOR EACH ROW EXECUTE FUNCTION insert_invocation();

DROP TRIGGER IF EXISTS after_chute_insert ON chutes;
CREATE TRIGGER after_chute_insert
    AFTER INSERT ON chutes
    FOR EACH ROW EXECUTE FUNCTION initialize_bounty();

DROP TRIGGER IF EXISTS tr_instance_audit_delete ON instances;
CREATE TRIGGER tr_instance_audit_delete
    BEFORE DELETE ON instances
    FOR EACH ROW EXECUTE FUNCTION fn_instance_audit_delete();
DROP TRIGGER IF EXISTS tr_instance_audit_insert ON instances;
CREATE TRIGGER tr_instance_audit_insert
    AFTER INSERT ON instances
    FOR EACH ROW EXECUTE FUNCTION fn_instance_audit_insert();
DROP TRIGGER IF EXISTS tr_instance_audit_update ON instances;
CREATE TRIGGER tr_instance_audit_update
    AFTER UPDATE ON instances
    FOR EACH ROW EXECUTE FUNCTION fn_instance_audit_update();

DROP TRIGGER IF EXISTS tr_ich_update ON instances;
CREATE TRIGGER tr_ich_update
    AFTER UPDATE ON instances
    FOR EACH ROW EXECUTE FUNCTION fn_instance_compute_history_update();
DROP TRIGGER IF EXISTS tr_ich_delete ON instances;
CREATE TRIGGER tr_ich_delete
    BEFORE DELETE ON instances
    FOR EACH ROW EXECUTE FUNCTION fn_instance_compute_history_delete();

DROP TRIGGER IF EXISTS tr_chute_history_insert ON chutes;
CREATE TRIGGER tr_chute_history_insert
    AFTER INSERT ON chutes
    FOR EACH ROW EXECUTE FUNCTION fn_chute_history_insert();
DROP TRIGGER IF EXISTS tr_chute_history_update ON chutes;
CREATE TRIGGER tr_chute_history_update
    AFTER UPDATE ON chutes
    FOR EACH ROW EXECUTE FUNCTION fn_chute_history_update();
DROP TRIGGER IF EXISTS tr_chute_history_delete ON chutes;
CREATE TRIGGER tr_chute_history_delete
    BEFORE DELETE ON chutes
    FOR EACH ROW EXECUTE FUNCTION fn_chute_history_delete();

DROP TRIGGER IF EXISTS tr_image_history_insert ON images;
CREATE TRIGGER tr_image_history_insert
    AFTER INSERT ON images
    FOR EACH ROW EXECUTE FUNCTION fn_image_history_insert();
DROP TRIGGER IF EXISTS tr_image_history_update ON images;
CREATE TRIGGER tr_image_history_update
    AFTER UPDATE ON images
    FOR EACH ROW EXECUTE FUNCTION fn_image_history_update();
DROP TRIGGER IF EXISTS tr_image_history_delete ON images;
CREATE TRIGGER tr_image_history_delete
    BEFORE DELETE ON images
    FOR EACH ROW EXECUTE FUNCTION fn_image_history_delete();

DROP TRIGGER IF EXISTS tr_node_history_insert ON nodes;
CREATE TRIGGER tr_node_history_insert
    AFTER INSERT ON nodes
    FOR EACH ROW EXECUTE FUNCTION fn_node_history_insert();
DROP TRIGGER IF EXISTS tr_node_history_delete ON nodes;
CREATE TRIGGER tr_node_history_delete
    BEFORE DELETE ON nodes
    FOR EACH ROW EXECUTE FUNCTION fn_node_history_delete();

DROP TRIGGER IF EXISTS track_instance_node_assignment_trigger ON instance_nodes;
CREATE TRIGGER track_instance_node_assignment_trigger
    AFTER INSERT ON instance_nodes
    FOR EACH ROW EXECUTE FUNCTION track_instance_node_assignment();

DROP TRIGGER IF EXISTS tr_reset_jobs_on_fail ON launch_configs;
CREATE TRIGGER tr_reset_jobs_on_fail
    AFTER UPDATE ON launch_configs
    FOR EACH ROW EXECUTE FUNCTION fn_reset_job_assignment();

DROP TRIGGER IF EXISTS trigger_update_balance_on_delete ON instances;
CREATE TRIGGER trigger_update_balance_on_delete
    BEFORE DELETE ON instances
    FOR EACH ROW EXECUTE FUNCTION update_balance_on_instance_delete();

-- The reports subsystem caller was intentionally deleted in e64506a.  Preserve any legacy
-- database helper as unowned evidence until an explicit audited retirement migration.

DO $production_base$
DECLARE
    mismatch TEXT;
BEGIN
    WITH expected(name, kind) AS (
        VALUES
            ('audit_entries', 'r'::"char"),
            ('bounties', 'r'::"char"),
            ('bounty_history', 'r'::"char"),
            ('chute_manual_boosts', 'r'::"char"),
            ('instance_audit', 'r'::"char"),
            ('instance_compute_history', 'r'::"char"),
            ('partitioned_invocations', 'p'::"char"),
            ('invocations', 'v'::"char"),
            ('node_history', 'r'::"char"),
            ('instance_node_history', 'r'::"char"),
            ('p_llm_metrics', 'p'::"char"),
            ('vllm_metrics', 'r'::"char"),
            ('diffusion_metrics', 'r'::"char"),
            ('inference_sponsorships', 'r'::"char"),
            ('sponsorship_chutes', 'r'::"char"),
            ('user_current_balance', 'm'::"char"),
            ('daily_instance_revenue', 'm'::"char"),
            ('daily_revenue_summary', 'm'::"char")
    ), actual AS (
        SELECT relation.relname AS name, relation.relkind AS kind
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = current_schema()
    )
    SELECT string_agg(expected.name || ': expected ' || expected.kind::TEXT
        || ', got ' || COALESCE(actual.kind::TEXT, '<missing>'), ', ' ORDER BY expected.name)
      INTO mismatch
      FROM expected LEFT JOIN actual USING (name)
     WHERE actual.kind IS DISTINCT FROM expected.kind;
    IF mismatch IS NOT NULL THEN
        RAISE EXCEPTION 'production-base relation kind mismatch: %', mismatch;
    END IF;

    IF pg_get_partkeydef(format('%I.partitioned_invocations', current_schema())::regclass)
           IS DISTINCT FROM 'RANGE (started_at)'
       OR pg_get_partkeydef(format('%I.p_llm_metrics', current_schema())::regclass)
           IS DISTINCT FROM 'RANGE (date)'
    THEN
        RAISE EXCEPTION 'production-base partition key mismatch';
    END IF;

    IF pg_get_serial_sequence(
        format('%I.instance_compute_history', current_schema()), 'id'
    ) IS DISTINCT FROM format('%I.instance_compute_history_id_seq', current_schema()) THEN
        RAISE EXCEPTION 'instance_compute_history sequence is not owned by id';
    END IF;
END
$production_base$;

DO $production_base$
DECLARE
    mismatch TEXT;
BEGIN
    WITH expected(trigger_name, table_name, function_name) AS (
        VALUES
            ('invocations_insert_trigger', 'invocations', 'insert_invocation'),
            ('after_chute_insert', 'chutes', 'initialize_bounty'),
            ('tr_instance_audit_delete', 'instances', 'fn_instance_audit_delete'),
            ('tr_instance_audit_insert', 'instances', 'fn_instance_audit_insert'),
            ('tr_instance_audit_update', 'instances', 'fn_instance_audit_update'),
            ('tr_ich_update', 'instances', 'fn_instance_compute_history_update'),
            ('tr_ich_delete', 'instances', 'fn_instance_compute_history_delete'),
            ('tr_chute_history_insert', 'chutes', 'fn_chute_history_insert'),
            ('tr_chute_history_update', 'chutes', 'fn_chute_history_update'),
            ('tr_chute_history_delete', 'chutes', 'fn_chute_history_delete'),
            ('tr_image_history_insert', 'images', 'fn_image_history_insert'),
            ('tr_image_history_update', 'images', 'fn_image_history_update'),
            ('tr_image_history_delete', 'images', 'fn_image_history_delete'),
            ('tr_node_history_insert', 'nodes', 'fn_node_history_insert'),
            ('tr_node_history_delete', 'nodes', 'fn_node_history_delete'),
            ('track_instance_node_assignment_trigger', 'instance_nodes',
                'track_instance_node_assignment'),
            ('tr_reset_jobs_on_fail', 'launch_configs', 'fn_reset_job_assignment'),
            ('trigger_update_balance_on_delete', 'instances',
                'update_balance_on_instance_delete')
    ), actual AS (
        SELECT trigger_row.tgname AS trigger_name,
               relation.relname AS table_name,
               procedure.proname AS function_name,
               trigger_row.tgenabled
          FROM pg_trigger AS trigger_row
          JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_proc AS procedure ON procedure.oid = trigger_row.tgfoid
         WHERE namespace.nspname = current_schema() AND NOT trigger_row.tgisinternal
    )
    SELECT string_agg(expected.trigger_name, ', ' ORDER BY expected.trigger_name)
      INTO mismatch
      FROM expected LEFT JOIN actual USING (trigger_name, table_name, function_name)
     WHERE actual.trigger_name IS NULL OR actual.tgenabled <> 'O';
    IF mismatch IS NOT NULL THEN
        RAISE EXCEPTION 'production-base trigger mismatch: %', mismatch;
    END IF;
END
$production_base$;
