-- migrate:up

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'gpu_launch_reservations'
          AND column_name = 'descriptor_closure_sha256'
    ) AND EXISTS (
        SELECT 1
        FROM gpu_launch_reservations
        WHERE management_mode = 'platform'
    ) THEN
        RAISE EXCEPTION
            'cannot migrate pre-closure platform GPU reservations; retire them before upgrade';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'gpu_launch_reservations'
          AND column_name = 'workload_identity'
    ) AND EXISTS (
        SELECT 1
        FROM gpu_launch_reservations
        WHERE management_mode = 'platform'
    ) THEN
        RAISE EXCEPTION
            'cannot migrate pre-identity platform GPU reservations; retire them before upgrade';
    END IF;
END
$$;

ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS descriptor_closure_sha256 TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS chute_version TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS workload_identity JSONB;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS workload_identity_sha256 TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS allowed_manifests JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS allowed_blobs JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS allowed_manifest_tags JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS manifest_tag_digests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS manifest_tag_digests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS ck_registry_session_closure;
ALTER TABLE registry_sessions
    ADD CONSTRAINT ck_registry_session_closure CHECK (
        jsonb_typeof(allowed_manifests) = 'array'
        AND jsonb_typeof(allowed_blobs) = 'array'
        AND jsonb_typeof(allowed_manifest_tags) = 'array'
        AND jsonb_typeof(manifest_tag_digests) = 'object'
        AND (
            descriptor_closure_sha256 IS NULL
            OR descriptor_closure_sha256 ~ '^[0-9a-f]{64}$'
        )
    );
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS launch_command_id TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS launch_dispatched_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS launch_ack_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS launch_ack_status TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS launch_ack_detail TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS workload_dispatched_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS workload_command_id TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_command_id TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_dispatched_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_requested_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_reason TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_ack_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_ack_status TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS teardown_ack_detail TEXT;
ALTER TABLE gpu_launch_reservations
    ADD COLUMN IF NOT EXISTS last_reconciled_at TIMESTAMPTZ;
ALTER TABLE gpu_launch_reservations
    DROP CONSTRAINT IF EXISTS ck_gpu_launch_descriptor_closure;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT ck_gpu_launch_descriptor_closure CHECK (
        (
            management_mode = 'platform'
            AND chute_version IS NOT NULL
            AND jsonb_typeof(workload_identity) = 'object'
            AND workload_identity_sha256 ~ '^[0-9a-f]{64}$'
            AND descriptor_closure_sha256 ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(allowed_manifests) = 'array'
            AND jsonb_array_length(allowed_manifests) > 0
            AND jsonb_typeof(allowed_blobs) = 'array'
            AND jsonb_array_length(allowed_blobs) > 0
            AND jsonb_typeof(allowed_manifest_tags) = 'array'
            AND jsonb_array_length(allowed_manifest_tags) > 0
            AND jsonb_typeof(manifest_tag_digests) = 'object'
            AND manifest_tag_digests <> '{}'::jsonb
        )
        OR
        (
            management_mode = 'miner'
            AND chute_version IS NULL
            AND workload_identity IS NULL
            AND workload_identity_sha256 IS NULL
            AND descriptor_closure_sha256 IS NULL
            AND allowed_manifests = '[]'::jsonb
            AND allowed_blobs = '[]'::jsonb
            AND allowed_manifest_tags = '[]'::jsonb
            AND manifest_tag_digests = '{}'::jsonb
        )
    );
ALTER TABLE gpu_launch_reservations
    DROP CONSTRAINT IF EXISTS ck_gpu_launch_command_ack;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT ck_gpu_launch_command_ack CHECK (
        (launch_ack_at IS NULL AND launch_ack_status IS NULL AND launch_ack_detail IS NULL)
        OR
        (
            launch_command_id IS NOT NULL
            AND launch_dispatched_at IS NOT NULL
            AND launch_ack_at IS NOT NULL
            AND launch_ack_status IS NOT NULL
        )
    );
ALTER TABLE gpu_launch_reservations
    DROP CONSTRAINT IF EXISTS ck_gpu_teardown_command_ack;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT ck_gpu_teardown_command_ack CHECK (
        (
            teardown_requested_at IS NULL
            AND teardown_command_id IS NULL
            AND teardown_dispatched_at IS NULL
            AND teardown_reason IS NULL
            AND teardown_ack_at IS NULL
            AND teardown_ack_status IS NULL
            AND teardown_ack_detail IS NULL
        )
        OR
        (
            teardown_requested_at IS NOT NULL
            AND teardown_reason IS NOT NULL
            AND (
                (
                    teardown_command_id IS NULL
                    AND teardown_dispatched_at IS NULL
                    AND teardown_ack_at IS NULL
                    AND teardown_ack_status IS NULL
                    AND teardown_ack_detail IS NULL
                )
                OR
                (
                    teardown_command_id IS NOT NULL
                    AND teardown_dispatched_at IS NOT NULL
                    AND teardown_ack_at IS NOT NULL
                    AND teardown_ack_status IS NOT NULL
                )
                OR
                (
                    teardown_command_id IS NOT NULL
                    AND teardown_dispatched_at IS NOT NULL
                    AND teardown_ack_at IS NULL
                    AND teardown_ack_status IS NULL
                    AND teardown_ack_detail IS NULL
                )
            )
        )
    );
CREATE INDEX IF NOT EXISTS idx_gpu_launch_reservations_platform_workload
    ON gpu_launch_reservations (management_mode, chute_id, job_id, state);

ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS gpu_management_mode VARCHAR;
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR;
ALTER TABLE launch_configs
    DROP CONSTRAINT IF EXISTS ck_launch_config_gpu_manager;
ALTER TABLE launch_configs
    ADD CONSTRAINT ck_launch_config_gpu_manager CHECK (
        (
            gpu_management_mode IS NULL
            AND gpu_launch_reservation_id IS NULL
        )
        OR
        (
            gpu_management_mode IN ('platform', 'miner')
            AND gpu_launch_reservation_id IS NOT NULL
            AND server_id IS NOT NULL
        )
    );
ALTER TABLE launch_configs DROP CONSTRAINT IF EXISTS uq_job_launch_config;
DROP INDEX IF EXISTS uq_job_launch_config_active;
CREATE UNIQUE INDEX uq_job_launch_config_active
    ON launch_configs (job_id)
    WHERE job_id IS NOT NULL AND failed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_launch_configs_gpu_reservation
    ON launch_configs (gpu_launch_reservation_id)
    WHERE gpu_launch_reservation_id IS NOT NULL
      AND gpu_management_mode = 'platform';

ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS gpu_management_mode VARCHAR;
ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR;
ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_id VARCHAR;
ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_launch_configs_gpu_launch_reservation'
          AND conrelid = 'launch_configs'::regclass
    ) THEN
        ALTER TABLE launch_configs
            ADD CONSTRAINT fk_launch_configs_gpu_launch_reservation
            FOREIGN KEY (gpu_launch_reservation_id)
            REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_instances_gpu_launch_reservation'
          AND conrelid = 'instances'::regclass
    ) THEN
        ALTER TABLE instances
            ADD CONSTRAINT fk_instances_gpu_launch_reservation
            FOREIGN KEY (gpu_launch_reservation_id)
            REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_instances_gpu_allocation_group'
          AND conrelid = 'instances'::regclass
    ) THEN
        ALTER TABLE instances
            ADD CONSTRAINT fk_instances_gpu_allocation_group
            FOREIGN KEY (gpu_allocation_group_id)
            REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT;
    END IF;
END
$$;
ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS gpu_process_incarnation VARCHAR;
ALTER TABLE instances DROP CONSTRAINT IF EXISTS ck_instances_gpu_manager;
ALTER TABLE instances
    ADD CONSTRAINT ck_instances_gpu_manager CHECK (
        (
            gpu_management_mode IS NULL
            AND gpu_launch_reservation_id IS NULL
            AND gpu_allocation_group_id IS NULL
            AND gpu_allocation_group_generation IS NULL
            AND gpu_process_incarnation IS NULL
        )
        OR
        (
            gpu_management_mode IN ('platform', 'miner')
            AND gpu_launch_reservation_id IS NOT NULL
            AND gpu_allocation_group_id IS NOT NULL
            AND gpu_allocation_group_generation > 0
            AND gpu_process_incarnation IS NOT NULL
            AND server_id IS NOT NULL
        )
    );
CREATE UNIQUE INDEX IF NOT EXISTS uq_instances_gpu_reservation
    ON instances (gpu_launch_reservation_id)
    WHERE gpu_launch_reservation_id IS NOT NULL
      AND gpu_management_mode = 'platform';

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS gpu_management_mode VARCHAR;
ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR
        REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS ck_jobs_gpu_manager;
ALTER TABLE jobs
    ADD CONSTRAINT ck_jobs_gpu_manager CHECK (
        (
            gpu_management_mode IS NULL
            AND gpu_launch_reservation_id IS NULL
        )
        OR
        (
            gpu_management_mode IN ('platform', 'miner')
            AND gpu_launch_reservation_id IS NOT NULL
        )
    );

ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_evidence JSONB;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_evidence_sha256 VARCHAR(64);
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_evidence_certificate_sha256s JSONB;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_id VARCHAR
        REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_host_boot_generation INTEGER;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_reservation_generation INTEGER;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_management_mode VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_process_incarnation VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_topology_fingerprint VARCHAR(64);
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_release_id VARCHAR REFERENCES guest_releases(release_id) ON DELETE RESTRICT;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_profile_id VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_chute_id VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_job_id VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_claims_sha256 VARCHAR(64);
ALTER TABLE server_attestations DROP CONSTRAINT IF EXISTS ck_server_attestation_gpu_lineage;
ALTER TABLE server_attestations
    ADD CONSTRAINT ck_server_attestation_gpu_lineage CHECK (
        (
            gpu_launch_reservation_id IS NULL
            AND gpu_allocation_group_id IS NULL
            AND gpu_allocation_group_generation IS NULL
            AND gpu_host_boot_generation IS NULL
            AND gpu_reservation_generation IS NULL
            AND gpu_management_mode IS NULL
            AND gpu_process_incarnation IS NULL
            AND gpu_topology_fingerprint IS NULL
            AND gpu_release_id IS NULL
            AND gpu_profile_id IS NULL
            AND gpu_chute_id IS NULL
            AND gpu_job_id IS NULL
            AND gpu_claims_sha256 IS NULL
            AND gpu_evidence IS NULL
            AND gpu_evidence_sha256 IS NULL
            AND gpu_evidence_certificate_sha256s IS NULL
        )
        OR
        (
            gpu_launch_reservation_id IS NOT NULL
            AND gpu_allocation_group_id IS NOT NULL
            AND gpu_allocation_group_generation > 0
            AND gpu_host_boot_generation > 0
            AND gpu_reservation_generation > 0
            AND gpu_management_mode IN ('platform', 'miner')
            AND gpu_process_incarnation IS NOT NULL
            AND gpu_topology_fingerprint ~ '^[0-9a-f]{64}$'
            AND gpu_release_id IS NOT NULL
            AND gpu_profile_id IS NOT NULL
            AND gpu_claims_sha256 ~ '^[0-9a-f]{64}$'
            AND gpu_evidence IS NOT NULL
            AND gpu_evidence_sha256 ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(gpu_evidence_certificate_sha256s) = 'array'
            AND (
                verification_error IS NOT NULL
                OR jsonb_array_length(gpu_evidence_certificate_sha256s) > 0
            )
        )
    );
CREATE INDEX IF NOT EXISTS idx_server_attestations_gpu_lineage
    ON server_attestations (
        gpu_launch_reservation_id,
        gpu_allocation_group_id,
        attempt_sequence DESC
    )
    WHERE gpu_launch_reservation_id IS NOT NULL;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_runtime_session_attestation_id VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_runtime_session_expires_at TIMESTAMPTZ;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_gpu_runtime_session;
ALTER TABLE servers
    ADD CONSTRAINT ck_servers_gpu_runtime_session CHECK (
        (
            gpu_runtime_session_attestation_id IS NULL
            AND gpu_runtime_session_expires_at IS NULL
        )
        OR
        (
            gpu_launch_reservation_id IS NOT NULL
            AND gpu_runtime_session_attestation_id IS NOT NULL
            AND gpu_runtime_session_expires_at IS NOT NULL
        )
    );

-- migrate:down

-- Refuse a lossy rollback before changing any catalog object. The locks close the
-- check-to-DDL race and deliberately follow one fixed cross-table order.
LOCK TABLE gpu_launch_reservations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE instances IN ACCESS EXCLUSIVE MODE;
LOCK TABLE jobs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE launch_configs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE registry_sessions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE server_attestations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE servers IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM servers
         WHERE gpu_runtime_session_attestation_id IS NOT NULL
            OR gpu_runtime_session_expires_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1
          FROM server_attestations
         WHERE gpu_evidence IS NOT NULL
            OR gpu_evidence_sha256 IS NOT NULL
            OR gpu_evidence_certificate_sha256s IS NOT NULL
            OR gpu_launch_reservation_id IS NOT NULL
            OR gpu_allocation_group_id IS NOT NULL
            OR gpu_allocation_group_generation IS NOT NULL
            OR gpu_host_boot_generation IS NOT NULL
            OR gpu_reservation_generation IS NOT NULL
            OR gpu_management_mode IS NOT NULL
            OR gpu_process_incarnation IS NOT NULL
            OR gpu_topology_fingerprint IS NOT NULL
            OR gpu_release_id IS NOT NULL
            OR gpu_profile_id IS NOT NULL
            OR gpu_chute_id IS NOT NULL
            OR gpu_job_id IS NOT NULL
            OR gpu_claims_sha256 IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM jobs
         WHERE gpu_management_mode IS NOT NULL
            OR gpu_launch_reservation_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM instances
         WHERE gpu_management_mode IS NOT NULL
            OR gpu_launch_reservation_id IS NOT NULL
            OR gpu_allocation_group_id IS NOT NULL
            OR gpu_allocation_group_generation IS NOT NULL
            OR gpu_process_incarnation IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM launch_configs
         WHERE gpu_management_mode IS NOT NULL
            OR gpu_launch_reservation_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM registry_sessions
         WHERE manifest_tag_digests <> '{}'::jsonb
    ) OR EXISTS (
        SELECT 1 FROM gpu_launch_reservations
         WHERE chute_version IS NOT NULL
            OR workload_identity IS NOT NULL
            OR workload_identity_sha256 IS NOT NULL
            OR descriptor_closure_sha256 IS NOT NULL
            OR allowed_manifests <> '[]'::jsonb
            OR allowed_blobs <> '[]'::jsonb
            OR allowed_manifest_tags <> '[]'::jsonb
            OR manifest_tag_digests <> '{}'::jsonb
            OR launch_command_id IS NOT NULL
            OR launch_dispatched_at IS NOT NULL
            OR launch_ack_at IS NOT NULL
            OR launch_ack_status IS NOT NULL
            OR launch_ack_detail IS NOT NULL
            OR workload_dispatched_at IS NOT NULL
            OR workload_command_id IS NOT NULL
            OR teardown_command_id IS NOT NULL
            OR teardown_dispatched_at IS NOT NULL
            OR teardown_requested_at IS NOT NULL
            OR teardown_reason IS NOT NULL
            OR teardown_ack_at IS NOT NULL
            OR teardown_ack_status IS NOT NULL
            OR teardown_ack_detail IS NOT NULL
            OR last_reconciled_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM launch_configs
         WHERE job_id IS NOT NULL
         GROUP BY job_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot roll back GPU platform scheduler migration while migration-owned state exists';
    END IF;
END
$$;

ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_gpu_runtime_session;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_runtime_session_expires_at;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_runtime_session_attestation_id;
ALTER TABLE server_attestations DROP CONSTRAINT IF EXISTS ck_server_attestation_gpu_lineage;
DROP INDEX IF EXISTS idx_server_attestations_gpu_lineage;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_claims_sha256;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_job_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_chute_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_profile_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_release_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_topology_fingerprint;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_process_incarnation;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_management_mode;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_reservation_generation;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_host_boot_generation;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_launch_reservation_id;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_evidence_certificate_sha256s;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_evidence_sha256;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_evidence;

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS ck_jobs_gpu_manager;
ALTER TABLE jobs DROP COLUMN IF EXISTS gpu_launch_reservation_id;
ALTER TABLE jobs DROP COLUMN IF EXISTS gpu_management_mode;

DROP INDEX IF EXISTS uq_instances_gpu_reservation;
ALTER TABLE instances DROP CONSTRAINT IF EXISTS ck_instances_gpu_manager;
ALTER TABLE instances DROP COLUMN IF EXISTS gpu_process_incarnation;
ALTER TABLE instances DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE instances DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE instances DROP COLUMN IF EXISTS gpu_launch_reservation_id;
ALTER TABLE instances DROP COLUMN IF EXISTS gpu_management_mode;

DROP INDEX IF EXISTS uq_launch_configs_gpu_reservation;
DROP INDEX IF EXISTS uq_job_launch_config_active;
ALTER TABLE launch_configs
    ADD CONSTRAINT uq_job_launch_config UNIQUE (job_id);
ALTER TABLE launch_configs DROP CONSTRAINT IF EXISTS ck_launch_config_gpu_manager;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS gpu_launch_reservation_id;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS gpu_management_mode;

DROP INDEX IF EXISTS idx_gpu_launch_reservations_platform_workload;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS ck_gpu_teardown_command_ack;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS ck_gpu_launch_command_ack;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS ck_gpu_launch_descriptor_closure;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS last_reconciled_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_ack_detail;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_ack_status;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_ack_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_reason;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_requested_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_command_id;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS teardown_dispatched_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS workload_command_id;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS workload_dispatched_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS launch_ack_detail;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS launch_ack_status;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS launch_ack_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS launch_dispatched_at;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS launch_command_id;
ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS ck_registry_session_closure;
ALTER TABLE registry_sessions
    ADD CONSTRAINT ck_registry_session_closure CHECK (
        jsonb_typeof(allowed_manifests) = 'array'
        AND jsonb_typeof(allowed_blobs) = 'array'
        AND jsonb_typeof(allowed_manifest_tags) = 'array'
        AND (
            descriptor_closure_sha256 IS NULL
            OR descriptor_closure_sha256 ~ '^[0-9a-f]{64}$'
        )
    );
ALTER TABLE registry_sessions DROP COLUMN IF EXISTS manifest_tag_digests;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS manifest_tag_digests;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS allowed_manifest_tags;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS allowed_blobs;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS allowed_manifests;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS descriptor_closure_sha256;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS workload_identity_sha256;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS workload_identity;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS chute_version;
