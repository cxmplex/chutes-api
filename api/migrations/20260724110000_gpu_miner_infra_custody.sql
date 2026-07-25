-- migrate:up

CREATE TABLE IF NOT EXISTS gpu_miner_identities (
    host_id TEXT PRIMARY KEY REFERENCES hosts(host_id) ON DELETE RESTRICT,
    server_id TEXT NOT NULL UNIQUE,
    owner_hotkey TEXT NOT NULL,
    legacy_vm_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS gpu_legacy_cutover_authorizations (
    authorization_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    owner_hotkey TEXT NOT NULL,
    legacy_server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    legacy_vm_name TEXT NOT NULL,
    target_server_id TEXT NOT NULL,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    migration_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gpu_legacy_cutover_source UNIQUE (legacy_server_id),
    CONSTRAINT uq_gpu_legacy_cutover_target UNIQUE (target_server_id),
    CONSTRAINT ck_gpu_legacy_cutover_state CHECK (
        (state = 'issued' AND consumed_at IS NULL AND migration_id IS NULL)
        OR
        (state = 'consumed' AND consumed_at IS NOT NULL AND migration_id IS NOT NULL)
    ),
    CONSTRAINT ck_gpu_legacy_cutover_hash CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

ALTER TABLE gpu_launch_reservations ADD COLUMN IF NOT EXISTS legacy_vm_name TEXT;
ALTER TABLE gpu_launch_reservations ADD COLUMN IF NOT EXISTS legacy_migration_id TEXT;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS ck_gpu_launch_workload;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT ck_gpu_launch_workload CHECK (
        (
            management_mode = 'platform'
            AND legacy_vm_name IS NULL
            AND legacy_migration_id IS NULL
            AND chute_id IS NOT NULL
            AND chute_version IS NOT NULL
            AND container_repository IS NOT NULL
            AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
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
            AND ((legacy_vm_name IS NULL AND legacy_migration_id IS NULL)
                 OR (legacy_vm_name IS NOT NULL AND legacy_migration_id IS NOT NULL))
            AND chute_id IS NULL
            AND job_id IS NULL
            AND chute_version IS NULL
            AND container_repository IS NULL
            AND container_manifest_digest IS NULL
            AND descriptor_closure_sha256 IS NULL
            AND allowed_manifests = '[]'::jsonb
            AND allowed_blobs = '[]'::jsonb
            AND allowed_manifest_tags = '[]'::jsonb
            AND manifest_tag_digests = '{}'::jsonb
        )
    );

-- One immutable record owns both actual legacy sources: the XFS `storage`
-- filesystem containing k3s/kubelet/control state and the separate `tdx-cache`
-- filesystem containing PostgreSQL. Keys are removed from vm_cache_configs when
-- the old attested guest closes, so no old/new reader can obtain them concurrently.
CREATE TABLE IF NOT EXISTS gpu_legacy_migrations (
    migration_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    owner_hotkey TEXT NOT NULL,
    legacy_server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE RESTRICT,
    legacy_vm_name TEXT NOT NULL,
    target_server_id TEXT NOT NULL,
    state TEXT NOT NULL,
    close_attestation_id TEXT NOT NULL REFERENCES server_attestations(attestation_id) ON DELETE RESTRICT,
    close_cert_hash TEXT NOT NULL,
    storage_luks_uuid TEXT NOT NULL,
    storage_filesystem_uuid TEXT NOT NULL,
    storage_generation INTEGER NOT NULL,
    storage_current_passphrase TEXT,
    storage_pending_passphrase TEXT,
    storage_lease JSONB,
    cache_luks_uuid TEXT NOT NULL,
    cache_filesystem_uuid TEXT NOT NULL,
    cache_filesystem_type TEXT NOT NULL,
    cache_generation INTEGER NOT NULL,
    cache_current_passphrase TEXT,
    cache_pending_passphrase TEXT,
    cache_lease JSONB,
    k3s_encryption_key TEXT,
    postgres_password TEXT,
    required_entries JSONB NOT NULL,
    optional_entries JSONB NOT NULL,
    guest_closed_at TIMESTAMPTZ NOT NULL,
    host_confirmed_at TIMESTAMPTZ,
    source_capability_hash TEXT,
    source_capability_expires_at TIMESTAMPTZ,
    source_capability_consumed_at TIMESTAMPTZ,
    promoted_marker_sha256 TEXT,
    promoted_summary JSONB,
    promoted_at TIMESTAMPTZ,
    discarded_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gpu_legacy_migration_source UNIQUE (owner_hotkey, legacy_server_id),
    CONSTRAINT uq_gpu_legacy_migration_target UNIQUE (target_server_id),
    CONSTRAINT ck_gpu_legacy_migration_state CHECK (
        state IN ('guest_closed', 'ready', 'leased', 'promoted', 'completed', 'abandoned')
    ),
    CONSTRAINT ck_gpu_legacy_migration_digests CHECK (
        close_cert_hash ~ '^[0-9a-f]{64}$'
        AND storage_luks_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND storage_filesystem_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND cache_luks_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND cache_filesystem_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND (source_capability_hash IS NULL OR source_capability_hash ~ '^[0-9a-f]{64}$')
        AND (promoted_marker_sha256 IS NULL OR promoted_marker_sha256 ~ '^[0-9a-f]{64}$')
        AND cache_filesystem_type IN ('xfs', 'ext4')
    ),
    CONSTRAINT ck_gpu_legacy_migration_generations CHECK (
        storage_generation >= 0 AND cache_generation >= 0
    ),
    CONSTRAINT ck_gpu_legacy_migration_entries CHECK (
        jsonb_typeof(required_entries) = 'array'
        AND jsonb_array_length(required_entries) > 0
        AND jsonb_typeof(optional_entries) = 'array'
    ),
    CONSTRAINT ck_gpu_legacy_migration_progress CHECK (
        (state = 'guest_closed' AND host_confirmed_at IS NULL)
        OR
        (state IN ('ready', 'leased') AND host_confirmed_at IS NOT NULL)
        OR
        (state = 'promoted' AND promoted_at IS NOT NULL
         AND promoted_marker_sha256 IS NOT NULL AND promoted_summary IS NOT NULL)
        OR
        (state = 'completed' AND promoted_at IS NOT NULL
         AND discarded_at IS NOT NULL AND completed_at IS NOT NULL
         AND storage_current_passphrase IS NULL
         AND storage_pending_passphrase IS NULL
         AND storage_lease IS NULL
         AND cache_current_passphrase IS NULL
         AND cache_pending_passphrase IS NULL
         AND cache_lease IS NULL
         AND k3s_encryption_key IS NULL
         AND postgres_password IS NULL
         AND source_capability_hash IS NULL
         AND source_capability_expires_at IS NULL)
        OR state = 'abandoned'
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_legacy_migrations_host_state
    ON gpu_legacy_migrations (host_id, state);
ALTER TABLE gpu_legacy_cutover_authorizations
    DROP CONSTRAINT IF EXISTS fk_gpu_legacy_cutover_migration;
ALTER TABLE gpu_legacy_cutover_authorizations
    ADD CONSTRAINT fk_gpu_legacy_cutover_migration
    FOREIGN KEY (migration_id)
    REFERENCES gpu_legacy_migrations(migration_id)
    ON DELETE RESTRICT;

ALTER TABLE gpu_launch_reservations
    DROP CONSTRAINT IF EXISTS fk_gpu_launch_legacy_migration;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT fk_gpu_launch_legacy_migration
    FOREIGN KEY (legacy_migration_id)
    REFERENCES gpu_legacy_migrations(migration_id)
    ON DELETE RESTRICT;

CREATE TABLE IF NOT EXISTS gpu_infra_custodies (
    server_id TEXT PRIMARY KEY REFERENCES servers(server_id) ON DELETE RESTRICT,
    owner_hotkey TEXT NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_boot_generation INTEGER NOT NULL,
    reservation_id TEXT NOT NULL REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT,
    reservation_generation INTEGER NOT NULL,
    allocation_group_id TEXT NOT NULL REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    management_mode TEXT NOT NULL,
    volume_name TEXT NOT NULL DEFAULT 'gpu-infra',
    current_passphrase TEXT,
    pending_passphrase TEXT,
    retiring_passphrase TEXT,
    retiring_key_slot INTEGER,
    k3s_encryption_key TEXT NOT NULL,
    confirmed_generation INTEGER NOT NULL DEFAULT 0,
    active_key_slot INTEGER,
    pending_key_slot INTEGER,
    lease_id TEXT,
    lease_generation INTEGER,
    lease_expires_at TIMESTAMPTZ,
    lease_attestation_id TEXT REFERENCES server_attestations(attestation_id) ON DELETE RESTRICT,
    lease_cert_hash TEXT,
    lease_session_jti TEXT,
    pending_marker_sha256 TEXT,
    state TEXT NOT NULL DEFAULT 'current',
    rollback_generation INTEGER,
    rollback_key_slot INTEGER,
    rollback_passphrase TEXT,
    sealed_at TIMESTAMPTZ,
    guest_closed_generation INTEGER,
    guest_closed_at TIMESTAMPTZ,
    migration_id TEXT UNIQUE REFERENCES gpu_legacy_migrations(migration_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_gpu_infra_mode CHECK (management_mode = 'miner' AND volume_name = 'gpu-infra'),
    CONSTRAINT ck_gpu_infra_generations CHECK (
        host_boot_generation > 0
        AND reservation_generation > 0
        AND allocation_group_generation > 0
        AND confirmed_generation >= 0
        AND (lease_generation IS NULL OR lease_generation = confirmed_generation + 1)
        AND (rollback_generation IS NULL OR rollback_generation = confirmed_generation + 1)
        AND (guest_closed_generation IS NULL OR guest_closed_generation = confirmed_generation)
    ),
    CONSTRAINT ck_gpu_infra_slots CHECK (
        (active_key_slot IS NULL OR active_key_slot BETWEEN 0 AND 7)
        AND (pending_key_slot IS NULL OR pending_key_slot BETWEEN 0 AND 7)
        AND (retiring_key_slot IS NULL OR retiring_key_slot BETWEEN 0 AND 7)
        AND (rollback_key_slot IS NULL OR rollback_key_slot BETWEEN 0 AND 7)
        AND (active_key_slot IS NULL OR pending_key_slot IS NULL OR active_key_slot <> pending_key_slot)
    ),
    CONSTRAINT ck_gpu_infra_state CHECK (
        state IN ('current', 'leased', 'awaiting_ack', 'sealed', 'conflict')
    ),
    CONSTRAINT ck_gpu_infra_lease_shape CHECK (
        (
            state IN ('leased', 'awaiting_ack')
            AND pending_passphrase IS NOT NULL
            AND pending_key_slot IS NOT NULL
            AND lease_id IS NOT NULL
            AND lease_generation = confirmed_generation + 1
            AND lease_expires_at IS NOT NULL
            AND lease_attestation_id IS NOT NULL
            AND lease_cert_hash ~ '^[0-9a-f]{64}$'
            AND lease_session_jti IS NOT NULL
            AND (pending_marker_sha256 IS NULL OR pending_marker_sha256 ~ '^[0-9a-f]{64}$')
        )
        OR
        (
            state IN ('current', 'sealed', 'conflict')
            AND pending_passphrase IS NULL
            AND pending_key_slot IS NULL
            AND lease_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND lease_attestation_id IS NULL
            AND lease_cert_hash IS NULL
            AND lease_session_jti IS NULL
            AND pending_marker_sha256 IS NULL
        )
    ),
    CONSTRAINT ck_gpu_infra_rollback_shape CHECK (
        (rollback_generation IS NULL AND rollback_key_slot IS NULL AND rollback_passphrase IS NULL)
        OR
        (rollback_generation = confirmed_generation + 1
         AND rollback_key_slot IS NOT NULL AND rollback_passphrase IS NOT NULL)
    ),
    CONSTRAINT ck_gpu_infra_seal_shape CHECK (
        (state = 'sealed' AND sealed_at IS NOT NULL)
        OR (state <> 'sealed' AND sealed_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_infra_host
    ON gpu_infra_custodies (host_id, allocation_group_id, allocation_group_generation);
CREATE INDEX IF NOT EXISTS idx_gpu_infra_reservation
    ON gpu_infra_custodies (reservation_id, reservation_generation);
CREATE INDEX IF NOT EXISTS idx_gpu_infra_lease_expiry
    ON gpu_infra_custodies (lease_expires_at)
    WHERE lease_expires_at IS NOT NULL;

-- migrate:down

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM gpu_infra_custodies)
       OR EXISTS (SELECT 1 FROM gpu_legacy_migrations)
       OR EXISTS (SELECT 1 FROM gpu_legacy_cutover_authorizations)
       OR EXISTS (SELECT 1 FROM gpu_miner_identities) THEN
        RAISE EXCEPTION 'cannot remove durable GPU miner custody while rows exist';
    END IF;
END
$$;

DROP TABLE IF EXISTS gpu_infra_custodies;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS fk_gpu_launch_legacy_migration;
ALTER TABLE gpu_launch_reservations
    DROP CONSTRAINT IF EXISTS gpu_launch_reservations_legacy_migration_id_fkey;
DROP TABLE IF EXISTS gpu_legacy_cutover_authorizations;
DROP TABLE IF EXISTS gpu_legacy_migrations;
ALTER TABLE gpu_launch_reservations DROP CONSTRAINT IF EXISTS ck_gpu_launch_workload;
ALTER TABLE gpu_launch_reservations
    ADD CONSTRAINT ck_gpu_launch_workload CHECK (
        (
            management_mode = 'platform'
            AND chute_id IS NOT NULL
            AND chute_version IS NOT NULL
            AND container_repository IS NOT NULL
            AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
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
            AND chute_id IS NULL
            AND job_id IS NULL
            AND chute_version IS NULL
            AND container_repository IS NULL
            AND container_manifest_digest IS NULL
            AND descriptor_closure_sha256 IS NULL
            AND allowed_manifests = '[]'::jsonb
            AND allowed_blobs = '[]'::jsonb
            AND allowed_manifest_tags = '[]'::jsonb
            AND manifest_tag_digests = '{}'::jsonb
        )
    );
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS legacy_migration_id;
ALTER TABLE gpu_launch_reservations DROP COLUMN IF EXISTS legacy_vm_name;
DROP TABLE IF EXISTS gpu_miner_identities;
