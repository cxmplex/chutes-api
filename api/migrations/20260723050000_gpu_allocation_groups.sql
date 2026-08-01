-- migrate:up

-- A GPU L0 remains an unattested logical launcher. boot_id is signed telemetry from
-- its enrolled key; boot_generation is the validator-owned monotonic fence derived
-- from that telemetry and must never be presented as physical-host proof.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS boot_id TEXT;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS boot_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS gpu_inventory_report_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS gpu_inventory_fingerprint TEXT;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS gpu_inventory_reconciled_at TIMESTAMPTZ;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_boot_generation;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_boot_generation CHECK (
        (boot_id IS NULL AND boot_generation = 0)
        OR
        (
            boot_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND boot_generation > 0
        )
    );
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_gpu_inventory_generation;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_gpu_inventory_generation CHECK (
        gpu_inventory_report_generation >= 0
        AND (
            gpu_inventory_fingerprint IS NULL
            OR gpu_inventory_fingerprint ~ '^[0-9a-f]{64}$'
        )
    );

CREATE TABLE IF NOT EXISTS gpu_inventory_reports (
    report_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    report_generation INTEGER NOT NULL,
    gpu_release_id TEXT NOT NULL REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    profile_contract_sha256 TEXT NOT NULL,
    topology_fingerprint TEXT NOT NULL,
    claims JSONB NOT NULL,
    claims_sha256 TEXT NOT NULL,
    reconciliation_status TEXT NOT NULL,
    failure_reason TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ,
    CONSTRAINT uq_gpu_inventory_report_generation
        UNIQUE (host_id, host_boot_generation, report_generation),
    CONSTRAINT fk_gpu_inventory_report_host_key
        FOREIGN KEY (host_id, host_key_generation)
        REFERENCES host_key_generations(host_id, generation)
        ON DELETE RESTRICT,
    CONSTRAINT ck_gpu_inventory_report_generations CHECK (
        host_key_generation > 0
        AND host_boot_generation > 0
        AND report_generation > 0
    ),
    CONSTRAINT ck_gpu_inventory_report_digests CHECK (
        profile_contract_sha256 ~ '^[0-9a-f]{64}$'
        AND topology_fingerprint ~ '^[0-9a-f]{64}$'
        AND claims_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_gpu_inventory_report_status CHECK (
        reconciliation_status IN ('accepted', 'rejected', 'quarantined')
    ),
    CONSTRAINT ck_gpu_inventory_report_acceptance CHECK (
        (reconciliation_status = 'accepted' AND accepted_at IS NOT NULL AND failure_reason IS NULL)
        OR
        (reconciliation_status <> 'accepted' AND accepted_at IS NULL AND failure_reason IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_inventory_reports_host
    ON gpu_inventory_reports (host_id, host_boot_generation, report_generation);

CREATE TABLE IF NOT EXISTS gpu_allocation_groups (
    allocation_group_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    gpu_release_id TEXT NOT NULL REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    profile_id TEXT NOT NULL,
    profile_contract_sha256 TEXT NOT NULL,
    topology_fingerprint TEXT NOT NULL,
    gpu_bdfs JSONB NOT NULL,
    gpu_uuids JSONB NOT NULL,
    gpu_identifiers JSONB NOT NULL,
    gpu_attestation_certificate_sha256s JSONB NOT NULL,
    iommu_domains JSONB NOT NULL,
    reset_domains JSONB NOT NULL,
    nvlink_edges JSONB NOT NULL,
    nvswitch_fabric JSONB NOT NULL,
    model TEXT NOT NULL,
    gpu_count INTEGER NOT NULL,
    vram_mib INTEGER NOT NULL,
    state TEXT NOT NULL,
    management_mode TEXT,
    reservation_owner TEXT,
    reservation_id TEXT,
    reservation_generation INTEGER NOT NULL DEFAULT 0,
    process_incarnation TEXT,
    last_report_id TEXT NOT NULL REFERENCES gpu_inventory_reports(report_id) ON DELETE RESTRICT,
    recovery_authorization_id TEXT,
    recovery_report_id TEXT REFERENCES gpu_inventory_reports(report_id) ON DELETE RESTRICT,
    recovery_nonce_hash TEXT,
    recovery_authorized_by TEXT,
    recovery_authorized_at TIMESTAMPTZ,
    recovery_started_at TIMESTAMPTZ,
    recovery_completed_at TIMESTAMPTZ,
    failure_code TEXT,
    failure_reason TEXT,
    failure_metadata JSONB,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ,
    reserved_at TIMESTAMPTZ,
    launching_at TIMESTAMPTZ,
    running_at TIMESTAMPTZ,
    resetting_at TIMESTAMPTZ,
    quarantined_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gpu_allocation_group_host_topology
        UNIQUE (host_id, profile_id, topology_fingerprint),
    CONSTRAINT fk_gpu_allocation_group_host_key
        FOREIGN KEY (host_id, host_key_generation)
        REFERENCES host_key_generations(host_id, generation)
        ON DELETE RESTRICT,
    CONSTRAINT ck_gpu_allocation_group_generations CHECK (
        host_key_generation > 0
        AND host_boot_generation > 0
        AND generation > 0
        AND reservation_generation >= 0
    ),
    CONSTRAINT ck_gpu_allocation_group_digests CHECK (
        profile_contract_sha256 ~ '^[0-9a-f]{64}$'
        AND topology_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_gpu_allocation_group_shape CHECK (
        gpu_count > 0
        AND vram_mib > 0
        AND jsonb_typeof(gpu_bdfs) = 'array'
        AND jsonb_array_length(gpu_bdfs) = gpu_count
        AND jsonb_typeof(gpu_uuids) = 'array'
        AND jsonb_array_length(gpu_uuids) = gpu_count
        AND jsonb_typeof(gpu_identifiers) = 'array'
        AND jsonb_array_length(gpu_identifiers) = gpu_count
        AND jsonb_typeof(gpu_attestation_certificate_sha256s) = 'array'
        AND jsonb_array_length(gpu_attestation_certificate_sha256s) = gpu_count
        AND jsonb_typeof(iommu_domains) = 'array'
        AND jsonb_typeof(reset_domains) = 'array'
        AND jsonb_typeof(nvlink_edges) = 'array'
        AND jsonb_typeof(nvswitch_fabric) = 'array'
    ),
    CONSTRAINT ck_gpu_allocation_group_state CHECK (
        state IN (
            'discovered',
            'available',
            'reserved',
            'launching',
            'running',
            'resetting',
            'quarantined',
            'retired'
        )
    ),
    CONSTRAINT ck_gpu_allocation_group_owner CHECK (
        (
            state IN ('discovered', 'available', 'retired')
            AND management_mode IS NULL
            AND reservation_owner IS NULL
            AND reservation_id IS NULL
            AND process_incarnation IS NULL
        )
        OR state = 'quarantined'
        OR
        (
            state IN ('reserved', 'launching', 'running', 'resetting')
            AND management_mode IN ('platform', 'miner')
            AND reservation_owner IS NOT NULL
            AND reservation_id IS NOT NULL
            AND reservation_generation > 0
            AND process_incarnation IS NOT NULL
        )
        OR
        (
            state = 'resetting'
            AND management_mode IS NULL
            AND reservation_owner IS NULL
            AND reservation_id IS NULL
            AND process_incarnation IS NULL
            AND recovery_started_at IS NOT NULL
        )
    ),
    CONSTRAINT ck_gpu_allocation_group_recovery CHECK (
        (
            recovery_authorization_id IS NULL
            AND recovery_report_id IS NULL
            AND recovery_nonce_hash IS NULL
            AND recovery_authorized_by IS NULL
            AND recovery_authorized_at IS NULL
            AND recovery_started_at IS NULL
            AND recovery_completed_at IS NULL
        )
        OR
        (
            recovery_authorization_id IS NOT NULL
            AND recovery_report_id IS NOT NULL
            AND recovery_nonce_hash ~ '^[0-9a-f]{64}$'
            AND recovery_authorized_by IS NOT NULL
            AND recovery_authorized_at IS NOT NULL
            AND (
                recovery_started_at IS NULL
                OR recovery_started_at >= recovery_authorized_at
            )
            AND (
                recovery_completed_at IS NULL
                OR (
                    recovery_started_at IS NOT NULL
                    AND recovery_completed_at >= recovery_started_at
                )
            )
        )
    ),
    CONSTRAINT ck_gpu_allocation_group_failure CHECK (
        (
            state = 'quarantined'
            AND quarantined_at IS NOT NULL
            AND failure_code IS NOT NULL
            AND failure_reason IS NOT NULL
        )
        OR
        (
            state <> 'quarantined'
            AND quarantined_at IS NULL
            AND failure_code IS NULL
            AND failure_reason IS NULL
            AND failure_metadata IS NULL
        )
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_allocation_groups_match
    ON gpu_allocation_groups (state, profile_id, model, gpu_count, vram_mib);
CREATE INDEX IF NOT EXISTS idx_gpu_allocation_groups_host
    ON gpu_allocation_groups (host_id, host_boot_generation, state);

CREATE TABLE IF NOT EXISTS gpu_launch_reservations (
    reservation_id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    claims_version INTEGER NOT NULL,
    claims JSONB NOT NULL,
    claims_sha256 TEXT NOT NULL,
    owner_hotkey TEXT NOT NULL,
    workload_owner TEXT NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    host_boot_generation INTEGER NOT NULL,
    allocation_group_id TEXT NOT NULL
        REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT,
    allocation_group_generation INTEGER NOT NULL,
    reservation_generation INTEGER NOT NULL,
    registration_generation INTEGER NOT NULL DEFAULT 0,
    management_mode TEXT NOT NULL,
    server_id TEXT NOT NULL,
    process_incarnation TEXT NOT NULL,
    gpu_release_id TEXT NOT NULL REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    profile_id TEXT NOT NULL,
    profile_contract_sha256 TEXT NOT NULL,
    measurement_name TEXT NOT NULL,
    kernel_measurement_mode TEXT NOT NULL,
    topology_fingerprint TEXT NOT NULL,
    gpu_bdfs JSONB NOT NULL,
    gpu_uuids JSONB NOT NULL,
    gpu_identifiers JSONB NOT NULL,
    gpu_attestation_certificate_sha256s JSONB NOT NULL,
    qemu_binary_sha256 TEXT NOT NULL,
    qemu_package_version TEXT NOT NULL,
    machine_type TEXT NOT NULL,
    tdvf_sha256 TEXT NOT NULL,
    image_sha256 TEXT NOT NULL,
    image_version TEXT NOT NULL,
    kernel_sha256 TEXT NOT NULL,
    initrd_sha256 TEXT NOT NULL,
    mode_cmdline_sha256 TEXT NOT NULL,
    release_target_sha256 TEXT NOT NULL,
    chute_id TEXT,
    job_id TEXT,
    container_repository TEXT,
    container_manifest_digest TEXT,
    launch_nonce TEXT NOT NULL,
    state TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ,
    guest_consumed_at TIMESTAMPTZ,
    launching_at TIMESTAMPTZ,
    running_at TIMESTAMPTZ,
    teardown_started_at TIMESTAMPTZ,
    reset_completed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    quarantined_at TIMESTAMPTZ,
    registration_attestation_id TEXT REFERENCES server_attestations(attestation_id) ON DELETE RESTRICT,
    failure_code TEXT,
    failure_reason TEXT,
    failure_metadata JSONB,
    CONSTRAINT uq_gpu_launch_group_generation
        UNIQUE (allocation_group_id, reservation_generation),
    CONSTRAINT fk_gpu_launch_reservation_host_key
        FOREIGN KEY (host_id, host_key_generation)
        REFERENCES host_key_generations(host_id, generation)
        ON DELETE RESTRICT,
    CONSTRAINT ck_gpu_launch_claims_version CHECK (claims_version = 1),
    CONSTRAINT ck_gpu_launch_generations CHECK (
        host_key_generation > 0
        AND host_boot_generation > 0
        AND allocation_group_generation > 0
        AND reservation_generation > 0
        AND registration_generation >= 0
        AND registration_generation <= 1024
    ),
    CONSTRAINT ck_gpu_launch_mode CHECK (
        management_mode IN ('platform', 'miner')
    ),
    CONSTRAINT ck_gpu_launch_state CHECK (
        state IN (
            'reserved',
            'claimed',
            'launching',
            'running',
            'resetting',
            'released',
            'expired',
            'quarantined'
        )
    ),
    CONSTRAINT ck_gpu_launch_digests CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
        AND claims_sha256 ~ '^[0-9a-f]{64}$'
        AND profile_contract_sha256 ~ '^[0-9a-f]{64}$'
        AND topology_fingerprint ~ '^[0-9a-f]{64}$'
        AND qemu_binary_sha256 ~ '^[0-9a-f]{64}$'
        AND tdvf_sha256 ~ '^[0-9a-f]{64}$'
        AND image_sha256 ~ '^[0-9a-f]{64}$'
        AND kernel_sha256 ~ '^[0-9a-f]{64}$'
        AND initrd_sha256 ~ '^[0-9a-f]{64}$'
        AND mode_cmdline_sha256 ~ '^[0-9a-f]{64}$'
        AND release_target_sha256 ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(gpu_attestation_certificate_sha256s) = 'array'
        AND jsonb_array_length(gpu_attestation_certificate_sha256s) =
            jsonb_array_length(gpu_uuids)
        AND (
            container_manifest_digest IS NULL
            OR container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT ck_gpu_launch_workload CHECK (
        (
            management_mode = 'platform'
            AND chute_id IS NOT NULL
            AND container_repository IS NOT NULL
            AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
        )
        OR
        (
            management_mode = 'miner'
            AND chute_id IS NULL
            AND job_id IS NULL
            AND container_repository IS NULL
            AND container_manifest_digest IS NULL
        )
    ),
    CONSTRAINT ck_gpu_launch_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_gpu_launch_terminal_failure CHECK (
        (
            state = 'quarantined'
            AND quarantined_at IS NOT NULL
            AND failure_code IS NOT NULL
            AND failure_reason IS NOT NULL
        )
        OR state <> 'quarantined'
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_gpu_launch_reservation_active_group
    ON gpu_launch_reservations (allocation_group_id)
    WHERE state IN ('reserved', 'claimed', 'launching', 'running', 'resetting');
CREATE INDEX IF NOT EXISTS idx_gpu_launch_reservations_host
    ON gpu_launch_reservations (host_id, state, expires_at);

ALTER TABLE gpu_allocation_groups
    DROP CONSTRAINT IF EXISTS fk_gpu_allocation_group_reservation;
ALTER TABLE gpu_allocation_groups
    ADD CONSTRAINT fk_gpu_allocation_group_reservation
    FOREIGN KEY (reservation_id)
    REFERENCES gpu_launch_reservations(reservation_id)
    ON DELETE RESTRICT;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_launch_reservation_id VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_id VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_servers_gpu_launch_reservation'
          AND conrelid = 'servers'::regclass
    ) THEN
        ALTER TABLE servers
            ADD CONSTRAINT fk_servers_gpu_launch_reservation
            FOREIGN KEY (gpu_launch_reservation_id)
            REFERENCES gpu_launch_reservations(reservation_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_servers_gpu_allocation_group'
          AND conrelid = 'servers'::regclass
    ) THEN
        ALTER TABLE servers
            ADD CONSTRAINT fk_servers_gpu_allocation_group
            FOREIGN KEY (gpu_allocation_group_id)
            REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT;
    END IF;
END
$$;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_management_mode VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_process_incarnation VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_topology_fingerprint VARCHAR(64);
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_retired_at TIMESTAMPTZ;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS gpu_retirement_reason TEXT;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS gpu_retired_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_gpu_launch_reservation
    ON servers (gpu_launch_reservation_id)
    WHERE gpu_launch_reservation_id IS NOT NULL;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_gpu_launch_identity;
ALTER TABLE servers
    ADD CONSTRAINT ck_servers_gpu_launch_identity CHECK (
        (
            gpu_launch_reservation_id IS NULL
            AND gpu_allocation_group_id IS NULL
            AND gpu_allocation_group_generation IS NULL
            AND gpu_management_mode IS NULL
            AND gpu_process_incarnation IS NULL
            AND gpu_topology_fingerprint IS NULL
        )
        OR
        (
            compute_type = 'gpu'
            AND gpu_launch_reservation_id IS NOT NULL
            AND gpu_allocation_group_id IS NOT NULL
            AND gpu_allocation_group_generation > 0
            AND gpu_management_mode IN ('platform', 'miner')
            AND gpu_process_incarnation IS NOT NULL
            AND gpu_topology_fingerprint ~ '^[0-9a-f]{64}$'
        )
    );

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_id VARCHAR;
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS gpu_allocation_group_generation INTEGER;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_nodes_gpu_allocation_group'
          AND conrelid = 'nodes'::regclass
    ) THEN
        ALTER TABLE nodes
            ADD CONSTRAINT fk_nodes_gpu_allocation_group
            FOREIGN KEY (gpu_allocation_group_id)
            REFERENCES gpu_allocation_groups(allocation_group_id) ON DELETE RESTRICT;
    END IF;
END
$$;
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS gpu_retired_at TIMESTAMPTZ;
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS ck_nodes_gpu_allocation_identity;
ALTER TABLE nodes
    ADD CONSTRAINT ck_nodes_gpu_allocation_identity CHECK (
        (
            gpu_allocation_group_id IS NULL
            AND gpu_allocation_group_generation IS NULL
        )
        OR
        (
            gpu_allocation_group_id IS NOT NULL
            AND gpu_allocation_group_generation > 0
        )
    );

-- migrate:down

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM gpu_launch_reservations)
       OR EXISTS (SELECT 1 FROM gpu_allocation_groups)
       OR EXISTS (SELECT 1 FROM gpu_inventory_reports) THEN
        RAISE EXCEPTION 'cannot remove durable GPU allocation state while rows exist';
    END IF;
END
$$;

DROP INDEX IF EXISTS uq_servers_gpu_launch_reservation;
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS ck_nodes_gpu_allocation_identity;
ALTER TABLE nodes DROP COLUMN IF EXISTS gpu_retired_at;
ALTER TABLE nodes DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE nodes DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_gpu_launch_identity;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS gpu_retired_at;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_retirement_reason;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_retired_at;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_topology_fingerprint;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_process_incarnation;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_management_mode;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_allocation_group_generation;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_allocation_group_id;
ALTER TABLE servers DROP COLUMN IF EXISTS gpu_launch_reservation_id;

ALTER TABLE gpu_allocation_groups
    DROP CONSTRAINT IF EXISTS fk_gpu_allocation_group_reservation;
DROP TABLE IF EXISTS gpu_launch_reservations;
DROP TABLE IF EXISTS gpu_allocation_groups;
DROP TABLE IF EXISTS gpu_inventory_reports;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_gpu_inventory_generation;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_boot_generation;
ALTER TABLE hosts DROP COLUMN IF EXISTS gpu_inventory_reconciled_at;
ALTER TABLE hosts DROP COLUMN IF EXISTS gpu_inventory_fingerprint;
ALTER TABLE hosts DROP COLUMN IF EXISTS gpu_inventory_report_generation;
ALTER TABLE hosts DROP COLUMN IF EXISTS boot_generation;
ALTER TABLE hosts DROP COLUMN IF EXISTS boot_id;
