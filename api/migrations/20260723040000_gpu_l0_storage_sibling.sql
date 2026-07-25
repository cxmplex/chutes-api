-- migrate:up

-- GPU L0s report a requested capacity, but the validator advertises zero until the
-- independently attested CPU/storage sibling is current and live.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS reported_capacity INTEGER;
UPDATE hosts SET reported_capacity = capacity WHERE reported_capacity IS NULL;
ALTER TABLE hosts ALTER COLUMN reported_capacity SET DEFAULT 1;
ALTER TABLE hosts ALTER COLUMN reported_capacity SET NOT NULL;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_reported_capacity;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_reported_capacity CHECK (reported_capacity BETWEEN 0 AND 64);
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS untrusted_gpu_inventory JSONB;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS untrusted_gpu_inventory_ready BOOLEAN;

-- Reuse the durable storage-intent state machine while keeping CPU rollout targets
-- immutable. CPU intents retain their target_id; GPU-host sibling intents deliberately
-- have no CPU target and instead bind both independently active release identities.
ALTER TABLE storage_launch_intents ALTER COLUMN target_id DROP NOT NULL;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS host_compute_type TEXT NOT NULL DEFAULT 'cpu';
UPDATE storage_launch_intents
    SET host_compute_type = 'cpu' WHERE host_compute_type IS NULL;
ALTER TABLE storage_launch_intents
    ALTER COLUMN host_compute_type SET DEFAULT 'cpu';
ALTER TABLE storage_launch_intents
    ALTER COLUMN host_compute_type SET NOT NULL;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS gpu_release_id TEXT
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS active_cpu_release_id TEXT
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS kernel_sha256 TEXT;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS initrd_sha256 TEXT;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS cmdline_sha256 TEXT;
ALTER TABLE storage_launch_intents
    ADD COLUMN IF NOT EXISTS launch_contract JSONB;
ALTER TABLE storage_launch_intents
    DROP CONSTRAINT IF EXISTS ck_storage_launch_intent_host_scope;
ALTER TABLE storage_launch_intents
    ADD CONSTRAINT ck_storage_launch_intent_host_scope CHECK (
        (
            host_compute_type = 'cpu'
            AND target_id IS NOT NULL
            AND gpu_release_id IS NULL
            AND active_cpu_release_id IS NULL
            AND kernel_sha256 IS NULL
            AND initrd_sha256 IS NULL
            AND cmdline_sha256 IS NULL
            AND launch_contract IS NULL
        )
        OR
        (
            host_compute_type = 'gpu'
            AND tee_type = 'tdx'
            AND target_id IS NULL
            AND gpu_release_id IS NOT NULL
            AND active_cpu_release_id IS NOT NULL
            AND kernel_sha256 ~ '^[0-9a-f]{64}$'
            AND initrd_sha256 ~ '^[0-9a-f]{64}$'
            AND cmdline_sha256 ~ '^[0-9a-f]{64}$'
            AND launch_contract IS NOT NULL
        )
    );
DROP INDEX IF EXISTS idx_storage_launch_intents_slot;
CREATE INDEX idx_storage_launch_intents_slot
    ON storage_launch_intents (tee_type, channel, host_compute_type, state, host_id);

-- Reservation v1 remains byte-for-byte the CPU-host contract. Version 2 adds only
-- the GPU-host routing identities; the attested storage guest still boots the exact
-- CPU release and uses the unchanged quote commitment and registration signature.
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS claims_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS host_compute_type TEXT NOT NULL DEFAULT 'cpu';
UPDATE td_launch_reservations
    SET claims_version = 1 WHERE claims_version IS NULL;
UPDATE td_launch_reservations
    SET host_compute_type = 'cpu' WHERE host_compute_type IS NULL;
ALTER TABLE td_launch_reservations
    ALTER COLUMN claims_version SET DEFAULT 1;
ALTER TABLE td_launch_reservations
    ALTER COLUMN claims_version SET NOT NULL;
ALTER TABLE td_launch_reservations
    ALTER COLUMN host_compute_type SET DEFAULT 'cpu';
ALTER TABLE td_launch_reservations
    ALTER COLUMN host_compute_type SET NOT NULL;
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS gpu_release_id TEXT
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT;
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS active_cpu_release_id TEXT
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT;
ALTER TABLE td_launch_reservations
    DROP CONSTRAINT IF EXISTS ck_td_reservation_claim_version;
ALTER TABLE td_launch_reservations
    ADD CONSTRAINT ck_td_reservation_claim_version CHECK (
        (
            claims_version = 1
            AND host_compute_type = 'cpu'
            AND gpu_release_id IS NULL
            AND active_cpu_release_id IS NULL
        )
        OR
        (
            claims_version = 2
            AND role = 'storage'
            AND host_compute_type = 'gpu'
            AND tee_type = 'tdx'
            AND gpu_release_id IS NOT NULL
            AND active_cpu_release_id IS NOT NULL
        )
    );

-- migrate:down

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM hosts WHERE compute_type = 'gpu'
    ) OR EXISTS (
        SELECT 1 FROM storage_launch_intents WHERE host_compute_type = 'gpu'
    ) OR EXISTS (
        SELECT 1 FROM td_launch_reservations WHERE claims_version = 2
    ) THEN
        RAISE EXCEPTION 'cannot remove GPU storage-sibling contracts while GPU rows exist';
    END IF;
END
$$;

ALTER TABLE td_launch_reservations
    DROP CONSTRAINT IF EXISTS ck_td_reservation_claim_version;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS active_cpu_release_id;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS gpu_release_id;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS host_compute_type;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS claims_version;

DROP INDEX IF EXISTS idx_storage_launch_intents_slot;
CREATE INDEX idx_storage_launch_intents_slot
    ON storage_launch_intents (tee_type, channel, state, host_id);
ALTER TABLE storage_launch_intents
    DROP CONSTRAINT IF EXISTS ck_storage_launch_intent_host_scope;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS launch_contract;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS cmdline_sha256;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS initrd_sha256;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS kernel_sha256;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS active_cpu_release_id;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS gpu_release_id;
ALTER TABLE storage_launch_intents DROP COLUMN IF EXISTS host_compute_type;
ALTER TABLE storage_launch_intents ALTER COLUMN target_id SET NOT NULL;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_reported_capacity;
ALTER TABLE hosts DROP COLUMN IF EXISTS untrusted_gpu_inventory_ready;
ALTER TABLE hosts DROP COLUMN IF EXISTS untrusted_gpu_inventory;
ALTER TABLE hosts DROP COLUMN IF EXISTS reported_capacity;
