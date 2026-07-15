-- migrate:up

-- Persist explicit storage enrollment and desired-state channel on each logical L0 launcher.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS storage_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS release_channel TEXT NOT NULL DEFAULT 'stable';

-- Existing storage TD registrations identify hosts that were already enrolled before this column.
UPDATE hosts AS host
SET storage_enabled = TRUE
WHERE EXISTS (
    SELECT 1
    FROM servers AS server
    WHERE server.host_id = host.host_id
      AND server.storage_role IS TRUE
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_hosts_capacity_nonnegative'
    ) THEN
        ALTER TABLE hosts
            ADD CONSTRAINT ck_hosts_capacity_nonnegative CHECK (capacity >= 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_hosts_zero_capacity_storage_only'
    ) THEN
        ALTER TABLE hosts
            ADD CONSTRAINT ck_hosts_zero_capacity_storage_only
            CHECK (capacity > 0 OR storage_enabled IS TRUE);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_hosts_release_targeting
    ON hosts (release_channel, tee_type);

-- NULL means a legacy active release has not captured its immutable target set yet. A non-NULL
-- timestamp also represents an intentionally empty target set.
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS targets_captured_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS guest_release_targets (
    target_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL REFERENCES guest_releases(release_id) ON DELETE CASCADE,
    host_id TEXT NOT NULL,
    miner_hotkey TEXT NOT NULL,
    tee_type TEXT NOT NULL,
    role TEXT NOT NULL,
    current_generation INTEGER NOT NULL DEFAULT 1,
    current_token_id TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,
    consumed_server_id TEXT,
    consumed_attestation_id TEXT,
    consumed_cert_pubkey_hash TEXT,
    consumed_measurement_name TEXT,
    consumed_measurement_version TEXT,
    CONSTRAINT uq_guest_release_logical_target UNIQUE (release_id, host_id, role),
    CONSTRAINT uq_guest_release_target_current_token UNIQUE (current_token_id),
    CONSTRAINT uq_guest_release_target_attestation UNIQUE (consumed_attestation_id),
    CONSTRAINT ck_guest_release_target_role CHECK (role IN ('chute', 'storage')),
    CONSTRAINT ck_guest_release_target_generation CHECK (current_generation > 0),
    CONSTRAINT ck_guest_release_target_consumption CHECK (
        (
            consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL
        )
        OR
        (
            consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_guest_release_targets_release
    ON guest_release_targets (release_id, role, host_id);
CREATE INDEX IF NOT EXISTS idx_guest_release_targets_server
    ON guest_release_targets (consumed_server_id);

-- The target row stores only the current binding. Every prior token generation and its exact
-- quote/certificate consumption remains immutable audit history here.
CREATE TABLE IF NOT EXISTS guest_release_target_token_generations (
    target_id TEXT NOT NULL REFERENCES guest_release_targets(target_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    token_id TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    invalidated_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_server_id TEXT,
    consumed_attestation_id TEXT,
    consumed_cert_pubkey_hash TEXT,
    consumed_measurement_name TEXT,
    consumed_measurement_version TEXT,
    CONSTRAINT pk_guest_release_target_token_generation PRIMARY KEY (target_id, generation),
    CONSTRAINT uq_guest_release_target_token_id UNIQUE (token_id),
    CONSTRAINT uq_guest_release_target_token_attestation UNIQUE (consumed_attestation_id),
    CONSTRAINT ck_guest_release_target_token_generation CHECK (generation > 0),
    CONSTRAINT ck_guest_release_target_token_invalidation
        CHECK (invalidated_at IS NULL OR invalidated_at >= issued_at),
    CONSTRAINT ck_guest_release_target_token_consumption CHECK (
        (
            consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL
        )
        OR
        (
            consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_guest_release_target_token_current
    ON guest_release_target_token_generations (target_id, generation);
CREATE INDEX IF NOT EXISTS idx_guest_release_target_token_server
    ON guest_release_target_token_generations (consumed_server_id);

-- migrate:down

DROP TABLE IF EXISTS guest_release_target_token_generations;
DROP TABLE IF EXISTS guest_release_targets;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS targets_captured_at;
DROP INDEX IF EXISTS idx_hosts_release_targeting;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_zero_capacity_storage_only;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_capacity_nonnegative;
ALTER TABLE hosts DROP COLUMN IF EXISTS release_channel;
ALTER TABLE hosts DROP COLUMN IF EXISTS storage_enabled;
