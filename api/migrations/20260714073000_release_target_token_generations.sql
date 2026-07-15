-- migrate:up

-- Upgrade databases that applied the first rollout-target migration before monotonic token
-- generations landed. Fresh ORM-created schemas already have these columns/table, so every step is
-- idempotent.
ALTER TABLE guest_release_targets
    ADD COLUMN IF NOT EXISTS current_generation INTEGER NOT NULL DEFAULT 1;
ALTER TABLE guest_release_targets
    ADD COLUMN IF NOT EXISTS current_token_id TEXT;

UPDATE guest_release_targets
SET current_token_id = target_id || ':' || current_generation::TEXT
WHERE current_token_id IS NULL;

ALTER TABLE guest_release_targets
    ALTER COLUMN current_token_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_guest_release_target_current_token'
          AND conrelid = 'guest_release_targets'::regclass
    ) THEN
        ALTER TABLE guest_release_targets
            ADD CONSTRAINT uq_guest_release_target_current_token UNIQUE (current_token_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_guest_release_target_generation'
          AND conrelid = 'guest_release_targets'::regclass
    ) THEN
        ALTER TABLE guest_release_targets
            ADD CONSTRAINT ck_guest_release_target_generation CHECK (current_generation > 0);
    END IF;
END
$$;

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

INSERT INTO guest_release_target_token_generations (
    target_id,
    generation,
    token_id,
    issued_at,
    consumed_at,
    consumed_server_id,
    consumed_attestation_id,
    consumed_cert_pubkey_hash,
    consumed_measurement_name,
    consumed_measurement_version
)
SELECT
    target_id,
    current_generation,
    current_token_id,
    issued_at,
    consumed_at,
    consumed_server_id,
    consumed_attestation_id,
    consumed_cert_pubkey_hash,
    consumed_measurement_name,
    consumed_measurement_version
FROM guest_release_targets
ON CONFLICT (target_id, generation) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_guest_release_target_token_current
    ON guest_release_target_token_generations (target_id, generation);
CREATE INDEX IF NOT EXISTS idx_guest_release_target_token_server
    ON guest_release_target_token_generations (consumed_server_id);

-- migrate:down

DROP TABLE IF EXISTS guest_release_target_token_generations;
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_generation;
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS uq_guest_release_target_current_token;
ALTER TABLE guest_release_targets
    DROP COLUMN IF EXISTS current_token_id;
ALTER TABLE guest_release_targets
    DROP COLUMN IF EXISTS current_generation;
