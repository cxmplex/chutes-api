-- migrate:up

-- A pin name can be reused with changed security fields. Persist the canonical configuration and
-- complete trust-set fingerprints that were active for every successful attestation.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS measurement_config_fingerprint VARCHAR(64);
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS trust_set_fingerprint VARCHAR(64);
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS measurement_config_fingerprint VARCHAR(64);
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS trust_set_fingerprint VARCHAR(64);
ALTER TABLE boot_attestations
    ADD COLUMN IF NOT EXISTS measurement_config_fingerprint VARCHAR(64);
ALTER TABLE boot_attestations
    ADD COLUMN IF NOT EXISTS trust_set_fingerprint VARCHAR(64);

-- Release target completion must retain the exact pin contents, not only name/version labels.
ALTER TABLE guest_release_targets
    ADD COLUMN IF NOT EXISTS consumed_measurement_config_fingerprint VARCHAR(64);
ALTER TABLE guest_release_targets
    ADD COLUMN IF NOT EXISTS consumed_trust_set_fingerprint VARCHAR(64);
ALTER TABLE guest_release_target_token_generations
    ADD COLUMN IF NOT EXISTS consumed_measurement_config_fingerprint VARCHAR(64);
ALTER TABLE guest_release_target_token_generations
    ADD COLUMN IF NOT EXISTS consumed_trust_set_fingerprint VARCHAR(64);

ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_consumption;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_consumption CHECK (
        (consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL
            AND consumed_measurement_config_fingerprint IS NULL
            AND consumed_trust_set_fingerprint IS NULL)
        OR
        (consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL
            AND consumed_measurement_config_fingerprint IS NOT NULL
            AND consumed_trust_set_fingerprint IS NOT NULL)
    );
ALTER TABLE guest_release_target_token_generations
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_token_consumption;
ALTER TABLE guest_release_target_token_generations
    ADD CONSTRAINT ck_guest_release_target_token_consumption CHECK (
        (consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL
            AND consumed_measurement_config_fingerprint IS NULL
            AND consumed_trust_set_fingerprint IS NULL)
        OR
        (consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL
            AND consumed_measurement_config_fingerprint IS NOT NULL
            AND consumed_trust_set_fingerprint IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS idx_servers_active_attestation_identity
    ON servers (measurement_name, measurement_config_fingerprint, trust_set_fingerprint)
    WHERE is_tee IS TRUE;
CREATE INDEX IF NOT EXISTS idx_server_attestations_trust_identity
    ON server_attestations (
        server_id,
        created_at DESC,
        measurement_name,
        measurement_config_fingerprint,
        trust_set_fingerprint
    );

-- migrate:down

DROP INDEX IF EXISTS idx_server_attestations_trust_identity;
DROP INDEX IF EXISTS idx_servers_active_attestation_identity;
ALTER TABLE guest_release_target_token_generations
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_token_consumption;
ALTER TABLE guest_release_target_token_generations
    ADD CONSTRAINT ck_guest_release_target_token_consumption CHECK (
        (consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL)
        OR
        (consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL)
    );
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_consumption;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_consumption CHECK (
        (consumed_at IS NULL
            AND consumed_server_id IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
            AND consumed_measurement_name IS NULL
            AND consumed_measurement_version IS NULL)
        OR
        (consumed_at IS NOT NULL
            AND consumed_server_id IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash IS NOT NULL
            AND consumed_measurement_name IS NOT NULL
            AND consumed_measurement_version IS NOT NULL)
    );
ALTER TABLE guest_release_target_token_generations
    DROP COLUMN IF EXISTS consumed_trust_set_fingerprint;
ALTER TABLE guest_release_target_token_generations
    DROP COLUMN IF EXISTS consumed_measurement_config_fingerprint;
ALTER TABLE guest_release_targets DROP COLUMN IF EXISTS consumed_trust_set_fingerprint;
ALTER TABLE guest_release_targets
    DROP COLUMN IF EXISTS consumed_measurement_config_fingerprint;
ALTER TABLE boot_attestations DROP COLUMN IF EXISTS trust_set_fingerprint;
ALTER TABLE boot_attestations DROP COLUMN IF EXISTS measurement_config_fingerprint;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS trust_set_fingerprint;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS measurement_config_fingerprint;
ALTER TABLE servers DROP COLUMN IF EXISTS trust_set_fingerprint;
ALTER TABLE servers DROP COLUMN IF EXISTS measurement_config_fingerprint;
