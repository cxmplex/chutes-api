-- migrate:up

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS identity_durable_at TIMESTAMPTZ;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS identity_metadata_sha256 TEXT;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS steady_config_sha256 TEXT;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS provisioning_heartbeat_at TIMESTAMPTZ;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS provisioning_status JSONB;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_provisioning_state;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_provisioning_state CHECK (
        provisioning_state IN (
            'legacy',
            'unclaimed',
            'persisting_identity',
            'awaiting_pcs',
            'ready',
            'revoked'
        )
    );

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_identity_durability;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_identity_durability CHECK (
        (
            identity_durable_at IS NULL
            AND identity_metadata_sha256 IS NULL
            AND steady_config_sha256 IS NULL
        )
        OR
        (
            identity_durable_at IS NOT NULL
            AND identity_metadata_sha256 ~ '^[0-9a-f]{64}$'
            AND steady_config_sha256 ~ '^[0-9a-f]{64}$'
        )
    );

-- migrate:down

UPDATE hosts
SET provisioning_state = 'unclaimed'
WHERE provisioning_state = 'persisting_identity';

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_identity_durability;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_provisioning_state;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_provisioning_state CHECK (
        provisioning_state IN ('legacy', 'unclaimed', 'awaiting_pcs', 'ready', 'revoked')
    );

ALTER TABLE hosts DROP COLUMN IF EXISTS provisioning_status;
ALTER TABLE hosts DROP COLUMN IF EXISTS provisioning_heartbeat_at;
ALTER TABLE hosts DROP COLUMN IF EXISTS steady_config_sha256;
ALTER TABLE hosts DROP COLUMN IF EXISTS identity_metadata_sha256;
ALTER TABLE hosts DROP COLUMN IF EXISTS identity_durable_at;
