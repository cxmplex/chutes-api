-- migrate:up

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS attestation_revocation_status JSONB;

ALTER TABLE boot_attestations
    ADD COLUMN IF NOT EXISTS revocation_status JSONB;

ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS revocation_status JSONB;

COMMENT ON COLUMN servers.attestation_revocation_status IS
    'Latest successful attestation revocation outcome; revocation_not_advertised explicitly means no revocation mechanism was available.';
COMMENT ON COLUMN boot_attestations.revocation_status IS
    'Per-attestation authenticated revocation outcomes and explicit revocation_not_advertised signals.';
COMMENT ON COLUMN server_attestations.revocation_status IS
    'Per-attestation authenticated revocation outcomes and explicit revocation_not_advertised signals.';

-- migrate:down

ALTER TABLE server_attestations
    DROP COLUMN IF EXISTS revocation_status;
ALTER TABLE boot_attestations
    DROP COLUMN IF EXISTS revocation_status;
ALTER TABLE servers
    DROP COLUMN IF EXISTS attestation_revocation_status;
