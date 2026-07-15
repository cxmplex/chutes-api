-- migrate:up

-- A measurement version is not a unique image identity: provider, TEE, role and vCPU classes can
-- share version strings. Persist the exact matched pin name so release completion can be authorized
-- only by fresh attestations for the release's signed provenance.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS measurement_name TEXT;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS measurement_name VARCHAR;
ALTER TABLE boot_attestations
    ADD COLUMN IF NOT EXISTS measurement_name VARCHAR;

CREATE INDEX IF NOT EXISTS idx_server_attestations_release_identity
    ON server_attestations (server_id, created_at DESC, attestation_id DESC)
    INCLUDE (measurement_name, measurement_version, verification_error, verified_at);

-- migrate:down

DROP INDEX IF EXISTS idx_server_attestations_release_identity;
ALTER TABLE boot_attestations DROP COLUMN IF EXISTS measurement_name;
ALTER TABLE server_attestations DROP COLUMN IF EXISTS measurement_name;
ALTER TABLE servers DROP COLUMN IF EXISTS measurement_name;
