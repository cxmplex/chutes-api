-- migrate:up

-- This terminal transition is deliberately additive. Production GPU lineage and
-- attestations remain in place; only active secret custody and serving pointers
-- are removed after the physical lifecycle has reached a closed terminal state.
LOCK TABLE gpu_legacy_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gpu_infra_custodies IN ACCESS EXCLUSIVE MODE;

ALTER TABLE gpu_legacy_migrations
    ADD COLUMN IF NOT EXISTS decommission_request_id VARCHAR,
    ADD COLUMN IF NOT EXISTS decommissioned_at TIMESTAMPTZ;

ALTER TABLE gpu_legacy_migrations
    DROP CONSTRAINT IF EXISTS ck_gpu_legacy_migration_state,
    DROP CONSTRAINT IF EXISTS ck_gpu_legacy_migration_progress,
    DROP CONSTRAINT IF EXISTS ck_gpu_legacy_migration_decommission;
ALTER TABLE gpu_legacy_migrations
    ADD CONSTRAINT ck_gpu_legacy_migration_state CHECK (
        state IN (
            'guest_closed', 'ready', 'leased', 'promoted', 'completed',
            'decommissioned', 'abandoned'
        )
    ),
    ADD CONSTRAINT ck_gpu_legacy_migration_progress CHECK (
        (state = 'guest_closed' AND host_confirmed_at IS NULL)
        OR (state IN ('ready', 'leased') AND host_confirmed_at IS NOT NULL)
        OR (state = 'promoted' AND promoted_at IS NOT NULL
            AND promoted_marker_sha256 IS NOT NULL AND promoted_summary IS NOT NULL)
        OR (state IN ('completed', 'decommissioned') AND promoted_at IS NOT NULL
            AND discarded_at IS NOT NULL AND completed_at IS NOT NULL
            AND storage_current_passphrase IS NULL
            AND storage_pending_passphrase IS NULL AND storage_lease IS NULL
            AND cache_current_passphrase IS NULL
            AND cache_pending_passphrase IS NULL AND cache_lease IS NULL
            AND k3s_encryption_key IS NULL AND postgres_password IS NULL
            AND source_capability_hash IS NULL
            AND source_capability_expires_at IS NULL)
        OR state = 'abandoned'
    ),
    ADD CONSTRAINT ck_gpu_legacy_migration_decommission CHECK (
        (state = 'decommissioned' AND decommission_request_id IS NOT NULL
            AND decommissioned_at IS NOT NULL)
        OR (state <> 'decommissioned' AND decommission_request_id IS NULL
            AND decommissioned_at IS NULL)
    );

ALTER TABLE gpu_infra_custodies
    ALTER COLUMN k3s_encryption_key DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS decommission_request_id VARCHAR,
    ADD COLUMN IF NOT EXISTS decommissioned_at TIMESTAMPTZ;

ALTER TABLE gpu_infra_custodies
    DROP CONSTRAINT IF EXISTS ck_gpu_infra_state,
    DROP CONSTRAINT IF EXISTS ck_gpu_infra_lease_shape,
    DROP CONSTRAINT IF EXISTS ck_gpu_infra_seal_shape,
    DROP CONSTRAINT IF EXISTS ck_gpu_infra_decommission;
ALTER TABLE gpu_infra_custodies
    ADD CONSTRAINT ck_gpu_infra_state CHECK (
        state IN ('current', 'leased', 'awaiting_ack', 'sealed', 'decommissioned', 'conflict')
    ),
    ADD CONSTRAINT ck_gpu_infra_lease_shape CHECK (
        (state IN ('leased', 'awaiting_ack')
            AND pending_passphrase IS NOT NULL AND pending_key_slot IS NOT NULL
            AND lease_id IS NOT NULL
            AND lease_generation = confirmed_generation + 1
            AND lease_expires_at IS NOT NULL AND lease_attestation_id IS NOT NULL
            AND lease_cert_hash ~ '^[0-9a-f]{64}$' AND lease_session_jti IS NOT NULL
            AND (pending_marker_sha256 IS NULL
                OR pending_marker_sha256 ~ '^[0-9a-f]{64}$'))
        OR (state IN ('current', 'sealed', 'decommissioned', 'conflict')
            AND pending_passphrase IS NULL AND pending_key_slot IS NULL
            AND lease_id IS NULL AND lease_generation IS NULL
            AND lease_expires_at IS NULL AND lease_attestation_id IS NULL
            AND lease_cert_hash IS NULL AND lease_session_jti IS NULL
            AND pending_marker_sha256 IS NULL)
    ),
    ADD CONSTRAINT ck_gpu_infra_seal_shape CHECK (
        (state IN ('sealed', 'decommissioned') AND sealed_at IS NOT NULL)
        OR (state NOT IN ('sealed', 'decommissioned') AND sealed_at IS NULL)
    ),
    ADD CONSTRAINT ck_gpu_infra_decommission CHECK (
        (state = 'decommissioned'
            AND decommission_request_id IS NOT NULL AND decommissioned_at IS NOT NULL
            AND guest_closed_at IS NOT NULL
            AND guest_closed_generation = confirmed_generation
            AND current_passphrase IS NULL AND pending_passphrase IS NULL
            AND retiring_passphrase IS NULL AND k3s_encryption_key IS NULL
            AND active_key_slot IS NULL AND pending_key_slot IS NULL
            AND retiring_key_slot IS NULL
            AND lease_id IS NULL AND lease_generation IS NULL
            AND lease_expires_at IS NULL AND lease_attestation_id IS NULL
            AND lease_cert_hash IS NULL AND lease_session_jti IS NULL
            AND pending_marker_sha256 IS NULL
            AND rollback_generation IS NULL AND rollback_key_slot IS NULL
            AND rollback_passphrase IS NULL)
        OR (state <> 'decommissioned' AND decommission_request_id IS NULL
            AND decommissioned_at IS NULL AND k3s_encryption_key IS NOT NULL)
    );

CREATE TABLE IF NOT EXISTS gpu_server_decommissions (
    server_id VARCHAR PRIMARY KEY
        REFERENCES servers(server_id) ON DELETE RESTRICT,
    request_id VARCHAR NOT NULL UNIQUE,
    owner_hotkey VARCHAR NOT NULL,
    reason TEXT NOT NULL,
    host_id VARCHAR,
    reservation_id VARCHAR,
    reservation_generation INTEGER,
    allocation_group_id VARCHAR,
    allocation_group_generation INTEGER,
    migration_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_json JSONB NOT NULL,
    decommissioned_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_gpu_server_decommission_audit CHECK (
        length(reason) BETWEEN 1 AND 2000
        AND jsonb_typeof(migration_ids) = 'array'
        AND jsonb_typeof(response_json) = 'object'
        AND ((reservation_id IS NULL AND reservation_generation IS NULL)
            OR (reservation_id IS NOT NULL AND reservation_generation > 0))
        AND ((allocation_group_id IS NULL AND allocation_group_generation IS NULL)
            OR (allocation_group_id IS NOT NULL AND allocation_group_generation > 0))
    )
);
CREATE INDEX IF NOT EXISTS idx_gpu_server_decommissions_owner
    ON gpu_server_decommissions(owner_hotkey, decommissioned_at);

CREATE OR REPLACE FUNCTION preserve_gpu_server_decommission_audit()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'gpu server decommission audit rows are immutable';
END
$$;
DROP TRIGGER IF EXISTS preserve_gpu_server_decommission_audit
    ON gpu_server_decommissions;
CREATE TRIGGER preserve_gpu_server_decommission_audit
BEFORE UPDATE OR DELETE ON gpu_server_decommissions
FOR EACH ROW EXECUTE FUNCTION preserve_gpu_server_decommission_audit();

CREATE OR REPLACE FUNCTION preserve_gpu_decommission_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    _terminal_at TIMESTAMPTZ;
    _terminal_reason TEXT;
BEGIN
    IF TG_TABLE_NAME = 'servers' THEN
        SELECT decommissioned_at, reason
          INTO _terminal_at, _terminal_reason
          FROM gpu_server_decommissions
         WHERE server_id = OLD.server_id;
        IF FOUND THEN
            IF TG_OP = 'UPDATE'
               AND OLD.gpu_retired_at IS NULL
               AND NEW.gpu_retired_at = _terminal_at
               AND NEW.gpu_retirement_reason = _terminal_reason
               AND NEW.gpu_launch_reservation_id IS NULL
               AND NEW.gpu_allocation_group_id IS NULL
               AND NEW.gpu_allocation_group_generation IS NULL
               AND NEW.gpu_management_mode IS NULL
               AND NEW.gpu_process_incarnation IS NULL
               AND NEW.gpu_topology_fingerprint IS NULL
               AND NEW.gpu_runtime_session_attestation_id IS NULL
               AND NEW.gpu_runtime_session_expires_at IS NULL
               AND NEW.attested_cert IS NULL
               AND NEW.attested_cert_pubkey_hash IS NULL
               AND NEW.external_host IS NULL
               AND NEW.external_ports IS NULL
               AND NEW.last_health_at IS NULL
               AND (
                   to_jsonb(NEW) - ARRAY[
                       'updated_at', 'gpu_retired_at', 'gpu_retirement_reason',
                       'gpu_launch_reservation_id', 'gpu_allocation_group_id',
                       'gpu_allocation_group_generation', 'gpu_management_mode',
                       'gpu_process_incarnation', 'gpu_topology_fingerprint',
                       'gpu_runtime_session_attestation_id',
                       'gpu_runtime_session_expires_at', 'attested_cert',
                       'attested_cert_pubkey_hash', 'external_host',
                       'external_ports', 'last_health_at'
                   ]::text[]
               ) IS NOT DISTINCT FROM (
                   to_jsonb(OLD) - ARRAY[
                       'updated_at', 'gpu_retired_at', 'gpu_retirement_reason',
                       'gpu_launch_reservation_id', 'gpu_allocation_group_id',
                       'gpu_allocation_group_generation', 'gpu_management_mode',
                       'gpu_process_incarnation', 'gpu_topology_fingerprint',
                       'gpu_runtime_session_attestation_id',
                       'gpu_runtime_session_expires_at', 'attested_cert',
                       'attested_cert_pubkey_hash', 'external_host',
                       'external_ports', 'last_health_at'
                   ]::text[]
               ) THEN
                RETURN NEW;
            END IF;
            IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'decommissioned GPU server rows are immutable';
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        IF TG_TABLE_NAME = 'gpu_infra_custodies' THEN
            IF EXISTS (
                SELECT 1 FROM gpu_server_decommissions
                 WHERE server_id = NEW.server_id
            ) THEN
                RAISE EXCEPTION 'decommissioned GPU custody cannot be recreated';
            END IF;
        ELSIF TG_TABLE_NAME = 'gpu_legacy_migrations' THEN
            IF EXISTS (
                SELECT 1 FROM gpu_server_decommissions
                 WHERE server_id = NEW.legacy_server_id
                    OR server_id = NEW.target_server_id
            ) THEN
                RAISE EXCEPTION 'decommissioned GPU migration lineage cannot be recreated';
            END IF;
        END IF;
        RETURN NEW;
    ELSIF (to_jsonb(OLD)->>'state') = 'decommissioned' THEN
        IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'decommissioned GPU custody and migration rows are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_server ON servers;
DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_custody
    ON gpu_infra_custodies;
DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_migration
    ON gpu_legacy_migrations;
CREATE TRIGGER preserve_gpu_decommissioned_server
BEFORE UPDATE OR DELETE ON servers
FOR EACH ROW EXECUTE FUNCTION preserve_gpu_decommission_terminal();
CREATE TRIGGER preserve_gpu_decommissioned_custody
BEFORE INSERT OR UPDATE OR DELETE ON gpu_infra_custodies
FOR EACH ROW EXECUTE FUNCTION preserve_gpu_decommission_terminal();
CREATE TRIGGER preserve_gpu_decommissioned_migration
BEFORE INSERT OR UPDATE OR DELETE ON gpu_legacy_migrations
FOR EACH ROW EXECUTE FUNCTION preserve_gpu_decommission_terminal();

-- migrate:down

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM gpu_server_decommissions)
       OR EXISTS (SELECT 1 FROM gpu_infra_custodies WHERE state = 'decommissioned')
       OR EXISTS (SELECT 1 FROM gpu_legacy_migrations WHERE state = 'decommissioned') THEN
        RAISE EXCEPTION
            'cannot remove GPU terminal-decommission schema while immutable terminal history exists';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_server ON servers;
DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_custody
    ON gpu_infra_custodies;
DROP TRIGGER IF EXISTS preserve_gpu_decommissioned_migration
    ON gpu_legacy_migrations;
DROP FUNCTION preserve_gpu_decommission_terminal();

DROP TRIGGER IF EXISTS preserve_gpu_server_decommission_audit
    ON gpu_server_decommissions;
DROP TABLE gpu_server_decommissions;
DROP FUNCTION preserve_gpu_server_decommission_audit();

ALTER TABLE gpu_infra_custodies
    DROP CONSTRAINT ck_gpu_infra_decommission,
    DROP CONSTRAINT ck_gpu_infra_seal_shape,
    DROP CONSTRAINT ck_gpu_infra_lease_shape,
    DROP CONSTRAINT ck_gpu_infra_state;
ALTER TABLE gpu_infra_custodies
    ADD CONSTRAINT ck_gpu_infra_state CHECK (
        state IN ('current', 'leased', 'awaiting_ack', 'sealed', 'conflict')
    ),
    ADD CONSTRAINT ck_gpu_infra_lease_shape CHECK (
        (state IN ('leased', 'awaiting_ack')
            AND pending_passphrase IS NOT NULL AND pending_key_slot IS NOT NULL
            AND lease_id IS NOT NULL
            AND lease_generation = confirmed_generation + 1
            AND lease_expires_at IS NOT NULL AND lease_attestation_id IS NOT NULL
            AND lease_cert_hash ~ '^[0-9a-f]{64}$' AND lease_session_jti IS NOT NULL
            AND (pending_marker_sha256 IS NULL
                OR pending_marker_sha256 ~ '^[0-9a-f]{64}$'))
        OR (state IN ('current', 'sealed', 'conflict')
            AND pending_passphrase IS NULL AND pending_key_slot IS NULL
            AND lease_id IS NULL AND lease_generation IS NULL
            AND lease_expires_at IS NULL AND lease_attestation_id IS NULL
            AND lease_cert_hash IS NULL AND lease_session_jti IS NULL
            AND pending_marker_sha256 IS NULL)
    ),
    ADD CONSTRAINT ck_gpu_infra_seal_shape CHECK (
        (state = 'sealed' AND sealed_at IS NOT NULL)
        OR (state <> 'sealed' AND sealed_at IS NULL)
    );
ALTER TABLE gpu_infra_custodies
    ALTER COLUMN k3s_encryption_key SET NOT NULL,
    DROP COLUMN decommission_request_id,
    DROP COLUMN decommissioned_at;

ALTER TABLE gpu_legacy_migrations
    DROP CONSTRAINT ck_gpu_legacy_migration_decommission,
    DROP CONSTRAINT ck_gpu_legacy_migration_progress,
    DROP CONSTRAINT ck_gpu_legacy_migration_state;
ALTER TABLE gpu_legacy_migrations
    ADD CONSTRAINT ck_gpu_legacy_migration_state CHECK (
        state IN ('guest_closed', 'ready', 'leased', 'promoted', 'completed', 'abandoned')
    ),
    ADD CONSTRAINT ck_gpu_legacy_migration_progress CHECK (
        (state = 'guest_closed' AND host_confirmed_at IS NULL)
        OR (state IN ('ready', 'leased') AND host_confirmed_at IS NOT NULL)
        OR (state = 'promoted' AND promoted_at IS NOT NULL
            AND promoted_marker_sha256 IS NOT NULL AND promoted_summary IS NOT NULL)
        OR (state = 'completed' AND promoted_at IS NOT NULL
            AND discarded_at IS NOT NULL AND completed_at IS NOT NULL
            AND storage_current_passphrase IS NULL
            AND storage_pending_passphrase IS NULL AND storage_lease IS NULL
            AND cache_current_passphrase IS NULL
            AND cache_pending_passphrase IS NULL AND cache_lease IS NULL
            AND k3s_encryption_key IS NULL AND postgres_password IS NULL
            AND source_capability_hash IS NULL
            AND source_capability_expires_at IS NULL)
        OR state = 'abandoned'
    );
ALTER TABLE gpu_legacy_migrations
    DROP COLUMN decommission_request_id,
    DROP COLUMN decommissioned_at;
