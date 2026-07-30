-- migrate:up

-- Durable per-owner/per-chute default ChuteFS volumes.  The chute identifier is deliberately not a
-- foreign key: deleting a chute revokes its launches, but must never cascade into durable user data.
CREATE TABLE IF NOT EXISTS default_chutefs_volume_bindings (
    binding_id       VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id          VARCHAR NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    chute_id         VARCHAR NOT NULL,
    volume_id        VARCHAR NOT NULL UNIQUE REFERENCES storage_volumes(volume_id) ON DELETE RESTRICT,
    lifecycle_state  VARCHAR NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at       TIMESTAMPTZ,
    CONSTRAINT ck_default_chutefs_binding_lifecycle CHECK (
        (lifecycle_state = 'active' AND retired_at IS NULL)
        OR
        (lifecycle_state = 'retired' AND retired_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_default_chutefs_binding_active
    ON default_chutefs_volume_bindings(user_id, chute_id)
    WHERE lifecycle_state = 'active';
CREATE INDEX IF NOT EXISTS idx_default_chutefs_binding_owner
    ON default_chutefs_volume_bindings(user_id, chute_id, created_at DESC);

CREATE OR REPLACE FUNCTION enforce_default_chutefs_binding_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    bound_owner VARCHAR;
    bound_deleted BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.chute_id IS DISTINCT FROM OLD.chute_id
        OR NEW.volume_id IS DISTINCT FROM OLD.volume_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION 'default ChuteFS binding identity is immutable';
    END IF;

    SELECT user_id, deleted
      INTO bound_owner, bound_deleted
      FROM storage_volumes
     WHERE volume_id = NEW.volume_id;
    IF bound_owner IS NULL OR bound_owner IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'default ChuteFS binding owner does not match volume owner';
    END IF;
    IF NEW.lifecycle_state = 'active' AND bound_deleted THEN
        RAISE EXCEPTION 'deleted ChuteFS volume cannot have an active default binding';
    END IF;
    IF NEW.lifecycle_state = 'retired' AND NOT bound_deleted THEN
        RAISE EXCEPTION 'default ChuteFS binding cannot retire before volume deletion';
    END IF;
    IF NEW.lifecycle_state = 'active' AND EXISTS (
        SELECT 1
          FROM default_chutefs_volume_bindings prior
          JOIN storage_volumes prior_volume ON prior_volume.volume_id = prior.volume_id
         WHERE prior.user_id = NEW.user_id
           AND prior.chute_id = NEW.chute_id
           AND prior.lifecycle_state = 'retired'
           AND (prior_volume.purged_at IS NULL OR prior_volume.key_shredded_at IS NULL)
    ) THEN
        RAISE EXCEPTION 'prior default ChuteFS volume has not safely completed purge';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_default_chutefs_binding_identity
    ON default_chutefs_volume_bindings;
CREATE TRIGGER trg_default_chutefs_binding_identity
BEFORE INSERT OR UPDATE ON default_chutefs_volume_bindings
FOR EACH ROW EXECUTE FUNCTION enforce_default_chutefs_binding_identity();

CREATE OR REPLACE FUNCTION prevent_bound_chutefs_owner_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id AND EXISTS (
        SELECT 1
          FROM default_chutefs_volume_bindings
         WHERE volume_id = OLD.volume_id
    ) THEN
        RAISE EXCEPTION 'bound ChuteFS volume ownership is immutable';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_bound_chutefs_owner_immutable ON storage_volumes;
CREATE TRIGGER trg_bound_chutefs_owner_immutable
BEFORE UPDATE OF user_id ON storage_volumes
FOR EACH ROW EXECUTE FUNCTION prevent_bound_chutefs_owner_change();

CREATE OR REPLACE FUNCTION prevent_user_delete_before_chutefs_erasure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
           SELECT 1
             FROM storage_volumes
            WHERE user_id = OLD.user_id
              AND (purged_at IS NULL OR key_shredded_at IS NULL)
       )
       OR EXISTS (
           SELECT 1
             FROM storage_volume_keys key
             JOIN storage_volumes volume ON volume.volume_id = key.volume_id
            WHERE volume.user_id = OLD.user_id
       )
       OR EXISTS (
           SELECT 1
             FROM chutefs_launch_sessions
            WHERE user_id = OLD.user_id
              AND revoked_at IS NULL
       )
       OR EXISTS (
           SELECT 1
             FROM launch_configs config
            WHERE config.user_id = OLD.user_id
              AND config.failed_at IS NULL
              AND (
                  (
                      config.completed_at IS NULL
                      AND config.verified_at IS NULL
                  )
                  OR EXISTS (
                      SELECT 1
                        FROM instances instance
                       WHERE instance.config_id = config.config_id
                         AND (instance.active OR instance.verified)
                  )
                  OR EXISTS (
                      SELECT 1
                        FROM gpu_launch_reservations reservation
                       WHERE reservation.reservation_id = config.gpu_launch_reservation_id
                         AND reservation.state IN (
                             'reserved', 'claimed', 'launching', 'running',
                             'resetting', 'quarantined'
                         )
                  )
                  OR EXISTS (
                      SELECT 1
                        FROM chutefs_launch_sessions session
                       WHERE session.config_id = config.config_id
                         AND session.revoked_at IS NULL
                  )
              )
       )
    THEN
        RAISE EXCEPTION 'user ChuteFS erasure lifecycle is incomplete';
    END IF;
    RETURN OLD;
END
$$;

-- Persist the authoritative owner/storage identity used when the launch JWT is signed.  Existing
-- launch configs predate the contract and cannot exchange a storage session; new configs set the
-- permission and default_volume_id transactionally with binding creation.
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS user_id VARCHAR REFERENCES users(user_id) ON DELETE CASCADE;
ALTER TABLE launch_configs ADD COLUMN IF NOT EXISTS compute_type VARCHAR;
ALTER TABLE launch_configs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS default_volume_id VARCHAR
        REFERENCES storage_volumes(volume_id) ON DELETE RESTRICT;
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS storage_session_exchange_allowed BOOLEAN NOT NULL DEFAULT false;

UPDATE launch_configs lc
   SET user_id = COALESCE(
           (SELECT j.user_id FROM jobs j WHERE j.job_id = lc.job_id),
           (SELECT c.user_id FROM chutes c WHERE c.chute_id = lc.chute_id)
       ),
       compute_type = COALESCE(
           (
               SELECT LOWER(COALESCE(c.node_selector->>'compute_type', 'gpu'))
                 FROM chutes c
                WHERE c.chute_id = lc.chute_id
           ),
           'gpu'
       );

ALTER TABLE launch_configs ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE launch_configs ALTER COLUMN compute_type SET NOT NULL;
ALTER TABLE launch_configs DROP CONSTRAINT IF EXISTS ck_launch_config_compute_type;
ALTER TABLE launch_configs
    ADD CONSTRAINT ck_launch_config_compute_type CHECK (compute_type IN ('cpu', 'gpu'));

CREATE OR REPLACE FUNCTION enforce_launch_storage_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.config_id IS DISTINCT FROM OLD.config_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.chute_id IS DISTINCT FROM OLD.chute_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.compute_type IS DISTINCT FROM OLD.compute_type
       OR NEW.default_volume_id IS DISTINCT FROM OLD.default_volume_id
       OR NEW.storage_session_exchange_allowed IS DISTINCT FROM OLD.storage_session_exchange_allowed
       OR NEW.server_id IS DISTINCT FROM OLD.server_id
       OR NEW.gpu_management_mode IS DISTINCT FROM OLD.gpu_management_mode
       OR NEW.gpu_launch_reservation_id IS DISTINCT FROM OLD.gpu_launch_reservation_id
    THEN
        RAISE EXCEPTION 'launch storage identity is immutable';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_launch_storage_identity_immutable ON launch_configs;
CREATE TRIGGER trg_launch_storage_identity_immutable
BEFORE UPDATE ON launch_configs
FOR EACH ROW EXECUTE FUNCTION enforce_launch_storage_identity_immutable();

CREATE OR REPLACE FUNCTION revoke_registry_scope_on_launch_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.failed_at IS NOT NULL
       OR NEW.completed_at IS NOT NULL
       OR NEW.verification_error IS NOT NULL
       OR NOT NEW.registry_scope_active THEN
        UPDATE registry_sessions
        SET revoked_at = COALESCE(revoked_at, NOW())
        WHERE launch_config_id = NEW.config_id
          AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_launch_terminal_registry_scope ON launch_configs;
CREATE TRIGGER trg_launch_terminal_registry_scope
AFTER UPDATE OF failed_at, completed_at, verification_error, registry_scope_active
ON launch_configs
FOR EACH ROW EXECUTE FUNCTION revoke_registry_scope_on_launch_terminal();

-- A durable monotonic epoch is the database authority for instance-level
-- storage revocation. The BEFORE trigger auto-advances terminal transitions
-- while also permitting callers to advance the epoch explicitly under lock.
ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS storage_revocation_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE instances
    DROP CONSTRAINT IF EXISTS ck_instances_storage_revocation_epoch;
ALTER TABLE instances
    ADD CONSTRAINT ck_instances_storage_revocation_epoch
        CHECK (storage_revocation_epoch >= 0);

CREATE OR REPLACE FUNCTION enforce_instance_storage_revocation_epoch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.storage_revocation_epoch < OLD.storage_revocation_epoch THEN
        RAISE EXCEPTION 'instance storage revocation epoch cannot decrease';
    END IF;
    IF ((OLD.active AND NOT NEW.active)
        OR (OLD.verified AND NOT NEW.verified))
       AND NEW.storage_revocation_epoch = OLD.storage_revocation_epoch
    THEN
        NEW.storage_revocation_epoch := OLD.storage_revocation_epoch + 1;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_instance_storage_revocation_epoch ON instances;
CREATE TRIGGER trg_instance_storage_revocation_epoch
BEFORE UPDATE OF active, verified, storage_revocation_epoch ON instances
FOR EACH ROW EXECUTE FUNCTION enforce_instance_storage_revocation_epoch();

-- Opaque, rotating launch-bound sessions.  Tokens are stored only as SHA-256 digests.  Snapshot
-- columns are immutable and revalidated against all current launch/server/reservation rows on every
-- exchange, refresh, tracker operation, and grant.
CREATE TABLE IF NOT EXISTS chutefs_launch_sessions (
    session_id                    VARCHAR PRIMARY KEY,
    config_id                     VARCHAR NOT NULL UNIQUE
                                      REFERENCES launch_configs(config_id) ON DELETE CASCADE,
    instance_id                   VARCHAR NOT NULL UNIQUE
                                      REFERENCES instances(instance_id) ON DELETE CASCADE,
    binding_id                    VARCHAR NOT NULL
                                      REFERENCES default_chutefs_volume_bindings(binding_id)
                                      ON DELETE RESTRICT,
    user_id                       VARCHAR NOT NULL,
    chute_id                      VARCHAR NOT NULL,
    job_id                        VARCHAR,
    compute_type                  VARCHAR NOT NULL,
    management_mode               VARCHAR NOT NULL,
    server_id                     VARCHAR NOT NULL,
    volume_id                     VARCHAR NOT NULL
                                      REFERENCES storage_volumes(volume_id) ON DELETE RESTRICT,
    reservation_id                VARCHAR,
    allocation_group_id           VARCHAR,
    allocation_group_generation   INTEGER,
    process_incarnation            VARCHAR,
    attestation_id                VARCHAR,
    attested_cert_pubkey_hash      VARCHAR,
    allowed_operations             JSONB NOT NULL,
    generation                     INTEGER NOT NULL DEFAULT 1,
    revocation_epoch               BIGINT NOT NULL,
    access_token_hash              VARCHAR(64) NOT NULL UNIQUE,
    refresh_token_hash             VARCHAR(64) NOT NULL UNIQUE,
    reexchange_token_hash          VARCHAR(64) NOT NULL UNIQUE,
    access_expires_at              TIMESTAMPTZ NOT NULL,
    refresh_expires_at             TIMESTAMPTZ NOT NULL,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at                     TIMESTAMPTZ,
    CONSTRAINT ck_chutefs_launch_session_scope CHECK (
        compute_type IN ('cpu', 'gpu')
        AND management_mode IN ('platform', 'miner')
        AND jsonb_typeof(allowed_operations) = 'array'
        AND allowed_operations = '["put", "get", "list", "delete"]'::jsonb
        AND generation > 0
        AND revocation_epoch >= 0
        AND access_expires_at <= refresh_expires_at
        AND attested_cert_pubkey_hash ~ '^[0-9a-f]{64}$'
        AND (
            (
                compute_type = 'cpu'
                AND management_mode = 'platform'
                AND reservation_id IS NULL
                AND allocation_group_id IS NULL
                AND allocation_group_generation IS NULL
                AND process_incarnation IS NULL
            )
            OR
            (
                compute_type = 'gpu'
                AND reservation_id IS NOT NULL
                AND allocation_group_id IS NOT NULL
                AND allocation_group_generation > 0
                AND process_incarnation IS NOT NULL
                AND attestation_id IS NOT NULL
            )
        )
    ),
    CONSTRAINT ck_chutefs_launch_session_access_hash
        CHECK (access_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_chutefs_launch_session_refresh_hash
        CHECK (refresh_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_chutefs_launch_session_reexchange_hash
        CHECK (reexchange_token_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_chutefs_launch_sessions_expiry
    ON chutefs_launch_sessions(access_expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_chutefs_launch_sessions_server
    ON chutefs_launch_sessions(server_id)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION enforce_chutefs_launch_session_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.config_id IS DISTINCT FROM OLD.config_id
        OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.chute_id IS DISTINCT FROM OLD.chute_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.compute_type IS DISTINCT FROM OLD.compute_type
        OR NEW.management_mode IS DISTINCT FROM OLD.management_mode
        OR NEW.server_id IS DISTINCT FROM OLD.server_id
        OR NEW.volume_id IS DISTINCT FROM OLD.volume_id
        OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
        OR NEW.allocation_group_id IS DISTINCT FROM OLD.allocation_group_id
        OR NEW.allocation_group_generation IS DISTINCT FROM OLD.allocation_group_generation
        OR NEW.process_incarnation IS DISTINCT FROM OLD.process_incarnation
        OR NEW.attestation_id IS DISTINCT FROM OLD.attestation_id
        OR NEW.attested_cert_pubkey_hash IS DISTINCT FROM OLD.attested_cert_pubkey_hash
        OR NEW.allowed_operations IS DISTINCT FROM OLD.allowed_operations
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.revocation_epoch IS DISTINCT FROM OLD.revocation_epoch
        OR NEW.access_token_hash IS DISTINCT FROM OLD.access_token_hash
        OR NEW.refresh_token_hash IS DISTINCT FROM OLD.refresh_token_hash
        OR NEW.reexchange_token_hash IS DISTINCT FROM OLD.reexchange_token_hash
        OR NEW.access_expires_at IS DISTINCT FROM OLD.access_expires_at
        OR NEW.refresh_expires_at IS DISTINCT FROM OLD.refresh_expires_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.rotated_at IS DISTINCT FROM OLD.rotated_at
    ) THEN
        RAISE EXCEPTION 'launch-bound ChuteFS session identity is immutable';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_chutefs_launch_session_identity ON chutefs_launch_sessions;
CREATE TRIGGER trg_chutefs_launch_session_identity
BEFORE UPDATE ON chutefs_launch_sessions
FOR EACH ROW EXECUTE FUNCTION enforce_chutefs_launch_session_identity();

CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_instance_disable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD.active AND NOT NEW.active)
       OR (OLD.verified AND NOT NEW.verified)
       OR NEW.storage_revocation_epoch IS DISTINCT FROM OLD.storage_revocation_epoch
    THEN
        UPDATE chutefs_launch_sessions
           SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE instance_id = NEW.instance_id
           AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_instance_disable ON instances;
CREATE TRIGGER trg_revoke_chutefs_session_on_instance_disable
AFTER UPDATE OF active, verified, storage_revocation_epoch ON instances
FOR EACH ROW EXECUTE FUNCTION revoke_chutefs_session_on_instance_disable();

CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_config_failure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD.failed_at IS NULL AND NEW.failed_at IS NOT NULL)
       OR (OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL)
    THEN
        UPDATE chutefs_launch_sessions
           SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE config_id = NEW.config_id
           AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_config_failure ON launch_configs;
CREATE TRIGGER trg_revoke_chutefs_session_on_config_failure
AFTER UPDATE OF failed_at, completed_at ON launch_configs
FOR EACH ROW EXECUTE FUNCTION revoke_chutefs_session_on_config_failure();

CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_server_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.gpu_retired_at IS DISTINCT FROM OLD.gpu_retired_at
       OR NEW.gpu_runtime_session_attestation_id
            IS DISTINCT FROM OLD.gpu_runtime_session_attestation_id
       OR NEW.attested_cert_pubkey_hash
            IS DISTINCT FROM OLD.attested_cert_pubkey_hash
    THEN
        UPDATE chutefs_launch_sessions
           SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE server_id = NEW.server_id
           AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_server_change ON servers;
CREATE TRIGGER trg_revoke_chutefs_session_on_server_change
AFTER UPDATE OF gpu_retired_at, gpu_runtime_session_attestation_id,
    attested_cert_pubkey_hash ON servers
FOR EACH ROW EXECUTE FUNCTION revoke_chutefs_session_on_server_change();

CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_reservation_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = 'running' AND NEW.state IS DISTINCT FROM 'running' THEN
        UPDATE chutefs_launch_sessions
           SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE reservation_id = NEW.reservation_id
           AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_reservation_change
    ON gpu_launch_reservations;
CREATE TRIGGER trg_revoke_chutefs_session_on_reservation_change
AFTER UPDATE OF state ON gpu_launch_reservations
FOR EACH ROW EXECUTE FUNCTION revoke_chutefs_session_on_reservation_change();

CREATE OR REPLACE FUNCTION complete_launch_config_on_instance_terminal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_config_id VARCHAR;
BEGIN
    target_config_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.config_id ELSE NEW.config_id END;
    IF target_config_id IS NOT NULL
       AND (
           TG_OP = 'DELETE'
           OR (
               NOT NEW.active
               AND NOT NEW.verified
               AND (OLD.active OR OLD.verified)
           )
       )
    THEN
        UPDATE launch_configs
           SET completed_at = COALESCE(completed_at, NOW())
         WHERE config_id = target_config_id
           AND failed_at IS NULL;
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

DROP TRIGGER IF EXISTS trg_complete_launch_config_on_instance_terminal ON instances;
CREATE TRIGGER trg_complete_launch_config_on_instance_terminal
AFTER DELETE OR UPDATE OF active, verified ON instances
FOR EACH ROW EXECUTE FUNCTION complete_launch_config_on_instance_terminal();

CREATE OR REPLACE FUNCTION complete_launch_config_on_job_terminal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.finished_at IS NULL AND NEW.finished_at IS NOT NULL THEN
        UPDATE launch_configs
           SET completed_at = COALESCE(completed_at, NEW.finished_at)
         WHERE job_id = NEW.job_id
           AND failed_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_complete_launch_config_on_job_terminal ON jobs;
CREATE TRIGGER trg_complete_launch_config_on_job_terminal
AFTER UPDATE OF finished_at ON jobs
FOR EACH ROW EXECUTE FUNCTION complete_launch_config_on_job_terminal();

UPDATE launch_configs config
   SET completed_at = COALESCE(
       (SELECT job.finished_at FROM jobs job WHERE job.job_id = config.job_id),
       config.verified_at,
       config.retrieved_at,
       config.created_at,
       NOW()
   )
 WHERE config.failed_at IS NULL
   AND config.verified_at IS NOT NULL
   AND NOT EXISTS (
       SELECT 1
         FROM instances instance
        WHERE instance.config_id = config.config_id
          AND (instance.active OR instance.verified)
   )
   AND NOT EXISTS (
       SELECT 1
         FROM gpu_launch_reservations reservation
        WHERE reservation.reservation_id = config.gpu_launch_reservation_id
          AND reservation.state IN (
              'reserved', 'claimed', 'launching', 'running',
              'resetting', 'quarantined'
          )
   )
   AND NOT EXISTS (
       SELECT 1
         FROM chutefs_launch_sessions session
        WHERE session.config_id = config.config_id
          AND session.revoked_at IS NULL
   );

DROP INDEX IF EXISTS uq_job_launch_config_active;
CREATE UNIQUE INDEX uq_job_launch_config_active
    ON launch_configs (job_id)
    WHERE job_id IS NOT NULL
      AND failed_at IS NULL
      AND completed_at IS NULL;

DROP TRIGGER IF EXISTS trg_prevent_user_delete_before_chutefs_erasure ON users;
CREATE TRIGGER trg_prevent_user_delete_before_chutefs_erasure
BEFORE DELETE ON users
FOR EACH ROW EXECUTE FUNCTION prevent_user_delete_before_chutefs_erasure();

-- migrate:down

-- Runtime ends its non-authoritative lookup transaction before taking this
-- lock in shared mode, so no earlier ACCESS SHARE table lock can invert this
-- destructive-down order.
SELECT pg_advisory_xact_lock(
    hashtextextended('chutes.chutefs-schema-fence.v1', 0)
);
LOCK TABLE gpu_launch_reservations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE instances IN ACCESS EXCLUSIVE MODE;
LOCK TABLE jobs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE launch_configs IN ACCESS EXCLUSIVE MODE;
LOCK TABLE servers IN ACCESS EXCLUSIVE MODE;
LOCK TABLE storage_volume_keys IN ACCESS EXCLUSIVE MODE;
LOCK TABLE storage_volumes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE users IN ACCESS EXCLUSIVE MODE;
LOCK TABLE chutefs_launch_sessions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE default_chutefs_volume_bindings IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM default_chutefs_volume_bindings)
       OR EXISTS (SELECT 1 FROM chutefs_launch_sessions)
       OR EXISTS (
           SELECT 1
             FROM storage_volumes volume
            WHERE (volume.purged_at IS NULL OR volume.key_shredded_at IS NULL)
              AND NOT EXISTS (
                  SELECT 1
                    FROM default_chutefs_volume_bindings binding
                   WHERE binding.volume_id = volume.volume_id
              )
       )
       OR EXISTS (SELECT 1 FROM storage_volume_keys)
       OR EXISTS (
           SELECT 1
            FROM launch_configs
            WHERE default_volume_id IS NOT NULL
               OR storage_session_exchange_allowed
               OR (failed_at IS NULL AND completed_at IS NULL)
       )
       OR EXISTS (
           SELECT 1
             FROM launch_configs
            WHERE job_id IS NOT NULL
              AND failed_at IS NULL
            GROUP BY job_id
           HAVING COUNT(*) > 1
       )
    THEN
        RAISE EXCEPTION
            'cannot roll back default ChuteFS volumes while migration-owned state exists';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_reservation_change
    ON gpu_launch_reservations;
DROP FUNCTION IF EXISTS revoke_chutefs_session_on_reservation_change();
DROP TRIGGER IF EXISTS trg_prevent_user_delete_before_chutefs_erasure ON users;
DROP FUNCTION IF EXISTS prevent_user_delete_before_chutefs_erasure();
DROP TRIGGER IF EXISTS trg_complete_launch_config_on_job_terminal ON jobs;
DROP FUNCTION IF EXISTS complete_launch_config_on_job_terminal();
DROP TRIGGER IF EXISTS trg_complete_launch_config_on_instance_terminal ON instances;
DROP FUNCTION IF EXISTS complete_launch_config_on_instance_terminal();
DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_server_change ON servers;
DROP FUNCTION IF EXISTS revoke_chutefs_session_on_server_change();
DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_config_failure ON launch_configs;
DROP FUNCTION IF EXISTS revoke_chutefs_session_on_config_failure();
DROP TRIGGER IF EXISTS trg_revoke_chutefs_session_on_instance_disable ON instances;
DROP FUNCTION IF EXISTS revoke_chutefs_session_on_instance_disable();
DROP TRIGGER IF EXISTS trg_chutefs_launch_session_identity ON chutefs_launch_sessions;
DROP FUNCTION IF EXISTS enforce_chutefs_launch_session_identity();
DROP TABLE IF EXISTS chutefs_launch_sessions;
DROP TRIGGER IF EXISTS trg_instance_storage_revocation_epoch ON instances;
DROP FUNCTION IF EXISTS enforce_instance_storage_revocation_epoch();
ALTER TABLE instances
    DROP CONSTRAINT IF EXISTS ck_instances_storage_revocation_epoch;
ALTER TABLE instances DROP COLUMN IF EXISTS storage_revocation_epoch;
DROP TRIGGER IF EXISTS trg_launch_storage_identity_immutable ON launch_configs;
DROP FUNCTION IF EXISTS enforce_launch_storage_identity_immutable();
CREATE OR REPLACE FUNCTION revoke_registry_scope_on_launch_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.failed_at IS NOT NULL
       OR NEW.verification_error IS NOT NULL
       OR NOT NEW.registry_scope_active THEN
        UPDATE registry_sessions
        SET revoked_at = COALESCE(revoked_at, NOW())
        WHERE launch_config_id = NEW.config_id
          AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_launch_terminal_registry_scope ON launch_configs;
CREATE TRIGGER trg_launch_terminal_registry_scope
AFTER UPDATE OF failed_at, verification_error, registry_scope_active ON launch_configs
FOR EACH ROW EXECUTE FUNCTION revoke_registry_scope_on_launch_terminal();
ALTER TABLE launch_configs DROP CONSTRAINT IF EXISTS ck_launch_config_compute_type;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS storage_session_exchange_allowed;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS default_volume_id;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS completed_at;
CREATE UNIQUE INDEX IF NOT EXISTS uq_job_launch_config_active
    ON launch_configs (job_id)
    WHERE job_id IS NOT NULL AND failed_at IS NULL;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS compute_type;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS user_id;
DROP TRIGGER IF EXISTS trg_bound_chutefs_owner_immutable ON storage_volumes;
DROP FUNCTION IF EXISTS prevent_bound_chutefs_owner_change();
DROP TRIGGER IF EXISTS trg_default_chutefs_binding_identity
    ON default_chutefs_volume_bindings;
DROP FUNCTION IF EXISTS enforce_default_chutefs_binding_identity();
DROP TABLE IF EXISTS default_chutefs_volume_bindings;
