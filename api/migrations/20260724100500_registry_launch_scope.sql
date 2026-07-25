-- migrate:up

ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS container_repository TEXT,
    ADD COLUMN IF NOT EXISTS container_manifest_digest TEXT,
    ADD COLUMN IF NOT EXISTS registry_scope_active BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS registry_scope_revoked_at TIMESTAMPTZ;

ALTER TABLE launch_configs DROP CONSTRAINT IF EXISTS ck_launch_config_registry_scope;
ALTER TABLE launch_configs
    ADD CONSTRAINT ck_launch_config_registry_scope
    CHECK (
        (container_repository IS NULL AND container_manifest_digest IS NULL
         AND NOT registry_scope_active AND registry_scope_revoked_at IS NULL)
        OR (
            server_id IS NOT NULL
            AND container_repository IS NOT NULL
            AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
            AND (
                (gpu_management_mode = 'miner'
                 AND (registry_scope_active OR registry_scope_revoked_at IS NOT NULL))
                OR
                (gpu_management_mode IS DISTINCT FROM 'miner'
                 AND NOT registry_scope_active AND registry_scope_revoked_at IS NULL)
            )
        )
    );

ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS scope_id TEXT,
    ADD COLUMN IF NOT EXISTS launch_config_id TEXT;

UPDATE registry_sessions
SET scope_id = 'legacy:' || session_id
WHERE scope_id IS NULL;

ALTER TABLE registry_sessions ALTER COLUMN scope_id SET NOT NULL;
ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS uq_registry_session_server;
ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS uq_registry_session_server_scope;
ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS fk_registry_session_launch_config;
ALTER TABLE registry_sessions
    ADD CONSTRAINT uq_registry_session_server_scope UNIQUE (server_id, scope_id);
ALTER TABLE registry_sessions
    ADD CONSTRAINT fk_registry_session_launch_config
        FOREIGN KEY (launch_config_id)
        REFERENCES launch_configs(config_id)
        ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION revoke_launch_registry_scope(p_config_id TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE launch_configs
    SET registry_scope_active = FALSE,
        registry_scope_revoked_at = COALESCE(registry_scope_revoked_at, NOW())
    WHERE config_id = p_config_id
      AND registry_scope_active;
    UPDATE registry_sessions
    SET revoked_at = COALESCE(revoked_at, NOW())
    WHERE launch_config_id = p_config_id
      AND revoked_at IS NULL;
END
$$;

CREATE OR REPLACE FUNCTION revoke_registry_scope_on_instance_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_config_id TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_config_id := OLD.config_id;
    ELSIF NEW.verification_error IS NOT NULL
          OR NEW.stop_billing_at IS NOT NULL
          OR (NEW.verified AND NOT NEW.active) THEN
        target_config_id := NEW.config_id;
    END IF;
    IF target_config_id IS NOT NULL THEN
        PERFORM revoke_launch_registry_scope(target_config_id);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_instance_terminal_registry_scope ON instances;
CREATE TRIGGER trg_instance_terminal_registry_scope
AFTER UPDATE OF active, verified, verification_error, stop_billing_at OR DELETE ON instances
FOR EACH ROW EXECUTE FUNCTION revoke_registry_scope_on_instance_terminal();

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

CREATE OR REPLACE FUNCTION revoke_registry_scope_on_job_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    config RECORD;
    target_job_id TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_job_id := OLD.job_id;
    ELSIF NEW.finished_at IS NOT NULL OR NEW.miner_terminated IS TRUE THEN
        target_job_id := NEW.job_id;
    END IF;
    IF target_job_id IS NOT NULL THEN
        FOR config IN
            SELECT config_id
            FROM launch_configs
            WHERE job_id = target_job_id
        LOOP
            PERFORM revoke_launch_registry_scope(config.config_id);
        END LOOP;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_job_terminal_registry_scope ON jobs;
CREATE TRIGGER trg_job_terminal_registry_scope
AFTER UPDATE OF finished_at, miner_terminated OR DELETE ON jobs
FOR EACH ROW EXECUTE FUNCTION revoke_registry_scope_on_job_terminal();

-- migrate:down

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM registry_sessions
        GROUP BY server_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot restore unique registry session per server while multiple scoped sessions exist';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_instance_terminal_registry_scope ON instances;
DROP TRIGGER IF EXISTS trg_launch_terminal_registry_scope ON launch_configs;
DROP TRIGGER IF EXISTS trg_job_terminal_registry_scope ON jobs;
DROP FUNCTION IF EXISTS revoke_registry_scope_on_instance_terminal();
DROP FUNCTION IF EXISTS revoke_registry_scope_on_launch_terminal();
DROP FUNCTION IF EXISTS revoke_registry_scope_on_job_terminal();
DROP FUNCTION IF EXISTS revoke_launch_registry_scope(TEXT);

ALTER TABLE registry_sessions
    DROP CONSTRAINT IF EXISTS fk_registry_session_launch_config,
    DROP CONSTRAINT IF EXISTS uq_registry_session_server_scope,
    DROP CONSTRAINT IF EXISTS uq_registry_session_server,
    ADD CONSTRAINT uq_registry_session_server UNIQUE (server_id),
    DROP COLUMN IF EXISTS launch_config_id,
    DROP COLUMN IF EXISTS scope_id;

ALTER TABLE launch_configs
    DROP CONSTRAINT IF EXISTS ck_launch_config_registry_scope,
    DROP COLUMN IF EXISTS registry_scope_revoked_at,
    DROP COLUMN IF EXISTS registry_scope_active,
    DROP COLUMN IF EXISTS container_manifest_digest,
    DROP COLUMN IF EXISTS container_repository;
