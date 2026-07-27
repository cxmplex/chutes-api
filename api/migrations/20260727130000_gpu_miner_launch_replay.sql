-- migrate:up

ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS miner_launch_request_id VARCHAR(36),
    ADD COLUMN IF NOT EXISTS miner_launch_request_sha256 VARCHAR(64);

ALTER TABLE launch_configs
    DROP CONSTRAINT IF EXISTS ck_launch_config_miner_request_replay;
ALTER TABLE launch_configs
    ADD CONSTRAINT ck_launch_config_miner_request_replay
    CHECK (
        (miner_launch_request_id IS NULL
         AND miner_launch_request_sha256 IS NULL)
        OR
        (miner_launch_request_id ~
             '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
         AND miner_launch_request_sha256 ~ '^[0-9a-f]{64}$')
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_launch_configs_miner_request
    ON launch_configs (miner_hotkey, miner_launch_request_id)
    WHERE miner_launch_request_id IS NOT NULL;

CREATE OR REPLACE FUNCTION enforce_miner_launch_request_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.miner_launch_request_id IS DISTINCT FROM NEW.miner_launch_request_id
       OR OLD.miner_launch_request_sha256
          IS DISTINCT FROM NEW.miner_launch_request_sha256 THEN
        RAISE EXCEPTION
            'miner launch request identity is immutable for launch config %',
            OLD.config_id;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_miner_launch_request_immutable ON launch_configs;
CREATE TRIGGER trg_miner_launch_request_immutable
BEFORE UPDATE OF miner_launch_request_id, miner_launch_request_sha256
ON launch_configs
FOR EACH ROW EXECUTE FUNCTION enforce_miner_launch_request_immutable();

-- migrate:down

-- This migration owns only two launch-config replay fields.  Take the table
-- lock before inspecting them so a concurrent writer cannot pass the guard and
-- publish replay state immediately before destructive DDL.
LOCK TABLE launch_configs IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM launch_configs
         WHERE miner_launch_request_id IS NOT NULL
            OR miner_launch_request_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot discard durable miner launch response replay state';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_miner_launch_request_immutable ON launch_configs;
DROP FUNCTION IF EXISTS enforce_miner_launch_request_immutable();
DROP INDEX IF EXISTS uq_launch_configs_miner_request;
ALTER TABLE launch_configs
    DROP CONSTRAINT IF EXISTS ck_launch_config_miner_request_replay,
    DROP COLUMN IF EXISTS miner_launch_request_sha256,
    DROP COLUMN IF EXISTS miner_launch_request_id;
