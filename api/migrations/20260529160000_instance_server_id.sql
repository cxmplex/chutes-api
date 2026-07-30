-- migrate:up

-- Explicit server linkage for 1-click self-registered CPU servers. Instances on the existing
-- (miner-run) path resolve their server by GPU nodes or host+hotkey; self-registered CPU servers
-- have neither GPU nodes nor a per-miner control plane, so the validator-driven scheduler stamps
-- the target server_id onto the launch config, and it is carried onto the created instance.
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS server_id VARCHAR;

ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS server_id VARCHAR;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_launch_configs_server'
          AND conrelid = 'launch_configs'::regclass
    ) THEN
        ALTER TABLE launch_configs
            ADD CONSTRAINT fk_launch_configs_server
            FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_instances_server'
          AND conrelid = 'instances'::regclass
    ) THEN
        ALTER TABLE instances
            ADD CONSTRAINT fk_instances_server
            FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_instances_server_id ON instances (server_id);

-- migrate:down

DROP INDEX IF EXISTS idx_instances_server_id;
ALTER TABLE instances DROP COLUMN IF EXISTS server_id;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS server_id;
