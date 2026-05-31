-- migrate:up

-- Explicit server linkage for 1-click self-registered CPU servers. Instances on the existing
-- (miner-run) path resolve their server by GPU nodes or host+hotkey; self-registered CPU servers
-- have neither GPU nodes nor a per-miner control plane, so the validator-driven scheduler stamps
-- the target server_id onto the launch config, and it is carried onto the created instance.
ALTER TABLE launch_configs
    ADD COLUMN IF NOT EXISTS server_id VARCHAR REFERENCES servers(server_id) ON DELETE SET NULL;

ALTER TABLE instances
    ADD COLUMN IF NOT EXISTS server_id VARCHAR REFERENCES servers(server_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_instances_server_id ON instances (server_id);

-- migrate:down

DROP INDEX IF EXISTS idx_instances_server_id;
ALTER TABLE instances DROP COLUMN IF EXISTS server_id;
ALTER TABLE launch_configs DROP COLUMN IF EXISTS server_id;
