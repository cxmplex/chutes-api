-- migrate:up

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS last_health_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_servers_last_health
    ON servers (last_health_at);

-- migrate:down

-- This catch-up only repairs databases where the upstream migration was historically
-- baselined. The column and index remain owned by 20260626120000_server_health.sql.
SELECT 1;
