-- migrate:up

-- Model B (per-chute confidential VMs): bare-metal L0 launcher hosts. A host is a launcher only
-- (NOT attested) -- it registers by miner-hotkey signature so the CPU scheduler can dispatch
-- per-chute TD launches to it over the control channel; workload trust is each TD's own attestation.
CREATE TABLE IF NOT EXISTS hosts (
    host_id        VARCHAR PRIMARY KEY,
    name           VARCHAR NOT NULL,
    miner_hotkey   VARCHAR NOT NULL,
    netuid         INTEGER NOT NULL DEFAULT 64,
    tee_type       VARCHAR NOT NULL DEFAULT 'tdx',
    capacity       INTEGER NOT NULL DEFAULT 1,
    default_mem    VARCHAR,
    default_vcpus  INTEGER,
    external_host  VARCHAR,
    created_at     TIMESTAMPTZ DEFAULT now(),
    updated_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_hosts_miner ON hosts (miner_hotkey);

-- The L0 host (hosts.host_id) that launched a per-chute TD; NULL for standalone single-VM
-- self-registrations. Lets the validator account per-host capacity + tear down a host's TDs.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS host_id VARCHAR;
CREATE INDEX IF NOT EXISTS idx_servers_host_id ON servers (host_id) WHERE host_id IS NOT NULL;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS host_id;
DROP TABLE IF EXISTS hosts;
