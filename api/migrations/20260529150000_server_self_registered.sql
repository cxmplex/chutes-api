-- migrate:up

-- 1-click self-registering CPU TEE servers: distinguishes servers that attested + checked in
-- themselves (via POST /servers/cpu/register) from servers advertised by a miner control plane.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS self_registered BOOLEAN NOT NULL DEFAULT false;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS self_registered;
