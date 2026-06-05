-- migrate:up

-- Model B (per-chute TD): the public host + per-TD DNAT'd external ports that reach this TD via the
-- L0 launcher host (e.g. {"primary":31000,"logging":31001,"attestation":31002}). Reported by the
-- in-guest agent at CPU self-registration. The scheduler deploys chutes with these so the chute
-- advertises the externally reachable public_host:<ext> rather than the in-TD :8000 -- which also
-- keeps multiple TDs on one host from colliding on the unique (host, port) instances index.
-- NULL for standalone single-VM self-registrations (external == internal).
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS external_host VARCHAR;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS external_ports JSONB;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS external_ports;
ALTER TABLE servers DROP COLUMN IF EXISTS external_host;
