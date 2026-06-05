-- migrate:up

-- User-attestable instance reach info advertised by the in-TEE agent at CPU registration:
-- {"host", "attest_port", "provision_port", "ssh_port", "wg_port"}. Returned by the
-- owner-authenticated GET /servers/cpu/{id}/connection (with a minted provision token + manifest)
-- so `chutes ssh/connect <id>` can locate + attest the instance without explicit flags. Discovery
-- convenience only -- the trust decision is the client-side attestation, not this record.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS tee_endpoints JSONB;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS tee_endpoints;
