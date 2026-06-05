-- migrate:up

-- TEE provider for a server's attestation: 'tdx' (Intel, default) or 'sev-snp' (AMD SEV-SNP).
-- Stamped at CPU self-registration; selects the re-attestation verifier (Intel dcap-qvl vs the
-- AMD VCEK->ASK->ARK chain). Defaults to 'tdx' so existing rows keep their current behavior.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS tee_type VARCHAR NOT NULL DEFAULT 'tdx';

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS tee_type;
