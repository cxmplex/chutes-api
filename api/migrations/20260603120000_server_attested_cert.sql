-- migrate:up

-- Attestation-bound TLS serving cert (PEM) for 1-click self-registered CPU TEE servers. The cert's
-- public-key hash is bound into the server's TDX registration quote report_data (verify_quote at
-- POST /servers/cpu/register), so this PEM is the attested TLS identity of the Trust Domain. The
-- validator pins it as the instance cacert so the validator<->chute user-data transport is TLS
-- terminated INSIDE the attested TD -- the untrusted host (which routes the TD's traffic) cannot
-- MITM, read, or tamper with it.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS attested_cert TEXT;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS attested_cert;
