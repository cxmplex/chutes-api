-- migrate:up

-- KC-02/KC-03: retain an unresolved per-volume key release as one exclusive generation lease.
-- The matching pending passphrase remains in volume_passphrases; this JSONB state binds that key
-- and generation to the registered server/certificate capability until exact confirmation
-- atomically advances volume_epochs (the confirmed generation floor) and clears the lease.
ALTER TABLE vm_cache_configs
    ADD COLUMN IF NOT EXISTS volume_generation_leases JSONB NOT NULL DEFAULT '{}'::jsonb;

-- migrate:down

ALTER TABLE vm_cache_configs DROP COLUMN IF EXISTS volume_generation_leases;
