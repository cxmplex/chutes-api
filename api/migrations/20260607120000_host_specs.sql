-- migrate:up

-- Model B L0 hosts report auto-discovered hardware inventory at registration (CPU/RAM/baseboard/
-- system/BIOS). cpu_cores + ram_gb are denormalized for querying/scheduling; full detail is in specs.
-- The host is NOT attested -- this inventory is informational, established by hotkey-signed registration.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS cpu_cores INTEGER;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS ram_gb INTEGER;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS specs JSONB;

-- migrate:down

ALTER TABLE hosts DROP COLUMN IF EXISTS specs;
ALTER TABLE hosts DROP COLUMN IF EXISTS ram_gb;
ALTER TABLE hosts DROP COLUMN IF EXISTS cpu_cores;
