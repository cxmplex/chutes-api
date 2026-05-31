-- migrate:up

-- CPU-only (GPU-less) TEE server inventory. CPU servers create no GPU Node rows; their
-- capacity and benchmark live directly on the servers row.
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS compute_type VARCHAR NOT NULL DEFAULT 'gpu';

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS cpu_cores INTEGER;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS ram_gb INTEGER;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS benchmark_score DOUBLE PRECISION;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS benchmark JSONB;

-- migrate:down

ALTER TABLE servers DROP COLUMN IF EXISTS benchmark;
ALTER TABLE servers DROP COLUMN IF EXISTS benchmark_score;
ALTER TABLE servers DROP COLUMN IF EXISTS ram_gb;
ALTER TABLE servers DROP COLUMN IF EXISTS cpu_cores;
ALTER TABLE servers DROP COLUMN IF EXISTS compute_type;
