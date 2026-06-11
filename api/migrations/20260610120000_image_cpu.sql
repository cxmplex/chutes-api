-- migrate:up

-- CPU-only chute images skip the GPU-oriented filesystem-verification (cfsv) + inspecto build
-- stage; the flag marks an image as built by the CPU-TEE forge path (see api/image/schemas.py).
ALTER TABLE images
    ADD COLUMN IF NOT EXISTS cpu BOOLEAN NOT NULL DEFAULT false;

-- migrate:down

ALTER TABLE images DROP COLUMN IF EXISTS cpu;
