-- migrate:up

ALTER TABLE images
    ADD COLUMN IF NOT EXISTS compute_type TEXT;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'images'
          AND column_name = 'cpu'
    ) THEN
        EXECUTE
            'UPDATE images SET compute_type = CASE WHEN cpu IS TRUE THEN ''cpu'' ELSE ''gpu'' END '
            'WHERE compute_type IS NULL';
    ELSE
        UPDATE images SET compute_type = 'gpu' WHERE compute_type IS NULL;
    END IF;
END
$$;

ALTER TABLE images
    ALTER COLUMN compute_type SET DEFAULT 'gpu',
    ALTER COLUMN compute_type SET NOT NULL;

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS ck_images_compute_type;
ALTER TABLE images
    ADD CONSTRAINT ck_images_compute_type CHECK (compute_type IN ('cpu', 'gpu'));

ALTER TABLE images DROP COLUMN IF EXISTS cpu;

-- migrate:down

ALTER TABLE images
    ADD COLUMN IF NOT EXISTS cpu BOOLEAN NOT NULL DEFAULT false;

UPDATE images SET cpu = (compute_type = 'cpu');

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS ck_images_compute_type;

ALTER TABLE images DROP COLUMN IF EXISTS compute_type;
