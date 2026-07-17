-- migrate:up

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

ALTER TABLE images
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
ALTER TABLE images
    ADD COLUMN IF NOT EXISTS artifact_id TEXT;

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

-- Keep the immutable object-store namespace even though image_id is rekeyed below.
UPDATE images SET artifact_id = image_id WHERE artifact_id IS NULL;

ALTER TABLE images
    ALTER COLUMN compute_type SET DEFAULT 'gpu',
    ALTER COLUMN compute_type SET NOT NULL;
ALTER TABLE images
    ALTER COLUMN artifact_id SET NOT NULL;

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS ck_images_compute_type;
ALTER TABLE images
    ADD CONSTRAINT ck_images_compute_type CHECK (compute_type IN ('cpu', 'gpu'));
ALTER TABLE images
    DROP CONSTRAINT IF EXISTS uq_images_artifact_id;
ALTER TABLE images
    ADD CONSTRAINT uq_images_artifact_id UNIQUE (artifact_id);

CREATE TEMP TABLE image_compute_type_id_cutover (
    old_image_id TEXT PRIMARY KEY,
    new_image_id TEXT NOT NULL UNIQUE
) ON COMMIT DROP;

DO $$
DECLARE
    uuid_extension_schema TEXT;
BEGIN
    SELECT namespace.nspname
    INTO uuid_extension_schema
    FROM pg_extension extension
    JOIN pg_namespace namespace ON namespace.oid = extension.extnamespace
    WHERE extension.extname = 'uuid-ossp';

    IF uuid_extension_schema IS NULL THEN
        RAISE EXCEPTION 'uuid-ossp extension schema could not be resolved';
    END IF;

    EXECUTE format(
        $cutover$
        INSERT INTO image_compute_type_id_cutover (old_image_id, new_image_id)
        SELECT
            image.image_id,
            %I.uuid_generate_v5(
                %I.uuid_ns_oid(),
                lower(
                    app_user.username || '/' || image.name || ':' || image.tag || ':' ||
                    image.compute_type
                )
            )::text
        FROM images image
        JOIN users app_user ON app_user.user_id = image.user_id
        $cutover$,
        uuid_extension_schema,
        uuid_extension_schema
    );
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM image_compute_type_id_cutover cutover
        JOIN images collision ON collision.image_id = cutover.new_image_id
        WHERE collision.image_id <> cutover.old_image_id
    ) THEN
        RAISE EXCEPTION 'compute-specific image ID collides with an existing image';
    END IF;
END
$$;

-- The only live FK to images.image_id is chutes.image_id. Verify that exact
-- catalog shape, then make primary-key rekeys cascade instead of disabling FKs.
DO $$
DECLARE
    image_fk_count INTEGER;
    image_fk_name TEXT;
BEGIN
    SELECT count(*), min(constraint_row.conname)
    INTO image_fk_count, image_fk_name
    FROM pg_constraint constraint_row
    WHERE constraint_row.contype = 'f'
      AND constraint_row.conrelid = to_regclass(
          format('%I.%I', current_schema(), 'chutes')
      )
      AND constraint_row.confrelid = to_regclass(
          format('%I.%I', current_schema(), 'images')
      )
      AND constraint_row.conkey = ARRAY[(
          SELECT attribute.attnum
          FROM pg_attribute attribute
          WHERE attribute.attrelid = constraint_row.conrelid
            AND attribute.attname = 'image_id'
            AND NOT attribute.attisdropped
      )]::SMALLINT[]
      AND constraint_row.confkey = ARRAY[(
          SELECT attribute.attnum
          FROM pg_attribute attribute
          WHERE attribute.attrelid = constraint_row.confrelid
            AND attribute.attname = 'image_id'
            AND NOT attribute.attisdropped
      )]::SMALLINT[];

    IF image_fk_count <> 1 THEN
        RAISE EXCEPTION
            'expected exactly one chutes.image_id -> images.image_id FK, found %',
            image_fk_count;
    END IF;

    EXECUTE format('ALTER TABLE chutes DROP CONSTRAINT %I', image_fk_name);
    EXECUTE format(
        'ALTER TABLE chutes ADD CONSTRAINT %I '
        'FOREIGN KEY (image_id) REFERENCES images(image_id) ON UPDATE CASCADE',
        image_fk_name
    );
END
$$;

UPDATE images image
SET image_id = cutover.new_image_id
FROM image_compute_type_id_cutover cutover
WHERE image.image_id = cutover.old_image_id
  AND cutover.old_image_id <> cutover.new_image_id;

-- These are historical/analytics references rather than FKs, so update every
-- table that actually exists in the deployed schema.
DO $$
BEGIN
    IF to_regclass(format('%I.%I', current_schema(), 'image_history')) IS NOT NULL THEN
        UPDATE image_history history
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE history.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;

    IF to_regclass(format('%I.%I', current_schema(), 'chute_history')) IS NOT NULL THEN
        UPDATE chute_history history
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE history.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;

    IF to_regclass(format('%I.%I', current_schema(), 'partitioned_invocations')) IS NOT NULL THEN
        UPDATE partitioned_invocations invocation
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE invocation.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;
END
$$;

ALTER TABLE images DROP COLUMN IF EXISTS cpu;

-- migrate:down

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

ALTER TABLE images
    ADD COLUMN IF NOT EXISTS cpu BOOLEAN NOT NULL DEFAULT false;

UPDATE images SET cpu = (compute_type = 'cpu');

CREATE TEMP TABLE image_compute_type_id_cutover (
    old_image_id TEXT PRIMARY KEY,
    new_image_id TEXT NOT NULL UNIQUE
) ON COMMIT DROP;

DO $$
DECLARE
    uuid_extension_schema TEXT;
BEGIN
    SELECT namespace.nspname
    INTO uuid_extension_schema
    FROM pg_extension extension
    JOIN pg_namespace namespace ON namespace.oid = extension.extnamespace
    WHERE extension.extname = 'uuid-ossp';

    IF uuid_extension_schema IS NULL THEN
        RAISE EXCEPTION 'uuid-ossp extension schema could not be resolved';
    END IF;

    EXECUTE format(
        $cutover$
        INSERT INTO image_compute_type_id_cutover (old_image_id, new_image_id)
        SELECT
            image.image_id,
            %I.uuid_generate_v5(
                %I.uuid_ns_oid(),
                lower(app_user.username || '/' || image.name || ':' || image.tag)
            )::text
        FROM images image
        JOIN users app_user ON app_user.user_id = image.user_id
        $cutover$,
        uuid_extension_schema,
        uuid_extension_schema
    );
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM images image
        JOIN image_compute_type_id_cutover cutover
          ON cutover.old_image_id = image.image_id
        WHERE image.artifact_id <> cutover.new_image_id
    ) THEN
        RAISE EXCEPTION
            'cannot reverse image ID cutover after images were created under compute-specific IDs';
    END IF;
END
$$;

UPDATE images image
SET image_id = cutover.new_image_id
FROM image_compute_type_id_cutover cutover
WHERE image.image_id = cutover.old_image_id
  AND cutover.old_image_id <> cutover.new_image_id;

DO $$
BEGIN
    IF to_regclass(format('%I.%I', current_schema(), 'image_history')) IS NOT NULL THEN
        UPDATE image_history history
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE history.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;

    IF to_regclass(format('%I.%I', current_schema(), 'chute_history')) IS NOT NULL THEN
        UPDATE chute_history history
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE history.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;

    IF to_regclass(format('%I.%I', current_schema(), 'partitioned_invocations')) IS NOT NULL THEN
        UPDATE partitioned_invocations invocation
        SET image_id = cutover.new_image_id
        FROM image_compute_type_id_cutover cutover
        WHERE invocation.image_id = cutover.old_image_id
          AND cutover.old_image_id <> cutover.new_image_id;
    END IF;
END
$$;

DO $$
DECLARE
    image_fk_count INTEGER;
    image_fk_name TEXT;
BEGIN
    SELECT count(*), min(constraint_row.conname)
    INTO image_fk_count, image_fk_name
    FROM pg_constraint constraint_row
    WHERE constraint_row.contype = 'f'
      AND constraint_row.conrelid = to_regclass(
          format('%I.%I', current_schema(), 'chutes')
      )
      AND constraint_row.confrelid = to_regclass(
          format('%I.%I', current_schema(), 'images')
      )
      AND constraint_row.conkey = ARRAY[(
          SELECT attribute.attnum
          FROM pg_attribute attribute
          WHERE attribute.attrelid = constraint_row.conrelid
            AND attribute.attname = 'image_id'
            AND NOT attribute.attisdropped
      )]::SMALLINT[]
      AND constraint_row.confkey = ARRAY[(
          SELECT attribute.attnum
          FROM pg_attribute attribute
          WHERE attribute.attrelid = constraint_row.confrelid
            AND attribute.attname = 'image_id'
            AND NOT attribute.attisdropped
      )]::SMALLINT[];

    IF image_fk_count <> 1 THEN
        RAISE EXCEPTION
            'expected exactly one chutes.image_id -> images.image_id FK, found %',
            image_fk_count;
    END IF;

    EXECUTE format('ALTER TABLE chutes DROP CONSTRAINT %I', image_fk_name);
    EXECUTE format(
        'ALTER TABLE chutes ADD CONSTRAINT %I '
        'FOREIGN KEY (image_id) REFERENCES images(image_id)',
        image_fk_name
    );
END
$$;

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS ck_images_compute_type;
ALTER TABLE images
    DROP CONSTRAINT IF EXISTS uq_images_artifact_id;

ALTER TABLE images DROP COLUMN IF EXISTS compute_type;
ALTER TABLE images DROP COLUMN IF EXISTS artifact_id;
