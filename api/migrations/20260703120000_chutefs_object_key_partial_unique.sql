-- migrate:up

-- ChuteFS: scope object-key uniqueness to non-deleted objects (matching storage_volumes), so a
-- soft-deleted key can be re-PUT. The original unconditional UNIQUE(volume_id, object_key) turned
-- a normal delete-then-reupload into a permanent IntegrityError (500), because the soft-deleted row
-- is retained and plan_object_placement inserts a fresh row on the next PUT.
--
-- The original constraint was created UNNAMED in-line (`UNIQUE (volume_id, object_key)`), so
-- Postgres auto-named it `storage_objects_volume_id_object_key_key`; drop that and the ORM-named
-- variant so this applies cleanly regardless of how the table was materialized.
ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS storage_objects_volume_id_object_key_key;
ALTER TABLE storage_objects DROP CONSTRAINT IF EXISTS uq_storage_object_key;
DROP INDEX IF EXISTS uq_storage_object_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_object_key
    ON storage_objects (volume_id, object_key)
    WHERE deleted IS false;

-- migrate:down

DROP INDEX IF EXISTS uq_storage_object_key;
ALTER TABLE storage_objects ADD CONSTRAINT uq_storage_object_key UNIQUE (volume_id, object_key);
