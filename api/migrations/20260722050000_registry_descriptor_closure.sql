-- migrate:up

ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS allowed_manifests JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS allowed_blobs JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS allowed_manifest_tags JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE registry_sessions
    ADD COLUMN IF NOT EXISTS descriptor_closure_sha256 TEXT;

ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS ck_registry_session_closure;
ALTER TABLE registry_sessions
    ADD CONSTRAINT ck_registry_session_closure CHECK (
        jsonb_typeof(allowed_manifests) = 'array'
        AND jsonb_typeof(allowed_blobs) = 'array'
        AND jsonb_typeof(allowed_manifest_tags) = 'array'
        AND (
            descriptor_closure_sha256 IS NULL
            OR descriptor_closure_sha256 ~ '^[0-9a-f]{64}$'
        )
    );

-- migrate:down

ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS ck_registry_session_closure;
ALTER TABLE registry_sessions DROP COLUMN IF EXISTS descriptor_closure_sha256;
ALTER TABLE registry_sessions DROP COLUMN IF EXISTS allowed_manifest_tags;
ALTER TABLE registry_sessions DROP COLUMN IF EXISTS allowed_blobs;
ALTER TABLE registry_sessions DROP COLUMN IF EXISTS allowed_manifests;
