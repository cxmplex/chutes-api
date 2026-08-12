-- migrate:up

-- Historical release rows predate the deterministic publisher and remain readable with a NULL
-- identity. Every API-created row after this migration is required by the route/service to carry
-- the SHA-256 of its canonical create request.
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS release_request_sha256 VARCHAR(64);

ALTER TABLE guest_releases
    DROP CONSTRAINT IF EXISTS ck_guest_releases_request_sha256;
ALTER TABLE guest_releases
    ADD CONSTRAINT ck_guest_releases_request_sha256 CHECK (
        release_request_sha256 IS NULL
        OR release_request_sha256 ~ '^[0-9a-f]{64}$'
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_guest_releases_request_sha256
    ON guest_releases (release_request_sha256)
    WHERE release_request_sha256 IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_guest_release_request_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.release_request_sha256 IS DISTINCT FROM OLD.release_request_sha256 THEN
        RAISE EXCEPTION 'guest release request identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_guest_release_request_identity_immutable ON guest_releases;
CREATE TRIGGER trg_guest_release_request_identity_immutable
BEFORE UPDATE OF release_request_sha256 ON guest_releases
FOR EACH ROW EXECUTE FUNCTION prevent_guest_release_request_identity_mutation();

-- migrate:down

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM guest_releases WHERE release_request_sha256 IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot downgrade after durable guest release request identities have been used';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_guest_release_request_identity_immutable ON guest_releases;
DROP FUNCTION IF EXISTS prevent_guest_release_request_identity_mutation();
DROP INDEX IF EXISTS uq_guest_releases_request_sha256;
ALTER TABLE guest_releases
    DROP CONSTRAINT IF EXISTS ck_guest_releases_request_sha256,
    DROP COLUMN IF EXISTS release_request_sha256;
