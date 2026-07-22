-- migrate:up

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS storage_td_vcpus INTEGER;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS storage_td_mem TEXT;

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_storage_td_profile;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_storage_td_profile CHECK (
        (
            storage_td_vcpus IS NULL
            AND storage_td_mem IS NULL
        )
        OR
        (
            storage_td_vcpus BETWEEN 1 AND 4096
            AND storage_td_mem ~ '^[1-9][0-9]*(G|M)$'
        )
    );

CREATE TABLE IF NOT EXISTS storage_launch_intents (
    intent_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL UNIQUE
        REFERENCES guest_release_targets(target_id) ON DELETE RESTRICT,
    release_id TEXT NOT NULL
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    tee_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    host_id TEXT NOT NULL
        REFERENCES hosts(host_id) ON DELETE RESTRICT,
    owner_hotkey TEXT NOT NULL,
    server_id TEXT NOT NULL,
    process_incarnation TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    image_sha256 TEXT NOT NULL,
    image_version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    claim_generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_claimed_at TIMESTAMPTZ,
    CONSTRAINT ck_storage_launch_intent_tee
        CHECK (tee_type IN ('sev-snp', 'tdx')),
    CONSTRAINT ck_storage_launch_intent_state
        CHECK (state IN ('active', 'superseded')),
    CONSTRAINT ck_storage_launch_intent_generation
        CHECK (claim_generation >= 0),
    CONSTRAINT ck_storage_launch_intent_image_sha
        CHECK (image_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_storage_launch_intents_slot
    ON storage_launch_intents (tee_type, channel, state, host_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_launch_intent_active_host
    ON storage_launch_intents (tee_type, channel, host_id)
    WHERE state = 'active';

WITH latest_storage AS (
    SELECT DISTINCT ON (host_id)
        host_id,
        profile_id
    FROM td_launch_reservations
    WHERE role = 'storage'
    ORDER BY
        host_id,
        consumed_at DESC NULLS LAST,
        issued_at DESC,
        reservation_id DESC
)
UPDATE hosts AS host
SET
    storage_td_vcpus = (
        regexp_match(latest.profile_id, '-([0-9]+)vcpu(?:-[0-9]+g)?$')
    )[1]::INTEGER,
    storage_td_mem = UPPER(
        COALESCE(
            (
                regexp_match(latest.profile_id, '-[0-9]+vcpu-([0-9]+g)$')
            )[1],
            '8G'
        )
    )::TEXT
FROM latest_storage AS latest
WHERE host.host_id = latest.host_id
  AND latest.profile_id ~ '-[0-9]+vcpu(?:-[0-9]+g)?$'
  AND host.storage_td_vcpus IS NULL
  AND host.storage_td_mem IS NULL;

WITH eligible_targets AS (
    SELECT DISTINCT ON (active.tee_type, active.channel, target.host_id)
        target.target_id,
        target.release_id AS source_release_id,
        target.host_id,
        target.miner_hotkey,
        active.tee_type,
        active.channel,
        active.images -> 'storage' AS image
    FROM guest_release_targets AS target
    JOIN guest_releases AS source
      ON source.release_id = target.release_id
    JOIN guest_releases AS active
      ON active.tee_type = source.tee_type
     AND active.channel = source.channel
     AND active.status = 'active'
    JOIN hosts AS host
      ON host.host_id = target.host_id
     AND host.miner_hotkey = target.miner_hotkey
     AND host.tee_type = active.tee_type
     AND host.release_channel = active.channel
    WHERE target.role = 'storage'
      AND host.storage_enabled IS TRUE
      AND host.provisioning_state = 'ready'
      AND (
          COALESCE(
              (active.images -> 'storage' ->> '_inherited')::BOOLEAN,
              FALSE
          )
          OR target.release_id = active.release_id
      )
      AND source.images -> 'storage' ->> 'sha256'
          = active.images -> 'storage' ->> 'sha256'
      AND source.images -> 'storage' ->> 'version'
          = active.images -> 'storage' ->> 'version'
    ORDER BY
        active.tee_type,
        active.channel,
        target.host_id,
        target.issued_at DESC,
        target.target_id DESC
),
resolved AS (
    SELECT
        target.*,
        reservation.profile_id
    FROM eligible_targets AS target
    JOIN LATERAL (
        SELECT row.profile_id
        FROM td_launch_reservations AS row
        WHERE row.host_id = target.host_id
          AND row.role = 'storage'
          AND row.image_sha256 = target.image ->> 'sha256'
          AND (target.image -> 'measurement_names') ? row.profile_id
        ORDER BY
            row.consumed_at DESC NULLS LAST,
            row.issued_at DESC,
            row.reservation_id DESC
        LIMIT 1
    ) AS reservation ON TRUE
)
INSERT INTO storage_launch_intents (
    intent_id,
    target_id,
    release_id,
    tee_type,
    channel,
    host_id,
    owner_hotkey,
    server_id,
    process_incarnation,
    profile_id,
    image_sha256,
    image_version,
    state,
    claim_generation
)
SELECT
    gen_random_uuid()::TEXT,
    target_id,
    source_release_id,
    tee_type,
    channel,
    host_id,
    miner_hotkey,
    'chute-stor' || SUBSTRING(
        encode(public.digest(convert_to(host_id, 'UTF8'), 'sha256'), 'hex')
        FROM 1 FOR 8
    ),
    'stor' || SUBSTRING(
        encode(public.digest(convert_to(host_id, 'UTF8'), 'sha256'), 'hex')
        FROM 1 FOR 8
    ),
    profile_id,
    image ->> 'sha256',
    image ->> 'version',
    'active',
    0
FROM resolved
ON CONFLICT DO NOTHING;

ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS storage_intent_id TEXT
        REFERENCES storage_launch_intents(intent_id) ON DELETE RESTRICT;
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS storage_intent_generation INTEGER;
ALTER TABLE td_launch_reservations
    ADD COLUMN IF NOT EXISTS claims_sha256 TEXT;

ALTER TABLE td_launch_reservations DROP CONSTRAINT IF EXISTS ck_td_reservation_claims_sha;
ALTER TABLE td_launch_reservations
    ADD CONSTRAINT ck_td_reservation_claims_sha CHECK (
        claims_sha256 IS NULL OR claims_sha256 ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE td_launch_reservations DROP CONSTRAINT IF EXISTS ck_td_reservation_storage_intent;
ALTER TABLE td_launch_reservations
    ADD CONSTRAINT ck_td_reservation_storage_intent CHECK (
        (
            storage_intent_id IS NULL
            AND storage_intent_generation IS NULL
        )
        OR
        (
            role = 'storage'
            AND storage_intent_id IS NOT NULL
            AND storage_intent_generation > 0
        )
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_td_reservation_storage_intent_generation
    ON td_launch_reservations (storage_intent_id, storage_intent_generation)
    WHERE storage_intent_id IS NOT NULL;

-- migrate:down

DROP INDEX IF EXISTS uq_td_reservation_storage_intent_generation;
ALTER TABLE td_launch_reservations DROP CONSTRAINT IF EXISTS ck_td_reservation_storage_intent;
ALTER TABLE td_launch_reservations DROP CONSTRAINT IF EXISTS ck_td_reservation_claims_sha;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS claims_sha256;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS storage_intent_generation;
ALTER TABLE td_launch_reservations DROP COLUMN IF EXISTS storage_intent_id;
DROP INDEX IF EXISTS idx_storage_launch_intents_slot;
DROP INDEX IF EXISTS uq_storage_launch_intent_active_host;
DROP TABLE IF EXISTS storage_launch_intents;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_storage_td_profile;
ALTER TABLE hosts DROP COLUMN IF EXISTS storage_td_mem;
ALTER TABLE hosts DROP COLUMN IF EXISTS storage_td_vcpus;
