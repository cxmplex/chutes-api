-- migrate:up

CREATE TABLE IF NOT EXISTS l0_bootstrap_publications (
    tee_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    generation INTEGER NOT NULL,
    manifest_digest TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_epoch INTEGER NOT NULL,
    l0_version TEXT NOT NULL,
    squashfs_sha256 TEXT NOT NULL,
    signed_manifest JSONB NOT NULL,
    source_release_id TEXT NOT NULL
        REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    admission_status TEXT NOT NULL DEFAULT 'staged',
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    CONSTRAINT pk_l0_bootstrap_publications
        PRIMARY KEY (tee_type, channel, generation),
    CONSTRAINT uq_l0_bootstrap_slot_digest
        UNIQUE (tee_type, channel, manifest_digest),
    CONSTRAINT ck_l0_publication_tee
        CHECK (tee_type IN ('sev-snp', 'tdx')),
    CONSTRAINT ck_l0_publication_generation
        CHECK (generation > 0 AND key_epoch > 0),
    CONSTRAINT ck_l0_publication_digests
        CHECK (
            manifest_digest ~ '^[0-9a-f]{64}$'
            AND squashfs_sha256 ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT ck_l0_publication_status
        CHECK (admission_status IN ('staged', 'active'))
);

CREATE INDEX IF NOT EXISTS idx_l0_publication_slot_latest
    ON l0_bootstrap_publications (tee_type, channel, generation);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM guest_releases
        WHERE l0_manifest_generation IS NOT NULL
          AND l0_manifest_digest IS NOT NULL
        GROUP BY tee_type, channel, l0_manifest_generation
        HAVING COUNT(DISTINCT l0_manifest_digest) > 1
    ) THEN
        RAISE EXCEPTION 'existing guest releases equivocate on an L0 bootstrap generation';
    END IF;
END
$$;

WITH ranked AS (
    SELECT
        release_id,
        tee_type,
        channel,
        l0_manifest_generation,
        l0_manifest_digest,
        l0_manifest_key_id,
        l0_manifest_key_epoch,
        images -> 'l0' ->> 'version' AS l0_version,
        images -> 'l0' ->> 'squashfs_sha256' AS squashfs_sha256,
        images -> 'l0' -> 'bootstrap' AS signed_manifest,
        status,
        activated_at,
        ROW_NUMBER() OVER (
            PARTITION BY tee_type, channel, l0_manifest_generation
            ORDER BY
                (status = 'active') DESC,
                activated_at DESC NULLS LAST,
                created_at DESC,
                release_id DESC
        ) AS rank
    FROM guest_releases
    WHERE l0_manifest_generation IS NOT NULL
      AND l0_manifest_digest ~ '^[0-9a-f]{64}$'
      AND l0_manifest_key_id IS NOT NULL
      AND l0_manifest_key_epoch > 0
      AND images -> 'l0' -> 'bootstrap' IS NOT NULL
      AND images -> 'l0' ->> 'version' IS NOT NULL
      AND images -> 'l0' ->> 'squashfs_sha256' ~ '^[0-9a-f]{64}$'
)
INSERT INTO l0_bootstrap_publications (
    tee_type,
    channel,
    generation,
    manifest_digest,
    key_id,
    key_epoch,
    l0_version,
    squashfs_sha256,
    signed_manifest,
    source_release_id,
    admission_status,
    activated_at
)
SELECT
    tee_type,
    channel,
    l0_manifest_generation,
    l0_manifest_digest,
    l0_manifest_key_id,
    l0_manifest_key_epoch,
    l0_version,
    squashfs_sha256,
    signed_manifest,
    release_id,
    CASE WHEN status = 'active' THEN 'active' ELSE 'staged' END,
    CASE WHEN status = 'active' THEN activated_at ELSE NULL END
FROM ranked
WHERE rank = 1
ON CONFLICT DO NOTHING;

-- migrate:down

DROP TABLE IF EXISTS l0_bootstrap_publications;
