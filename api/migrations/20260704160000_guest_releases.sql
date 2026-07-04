-- migrate:up

-- Fleet image release registry: the validator-owned desired-state for the guest images an L0 host
-- boots its TDs from. Publishing a new image + activating a release + rolling it out replaces the
-- old "bake the URL into l0.conf at netboot" flow, so the whole registered miner fleet can be
-- updated without a reinstall. A release is a per-(channel, tee_type) manifest of the chute + storage
-- images (URL + sha256 + version + the measurement names those images attest as). Activation is
-- gated on the validator already having those measurements pinned (see api/releases/service.py), so
-- a release can never outrun its attestation pins.
CREATE TABLE IF NOT EXISTS guest_releases (
    release_id    VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    channel       VARCHAR NOT NULL DEFAULT 'stable',
    -- Which fleet this release targets: "sev-snp" | "tdx". A host only converges to a release whose
    -- tee_type matches its own launcher tee_type.
    tee_type      VARCHAR NOT NULL,
    -- draft (created, not yet live) | active (the desired state hosts converge to) | superseded.
    status        VARCHAR NOT NULL DEFAULT 'draft',
    -- The image manifest: {"chute": {url, sha256, version, measurement_names:[...]},
    --                      "storage": {url, sha256, version, measurement_names:[...]}}.
    -- "storage" is optional (a release may ship a chute image only). measurement_names are validated
    -- against the loaded tee_measurements at activation time.
    images        JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes         TEXT,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    activated_at  TIMESTAMP WITH TIME ZONE
);

-- Exactly one ACTIVE release per (channel, tee_type): activation supersedes the prior active one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_guest_release_active
    ON guest_releases (channel, tee_type) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_guest_releases_tee_status ON guest_releases (tee_type, status);

-- Per-host convergence visibility: the digests the host reports it currently has staged (from the
-- node-agent heartbeat), so GET /releases/{id}/status can show which hosts have converged. Purely
-- informational (the host is not attested); attestation still gates whether a launched TD is trusted.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS staged_images JSONB;

-- migrate:down

ALTER TABLE hosts DROP COLUMN IF EXISTS staged_images;
DROP INDEX IF EXISTS idx_guest_releases_tee_status;
DROP INDEX IF EXISTS uq_guest_release_active;
DROP TABLE IF EXISTS guest_releases;
