-- migrate:up

-- Compute-scoped desired state. Existing releases, publications, targets, and logical hosts are
-- CPU state; the update is deliberately metadata-only and does not rewrite image JSON, signed L0
-- manifests, target generations, token identities, or release lifecycle rows.
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
UPDATE guest_releases SET compute_type = 'cpu' WHERE compute_type IS NULL;
ALTER TABLE guest_releases ALTER COLUMN compute_type SET DEFAULT 'cpu';
ALTER TABLE guest_releases ALTER COLUMN compute_type SET NOT NULL;

ALTER TABLE l0_bootstrap_publications
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
UPDATE l0_bootstrap_publications SET compute_type = 'cpu' WHERE compute_type IS NULL;
ALTER TABLE l0_bootstrap_publications ALTER COLUMN compute_type SET DEFAULT 'cpu';
ALTER TABLE l0_bootstrap_publications ALTER COLUMN compute_type SET NOT NULL;

ALTER TABLE guest_release_targets
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
UPDATE guest_release_targets SET compute_type = 'cpu' WHERE compute_type IS NULL;
ALTER TABLE guest_release_targets ALTER COLUMN compute_type SET DEFAULT 'cpu';
ALTER TABLE guest_release_targets ALTER COLUMN compute_type SET NOT NULL;

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
UPDATE hosts SET compute_type = 'cpu' WHERE compute_type IS NULL;
ALTER TABLE hosts ALTER COLUMN compute_type SET DEFAULT 'cpu';
ALTER TABLE hosts ALTER COLUMN compute_type SET NOT NULL;

ALTER TABLE host_enrollment_vouchers
    ADD COLUMN IF NOT EXISTS compute_type TEXT;
UPDATE host_enrollment_vouchers SET compute_type = 'cpu' WHERE compute_type IS NULL;
ALTER TABLE host_enrollment_vouchers ALTER COLUMN compute_type SET DEFAULT 'cpu';
ALTER TABLE host_enrollment_vouchers ALTER COLUMN compute_type SET NOT NULL;

DROP INDEX IF EXISTS uq_guest_release_active;
CREATE UNIQUE INDEX uq_guest_release_active
    ON guest_releases (channel, tee_type, compute_type)
    WHERE status = 'active';

DROP INDEX IF EXISTS idx_guest_releases_l0_generation;
CREATE INDEX idx_guest_releases_l0_generation
    ON guest_releases (tee_type, channel, compute_type, l0_manifest_generation)
    WHERE l0_manifest_generation IS NOT NULL;

ALTER TABLE guest_releases DROP CONSTRAINT IF EXISTS ck_guest_releases_compute_type;
ALTER TABLE guest_releases
    ADD CONSTRAINT ck_guest_releases_compute_type
    CHECK (compute_type IN ('cpu', 'gpu'));
ALTER TABLE guest_releases DROP CONSTRAINT IF EXISTS ck_guest_releases_gpu_tdx;
ALTER TABLE guest_releases
    ADD CONSTRAINT ck_guest_releases_gpu_tdx
    CHECK (compute_type = 'cpu' OR tee_type = 'tdx');

ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS l0_bootstrap_publications_pkey;
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS pk_l0_bootstrap_publications;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT pk_l0_bootstrap_publications
    PRIMARY KEY (tee_type, channel, compute_type, generation);
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS uq_l0_bootstrap_slot_digest;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT uq_l0_bootstrap_slot_digest
    UNIQUE (tee_type, channel, compute_type, manifest_digest);
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS ck_l0_publication_compute_type;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT ck_l0_publication_compute_type
    CHECK (compute_type IN ('cpu', 'gpu'));
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS ck_l0_publication_gpu_tdx;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT ck_l0_publication_gpu_tdx
    CHECK (compute_type = 'cpu' OR tee_type = 'tdx');
DROP INDEX IF EXISTS idx_l0_publication_slot_latest;
CREATE INDEX idx_l0_publication_slot_latest
    ON l0_bootstrap_publications (tee_type, channel, compute_type, generation);

ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS uq_guest_release_logical_target;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT uq_guest_release_logical_target
    UNIQUE (release_id, host_id, role, compute_type);
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_role;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_role
    CHECK (role IN ('chute', 'storage', 'gpu'));
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_compute_type;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_compute_type
    CHECK (compute_type IN ('cpu', 'gpu'));
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_compute_role;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_compute_role
    CHECK (
        (compute_type = 'cpu' AND role IN ('chute', 'storage'))
        OR
        (compute_type = 'gpu' AND tee_type = 'tdx' AND role = 'gpu')
    );

DROP INDEX IF EXISTS idx_hosts_release_targeting;
CREATE INDEX idx_hosts_release_targeting
    ON hosts (release_channel, tee_type, compute_type);
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_compute_type;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_compute_type
    CHECK (compute_type IN ('cpu', 'gpu'));
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_gpu_tdx;
ALTER TABLE hosts
    ADD CONSTRAINT ck_hosts_gpu_tdx
    CHECK (compute_type = 'cpu' OR tee_type = 'tdx');
ALTER TABLE host_enrollment_vouchers
    DROP CONSTRAINT IF EXISTS ck_host_voucher_compute_type;
ALTER TABLE host_enrollment_vouchers
    ADD CONSTRAINT ck_host_voucher_compute_type
    CHECK (
        compute_type = 'cpu'
        OR (compute_type = 'gpu' AND tee_type = 'tdx')
    );

-- migrate:down

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM guest_releases WHERE compute_type <> 'cpu')
       OR EXISTS (SELECT 1 FROM l0_bootstrap_publications WHERE compute_type <> 'cpu')
       OR EXISTS (SELECT 1 FROM guest_release_targets WHERE compute_type <> 'cpu')
       OR EXISTS (SELECT 1 FROM hosts WHERE compute_type <> 'cpu')
       OR EXISTS (SELECT 1 FROM host_enrollment_vouchers WHERE compute_type <> 'cpu') THEN
        RAISE EXCEPTION 'cannot remove compute-scoped release identity while GPU rows exist';
    END IF;
END
$$;

ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_compute_role;
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_compute_type;
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS ck_guest_release_target_role;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT ck_guest_release_target_role CHECK (role IN ('chute', 'storage'));
ALTER TABLE guest_release_targets
    DROP CONSTRAINT IF EXISTS uq_guest_release_logical_target;
ALTER TABLE guest_release_targets
    ADD CONSTRAINT uq_guest_release_logical_target UNIQUE (release_id, host_id, role);

ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS ck_l0_publication_gpu_tdx;
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS ck_l0_publication_compute_type;
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS uq_l0_bootstrap_slot_digest;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT uq_l0_bootstrap_slot_digest
    UNIQUE (tee_type, channel, manifest_digest);
ALTER TABLE l0_bootstrap_publications
    DROP CONSTRAINT IF EXISTS pk_l0_bootstrap_publications;
ALTER TABLE l0_bootstrap_publications
    ADD CONSTRAINT pk_l0_bootstrap_publications
    PRIMARY KEY (tee_type, channel, generation);

ALTER TABLE guest_releases DROP CONSTRAINT IF EXISTS ck_guest_releases_gpu_tdx;
ALTER TABLE guest_releases DROP CONSTRAINT IF EXISTS ck_guest_releases_compute_type;
DROP INDEX IF EXISTS uq_guest_release_active;
CREATE UNIQUE INDEX uq_guest_release_active
    ON guest_releases (channel, tee_type)
    WHERE status = 'active';
DROP INDEX IF EXISTS idx_guest_releases_l0_generation;
CREATE INDEX idx_guest_releases_l0_generation
    ON guest_releases (tee_type, channel, l0_manifest_generation)
    WHERE l0_manifest_generation IS NOT NULL;

DROP INDEX IF EXISTS idx_l0_publication_slot_latest;
CREATE INDEX idx_l0_publication_slot_latest
    ON l0_bootstrap_publications (tee_type, channel, generation);
DROP INDEX IF EXISTS idx_hosts_release_targeting;
CREATE INDEX idx_hosts_release_targeting ON hosts (release_channel, tee_type);
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_gpu_tdx;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_compute_type;
ALTER TABLE host_enrollment_vouchers
    DROP CONSTRAINT IF EXISTS ck_host_voucher_compute_type;

ALTER TABLE host_enrollment_vouchers DROP COLUMN IF EXISTS compute_type;
ALTER TABLE hosts DROP COLUMN IF EXISTS compute_type;
ALTER TABLE guest_release_targets DROP COLUMN IF EXISTS compute_type;
ALTER TABLE l0_bootstrap_publications DROP COLUMN IF EXISTS compute_type;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS compute_type;
