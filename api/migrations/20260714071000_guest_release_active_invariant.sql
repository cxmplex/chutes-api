-- migrate:up

-- Reassert this post-baseline so both clean ORM bootstraps and legacy upgrades receive the database
-- invariant even when historical dbmate bookkeeping was initialized after guest_releases existed.
CREATE UNIQUE INDEX IF NOT EXISTS uq_guest_release_active
    ON guest_releases (channel, tee_type)
    WHERE status = 'active';

-- migrate:down

DROP INDEX IF EXISTS uq_guest_release_active;
