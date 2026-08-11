-- migrate:up
-- API startup bootstraps the current ORM catalog before dbmate records branch-added versions.
-- Keep this unshipped migration compatible with that exact fresh/create_all starting state.
CREATE TABLE IF NOT EXISTS vm_auth_keys (
    miner_hotkey TEXT NOT NULL,
    vm_name TEXT NOT NULL,
    auth_seed TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (miner_hotkey, vm_name)
);
CREATE INDEX IF NOT EXISTS idx_vm_auth_keys_miner ON vm_auth_keys (miner_hotkey);

-- migrate:down
DROP TABLE IF EXISTS vm_auth_keys;
