-- migrate:up

-- ChuteFS M16 (anti-rollback): a monotonic freshness epoch per LUKS volume, advanced on every
-- confirmed open. The storage TD writes the epoch inside the encrypted filesystem and refuses to
-- serve a volume whose on-disk epoch is older than the validator's last-confirmed epoch -- catching
-- a host that re-presents an old raw-disk snapshot (which opens fine under the still-valid LUKS
-- passphrase, so plain LUKS cannot detect the rollback).
ALTER TABLE vm_cache_configs ADD COLUMN IF NOT EXISTS volume_epochs JSONB NOT NULL DEFAULT '{}'::jsonb;

-- migrate:down

ALTER TABLE vm_cache_configs DROP COLUMN IF EXISTS volume_epochs;
