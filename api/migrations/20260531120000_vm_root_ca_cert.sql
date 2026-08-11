-- migrate:up
-- API startup may already have added this ORM column on a fresh/create_all database.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS vm_root_ca_cert TEXT;

-- migrate:down
ALTER TABLE servers DROP COLUMN IF EXISTS vm_root_ca_cert;
