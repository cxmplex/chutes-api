-- migrate:up

-- ChuteFS decentralized storage network.
--
-- An always-on attested "storage TD" runs on every bare-metal L0 host and self-registers as a
-- storage-role CPU server. It serves BOTH (a) public model/file distribution (integrity-only,
-- replacing the slow HuggingFace cold-pull) and (b) confidential, replicated per-user volumes.
-- The validator is the tracker: it records disk capacity, the content/replica registry, the
-- user-volume metadata, and (Fernet-encrypted) per-volume app-layer keys released only to attested
-- storage TDs that hold a replica.

-- --- storage role + disk capacity on servers / hosts -------------------------------------------

-- A storage-role server is the always-on ChuteFS storage TD; it must NEVER be picked by the CPU
-- scheduler for user chutes, and it advertises durable disk capacity (not just TD slot count).
ALTER TABLE servers ADD COLUMN IF NOT EXISTS storage_role BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS disk_total_gb INTEGER;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS disk_free_gb INTEGER;
CREATE INDEX IF NOT EXISTS idx_servers_storage_role ON servers (storage_role) WHERE storage_role IS true;

-- sha256 of the attested serving-cert pubkey (DER SPKI). Identical to the value verify_quote already
-- bound against report_data at registration. Indexed so a peer presenting its attested mTLS cert can
-- be matched to its server row in O(1) (peer directory / cert authority / attested-caller auth).
ALTER TABLE servers ADD COLUMN IF NOT EXISTS attested_cert_pubkey_hash VARCHAR;
CREATE INDEX IF NOT EXISTS idx_servers_attested_pubkey ON servers (attested_cert_pubkey_hash)
    WHERE attested_cert_pubkey_hash IS NOT NULL;

-- The L0 host's physical disk inventory (informational; the host is not attested). The node-agent
-- reports it at registration so the validator knows how much durable storage the host can back.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS disk_total_gb INTEGER;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS disk_free_gb INTEGER;

-- --- public model/file distribution registry ---------------------------------------------------

-- Which storage TD currently holds which public model repo@revision (integrity-only). A chute TD
-- queries this to find attested peers that already hold the weights it needs, fetches over
-- mutually-attested TLS, verifies against /misc/hf_repo_info, then announces its own holding.
CREATE TABLE IF NOT EXISTS content_holdings (
    holding_id   VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    server_id    VARCHAR NOT NULL REFERENCES servers (server_id) ON DELETE CASCADE,
    repo_id      VARCHAR NOT NULL,
    revision     VARCHAR NOT NULL DEFAULT 'main',
    bytes        BIGINT  NOT NULL DEFAULT 0,
    status       VARCHAR NOT NULL DEFAULT 'present',  -- present | pending | evicted
    announced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, repo_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_content_holdings_repo ON content_holdings (repo_id, revision);
CREATE INDEX IF NOT EXISTS idx_content_holdings_server ON content_holdings (server_id);

-- --- confidential per-user volumes -------------------------------------------------------------

-- A user-owned confidential storage volume. Objects within it are replicated across N attested
-- storage TDs on distinct hosts and encrypted at the application layer with a per-volume key that
-- is only ever released to attested storage TDs holding a replica.
CREATE TABLE IF NOT EXISTS storage_volumes (
    volume_id          VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id            VARCHAR NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    name               VARCHAR NOT NULL,
    replication_factor INTEGER NOT NULL DEFAULT 3,
    quota_bytes        BIGINT  NOT NULL DEFAULT 10737418240,  -- 10 GiB default soft quota
    used_bytes         BIGINT  NOT NULL DEFAULT 0,
    deleted            BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ
);
-- Name uniqueness is scoped to NON-deleted volumes so a name can be reused after a soft-delete.
CREATE UNIQUE INDEX IF NOT EXISTS uq_storage_volume_user_name ON storage_volumes (user_id, name)
    WHERE deleted IS false;
CREATE INDEX IF NOT EXISTS idx_storage_volumes_user ON storage_volumes (user_id) WHERE deleted IS false;

-- The Fernet-encrypted, per-volume application-layer key. Generated when the volume is created and
-- released ONLY to an attested storage TD that (a) passes a fresh quote verification and (b) holds a
-- replica of the volume. Stored encrypted at rest with CACHE_PASSPHRASE_KEY (same as LUKS passphrases).
CREATE TABLE IF NOT EXISTS storage_volume_keys (
    volume_id     VARCHAR PRIMARY KEY REFERENCES storage_volumes (volume_id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- An object (key -> bytes) inside a volume. The validator tracks metadata + integrity hash; the
-- ciphertext bytes live only on the storage TDs. size_bytes is the plaintext size for billing.
CREATE TABLE IF NOT EXISTS storage_objects (
    object_id   VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    volume_id   VARCHAR NOT NULL REFERENCES storage_volumes (volume_id) ON DELETE CASCADE,
    object_key  VARCHAR NOT NULL,
    size_bytes  BIGINT  NOT NULL DEFAULT 0,
    sha256      VARCHAR,                       -- ciphertext content hash (integrity across replicas)
    deleted     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ,
    UNIQUE (volume_id, object_key)
);
CREATE INDEX IF NOT EXISTS idx_storage_objects_volume ON storage_objects (volume_id) WHERE deleted IS false;

-- Which storage TDs hold a replica of a given object. The validator uses this to (a) satisfy the
-- volume's replication factor by dispatching replication, (b) answer "who has object X" peer lookups,
-- and (c) decide which TDs may receive the per-volume key.
CREATE TABLE IF NOT EXISTS replica_placement (
    placement_id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    object_id    VARCHAR NOT NULL REFERENCES storage_objects (object_id) ON DELETE CASCADE,
    server_id    VARCHAR NOT NULL REFERENCES servers (server_id) ON DELETE CASCADE,
    status       VARCHAR NOT NULL DEFAULT 'present',  -- present | pending | evicted
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at TIMESTAMPTZ,
    UNIQUE (object_id, server_id)
);
CREATE INDEX IF NOT EXISTS idx_replica_placement_object ON replica_placement (object_id);
CREATE INDEX IF NOT EXISTS idx_replica_placement_server ON replica_placement (server_id);

-- migrate:down

DROP TABLE IF EXISTS replica_placement;
DROP TABLE IF EXISTS storage_objects;
DROP TABLE IF EXISTS storage_volume_keys;
DROP TABLE IF EXISTS storage_volumes;
DROP TABLE IF EXISTS content_holdings;
ALTER TABLE hosts DROP COLUMN IF EXISTS disk_free_gb;
ALTER TABLE hosts DROP COLUMN IF EXISTS disk_total_gb;
DROP INDEX IF EXISTS idx_servers_attested_pubkey;
ALTER TABLE servers DROP COLUMN IF EXISTS attested_cert_pubkey_hash;
DROP INDEX IF EXISTS idx_servers_storage_role;
ALTER TABLE servers DROP COLUMN IF EXISTS disk_free_gb;
ALTER TABLE servers DROP COLUMN IF EXISTS disk_total_gb;
ALTER TABLE servers DROP COLUMN IF EXISTS storage_role;
