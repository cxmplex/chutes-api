-- migrate:up

-- Publisher-authenticated L0 audit. Historical rows intentionally remain NULL.
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS l0_manifest JSONB;
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS l0_manifest_digest TEXT;
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS l0_manifest_generation INTEGER;
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS l0_manifest_key_id TEXT;
ALTER TABLE guest_releases
    ADD COLUMN IF NOT EXISTS l0_manifest_key_epoch INTEGER;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_guest_releases_l0_manifest_audit'
          AND conrelid = 'guest_releases'::regclass
    ) THEN
        ALTER TABLE guest_releases
            ADD CONSTRAINT ck_guest_releases_l0_manifest_audit CHECK (
                (
                    l0_manifest IS NULL
                    AND l0_manifest_digest IS NULL
                    AND l0_manifest_generation IS NULL
                    AND l0_manifest_key_id IS NULL
                    AND l0_manifest_key_epoch IS NULL
                )
                OR
                (
                    l0_manifest IS NOT NULL
                    AND l0_manifest_digest ~ '^[0-9a-f]{64}$'
                    AND l0_manifest_generation > 0
                    AND l0_manifest_key_id IS NOT NULL
                    AND l0_manifest_key_epoch > 0
                )
            );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_guest_releases_l0_generation
    ON guest_releases (tee_type, channel, l0_manifest_generation DESC)
    WHERE l0_manifest_generation IS NOT NULL;

-- A Host is an untrusted logical launcher. Existing rows remain explicitly legacy until enrolled.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS enrollment_generation INTEGER;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS active_key_generation INTEGER;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS provisioning_state TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS last_accepted_manifest_generation INTEGER;
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_hosts_provisioning_state'
          AND conrelid = 'hosts'::regclass
    ) THEN
        ALTER TABLE hosts
            ADD CONSTRAINT ck_hosts_provisioning_state CHECK (
                provisioning_state IN ('legacy', 'unclaimed', 'awaiting_pcs', 'ready', 'revoked')
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_hosts_enrollment_generations'
          AND conrelid = 'hosts'::regclass
    ) THEN
        ALTER TABLE hosts
            ADD CONSTRAINT ck_hosts_enrollment_generations CHECK (
                (enrollment_generation IS NULL AND active_key_generation IS NULL)
                OR
                (enrollment_generation > 0 AND active_key_generation > 0)
            );
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS host_enrollment_vouchers (
    voucher_id TEXT PRIMARY KEY,
    voucher_hash TEXT NOT NULL UNIQUE,
    owner_hotkey TEXT NOT NULL,
    host_id TEXT NOT NULL,
    tee_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    enrollment_generation INTEGER NOT NULL,
    claims JSONB NOT NULL,
    provider TEXT,
    source TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_key_generation INTEGER,
    invalidated_at TIMESTAMPTZ,
    CONSTRAINT uq_host_enrollment_generation UNIQUE (host_id, enrollment_generation),
    CONSTRAINT ck_host_voucher_tee_type CHECK (tee_type IN ('sev-snp', 'tdx')),
    CONSTRAINT ck_host_voucher_generation CHECK (enrollment_generation > 0),
    CONSTRAINT ck_host_voucher_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_host_voucher_consumption CHECK (
        (consumed_at IS NULL AND consumed_key_generation IS NULL)
        OR
        (consumed_at IS NOT NULL AND consumed_key_generation > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_host_vouchers_owner_active
    ON host_enrollment_vouchers (owner_hotkey, host_id)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS host_key_generations (
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    enrollment_generation INTEGER NOT NULL,
    ed25519_public_key TEXT NOT NULL,
    ed25519_fingerprint TEXT NOT NULL UNIQUE,
    x25519_public_key TEXT NOT NULL,
    x25519_fingerprint TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    CONSTRAINT pk_host_key_generations PRIMARY KEY (host_id, generation),
    CONSTRAINT ck_host_key_generation CHECK (generation > 0),
    CONSTRAINT ck_host_key_enrollment_generation CHECK (enrollment_generation > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_host_key_active
    ON host_key_generations (host_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS host_enrollment_challenges (
    challenge_id TEXT PRIMARY KEY,
    voucher_id TEXT NOT NULL
        REFERENCES host_enrollment_vouchers(voucher_id) ON DELETE CASCADE,
    ed25519_public_key TEXT NOT NULL,
    x25519_public_key TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT ck_host_enrollment_challenge_expiry CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS idx_host_enrollment_challenge_voucher
    ON host_enrollment_challenges (voucher_id, expires_at);

CREATE TABLE IF NOT EXISTS host_pcs_mailboxes (
    message_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    owner_hotkey TEXT NOT NULL,
    enrollment_generation INTEGER NOT NULL,
    key_generation INTEGER NOT NULL,
    recipient_fingerprint TEXT NOT NULL,
    envelope JSONB NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    invalidated_at TIMESTAMPTZ,
    CONSTRAINT ck_host_pcs_mailbox_generations CHECK (
        enrollment_generation > 0 AND key_generation > 0
    ),
    CONSTRAINT ck_host_pcs_mailbox_expiry CHECK (expires_at > issued_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_host_pcs_mailbox_active
    ON host_pcs_mailboxes (host_id)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS td_launch_reservations (
    reservation_id VARCHAR PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    owner_hotkey VARCHAR NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE RESTRICT,
    host_key_generation INTEGER NOT NULL,
    server_id VARCHAR NOT NULL,
    role TEXT NOT NULL,
    compute_type TEXT NOT NULL DEFAULT 'cpu',
    tee_type TEXT NOT NULL,
    process_incarnation TEXT NOT NULL,
    boot_generation INTEGER NOT NULL,
    release_id TEXT NOT NULL REFERENCES guest_releases(release_id) ON DELETE RESTRICT,
    image_sha256 TEXT NOT NULL,
    image_version TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    chute_id TEXT,
    job_id TEXT,
    container_repository TEXT,
    container_manifest_digest TEXT,
    launch_nonce TEXT NOT NULL,
    release_target_sha256 TEXT NOT NULL,
    claims JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    handed_to_host_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_attestation_id TEXT UNIQUE,
    consumed_cert_pubkey_hash TEXT,
    invalidated_at TIMESTAMPTZ,
    CONSTRAINT uq_td_launch_reservation_boot UNIQUE (server_id, boot_generation),
    CONSTRAINT uq_td_launch_reservation_attribution
        UNIQUE (reservation_id, server_id, owner_hotkey),
    CONSTRAINT ck_td_reservation_role CHECK (role IN ('chute', 'storage')),
    CONSTRAINT ck_td_reservation_compute_type CHECK (compute_type = 'cpu'),
    CONSTRAINT ck_td_reservation_tee_type CHECK (tee_type IN ('sev-snp', 'tdx')),
    CONSTRAINT ck_td_reservation_generations CHECK (
        host_key_generation > 0 AND boot_generation > 0
    ),
    CONSTRAINT ck_td_reservation_chute_role CHECK (
        (
            role = 'storage'
            AND chute_id IS NULL
            AND job_id IS NULL
            AND container_repository IS NULL
            AND container_manifest_digest IS NULL
        )
        OR
        (
            role = 'chute'
            AND chute_id IS NOT NULL
            AND container_repository IS NOT NULL
            AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$'
        )
    ),
    CONSTRAINT ck_td_reservation_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_td_reservation_consumption CHECK (
        (
            consumed_at IS NULL
            AND consumed_attestation_id IS NULL
            AND consumed_cert_pubkey_hash IS NULL
        )
        OR
        (
            consumed_at IS NOT NULL
            AND consumed_attestation_id IS NOT NULL
            AND consumed_cert_pubkey_hash ~ '^[0-9a-f]{64}$'
        )
    )
);

-- create_all already installs this final composite authority. Production creates it above.
-- Add only when wholly absent, and reject aliases, duplicate indexes, or same-name wrong shapes.
DO $$
DECLARE
    attribution_key SMALLINT[];
    matching_constraints INTEGER;
    matching_unique_indexes INTEGER;
BEGIN
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'reservation_id' AND attnum > 0 AND NOT attisdropped),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'server_id' AND attnum > 0 AND NOT attisdropped),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'owner_hotkey' AND attnum > 0 AND NOT attisdropped)
    ]::SMALLINT[] INTO attribution_key;
    IF array_position(attribution_key, NULL) IS NOT NULL THEN
        RAISE EXCEPTION
            'td_launch_reservations lacks attribution authority columns';
    END IF;

    SELECT COUNT(*)
      INTO matching_constraints
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'td_launch_reservations'::regclass
       AND constraint_row.contype = 'u'
       AND constraint_row.conkey = attribution_key;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'td_launch_reservations'::regclass
           AND constraint_row.conname = 'uq_td_launch_reservation_attribution'
    ) THEN
        IF matching_constraints <> 0 THEN
            RAISE EXCEPTION
                'td launch reservation attribution uniqueness has an unexpected name';
        END IF;
        EXECUTE
            'ALTER TABLE td_launch_reservations '
            'ADD CONSTRAINT uq_td_launch_reservation_attribution '
            'UNIQUE (reservation_id, server_id, owner_hotkey)';
    END IF;

    SELECT COUNT(*)
      INTO matching_constraints
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'td_launch_reservations'::regclass
       AND constraint_row.contype = 'u'
       AND constraint_row.conkey = attribution_key;
    SELECT COUNT(*)
      INTO matching_unique_indexes
      FROM pg_index AS index_definition
     WHERE index_definition.indrelid = 'td_launch_reservations'::regclass
       AND index_definition.indisunique
       AND index_definition.indnkeyatts = 3
       AND index_definition.indnatts = 3
       AND index_definition.indkey::TEXT = array_to_string(attribution_key, ' ')
       AND index_definition.indexprs IS NULL
       AND index_definition.indpred IS NULL;
    IF matching_constraints <> 1
       OR matching_unique_indexes <> 1
       OR NOT EXISTS (
            SELECT 1
              FROM pg_constraint AS constraint_row
              JOIN pg_index AS index_definition
                ON index_definition.indexrelid = constraint_row.conindid
             WHERE constraint_row.conrelid = 'td_launch_reservations'::regclass
               AND constraint_row.conname = 'uq_td_launch_reservation_attribution'
               AND constraint_row.contype = 'u'
               AND constraint_row.conkey = attribution_key
               AND NOT constraint_row.condeferrable
               AND NOT constraint_row.condeferred
               AND constraint_row.convalidated
               AND index_definition.indisunique
               AND index_definition.indisvalid
               AND index_definition.indisready
               AND index_definition.indislive
               AND lower(
                    regexp_replace(
                        pg_get_constraintdef(constraint_row.oid, TRUE),
                        '[[:space:]]+',
                        '',
                        'g'
                    )
               ) = 'unique(reservation_id,server_id,owner_hotkey)'
       ) THEN
        RAISE EXCEPTION
            'uq_td_launch_reservation_attribution has invalid or duplicate authority';
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_td_reservation_host_active
    ON td_launch_reservations (host_id, role)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

-- Attribute every Model-B attestation, including a failure before Server creation, to the exact
-- authenticated reservation/server/owner tuple. Non-Model-B attestations keep both columns NULL.
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS attribution_reservation_id VARCHAR;
ALTER TABLE server_attestations
    ADD COLUMN IF NOT EXISTS attribution_owner_hotkey VARCHAR;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('attribution_reservation_id'),
                ('attribution_owner_hotkey')
          ) AS expected(column_name)
          LEFT JOIN pg_attribute AS attribute
            ON attribute.attrelid = 'server_attestations'::regclass
           AND attribute.attname = expected.column_name
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = attribute.attrelid
           AND attribute_default.adnum = attribute.attnum
         WHERE attribute.attname IS NULL
            OR format_type(attribute.atttypid, attribute.atttypmod) <>
                'character varying'
            OR attribute.attnotnull
            OR attribute_default.oid IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'server attestation attribution columns have invalid definitions';
    END IF;
END
$$;

CREATE TEMPORARY TABLE expected_server_attestation_attribution_shape (
    attribution_reservation_id VARCHAR,
    attribution_owner_hotkey VARCHAR,
    CONSTRAINT ck_server_attestation_attribution CHECK (
        (attribution_reservation_id IS NULL AND attribution_owner_hotkey IS NULL)
        OR
        (attribution_reservation_id IS NOT NULL AND attribution_owner_hotkey IS NOT NULL)
    )
);

DO $$
DECLARE
    attribution_columns SMALLINT[];
    matching_checks INTEGER;
BEGIN
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'attribution_reservation_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'attribution_owner_hotkey')
    ]::SMALLINT[] INTO attribution_columns;

    SELECT COUNT(*)
      INTO matching_checks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'c'
       AND cardinality(constraint_row.conkey) = 2
       AND constraint_row.conkey @> attribution_columns
       AND attribution_columns @> constraint_row.conkey;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname = 'ck_server_attestation_attribution'
    ) THEN
        IF matching_checks <> 0 THEN
            RAISE EXCEPTION
                'server attestation attribution check has an unexpected name';
        END IF;
        EXECUTE
            'ALTER TABLE server_attestations '
            'ADD CONSTRAINT ck_server_attestation_attribution CHECK ('
            '(attribution_reservation_id IS NULL '
            'AND attribution_owner_hotkey IS NULL) OR '
            '(attribution_reservation_id IS NOT NULL '
            'AND attribution_owner_hotkey IS NOT NULL))';
    END IF;

    SELECT COUNT(*)
      INTO matching_checks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'c'
       AND cardinality(constraint_row.conkey) = 2
       AND constraint_row.conkey @> attribution_columns
       AND attribution_columns @> constraint_row.conkey;
    IF matching_checks <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS actual
          JOIN pg_constraint AS expected
            ON expected.conrelid =
                'expected_server_attestation_attribution_shape'::regclass
           AND expected.conname = actual.conname
         WHERE actual.conrelid = 'server_attestations'::regclass
           AND actual.conname = 'ck_server_attestation_attribution'
           AND actual.contype = 'c'
           AND NOT actual.condeferrable
           AND NOT actual.condeferred
           AND actual.convalidated
           AND cardinality(actual.conkey) = 2
           AND actual.conkey @> attribution_columns
           AND attribution_columns @> actual.conkey
           AND lower(
                regexp_replace(
                    pg_get_constraintdef(actual.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           ) = lower(
                regexp_replace(
                    pg_get_constraintdef(expected.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           )
    ) THEN
        RAISE EXCEPTION
            'ck_server_attestation_attribution has invalid or duplicate authority';
    END IF;
END
$$;
DROP TABLE expected_server_attestation_attribution_shape;

DO $$
DECLARE
    owner_source SMALLINT[];
    owner_target SMALLINT[];
    reservation_source SMALLINT[];
    reservation_target SMALLINT[];
    matching_fks INTEGER;
BEGIN
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'server_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'attribution_owner_hotkey')
    ]::SMALLINT[] INTO owner_source;
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestation_subjects'::regclass
            AND attname = 'server_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestation_subjects'::regclass
            AND attname = 'owner_hotkey')
    ]::SMALLINT[] INTO owner_target;

    SELECT COUNT(*)
      INTO matching_fks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'f'
       AND constraint_row.conkey = owner_source;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname = 'fk_server_attestations_attribution_owner'
    ) THEN
        IF matching_fks <> 0 THEN
            RAISE EXCEPTION
                'server attestation owner attribution FK has an unexpected name';
        END IF;
        EXECUTE
            'ALTER TABLE server_attestations '
            'ADD CONSTRAINT fk_server_attestations_attribution_owner '
            'FOREIGN KEY (server_id, attribution_owner_hotkey) '
            'REFERENCES server_attestation_subjects(server_id, owner_hotkey) '
            'ON DELETE RESTRICT';
    END IF;

    SELECT COUNT(*)
      INTO matching_fks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'f'
       AND constraint_row.conkey = owner_source;
    IF matching_fks <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname = 'fk_server_attestations_attribution_owner'
           AND constraint_row.contype = 'f'
           AND constraint_row.conkey = owner_source
           AND constraint_row.confrelid = 'server_attestation_subjects'::regclass
           AND constraint_row.confkey = owner_target
           AND constraint_row.confdeltype = 'r'
           AND constraint_row.confupdtype = 'a'
           AND constraint_row.confmatchtype = 's'
           AND NOT constraint_row.condeferrable
           AND NOT constraint_row.condeferred
           AND constraint_row.convalidated
           AND lower(
                regexp_replace(
                    pg_get_constraintdef(constraint_row.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           ) = 'foreignkey(server_id,attribution_owner_hotkey)referencesserver_attestation_subjects(server_id,owner_hotkey)ondeleterestrict'
    ) THEN
        RAISE EXCEPTION
            'fk_server_attestations_attribution_owner has invalid or duplicate authority';
    END IF;

    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'attribution_reservation_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'server_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'server_attestations'::regclass
            AND attname = 'attribution_owner_hotkey')
    ]::SMALLINT[] INTO reservation_source;
    SELECT ARRAY[
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'reservation_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'server_id'),
        (SELECT attnum FROM pg_attribute
          WHERE attrelid = 'td_launch_reservations'::regclass
            AND attname = 'owner_hotkey')
    ]::SMALLINT[] INTO reservation_target;

    SELECT COUNT(*)
      INTO matching_fks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'f'
       AND constraint_row.conkey = reservation_source;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname =
                'fk_server_attestations_td_reservation_attribution'
    ) THEN
        IF matching_fks <> 0 THEN
            RAISE EXCEPTION
                'server attestation reservation attribution FK has an unexpected name';
        END IF;
        EXECUTE
            'ALTER TABLE server_attestations '
            'ADD CONSTRAINT fk_server_attestations_td_reservation_attribution '
            'FOREIGN KEY ('
            'attribution_reservation_id, server_id, attribution_owner_hotkey) '
            'REFERENCES td_launch_reservations('
            'reservation_id, server_id, owner_hotkey) ON DELETE RESTRICT';
    END IF;

    SELECT COUNT(*)
      INTO matching_fks
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'server_attestations'::regclass
       AND constraint_row.contype = 'f'
       AND constraint_row.conkey = reservation_source;
    IF matching_fks <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = 'server_attestations'::regclass
           AND constraint_row.conname =
                'fk_server_attestations_td_reservation_attribution'
           AND constraint_row.contype = 'f'
           AND constraint_row.conkey = reservation_source
           AND constraint_row.confrelid = 'td_launch_reservations'::regclass
           AND constraint_row.confkey = reservation_target
           AND constraint_row.confdeltype = 'r'
           AND constraint_row.confupdtype = 'a'
           AND constraint_row.confmatchtype = 's'
           AND NOT constraint_row.condeferrable
           AND NOT constraint_row.condeferred
           AND constraint_row.convalidated
           AND lower(
                regexp_replace(
                    pg_get_constraintdef(constraint_row.oid, TRUE),
                    '[[:space:]]+',
                    '',
                    'g'
                )
           ) = 'foreignkey(attribution_reservation_id,server_id,attribution_owner_hotkey)referencestd_launch_reservations(reservation_id,server_id,owner_hotkey)ondeleterestrict'
    ) THEN
        RAISE EXCEPTION
            'fk_server_attestations_td_reservation_attribution has invalid or duplicate authority';
    END IF;
END
$$;

ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS launch_reservation_id TEXT;
ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS launch_boot_generation INTEGER;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_servers_launch_reservation'
          AND conrelid = 'servers'::regclass
    ) THEN
        ALTER TABLE servers
            ADD CONSTRAINT fk_servers_launch_reservation
            FOREIGN KEY (launch_reservation_id)
            REFERENCES td_launch_reservations(reservation_id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_servers_launch_reservation_generation'
          AND conrelid = 'servers'::regclass
    ) THEN
        ALTER TABLE servers
            ADD CONSTRAINT ck_servers_launch_reservation_generation CHECK (
                (launch_reservation_id IS NULL AND launch_boot_generation IS NULL)
                OR
                (launch_reservation_id IS NOT NULL AND launch_boot_generation > 0)
            );
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_launch_reservation
    ON servers (launch_reservation_id)
    WHERE launch_reservation_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS registry_sessions (
    session_id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE,
    server_id TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    attested_cert_pubkey_hash TEXT NOT NULL,
    repository TEXT NOT NULL,
    actions JSONB NOT NULL,
    manifest_digest TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT uq_registry_session_server UNIQUE (server_id),
    CONSTRAINT ck_registry_session_expiry CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS idx_registry_session_server_active
    ON registry_sessions (server_id, expires_at)
    WHERE revoked_at IS NULL;

-- migrate:down

DROP TABLE IF EXISTS registry_sessions;
ALTER TABLE server_attestations
    DROP CONSTRAINT IF EXISTS fk_server_attestations_td_reservation_attribution;
ALTER TABLE server_attestations
    DROP CONSTRAINT IF EXISTS fk_server_attestations_attribution_owner;
ALTER TABLE server_attestations
    DROP CONSTRAINT IF EXISTS ck_server_attestation_attribution;
ALTER TABLE server_attestations
    DROP COLUMN IF EXISTS attribution_owner_hotkey;
ALTER TABLE server_attestations
    DROP COLUMN IF EXISTS attribution_reservation_id;
DROP INDEX IF EXISTS uq_servers_launch_reservation;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_launch_reservation_generation;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS fk_servers_launch_reservation;
ALTER TABLE servers DROP COLUMN IF EXISTS launch_boot_generation;
ALTER TABLE servers DROP COLUMN IF EXISTS launch_reservation_id;
DROP TABLE IF EXISTS td_launch_reservations;
DROP TABLE IF EXISTS host_pcs_mailboxes;
DROP TABLE IF EXISTS host_enrollment_challenges;
DROP TABLE IF EXISTS host_key_generations;
DROP TABLE IF EXISTS host_enrollment_vouchers;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_enrollment_generations;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_hosts_provisioning_state;
ALTER TABLE hosts DROP COLUMN IF EXISTS enrolled_at;
ALTER TABLE hosts DROP COLUMN IF EXISTS last_accepted_manifest_generation;
ALTER TABLE hosts DROP COLUMN IF EXISTS provisioning_state;
ALTER TABLE hosts DROP COLUMN IF EXISTS active_key_generation;
ALTER TABLE hosts DROP COLUMN IF EXISTS enrollment_generation;
DROP INDEX IF EXISTS idx_guest_releases_l0_generation;
ALTER TABLE guest_releases DROP CONSTRAINT IF EXISTS ck_guest_releases_l0_manifest_audit;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS l0_manifest_key_epoch;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS l0_manifest_key_id;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS l0_manifest_generation;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS l0_manifest_digest;
ALTER TABLE guest_releases DROP COLUMN IF EXISTS l0_manifest;
