-- migrate:up

ALTER TABLE chutefs_launch_sessions
    ADD COLUMN IF NOT EXISTS rotated_from_session_id TEXT
        REFERENCES chutefs_launch_sessions(session_id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS rotation_request_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS token_seed TEXT,
    ADD COLUMN IF NOT EXISTS token_key_id TEXT,
    ADD COLUMN IF NOT EXISTS response_replay_until TIMESTAMPTZ;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS chutefs_launch_sessions_config_id_key,
    DROP CONSTRAINT IF EXISTS chutefs_launch_sessions_instance_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_active_config
    ON chutefs_launch_sessions(config_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_active_instance
    ON chutefs_launch_sessions(instance_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_chutefs_launch_session_successor
    ON chutefs_launch_sessions(rotated_from_session_id)
    WHERE rotated_from_session_id IS NOT NULL;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS ck_chutefs_launch_session_rotation_replay;

ALTER TABLE chutefs_launch_sessions
    ADD CONSTRAINT ck_chutefs_launch_session_rotation_replay CHECK (
        (
            token_seed IS NULL
            AND token_key_id IS NULL
            AND rotation_request_sha256 IS NULL
            AND response_replay_until IS NULL
            AND rotated_from_session_id IS NULL
        )
        OR
        (
            token_seed ~ '^[0-9a-f]{64}$'
            AND token_key_id IS NOT NULL
            AND token_key_id <> ''
            AND rotation_request_sha256 ~ '^[0-9a-f]{64}$'
            AND response_replay_until IS NOT NULL
            AND response_replay_until <= refresh_expires_at
        )
    );

-- migrate:down

LOCK TABLE chutefs_launch_sessions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         WHERE rotated_from_session_id IS NOT NULL
            OR rotation_request_sha256 IS NOT NULL
            OR token_seed IS NOT NULL
            OR token_key_id IS NOT NULL
            OR response_replay_until IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot remove ChuteFS rotation replay state after it has been used';
    ELSIF EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         GROUP BY config_id
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
          FROM chutefs_launch_sessions
         GROUP BY instance_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot restore one-session uniqueness while session history exists';
    END IF;
END
$$;

DROP INDEX IF EXISTS uq_chutefs_launch_session_successor;
DROP INDEX IF EXISTS uq_chutefs_launch_session_active_instance;
DROP INDEX IF EXISTS uq_chutefs_launch_session_active_config;

ALTER TABLE chutefs_launch_sessions
    DROP CONSTRAINT IF EXISTS ck_chutefs_launch_session_rotation_replay;

ALTER TABLE chutefs_launch_sessions
    ADD CONSTRAINT chutefs_launch_sessions_config_id_key UNIQUE (config_id),
    ADD CONSTRAINT chutefs_launch_sessions_instance_id_key UNIQUE (instance_id);

ALTER TABLE chutefs_launch_sessions
    DROP COLUMN IF EXISTS response_replay_until,
    DROP COLUMN IF EXISTS token_key_id,
    DROP COLUMN IF EXISTS token_seed,
    DROP COLUMN IF EXISTS rotation_request_sha256,
    DROP COLUMN IF EXISTS rotated_from_session_id;
