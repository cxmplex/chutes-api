-- Deterministic source-only upgrade fixture generated from b4f439b37327fa35e2d731b98c1645f90df97426.
-- Contains only synthetic lineage/attestation rows and the exact 64-version migration ledger.
-- It is not a substitute for deployment-owned restored production snapshots, deployed SHAs,
-- migration ledgers, row-count preservation, or backup/restore evidence.
-- Replace __CHUTES_PRODUCTION_BASE_SCHEMA__ with a validated isolated schema name before restore.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

CREATE SCHEMA __CHUTES_PRODUCTION_BASE_SCHEMA__;

CREATE TYPE __CHUTES_PRODUCTION_BASE_SCHEMA__.action AS ENUM (
    'READ',
    'WRITE',
    'DELETE',
    'INVOKE'
);

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.admin_balance_changes (
    event_id character varying NOT NULL,
    user_id character varying,
    amount double precision NOT NULL,
    reason character varying NOT NULL,
    "timestamp" timestamp without time zone,
    created_by character varying,
    raw_request jsonb
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.agent_registrations (
    registration_id character varying NOT NULL,
    user_id character varying NOT NULL,
    hotkey character varying NOT NULL,
    coldkey character varying NOT NULL,
    username character varying NOT NULL,
    payment_address character varying NOT NULL,
    wallet_secret character varying NOT NULL,
    received_amount double precision,
    received_rao bigint,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    deleted_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.api_key_scopes (
    scope_id character varying NOT NULL,
    api_key_id character varying NOT NULL,
    object_type character varying NOT NULL,
    object_id character varying,
    action __CHUTES_PRODUCTION_BASE_SCHEMA__.action
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.api_keys (
    api_key_id character varying NOT NULL,
    key_hash character varying NOT NULL,
    user_id character varying NOT NULL,
    admin boolean,
    name character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    last_used_at timestamp without time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.app_usage_data (
    app_id character varying NOT NULL,
    user_id character varying NOT NULL,
    bucket timestamp without time zone NOT NULL,
    chute_id character varying NOT NULL,
    amount double precision NOT NULL,
    count bigint NOT NULL,
    input_tokens numeric,
    output_tokens numeric,
    cached_tokens numeric,
    compute_time double precision,
    paygo_amount double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations (
    attestation_id character varying NOT NULL,
    quote_data text NOT NULL,
    server_ip character varying,
    miner_hotkey character varying,
    vm_name character varying,
    verification_error character varying,
    measurement_version character varying,
    created_at timestamp with time zone DEFAULT now(),
    verified_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.bt_transfer_monitor_state (
    instance_id character varying NOT NULL,
    block_number bigint NOT NULL,
    block_hash character varying NOT NULL,
    is_locked boolean NOT NULL,
    lock_holder character varying,
    locked_at timestamp without time zone,
    last_updated_at timestamp without time zone NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.bt_tx_history (
    extrinsic_id character varying NOT NULL,
    block bigint NOT NULL,
    rao_amount bigint NOT NULL,
    transaction_hash character varying,
    created_at timestamp without time zone NOT NULL,
    source character varying NOT NULL,
    dest character varying NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.capacity_log (
    chute_id character varying NOT NULL,
    "timestamp" timestamp without time zone NOT NULL,
    utilization_current double precision,
    utilization_5m double precision,
    utilization_15m double precision,
    utilization_1h double precision,
    rate_limit_ratio_5m double precision,
    rate_limit_ratio_15m double precision,
    rate_limit_ratio_1h double precision,
    total_requests_5m double precision,
    total_requests_15m double precision,
    total_requests_1h double precision,
    completed_requests_5m double precision,
    completed_requests_15m double precision,
    completed_requests_1h double precision,
    rate_limited_requests_5m double precision,
    rate_limited_requests_15m double precision,
    rate_limited_requests_1h double precision,
    instance_count integer,
    action_taken character varying,
    target_count integer NOT NULL,
    effective_multiplier double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_history (
    entry_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    user_id character varying NOT NULL,
    version character varying,
    name character varying,
    tagline character varying,
    readme character varying,
    tool_description character varying,
    image_id character varying NOT NULL,
    logo_id character varying,
    public boolean,
    standard_template character varying,
    cords jsonb NOT NULL,
    node_selector jsonb NOT NULL,
    slug character varying,
    code character varying NOT NULL,
    filename character varying NOT NULL,
    ref_str character varying NOT NULL,
    chutes_version character varying,
    openrouter boolean,
    discount double precision,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    deleted_at timestamp without time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_shares (
    chute_id character varying NOT NULL,
    shared_by character varying NOT NULL,
    shared_to character varying NOT NULL,
    shared_at timestamp without time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes (
    chute_id character varying NOT NULL,
    user_id character varying NOT NULL,
    name character varying,
    tagline character varying,
    readme character varying,
    tool_description character varying,
    image_id character varying,
    logo_id character varying,
    public boolean,
    standard_template character varying,
    cords jsonb NOT NULL,
    jobs jsonb,
    node_selector jsonb NOT NULL,
    slug character varying,
    code character varying NOT NULL,
    filename character varying NOT NULL,
    ref_str character varying NOT NULL,
    version character varying,
    concurrency integer,
    boost double precision,
    chutes_version character varying,
    revision character varying,
    openrouter boolean,
    discount double precision,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    max_instances integer,
    scaling_threshold double precision,
    shutdown_after_seconds integer,
    allow_external_egress boolean,
    encrypted_fs boolean,
    tee boolean,
    lock_modules boolean,
    immutable boolean,
    disabled boolean,
    invocation_count bigint
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.fmv_history (
    ticker character varying NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    price double precision NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.image_history (
    entry_id character varying NOT NULL,
    image_id character varying NOT NULL,
    user_id character varying NOT NULL,
    name character varying NOT NULL,
    tag character varying NOT NULL,
    readme character varying,
    logo_id character varying,
    public boolean,
    status character varying,
    created_at timestamp without time zone,
    deleted_at timestamp without time zone,
    chutes_version character varying,
    build_started_at timestamp with time zone,
    build_completed_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.images (
    image_id character varying NOT NULL,
    user_id character varying NOT NULL,
    name character varying NOT NULL,
    tag character varying NOT NULL,
    readme character varying,
    logo_id character varying,
    public boolean,
    status character varying,
    created_at timestamp with time zone DEFAULT now(),
    chutes_version character varying,
    patch_version character varying,
    build_started_at timestamp with time zone,
    build_completed_at timestamp with time zone,
    inspecto character varying,
    package_hashes jsonb
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.instance_nodes (
    instance_id character varying,
    node_id character varying
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.instances (
    instance_id character varying NOT NULL,
    host character varying NOT NULL,
    port integer NOT NULL,
    chute_id character varying NOT NULL,
    version character varying NOT NULL,
    miner_uid integer NOT NULL,
    miner_hotkey character varying NOT NULL,
    miner_coldkey character varying NOT NULL,
    region character varying,
    active boolean,
    verified boolean,
    last_queried_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    activated_at timestamp with time zone,
    last_verified_at timestamp with time zone,
    stop_billing_at timestamp without time zone,
    billed_to character varying,
    verification_error character varying,
    consecutive_failures integer,
    chutes_version character varying,
    symmetric_key character varying,
    config_id character varying,
    deployment_id character varying,
    cacert character varying,
    port_mappings jsonb,
    inspecto character varying,
    env_creation jsonb,
    bounty boolean,
    rint_commitment character varying,
    rint_nonce character varying,
    rint_pubkey character varying,
    rint_session_key character varying,
    extra jsonb,
    hourly_rate double precision,
    compute_multiplier double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.invocation_discounts (
    user_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    discount double precision NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.invocation_quotas (
    user_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    is_default boolean,
    payment_refresh_date timestamp without time zone,
    effective_date timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    quota bigint NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.job_quotas (
    user_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    is_default boolean,
    payment_refresh_date timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    quota bigint NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs (
    job_id character varying NOT NULL,
    user_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    version character varying NOT NULL,
    chutes_version character varying,
    method character varying NOT NULL,
    miner_uid integer,
    miner_hotkey character varying,
    miner_coldkey character varying,
    instance_id character varying,
    active boolean,
    verified boolean,
    last_queried_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone,
    started_at timestamp without time zone,
    finished_at timestamp without time zone,
    job_args jsonb NOT NULL,
    node_selector jsonb,
    status character varying NOT NULL,
    result jsonb,
    error_detail character varying,
    output_files jsonb,
    miner_terminated boolean,
    port_mappings jsonb,
    miner_history jsonb NOT NULL,
    compute_multiplier double precision NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs (
    config_id character varying NOT NULL,
    seed numeric NOT NULL,
    env_key character varying NOT NULL,
    chute_id character varying NOT NULL,
    job_id character varying,
    host character varying,
    port integer,
    env_type character varying,
    miner_uid integer NOT NULL,
    miner_hotkey character varying NOT NULL,
    miner_coldkey character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    retrieved_at timestamp without time zone,
    verified_at timestamp without time zone,
    failed_at timestamp without time zone,
    verification_error character varying,
    nonce character varying
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.llm_details (
    chute_id character varying NOT NULL,
    details jsonb NOT NULL,
    updated_at timestamp without time zone DEFAULT now(),
    overrides jsonb
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.logos (
    logo_id character varying NOT NULL,
    path character varying NOT NULL,
    user_id character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.metagraph_nodes (
    hotkey character varying NOT NULL,
    netuid integer NOT NULL,
    checksum character varying NOT NULL,
    coldkey character varying NOT NULL,
    node_id integer,
    incentive double precision,
    stake double precision,
    tao_stake double precision,
    alpha_stake double precision,
    trust double precision,
    vtrust double precision,
    last_updated integer,
    ip character varying,
    ip_type integer,
    port integer,
    protocol integer,
    real_host character varying,
    real_port integer,
    synced_at timestamp without time zone DEFAULT now(),
    blacklist_reason character varying
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.model_aliases (
    user_id character varying NOT NULL,
    alias character varying(64) NOT NULL,
    chute_ids jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.nodes (
    uuid character varying NOT NULL,
    name character varying NOT NULL,
    memory bigint NOT NULL,
    major integer,
    minor integer,
    processors integer NOT NULL,
    sxm boolean,
    clock_rate double precision NOT NULL,
    max_threads_per_processor integer NOT NULL,
    concurrent_kernels boolean,
    ecc boolean,
    seed numeric NOT NULL,
    miner_hotkey character varying,
    gpu_identifier character varying NOT NULL,
    device_index integer NOT NULL,
    server_id character varying,
    created_at timestamp with time zone DEFAULT now(),
    verification_host character varying NOT NULL,
    verification_port integer NOT NULL,
    verification_error character varying,
    verified_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_access_tokens (
    token_id character varying NOT NULL,
    token_hash character varying NOT NULL,
    authorization_id character varying NOT NULL,
    scopes character varying[] NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    revoked boolean NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_app_shares (
    app_id character varying NOT NULL,
    shared_by character varying NOT NULL,
    shared_to character varying NOT NULL,
    shared_at timestamp without time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps (
    app_id character varying NOT NULL,
    client_id character varying NOT NULL,
    client_secret_hash character varying NOT NULL,
    user_id character varying NOT NULL,
    name character varying(64) NOT NULL,
    description text,
    redirect_uris character varying[] NOT NULL,
    homepage_url character varying,
    logo_url character varying,
    active boolean NOT NULL,
    public boolean NOT NULL,
    refresh_token_lifetime_days integer NOT NULL,
    allowed_scopes character varying[],
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations (
    authorization_id character varying NOT NULL,
    user_id character varying NOT NULL,
    app_id character varying NOT NULL,
    scopes character varying[] NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    revoked boolean NOT NULL,
    revoked_at timestamp without time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_refresh_tokens (
    token_id character varying NOT NULL,
    token_hash character varying NOT NULL,
    authorization_id character varying NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    revoked boolean NOT NULL,
    used boolean NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.payment_monitor_state (
    instance_id character varying NOT NULL,
    block_number bigint NOT NULL,
    block_hash character varying NOT NULL,
    is_locked boolean,
    lock_holder character varying,
    locked_at timestamp without time zone,
    last_updated_at timestamp without time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.payments (
    payment_id character varying NOT NULL,
    user_id character varying NOT NULL,
    block bigint NOT NULL,
    rao_amount bigint NOT NULL,
    fmv double precision NOT NULL,
    usd_amount double precision NOT NULL,
    transaction_hash character varying NOT NULL,
    extrinsic_idx bigint,
    purpose character varying,
    source_address character varying,
    created_at timestamp with time zone DEFAULT now(),
    refunded boolean
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.pending_stakes (
    wallet_address character varying NOT NULL,
    netuid bigint NOT NULL,
    source_hotkey character varying NOT NULL,
    user_id character varying NOT NULL,
    pending_balance bigint NOT NULL,
    status character varying NOT NULL,
    last_processed_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    attempt_count bigint NOT NULL,
    error_message character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.price_overrides (
    user_id character varying NOT NULL,
    chute_id character varying NOT NULL,
    per_request double precision,
    per_million_in double precision,
    per_million_out double precision,
    per_step double precision,
    cache_discount double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.rolling_updates (
    chute_id character varying NOT NULL,
    old_version character varying NOT NULL,
    new_version character varying NOT NULL,
    started_at timestamp without time zone DEFAULT now(),
    permitted jsonb NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (
    version character varying(255) NOT NULL
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.secrets (
    secret_id character varying NOT NULL,
    user_id character varying NOT NULL,
    purpose character varying,
    key character varying NOT NULL,
    value character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations (
    attestation_id character varying NOT NULL,
    server_id character varying NOT NULL,
    quote_data text,
    verification_error character varying,
    measurement_version character varying,
    created_at timestamp with time zone DEFAULT now(),
    verified_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.servers (
    server_id character varying NOT NULL,
    ip character varying NOT NULL,
    miner_hotkey character varying NOT NULL,
    name character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    netuid integer DEFAULT 64 NOT NULL,
    is_tee boolean DEFAULT false,
    maintenance_pending_window_id character varying,
    version text,
    last_health_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.tee_upgrade_windows (
    id character varying NOT NULL,
    upgrade_window_start timestamp with time zone NOT NULL,
    upgrade_window_end timestamp with time zone NOT NULL,
    target_measurement_version text NOT NULL,
    max_concurrent_per_miner integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_window_bounds CHECK ((upgrade_window_end > upgrade_window_start))
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.usage_data (
    user_id character varying NOT NULL,
    bucket timestamp without time zone NOT NULL,
    chute_id character varying NOT NULL,
    amount double precision NOT NULL,
    count bigint NOT NULL,
    input_tokens numeric,
    output_tokens numeric,
    compute_time double precision,
    paygo_amount double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.user_current_balance (
    user_id character varying NOT NULL,
    stored_balance double precision,
    total_instance_costs double precision,
    effective_balance double precision
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.users (
    user_id character varying NOT NULL,
    hotkey character varying,
    coldkey character varying NOT NULL,
    payment_address character varying,
    wallet_secret character varying,
    developer_payment_address character varying,
    developer_wallet_secret character varying,
    balance double precision,
    username character varying,
    fingerprint_hash character varying NOT NULL,
    permissions_bitmask bigint,
    validator_hotkey character varying,
    subnet_owner_hotkey character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    netuids integer[],
    logo_id character varying,
    rate_limit_overrides jsonb
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.vm_cache_configs (
    miner_hotkey character varying NOT NULL,
    vm_name character varying NOT NULL,
    volume_passphrases jsonb NOT NULL,
    k3s_encryption_key text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    last_boot_at timestamp with time zone
);

CREATE TABLE __CHUTES_PRODUCTION_BASE_SCHEMA__.wallet_balances (
    wallet_id character varying NOT NULL,
    balance bigint
);

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations (attestation_id, quote_data, server_ip, miner_hotkey, vm_name, verification_error, measurement_version, created_at, verified_at) VALUES ('synthetic-legacy-boot-attestation', 'c3ludGhldGljLWJvb3QtcXVvdGU=', '192.0.2.10', '5SyntheticLegacyMiner', 'synthetic-legacy-vm', NULL, 'legacy-1.0.0', '2026-07-14 12:00:30+00', '2026-07-14 12:00:45+00');

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.metagraph_nodes (hotkey, netuid, checksum, coldkey, node_id, incentive, stake, tao_stake, alpha_stake, trust, vtrust, last_updated, ip, ip_type, port, protocol, real_host, real_port, synced_at, blacklist_reason) VALUES ('5SyntheticLegacyMiner', 64, 'synthetic-ledger-checksum', '5SyntheticLegacyColdkey', 7, 0.5, 100, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2026-07-14 12:00:00', NULL);

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.nodes (uuid, name, memory, major, minor, processors, sxm, clock_rate, max_threads_per_processor, concurrent_kernels, ecc, seed, miner_hotkey, gpu_identifier, device_index, server_id, created_at, verification_host, verification_port, verification_error, verified_at) VALUES ('synthetic-legacy-node', 'synthetic-gpu-node', 85899345920, 9, 0, 132, true, 1980, 32, true, true, 12345, '5SyntheticLegacyMiner', 'NVIDIA-B200-SYNTHETIC', 0, 'synthetic-legacy-server', '2026-07-14 12:04:00+00', '192.0.2.10', 8000, NULL, '2026-07-14 12:05:00+00');

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241101123129');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241101150057');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241106123144');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241113191447');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241118131550');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241122174045');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241128104225');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241201113452');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241202095623');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241211122523');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241212104206');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241213085609');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241214121531');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241214123318');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241214144031');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241216101012');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241217110214');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241221115644');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241227084133');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241229094223');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241229142051');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20241231195935');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250117101020');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250118143120');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250118204148');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250122121028');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250128185705');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250128185835');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250203180911');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250207120000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250218081133');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250218081504');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250219081020');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250306143614');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250319073422');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250319074720');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250415103135');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250423083926');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250424134911');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250512084635');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250705010101');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250709175230');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250712111758');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250716111259');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250716155308');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250720084231');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250726171323');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250727133106');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250824113239');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250829115200');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250903081317');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20250918104132');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20251030165517');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20251102184128');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20251229142400');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260102190913');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260115120000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260115120100');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260131120000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260131120100');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260218120000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260403120000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260513000000');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations (version) VALUES ('20260626120000');

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations (attestation_id, server_id, quote_data, verification_error, measurement_version, created_at, verified_at) VALUES ('synthetic-legacy-attestation-accepted', 'synthetic-legacy-server', 'c3ludGhldGljLWFjY2VwdGVkLXF1b3Rl', NULL, 'legacy-1.0.0', '2026-07-14 12:06:00+00', '2026-07-14 12:06:30+00');
INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations (attestation_id, server_id, quote_data, verification_error, measurement_version, created_at, verified_at) VALUES ('synthetic-legacy-attestation-rejected', 'synthetic-legacy-server', 'c3ludGhldGljLXJlamVjdGVkLXF1b3Rl', 'synthetic quote rejection', 'legacy-1.0.0', '2026-07-14 12:07:00+00', NULL);

INSERT INTO __CHUTES_PRODUCTION_BASE_SCHEMA__.servers (server_id, ip, miner_hotkey, name, created_at, updated_at, netuid, is_tee, maintenance_pending_window_id, version, last_health_at) VALUES ('synthetic-legacy-server', '192.0.2.10', '5SyntheticLegacyMiner', 'synthetic-legacy-server-name', '2026-07-14 12:01:00+00', '2026-07-14 12:02:00+00', 64, true, NULL, 'legacy-1.0.0', '2026-07-14 12:03:00+00');

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.admin_balance_changes
    ADD CONSTRAINT admin_balance_changes_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.agent_registrations
    ADD CONSTRAINT agent_registrations_hotkey_key UNIQUE (hotkey);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.agent_registrations
    ADD CONSTRAINT agent_registrations_pkey PRIMARY KEY (registration_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.api_key_scopes
    ADD CONSTRAINT api_key_scopes_pkey PRIMARY KEY (scope_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (api_key_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.app_usage_data
    ADD CONSTRAINT app_usage_data_pkey PRIMARY KEY (app_id, user_id, bucket, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations
    ADD CONSTRAINT boot_attestations_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.bt_transfer_monitor_state
    ADD CONSTRAINT bt_transfer_monitor_state_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.bt_tx_history
    ADD CONSTRAINT bt_tx_history_pkey PRIMARY KEY (extrinsic_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.capacity_log
    ADD CONSTRAINT capacity_log_pkey PRIMARY KEY (chute_id, "timestamp");

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_history
    ADD CONSTRAINT chute_history_pkey PRIMARY KEY (entry_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_shares
    ADD CONSTRAINT chute_shares_pkey PRIMARY KEY (chute_id, shared_by, shared_to);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes
    ADD CONSTRAINT chutes_pkey PRIMARY KEY (chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.api_keys
    ADD CONSTRAINT constraint_api_key_user_name UNIQUE (user_id, name);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps
    ADD CONSTRAINT constraint_oauth_app_name UNIQUE (name);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations
    ADD CONSTRAINT constraint_oauth_auth_user_app UNIQUE (user_id, app_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.images
    ADD CONSTRAINT constraint_user_id_image_name_tag UNIQUE (user_id, name, tag);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.fmv_history
    ADD CONSTRAINT fmv_history_pkey PRIMARY KEY (ticker, "timestamp");

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.image_history
    ADD CONSTRAINT image_history_pkey PRIMARY KEY (entry_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.images
    ADD CONSTRAINT images_pkey PRIMARY KEY (image_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT instances_config_id_key UNIQUE (config_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.invocation_discounts
    ADD CONSTRAINT invocation_discounts_pkey PRIMARY KEY (user_id, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.invocation_quotas
    ADD CONSTRAINT invocation_quotas_pkey PRIMARY KEY (user_id, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.job_quotas
    ADD CONSTRAINT job_quotas_pkey PRIMARY KEY (user_id, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs
    ADD CONSTRAINT jobs_instance_id_key UNIQUE (instance_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (job_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs
    ADD CONSTRAINT launch_configs_pkey PRIMARY KEY (config_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.llm_details
    ADD CONSTRAINT llm_details_pkey PRIMARY KEY (chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.logos
    ADD CONSTRAINT logos_pkey PRIMARY KEY (logo_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.metagraph_nodes
    ADD CONSTRAINT metagraph_nodes_pkey PRIMARY KEY (hotkey, netuid);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.model_aliases
    ADD CONSTRAINT model_aliases_pkey PRIMARY KEY (user_id, alias);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (uuid);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_pkey PRIMARY KEY (token_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_app_shares
    ADD CONSTRAINT oauth_app_shares_pkey PRIMARY KEY (app_id, shared_by, shared_to);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps
    ADD CONSTRAINT oauth_apps_pkey PRIMARY KEY (app_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_pkey PRIMARY KEY (authorization_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (token_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.payment_monitor_state
    ADD CONSTRAINT payment_monitor_state_pkey PRIMARY KEY (instance_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (payment_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.pending_stakes
    ADD CONSTRAINT pending_stakes_pkey PRIMARY KEY (wallet_address, netuid, source_hotkey);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.price_overrides
    ADD CONSTRAINT price_overrides_pkey PRIMARY KEY (user_id, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.rolling_updates
    ADD CONSTRAINT rolling_updates_pkey PRIMARY KEY (chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (secret_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations
    ADD CONSTRAINT server_attestations_pkey PRIMARY KEY (attestation_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.servers
    ADD CONSTRAINT servers_pkey PRIMARY KEY (server_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.tee_upgrade_windows
    ADD CONSTRAINT tee_upgrade_windows_pkey PRIMARY KEY (id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT unique_host_port UNIQUE (host, port);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instance_nodes
    ADD CONSTRAINT uq_inode UNIQUE (node_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instance_nodes
    ADD CONSTRAINT uq_instance_node UNIQUE (instance_id, node_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs
    ADD CONSTRAINT uq_job_launch_config UNIQUE (job_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.tee_upgrade_windows
    ADD CONSTRAINT uq_tee_upgrade_target UNIQUE (target_measurement_version);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.usage_data
    ADD CONSTRAINT usage_data_pkey PRIMARY KEY (user_id, bucket, chute_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.user_current_balance
    ADD CONSTRAINT user_current_balance_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.users
    ADD CONSTRAINT users_fingerprint_hash_key UNIQUE (fingerprint_hash);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.users
    ADD CONSTRAINT users_hotkey_key UNIQUE (hotkey);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.vm_cache_configs
    ADD CONSTRAINT vm_cache_configs_pkey PRIMARY KEY (miner_hotkey, vm_name);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.wallet_balances
    ADD CONSTRAINT wallet_balances_pkey PRIMARY KEY (wallet_id);

CREATE INDEX idx_attestation_created ON __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations USING btree (created_at);

CREATE INDEX idx_attestation_server ON __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations USING btree (server_id);

CREATE INDEX idx_attestation_verified ON __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations USING btree (verified_at);

CREATE INDEX idx_boot_created ON __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations USING btree (created_at);

CREATE INDEX idx_boot_miner_vm ON __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations USING btree (miner_hotkey, vm_name);

CREATE INDEX idx_boot_server_id ON __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations USING btree (server_ip);

CREATE INDEX idx_boot_verified ON __CHUTES_PRODUCTION_BASE_SCHEMA__.boot_attestations USING btree (verified_at);

CREATE INDEX idx_capacity_log_chute_timestamp ON __CHUTES_PRODUCTION_BASE_SCHEMA__.capacity_log USING btree (chute_id, "timestamp");

CREATE INDEX idx_chute_active_lastq ON __CHUTES_PRODUCTION_BASE_SCHEMA__.instances USING btree (chute_id, active, verified, last_queried_at);

CREATE INDEX idx_image_name_tag ON __CHUTES_PRODUCTION_BASE_SCHEMA__.images USING btree (name, tag);

CREATE INDEX idx_name_created_at ON __CHUTES_PRODUCTION_BASE_SCHEMA__.images USING btree (name, created_at);

CREATE INDEX idx_name_public ON __CHUTES_PRODUCTION_BASE_SCHEMA__.images USING btree (name, public);

CREATE INDEX idx_server_miner ON __CHUTES_PRODUCTION_BASE_SCHEMA__.servers USING btree (miner_hotkey);

CREATE INDEX idx_servers_last_health ON __CHUTES_PRODUCTION_BASE_SCHEMA__.servers USING btree (last_health_at);

CREATE INDEX idx_servers_maintenance_pending ON __CHUTES_PRODUCTION_BASE_SCHEMA__.servers USING btree (miner_hotkey) WHERE (maintenance_pending_window_id IS NOT NULL);

CREATE UNIQUE INDEX idx_servers_miner_name ON __CHUTES_PRODUCTION_BASE_SCHEMA__.servers USING btree (miner_hotkey, name);

CREATE INDEX idx_tee_upgrade_window_bounds ON __CHUTES_PRODUCTION_BASE_SCHEMA__.tee_upgrade_windows USING btree (upgrade_window_start, upgrade_window_end);

CREATE INDEX idx_user_id_date_block ON __CHUTES_PRODUCTION_BASE_SCHEMA__.payments USING btree (user_id, created_at, block);

CREATE INDEX idx_vm_cache_last_boot ON __CHUTES_PRODUCTION_BASE_SCHEMA__.vm_cache_configs USING btree (last_boot_at);

CREATE INDEX idx_vm_cache_miner ON __CHUTES_PRODUCTION_BASE_SCHEMA__.vm_cache_configs USING btree (miner_hotkey);

CREATE INDEX ix_capacity_log_chute_id ON __CHUTES_PRODUCTION_BASE_SCHEMA__.capacity_log USING btree (chute_id);

CREATE INDEX ix_capacity_log_timestamp ON __CHUTES_PRODUCTION_BASE_SCHEMA__.capacity_log USING btree ("timestamp");

CREATE UNIQUE INDEX ix_oauth_apps_client_id ON __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps USING btree (client_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.admin_balance_changes
    ADD CONSTRAINT admin_balance_changes_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.api_key_scopes
    ADD CONSTRAINT api_key_scopes_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.api_keys(api_key_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_shares
    ADD CONSTRAINT chute_shares_chute_id_fkey FOREIGN KEY (chute_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes(chute_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_shares
    ADD CONSTRAINT chute_shares_shared_by_fkey FOREIGN KEY (shared_by) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chute_shares
    ADD CONSTRAINT chute_shares_shared_to_fkey FOREIGN KEY (shared_to) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes
    ADD CONSTRAINT chutes_image_id_fkey FOREIGN KEY (image_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.images(image_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes
    ADD CONSTRAINT chutes_logo_id_fkey FOREIGN KEY (logo_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.logos(logo_id) ON DELETE SET NULL;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes
    ADD CONSTRAINT chutes_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.images
    ADD CONSTRAINT images_logo_id_fkey FOREIGN KEY (logo_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.logos(logo_id) ON DELETE SET NULL;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.images
    ADD CONSTRAINT images_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instance_nodes
    ADD CONSTRAINT instance_nodes_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.instances(instance_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instance_nodes
    ADD CONSTRAINT instance_nodes_node_id_fkey FOREIGN KEY (node_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.nodes(uuid);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT instances_billed_to_fkey FOREIGN KEY (billed_to) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT instances_chute_id_fkey FOREIGN KEY (chute_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes(chute_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.instances
    ADD CONSTRAINT instances_config_id_fkey FOREIGN KEY (config_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs(config_id) ON DELETE SET NULL;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs
    ADD CONSTRAINT jobs_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.instances(instance_id) ON DELETE SET NULL;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs
    ADD CONSTRAINT jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs
    ADD CONSTRAINT launch_configs_chute_id_fkey FOREIGN KEY (chute_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes(chute_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.launch_configs
    ADD CONSTRAINT launch_configs_job_id_fkey FOREIGN KEY (job_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.jobs(job_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.llm_details
    ADD CONSTRAINT llm_details_chute_id_fkey FOREIGN KEY (chute_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes(chute_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.logos
    ADD CONSTRAINT logos_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.model_aliases
    ADD CONSTRAINT model_aliases_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.nodes
    ADD CONSTRAINT nodes_server_id_fkey FOREIGN KEY (server_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.servers(server_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_authorization_id_fkey FOREIGN KEY (authorization_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations(authorization_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_app_shares
    ADD CONSTRAINT oauth_app_shares_app_id_fkey FOREIGN KEY (app_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps(app_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_app_shares
    ADD CONSTRAINT oauth_app_shares_shared_by_fkey FOREIGN KEY (shared_by) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_app_shares
    ADD CONSTRAINT oauth_app_shares_shared_to_fkey FOREIGN KEY (shared_to) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps
    ADD CONSTRAINT oauth_apps_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_app_id_fkey FOREIGN KEY (app_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_apps(app_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_authorization_id_fkey FOREIGN KEY (authorization_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.oauth_authorizations(authorization_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.pending_stakes
    ADD CONSTRAINT pending_stakes_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.rolling_updates
    ADD CONSTRAINT rolling_updates_chute_id_fkey FOREIGN KEY (chute_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.chutes(chute_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.secrets
    ADD CONSTRAINT secrets_user_id_fkey FOREIGN KEY (user_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.users(user_id);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.server_attestations
    ADD CONSTRAINT server_attestations_server_id_fkey FOREIGN KEY (server_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.servers(server_id) ON DELETE CASCADE;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.servers
    ADD CONSTRAINT servers_maintenance_pending_window_id_fkey FOREIGN KEY (maintenance_pending_window_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.tee_upgrade_windows(id) ON DELETE SET NULL;

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.servers
    ADD CONSTRAINT servers_netuid_miner_hotkey_fkey FOREIGN KEY (netuid, miner_hotkey) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.metagraph_nodes(netuid, hotkey);

ALTER TABLE ONLY __CHUTES_PRODUCTION_BASE_SCHEMA__.users
    ADD CONSTRAINT users_logo_id_fkey FOREIGN KEY (logo_id) REFERENCES __CHUTES_PRODUCTION_BASE_SCHEMA__.logos(logo_id) ON DELETE SET NULL;
