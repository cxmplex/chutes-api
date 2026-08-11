"""Fail-closed PostgreSQL checks for the immutable production-base catalog manifest."""

import hashlib
import os
from pathlib import Path
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

import api.database.orms  # noqa: F401
from api.database import Base, create_application_tables
from api.database.production_base_catalog import (
    DAILY_REVENUE_SUMMARY_HISTORICAL_MD5,
    DAILY_REVENUE_SUMMARY_QUOTA_COMMENT,
    DAILY_REVENUE_SUMMARY_QUOTA_VARIANT,
    PRODUCTION_BASE_CATALOG_SHA256,
    ProductionBaseCatalogMismatch,
    collect_production_base_catalog,
    function_body_sha256,
    load_production_base_catalog_manifest,
    normalize_catalog_sql,
    parse_production_base_catalog_manifest,
    production_base_contract_sha256,
    render_production_base_catalog_manifest,
    validate_production_base_catalog,
)
from api.database.migrations import bootstrap_production_base


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
PRODUCTION_BASE_SQL = (
    Path(__file__).resolve().parents[2] / "api/database/production_base.sql"
)
HISTORICAL_REVENUE_MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "api/migrations/20250918104132_per_day_private_instance_rev.sql"
)
requires_postgres = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for production-base catalog validation",
)


@pytest.fixture(autouse=True)
def nv_attest():
    yield


def _reset_metadata_foreign_key_create_rules() -> None:
    for table in Base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            constraint._create_rule = None


async def _raw_execute(connection, sql: str) -> None:
    raw = await connection.get_raw_connection()
    await raw.driver_connection.execute(sql)


async def _new_catalog_schema(*, install_contract: bool = True):
    schema = f"production_base_catalog_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        # Keep the target as the only explicit search-path entry. Adding public would make
        # SQLAlchemy's unqualified has_table() see public's application tables and skip creating
        # the isolated copies; pg_catalog remains implicitly searchable.
        connect_args={"server_settings": {"search_path": schema}},
    )
    if install_contract:
        _reset_metadata_foreign_key_create_rules()
        try:
            async with engine.begin() as connection:
                await connection.run_sync(create_application_tables)
                await _raw_execute(
                    connection, PRODUCTION_BASE_SQL.read_text(encoding="utf-8")
                )
        except BaseException:
            await engine.dispose()
            async with admin.begin() as connection:
                await connection.execute(
                    text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                )
            await admin.dispose()
            raise
        finally:
            _reset_metadata_foreign_key_create_rules()
    return schema, admin, engine


async def _drop_catalog_schema(schema, admin, engine) -> None:
    await engine.dispose()
    async with admin.begin() as connection:
        await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    await admin.dispose()


def _historical_daily_revenue_summary_sql() -> str:
    source = HISTORICAL_REVENUE_MIGRATION.read_text(encoding="utf-8")
    historical = source.split(
        "DROP MATERIALIZED VIEW IF EXISTS daily_revenue_summary CASCADE;", maxsplit=1
    )[1].split(
        "CREATE OR REPLACE FUNCTION update_balance_on_instance_delete()", maxsplit=1
    )[0]
    assert "FROM subscription_history" in historical
    assert (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_daily_revenue_summary_date" in historical
    )
    return (
        "CREATE MATERIALIZED VIEW subscription_history AS "
        "SELECT NULL::TIMESTAMP AS payment_date, "
        "       NULL::DOUBLE PRECISION AS amount WHERE FALSE; "
        "DROP MATERIALIZED VIEW daily_revenue_summary CASCADE; " + historical
    )


def test_function_body_fingerprint_is_schema_portable_and_preserves_public_digest():
    body = "BEGIN\n  RETURN encode(public.digest('two  spaces', 'sha256'), 'hex');\nEND"
    # pg_proc.prosrc excludes the owning function's schema. A function owned by public and the
    # same function installed in an isolated catalog therefore have identical semantic evidence,
    # while the explicit public.digest reference remains untouched.
    public_evidence = {
        "owner_schema": "public",
        "body_sha256": function_body_sha256(body),
    }
    isolated_evidence = {
        "owner_schema": "production_base_catalog_example",
        "body_sha256": function_body_sha256(body),
    }
    assert public_evidence["body_sha256"] == isolated_evidence["body_sha256"]
    assert public_evidence["body_sha256"] == (
        "b1e0452cc67a5c6e1f26ef01ef17b2b84ff78c5b67f0e21d64bb736b11582fa4"
    )
    assert (
        function_body_sha256(body.replace("'two  spaces'", "'two spaces'"))
        != (public_evidence["body_sha256"])
    )


def test_catalog_display_normalization_is_schema_and_whitespace_stable():
    first = "  SELECT  *\nFROM alpha.source  "
    second = 'SELECT * FROM "beta".source'
    assert normalize_catalog_sql(first, "alpha") == normalize_catalog_sql(
        second, "beta"
    )


def test_catalog_manifest_bytes_and_combined_contract_digest_are_pinned():
    path = (
        Path(__file__).resolve().parents[2]
        / "api/database/production_base_catalog.json"
    )
    payload = path.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == PRODUCTION_BASE_CATALOG_SHA256
    assert parse_production_base_catalog_manifest(payload)["format_version"] == 1
    assert (
        production_base_contract_sha256(
            "3ba9b6bdab3fd971709d116dfaa0459321cbb43f6538357c4350c53580150286"
        )
        == "0273cf6f3ce56f31a85f10e0d88549e3ae6040cda164e2b223d484b0f0877a20"
    )

    mutated = bytearray(payload)
    mutated[-2] ^= 1
    with pytest.raises(RuntimeError, match="manifest byte digest mismatch"):
        parse_production_base_catalog_manifest(bytes(mutated))


@pytest.mark.asyncio
@requires_postgres
async def test_fresh_production_base_matches_checked_in_exact_catalog():
    schema, admin, engine = await _new_catalog_schema()
    try:
        async with engine.connect() as connection:
            # Startup passes no schema argument. The validator must bind the non-public schema
            # from current_schema() and still normalize its generated definitions deterministically.
            assert schema != "public"
            actual = await validate_production_base_catalog(connection)
        expected = load_production_base_catalog_manifest()
        assert actual["daily_revenue_summary_variant"] == (
            DAILY_REVENUE_SUMMARY_QUOTA_VARIANT
        )
        assert expected["daily_revenue_summary_variant"] == (
            DAILY_REVENUE_SUMMARY_QUOTA_VARIANT
        )
        assert render_production_base_catalog_manifest(actual) == (
            Path(__file__).resolve().parents[2]
            / "api/database/production_base_catalog.json"
        ).read_text(encoding="utf-8")
    finally:
        await _drop_catalog_schema(schema, admin, engine)


@pytest.mark.asyncio
@requires_postgres
async def test_validator_rejects_unauthenticated_historical_subscription_summary():
    schema, admin, engine = await _new_catalog_schema()
    try:
        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                await connection.execute(text("SELECT 1"))
                await _raw_execute(connection, _historical_daily_revenue_summary_sql())
                catalog = await collect_production_base_catalog(connection)
                summary = next(
                    view
                    for view in catalog["views"]
                    if view["name"] == "daily_revenue_summary"
                )
                assert summary["definition_md5"] == DAILY_REVENUE_SUMMARY_HISTORICAL_MD5
                assert summary["comment"] is None
                with pytest.raises(
                    ProductionBaseCatalogMismatch,
                    match="disabled pending.*producer-provenance",
                ):
                    await validate_production_base_catalog(connection)
            finally:
                await transaction.rollback()
    finally:
        await _drop_catalog_schema(schema, admin, engine)


@pytest.mark.asyncio
@requires_postgres
async def test_validator_rejects_unknown_summary_body_or_comment():
    schema, admin, engine = await _new_catalog_schema()
    try:
        mutations = (
            "COMMENT ON MATERIALIZED VIEW daily_revenue_summary "
            "IS 'unknown compatibility claim'",
            _historical_daily_revenue_summary_sql()
            + "COMMENT ON MATERIALIZED VIEW daily_revenue_summary "
            "IS 'historical body with a forbidden comment';",
            "DROP MATERIALIZED VIEW daily_revenue_summary CASCADE; "
            "CREATE MATERIALIZED VIEW daily_revenue_summary AS "
            "SELECT CURRENT_DATE AS date, 0::BIGINT AS new_subscriber_count, "
            "       0::BIGINT AS new_subscriber_revenue, "
            "       0::DOUBLE PRECISION AS paygo_revenue, "
            "       0::DOUBLE PRECISION AS instance_revenue, "
            "       0::DOUBLE PRECISION AS sponsored_inference WHERE FALSE; "
            "COMMENT ON MATERIALIZED VIEW daily_revenue_summary IS '"
            + DAILY_REVENUE_SUMMARY_QUOTA_COMMENT
            + "'; CREATE UNIQUE INDEX idx_daily_revenue_summary_date "
            "ON daily_revenue_summary (date);",
        )
        for mutation in mutations:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    await connection.execute(text("SELECT 1"))
                    await _raw_execute(connection, mutation)
                    with pytest.raises(
                        ProductionBaseCatalogMismatch,
                        match="unknown body/comment pair",
                    ):
                        await validate_production_base_catalog(connection)
                finally:
                    await transaction.rollback()
    finally:
        await _drop_catalog_schema(schema, admin, engine)


@pytest.mark.asyncio
@requires_postgres
async def test_marker_fast_path_rejects_same_name_unexpected_function_overload():
    schema, admin, engine = await _new_catalog_schema(install_contract=False)
    try:
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
        async with engine.begin() as connection:
            await _raw_execute(
                connection,
                "CREATE FUNCTION version_numbers(INTEGER) RETURNS BIGINT "
                "LANGUAGE SQL IMMUTABLE AS 'SELECT $1::BIGINT'",
            )
        async with engine.connect() as connection:
            with pytest.raises(
                ProductionBaseCatalogMismatch,
                match="unexpected_function_overloads",
            ):
                await bootstrap_production_base(connection)
    finally:
        await _drop_catalog_schema(schema, admin, engine)


@pytest.mark.asyncio
@requires_postgres
async def test_validator_rejects_partition_collisions_without_mutating_seeded_rows():
    schema, admin, engine = await _new_catalog_schema()
    try:
        mutations = (
            "CREATE TABLE partitioned_invocations_collision (id INTEGER)",
            "CREATE TABLE p_llm_metrics_20260812 PARTITION OF p_llm_metrics "
            "FOR VALUES FROM ('2026-08-13') TO ('2026-08-14')",
            "CREATE TABLE metrics_wrong_name PARTITION OF p_llm_metrics "
            "FOR VALUES FROM ('2026-08-12') TO ('2026-08-13')",
            "ALTER TABLE p_llm_metrics_20260811 ADD CONSTRAINT "
            "unexpected_partition_requests_check CHECK (total_requests >= 0)",
            "ALTER TABLE p_llm_metrics_20260811 ENABLE ROW LEVEL SECURITY; "
            "CREATE POLICY unexpected_partition_policy ON p_llm_metrics_20260811 "
            "USING (true)",
            "CREATE TRIGGER unexpected_partition_before BEFORE UPDATE "
            "ON p_llm_metrics_20260811 FOR EACH ROW "
            "EXECUTE FUNCTION fn_reset_job_assignment()",
            "CREATE TABLE p_llm_metrics_20260812 "
            "(LIKE p_llm_metrics INCLUDING ALL); "
            "ALTER TABLE p_llm_metrics_20260812 ADD COLUMN discarded TEXT; "
            "ALTER TABLE p_llm_metrics_20260812 DROP COLUMN discarded; "
            "ALTER TABLE p_llm_metrics ATTACH PARTITION p_llm_metrics_20260812 "
            "FOR VALUES FROM ('2026-08-12') TO ('2026-08-13')",
        )
        for mutation in mutations:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    await connection.execute(
                        text("SELECT create_llm_metrics_part(DATE '2026-08-11')")
                    )
                    await connection.execute(
                        text(
                            "INSERT INTO p_llm_metrics (chute_id, date, total_requests) "
                            "VALUES ('seeded-partition-row', DATE '2026-08-11', 7)"
                        )
                    )
                    await _raw_execute(connection, mutation)
                    with pytest.raises(
                        ProductionBaseCatalogMismatch,
                        match="dynamic partition|partition-prefix",
                    ):
                        await validate_production_base_catalog(connection)
                    assert (
                        await connection.scalar(
                            text(
                                "SELECT total_requests FROM p_llm_metrics "
                                "WHERE chute_id = 'seeded-partition-row' "
                                "AND date = DATE '2026-08-11'"
                            )
                        )
                        == 7
                    )
                finally:
                    await transaction.rollback()
    finally:
        await _drop_catalog_schema(schema, admin, engine)


@pytest.mark.asyncio
@requires_postgres
async def test_validator_rejects_wrong_allowlisted_catalog_objects():
    schema, admin, engine = await _new_catalog_schema()
    try:
        mutations = (
            (
                "ALTER TABLE audit_entries ALTER COLUMN created_at DROP DEFAULT",
                '"default"',
            ),
            (
                "ALTER TABLE chute_manual_boosts "
                "ALTER COLUMN boost TYPE NUMERIC USING boost::NUMERIC",
                "boost",
            ),
            (
                'ALTER TABLE audit_entries ALTER COLUMN path TYPE TEXT COLLATE "C"',
                "collation",
            ),
            (
                "ALTER TABLE audit_entries ALTER COLUMN path SET STORAGE EXTERNAL",
                "storage",
            ),
            (
                "ALTER TABLE audit_entries ALTER COLUMN path SET COMPRESSION lz4",
                "compression",
            ),
            (
                "ALTER TABLE audit_entries ALTER COLUMN path SET STATISTICS 37",
                "statistics_target",
            ),
            (
                "ALTER TABLE audit_entries ALTER COLUMN path SET (n_distinct = 0.5)",
                "options",
            ),
            (
                "GRANT SELECT (path) ON audit_entries TO PUBLIC",
                "acl",
            ),
            (
                "GRANT SELECT ON audit_entries TO pg_read_all_data",
                "pg_read_all_data",
            ),
            (
                "GRANT EXECUTE ON FUNCTION version_numbers(TEXT) TO pg_read_all_data",
                "pg_read_all_data",
            ),
            (
                "ALTER FUNCTION version_numbers(TEXT) "
                "SUPPORT pg_catalog.varchar_support",
                "support",
            ),
            (
                "GRANT USAGE, UPDATE, SELECT ON SEQUENCE "
                "instance_compute_history_id_seq TO pg_read_all_data",
                "pg_read_all_data",
            ),
            (
                "DROP TRIGGER tr_node_history_insert ON nodes; "
                "CREATE CONSTRAINT TRIGGER tr_node_history_insert "
                "AFTER INSERT ON nodes NOT DEFERRABLE INITIALLY IMMEDIATE "
                "FOR EACH ROW EXECUTE FUNCTION fn_node_history_insert()",
                "constraint_oid",
            ),
            (
                "ALTER TABLE chute_manual_boosts ADD CONSTRAINT "
                "chute_manual_boosts_boost_unique UNIQUE (boost)",
                "chute_manual_boosts_boost_unique",
            ),
            (
                "CREATE INDEX unexpected_audit_lower_path "
                "ON audit_entries ((lower(path)))",
                "unexpected_audit_lower_path",
            ),
            (
                "CREATE TRIGGER unexpected_instance_audit_before "
                "BEFORE UPDATE ON instance_audit FOR EACH ROW "
                "EXECUTE FUNCTION fn_instance_audit_update()",
                "unexpected_instance_audit_before",
            ),
            (
                "CREATE RULE unexpected_audit_instead AS ON DELETE TO audit_entries "
                "DO INSTEAD NOTHING",
                "unexpected_audit_instead",
            ),
            (
                "CREATE TABLE audit_entries_inheritor () INHERITS (audit_entries)",
                "inheritance topology",
            ),
            (
                "ALTER TABLE audit_entries ADD COLUMN discarded TEXT; "
                "ALTER TABLE audit_entries DROP COLUMN discarded",
                "physical_attribute_count|dropped_attribute_count",
            ),
            (
                "CREATE POLICY latent_audit_policy ON audit_entries USING (false)",
                "policy_count",
            ),
            (
                "DROP INDEX idx_audit_path; "
                "CREATE INDEX idx_audit_path ON audit_entries (block)",
                "idx_audit_path",
            ),
            (
                "DROP MATERIALIZED VIEW user_current_balance; "
                "CREATE MATERIALIZED VIEW user_current_balance AS "
                "SELECT user_id, balance AS stored_balance, "
                "       0::DOUBLE PRECISION AS total_instance_costs, "
                "       balance AS effective_balance "
                "  FROM users WHERE FALSE; "
                "CREATE UNIQUE INDEX idx_user_current_balance_user_id "
                "ON user_current_balance (user_id)",
                "user_current_balance",
            ),
        )
        for mutation, match in mutations:
            async with engine.connect() as connection:
                transaction = await connection.begin()
                try:
                    # SQLAlchemy begins lazily; materialize the transaction before bypassing its
                    # statement layer for multi-command asyncpg execution.
                    await connection.execute(text("SELECT 1"))
                    await _raw_execute(connection, mutation)
                    with pytest.raises(ProductionBaseCatalogMismatch, match=match):
                        await validate_production_base_catalog(connection, schema)
                finally:
                    await transaction.rollback()

        async with engine.connect() as connection:
            # Every adversarial mutation was transactional; rollback must restore the exact head.
            restored = await validate_production_base_catalog(connection, schema)
            assert restored["daily_revenue_summary_variant"] == (
                DAILY_REVENUE_SUMMARY_QUOTA_VARIANT
            )
    finally:
        await _drop_catalog_schema(schema, admin, engine)
