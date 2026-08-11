"""Real PostgreSQL coverage for the exact ORM-bootstrap migration ordering."""

import asyncio
import os
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

import api.database.orms  # noqa: F401
import api.gpu_scheduler as gpu_scheduler
from api.database import Base, create_application_tables
from api.database import migrations as database_migrations
from api.database.migrations import (
    bootstrap_production_base,
    historical_migration_versions,
)
from api.database.production_base_catalog import collect_production_base_catalog


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for startup migration tests",
    ),
]
MIGRATIONS = Path(__file__).resolve().parents[2] / "api/migrations"
GPU_MIGRATION_FLOOR = "20260723030000"


@pytest.fixture(autouse=True)
def nv_attest():
    yield


def _migration_paths(*, floor: str | None = None) -> list[Path]:
    production_base = set(historical_migration_versions())
    return sorted(
        path
        for path in MIGRATIONS.glob("*.sql")
        if (version := path.name.split("_", 1)[0]).isdigit()
        and version not in production_base
        and (floor is None or version >= floor)
    )


def _split(path: Path) -> tuple[str, str]:
    return path.read_text(encoding="utf-8").split("-- migrate:down", 1)


async def _execute(connection, sql: str) -> None:
    raw = await connection.get_raw_connection()
    await raw.driver_connection.execute(sql)


async def _new_schema():
    schema = f"startup_chain_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"server_settings": {"search_path": schema}},
    )
    return schema, admin, engine


async def _drop_schema(schema, admin, engine):
    await engine.dispose()
    async with admin.begin() as connection:
        await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    await admin.dispose()


async def _create_all_then_apply_ordered_migrations(engine) -> None:
    async with engine.connect() as connection:
        await bootstrap_production_base(connection)
    for path in _migration_paths():
        version = path.name.split("_", 1)[0]
        up_sql, _down_sql = _split(path)
        async with engine.begin() as connection:
            try:
                await _execute(connection, up_sql)
            except Exception as exc:
                raise RuntimeError(f"ordered migration failed: {path.name}") from exc
            await connection.execute(
                text(
                    "INSERT INTO schema_migrations(version) VALUES (:version) "
                    "ON CONFLICT (version) DO NOTHING"
                ),
                {"version": version},
            )


async def _create_all_and_record_baseline(engine) -> None:
    async with engine.connect() as connection:
        await bootstrap_production_base(connection)


async def _record_exact_baseline_ledger(connection) -> None:
    await connection.execute(
        text("CREATE TABLE schema_migrations (version VARCHAR(255) PRIMARY KEY)")
    )
    for version in historical_migration_versions():
        await connection.execute(
            text("INSERT INTO schema_migrations(version) VALUES (:version)"),
            {"version": version},
        )


async def test_production_base_rejects_unledgered_nonempty_and_partial_schemas():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            await connection.execute(text("CREATE TABLE foreign_sentinel(value TEXT)"))
            await connection.execute(
                text("INSERT INTO foreign_sentinel VALUES ('preserve')")
            )
        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="unledgered nonempty schema"):
                await bootstrap_production_base(connection)
            await connection.rollback()
        async with engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT value FROM foreign_sentinel"))
                == "preserve"
            )
            assert await connection.scalar(
                text("SELECT to_regclass('schema_migrations') IS NULL")
            )

        async with engine.begin() as connection:
            await connection.execute(text("DROP TABLE foreign_sentinel"))
            await connection.execute(
                text("CREATE TABLE schema_migrations(version VARCHAR(255) PRIMARY KEY)")
            )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                {"version": historical_migration_versions()[0]},
            )
        async with engine.connect() as connection:
            with pytest.raises(
                RuntimeError, match="partial production migration baseline"
            ):
                await bootstrap_production_base(connection)
            await connection.rollback()
            assert (
                await connection.scalar(text("SELECT count(*) FROM schema_migrations"))
                == 1
            )
            assert await connection.scalar(text("SELECT to_regclass('users') IS NULL"))

        async with engine.begin() as connection:
            for version in historical_migration_versions()[1:]:
                await connection.execute(
                    text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                    {"version": version},
                )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES ('20991231235959')")
            )
        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="no source file on disk"):
                await bootstrap_production_base(connection)
            await connection.rollback()
            assert (
                await connection.scalar(text("SELECT count(*) FROM schema_migrations"))
                == len(historical_migration_versions()) + 1
            )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_exact_dev98_unbounded_ledger_converges_to_dbmate_varchar255():
    schema, admin, engine = await _new_schema()
    expected_versions = set(historical_migration_versions()) | set(
        database_migrations.REVIEWED_DEV_WIP_ADDITIONAL_VERSIONS
    )
    assert len(expected_versions) == 98
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text("CREATE TABLE schema_migrations(version VARCHAR PRIMARY KEY)")
            )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                [{"version": version} for version in sorted(expected_versions)],
            )
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
            column_type = await connection.scalar(
                text(
                    "SELECT format_type(attribute.atttypid, attribute.atttypmod) "
                    "FROM pg_attribute AS attribute "
                    "WHERE attribute.attrelid = 'schema_migrations'::regclass "
                    "AND attribute.attname = 'version'"
                )
            )
            assert column_type == "character varying(255)"
            assert await connection.scalar(
                text("SELECT count(*) FROM ONLY schema_migrations")
            ) == len(expected_versions)
            assert (
                await connection.scalar(
                    text("SELECT count(*) FROM ONLY schema_contracts")
                )
                == 1
            )
    finally:
        await _drop_schema(schema, admin, engine)


@pytest.mark.parametrize(
    "mutation",
    [
        "inherited-child",
        "custom-collation",
        "dropped-column",
        "extra-index",
        "clustered-index",
        "extra-foreign-key",
        "row-security-policy",
        "unknown-row",
        "stale-contract-digest",
        "public-grant",
        "public-column-grant",
    ],
)
async def test_production_base_marker_rejects_catalog_and_row_spoofing(mutation):
    schema, admin, engine = await _new_schema()
    try:
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
        async with engine.begin() as connection:
            if mutation == "inherited-child":
                await connection.execute(
                    text(
                        "CREATE TABLE schema_contracts_child (extra TEXT) "
                        "INHERITS (schema_contracts)"
                    )
                )
                await connection.execute(text("DELETE FROM ONLY schema_contracts"))
                await connection.execute(
                    text(
                        "INSERT INTO schema_contracts_child("
                        "contract_name, sql_sha256, catalog_sha256, contract_sha256, "
                        "catalog_variant) VALUES ("
                        ":contract_name, :sql_sha256, :catalog_sha256, :contract_sha256, "
                        "'quota_current_activation_approximation')"
                    ),
                    {
                        "contract_name": database_migrations.PRODUCTION_BASE_CONTRACT_NAME,
                        "sql_sha256": database_migrations.PRODUCTION_BASE_SQL_SHA256,
                        "catalog_sha256": database_migrations.PRODUCTION_BASE_CATALOG_SHA256,
                        "contract_sha256": database_migrations.PRODUCTION_BASE_CONTRACT_SHA256,
                    },
                )
            elif mutation == "custom-collation":
                await connection.execute(
                    text(
                        "ALTER TABLE schema_contracts ALTER COLUMN catalog_variant "
                        'TYPE TEXT COLLATE "C"'
                    )
                )
            elif mutation == "extra-index":
                await connection.execute(
                    text(
                        "CREATE INDEX schema_contracts_variant_idx "
                        "ON schema_contracts(catalog_variant)"
                    )
                )
            elif mutation == "dropped-column":
                await connection.execute(
                    text("ALTER TABLE schema_contracts ADD COLUMN discarded TEXT")
                )
                await connection.execute(
                    text("ALTER TABLE schema_contracts DROP COLUMN discarded")
                )
            elif mutation == "clustered-index":
                await connection.execute(
                    text("CLUSTER schema_contracts USING schema_contracts_pkey")
                )
            elif mutation == "extra-foreign-key":
                await connection.execute(
                    text("CREATE TABLE marker_variants(name TEXT PRIMARY KEY)")
                )
                await connection.execute(
                    text(
                        "INSERT INTO marker_variants VALUES "
                        "('quota_current_activation_approximation')"
                    )
                )
                await connection.execute(
                    text(
                        "ALTER TABLE schema_contracts ADD CONSTRAINT marker_variant_fk "
                        "FOREIGN KEY(catalog_variant) REFERENCES marker_variants(name)"
                    )
                )
            elif mutation == "row-security-policy":
                await connection.execute(
                    text("ALTER TABLE schema_contracts ENABLE ROW LEVEL SECURITY")
                )
                await connection.execute(
                    text("CREATE POLICY marker_policy ON schema_contracts USING (true)")
                )
            elif mutation == "unknown-row":
                await connection.execute(
                    text(
                        "INSERT INTO schema_contracts("
                        "contract_name, sql_sha256, catalog_sha256, contract_sha256, "
                        "catalog_variant) VALUES ('unknown-contract', repeat('0', 64), "
                        "repeat('0', 64), repeat('0', 64), 'unknown')"
                    )
                )
            elif mutation == "stale-contract-digest":
                await connection.execute(
                    text(
                        "UPDATE ONLY schema_contracts SET contract_sha256 = repeat('0', 64)"
                    )
                )
            elif mutation == "public-grant":
                await connection.execute(
                    text("GRANT SELECT ON schema_contracts TO PUBLIC")
                )
            else:
                await connection.execute(
                    text("GRANT UPDATE(contract_sha256) ON schema_contracts TO PUBLIC")
                )

        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="schema_contracts|contract digest"):
                await bootstrap_production_base(connection)
            await connection.rollback()
            if mutation == "inherited-child":
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ONLY schema_contracts")
                    )
                    == 0
                )
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ONLY schema_contracts_child")
                    )
                    == 1
                )
            elif mutation == "custom-collation":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT attribute.attcollation <> type_row.typcollation "
                            "FROM pg_attribute AS attribute "
                            "JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid "
                            "WHERE attribute.attrelid = 'schema_contracts'::regclass "
                            "AND attribute.attname = 'catalog_variant'"
                        )
                    )
                    is True
                )
            elif mutation == "extra-index":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT to_regclass('schema_contracts_variant_idx') IS NOT NULL"
                        )
                    )
                    is True
                )
            elif mutation == "dropped-column":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_attribute "
                            "WHERE attrelid = 'schema_contracts'::regclass "
                            "AND attnum > 0 AND attisdropped"
                        )
                    )
                    == 1
                )
            elif mutation == "clustered-index":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT indisclustered FROM pg_index "
                            "WHERE indrelid = 'schema_contracts'::regclass "
                            "AND indisprimary"
                        )
                    )
                    is True
                )
            elif mutation == "extra-foreign-key":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_constraint "
                            "WHERE conrelid = 'schema_contracts'::regclass "
                            "AND conname = 'marker_variant_fk'"
                        )
                    )
                    == 1
                )
            elif mutation == "row-security-policy":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_policy "
                            "WHERE polrelid = 'schema_contracts'::regclass"
                        )
                    )
                    == 1
                )
            elif mutation == "unknown-row":
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ONLY schema_contracts")
                    )
                    == 2
                )
            elif mutation == "stale-contract-digest":
                assert (
                    await connection.scalar(
                        text("SELECT contract_sha256 FROM ONLY schema_contracts")
                    )
                    == "0" * 64
                )
            elif mutation == "public-grant":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT relacl IS NOT NULL FROM pg_class "
                            "WHERE oid = 'schema_contracts'::regclass"
                        )
                    )
                    is True
                )
            else:
                assert (
                    await connection.scalar(
                        text(
                            "SELECT attacl IS NOT NULL FROM pg_attribute "
                            "WHERE attrelid = 'schema_contracts'::regclass "
                            "AND attname = 'contract_sha256'"
                        )
                    )
                    is True
                )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_unbounded_ledger_shape_is_not_accepted_for_only_the_base64():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text("CREATE TABLE schema_migrations(version VARCHAR PRIMARY KEY)")
            )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                [{"version": version} for version in historical_migration_versions()],
            )
        async with engine.connect() as connection:
            with pytest.raises(
                RuntimeError, match="only for the exact witnessed 98-version"
            ):
                await bootstrap_production_base(connection)
            await connection.rollback()
            assert (
                await connection.scalar(
                    text(
                        "SELECT format_type(attribute.atttypid, attribute.atttypmod) "
                        "FROM pg_attribute AS attribute "
                        "WHERE attribute.attrelid = 'schema_migrations'::regclass "
                        "AND attribute.attname = 'version'"
                    )
                )
                == "character varying"
            )
            assert await connection.scalar(text("SELECT to_regclass('users') IS NULL"))
    finally:
        await _drop_schema(schema, admin, engine)


@pytest.mark.parametrize(
    "ledger_kind",
    [
        "no-primary-key",
        "view",
        "expression-index",
        "dropped-column",
        "clustered-index",
        "insert-trigger",
        "insert-rule",
        "public-grant",
        "public-column-grant",
        "foreign-owner",
    ],
)
async def test_production_base_rejects_wrong_schema_migrations_catalog(ledger_kind):
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            if ledger_kind == "no-primary-key":
                await connection.execute(
                    text(
                        "CREATE TABLE schema_migrations(version VARCHAR(255) NOT NULL)"
                    )
                )
                for version in historical_migration_versions():
                    await connection.execute(
                        text(
                            "INSERT INTO schema_migrations(version) VALUES (:version)"
                        ),
                        {"version": version},
                    )
            elif ledger_kind == "view":
                known_version = historical_migration_versions()[0]
                assert known_version.isdigit()
                await connection.execute(
                    text(
                        "CREATE VIEW schema_migrations AS "
                        f"SELECT CAST('{known_version}' AS VARCHAR(255)) AS version"
                    )
                )
            else:
                await connection.execute(
                    text(
                        "CREATE TABLE schema_migrations(version VARCHAR(255) PRIMARY KEY)"
                    )
                )
                if ledger_kind == "expression-index":
                    await connection.execute(
                        text(
                            "CREATE INDEX schema_migrations_expression_idx "
                            "ON schema_migrations (LOWER(version))"
                        )
                    )
                elif ledger_kind == "dropped-column":
                    await connection.execute(
                        text("ALTER TABLE schema_migrations ADD COLUMN discarded TEXT")
                    )
                    await connection.execute(
                        text("ALTER TABLE schema_migrations DROP COLUMN discarded")
                    )
                elif ledger_kind == "clustered-index":
                    await connection.execute(
                        text("CLUSTER schema_migrations USING schema_migrations_pkey")
                    )
                elif ledger_kind == "insert-trigger":
                    await _execute(
                        connection,
                        "CREATE FUNCTION suppress_schema_migration() RETURNS TRIGGER "
                        "LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; "
                        "CREATE TRIGGER suppress_schema_migration BEFORE INSERT "
                        "ON schema_migrations FOR EACH ROW "
                        "EXECUTE FUNCTION suppress_schema_migration()",
                    )
                elif ledger_kind == "insert-rule":
                    await connection.execute(
                        text(
                            "CREATE RULE suppress_schema_migration AS ON INSERT "
                            "TO schema_migrations DO INSTEAD NOTHING"
                        )
                    )
                elif ledger_kind == "public-grant":
                    await connection.execute(
                        text("GRANT INSERT ON schema_migrations TO PUBLIC")
                    )
                elif ledger_kind == "public-column-grant":
                    await connection.execute(
                        text("GRANT UPDATE(version) ON schema_migrations TO PUBLIC")
                    )
                else:
                    await connection.execute(
                        text("ALTER TABLE schema_migrations OWNER TO pg_read_all_data")
                    )
        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="schema_migrations"):
                await bootstrap_production_base(connection)
            await connection.rollback()
            assert await connection.scalar(text("SELECT to_regclass('users') IS NULL"))
            relation_kind = await connection.scalar(
                text(
                    "SELECT relkind::text FROM pg_class WHERE oid = 'schema_migrations'::regclass"
                )
            )
            assert relation_kind == ("v" if ledger_kind == "view" else "r")
            if ledger_kind == "dropped-column":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM pg_attribute "
                            "WHERE attrelid = 'schema_migrations'::regclass "
                            "AND attnum > 0 AND attisdropped"
                        )
                    )
                    == 1
                )
            elif ledger_kind == "clustered-index":
                assert (
                    await connection.scalar(
                        text(
                            "SELECT indisclustered FROM pg_index "
                            "WHERE indrelid = 'schema_migrations'::regclass "
                            "AND indisprimary"
                        )
                    )
                    is True
                )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_unknown_function_failure_preserves_error_and_releases_session_lock(
    monkeypatch,
):
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(create_application_tables)
            await _record_exact_baseline_ledger(connection)
            await _execute(
                connection,
                "CREATE FUNCTION version_numbers(ver TEXT) RETURNS BIGINT "
                "LANGUAGE SQL AS 'SELECT 7::BIGINT'",
            )

        monkeypatch.setattr(database_migrations, "engine", engine)
        with pytest.raises(
            RuntimeError, match="unknown production-base function"
        ) as error:
            await database_migrations.run_database_migrations()
        assert "version_numbers" in str(error.value)

        async with engine.connect() as connection:
            reacquired = await connection.scalar(
                text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                {"lock_key": database_migrations.MIGRATION_LOCK_KEY},
            )
            assert reacquired is True
            assert (
                await connection.scalar(
                    text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
                    {"lock_key": database_migrations.MIGRATION_LOCK_KEY},
                )
                is True
            )
            assert await connection.scalar(text("SELECT version_numbers('1.2.3')")) == 7
            assert await connection.scalar(
                text("SELECT to_regclass('schema_contracts') IS NULL")
            )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_unknown_trigger_is_rejected_and_preserved_before_replacement():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "DELETE FROM schema_contracts WHERE contract_name = :contract_name"
                ),
                {"contract_name": database_migrations.PRODUCTION_BASE_CONTRACT_NAME},
            )
            await _execute(
                connection,
                "DROP TRIGGER after_chute_insert ON chutes; "
                "CREATE TRIGGER after_chute_insert BEFORE INSERT ON chutes "
                "FOR EACH ROW EXECUTE FUNCTION initialize_bounty()",
            )

        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="unknown production-base trigger"):
                await bootstrap_production_base(connection)
            await connection.rollback()
            trigger_type = await connection.scalar(
                text(
                    "SELECT trigger_row.tgtype::integer FROM pg_trigger AS trigger_row "
                    "WHERE trigger_row.tgrelid = 'chutes'::regclass "
                    "AND trigger_row.tgname = 'after_chute_insert'"
                )
            )
            assert (
                trigger_type == 7
            )  # row-level BEFORE INSERT, deliberately not final AFTER.
            assert (
                await connection.scalar(
                    text(
                        "SELECT count(*) FROM schema_contracts "
                        "WHERE contract_name = :contract_name"
                    ),
                    {
                        "contract_name": database_migrations.PRODUCTION_BASE_CONTRACT_NAME
                    },
                )
                == 0
            )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_deployed_cacher_diffusion_function_remains_compatible_on_final_base():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
        async with engine.begin() as connection:
            await _execute(
                connection,
                """
                INSERT INTO users(user_id, coldkey, username, fingerprint_hash, balance)
                VALUES ('legacy-metrics-user', 'legacy-coldkey', 'legacy-metrics-user',
                        'legacy-metrics-fingerprint', 100);
                INSERT INTO images(image_id, artifact_id, user_id, name, tag, compute_type)
                VALUES ('legacy-metrics-image', 'legacy-metrics-image', 'legacy-metrics-user',
                        'legacy-metrics-image', 'v1', 'gpu');
                INSERT INTO chutes(
                    chute_id, user_id, name, image_id, public, standard_template, cords,
                    node_selector, code, filename, ref_str, version, chutes_version
                ) VALUES (
                    'legacy-diffusion-chute', 'legacy-metrics-user', 'legacy-diffusion-chute',
                    'legacy-metrics-image', true, 'diffusion', '[]'::jsonb,
                    '{"compute_type":"gpu","gpu_count":1,"min_vram_gb_per_gpu":16}'::jsonb,
                    'pass', 'chute.py', 'chute:app', 'v1', '0.6.11'
                );
                INSERT INTO invocations(
                    invocation_id, chute_id, chute_user_id, function_name, user_id, image_id,
                    image_user_id, instance_id, miner_uid, miner_hotkey, started_at, completed_at,
                    error_message, request_path, response_path, compute_multiplier, bounty,
                    parent_invocation_id, metrics
                ) VALUES (
                    'legacy-diffusion-invocation', 'legacy-diffusion-chute',
                    'legacy-metrics-user', 'generate', 'legacy-metrics-user',
                    'legacy-metrics-image', 'legacy-metrics-user', 'legacy-instance', 7,
                    'legacy-miner', '2026-08-10 12:00:00', '2026-08-10 12:00:05', NULL,
                    '/request', '/response', 1.0, 0, NULL,
                    '{"steps":20,"sps":4}'::jsonb
                );
                TRUNCATE TABLE diffusion_metrics;
                INSERT INTO diffusion_metrics
                SELECT * FROM get_diffusion_metrics('2026-08-10', '2026-08-10')
                ORDER BY date DESC, name;
                """,
            )
            metric = (
                await connection.execute(
                    text(
                        "SELECT chute_id, name, date, total_steps, total_requests, average_sps "
                        "FROM diffusion_metrics WHERE chute_id = 'legacy-diffusion-chute'"
                    )
                )
            ).one()
            assert tuple(metric[:2]) == (
                "legacy-diffusion-chute",
                "legacy-diffusion-chute",
            )
            assert metric.date.isoformat() == "2026-08-10"
            assert tuple(metric[3:]) == (20, 1, 4)
    finally:
        await _drop_schema(schema, admin, engine)


async def test_legacy_unfiltered_create_all_is_read_only_on_final_catalog():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.connect() as connection:
            await bootstrap_production_base(connection)
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users(user_id, coldkey, username, fingerprint_hash, balance) "
                    "VALUES ('legacy-startup-user', 'legacy-coldkey', 'legacy-startup-user', "
                    "'legacy-startup-fingerprint', 42)"
                )
            )
            await connection.execute(
                text("REFRESH MATERIALIZED VIEW user_current_balance")
            )
        async with engine.connect() as connection:
            before_catalog = await collect_production_base_catalog(connection, schema)
            before_balance = (
                await connection.execute(
                    text(
                        "SELECT user_id, stored_balance, total_instance_costs, effective_balance "
                        "FROM user_current_balance ORDER BY user_id"
                    )
                )
            ).all()
            await connection.run_sync(Base.metadata.create_all)
            after_catalog = await collect_production_base_catalog(connection, schema)
            after_balance = (
                await connection.execute(
                    text(
                        "SELECT user_id, stored_balance, total_instance_costs, effective_balance "
                        "FROM user_current_balance ORDER BY user_id"
                    )
                )
            ).all()
            assert after_catalog == before_catalog
            assert after_balance == before_balance
            assert len(after_balance) == 1
            assert after_balance[0].user_id == "legacy-startup-user"
    finally:
        await _drop_schema(schema, admin, engine)


async def test_unknown_legacy_cache_trigger_blocks_replacement_and_is_preserved():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await _record_exact_baseline_ledger(connection)
            await _execute(
                connection,
                """
                CREATE FUNCTION unknown_legacy_cache_trigger() RETURNS TRIGGER
                LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
                CREATE TRIGGER unknown_legacy_cache_before_update
                BEFORE UPDATE ON user_current_balance FOR EACH ROW
                EXECUTE FUNCTION unknown_legacy_cache_trigger();
                """,
            )

        async with engine.connect() as connection:
            with pytest.raises(
                Exception,
                match="user_current_balance ordinary table has an unknown catalog",
            ):
                await bootstrap_production_base(connection)
            await connection.rollback()
            assert (
                await connection.scalar(
                    text(
                        "SELECT relkind::text FROM pg_class "
                        "WHERE oid = 'user_current_balance'::regclass"
                    )
                )
                == "r"
            )
            assert (
                await connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_trigger "
                        "WHERE tgrelid = 'user_current_balance'::regclass "
                        "AND tgname = 'unknown_legacy_cache_before_update'"
                    )
                )
                == 1
            )
            assert await connection.scalar(
                text("SELECT to_regclass('schema_contracts') IS NULL")
            )
    finally:
        await _drop_schema(schema, admin, engine)


async def test_create_all_then_full_ordered_migration_chain_installs_invariants():
    schema, admin, engine = await _new_schema()
    try:
        await _create_all_then_apply_ordered_migrations(engine)
        async with engine.connect() as connection:
            versions = set(
                (
                    await connection.execute(
                        text("SELECT version FROM schema_migrations")
                    )
                )
                .scalars()
                .all()
            )
            triggers = set(
                (
                    await connection.execute(
                        text(
                            "SELECT trigger_row.tgname "
                            "FROM pg_trigger AS trigger_row "
                            "JOIN pg_class AS relation "
                            "ON relation.oid = trigger_row.tgrelid "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = relation.relnamespace "
                            "WHERE NOT trigger_row.tgisinternal "
                            "AND namespace.oid = current_schema()::regnamespace"
                        )
                    )
                )
                .scalars()
                .all()
            )
            lineage_foreign_keys = {
                (row.table_name, row.column_name): (
                    row.constraint_count,
                    row.constraint_names,
                    row.delete_actions,
                )
                for row in (
                    await connection.execute(
                        text(
                            "SELECT relation.relname AS table_name, "
                            "attribute.attname AS column_name, "
                            "COUNT(*) AS constraint_count, "
                            "ARRAY_AGG(constraint_row.conname ORDER BY "
                            "constraint_row.conname) AS constraint_names, "
                            "ARRAY_AGG(constraint_row.confdeltype::text ORDER BY "
                            "constraint_row.conname) AS delete_actions "
                            "FROM pg_constraint AS constraint_row "
                            "JOIN pg_class AS relation "
                            "ON relation.oid = constraint_row.conrelid "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = relation.relnamespace "
                            "JOIN pg_attribute AS attribute "
                            "ON attribute.attrelid = relation.oid "
                            "AND attribute.attnum = ANY(constraint_row.conkey) "
                            "WHERE namespace.oid = current_schema()::regnamespace "
                            "AND constraint_row.contype = 'f' "
                            "AND (relation.relname, attribute.attname) IN ("
                            "('servers', 'launch_reservation_id'), "
                            "('servers', 'gpu_launch_reservation_id'), "
                            "('servers', 'gpu_allocation_group_id'), "
                            "('instances', 'server_id'), "
                            "('instances', 'gpu_launch_reservation_id'), "
                            "('instances', 'gpu_allocation_group_id'), "
                            "('launch_configs', 'server_id'), "
                            "('launch_configs', 'gpu_launch_reservation_id'), "
                            "('nodes', 'gpu_allocation_group_id')) "
                            "GROUP BY relation.relname, attribute.attname"
                        )
                    )
                )
            }
            # Exact old-binary gate: its SQL column list has storage_enabled but does not know the
            # additive storage_requested column. Both INSERT and UPDATE must remain valid after the
            # schema migration, and the compatibility trigger must preserve the new invariant.
            await connection.execute(
                text(
                    "INSERT INTO metagraph_nodes (hotkey, netuid, checksum, coldkey) "
                    "VALUES ('legacy-storage-owner', 64, 'legacy-storage', 'coldkey')"
                )
            )
            await connection.execute(
                text(
                    "INSERT INTO hosts "
                    "(host_id, name, miner_hotkey, netuid, tee_type, capacity, storage_enabled) "
                    "VALUES ('legacy-storage-insert', 'legacy-storage-insert', "
                    "'legacy-storage-owner', 64, 'tdx', 0, TRUE), "
                    "('legacy-storage-update', 'legacy-storage-update', "
                    "'legacy-storage-owner', 64, 'tdx', 4, FALSE)"
                )
            )
            await connection.execute(
                text(
                    "UPDATE hosts SET capacity = 0, storage_enabled = TRUE "
                    "WHERE host_id = 'legacy-storage-update'"
                )
            )
            legacy_storage_rows = {
                row.host_id: (
                    row.storage_requested,
                    row.storage_enabled,
                    row.capacity,
                )
                for row in (
                    await connection.execute(
                        text(
                            "SELECT host_id, storage_requested, storage_enabled, capacity "
                            "FROM hosts WHERE host_id LIKE 'legacy-storage-%'"
                        )
                    )
                )
            }
        assert legacy_storage_rows == {
            "legacy-storage-insert": (True, True, 0),
            "legacy-storage-update": (True, True, 0),
        }
        assert {path.name.split("_", 1)[0] for path in _migration_paths()} <= versions
        assert {
            "trg_prevent_user_delete_before_chutefs_erasure",
            "trg_complete_launch_config_on_job_terminal",
            "trg_launch_terminal_registry_scope",
            "trg_hosts_storage_capability_implies_intent",
        } <= triggers
        assert lineage_foreign_keys == {
            ("servers", "launch_reservation_id"): (
                1,
                ["fk_servers_launch_reservation"],
                ["r"],
            ),
            ("servers", "gpu_launch_reservation_id"): (
                1,
                ["fk_servers_gpu_launch_reservation"],
                ["r"],
            ),
            ("servers", "gpu_allocation_group_id"): (
                1,
                ["fk_servers_gpu_allocation_group"],
                ["r"],
            ),
            ("instances", "server_id"): (1, ["fk_instances_server"], ["n"]),
            ("instances", "gpu_launch_reservation_id"): (
                1,
                ["fk_instances_gpu_launch_reservation"],
                ["r"],
            ),
            ("instances", "gpu_allocation_group_id"): (
                1,
                ["fk_instances_gpu_allocation_group"],
                ["r"],
            ),
            ("launch_configs", "server_id"): (
                1,
                ["fk_launch_configs_server"],
                ["r"],
            ),
            ("launch_configs", "gpu_launch_reservation_id"): (
                1,
                ["fk_launch_configs_gpu_launch_reservation"],
                ["r"],
            ),
            ("nodes", "gpu_allocation_group_id"): (
                1,
                ["fk_nodes_gpu_allocation_group"],
                ["r"],
            ),
        }
    finally:
        await _drop_schema(schema, admin, engine)


async def test_storage_object_key_migrations_accept_exact_legacy_and_reject_mixed():
    schema, admin, engine = await _new_schema()
    bootstrap_up, _bootstrap_down = _split(
        MIGRATIONS / "20260629120000_chutefs_storage.sql"
    )
    object_key_up, object_key_down = _split(
        MIGRATIONS / "20260703120000_chutefs_object_key_partial_unique.sql"
    )
    try:
        async with engine.begin() as connection:
            await _execute(
                connection,
                "CREATE TABLE users(user_id VARCHAR PRIMARY KEY);"
                "CREATE TABLE servers(server_id VARCHAR PRIMARY KEY);"
                "CREATE TABLE hosts(host_id VARCHAR PRIMARY KEY);",
            )
            await _execute(connection, bootstrap_up)
            await _execute(connection, bootstrap_up)

        # A same-name wrong legacy index is not accepted. The failed transaction rolls the
        # mutation back, leaving the exact bootstrap catalog available for the next phase.
        with pytest.raises(asyncpg.PostgresError, match="invalid legacy shape"):
            async with engine.begin() as connection:
                await _execute(
                    connection,
                    "DROP INDEX idx_storage_objects_volume;"
                    "CREATE INDEX idx_storage_objects_volume "
                    "ON storage_objects(object_id);",
                )
                await _execute(connection, bootstrap_up)

        async with engine.begin() as connection:
            await _execute(connection, object_key_up)
            await _execute(connection, object_key_up)
            predicate = (
                await connection.execute(
                    text(
                        "SELECT pg_get_expr(index_definition.indpred, "
                        "index_definition.indrelid, true) "
                        "FROM pg_index AS index_definition "
                        "WHERE index_definition.indexrelid = "
                        "'uq_storage_object_key'::regclass"
                    )
                )
            ).scalar_one()
            constraint_count = (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM pg_constraint "
                        "WHERE conrelid = 'storage_objects'::regclass "
                        "AND contype = 'u' AND conkey = ARRAY[("
                        "SELECT attnum FROM pg_attribute "
                        "WHERE attrelid = 'storage_objects'::regclass "
                        "AND attname = 'volume_id'), ("
                        "SELECT attnum FROM pg_attribute "
                        "WHERE attrelid = 'storage_objects'::regclass "
                        "AND attname = 'object_key')]::smallint[]"
                    )
                )
            ).scalar_one()
            assert predicate == "deleted IS FALSE"
            assert constraint_count == 0

            # The exact post-migration legacy catalog is reversible and can transition again.
            await _execute(connection, object_key_down)
            await _execute(connection, object_key_up)

        with pytest.raises(
            asyncpg.PostgresError,
            match="requires exact legacy or final columns",
        ):
            async with engine.begin() as connection:
                await _execute(
                    connection,
                    "ALTER TABLE storage_objects ADD COLUMN lifecycle_state "
                    "VARCHAR NOT NULL DEFAULT 'pending'",
                )
                await _execute(connection, object_key_up)
    finally:
        await _drop_schema(schema, admin, engine)


async def test_exact_create_all_baseline_then_dbmate_startup_sequence():
    dbmate = os.getenv("DBMATE_BIN") or shutil.which("dbmate")
    if not dbmate:
        pytest.skip("dbmate binary is required for the exact startup-sequence test")
    schema, admin, engine = await _new_schema()
    try:
        await _create_all_and_record_baseline(engine)
        sync_url = TEST_DATABASE_URL.replace("+asyncpg", "")
        separator = "&" if "?" in sync_url else "?"
        sync_url = f"{sync_url}{separator}search_path={schema}&sslmode=disable"
        process = await asyncio.create_subprocess_exec(
            dbmate,
            "--url",
            sync_url,
            "--migrations-dir",
            str(MIGRATIONS),
            "--migrations-table",
            "schema_migrations",
            "--no-dump-schema",
            "migrate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, stdout.decode(errors="replace") + stderr.decode(
            errors="replace"
        )
        async with engine.connect() as connection:
            versions = set(
                (
                    await connection.execute(
                        text("SELECT version FROM schema_migrations")
                    )
                )
                .scalars()
                .all()
            )
        assert {path.name.split("_", 1)[0] for path in _migration_paths()} <= versions
    finally:
        await _drop_schema(schema, admin, engine)


async def test_prechange_schema_accepts_new_migrations_sequentially_and_down_guards():
    schema, admin, engine = await _new_schema()
    try:
        await _create_all_then_apply_ordered_migrations(engine)
        paths = _migration_paths(floor=GPU_MIGRATION_FLOOR)
        for path in reversed(paths):
            _up_sql, down_sql = _split(path)
            async with engine.begin() as connection:
                await _execute(connection, down_sql)
        for path in paths:
            up_sql, _down_sql = _split(path)
            async with engine.begin() as connection:
                await _execute(connection, up_sql)
        async with engine.connect() as connection:
            completed = await connection.scalar(
                text(
                    "SELECT COUNT(*) FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = 'launch_configs' "
                    "AND column_name = 'completed_at'"
                )
            )
            registry_constraint = await connection.scalar(
                text(
                    "SELECT COUNT(*) FROM pg_constraint "
                    "WHERE conname = 'ck_launch_config_registry_scope' "
                    "AND connamespace = current_schema()::regnamespace"
                )
            )
        assert completed == 1
        assert registry_constraint == 1
    finally:
        await _drop_schema(schema, admin, engine)


async def test_scheduler_readiness_stays_false_until_exact_schema_commit():
    schema, admin, engine = await _new_schema()
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "CREATE TABLE schema_migrations (version VARCHAR(255) PRIMARY KEY)"
                )
            )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                {"version": "99999999999999"},
            )
        with patch.object(gpu_scheduler, "engine", engine):
            assert await gpu_scheduler.required_gpu_schema_present() is False
            async with engine.connect() as migration_connection:
                migration = await migration_connection.begin()
                await migration_connection.execute(
                    text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                    {"version": gpu_scheduler.REQUIRED_GPU_SCHEMA_VERSION},
                )
                # The exact row remains invisible to the readiness connection until
                # the migration owner's transaction commits its whole schema change.
                assert await gpu_scheduler.required_gpu_schema_present() is False
                await migration.commit()
            assert await gpu_scheduler.required_gpu_schema_present() is True
            assert gpu_scheduler.scheduler_liveness_healthy() is True
    finally:
        await _drop_schema(schema, admin, engine)


async def test_scheduler_main_does_no_election_or_orm_work_before_real_schema_barrier():
    class StopScheduler(BaseException):
        pass

    schema, admin, engine = await _new_schema()
    migration_connection = None
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "CREATE TABLE schema_migrations (version VARCHAR(255) PRIMARY KEY)"
                )
            )
            await connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                {"version": "99999999999999"},
            )

        migration_connection = await engine.connect()
        migration = await migration_connection.begin()
        await migration_connection.execute(
            text("INSERT INTO schema_migrations(version) VALUES (:version)"),
            {"version": gpu_scheduler.REQUIRED_GPU_SCHEMA_VERSION},
        )

        tick = AsyncMock(side_effect=StopScheduler())
        schedule = AsyncMock()
        redis = AsyncMock()
        schema_committed = False

        async def release_schema(_delay):
            nonlocal schema_committed
            assert not schema_committed
            assert await gpu_scheduler.required_gpu_schema_present() is False
            assert gpu_scheduler.scheduler_liveness_healthy() is True
            tick.assert_not_awaited()
            schedule.assert_not_awaited()
            redis.set.assert_not_awaited()
            redis.eval.assert_not_awaited()
            await migration.commit()
            schema_committed = True

        with (
            patch.object(gpu_scheduler, "engine", engine),
            patch.object(
                gpu_scheduler,
                "settings",
                SimpleNamespace(redis_client=redis),
            ),
            patch.object(gpu_scheduler, "_tick_with_lock", tick),
            patch.object(gpu_scheduler, "schedule_once", schedule),
            patch.object(gpu_scheduler.asyncio, "sleep", side_effect=release_schema),
            pytest.raises(StopScheduler),
        ):
            await gpu_scheduler.main()

        assert schema_committed
        with patch.object(gpu_scheduler, "engine", engine):
            assert await gpu_scheduler.required_gpu_schema_present() is True
        tick.assert_awaited_once_with()
        schedule.assert_not_awaited()
        redis.set.assert_not_awaited()
        redis.eval.assert_not_awaited()
    finally:
        if migration_connection is not None:
            await migration_connection.close()
        await _drop_schema(schema, admin, engine)
