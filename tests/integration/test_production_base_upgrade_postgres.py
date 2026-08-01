"""Deterministic production-base upgrade and fresh-catalog convergence on PostgreSQL.

The tracked fixture is generated from b4f439b's ORM metadata and exact 64-row migration ledger.
It contains only fixed synthetic rows. It deliberately does not stand in for deployment-owned
restored production snapshots, deployed source SHAs, migration ledgers, row counts, or restore
evidence, all of which remain release qualifications outside source control.
"""

import asyncio
from collections import Counter
import hashlib
import os
from pathlib import Path
from pprint import pformat
import re
import shutil
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

import api.database.orms  # noqa: F401
from api.database import Base
from api.database.migrations import historical_migration_versions


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for the production-base upgrade harness",
    ),
]
MIGRATIONS = Path(__file__).resolve().parents[2] / "api/migrations"
BASE_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/production_base_b4f439b.sql"
BASE_FIXTURE_SHA256 = "c29d88a31b2d4c3db922b3833492e95dd2148be7e3eadd910550f2de98b19e5f"
SCHEMA_PLACEHOLDER = "__CHUTES_PRODUCTION_BASE_SCHEMA__"
SCHEMA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
SYNTHETIC_SERVER_ID = "synthetic-legacy-server"


@pytest.fixture(autouse=True)
def nv_attest():
    yield


def _fixture_source(schema: str) -> str:
    assert SCHEMA_NAME.fullmatch(schema), schema
    source = BASE_FIXTURE.read_text(encoding="utf-8")
    assert hashlib.sha256(source.encode("utf-8")).hexdigest() == BASE_FIXTURE_SHA256
    assert "generated from b4f439b37327fa35e2d731b98c1645f90df97426" in source
    assert "not a substitute for deployment-owned restored production snapshots" in source
    assert source.count(f"INSERT INTO {SCHEMA_PLACEHOLDER}.schema_migrations") == 64
    assert "synthetic-legacy-attestation-accepted" in source
    assert "synthetic-legacy-attestation-rejected" in source
    assert "synthetic-legacy-node" in source
    assert source.count(SCHEMA_PLACEHOLDER) > 100
    assert "fixture_b4f439b_source" not in source
    assert "COPY " not in source
    insert_lines = [line for line in source.splitlines() if line.startswith("INSERT INTO ")]
    assert not any(
        re.search(
            r"\b(?:clock_timestamp|current_timestamp|gen_random_uuid|now|random)\s*\(",
            line,
            re.IGNORECASE,
        )
        for line in insert_lines
    )
    insert_targets = re.findall(
        rf"^INSERT INTO {re.escape(SCHEMA_PLACEHOLDER)}\.([a-z_]+) ",
        source,
        flags=re.MULTILINE,
    )
    assert Counter(insert_targets) == Counter(
        {
            "boot_attestations": 1,
            "metagraph_nodes": 1,
            "nodes": 1,
            "schema_migrations": 64,
            "server_attestations": 2,
            "servers": 1,
        }
    )
    return source.replace(SCHEMA_PLACEHOLDER, schema)


async def _raw_execute(connection, sql: str) -> None:
    raw = await connection.get_raw_connection()
    await raw.driver_connection.execute(sql)


async def _restore_base_fixture(admin, schema: str) -> None:
    async with admin.begin() as connection:
        await _raw_execute(connection, _fixture_source(schema))


async def _create_schema(admin, schema: str) -> None:
    assert SCHEMA_NAME.fullmatch(schema), schema
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))


async def _drop_schema(admin, schema: str) -> None:
    assert SCHEMA_NAME.fullmatch(schema), schema
    async with admin.begin() as connection:
        await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))


def _schema_engine(schema: str):
    assert SCHEMA_NAME.fullmatch(schema), schema
    return create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"server_settings": {"search_path": schema}},
    )


def _reset_metadata_foreign_key_create_rules() -> None:
    """Make each create_all call behave like startup in a fresh interpreter.

    PostgreSQL cycle handling builds ``AddConstraint`` objects that permanently install a
    private, inline-create suppression rule on the shared SQLAlchemy constraint object. Test
    modules create schemas repeatedly in one interpreter, so clear those generated rules before
    and after this production-upgrade bootstrap instead of allowing an earlier fixture to change
    which foreign keys a later partial-schema create emits.
    """

    for table in Base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            constraint._create_rule = None


async def _install_current_orm_and_baseline(engine) -> None:
    """Mirror startup's create_all plus immutable production-ledger recording."""
    _reset_metadata_foreign_key_create_rules()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await connection.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS "
                    "schema_migrations (version VARCHAR(255) PRIMARY KEY)"
                )
            )
            for version in historical_migration_versions():
                await connection.execute(
                    text(
                        "INSERT INTO schema_migrations(version) VALUES (:version) "
                        "ON CONFLICT (version) DO NOTHING"
                    ),
                    {"version": version},
                )
    finally:
        _reset_metadata_foreign_key_create_rules()


def _dbmate_url(schema: str) -> str:
    url = make_url(TEST_DATABASE_URL)
    url = url.set(drivername=url.drivername.replace("+asyncpg", ""))
    url = url.update_query_dict({"search_path": schema, "sslmode": "disable"})
    return url.render_as_string(hide_password=False)


async def _migrate_with_dbmate(schema: str) -> None:
    dbmate = os.getenv("DBMATE_BIN") or shutil.which("dbmate")
    if not dbmate:
        pytest.skip("dbmate binary is required for the production-base upgrade harness")
    process = await asyncio.create_subprocess_exec(
        dbmate,
        "--url",
        _dbmate_url(schema),
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
    assert process.returncode == 0, (
        f"dbmate failed for {schema}:\n"
        + stdout.decode(errors="replace")
        + stderr.decode(errors="replace")
    )


def _normalize_sql(value, schema: str):
    if value is None:
        return None
    rendered = str(value)
    rendered = rendered.replace(f'"{schema}".', "<schema>.")
    rendered = rendered.replace(f"{schema}.", "<schema>.")
    return " ".join(rendered.split())


def _normalized_constraint_name(table: str, name: str, kind: str) -> str:
    if kind == "p" and name == f"{table}_pkey":
        return "<auto-primary-key>"
    if kind == "u" and name.startswith(f"{table}_") and name.endswith("_key"):
        return "<auto-unique>"
    if kind == "f" and name.startswith(f"{table}_") and name.endswith("_fkey"):
        return "<auto-foreign-key>"
    return name


def _normalized_index_name(table: str, name: str) -> str:
    if name == f"{table}_pkey":
        return "<auto-primary-key>"
    if name.startswith(f"{table}_") and name.endswith("_key"):
        return "<auto-unique>"
    return name


async def _query_rows(engine, statement: str, schema: str):
    async with engine.connect() as connection:
        result = await connection.execute(text(statement), {"schema": schema})
        return [dict(row._mapping) for row in result]


async def _normalized_catalog(engine, schema: str) -> dict[str, list[tuple]]:
    columns = await _query_rows(
        engine,
        """
        SELECT relation.relname AS table_name,
               relation.relkind::text AS relation_kind,
               attribute.attname AS column_name,
               format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
               attribute.attnotnull AS not_null,
               pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true)
                   AS default_expression,
               attribute.attidentity::text AS identity_kind,
               attribute.attgenerated::text AS generated_kind
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = relation.oid
           AND attribute_default.adnum = attribute.attnum
         WHERE namespace.nspname = :schema
           AND relation.relkind IN ('r', 'p', 'v', 'm')
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY relation.relname, attribute.attname
        """,
        schema,
    )
    constraints = await _query_rows(
        engine,
        """
        SELECT relation.relname AS table_name,
               constraint_row.conname AS constraint_name,
               constraint_row.contype::text AS constraint_kind,
               constraint_row.confdeltype::text AS delete_action,
               constraint_row.confupdtype::text AS update_action,
               constraint_row.condeferrable AS deferrable,
               constraint_row.condeferred AS initially_deferred,
               constraint_row.convalidated AS validated,
               pg_get_constraintdef(constraint_row.oid, true) AS definition
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND constraint_row.contype IN ('p', 'u', 'c', 'f')
         ORDER BY relation.relname, constraint_row.conname
        """,
        schema,
    )
    indexes = await _query_rows(
        engine,
        """
        SELECT relation.relname AS table_name,
               index_relation.relname AS index_name,
               index_row.indisunique AS is_unique,
               index_row.indisprimary AS is_primary,
               access_method.amname AS access_method,
               pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate,
               pg_get_indexdef(index_row.indexrelid, 0, true) AS definition
          FROM pg_index AS index_row
          JOIN pg_class AS relation ON relation.oid = index_row.indrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_am AS access_method ON access_method.oid = index_relation.relam
         WHERE namespace.nspname = :schema
         ORDER BY relation.relname, index_relation.relname
        """,
        schema,
    )
    functions = await _query_rows(
        engine,
        """
        SELECT procedure.proname AS function_name,
               pg_get_function_identity_arguments(procedure.oid) AS identity_arguments,
               procedure.prokind::text AS function_kind,
               language.lanname AS language,
               pg_get_functiondef(procedure.oid) AS definition
          FROM pg_proc AS procedure
          JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
          JOIN pg_language AS language ON language.oid = procedure.prolang
         WHERE namespace.nspname = :schema
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_depend AS dependency
                WHERE dependency.classid = 'pg_proc'::regclass
                  AND dependency.objid = procedure.oid
                  AND dependency.refclassid = 'pg_extension'::regclass
                  AND dependency.deptype = 'e'
           )
         ORDER BY procedure.proname, pg_get_function_identity_arguments(procedure.oid)
        """,
        schema,
    )
    triggers = await _query_rows(
        engine,
        """
        SELECT relation.relname AS table_name,
               trigger_row.tgname AS trigger_name,
               trigger_row.tgenabled::text AS enabled,
               pg_get_triggerdef(trigger_row.oid, true) AS definition
          FROM pg_trigger AS trigger_row
          JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND NOT trigger_row.tgisinternal
         ORDER BY relation.relname, trigger_row.tgname
        """,
        schema,
    )

    return {
        "columns": sorted(
            (
                row["table_name"],
                row["relation_kind"],
                row["column_name"],
                row["data_type"],
                row["not_null"],
                _normalize_sql(row["default_expression"], schema),
                row["identity_kind"],
                row["generated_kind"],
            )
            for row in columns
        ),
        "constraints": sorted(
            (
                row["table_name"],
                _normalized_constraint_name(
                    row["table_name"],
                    row["constraint_name"],
                    row["constraint_kind"],
                ),
                row["constraint_kind"],
                row["delete_action"],
                row["update_action"],
                row["deferrable"],
                row["initially_deferred"],
                row["validated"],
                _normalize_sql(row["definition"], schema),
            )
            for row in constraints
        ),
        "indexes": sorted(
            (
                row["table_name"],
                _normalized_index_name(row["table_name"], row["index_name"]),
                row["is_unique"],
                row["is_primary"],
                row["access_method"],
                _normalize_sql(row["predicate"], schema),
                _normalize_sql(row["definition"], schema),
            )
            for row in indexes
        ),
        "functions": sorted(
            (
                row["function_name"],
                _normalize_sql(row["identity_arguments"], schema),
                row["function_kind"],
                row["language"],
                _normalize_sql(row["definition"], schema),
            )
            for row in functions
        ),
        "triggers": sorted(
            (
                row["table_name"],
                row["trigger_name"],
                row["enabled"],
                _normalize_sql(row["definition"], schema),
            )
            for row in triggers
        ),
    }


def _assert_catalogs_equal(upgraded: dict[str, list[tuple]], fresh: dict[str, list[tuple]]):
    differences = []
    for section in ("columns", "constraints", "indexes", "functions", "triggers"):
        upgraded_counter = Counter(upgraded[section])
        fresh_counter = Counter(fresh[section])
        if upgraded_counter == fresh_counter:
            continue
        missing = list((fresh_counter - upgraded_counter).elements())
        unexpected = list((upgraded_counter - fresh_counter).elements())
        differences.append(
            f"normalized {section} catalog differs "
            f"({len(missing)} missing, {len(unexpected)} unexpected)\n"
            f"missing from upgrade:\n{pformat(missing)}\n"
            f"unexpected in upgrade:\n{pformat(unexpected)}"
        )
    if differences:
        pytest.fail(
            "production-base upgrade catalog differs from fresh install:\n\n"
            + "\n\n".join(differences)
        )


async def _assert_synthetic_history_preserved(engine) -> None:
    async with engine.connect() as connection:
        server = (
            await connection.execute(
                text(
                    "SELECT server_id, ip, miner_hotkey, name, created_at, compute_type, tee_type "
                    "FROM servers WHERE server_id = :server_id"
                ),
                {"server_id": SYNTHETIC_SERVER_ID},
            )
        ).one()
        assert tuple(server) == (
            SYNTHETIC_SERVER_ID,
            "192.0.2.10",
            "5SyntheticLegacyMiner",
            "synthetic-legacy-server-name",
            server.created_at,
            "gpu",
            "tdx",
        )
        assert server.created_at.isoformat() == "2026-07-14T12:01:00+00:00"

        node = (
            await connection.execute(
                text(
                    "SELECT uuid, server_id, miner_hotkey, gpu_identifier, verified_at "
                    "FROM nodes WHERE uuid = 'synthetic-legacy-node'"
                )
            )
        ).one()
        assert tuple(node[:4]) == (
            "synthetic-legacy-node",
            SYNTHETIC_SERVER_ID,
            "5SyntheticLegacyMiner",
            "NVIDIA-B200-SYNTHETIC",
        )
        assert node.verified_at.isoformat() == "2026-07-14T12:05:00+00:00"

        attestations = (
            await connection.execute(
                text(
                    "SELECT attestation_id, quote_data, verification_error, measurement_version, "
                    "attempt_sequence FROM server_attestations "
                    "WHERE server_id = :server_id ORDER BY attempt_sequence"
                ),
                {"server_id": SYNTHETIC_SERVER_ID},
            )
        ).all()
        assert [tuple(row) for row in attestations] == [
            (
                "synthetic-legacy-attestation-accepted",
                "c3ludGhldGljLWFjY2VwdGVkLXF1b3Rl",
                None,
                "legacy-1.0.0",
                1,
            ),
            (
                "synthetic-legacy-attestation-rejected",
                "c3ludGhldGljLXJlamVjdGVkLXF1b3Rl",
                "synthetic quote rejection",
                "legacy-1.0.0",
                2,
            ),
        ]

        subject = (
            await connection.execute(
                text(
                    "SELECT owner_hotkey, compute_type, tee_type, deployment_model "
                    "FROM server_attestation_subjects WHERE server_id = :server_id"
                ),
                {"server_id": SYNTHETIC_SERVER_ID},
            )
        ).one()
        assert tuple(subject) == ("5SyntheticLegacyMiner", "gpu", "tdx", "gpu")

        boot = (
            await connection.execute(
                text(
                    "SELECT quote_data, server_ip, miner_hotkey, vm_name, measurement_version "
                    "FROM boot_attestations "
                    "WHERE attestation_id = 'synthetic-legacy-boot-attestation'"
                )
            )
        ).one()
        assert tuple(boot) == (
            "c3ludGhldGljLWJvb3QtcXVvdGU=",
            "192.0.2.10",
            "5SyntheticLegacyMiner",
            "synthetic-legacy-vm",
            "legacy-1.0.0",
        )

        versions = set(
            (await connection.execute(text("SELECT version FROM schema_migrations")))
            .scalars()
            .all()
        )
        expected_versions = {path.name.split("_", 1)[0] for path in MIGRATIONS.glob("*.sql")}
        assert versions == expected_versions


async def test_b4f439b_upgrade_converges_with_fresh_catalog_and_preserves_history():
    suffix = uuid.uuid4().hex
    upgraded_schema = f"production_base_upgrade_{suffix}"
    fresh_schema = f"production_base_fresh_{suffix}"
    admin = create_async_engine(TEST_DATABASE_URL)
    upgraded_engine = None
    fresh_engine = None
    try:
        await _restore_base_fixture(admin, upgraded_schema)
        await _create_schema(admin, fresh_schema)
        upgraded_engine = _schema_engine(upgraded_schema)
        fresh_engine = _schema_engine(fresh_schema)

        async with upgraded_engine.connect() as connection:
            fixture_versions = set(
                (await connection.execute(text("SELECT version FROM schema_migrations")))
                .scalars()
                .all()
            )
        assert fixture_versions == set(historical_migration_versions())
        assert len(fixture_versions) == 64

        await _install_current_orm_and_baseline(upgraded_engine)
        await _install_current_orm_and_baseline(fresh_engine)
        await _migrate_with_dbmate(upgraded_schema)
        await _migrate_with_dbmate(fresh_schema)

        await _assert_synthetic_history_preserved(upgraded_engine)
        upgraded_catalog = await _normalized_catalog(upgraded_engine, upgraded_schema)
        fresh_catalog = await _normalized_catalog(fresh_engine, fresh_schema)
        _assert_catalogs_equal(upgraded_catalog, fresh_catalog)
    finally:
        if upgraded_engine is not None:
            await upgraded_engine.dispose()
        if fresh_engine is not None:
            await fresh_engine.dispose()
        await _drop_schema(admin, upgraded_schema)
        await _drop_schema(admin, fresh_schema)
        await admin.dispose()
