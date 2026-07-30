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
from api.database import Base
from api.database.migrations import historical_migration_versions


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
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)")
        )
        for version in historical_migration_versions():
            await connection.execute(
                text(
                    "INSERT INTO schema_migrations(version) VALUES (:version) "
                    "ON CONFLICT (version) DO NOTHING"
                ),
                {"version": version},
            )
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
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)")
        )
        for version in historical_migration_versions():
            await connection.execute(
                text(
                    "INSERT INTO schema_migrations(version) VALUES (:version) "
                    "ON CONFLICT (version) DO NOTHING"
                ),
                {"version": version},
            )


async def test_create_all_then_full_ordered_migration_chain_installs_invariants():
    schema, admin, engine = await _new_schema()
    try:
        await _create_all_then_apply_ordered_migrations(engine)
        async with engine.connect() as connection:
            versions = set(
                (await connection.execute(text("SELECT version FROM schema_migrations")))
                .scalars()
                .all()
            )
            triggers = set(
                (
                    await connection.execute(
                        text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")
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
        assert {path.name.split("_", 1)[0] for path in _migration_paths()} <= versions
        assert {
            "trg_prevent_user_delete_before_chutefs_erasure",
            "trg_complete_launch_config_on_job_terminal",
            "trg_launch_terminal_registry_scope",
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
                (await connection.execute(text("SELECT version FROM schema_migrations")))
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
                    "CREATE TABLE schema_migrations "
                    "(version VARCHAR(255) PRIMARY KEY)"
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
                    text(
                        "INSERT INTO schema_migrations(version) VALUES (:version)"
                    ),
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
                    "CREATE TABLE schema_migrations "
                    "(version VARCHAR(255) PRIMARY KEY)"
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
