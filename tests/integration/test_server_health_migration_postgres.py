"""Real-Postgres ownership tests for the server-health catch-up migration."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
MIGRATION_DIR = Path(__file__).resolve().parents[2] / "api/migrations"
UPSTREAM_MIGRATION = "20260626120000_server_health.sql"
CATCH_UP_MIGRATION = "20260715120000_server_health_forward.sql"
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for real-Postgres migration tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """Migration tests do not invoke the external GPU-attestation CLI."""
    yield


def _migration_sql(filename: str, direction: str) -> str:
    migration = (MIGRATION_DIR / filename).read_text()
    if direction == "up":
        return migration.split("-- migrate:up", 1)[1].split("-- migrate:down", 1)[0]
    return migration.split("-- migrate:down", 1)[1]


async def _server_health_shape(engine) -> tuple[bool, bool]:
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                """
                SELECT
                    EXISTS (
                        SELECT 1
                        FROM information_schema.columns
                        WHERE table_schema = current_schema()
                          AND table_name = 'servers'
                          AND column_name = 'last_health_at'
                          AND data_type = 'timestamp with time zone'
                    ),
                    EXISTS (
                        SELECT 1
                        FROM pg_indexes
                        WHERE schemaname = current_schema()
                          AND indexname = 'idx_servers_last_health'
                    )
                """
            )
        )
        return tuple(result.one())


@pytest.mark.parametrize("baseline", ["fresh", "remediation"])
async def test_server_health_up_down_chain_preserves_upstream_ownership(baseline):
    schema = f"server_health_migration_{baseline}_{uuid.uuid4().hex}"
    admin = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    engine = None
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            TEST_DATABASE_URL,
            poolclass=NullPool,
            connect_args={"server_settings": {"search_path": schema}},
        )

        async with engine.begin() as connection:
            raw = await connection.get_raw_connection()
            driver = raw.driver_connection
            await driver.execute("CREATE TABLE servers (server_id TEXT PRIMARY KEY)")
            await driver.execute(
                "CREATE TABLE schema_migrations (version VARCHAR(255) PRIMARY KEY)"
            )
            if baseline == "fresh":
                await driver.execute(_migration_sql(UPSTREAM_MIGRATION, "up"))
            await driver.execute(
                "INSERT INTO schema_migrations (version) VALUES ('20260626120000')"
            )

            catch_up = _migration_sql(CATCH_UP_MIGRATION, "up")
            await driver.execute(catch_up)
            await driver.execute(catch_up)
            await driver.execute(
                "INSERT INTO schema_migrations (version) VALUES ('20260715120000')"
            )

        assert await _server_health_shape(engine) == (True, True)

        async with engine.begin() as connection:
            raw = await connection.get_raw_connection()
            driver = raw.driver_connection
            await driver.execute(_migration_sql(CATCH_UP_MIGRATION, "down"))
            await driver.execute("DELETE FROM schema_migrations WHERE version = '20260715120000'")

        assert await _server_health_shape(engine) == (True, True)

        async with engine.begin() as connection:
            raw = await connection.get_raw_connection()
            driver = raw.driver_connection
            await driver.execute(_migration_sql(UPSTREAM_MIGRATION, "down"))
            await driver.execute("DELETE FROM schema_migrations WHERE version = '20260626120000'")

        assert await _server_health_shape(engine) == (False, False)
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()
