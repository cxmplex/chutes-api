"""Dedicated negative proving unsupported PostgreSQL majors mutate no application catalog."""

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from api.database.migrations import bootstrap_production_base


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not TEST_DATABASE_URL,
        reason="TEST_DATABASE_URL is required for the PostgreSQL-major rejection gate",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    yield


async def test_unsupported_postgres_major_rejects_before_schema_mutation():
    admin = create_async_engine(TEST_DATABASE_URL)
    async with admin.connect() as connection:
        server_version_num = await connection.scalar(
            text("SELECT current_setting('server_version_num')::INTEGER")
        )
    if server_version_num // 10000 == 15:
        await admin.dispose()
        pytest.skip("the dedicated rejection gate requires PostgreSQL 16")

    schema = f"unsupported_production_base_{uuid.uuid4().hex}"
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="qualified only for PostgreSQL 15"):
                await bootstrap_production_base(connection)
            await connection.rollback()
            relations = list(
                (
                    await connection.execute(
                        text(
                            "SELECT relname FROM pg_class AS relation "
                            "JOIN pg_namespace AS namespace "
                            "ON namespace.oid = relation.relnamespace "
                            "WHERE namespace.nspname = current_schema()"
                        )
                    )
                ).scalars()
            )
            assert relations == []
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await admin.dispose()
