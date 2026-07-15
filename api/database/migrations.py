"""Serialized dbmate startup migrations for every API worker."""

import asyncio
from pathlib import Path
from urllib.parse import quote

from loguru import logger
from sqlalchemy import text

import api.database.orms  # noqa: F401
from api.config import settings
from api.database import Base, engine


MIGRATION_LOCK_KEY = "chutes-api-dbmate-migrations-v1"
TRACKED_MIGRATION_BASELINE = "20260713140000"


def dbmate_url() -> str:
    db_url = quote(settings.sqlalchemy.replace("+asyncpg", ""), safe=":/@")
    if "127.0.0.1" in db_url or "@postgres:" in db_url:
        separator = "&" if "?" in db_url else "?"
        db_url += f"{separator}sslmode=disable"
    return db_url


def historical_migration_versions() -> list[str]:
    """Versions represented by the ORM bootstrap that predate the enforced storage chain."""
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    return sorted(
        path.name.split("_", 1)[0]
        for path in migrations_dir.glob("*.sql")
        if path.name.split("_", 1)[0].isdigit()
        and path.name.split("_", 1)[0] < TRACKED_MIGRATION_BASELINE
    )


async def record_historical_migration_baseline(connection) -> None:
    """Align legacy create_all deployments with dbmate without skipping the enforced chain."""
    await connection.execute(
        text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)")
    )
    versions = historical_migration_versions()
    if versions:
        values = ", ".join(f"('{version}')" for version in versions)
        await connection.execute(
            text(
                "INSERT INTO schema_migrations (version) "
                f"VALUES {values} ON CONFLICT (version) DO NOTHING"
            )
        )
    await connection.commit()


async def run_database_migrations() -> None:
    """Serialize ORM bootstrap plus every timestamped migration and fail startup closed."""
    async with engine.connect() as connection:
        await connection.execute(
            text("SELECT pg_advisory_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": MIGRATION_LOCK_KEY},
        )
        await connection.commit()
        try:
            # Historical migrations are deltas over the ORM-created base schema. Bootstrap missing
            # base tables under the same lock, then always run dbmate before application ORM work.
            # Triggers and migration-only invariants are never delegated to create_all().
            await connection.run_sync(Base.metadata.create_all)
            await connection.commit()
            await record_historical_migration_baseline(connection)

            process = await asyncio.create_subprocess_exec(
                "dbmate",
                "--url",
                dbmate_url(),
                "--migrations-dir",
                str(Path(__file__).resolve().parents[1] / "migrations"),
                "--migrations-table",
                "schema_migrations",
                "--no-dump-schema",
                "migrate",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if stdout:
                logger.info(stdout.decode(errors="replace").strip())
            if stderr:
                logger.warning(stderr.decode(errors="replace").strip())
            if process.returncode != 0:
                raise RuntimeError(f"dbmate migration failed with exit code {process.returncode}")
            logger.success("Applied all database migrations")
        finally:
            await connection.execute(
                text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
                {"lock_key": MIGRATION_LOCK_KEY},
            )
            await connection.commit()
