"""Serialized dbmate startup migrations for every API worker."""

import asyncio
from pathlib import Path

from loguru import logger
from sqlalchemy import text
from sqlalchemy.engine import make_url

import api.database.orms  # noqa: F401
from api.config import settings
from api.database import Base, engine


MIGRATION_LOCK_KEY = "chutes-api-dbmate-migrations-v1"

# Immutable versions present in the production API base used for this remediation. Branch-added
# migrations must never be inferred into this set by timestamp: every version outside this exact
# tuple remains visible to dbmate and runs against both existing and freshly bootstrapped schemas.
PRODUCTION_BASE_MIGRATION_VERSIONS: tuple[str, ...] = (
    "20241101123129",
    "20241101150057",
    "20241106123144",
    "20241113191447",
    "20241118131550",
    "20241122174045",
    "20241128104225",
    "20241201113452",
    "20241202095623",
    "20241211122523",
    "20241212104206",
    "20241213085609",
    "20241214121531",
    "20241214123318",
    "20241214144031",
    "20241216101012",
    "20241217110214",
    "20241221115644",
    "20241227084133",
    "20241229094223",
    "20241229142051",
    "20241231195935",
    "20250117101020",
    "20250118143120",
    "20250118204148",
    "20250122121028",
    "20250128185705",
    "20250128185835",
    "20250203180911",
    "20250207120000",
    "20250218081133",
    "20250218081504",
    "20250219081020",
    "20250306143614",
    "20250319073422",
    "20250319074720",
    "20250415103135",
    "20250423083926",
    "20250424134911",
    "20250512084635",
    "20250705010101",
    "20250709175230",
    "20250712111758",
    "20250716111259",
    "20250716155308",
    "20250720084231",
    "20250726171323",
    "20250727133106",
    "20250824113239",
    "20250829115200",
    "20250903081317",
    "20250918104132",
    "20251030165517",
    "20251102184128",
    "20251229142400",
    "20260102190913",
    "20260115120000",
    "20260115120100",
    "20260131120000",
    "20260131120100",
    "20260218120000",
    "20260403120000",
    "20260513000000",
    "20260626120000",
)
_LOCAL_DBMATE_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "postgres"})


def dbmate_url() -> str:
    """Render dbmate's URL structurally without corrupting credentials or query values."""
    db_url = make_url(settings.sqlalchemy)
    db_url = db_url.set(drivername=db_url.drivername.replace("+asyncpg", ""))
    if (db_url.host or "").lower() in _LOCAL_DBMATE_HOSTS and "sslmode" not in db_url.query:
        db_url = db_url.update_query_dict({"sslmode": "disable"})
    return db_url.render_as_string(hide_password=False)


def historical_migration_versions() -> list[str]:
    """Return only the immutable production-base versions represented by ORM bootstrap."""
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    files_by_version: dict[str, list[Path]] = {}
    for migration_path in migrations_dir.glob("*.sql"):
        version = migration_path.name.split("_", 1)[0]
        if version in PRODUCTION_BASE_MIGRATION_VERSIONS:
            files_by_version.setdefault(version, []).append(migration_path)

    missing = [
        version for version in PRODUCTION_BASE_MIGRATION_VERSIONS if version not in files_by_version
    ]
    duplicates = {version: paths for version, paths in files_by_version.items() if len(paths) != 1}
    if missing or duplicates:
        duplicate_names = {
            version: [path.name for path in paths] for version, paths in sorted(duplicates.items())
        }
        raise RuntimeError(
            "The immutable production migration baseline does not match disk: "
            f"missing={missing!r}, duplicates={duplicate_names!r}"
        )
    return list(PRODUCTION_BASE_MIGRATION_VERSIONS)


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
