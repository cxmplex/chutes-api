"""Global transaction serialization for GPU lifecycle authority."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


GPU_LIFECYCLE_LOCK_KEY = "chutes:gpu-lifecycle:v1"


async def acquire_gpu_lifecycle_lock(db: AsyncSession) -> None:
    """Acquire before any lifecycle-related ORM row lock.

    PostgreSQL transaction advisory locks are re-entrant, so dependencies and
    services may both call this without changing ordering.
    """

    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": GPU_LIFECYCLE_LOCK_KEY},
    )
