"""Global transaction serialization for GPU lifecycle authority."""

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session


GPU_LIFECYCLE_LOCK_KEY = "chutes:gpu-lifecycle:v1"
GPU_LIFECYCLE_LOCK_INFO_KEY = "gpu_lifecycle_lock_held"


@event.listens_for(Session, "after_transaction_end")
def _clear_lifecycle_lock_guard(session: Session, transaction) -> None:
    if transaction.parent is None:
        session.info.pop(GPU_LIFECYCLE_LOCK_INFO_KEY, None)


def assert_gpu_external_work_allowed(db: AsyncSession, operation: str) -> None:
    """Fail tests and runtime if an external adapter runs under lifecycle custody."""

    info = getattr(db, "info", None)
    if isinstance(info, dict) and info.get(GPU_LIFECYCLE_LOCK_INFO_KEY):
        raise RuntimeError(
            f"External GPU operation {operation} cannot run under the lifecycle transaction"
        )


async def acquire_gpu_lifecycle_lock(db: AsyncSession) -> None:
    """Acquire before any lifecycle-related ORM row lock.

    PostgreSQL transaction advisory locks are re-entrant, so dependencies and
    services may both call this without changing ordering.
    """

    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": GPU_LIFECYCLE_LOCK_KEY},
    )
    db.info[GPU_LIFECYCLE_LOCK_INFO_KEY] = True
