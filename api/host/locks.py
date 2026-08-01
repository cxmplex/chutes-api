"""Transaction-scoped advisory locks for lifecycle and registry authority."""

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session


GPU_LIFECYCLE_LOCK_KEY = "chutes:gpu-lifecycle:v1"
GPU_LIFECYCLE_LOCK_INFO_KEY = "gpu_lifecycle_lock_held"
REGISTRY_SUBJECT_LOCK_PREFIX = "chutes:registry-auth:v1"


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


def registry_subject_lock_keys(
    *,
    server_id: str,
    launch_config_id: str | None,
) -> tuple[str, ...]:
    """Return the deterministic registry lock set for one authenticated subject."""

    if not isinstance(server_id, str) or not server_id or server_id != server_id.strip():
        raise ValueError("registry subject requires a canonical server id")
    keys = {f"{REGISTRY_SUBJECT_LOCK_PREFIX}:server:{server_id}"}
    if launch_config_id is not None:
        if (
            not isinstance(launch_config_id, str)
            or not launch_config_id
            or launch_config_id != launch_config_id.strip()
        ):
            raise ValueError("registry subject requires a canonical launch config id")
        keys.add(f"{REGISTRY_SUBJECT_LOCK_PREFIX}:launch-config:{launch_config_id}")
    return tuple(sorted(keys))


async def acquire_registry_subject_locks(
    db: AsyncSession,
    *,
    server_id: str,
    launch_config_id: str | None,
) -> None:
    """Serialize one authenticated registry server/config subject.

    Every caller acquires the same sorted key set before ORM row locks. Distinct
    servers therefore proceed independently while a server or launch config
    shared by two requests remains serialized.
    """

    for key in registry_subject_lock_keys(
        server_id=server_id,
        launch_config_id=launch_config_id,
    ):
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )
