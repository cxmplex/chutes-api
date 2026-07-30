"""ChuteFS durability reconcile loop (M7).

Runs in a single API process (the migration/leader worker). Periodically:
  - GCs replica_placement rows for soft-deleted objects/volumes,
  - re-assigns replicas for under-target live objects onto fresh distinct healthy hosts.

The actual ciphertext copy is executed by the source storage TDs, which poll GET /storage/repair/tasks
and push to the newly-assigned peers; this loop only maintains the authoritative placement targets.
"""

import asyncio

from loguru import logger
from sqlalchemy import text

from api.database import engine, get_session
from api.storage.service import reconcile_storage

# How often to run a reconcile pass (seconds). Bounded per pass (max_objects) so a large fleet
# reconciles amortized rather than in one heavy sweep.
RECONCILE_INTERVAL_SECONDS = 300
_RECONCILE_LOCK_KEY = "chutefs-storage-reconcile-v1"


async def reconcile_storage_once() -> bool:
    """Run one pass while a dedicated connection owns the session advisory lock."""
    async with engine.connect() as leader_connection:
        got_lock = bool(
            (
                await leader_connection.execute(
                    text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                    {"lock_key": _RECONCILE_LOCK_KEY},
                )
            ).scalar_one()
        )
        # End the lock-acquisition transaction without returning this physical connection to the
        # pool. Session advisory-lock ownership remains bound to leader_connection.
        await leader_connection.commit()
        if not got_lock:
            return False

        try:
            # Reconcile commits in bounded phases. It must use independent work sessions so those
            # commits can never release or transfer the leader connection.
            async with get_session() as work_session:
                await reconcile_storage(work_session)
        finally:
            unlocked = bool(
                (
                    await leader_connection.execute(
                        text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
                        {"lock_key": _RECONCILE_LOCK_KEY},
                    )
                ).scalar_one()
            )
            await leader_connection.commit()
            if not unlocked:
                raise RuntimeError(
                    "ChuteFS reconcile leadership unlock was not owned by its dedicated connection."
                )
        return True


async def storage_reconcile_loop() -> None:
    """Forever: run a bounded ChuteFS reconcile pass every interval on one elected replica."""
    while True:
        try:
            await reconcile_storage_once()
        except Exception as exc:  # noqa: BLE001 - never let a bad pass kill the loop
            logger.warning(f"ChuteFS reconcile pass failed: {exc}")
        await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
