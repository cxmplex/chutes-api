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

from api.database import get_session
from api.storage.service import reconcile_storage

# How often to run a reconcile pass (seconds). Bounded per pass (max_objects) so a large fleet
# reconciles amortized rather than in one heavy sweep.
RECONCILE_INTERVAL_SECONDS = 300
_RECONCILE_LOCK_KEY = "chutefs-storage-reconcile-v1"


async def storage_reconcile_loop() -> None:
    """Forever: run a bounded ChuteFS reconcile pass every RECONCILE_INTERVAL_SECONDS (single pod)."""
    while True:
        try:
            # A session-level PostgreSQL advisory lock cannot expire mid-pass. It remains owned by
            # this exact DB connection across the reconcile function's bounded commits and is
            # explicitly released before the pooled connection is returned.
            async with get_session() as session:
                got_lock = bool(
                    (
                        await session.execute(
                            text("SELECT pg_try_advisory_lock(hashtextextended(:lock_key, 0))"),
                            {"lock_key": _RECONCILE_LOCK_KEY},
                        )
                    ).scalar_one()
                )
                if got_lock:
                    try:
                        await reconcile_storage(session)
                    finally:
                        await session.execute(
                            text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
                            {"lock_key": _RECONCILE_LOCK_KEY},
                        )
        except Exception as exc:  # noqa: BLE001 - never let a bad pass kill the loop
            logger.warning(f"ChuteFS reconcile pass failed: {exc}")
        await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
