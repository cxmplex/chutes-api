"""ChuteFS durability reconcile loop (M7).

Runs in a single API process (the migration/leader worker). Periodically:
  - GCs replica_placement rows for soft-deleted objects/volumes,
  - re-assigns replicas for under-target live objects onto fresh distinct healthy hosts.

The actual ciphertext copy is executed by the source storage TDs, which poll GET /storage/repair/tasks
and push to the newly-assigned peers; this loop only maintains the authoritative placement targets.
"""

import asyncio

from loguru import logger

from api.config import settings
from api.database import get_session
from api.storage.service import reconcile_storage

# How often to run a reconcile pass (seconds). Bounded per pass (max_objects) so a large fleet
# reconciles amortized rather than in one heavy sweep.
RECONCILE_INTERVAL_SECONDS = 300
# Cross-pod leader lock: the per-worker migration-process gate is per POD, so N API pods would each
# run a reconcile loop and race on the UNIQUE(object_id, server_id) placement rows. A short redis
# lock (TTL just under the interval) ensures only ONE pod runs a given pass.
_RECONCILE_LOCK_KEY = "storage:reconcile:leader"
_RECONCILE_LOCK_TTL = RECONCILE_INTERVAL_SECONDS - 30


async def storage_reconcile_loop() -> None:
    """Forever: run a bounded ChuteFS reconcile pass every RECONCILE_INTERVAL_SECONDS (single pod)."""
    while True:
        try:
            # Only the pod that wins the redis lock runs this pass; others skip until it expires.
            got_lock = await settings.redis_client.set(
                _RECONCILE_LOCK_KEY, "1", nx=True, ex=_RECONCILE_LOCK_TTL
            )
            if got_lock:
                async with get_session() as session:
                    await reconcile_storage(session)
        except Exception as exc:  # noqa: BLE001 - never let a bad pass kill the loop
            logger.warning(f"ChuteFS reconcile pass failed: {exc}")
        await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
