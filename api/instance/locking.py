"""Canonical row-lock order for launch configurations and instances."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.host.locks import acquire_gpu_lifecycle_lock
from api.instance.schemas import Instance, LaunchConfig


@dataclass(frozen=True)
class LockedLaunchInstanceRows:
    """Exact sorted row identities held by one lifecycle transaction."""

    config_ids: tuple[str, ...]
    instance_ids: tuple[str, ...]
    instance_config_ids: tuple[tuple[str, str | None], ...]


def _ordered_ids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


async def lock_launch_configs_before_instances(
    db: AsyncSession,
    *,
    config_ids: Iterable[str] = (),
    instance_ids: Iterable[str] = (),
    acquire_lifecycle: bool = True,
) -> LockedLaunchInstanceRows:
    """Lock lifecycle rows in the only supported order.

    The global GPU lifecycle advisory lock is first. Callers that already hold
    a workload/lineage advisory lock may pass ``acquire_lifecycle=False`` only
    after acquiring the global lifecycle lock themselves. LaunchConfig rows
    are then locked in lexical order, followed by Instance rows in lexical
    order. The initial Instance/config projection is non-locking and is used
    only to discover immutable ``config_id`` links.
    """

    requested_instances = _ordered_ids(instance_ids)
    requested_configs = _ordered_ids(config_ids)
    ordered_configs = set(requested_configs)
    if acquire_lifecycle:
        await acquire_gpu_lifecycle_lock(db)

    instance_config_map: dict[str, str | None] = {}
    if requested_instances:
        targeted_rows = (
            await db.execute(
                select(Instance.instance_id, Instance.config_id)
                .where(Instance.instance_id.in_(requested_instances))
                .order_by(Instance.instance_id)
                .execution_options(autoflush=False)
            )
        ).all()
        instance_config_map.update(targeted_rows)
        ordered_configs.update(
            config_id
            for _instance_id, config_id in targeted_rows
            if config_id is not None
        )

    final_config_ids = tuple(sorted(ordered_configs))
    if final_config_ids:
        await db.execute(
            select(LaunchConfig.config_id)
            .where(LaunchConfig.config_id.in_(final_config_ids))
            .order_by(LaunchConfig.config_id)
            .with_for_update(of=LaunchConfig)
            .execution_options(autoflush=False)
        )

    # Config-scoped callers (notably storage/session and server retirement)
    # lock every related Instance only after the LaunchConfig rows are held.
    # The projection itself is non-locking; the explicit LaunchConfig lock
    # fences concurrent FK insertions while the Instance set is discovered.
    if requested_configs:
        config_rows = (
            await db.execute(
                select(Instance.instance_id, Instance.config_id)
                .where(Instance.config_id.in_(requested_configs))
                .order_by(Instance.instance_id)
                .execution_options(autoflush=False)
            )
        ).all()
        instance_config_map.update(config_rows)

    instance_config_ids = tuple(sorted(instance_config_map.items()))
    final_instance_ids = tuple(
        instance_id for instance_id, _config_id in instance_config_ids
    )
    if final_instance_ids:
        await db.execute(
            select(Instance.instance_id)
            .where(Instance.instance_id.in_(final_instance_ids))
            .order_by(Instance.instance_id)
            .with_for_update(of=Instance)
            .execution_options(autoflush=False)
        )
    return LockedLaunchInstanceRows(
        config_ids=final_config_ids,
        instance_ids=final_instance_ids,
        instance_config_ids=instance_config_ids,
    )


async def prepare_instance_terminal_writes(
    db: AsyncSession,
    instance_ids: Iterable[str],
    *,
    config_ids: Iterable[str] = (),
    complete_launch_configs: bool,
) -> LockedLaunchInstanceRows:
    """Fence terminal Instance writes and project their LaunchConfig authority.

    Registry scope is revoked before the Instance mutation. Deletes and fully
    terminal transitions also complete non-failed launch configurations. Both
    changes happen while the LaunchConfig and Instance rows are held in the
    canonical order, replacing the former inverse database triggers.
    """

    locked = await lock_launch_configs_before_instances(
        db,
        config_ids=config_ids,
        instance_ids=instance_ids,
    )
    if not locked.config_ids:
        return locked

    await db.execute(
        update(LaunchConfig)
        .where(
            LaunchConfig.config_id.in_(locked.config_ids),
            LaunchConfig.registry_scope_active.is_(True),
        )
        .values(
            registry_scope_active=False,
            registry_scope_revoked_at=func.coalesce(
                LaunchConfig.registry_scope_revoked_at,
                func.now(),
            ),
        )
        .execution_options(autoflush=False)
    )
    if complete_launch_configs:
        await db.execute(
            update(LaunchConfig)
            .where(
                LaunchConfig.config_id.in_(locked.config_ids),
                LaunchConfig.failed_at.is_(None),
                LaunchConfig.completed_at.is_(None),
            )
            .values(completed_at=func.now())
            .execution_options(autoflush=False)
        )
    return locked
