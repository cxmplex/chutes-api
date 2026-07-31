"""Durable legacy GPU hotplug command identity, delivery, and acknowledgement."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.agent_channel import send_agent_command
from api.database import get_session
from api.gpu_contracts import (
    GpuHotplugCommandAckV1,
    GpuHotplugCommandV1,
    GpuHotplugPayloadV1,
)
from api.gpu_models import GpuHotplugCommand
from api.host.locks import acquire_gpu_lifecycle_lock, assert_gpu_external_work_allowed
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation, canonical_sha256
from api.server.schemas import GpuLegacyMigration, Host


_DISPATCH_LEASE_SECONDS = 90
_RETRY_SECONDS = 30
_MAX_RETRY_SECONDS = 15 * 60
_ALERT_ATTEMPT_COUNT = 10


class GpuHotplugError(ValueError):
    """A hotplug command or acknowledgement differed from durable custody."""


class GpuHotplugGoneError(GpuHotplugError):
    """A known command is terminal or no longer authorized for execution."""

    code = "gpu_hotplug_custody_ended"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _retry_delay(attempt_count: int) -> timedelta:
    exponent = max(0, min(int(attempt_count or 0) - 1, 20))
    return timedelta(seconds=min(_RETRY_SECONDS * (2**exponent), _MAX_RETRY_SECONDS))


def _mark_retry_alert(
    row: GpuHotplugCommand,
    observed_at: datetime,
) -> Optional[dict[str, object]]:
    if int(row.attempt_count or 0) < _ALERT_ATTEMPT_COUNT or row.alerted_at is not None:
        return None
    row.alerted_at = observed_at
    return {
        "command_id": row.command_id,
        "host_id": row.host_id,
        "reservation_id": row.reservation_id,
        "attempt_count": row.attempt_count,
        "next_attempt_at": row.next_attempt_at,
        "last_dispatch_error": row.last_dispatch_error,
    }


def _emit_retry_alert(alert: Optional[dict[str, object]]) -> None:
    if alert is None:
        return
    logger.bind(**alert).error(
        "Durable GPU hotplug command exceeded the retry alert threshold."
    )


def _command_from_row(row: GpuHotplugCommand) -> GpuHotplugCommandV1:
    return GpuHotplugCommandV1(
        command_id=row.command_id,
        host_id=row.host_id,
        host_key_generation=row.host_key_generation,
        host_boot_generation=row.host_boot_generation,
        reservation_id=row.reservation_id,
        reservation_generation=row.reservation_generation,
        claims_sha256=row.claims_sha256,
        allocation_group_id=row.allocation_group_id,
        allocation_group_generation=row.allocation_group_generation,
        process_incarnation=row.process_incarnation,
        stable_server_id=row.stable_server_id,
        migration_id=row.migration_id,
        payload=GpuHotplugPayloadV1.model_validate(row.payload),
        payload_sha256=row.payload_sha256,
    )


def _new_command(
    reservation: GpuLaunchReservation,
) -> GpuHotplugCommandV1:
    if not reservation.legacy_migration_id:
        raise GpuHotplugError("Legacy hotplug requires an exact migration identity.")
    payload = GpuHotplugPayloadV1(
        server_id=reservation.server_id,
        reservation_id=reservation.reservation_id,
        reservation_claims_sha256=reservation.claims_sha256,
        process_incarnation=reservation.process_incarnation,
        legacy_migration_id=reservation.legacy_migration_id,
    )
    payload_sha256 = canonical_sha256(payload)
    identity = {
        "schema": "chutes.gpu-hotplug-command-identity.v1",
        "version": 1,
        "command_type": "hotplug_gpu_legacy",
        "host_id": reservation.host_id,
        "host_key_generation": reservation.host_key_generation,
        "host_boot_generation": reservation.host_boot_generation,
        "reservation_id": reservation.reservation_id,
        "reservation_generation": reservation.reservation_generation,
        "claims_sha256": reservation.claims_sha256,
        "allocation_group_id": reservation.allocation_group_id,
        "allocation_group_generation": reservation.allocation_group_generation,
        "process_incarnation": reservation.process_incarnation,
        "stable_server_id": reservation.server_id,
        "migration_id": reservation.legacy_migration_id,
        "payload_sha256": payload_sha256,
    }
    return GpuHotplugCommandV1(
        command_id=f"gpu-hotplug-{canonical_sha256(identity)}",
        host_id=reservation.host_id,
        host_key_generation=reservation.host_key_generation,
        host_boot_generation=reservation.host_boot_generation,
        reservation_id=reservation.reservation_id,
        reservation_generation=reservation.reservation_generation,
        claims_sha256=reservation.claims_sha256,
        allocation_group_id=reservation.allocation_group_id,
        allocation_group_generation=reservation.allocation_group_generation,
        process_incarnation=reservation.process_incarnation,
        stable_server_id=reservation.server_id,
        migration_id=reservation.legacy_migration_id,
        payload=payload,
        payload_sha256=payload_sha256,
    )


async def require_gpu_hotplug_runtime_ack(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    stable_server_id: str,
) -> None:
    """Require the exact successful durable hotplug ACK before runtime access.

    Registration persists and dispatches a deterministic command, but Redis delivery is
    not custody. Every runtime-token mint and use for a legacy reservation must prove
    that the command and its backend+frontend ACK still match the current reservation.
    """

    if getattr(reservation, "legacy_migration_id", None) is None:
        return
    if (
        reservation.state != "running"
        or reservation.management_mode != "miner"
        or reservation.server_id != stable_server_id
    ):
        raise GpuHotplugError(
            "Legacy GPU runtime access requires the exact running miner reservation."
        )
    expected = _new_command(reservation)
    row = (
        await db.execute(
            select(GpuHotplugCommand).where(
                GpuHotplugCommand.command_id == expected.command_id
            )
        )
    ).scalar_one_or_none()
    group = (
        await db.execute(
            select(GpuAllocationGroup).where(
                GpuAllocationGroup.allocation_group_id
                == reservation.allocation_group_id
            )
        )
    ).scalar_one_or_none()
    if (
        row is None
        or group is None
        or group.state != "running"
        or group.reservation_id != reservation.reservation_id
        or group.generation != reservation.allocation_group_generation
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
    ):
        raise GpuHotplugError(
            "Legacy GPU runtime access requires current hotplug custody."
        )
    try:
        stored = _command_from_row(row)
        ack = GpuHotplugCommandAckV1.model_validate(row.ack)
    except (TypeError, ValueError) as exc:
        raise GpuHotplugError(
            "Legacy GPU hotplug command or ACK is not canonical."
        ) from exc
    if (
        canonical_sha256(stored) != canonical_sha256(expected)
        or row.state != "acked"
        or row.ack_sha256 is None
        or row.acknowledged_at is None
        or ack.state != "acked"
        or ack.command_id != expected.command_id
        or ack.payload_sha256 != expected.payload_sha256
        or not secrets.compare_digest(row.ack_sha256, ack.ack_sha256)
    ):
        raise GpuHotplugError(
            "Legacy GPU runtime access requires the exact successful hotplug ACK."
        )


async def ensure_gpu_hotplug_command(
    db: AsyncSession,
    reservation_id: str,
) -> Optional[GpuHotplugCommandV1]:
    """Persist the deterministic command before Redis transport is used."""

    await acquire_gpu_lifecycle_lock(db)
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise GpuHotplugError("GPU hotplug reservation is unknown.")
    if reservation.legacy_migration_id is None:
        return None
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(
                GpuAllocationGroup.allocation_group_id
                == reservation.allocation_group_id
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    host = (
        await db.execute(
            select(Host).where(Host.host_id == reservation.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == reservation.legacy_migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        group is None
        or host is None
        or migration is None
        or reservation.state != "running"
        or reservation.management_mode != "miner"
        or group.state != "running"
        or group.reservation_id != reservation.reservation_id
        or group.generation != reservation.allocation_group_generation
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
        or host.active_key_generation != reservation.host_key_generation
        or host.boot_generation != reservation.host_boot_generation
        or host.provisioning_state != "ready"
        or migration.host_id != reservation.host_id
        or migration.owner_hotkey != reservation.owner_hotkey
        or migration.target_server_id != reservation.server_id
        or migration.state not in {"ready", "leased", "promoted"}
    ):
        raise GpuHotplugError("Legacy hotplug custody is stale or incomplete.")
    command = _new_command(reservation)
    existing = (
        await db.execute(
            select(GpuHotplugCommand)
            .where(GpuHotplugCommand.command_id == command.command_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        if canonical_sha256(_command_from_row(existing)) != canonical_sha256(command):
            raise GpuHotplugError(
                "GPU hotplug command identity changed canonical bytes."
            )
        return command
    now = _now()
    db.add(
        GpuHotplugCommand(
            command_id=command.command_id,
            host_id=command.host_id,
            host_key_generation=command.host_key_generation,
            host_boot_generation=command.host_boot_generation,
            reservation_id=command.reservation_id,
            reservation_generation=command.reservation_generation,
            claims_sha256=command.claims_sha256,
            allocation_group_id=command.allocation_group_id,
            allocation_group_generation=command.allocation_group_generation,
            process_incarnation=command.process_incarnation,
            stable_server_id=command.stable_server_id,
            migration_id=command.migration_id,
            payload=command.payload.model_dump(mode="json"),
            payload_sha256=command.payload_sha256,
            state="pending",
            attempt_count=0,
            next_attempt_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    await db.flush()
    return command


def _cancel_stale_hotplug_command(row: GpuHotplugCommand, reason: str) -> None:
    """Terminalize a command that lost custody before external dispatch."""

    now = _now()
    row.state = "failed"
    row.dispatch_lease_owner = None
    row.dispatch_lease_expires_at = None
    row.ack = None
    row.ack_sha256 = None
    row.acknowledged_at = None
    row.failure_code = "gpu_hotplug_custody_ended"
    row.failure_reason = reason[:2000]
    row.updated_at = now


async def _locked_hotplug_dispatch_custody(
    db: AsyncSession, row: GpuHotplugCommand
) -> bool:
    """Revalidate the exact current running lineage before each dispatch step."""

    host = (
        await db.execute(
            select(Host).where(Host.host_id == row.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == row.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == row.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == row.migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        return False
    try:
        exact_command = canonical_sha256(_command_from_row(row)) == canonical_sha256(
            _new_command(reservation)
        )
    except (GpuHotplugError, TypeError, ValueError):
        exact_command = False
    return bool(
        exact_command
        and host is not None
        and group is not None
        and migration is not None
        and host.compute_type == "gpu"
        and host.tee_type == "tdx"
        and host.provisioning_state == "ready"
        and host.active_key_generation == row.host_key_generation
        and host.boot_generation == row.host_boot_generation
        and reservation.state == "running"
        and reservation.management_mode == "miner"
        and reservation.host_id == row.host_id == group.host_id
        and reservation.host_key_generation == row.host_key_generation
        and reservation.host_boot_generation == row.host_boot_generation
        and reservation.reservation_generation == row.reservation_generation
        and reservation.claims_sha256 == row.claims_sha256
        and reservation.allocation_group_id == row.allocation_group_id
        and reservation.allocation_group_generation == row.allocation_group_generation
        and reservation.process_incarnation == row.process_incarnation
        and reservation.server_id == row.stable_server_id
        and reservation.legacy_migration_id == row.migration_id
        and group.state == "running"
        and group.management_mode == "miner"
        and group.reservation_id == row.reservation_id
        and group.reservation_generation == row.reservation_generation
        and group.generation == row.allocation_group_generation
        and group.process_incarnation == row.process_incarnation
        and group.reservation_owner == reservation.workload_owner
        and migration.host_id == row.host_id
        and migration.owner_hotkey == reservation.owner_hotkey
        and migration.target_server_id == row.stable_server_id
        and migration.state in {"ready", "leased", "promoted"}
    )


async def dispatch_gpu_hotplug_command(command_id: str) -> bool:
    """Lease and publish the exact durable command; retry always uses the same id."""

    lease_owner = secrets.token_hex(16)
    async with get_session() as db:
        await acquire_gpu_lifecycle_lock(db)
        row = (
            await db.execute(
                select(GpuHotplugCommand)
                .where(GpuHotplugCommand.command_id == command_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise GpuHotplugError("GPU hotplug command is unknown.")
        if row.state in {"acked", "failed"}:
            return False
        now = _now()
        if row.state != "leased" and row.next_attempt_at > now:
            return False
        if (
            row.state == "leased"
            and row.dispatch_lease_expires_at is not None
            and row.dispatch_lease_expires_at > now
        ):
            return False
        if not await _locked_hotplug_dispatch_custody(db, row):
            _cancel_stale_hotplug_command(
                row, "Legacy GPU hotplug custody changed before dispatch lease."
            )
            await db.commit()
            return False
        lease_expires_at = now + timedelta(seconds=_DISPATCH_LEASE_SECONDS)
        row.state = "leased"
        row.dispatch_lease_owner = lease_owner
        row.dispatch_lease_expires_at = lease_expires_at
        # An abandoned lease becomes due exactly when the lease expires. The
        # retry selector treats this timestamp as a projection, not a second
        # independent gate that can strand an expired command.
        row.next_attempt_at = lease_expires_at
        row.attempt_count = int(row.attempt_count or 0) + 1
        row.updated_at = now
        await db.commit()

    # Recheck after the lease commit. Any quarantine/custody transition that won
    # the intervening lifecycle transaction terminalizes the durable command.
    async with get_session() as db:
        await acquire_gpu_lifecycle_lock(db)
        row = (
            await db.execute(
                select(GpuHotplugCommand)
                .where(GpuHotplugCommand.command_id == command_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise GpuHotplugError("GPU hotplug command disappeared after lease.")
        if row.state in {"acked", "failed"}:
            return False
        if row.state != "leased" or row.dispatch_lease_owner != lease_owner:
            raise GpuHotplugError("GPU hotplug dispatch lease changed before send.")
        if not await _locked_hotplug_dispatch_custody(db, row):
            _cancel_stale_hotplug_command(
                row, "Legacy GPU hotplug custody changed after dispatch lease."
            )
            await db.commit()
            return False
        command = _command_from_row(row)
        await db.commit()
        assert_gpu_external_work_allowed(db, "durable legacy GPU hotplug dispatch")

    try:
        await send_agent_command(
            command.host_id,
            "hotplug_gpu_legacy",
            command.model_dump(mode="json", exclude_none=True),
            command_id=command.command_id,
        )
    except Exception as exc:
        retry_alert = None
        async with get_session() as db:
            await acquire_gpu_lifecycle_lock(db)
            row = (
                await db.execute(
                    select(GpuHotplugCommand)
                    .where(GpuHotplugCommand.command_id == command_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                row is not None
                and row.state == "leased"
                and row.dispatch_lease_owner == lease_owner
            ):
                row.state = "dispatched" if row.dispatched_at is not None else "pending"
                row.dispatch_lease_owner = None
                row.dispatch_lease_expires_at = None
                row.updated_at = _now()
                row.next_attempt_at = row.updated_at + _retry_delay(row.attempt_count)
                row.last_dispatch_error = str(exc)[:2000]
                retry_alert = _mark_retry_alert(row, row.updated_at)
                await db.commit()
        _emit_retry_alert(retry_alert)
        raise

    retry_alert = None
    async with get_session() as db:
        await acquire_gpu_lifecycle_lock(db)
        row = (
            await db.execute(
                select(GpuHotplugCommand)
                .where(GpuHotplugCommand.command_id == command_id)
                .with_for_update()
            )
        ).scalar_one()
        if row.state == "acked":
            return True
        if row.state == "failed":
            return False
        if row.state != "leased" or row.dispatch_lease_owner != lease_owner:
            raise GpuHotplugError("GPU hotplug dispatch lease changed before CAS.")
        row.state = "dispatched"
        row.dispatch_lease_owner = None
        row.dispatch_lease_expires_at = None
        row.dispatched_at = _now()
        row.next_attempt_at = row.dispatched_at + _retry_delay(row.attempt_count)
        row.last_dispatch_error = None
        retry_alert = _mark_retry_alert(row, row.dispatched_at)
        row.updated_at = row.dispatched_at
        await db.commit()
    _emit_retry_alert(retry_alert)
    return True


async def retry_due_gpu_hotplug_commands() -> None:
    now = _now()
    async with get_session() as db:
        command_ids = list(
            (
                await db.execute(
                    select(GpuHotplugCommand.command_id)
                    .where(
                        or_(
                            (
                                (GpuHotplugCommand.state == "pending")
                                & (GpuHotplugCommand.next_attempt_at <= now)
                            ),
                            (
                                (GpuHotplugCommand.state == "leased")
                                & (GpuHotplugCommand.dispatch_lease_expires_at <= now)
                            ),
                            (
                                (GpuHotplugCommand.state == "dispatched")
                                & (GpuHotplugCommand.next_attempt_at <= now)
                            ),
                        )
                    )
                    .order_by(
                        GpuHotplugCommand.next_attempt_at,
                        GpuHotplugCommand.created_at,
                    )
                    .limit(100)
                )
            )
            .scalars()
            .all()
        )
    for command_id in command_ids:
        try:
            await dispatch_gpu_hotplug_command(command_id)
        except Exception:
            # The durable row remains retryable with the same identity.
            continue


async def get_gpu_hotplug_command(
    db: AsyncSession,
    host: Host,
    command_id: str,
) -> GpuHotplugCommandV1:
    """Return only an executable command under exact current custody."""

    await acquire_gpu_lifecycle_lock(db)
    row = (
        await db.execute(
            select(GpuHotplugCommand)
            .where(GpuHotplugCommand.command_id == command_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.host_id != host.host_id:
        raise GpuHotplugError("GPU hotplug command is unknown.")
    # An exact successful command/ACK replay precedes mutable custody checks.
    # The L0 journal has already recorded the physical result and must not be
    # made unrecoverable by a later reservation transition.
    if row.state == "acked":
        return _command_from_row(row)
    if row.state == "failed":
        raise GpuHotplugGoneError(
            "GPU hotplug command is terminal and must not be executed."
        )
    current_host = (
        await db.execute(
            select(Host).where(Host.host_id == row.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    authenticated_host_current = bool(
        current_host is not None
        and host.host_id == current_host.host_id
        and host.active_key_generation == current_host.active_key_generation
        and host.boot_generation == current_host.boot_generation
    )
    if not authenticated_host_current or not await _locked_hotplug_dispatch_custody(
        db, row
    ):
        _cancel_stale_hotplug_command(
            row, "Legacy GPU hotplug custody changed before command readback."
        )
        await db.commit()
        raise GpuHotplugGoneError(
            "GPU hotplug command custody ended and must not be executed."
        )
    return _command_from_row(row)


async def record_gpu_hotplug_ack(
    db: AsyncSession,
    host: Host,
    command_id: str,
    ack: GpuHotplugCommandAckV1,
) -> GpuHotplugCommandV1:
    """CAS one exact QMP backend+frontend acknowledgement into durable state."""

    await acquire_gpu_lifecycle_lock(db)
    row = (
        await db.execute(
            select(GpuHotplugCommand)
            .where(GpuHotplugCommand.command_id == command_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.host_id != host.host_id:
        raise GpuHotplugError("GPU hotplug command is unknown to this host.")
    if ack.command_id != row.command_id or ack.payload_sha256 != row.payload_sha256:
        raise GpuHotplugError("GPU hotplug ACK differs from the durable command.")
    # An exact ACK replay is authoritative before any mutable-current-custody check.  The
    # host may have advanced after the first ACK committed while its HTTP response was lost.
    if row.ack_sha256 is not None:
        if not secrets.compare_digest(row.ack_sha256, ack.ack_sha256):
            raise GpuHotplugError("GPU hotplug ACK replay changed canonical bytes.")
        return _command_from_row(row)
    locked_host = (
        await db.execute(
            select(Host).where(Host.host_id == row.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == row.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == row.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    migration = (
        await db.execute(
            select(GpuLegacyMigration)
            .where(GpuLegacyMigration.migration_id == row.migration_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        locked_host is None
        or host.host_id != locked_host.host_id
        or host.active_key_generation != locked_host.active_key_generation
        or host.boot_generation != locked_host.boot_generation
    ):
        raise GpuHotplugError("Authenticated GPU hotplug host is no longer current.")
    custody_current = bool(
        reservation is not None
        and group is not None
        and migration is not None
        and locked_host.provisioning_state == "ready"
        and locked_host.active_key_generation == row.host_key_generation
        and locked_host.boot_generation == row.host_boot_generation
        and reservation.host_id == row.host_id
        and reservation.host_key_generation == row.host_key_generation
        and reservation.host_boot_generation == row.host_boot_generation
        and reservation.reservation_generation == row.reservation_generation
        and reservation.claims_sha256 == row.claims_sha256
        and reservation.process_incarnation == row.process_incarnation
        and reservation.server_id == row.stable_server_id
        and reservation.legacy_migration_id == row.migration_id
        and group.state == "running"
        and group.reservation_id == row.reservation_id
        and group.generation == row.allocation_group_generation
        and group.reservation_generation == row.reservation_generation
        and group.process_incarnation == row.process_incarnation
        and migration.host_id == row.host_id
        and migration.target_server_id == row.stable_server_id
        and migration.migration_id == row.migration_id
        and migration.state in {"ready", "leased", "promoted"}
    )
    if not custody_current and ack.state != "failed":
        raise GpuHotplugError("GPU hotplug custody changed before acknowledgement.")
    if migration is None:
        raise GpuHotplugError(
            "GPU hotplug ACK source identity has no authoritative migration."
        )
    ack_luks_uuids = {
        item.namespace: item.source_identity.luks_uuid for item in ack.objects
    }
    expected_luks_uuids = {
        "storage": migration.storage_luks_uuid,
        "tdx-cache": migration.cache_luks_uuid,
    }
    if ack_luks_uuids != expected_luks_uuids:
        raise GpuHotplugError(
            "GPU hotplug ACK source identity differs from migration custody."
        )
    now = _now()
    row.ack = ack.model_dump(mode="json", exclude_none=True)
    row.ack_sha256 = ack.ack_sha256
    row.acknowledged_at = now
    row.dispatch_lease_owner = None
    row.dispatch_lease_expires_at = None
    row.state = ack.state
    row.failure_code = ack.failure_code
    row.failure_reason = ack.failure_reason
    row.updated_at = now
    if ack.state == "failed" and custody_current:
        from api.host.gpu_allocations import request_gpu_lifecycle_fence

        await request_gpu_lifecycle_fence(
            db,
            reservation.reservation_id,
            code=ack.failure_code or "gpu_hotplug_failed",
            reason=ack.failure_reason or "Legacy GPU hotplug failed.",
            operation_type="normal_delete",
            metadata={"hotplug_command_id": row.command_id},
        )
    await db.flush()
    return _command_from_row(row)
