"""Authoritative two-phase GPU physical lifecycle transitions."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import generate_uuid
from api.gpu_contracts import (
    GpuLifecycleOperationV1,
    GpuLocalReleaseAckV1,
    GpuPhysicalResultV1,
    GpuRecoveryAuthorizationEnvelopeV1,
    GpuRecoveryEventV1,
    GpuResetReceiptV1,
)
from api.gpu_models import (
    GpuLifecycleOperation,
    GpuRecoveryAuthorization,
    GpuRecoveryEvent,
)
from api.host.gpu_allocations import (
    _quarantine_group,
    _quarantine_reservation,
    _retire_gpu_runtime_lineage,
    _validate_row_claims,
)
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    GpuRecoveryAuthorizeRequestV1,
    canonical_sha256,
)
from api.server.schemas import Host


_RESERVATION_BACKED = {
    "pre_slot_claim_quarantine",
    "launch_rollback",
    "release_rollover",
    "normal_delete",
    "forced_dead_guest_recovery",
}
_NO_RESERVATION = {"pre_slot_claim_quarantine", "ownerless_group_recovery"}
_INTENT_OUTPUT_FIELDS = {
    "group_state",
    "physical_result_sha256",
    "result_outcome",
    "receipt_id",
    "receipt_sha256",
    "local_release_ack_sha256",
    "failure_code",
    "failure_reason",
    "created_at",
    "updated_at",
    "finalized_at",
}


class GpuLifecycleError(ValueError):
    """An authenticated lifecycle transition did not match durable custody."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _intent_document(intent: GpuLifecycleOperationV1) -> dict:
    return intent.model_dump(
        mode="json",
        exclude_none=True,
        exclude=_INTENT_OUTPUT_FIELDS,
    )


def _result_document(result: GpuPhysicalResultV1) -> dict:
    return result.model_dump(mode="json", exclude_none=True)


def _ack_document(ack: GpuLocalReleaseAckV1) -> dict:
    return ack.model_dump(mode="json", exclude_none=True)


def _assert_authenticated_host(
    host: Host,
    row: GpuLifecycleOperation | GpuLifecycleOperationV1,
    *,
    allow_reboot_resume: bool = False,
) -> None:
    boot_matches = host.boot_generation == row.host_boot_generation
    if (
        allow_reboot_resume
        and isinstance(row, GpuLifecycleOperation)
        and row.operation_type
        not in {"ownerless_group_recovery", "forced_dead_guest_recovery"}
    ):
        boot_matches = int(host.boot_generation or 0) >= int(
            row.host_boot_generation or 0
        )
    if (
        host.host_id != row.host_id
        or host.active_key_generation != row.host_key_generation
        or not boot_matches
    ):
        raise GpuLifecycleError(
            "GPU lifecycle operation belongs to another host key or boot generation."
        )


def _assert_intent_input(intent: GpuLifecycleOperationV1) -> None:
    if intent.phase != "intent" or any(
        getattr(intent, field) is not None for field in _INTENT_OUTPUT_FIELDS
    ):
        raise GpuLifecycleError("GPU lifecycle creation accepts an intent only.")


def _assert_group_snapshot(
    host: Host,
    group: GpuAllocationGroup,
    intent: GpuLifecycleOperationV1,
) -> None:
    if (
        host.host_id != intent.host_id
        or host.compute_type != "gpu"
        or host.active_key_generation != intent.host_key_generation
        or host.boot_generation != intent.host_boot_generation
        or group.host_id != intent.host_id
        or group.host_key_generation != intent.host_key_generation
        or (
            intent.operation_type != "forced_dead_guest_recovery"
            and group.host_boot_generation != intent.host_boot_generation
        )
        or group.generation != intent.allocation_group_generation
        or group.topology_fingerprint != intent.topology_fingerprint
        or list(group.gpu_bdfs) != intent.gpu_bdfs
        or list(group.gpu_uuids) != intent.gpu_uuids
    ):
        raise GpuLifecycleError(
            "GPU lifecycle intent differs from current host inventory."
        )


def _assert_reservation_snapshot(
    group: GpuAllocationGroup,
    reservation: GpuLaunchReservation,
    intent: GpuLifecycleOperationV1,
    *,
    recovery_prior_lineage: tuple[int, int] | None = None,
) -> None:
    _validate_row_claims(reservation)
    if (
        intent.operation_type not in _RESERVATION_BACKED
        or reservation.reservation_id != intent.reservation_id
        or reservation.host_id != intent.host_id
        or (
            intent.operation_type != "forced_dead_guest_recovery"
            and reservation.host_key_generation != intent.host_key_generation
        )
        or (
            intent.operation_type != "forced_dead_guest_recovery"
            and reservation.host_boot_generation != intent.host_boot_generation
        )
        or (
            intent.operation_type == "forced_dead_guest_recovery"
            and (
                recovery_prior_lineage is None
                or reservation.host_key_generation != recovery_prior_lineage[0]
                or reservation.host_boot_generation != recovery_prior_lineage[1]
            )
        )
        or reservation.allocation_group_id != intent.allocation_group_id
        or reservation.allocation_group_generation != intent.allocation_group_generation
        or reservation.reservation_generation != intent.reservation_generation
        or reservation.claims_sha256 != intent.claims_sha256
        or reservation.process_incarnation != intent.process_incarnation
        or reservation.topology_fingerprint != intent.topology_fingerprint
        or list(reservation.gpu_bdfs) != intent.gpu_bdfs
        or list(reservation.gpu_uuids) != intent.gpu_uuids
        or reservation.owner_hotkey != intent.owner_hotkey
        or reservation.server_id != intent.stable_server_id
        or reservation.management_mode != intent.management_mode
        or reservation.legacy_migration_id != intent.migration_id
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
        or group.reservation_owner != reservation.workload_owner
        or group.management_mode != reservation.management_mode
    ):
        raise GpuLifecycleError(
            "GPU lifecycle intent differs from reservation custody."
        )


def _assert_ownerless_snapshot(
    host: Host,
    group: GpuAllocationGroup,
    intent: GpuLifecycleOperationV1,
) -> None:
    eligible_states = (
        {"available", "discovered", "quarantined", "resetting"}
        if intent.operation_type == "pre_slot_claim_quarantine"
        else {"quarantined", "resetting"}
    )
    if (
        intent.operation_type not in _NO_RESERVATION
        or intent.owner_hotkey != host.miner_hotkey
        or intent.stable_server_id is not None
        or intent.management_mode is not None
        or intent.migration_id is not None
        or group.reservation_id is not None
        or group.reservation_owner is not None
        or group.management_mode is not None
        or group.process_incarnation is not None
        or group.state not in eligible_states
    ):
        raise GpuLifecycleError(
            "Ownerless GPU lifecycle intent has conflicting custody."
        )


async def _locked_host(
    db: AsyncSession,
    authenticated_host: Host,
) -> Host:
    host = (
        await db.execute(
            select(Host)
            .where(Host.host_id == authenticated_host.host_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if host is None:
        raise GpuLifecycleError("GPU lifecycle host is unknown.")
    return host


async def _locked_authenticated_host(
    db: AsyncSession,
    authenticated_host: Host,
    row: GpuLifecycleOperation | GpuLifecycleOperationV1,
    *,
    allow_reboot_resume: bool = False,
) -> Host:
    current = await _locked_host(db, authenticated_host)
    if (
        authenticated_host.host_id != current.host_id
        or authenticated_host.active_key_generation != current.active_key_generation
        or authenticated_host.boot_generation != current.boot_generation
    ):
        raise GpuLifecycleError(
            "Authenticated GPU host identity changed before lifecycle publication."
        )
    _assert_authenticated_host(
        current,
        row,
        allow_reboot_resume=allow_reboot_resume,
    )
    return current


async def _locked_group(
    db: AsyncSession,
    group_id: str,
) -> GpuAllocationGroup:
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if group is None:
        raise GpuLifecycleError("GPU lifecycle allocation group is unknown.")
    return group


async def _locked_reservation(
    db: AsyncSession,
    reservation_id: Optional[str],
) -> Optional[GpuLaunchReservation]:
    if reservation_id is None:
        return None
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise GpuLifecycleError("GPU lifecycle reservation is unknown.")
    return reservation


async def _locked_inventory_report(
    db: AsyncSession,
    report_id: str,
) -> GpuInventoryReport:
    report = (
        await db.execute(
            select(GpuInventoryReport)
            .where(GpuInventoryReport.report_id == report_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if report is None:
        raise GpuLifecycleError("GPU recovery inventory report is unknown.")
    return report


def _assert_recovery_inventory(
    host: Host,
    group: GpuAllocationGroup,
    report: GpuInventoryReport,
    claims: GpuInventoryReportV1,
) -> None:
    matching_groups = [
        item
        for item in claims.groups
        if item.topology_fingerprint == group.topology_fingerprint
        and [device.bdf for device in item.devices] == list(group.gpu_bdfs)
        and [device.uuid for device in item.devices] == list(group.gpu_uuids)
        and [device.attestation_certificate_sha256 for device in item.devices]
        == list(group.gpu_attestation_certificate_sha256s)
    ]
    if (
        len(matching_groups) != 1
        or host.compute_type != "gpu"
        or not host.miner_hotkey
        or group.state != "quarantined"
        or report.reconciliation_status not in {"accepted", "quarantined"}
        or report.claims_sha256 != canonical_sha256(claims)
        or report.host_id != host.host_id
        or report.host_key_generation != host.active_key_generation
        or report.host_boot_generation != host.boot_generation
        or claims.report_id != report.report_id
        or claims.host_id != host.host_id
        or claims.host_key_generation != host.active_key_generation
        or claims.host_boot_generation != host.boot_generation
        or claims.host_boot_id != host.boot_id
        or claims.gpu_release_id != group.gpu_release_id
        or claims.profile_contract_sha256 != group.profile_contract_sha256
        or report.topology_fingerprint != group.topology_fingerprint
    ):
        raise GpuLifecycleError(
            "GPU recovery requires exactly one matching current host-signed inventory group."
        )


async def _recovery_authorization_envelope(
    db: AsyncSession,
    authorization: GpuRecoveryAuthorization,
) -> GpuRecoveryAuthorizationEnvelopeV1:
    operation = await db.get(GpuLifecycleOperation, authorization.operation_id)
    if operation is None:
        raise GpuLifecycleError("GPU recovery authorization lost its lifecycle intent.")
    return GpuRecoveryAuthorizationEnvelopeV1(
        authorization_id=authorization.authorization_id,
        operation=GpuLifecycleOperationV1.model_validate(operation.intent),
        inventory_report_id=authorization.inventory_report_id,
        inventory_report_sha256=authorization.inventory_report_sha256,
        recovery_nonce=authorization.recovery_nonce,
        expires_at=authorization.expires_at,
    )


async def _append_recovery_event(
    db: AsyncSession,
    row: GpuLifecycleOperation,
    state: str,
    *,
    occurred_at: Optional[datetime] = None,
) -> None:
    authorization = (
        await db.execute(
            select(GpuRecoveryAuthorization).where(
                GpuRecoveryAuthorization.operation_id == row.operation_id
            )
        )
    ).scalar_one_or_none()
    if authorization is None:
        return
    occurred_at = occurred_at or _now()
    source_reader_result = None
    if row.physical_result is not None:
        source_reader_result = row.physical_result.get("source_reader_result")
    event_id = f"gpu-recovery-event-{generate_uuid()}"
    projection = GpuRecoveryEventV1(
        event_id=event_id,
        authorization_id=authorization.authorization_id,
        operation_id=row.operation_id,
        state=state,
        reset_result_sha256=row.physical_result_sha256,
        source_reader_result_sha256=(
            canonical_sha256(source_reader_result)
            if source_reader_result is not None
            else None
        ),
        receipt_id=row.receipt_id,
        receipt_sha256=row.receipt_sha256,
        local_release_ack_sha256=row.local_release_ack_sha256,
        completed_at=occurred_at if state == "completed" else None,
    )
    expected = {
        "authorization_id": projection.authorization_id,
        "operation_id": projection.operation_id,
        "state": projection.state,
        "reset_result": row.physical_result,
        "reset_result_sha256": projection.reset_result_sha256,
        "source_reader_result": source_reader_result,
        "source_reader_result_sha256": projection.source_reader_result_sha256,
        "receipt_id": projection.receipt_id,
        "receipt_sha256": projection.receipt_sha256,
        "local_release_ack": row.local_release_ack,
        "local_release_ack_sha256": projection.local_release_ack_sha256,
        "completed_at": projection.completed_at,
    }
    existing = (
        await db.execute(
            select(GpuRecoveryEvent).where(
                GpuRecoveryEvent.operation_id == row.operation_id,
                GpuRecoveryEvent.state == state,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        actual = {key: getattr(existing, key) for key in expected}
        if canonical_sha256(actual) != canonical_sha256(expected):
            raise GpuLifecycleError("GPU recovery event replay changed audit bytes.")
        return
    db.add(
        GpuRecoveryEvent(
            event_id=projection.event_id,
            created_at=occurred_at,
            updated_at=occurred_at,
            **expected,
        )
    )
    await db.flush()


async def _recovery_event_exists(
    db: AsyncSession,
    operation_id: str,
    state: str,
) -> bool:
    return (
        await db.execute(
            select(GpuRecoveryEvent.event_id).where(
                GpuRecoveryEvent.operation_id == operation_id,
                GpuRecoveryEvent.state == state,
            )
        )
    ).scalar_one_or_none() is not None


async def _revoke_expired_unstarted_recovery(
    db: AsyncSession,
    authorization: GpuRecoveryAuthorization,
    group: GpuAllocationGroup,
    now: datetime,
) -> None:
    row = await _locked_operation(db, authorization.operation_id)
    if await _recovery_event_exists(db, row.operation_id, "started"):
        raise GpuLifecycleError(
            "A started GPU recovery cannot be replaced by a new authorization."
        )
    if not await _recovery_event_exists(db, row.operation_id, "revoked"):
        await _append_recovery_event(db, row, "revoked", occurred_at=now)
    if row.phase == "intent":
        row.phase = "quarantined"
        row.reporting_state = "quarantined"
        row.failure_code = "gpu_recovery_authorization_expired"
        row.failure_reason = "GPU recovery authorization expired before presentation."
        row.finalized_at = now
        row.updated_at = now
    elif row.phase != "quarantined":
        raise GpuLifecycleError(
            "Expired GPU recovery authorization has already changed physical state."
        )
    if group.recovery_authorization_id == authorization.authorization_id:
        group.recovery_authorization_id = None
        group.recovery_report_id = None
        group.recovery_nonce_hash = None
        group.recovery_authorized_by = None
        group.recovery_authorized_at = None
        group.recovery_started_at = None
        group.recovery_completed_at = None
        group.updated_at = now
    await db.flush()


async def authorize_gpu_recovery(
    db: AsyncSession,
    allocation_group_id: str,
    request: GpuRecoveryAuthorizeRequestV1,
    *,
    authorized_by: str,
) -> GpuRecoveryAuthorizationEnvelopeV1:
    """Bind one immutable recovery authorization to current inventory and custody."""

    await acquire_gpu_lifecycle_lock(db)
    group = await _locked_group(db, allocation_group_id)
    host = (
        await db.execute(
            select(Host).where(Host.host_id == group.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    if host is None:
        raise GpuLifecycleError("GPU recovery host is unknown.")
    report = await _locked_inventory_report(db, request.report_id)
    try:
        report_claims = GpuInventoryReportV1.model_validate(report.claims)
    except ValueError as exc:
        raise GpuLifecycleError("GPU recovery inventory report is malformed.") from exc
    _assert_recovery_inventory(host, group, report, report_claims)

    now = _now()
    existing = (
        (
            await db.execute(
                select(GpuRecoveryAuthorization)
                .where(
                    GpuRecoveryAuthorization.allocation_group_id == allocation_group_id,
                    GpuRecoveryAuthorization.allocation_group_generation
                    == group.generation,
                )
                .order_by(GpuRecoveryAuthorization.issued_at.desc())
                .with_for_update()
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        started = await _recovery_event_exists(db, existing.operation_id, "started")
        revoked = await _recovery_event_exists(db, existing.operation_id, "revoked")
        if not revoked and (existing.expires_at > now or started):
            if existing.inventory_report_id != request.report_id:
                raise GpuLifecycleError(
                    "GPU recovery generation already has an authorization for another report."
                )
            return await _recovery_authorization_envelope(db, existing)
        if not revoked:
            await _revoke_expired_unstarted_recovery(db, existing, group, now)

    prior_host_key_generation = group.host_key_generation
    prior_host_boot_generation = group.host_boot_generation
    reservation = await _locked_reservation(db, group.reservation_id)
    if reservation is None:
        if any(
            value is not None
            for value in (
                group.reservation_owner,
                group.management_mode,
                group.process_incarnation,
            )
        ):
            raise GpuLifecycleError("Ownerless GPU recovery has conflicting custody.")
        operation_type = "ownerless_group_recovery"
        owner_hotkey = host.miner_hotkey
        stable_server_id = None
        management_mode = None
        migration_id = None
    else:
        _validate_row_claims(reservation)
        if (
            reservation.state != "quarantined"
            or reservation.host_id != host.host_id
            or reservation.host_key_generation != prior_host_key_generation
            or reservation.host_boot_generation != prior_host_boot_generation
            or reservation.allocation_group_id != group.allocation_group_id
            or reservation.allocation_group_generation != group.generation
            or group.reservation_owner != reservation.workload_owner
            or group.reservation_generation != reservation.reservation_generation
            or group.process_incarnation != reservation.process_incarnation
            or group.management_mode != reservation.management_mode
        ):
            raise GpuLifecycleError(
                "Forced GPU recovery custody is stale or incomplete."
            )
        if reservation.management_mode != "miner" or not reservation.server_id:
            raise GpuLifecycleError(
                "Forced dead-guest recovery is supported only for exact miner custody."
            )
        operation_type = "forced_dead_guest_recovery"
        owner_hotkey = reservation.owner_hotkey
        stable_server_id = reservation.server_id
        management_mode = reservation.management_mode
        migration_id = reservation.legacy_migration_id

    # The current signed inventory proves the same exact quarantined fabric under
    # the currently authenticated host. Preserve prior custody immutably below,
    # then move only the unavailable group projection to current key/boot lineage.
    group.host_key_generation = host.active_key_generation
    group.host_boot_generation = host.boot_generation
    group.updated_at = now

    authorization_id = f"gpu-recovery-{generate_uuid()}"
    operation_id = generate_uuid()
    recovery_nonce = secrets.token_hex(32)
    expires_at = now + timedelta(minutes=15)
    intent = GpuLifecycleOperationV1(
        operation_id=operation_id,
        operation_type=operation_type,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        host_boot_generation=host.boot_generation,
        allocation_group_id=group.allocation_group_id,
        allocation_group_generation=group.generation,
        reservation_id=reservation.reservation_id if reservation is not None else None,
        reservation_generation=(
            reservation.reservation_generation if reservation is not None else None
        ),
        claims_sha256=reservation.claims_sha256 if reservation is not None else None,
        process_incarnation=(
            reservation.process_incarnation if reservation is not None else None
        ),
        topology_fingerprint=group.topology_fingerprint,
        gpu_bdfs=list(group.gpu_bdfs),
        gpu_uuids=list(group.gpu_uuids),
        owner_hotkey=owner_hotkey,
        stable_server_id=stable_server_id,
        management_mode=management_mode,
        migration_id=migration_id,
        recovery_authorization_id=authorization_id,
    )

    group.recovery_authorization_id = authorization_id
    group.recovery_report_id = report.report_id
    group.recovery_nonce_hash = hashlib.sha256(
        recovery_nonce.encode("ascii")
    ).hexdigest()
    group.recovery_authorized_by = authorized_by
    group.recovery_authorized_at = now
    group.recovery_started_at = None
    group.recovery_completed_at = None
    await create_gpu_lifecycle_operation(
        db,
        host,
        intent,
        authorized_recovery=True,
        recovery_prior_lineage=(
            prior_host_key_generation,
            prior_host_boot_generation,
        ),
    )

    authorization = GpuRecoveryAuthorization(
        authorization_id=authorization_id,
        operation_id=operation_id,
        host_id=host.host_id,
        host_key_generation=host.active_key_generation,
        host_boot_generation=host.boot_generation,
        prior_host_key_generation=prior_host_key_generation,
        prior_host_boot_generation=prior_host_boot_generation,
        inventory_report_id=report.report_id,
        inventory_report_sha256=report.claims_sha256,
        reservation_id=reservation.reservation_id if reservation is not None else None,
        reservation_generation=(
            reservation.reservation_generation if reservation is not None else None
        ),
        claims_sha256=reservation.claims_sha256 if reservation is not None else None,
        process_incarnation=(
            reservation.process_incarnation if reservation is not None else None
        ),
        allocation_group_id=group.allocation_group_id,
        allocation_group_generation=group.generation,
        topology_fingerprint=group.topology_fingerprint,
        gpu_bdfs=list(group.gpu_bdfs),
        gpu_uuids=list(group.gpu_uuids),
        owner_hotkey=owner_hotkey,
        stable_server_id=stable_server_id,
        management_mode=management_mode,
        migration_id=migration_id,
        recovery_nonce=recovery_nonce,
        recovery_nonce_hash=hashlib.sha256(recovery_nonce.encode("ascii")).hexdigest(),
        state="issued",
        authorized_by=authorized_by,
        issued_at=now,
        expires_at=expires_at,
    )
    db.add(authorization)
    authorized_event = GpuRecoveryEventV1(
        event_id=f"gpu-recovery-event-{generate_uuid()}",
        authorization_id=authorization_id,
        operation_id=operation_id,
        state="authorized",
    )
    db.add(
        GpuRecoveryEvent(
            event_id=authorized_event.event_id,
            authorization_id=authorized_event.authorization_id,
            operation_id=authorized_event.operation_id,
            state=authorized_event.state,
            created_at=now,
            updated_at=now,
        )
    )
    await db.flush()
    return GpuRecoveryAuthorizationEnvelopeV1(
        authorization_id=authorization_id,
        operation=intent,
        inventory_report_id=report.report_id,
        inventory_report_sha256=report.claims_sha256,
        recovery_nonce=recovery_nonce,
        expires_at=expires_at,
    )


async def _locked_recovery_authorization(
    db: AsyncSession,
    row: GpuLifecycleOperation,
) -> GpuRecoveryAuthorization:
    authorization = (
        await db.execute(
            select(GpuRecoveryAuthorization)
            .where(
                GpuRecoveryAuthorization.operation_id == row.operation_id,
                GpuRecoveryAuthorization.authorization_id
                == row.recovery_authorization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if authorization is None:
        raise GpuLifecycleError("GPU recovery operation has no exact authorization.")
    return authorization


async def _validate_recovery_authorization(
    db: AsyncSession,
    authenticated_host: Host,
    row: GpuLifecycleOperation,
    *,
    envelope: Optional[GpuRecoveryAuthorizationEnvelopeV1] = None,
    require_started: bool = False,
) -> GpuRecoveryAuthorization:
    if row.operation_type not in {
        "ownerless_group_recovery",
        "forced_dead_guest_recovery",
    }:
        raise GpuLifecycleError("Lifecycle operation is not a recovery operation.")
    authorization = await _locked_recovery_authorization(db, row)
    now = _now()
    revoked = (
        await db.execute(
            select(GpuRecoveryEvent.event_id).where(
                GpuRecoveryEvent.operation_id == row.operation_id,
                GpuRecoveryEvent.state == "revoked",
            )
        )
    ).scalar_one_or_none()
    if authorization.state != "issued" or revoked is not None:
        raise GpuLifecycleError("GPU recovery authorization is revoked.")
    started = (
        await db.execute(
            select(GpuRecoveryEvent.event_id).where(
                GpuRecoveryEvent.operation_id == row.operation_id,
                GpuRecoveryEvent.state == "started",
            )
        )
    ).scalar_one_or_none()
    if authorization.expires_at <= now and started is None:
        raise GpuLifecycleError("GPU recovery authorization expired before start.")
    group = await _locked_group(db, row.allocation_group_id)
    report = await _locked_inventory_report(db, authorization.inventory_report_id)
    if (
        authenticated_host.host_id != authorization.host_id
        or authenticated_host.active_key_generation != authorization.host_key_generation
        or authenticated_host.boot_generation != authorization.host_boot_generation
        or row.host_id != authorization.host_id
        or row.host_key_generation != authorization.host_key_generation
        or row.host_boot_generation != authorization.host_boot_generation
        or row.allocation_group_id != authorization.allocation_group_id
        or row.allocation_group_generation != authorization.allocation_group_generation
        or row.reservation_id != authorization.reservation_id
        or row.reservation_generation != authorization.reservation_generation
        or row.claims_sha256 != authorization.claims_sha256
        or row.process_incarnation != authorization.process_incarnation
        or row.topology_fingerprint != authorization.topology_fingerprint
        or row.gpu_bdfs != authorization.gpu_bdfs
        or row.gpu_uuids != authorization.gpu_uuids
        or row.owner_hotkey != authorization.owner_hotkey
        or row.stable_server_id != authorization.stable_server_id
        or row.management_mode != authorization.management_mode
        or row.migration_id != authorization.migration_id
        or group.generation != authorization.allocation_group_generation
        or group.host_key_generation != authorization.host_key_generation
        or group.host_boot_generation != authorization.host_boot_generation
        or group.recovery_report_id != authorization.inventory_report_id
        or report.host_id != authorization.host_id
        or report.host_key_generation != authorization.host_key_generation
        or report.host_boot_generation != authorization.host_boot_generation
        or report.claims_sha256 != authorization.inventory_report_sha256
    ):
        raise GpuLifecycleError("GPU recovery authorization lineage changed.")
    if authorization.reservation_id is not None:
        reservation = await _locked_reservation(db, authorization.reservation_id)
        if (
            reservation is None
            or reservation.host_key_generation
            != authorization.prior_host_key_generation
            or reservation.host_boot_generation
            != authorization.prior_host_boot_generation
            or reservation.reservation_generation
            != authorization.reservation_generation
            or reservation.claims_sha256 != authorization.claims_sha256
            or reservation.process_incarnation != authorization.process_incarnation
        ):
            raise GpuLifecycleError("GPU recovery prior reservation custody changed.")
    if envelope is not None:
        expected = await _recovery_authorization_envelope(db, authorization)
        if canonical_sha256(envelope) != canonical_sha256(expected):
            raise GpuLifecycleError("GPU recovery envelope changed canonical bytes.")
        if not secrets.compare_digest(
            hashlib.sha256(envelope.recovery_nonce.encode("ascii")).hexdigest(),
            authorization.recovery_nonce_hash,
        ):
            raise GpuLifecycleError("GPU recovery nonce is invalid.")
    if require_started and started is None:
        raise GpuLifecycleError("GPU recovery has not presented its authorization.")
    return authorization


async def start_gpu_recovery(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    envelope: GpuRecoveryAuthorizationEnvelopeV1,
) -> GpuLifecycleOperationV1:
    """Present the immutable authorization and nonce before physical recovery."""

    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    current_host = await _locked_authenticated_host(db, authenticated_host, row)
    if envelope.operation.operation_id != operation_id:
        raise GpuLifecycleError("GPU recovery envelope targets another operation.")
    authorization = await _validate_recovery_authorization(
        db,
        current_host,
        row,
        envelope=envelope,
    )
    if row.phase != "intent":
        raise GpuLifecycleError("GPU recovery can start only from durable intent.")
    group = await _locked_group(db, row.allocation_group_id)
    reservation = await _locked_reservation(db, row.reservation_id)
    started_event = (
        await db.execute(
            select(GpuRecoveryEvent.event_id).where(
                GpuRecoveryEvent.operation_id == row.operation_id,
                GpuRecoveryEvent.state == "started",
            )
        )
    ).scalar_one_or_none()
    exact_started_replay = bool(
        started_event is not None
        and row.phase == "intent"
        and group.state == "resetting"
        and group.recovery_authorization_id == authorization.authorization_id
        and group.recovery_report_id == authorization.inventory_report_id
        and group.recovery_started_at is not None
        and (
            (
                reservation is None
                and group.reservation_id is None
                and group.process_incarnation is None
            )
            or (
                reservation is not None
                and reservation.state == "resetting"
                and group.reservation_id == reservation.reservation_id
                and group.process_incarnation == reservation.process_incarnation
            )
        )
    )
    if exact_started_replay:
        return await gpu_lifecycle_operation_response(db, row, group=group)
    if (
        group.state != "quarantined"
        or group.recovery_authorization_id != authorization.authorization_id
        or group.recovery_report_id != authorization.inventory_report_id
    ):
        raise GpuLifecycleError(
            "GPU recovery group left authorized quarantine custody."
        )
    now = _now()
    if reservation is not None:
        if (
            reservation.state != "quarantined"
            or group.reservation_id != reservation.reservation_id
            or group.process_incarnation != reservation.process_incarnation
        ):
            raise GpuLifecycleError(
                "GPU recovery reservation custody changed before start."
            )
        reservation.state = "resetting"
        reservation.teardown_started_at = reservation.teardown_started_at or now
        reservation.quarantined_at = None
        reservation.failure_code = None
        reservation.failure_reason = None
        reservation.failure_metadata = None
    elif any(
        value is not None
        for value in (
            group.reservation_id,
            group.reservation_owner,
            group.management_mode,
            group.process_incarnation,
        )
    ):
        raise GpuLifecycleError("Ownerless GPU recovery acquired conflicting custody.")
    group.state = "resetting"
    group.resetting_at = now
    group.quarantined_at = None
    group.failure_code = None
    group.failure_reason = None
    group.failure_metadata = None
    group.recovery_started_at = now
    group.updated_at = now
    await _append_recovery_event(db, row, "started", occurred_at=now)
    return await gpu_lifecycle_operation_response(db, row, group=group)


def _derived_reservation_operation_type(
    reservation: GpuLaunchReservation,
) -> str:
    """Derive the only legal producer type from validator-owned durable state."""

    if (
        reservation.failure_code
        in {
            "launch_active_release_changed",
            "reservation_active_release_changed",
        }
        or reservation.teardown_reason == "GPU release rolled"
    ):
        return "release_rollover"
    teardown_requested = reservation.teardown_requested_at is not None
    if (
        reservation.state == "reserved"
        and reservation.claimed_at is None
        and teardown_requested
        and reservation.launch_command_id is not None
        and reservation.launch_dispatched_at is not None
    ):
        return "pre_slot_claim_quarantine"
    if reservation.state in {"claimed", "launching"} and teardown_requested:
        return "launch_rollback"
    if reservation.state == "running" and teardown_requested:
        return "normal_delete"
    raise GpuLifecycleError(
        "GPU lifecycle producer type has no matching server-side custody cause."
    )


async def create_gpu_lifecycle_operation(
    db: AsyncSession,
    authenticated_host: Host,
    intent: GpuLifecycleOperationV1,
    *,
    authorized_recovery: bool = False,
    recovery_prior_lineage: tuple[int, int] | None = None,
) -> GpuLifecycleOperationV1:
    """Persist reset intent before any physical ownership mutation."""

    is_recovery = intent.operation_type in {
        "ownerless_group_recovery",
        "forced_dead_guest_recovery",
    }
    if is_recovery and not authorized_recovery:
        raise GpuLifecycleError(
            "GPU recovery intents may only be created by an administrator authorization."
        )
    if is_recovery and (
        recovery_prior_lineage is None or min(recovery_prior_lineage) < 1
    ):
        raise GpuLifecycleError(
            "GPU recovery intent is missing immutable prior host lineage."
        )
    if not is_recovery and recovery_prior_lineage is not None:
        raise GpuLifecycleError(
            "Ordinary lifecycle intent cannot carry recovery prior lineage."
        )
    _assert_intent_input(intent)
    intent_document = _intent_document(intent)
    intent_sha256 = canonical_sha256(intent_document)
    await acquire_gpu_lifecycle_lock(db)
    existing = (
        await db.execute(
            select(GpuLifecycleOperation)
            .where(GpuLifecycleOperation.operation_id == intent.operation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        await _locked_authenticated_host(
            db, authenticated_host, existing, allow_reboot_resume=True
        )
        if not secrets.compare_digest(existing.intent_sha256, intent_sha256):
            raise GpuLifecycleError(
                "GPU lifecycle operation id was reused with new intent."
            )
        return await gpu_lifecycle_operation_response(db, existing)

    host = await _locked_authenticated_host(db, authenticated_host, intent)
    group = await _locked_group(db, intent.allocation_group_id)
    _assert_group_snapshot(host, group, intent)
    active = (
        await db.execute(
            select(GpuLifecycleOperation.operation_id).where(
                GpuLifecycleOperation.allocation_group_id == intent.allocation_group_id,
                GpuLifecycleOperation.allocation_group_generation
                == intent.allocation_group_generation,
                GpuLifecycleOperation.phase.notin_(("finalized", "quarantined")),
            )
        )
    ).scalar_one_or_none()
    if active is not None:
        raise GpuLifecycleError(
            f"GPU group generation already has lifecycle operation {active}."
        )

    reservation = await _locked_reservation(db, intent.reservation_id)
    if reservation is None:
        _assert_ownerless_snapshot(host, group, intent)
    else:
        _assert_reservation_snapshot(
            group,
            reservation,
            intent,
            recovery_prior_lineage=recovery_prior_lineage,
        )
        if not is_recovery:
            expected_operation_type = _derived_reservation_operation_type(reservation)
            if intent.operation_type != expected_operation_type:
                raise GpuLifecycleError(
                    "GPU lifecycle operation type differs from server-side custody state."
                )

    now = _now()
    row = GpuLifecycleOperation(
        operation_id=intent.operation_id,
        operation_type=intent.operation_type,
        phase="intent",
        host_id=intent.host_id,
        host_key_generation=intent.host_key_generation,
        host_boot_generation=intent.host_boot_generation,
        allocation_group_id=intent.allocation_group_id,
        allocation_group_generation=intent.allocation_group_generation,
        reservation_id=intent.reservation_id,
        reservation_generation=intent.reservation_generation,
        claims_sha256=intent.claims_sha256,
        process_incarnation=intent.process_incarnation,
        topology_fingerprint=intent.topology_fingerprint,
        gpu_bdfs=list(intent.gpu_bdfs),
        gpu_uuids=list(intent.gpu_uuids),
        owner_hotkey=intent.owner_hotkey,
        stable_server_id=intent.stable_server_id,
        management_mode=intent.management_mode,
        migration_id=intent.migration_id,
        recovery_authorization_id=intent.recovery_authorization_id,
        intent=intent_document,
        intent_sha256=intent_sha256,
        reporting_state="pending",
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    if not is_recovery:
        if reservation is not None:
            reservation.state = "resetting"
            reservation.teardown_started_at = reservation.teardown_started_at or now
            reservation.quarantined_at = None
            reservation.failure_code = None
            reservation.failure_reason = None
            reservation.failure_metadata = None
        group.state = "resetting"
        group.resetting_at = group.resetting_at or now
        group.quarantined_at = None
        group.failure_code = None
        group.failure_reason = None
        group.failure_metadata = None
    group.updated_at = now
    await db.flush()
    return await gpu_lifecycle_operation_response(db, row, group=group)


async def ensure_reservation_lifecycle_operation(
    db: AsyncSession,
    reservation_id: str,
    *,
    operation_type: Optional[str] = None,
) -> GpuLifecycleOperationV1:
    """Create or replay the one authoritative physical-release intent for a reservation."""

    await acquire_gpu_lifecycle_lock(db)
    reservation = await _locked_reservation(db, reservation_id)
    if reservation is None:
        raise GpuLifecycleError("GPU lifecycle reservation is unknown.")
    group = await _locked_group(db, reservation.allocation_group_id)
    host = (
        await db.execute(
            select(Host).where(Host.host_id == reservation.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    if host is None:
        raise GpuLifecycleError("GPU lifecycle reservation host is unknown.")
    existing = (
        (
            await db.execute(
                select(GpuLifecycleOperation)
                .where(
                    GpuLifecycleOperation.allocation_group_id
                    == reservation.allocation_group_id,
                    GpuLifecycleOperation.allocation_group_generation
                    == reservation.allocation_group_generation,
                    GpuLifecycleOperation.reservation_id == reservation.reservation_id,
                )
                .order_by(
                    GpuLifecycleOperation.created_at,
                    GpuLifecycleOperation.operation_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        if operation_type is not None and existing.operation_type != operation_type:
            raise GpuLifecycleError(
                "GPU reservation already has another authoritative lifecycle operation."
            )
        return await gpu_lifecycle_operation_response(db, existing, group=group)
    expected_operation_type = _derived_reservation_operation_type(reservation)
    if operation_type is not None and operation_type != expected_operation_type:
        raise GpuLifecycleError(
            "Requested lifecycle producer type differs from server-side custody state."
        )
    operation_type = expected_operation_type
    intent = GpuLifecycleOperationV1(
        operation_id=generate_uuid(),
        operation_type=operation_type,
        host_id=reservation.host_id,
        host_key_generation=reservation.host_key_generation,
        host_boot_generation=reservation.host_boot_generation,
        allocation_group_id=reservation.allocation_group_id,
        allocation_group_generation=reservation.allocation_group_generation,
        reservation_id=reservation.reservation_id,
        reservation_generation=reservation.reservation_generation,
        claims_sha256=reservation.claims_sha256,
        process_incarnation=reservation.process_incarnation,
        topology_fingerprint=reservation.topology_fingerprint,
        gpu_bdfs=list(reservation.gpu_bdfs),
        gpu_uuids=list(reservation.gpu_uuids),
        owner_hotkey=reservation.owner_hotkey,
        stable_server_id=reservation.server_id,
        management_mode=reservation.management_mode,
        migration_id=reservation.legacy_migration_id,
    )
    return await create_gpu_lifecycle_operation(db, host, intent)


async def _locked_operation(
    db: AsyncSession,
    operation_id: str,
) -> GpuLifecycleOperation:
    row = (
        await db.execute(
            select(GpuLifecycleOperation)
            .where(GpuLifecycleOperation.operation_id == operation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise GpuLifecycleError("GPU lifecycle operation is unknown.")
    return row


async def gpu_lifecycle_operation_response(
    db: AsyncSession,
    row: GpuLifecycleOperation,
    *,
    group: Optional[GpuAllocationGroup] = None,
) -> GpuLifecycleOperationV1:
    if group is None:
        group = await db.get(GpuAllocationGroup, row.allocation_group_id)
    document = dict(row.intent)
    document.update(
        {
            "phase": row.phase,
            "group_state": group.state if group is not None else None,
            "physical_result_sha256": row.physical_result_sha256,
            "result_outcome": row.result_outcome,
            "receipt_id": row.receipt_id,
            "receipt_sha256": row.receipt_sha256,
            "local_release_ack_sha256": row.local_release_ack_sha256,
            "failure_code": row.failure_code,
            "failure_reason": row.failure_reason,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "finalized_at": row.finalized_at,
        }
    )
    return GpuLifecycleOperationV1.model_validate(document)


async def get_gpu_lifecycle_operation(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
) -> GpuLifecycleOperationV1:
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    await _locked_authenticated_host(
        db, authenticated_host, row, allow_reboot_resume=True
    )
    return await gpu_lifecycle_operation_response(db, row)


def _assert_result_snapshot(
    row: GpuLifecycleOperation,
    result: GpuPhysicalResultV1,
) -> None:
    if (
        result.operation_id != row.operation_id
        or result.allocation_group_id != row.allocation_group_id
        or result.allocation_group_generation != row.allocation_group_generation
        or result.reservation_id != row.reservation_id
        or result.reservation_generation != row.reservation_generation
        or result.claims_sha256 != row.claims_sha256
        or result.process_incarnation != row.process_incarnation
        or result.topology_fingerprint != row.topology_fingerprint
        or result.gpu_bdfs != row.gpu_bdfs
        or result.gpu_uuids != row.gpu_uuids
    ):
        raise GpuLifecycleError("GPU physical result differs from lifecycle intent.")
    if row.operation_type == "forced_dead_guest_recovery":
        if result.source_reader_result is None:
            raise GpuLifecycleError(
                "Forced GPU recovery requires an exact source-reader result."
            )
        if result.source_reader_result.migration_id != row.migration_id:
            raise GpuLifecycleError(
                "Forced GPU source-reader result changed migration identity."
            )
    elif result.source_reader_result is not None:
        raise GpuLifecycleError(
            "Source-reader evidence is valid only for forced dead-guest recovery."
        )


def _reset_receipt(row: GpuLifecycleOperation) -> GpuResetReceiptV1:
    if (
        row.receipt_id is None
        or row.physical_result_sha256 is None
        or row.result_outcome not in {"accepted", "quarantined"}
        or row.receipt_accepted_at is None
    ):
        raise GpuLifecycleError("GPU lifecycle receipt is incomplete.")
    return GpuResetReceiptV1(
        operation_id=row.operation_id,
        receipt_id=row.receipt_id,
        result_sha256=row.physical_result_sha256,
        outcome=row.result_outcome,
        local_release_required=row.result_outcome == "accepted",
        phase="receipt_accepted" if row.result_outcome == "accepted" else "quarantined",
        accepted_at=row.receipt_accepted_at,
    )


async def _accept_physical_result(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    result_sha256: str,
) -> GpuResetReceiptV1:
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    await _locked_authenticated_host(
        db, authenticated_host, row, allow_reboot_resume=True
    )
    if not secrets.compare_digest(row.physical_result_sha256 or "", result_sha256):
        raise GpuLifecycleError("GPU lifecycle result replay changed canonical bytes.")
    if row.phase in {
        "receipt_accepted",
        "local_release_acked",
        "finalized",
        "quarantined",
    }:
        return _reset_receipt(row)
    if row.phase != "physical_result":
        raise GpuLifecycleError("GPU lifecycle result is not ready for API receipt.")

    result = GpuPhysicalResultV1.model_validate(row.physical_result)
    group = await _locked_group(db, row.allocation_group_id)
    reservation = await _locked_reservation(db, row.reservation_id)
    if group.generation != row.allocation_group_generation:
        raise GpuLifecycleError("GPU group generation changed before reset receipt.")
    if reservation is None:
        if (
            group.state != "resetting"
            or group.reservation_id is not None
            or group.process_incarnation is not None
            or group.management_mode is not None
        ):
            raise GpuLifecycleError(
                "Ownerless GPU custody changed before reset receipt."
            )
    elif (
        group.reservation_id != row.reservation_id
        or group.reservation_generation != row.reservation_generation
        or group.process_incarnation != row.process_incarnation
        or reservation.reservation_generation != row.reservation_generation
        or reservation.claims_sha256 != row.claims_sha256
        or reservation.process_incarnation != row.process_incarnation
    ):
        raise GpuLifecycleError("GPU reservation custody changed before reset receipt.")

    physical_postconditions_succeeded = bool(
        result.qemu_absent
        and result.reset_succeeded
        and result.original_drivers_restored
        and (
            row.operation_type != "forced_dead_guest_recovery"
            or (
                result.source_reader_result is not None
                and result.source_reader_result.readers_absent
            )
        )
    )
    unclean_normal_miner_shutdown = bool(
        physical_postconditions_succeeded
        and row.operation_type == "normal_delete"
        and row.management_mode == "miner"
        and result.guest_shutdown_clean is not True
    )
    successful = physical_postconditions_succeeded and not unclean_normal_miner_shutdown
    infra_failure: Optional[str] = None
    if successful and reservation is not None and row.management_mode == "miner":
        from api.server.gpu_infra import (
            GpuInfraError,
            force_seal_gpu_infra_from_recovery,
            require_gpu_infra_sealed,
        )

        try:
            if row.operation_type == "forced_dead_guest_recovery":
                await force_seal_gpu_infra_from_recovery(
                    db,
                    reservation,
                    result.source_reader_result,
                )
            await require_gpu_infra_sealed(db, reservation)
        except GpuInfraError as exc:
            infra_failure = str(exc)
            successful = False

    now = _now()
    row.receipt_id = f"gpu-reset-receipt-{generate_uuid()}"
    row.receipt_accepted_at = now
    if successful:
        row.result_outcome = "accepted"
        row.phase = "receipt_accepted"
        row.reporting_state = "receipt_accepted"
        if reservation is not None:
            await _retire_gpu_runtime_lineage(
                db,
                reservation,
                now,
                remove_nodes=True,
                successful=True,
            )
            reservation.state = "resetting"
        group.state = "release_pending"
        group.resetting_at = None
        group.updated_at = now
    else:
        code = result.failure_code or (
            "gpu_guest_shutdown_unclean"
            if unclean_normal_miner_shutdown
            else (
                "gpu_infra_unclosed" if infra_failure else "gpu_reset_evidence_mismatch"
            )
        )
        reason = (
            result.failure_reason
            or infra_failure
            or (
                "Normal miner teardown did not prove a clean guest shutdown."
                if unclean_normal_miner_shutdown
                else "GPU physical reset evidence failed."
            )
        )
        row.result_outcome = "quarantined"
        row.phase = "quarantined"
        row.reporting_state = "quarantined"
        row.failure_code = code
        row.failure_reason = reason
        row.finalized_at = now
        if reservation is not None:
            _quarantine_reservation(
                reservation,
                group,
                code=code,
                reason=reason,
                metadata=dict(result.evidence),
                now=now,
            )
            await _retire_gpu_runtime_lineage(db, reservation, now, reason=reason)
        else:
            _quarantine_group(
                group,
                code=code,
                reason=reason,
                metadata=dict(result.evidence),
                now=now,
            )
    receipt = _reset_receipt(row)
    row.receipt_sha256 = canonical_sha256(receipt)
    row.updated_at = now
    await _append_recovery_event(
        db,
        row,
        "receipt_accepted" if row.result_outcome == "accepted" else "quarantined",
        occurred_at=now,
    )
    await db.flush()
    return receipt


async def record_gpu_physical_result(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    result: GpuPhysicalResultV1,
) -> GpuResetReceiptV1:
    """Persist exact physical result, then accept it in a separate transaction."""

    result_document = _result_document(result)
    result_sha256 = canonical_sha256(result_document)
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    current_host = await _locked_authenticated_host(
        db, authenticated_host, row, allow_reboot_resume=True
    )
    _assert_result_snapshot(row, result)
    if row.physical_result_sha256 is not None:
        if (
            not secrets.compare_digest(row.physical_result_sha256, result_sha256)
            or row.physical_result != result_document
        ):
            raise GpuLifecycleError(
                "GPU lifecycle result replay changed canonical bytes."
            )
        if row.phase in {
            "receipt_accepted",
            "local_release_acked",
            "finalized",
            "quarantined",
        }:
            return _reset_receipt(row)
    if row.operation_type in {
        "ownerless_group_recovery",
        "forced_dead_guest_recovery",
    }:
        await _validate_recovery_authorization(
            db, current_host, row, require_started=True
        )
    if row.physical_result_sha256 is None:
        if row.phase != "intent":
            raise GpuLifecycleError(
                "GPU lifecycle operation cannot accept a physical result."
            )
        group = await _locked_group(db, row.allocation_group_id)
        reservation = await _locked_reservation(db, row.reservation_id)
        if group.generation != row.allocation_group_generation:
            raise GpuLifecycleError(
                "GPU group generation changed before physical result."
            )
        if reservation is None:
            if group.state != "resetting" or group.reservation_id is not None:
                raise GpuLifecycleError("Ownerless GPU group left exact reset custody.")
        elif (
            group.reservation_id != row.reservation_id
            or reservation.state != "resetting"
            or group.state != "resetting"
        ):
            raise GpuLifecycleError("GPU reservation is not in exact reset custody.")
        row.physical_result = result_document
        row.physical_result_sha256 = result_sha256
        row.phase = "physical_result"
        row.reporting_state = "physical_result"
        row.updated_at = _now()
        await _append_recovery_event(
            db,
            row,
            "reset_reported",
            occurred_at=row.updated_at,
        )
        await db.flush()
        await db.commit()
    receipt = await _accept_physical_result(
        db,
        authenticated_host,
        operation_id,
        result_sha256,
    )
    await db.commit()
    return receipt


def _clear_group_for_reuse(group: GpuAllocationGroup, now: datetime) -> None:
    group.state = "available"
    group.management_mode = None
    group.reservation_owner = None
    group.reservation_id = None
    group.process_incarnation = None
    group.available_at = now
    group.reserved_at = None
    group.launching_at = None
    group.running_at = None
    group.resetting_at = None
    group.quarantined_at = None
    group.failure_code = None
    group.failure_reason = None
    group.failure_metadata = None
    group.recovery_authorization_id = None
    group.recovery_report_id = None
    group.recovery_nonce_hash = None
    group.recovery_authorized_by = None
    group.recovery_authorized_at = None
    group.recovery_started_at = None
    group.recovery_completed_at = None
    group.updated_at = now


async def _finalize_local_release(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    ack_sha256: str,
) -> GpuLifecycleOperationV1:
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    await _locked_authenticated_host(
        db, authenticated_host, row, allow_reboot_resume=True
    )
    if not secrets.compare_digest(row.local_release_ack_sha256 or "", ack_sha256):
        raise GpuLifecycleError("GPU local-release ACK replay changed canonical bytes.")
    if row.phase == "finalized":
        return await gpu_lifecycle_operation_response(db, row)
    if row.phase != "local_release_acked":
        raise GpuLifecycleError("GPU local-release ACK is not ready to finalize.")
    group = await _locked_group(db, row.allocation_group_id)
    reservation = await _locked_reservation(db, row.reservation_id)
    if group.state != "release_pending":
        raise GpuLifecycleError("GPU group left release-pending before final ACK.")
    now = _now()
    if row.operation_type == "forced_dead_guest_recovery":
        if reservation is None:
            raise GpuLifecycleError("Forced recovery lost its reservation lineage.")
        group.state = "recovery_required"
        # Physical reset plus the exact local-release ACK ends old-boot custody.
        # Only now may the reusable group advance to the current authorized
        # operator and inventory report; the old reservation claims remain
        # immutable for reclaim audit.
        group.host_key_generation = row.host_key_generation
        group.host_boot_generation = row.host_boot_generation
        group.last_report_id = group.recovery_report_id
        group.recovery_completed_at = now
        group.updated_at = now
        reservation.state = "quarantined"
        reservation.quarantined_at = now
        reservation.failure_code = "gpu_forced_recovery_required"
        reservation.failure_reason = (
            "Physical recovery completed; exact prior lineage must reclaim the group."
        )
        reservation.failure_metadata = {
            "lifecycle_operation_id": row.operation_id,
            "receipt_id": row.receipt_id,
        }
    else:
        if reservation is not None:
            reservation.state = "released"
            reservation.reset_completed_at = now
            reservation.released_at = now
        else:
            group.generation = int(group.generation) + 1
        _clear_group_for_reuse(group, now)
    row.phase = "finalized"
    row.reporting_state = "finalized"
    row.finalized_at = now
    row.updated_at = now
    await _append_recovery_event(db, row, "completed", occurred_at=now)
    await db.flush()
    return await gpu_lifecycle_operation_response(db, row, group=group)


async def record_gpu_local_release_ack(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    ack: GpuLocalReleaseAckV1,
) -> GpuLifecycleOperationV1:
    """Durably accept L0's absence proof, then finalize in a new transaction."""

    ack_document = _ack_document(ack)
    ack_sha256 = canonical_sha256(ack_document)
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    await _locked_authenticated_host(
        db, authenticated_host, row, allow_reboot_resume=True
    )
    if (
        ack.operation_id != row.operation_id
        or ack.receipt_id != row.receipt_id
        or ack.result_sha256 != row.physical_result_sha256
        or ack.allocation_group_id != row.allocation_group_id
        or ack.allocation_group_generation != row.allocation_group_generation
        or ack.reservation_id != row.reservation_id
        or ack.process_incarnation != row.process_incarnation
    ):
        raise GpuLifecycleError("GPU local-release ACK differs from its exact receipt.")
    if row.local_release_ack_sha256 is not None:
        if not secrets.compare_digest(row.local_release_ack_sha256, ack_sha256):
            raise GpuLifecycleError(
                "GPU local-release ACK replay changed canonical bytes."
            )
        if row.phase == "finalized":
            return await gpu_lifecycle_operation_response(db, row)
    else:
        if row.phase != "receipt_accepted" or row.result_outcome != "accepted":
            raise GpuLifecycleError(
                "GPU lifecycle operation cannot accept local release."
            )
        row.local_release_ack = ack_document
        row.local_release_ack_sha256 = ack_sha256
        row.local_release_acked_at = _now()
        row.phase = "local_release_acked"
        row.reporting_state = "local_release_acked"
        row.updated_at = row.local_release_acked_at
        await _append_recovery_event(
            db,
            row,
            "local_release_acked",
            occurred_at=row.updated_at,
        )
        await db.flush()
        await db.commit()
    response = await _finalize_local_release(
        db,
        authenticated_host,
        operation_id,
        ack_sha256,
    )
    await db.commit()
    return response


def lifecycle_http_error(exc: GpuLifecycleError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
