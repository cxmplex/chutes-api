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
    GpuReleaseRolloverEnsureRequestV1,
    GpuReleaseRolloverResponseV1,
    GpuRecoveryAuthorizationEnvelopeV1,
    GpuRecoveryEventV1,
    GpuResetReceiptV1,
)
from api.gpu_models import (
    GpuHostLossEvent,
    GpuLifecycleOperation,
    GpuRecoveryAuthorization,
    GpuRecoveryEvent,
)
from api.host.gpu_allocations import (
    _active_gpu_release,
    _gpu_release_target_sha256,
    _quarantine_group,
    _quarantine_reservation,
    _retire_gpu_runtime_lineage,
    _validate_row_claims,
)
from api.releases.provenance import load_canonical_provenance
from api.releases.schemas import GuestRelease
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    GpuHostLossFinalizeRequestV1,
    GpuRecoveryAuthorizeRequestV1,
    canonical_json_bytes,
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


def gpu_lifecycle_intent_document(operation: GpuLifecycleOperationV1) -> dict:
    """Project any lifecycle response onto the strict immutable intent wire shape."""

    return operation.model_dump(
        mode="json",
        exclude_none=True,
        exclude=_INTENT_OUTPUT_FIELDS,
    )


def gpu_recovery_authorization_document(
    envelope: GpuRecoveryAuthorizationEnvelopeV1,
) -> dict:
    """Return the one recovery document accepted for persistence and dispatch."""

    _assert_intent_input(envelope.operation)
    document = envelope.model_dump(mode="json", exclude_none=True)
    document["operation"] = gpu_lifecycle_intent_document(envelope.operation)
    return document


def gpu_recovery_authorization_bytes(
    envelope: GpuRecoveryAuthorizationEnvelopeV1,
) -> bytes:
    """Return canonical bytes for exact recovery-authorization comparisons."""

    return canonical_json_bytes(gpu_recovery_authorization_document(envelope))


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
    if allow_reboot_resume and isinstance(row, GpuLifecycleOperation):
        recovery_crossed_physical_boundary = bool(
            row.operation_type in {"ownerless_group_recovery", "forced_dead_guest_recovery"}
            and row.phase in {"physical_result", "receipt_accepted", "local_release_acked"}
        )
        if (
            row.operation_type not in {"ownerless_group_recovery", "forced_dead_guest_recovery"}
            or recovery_crossed_physical_boundary
        ):
            boot_matches = int(host.boot_generation or 0) >= int(row.host_boot_generation or 0)
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
        raise GpuLifecycleError("GPU lifecycle intent differs from current host inventory.")


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
        or (
            intent.operation_type == "release_rollover"
            and reservation.gpu_release_id != intent.current_gpu_release_id
        )
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.process_incarnation != reservation.process_incarnation
        or group.reservation_owner != reservation.workload_owner
        or group.management_mode != reservation.management_mode
    ):
        raise GpuLifecycleError("GPU lifecycle intent differs from reservation custody.")


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
        raise GpuLifecycleError("Ownerless GPU lifecycle intent has conflicting custody.")


async def _locked_host(
    db: AsyncSession,
    authenticated_host: Host,
) -> Host:
    host = (
        await db.execute(
            select(Host).where(Host.host_id == authenticated_host.host_id).with_for_update()
        )
    ).scalar_one_or_none()
    if host is None:
        raise GpuLifecycleError("GPU lifecycle host is unknown.")
    return host


async def _locked_current_logical_host(
    db: AsyncSession,
    authenticated_host: Host,
    row: GpuLifecycleOperation | GpuLifecycleOperationV1,
) -> Host:
    """Authenticate the current logical host without reviving old key/boot custody."""

    current = await _locked_host(db, authenticated_host)
    if (
        authenticated_host.host_id != current.host_id
        or authenticated_host.active_key_generation != current.active_key_generation
        or authenticated_host.boot_generation != current.boot_generation
        or current.host_id != row.host_id
    ):
        raise GpuLifecycleError("Authenticated GPU host identity changed before lifecycle replay.")
    return current


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
        or report.report_generation != host.gpu_inventory_report_generation
        or claims.report_generation != host.gpu_inventory_report_generation
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
            canonical_sha256(source_reader_result) if source_reader_result is not None else None
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


async def _group_is_permanently_lost(
    db: AsyncSession,
    group: GpuAllocationGroup,
) -> bool:
    event_id = (
        await db.execute(
            select(GpuHostLossEvent.event_id)
            .where(
                GpuHostLossEvent.allocation_group_id == group.allocation_group_id,
                GpuHostLossEvent.allocation_group_generation == group.generation,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return bool(event_id is not None or group.failure_code == "gpu_host_permanently_lost")


async def _revoke_unstarted_recovery(
    db: AsyncSession,
    authorization: GpuRecoveryAuthorization,
    group: GpuAllocationGroup,
    now: datetime,
    *,
    failure_code: str,
    failure_reason: str,
) -> None:
    row = await _locked_operation(db, authorization.operation_id)
    if await _recovery_event_exists(db, row.operation_id, "started"):
        raise GpuLifecycleError("A started GPU recovery cannot be replaced by a new authorization.")
    if not await _recovery_event_exists(db, row.operation_id, "revoked"):
        await _append_recovery_event(db, row, "revoked", occurred_at=now)
    if row.phase == "intent":
        row.phase = "quarantined"
        row.reporting_state = "quarantined"
        row.failure_code = failure_code
        row.failure_reason = failure_reason
        row.finalized_at = now
        row.updated_at = now
    elif row.phase != "quarantined":
        raise GpuLifecycleError("GPU recovery authorization has already changed physical state.")
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


def _assert_successor_recovery_custody(
    host: Host,
    group: GpuAllocationGroup,
    operation: GpuLifecycleOperation,
    authorization: GpuRecoveryAuthorization,
    reservation: Optional[GpuLaunchReservation],
    *,
    invalidated_finalized: bool = False,
) -> None:
    """Require the failed recovery's immutable custody before superseding it."""

    if (
        (
            operation.phase != "quarantined"
            if not invalidated_finalized
            else (
                operation.phase != "finalized"
                or operation.result_outcome != "accepted"
                or operation.receipt_id is None
                or operation.receipt_sha256 is None
                or operation.local_release_ack_sha256 is None
                or group.failure_code != "gpu_inventory_changed_during_release"
                or not isinstance(group.failure_metadata, dict)
                or not group.failure_metadata.get("inventory_report_id")
            )
        )
        or operation.host_id != authorization.host_id
        or authorization.host_id != host.host_id
        or group.host_key_generation != authorization.host_key_generation
        or group.host_boot_generation != authorization.host_boot_generation
        or operation.allocation_group_id != group.allocation_group_id
        or operation.allocation_group_generation != group.generation
        or operation.allocation_group_id != authorization.allocation_group_id
        or operation.allocation_group_generation != authorization.allocation_group_generation
        or operation.topology_fingerprint != group.topology_fingerprint
        or operation.topology_fingerprint != authorization.topology_fingerprint
        or operation.gpu_bdfs != list(group.gpu_bdfs)
        or operation.gpu_bdfs != authorization.gpu_bdfs
        or operation.gpu_uuids != list(group.gpu_uuids)
        or operation.gpu_uuids != authorization.gpu_uuids
        or operation.owner_hotkey != authorization.owner_hotkey
        or operation.stable_server_id != authorization.stable_server_id
        or operation.management_mode != authorization.management_mode
        or operation.migration_id != authorization.migration_id
        or group.state != "quarantined"
    ):
        raise GpuLifecycleError(
            "Failed GPU recovery custody changed before successor authorization."
        )
    if reservation is None:
        if (
            operation.operation_type != "ownerless_group_recovery"
            or operation.reservation_id is not None
            or authorization.reservation_id is not None
            or operation.owner_hotkey != host.miner_hotkey
            or any(
                value is not None
                for value in (
                    group.reservation_id,
                    group.reservation_owner,
                    group.management_mode,
                    group.process_incarnation,
                )
            )
        ):
            raise GpuLifecycleError("Failed ownerless GPU recovery acquired conflicting custody.")
        return
    if (
        operation.operation_type != "forced_dead_guest_recovery"
        or operation.reservation_id != reservation.reservation_id
        or authorization.reservation_id != reservation.reservation_id
        or operation.reservation_generation != reservation.reservation_generation
        or authorization.reservation_generation != reservation.reservation_generation
        or operation.claims_sha256 != reservation.claims_sha256
        or authorization.claims_sha256 != reservation.claims_sha256
        or operation.process_incarnation != reservation.process_incarnation
        or authorization.process_incarnation != reservation.process_incarnation
        or operation.owner_hotkey != reservation.owner_hotkey
        or operation.stable_server_id != reservation.server_id
        or operation.management_mode != reservation.management_mode
        or operation.migration_id != reservation.legacy_migration_id
        or reservation.host_key_generation != authorization.prior_host_key_generation
        or reservation.host_boot_generation != authorization.prior_host_boot_generation
        or reservation.state != "quarantined"
        or group.reservation_id != reservation.reservation_id
        or group.reservation_generation != reservation.reservation_generation
        or group.reservation_owner != reservation.workload_owner
        or group.process_incarnation != reservation.process_incarnation
        or group.management_mode != reservation.management_mode
    ):
        raise GpuLifecycleError(
            "Failed forced GPU recovery custody changed before successor authorization."
        )


async def _locked_recovery_predecessor_history(
    db: AsyncSession,
    host: Host,
    group: GpuAllocationGroup,
    reservation: Optional[GpuLaunchReservation],
) -> Optional[tuple[GpuRecoveryAuthorization, GpuLifecycleOperation, bool]]:
    """Find one exact revoked predecessor after its mutable projection was cleared."""

    query = select(GpuRecoveryAuthorization).where(
        GpuRecoveryAuthorization.host_id == host.host_id,
        GpuRecoveryAuthorization.allocation_group_id == group.allocation_group_id,
        GpuRecoveryAuthorization.allocation_group_generation == group.generation,
        GpuRecoveryAuthorization.host_key_generation == group.host_key_generation,
        GpuRecoveryAuthorization.host_boot_generation == group.host_boot_generation,
    )
    if reservation is None:
        query = query.where(GpuRecoveryAuthorization.reservation_id.is_(None))
    else:
        query = query.where(
            GpuRecoveryAuthorization.reservation_id == reservation.reservation_id,
            GpuRecoveryAuthorization.reservation_generation == reservation.reservation_generation,
        )
    authorizations = (
        (
            await db.execute(
                query.order_by(
                    GpuRecoveryAuthorization.issued_at.desc(),
                    GpuRecoveryAuthorization.authorization_id.desc(),
                ).with_for_update()
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[GpuRecoveryAuthorization, GpuLifecycleOperation, bool]] = []
    for authorization in authorizations:
        operation = await _locked_operation(db, authorization.operation_id)
        if operation.phase != "quarantined" or not await _recovery_event_exists(
            db, operation.operation_id, "revoked"
        ):
            continue
        _assert_successor_recovery_custody(
            host,
            group,
            operation,
            authorization,
            reservation,
        )
        matches.append(
            (
                authorization,
                operation,
                await _recovery_event_exists(db, operation.operation_id, "started"),
            )
        )
    if not matches:
        return None
    prior_lineages = {
        (
            item[0].prior_host_key_generation,
            item[0].prior_host_boot_generation,
        )
        for item in matches
    }
    if len(prior_lineages) != 1:
        raise GpuLifecycleError("Revoked GPU recovery history has ambiguous prior host lineage.")
    return matches[0]


def _clear_recovery_projection_for_successor(
    group: GpuAllocationGroup,
    authorization_id: str,
    now: datetime,
) -> None:
    if group.recovery_authorization_id != authorization_id:
        raise GpuLifecycleError(
            "Failed GPU recovery is no longer the group's current authorization."
        )
    group.recovery_authorization_id = None
    group.recovery_report_id = None
    group.recovery_nonce_hash = None
    group.recovery_authorized_by = None
    group.recovery_authorized_at = None
    group.recovery_started_at = None
    group.recovery_completed_at = None
    group.updated_at = now


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
    if await _group_is_permanently_lost(db, group):
        raise GpuLifecycleError("Permanently lost GPU custody cannot be recovered or reclaimed.")
    host = (
        await db.execute(select(Host).where(Host.host_id == group.host_id).with_for_update())
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
    reservation = await _locked_reservation(db, group.reservation_id)
    existing = None
    recovery_prior_lineage: Optional[tuple[int, int]] = None
    if group.recovery_authorization_id is not None:
        existing = (
            await db.execute(
                select(GpuRecoveryAuthorization)
                .where(
                    GpuRecoveryAuthorization.authorization_id == group.recovery_authorization_id,
                    GpuRecoveryAuthorization.allocation_group_id == allocation_group_id,
                    GpuRecoveryAuthorization.allocation_group_generation == group.generation,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if existing is None:
            raise GpuLifecycleError("GPU recovery group points to an unknown authorization.")
    if existing is not None:
        operation = await _locked_operation(db, existing.operation_id)
        started = await _recovery_event_exists(db, existing.operation_id, "started")
        completed = await _recovery_event_exists(db, existing.operation_id, "completed")
        revoked = await _recovery_event_exists(db, existing.operation_id, "revoked")
        invalidated_finalized = bool(
            operation.phase == "finalized"
            and operation.result_outcome == "accepted"
            and started
            and completed
            and revoked
            and group.state == "quarantined"
            and group.failure_code == "gpu_inventory_changed_during_release"
        )
        if (operation.phase == "quarantined" and started) or invalidated_finalized:
            if existing.inventory_report_id == request.report_id:
                raise GpuLifecycleError(
                    "Failed GPU recovery requires a fresh current inventory report."
                )
            _assert_successor_recovery_custody(
                host,
                group,
                operation,
                existing,
                reservation,
                invalidated_finalized=invalidated_finalized,
            )
            recovery_prior_lineage = (
                existing.prior_host_key_generation,
                existing.prior_host_boot_generation,
            )
            _clear_recovery_projection_for_successor(
                group,
                existing.authorization_id,
                now,
            )
        elif not started and existing.inventory_report_id != request.report_id:
            await _revoke_unstarted_recovery(
                db,
                existing,
                group,
                now,
                failure_code="gpu_recovery_inventory_superseded",
                failure_reason=(
                    "A newer exact host inventory report superseded the recovery "
                    "authorization before presentation."
                ),
            )
            _assert_successor_recovery_custody(
                host,
                group,
                operation,
                existing,
                reservation,
            )
            recovery_prior_lineage = (
                existing.prior_host_key_generation,
                existing.prior_host_boot_generation,
            )
        elif not revoked and (existing.expires_at > now or started):
            return await _recovery_authorization_envelope(db, existing)
        elif not revoked:
            await _revoke_unstarted_recovery(
                db,
                existing,
                group,
                now,
                failure_code="gpu_recovery_authorization_expired",
                failure_reason=("GPU recovery authorization expired before presentation."),
            )
            _assert_successor_recovery_custody(
                host,
                group,
                operation,
                existing,
                reservation,
            )
            recovery_prior_lineage = (
                existing.prior_host_key_generation,
                existing.prior_host_boot_generation,
            )
        else:
            if existing.inventory_report_id == request.report_id:
                raise GpuLifecycleError(
                    "Revoked GPU recovery authorization requires a fresh inventory report."
                )
            _assert_successor_recovery_custody(
                host,
                group,
                operation,
                existing,
                reservation,
            )
            recovery_prior_lineage = (
                existing.prior_host_key_generation,
                existing.prior_host_boot_generation,
            )
            _clear_recovery_projection_for_successor(
                group,
                existing.authorization_id,
                now,
            )

    if existing is None:
        historical = await _locked_recovery_predecessor_history(
            db,
            host,
            group,
            reservation,
        )
        if historical is not None:
            predecessor, _operation, predecessor_started = historical
            if predecessor_started and predecessor.inventory_report_id == request.report_id:
                raise GpuLifecycleError(
                    "Failed GPU recovery requires a fresh current inventory report."
                )
            recovery_prior_lineage = (
                predecessor.prior_host_key_generation,
                predecessor.prior_host_boot_generation,
            )

    prior_host_key_generation, prior_host_boot_generation = recovery_prior_lineage or (
        group.host_key_generation,
        group.host_boot_generation,
    )
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
            raise GpuLifecycleError("Forced GPU recovery custody is stale or incomplete.")
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
        process_incarnation=(reservation.process_incarnation if reservation is not None else None),
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
    group.recovery_nonce_hash = hashlib.sha256(recovery_nonce.encode("ascii")).hexdigest()
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
        process_incarnation=(reservation.process_incarnation if reservation is not None else None),
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
                GpuRecoveryAuthorization.authorization_id == row.recovery_authorization_id,
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
    if revoked is not None:
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
    if started is None:
        try:
            report_claims = GpuInventoryReportV1.model_validate(report.claims)
        except ValueError as exc:
            raise GpuLifecycleError("GPU recovery inventory report is malformed.") from exc
        _assert_recovery_inventory(
            authenticated_host,
            group,
            report,
            report_claims,
        )
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
            or reservation.host_key_generation != authorization.prior_host_key_generation
            or reservation.host_boot_generation != authorization.prior_host_boot_generation
            or reservation.reservation_generation != authorization.reservation_generation
            or reservation.claims_sha256 != authorization.claims_sha256
            or reservation.process_incarnation != authorization.process_incarnation
        ):
            raise GpuLifecycleError("GPU recovery prior reservation custody changed.")
    if envelope is not None:
        expected = await _recovery_authorization_envelope(db, authorization)
        if not secrets.compare_digest(
            gpu_recovery_authorization_bytes(envelope),
            gpu_recovery_authorization_bytes(expected),
        ):
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
        raise GpuLifecycleError("GPU recovery group left authorized quarantine custody.")
    # Wall time may step backwards under host clock correction. Preserve the
    # database recovery chronology instead of producing a started timestamp
    # earlier than its immutable authorization.
    now = max(
        _now(),
        authorization.issued_at,
        group.recovery_authorized_at,
    )
    if reservation is not None:
        if (
            reservation.state != "quarantined"
            or group.reservation_id != reservation.reservation_id
            or group.process_incarnation != reservation.process_incarnation
        ):
            raise GpuLifecycleError("GPU recovery reservation custody changed before start.")
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
            "claim_active_release_changed",
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
    authorized_release_rollover: bool = False,
    recovery_prior_lineage: tuple[int, int] | None = None,
) -> GpuLifecycleOperationV1:
    """Persist reset intent before any physical ownership mutation."""

    is_recovery = intent.operation_type in {
        "ownerless_group_recovery",
        "forced_dead_guest_recovery",
    }
    if intent.operation_type == "release_rollover" and not authorized_release_rollover:
        raise GpuLifecycleError(
            "GPU release rollover must be created by the atomic rollover producer."
        )
    if intent.operation_type != "release_rollover" and authorized_release_rollover:
        raise GpuLifecycleError("Release-rollover authority cannot create another operation type.")
    if is_recovery and not authorized_recovery:
        raise GpuLifecycleError(
            "GPU recovery intents may only be created by an administrator authorization."
        )
    if is_recovery and (recovery_prior_lineage is None or min(recovery_prior_lineage) < 1):
        raise GpuLifecycleError("GPU recovery intent is missing immutable prior host lineage.")
    if not is_recovery and recovery_prior_lineage is not None:
        raise GpuLifecycleError("Ordinary lifecycle intent cannot carry recovery prior lineage.")
    _assert_intent_input(intent)
    intent_document = gpu_lifecycle_intent_document(intent)
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
        if not secrets.compare_digest(existing.intent_sha256, intent_sha256):
            raise GpuLifecycleError("GPU lifecycle operation id was reused with new intent.")
        if existing.phase in {"finalized", "quarantined"}:
            await _locked_current_logical_host(db, authenticated_host, existing)
        else:
            await _locked_authenticated_host(
                db, authenticated_host, existing, allow_reboot_resume=True
            )
        return await gpu_lifecycle_operation_response(db, existing)

    host = await _locked_authenticated_host(db, authenticated_host, intent)
    group = await _locked_group(db, intent.allocation_group_id)
    _assert_group_snapshot(host, group, intent)
    if await _group_is_permanently_lost(db, group):
        raise GpuLifecycleError(
            "Permanently lost GPU custody cannot begin another lifecycle operation."
        )
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
        raise GpuLifecycleError(f"GPU group generation already has lifecycle operation {active}.")

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
        current_gpu_release_id=intent.current_gpu_release_id,
        desired_gpu_release_id=intent.desired_gpu_release_id,
        desired_release_target_sha256=intent.desired_release_target_sha256,
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
    current_gpu_release_id: str | None = None,
    desired_gpu_release_id: str | None = None,
    desired_release_target_sha256: str | None = None,
) -> GpuLifecycleOperationV1:
    """Create or replay the one authoritative physical-release intent for a reservation."""

    await acquire_gpu_lifecycle_lock(db)
    reservation = await _locked_reservation(db, reservation_id)
    if reservation is None:
        raise GpuLifecycleError("GPU lifecycle reservation is unknown.")
    group = await _locked_group(db, reservation.allocation_group_id)
    host = (
        await db.execute(select(Host).where(Host.host_id == reservation.host_id).with_for_update())
    ).scalar_one_or_none()
    if host is None:
        raise GpuLifecycleError("GPU lifecycle reservation host is unknown.")
    existing = (
        (
            await db.execute(
                select(GpuLifecycleOperation)
                .where(
                    GpuLifecycleOperation.allocation_group_id == reservation.allocation_group_id,
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
        if existing.operation_type == "release_rollover" and any(
            value is None
            for value in (
                existing.current_gpu_release_id,
                existing.desired_gpu_release_id,
                existing.desired_release_target_sha256,
            )
        ):
            raise GpuLifecycleError(
                "Existing GPU release rollover lacks immutable release identity."
            )
        return await gpu_lifecycle_operation_response(db, existing, group=group)
    expected_operation_type = _derived_reservation_operation_type(reservation)
    if operation_type is not None and operation_type != expected_operation_type:
        raise GpuLifecycleError(
            "Requested lifecycle producer type differs from server-side custody state."
        )
    operation_type = expected_operation_type
    rollover_identity = (
        current_gpu_release_id,
        desired_gpu_release_id,
        desired_release_target_sha256,
    )
    if operation_type == "release_rollover" and any(
        value is None for value in rollover_identity
    ):
        desired_release, _image, _provenance = await _active_gpu_release(db, host)
        current_gpu_release_id = reservation.gpu_release_id
        desired_gpu_release_id = desired_release.release_id
        desired_release_target_sha256 = _release_rollover_target_sha256(
            desired_release,
            reservation,
            group,
        )
        rollover_identity = (
            current_gpu_release_id,
            desired_gpu_release_id,
            desired_release_target_sha256,
        )
    if operation_type == "release_rollover":
        if (
            any(value is None for value in rollover_identity)
            or current_gpu_release_id != reservation.gpu_release_id
            or current_gpu_release_id == desired_gpu_release_id
        ):
            raise GpuLifecycleError("GPU release rollover identity is incomplete or stale.")
    elif any(value is not None for value in rollover_identity):
        raise GpuLifecycleError("Only release rollover may carry release identity.")
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
        current_gpu_release_id=current_gpu_release_id,
        desired_gpu_release_id=desired_gpu_release_id,
        desired_release_target_sha256=desired_release_target_sha256,
    )
    return await create_gpu_lifecycle_operation(
        db,
        host,
        intent,
        authorized_release_rollover=operation_type == "release_rollover",
    )


def _release_rollover_target_sha256(
    release: GuestRelease,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
) -> str:
    """Derive the exact replacement reservation target from signed release provenance."""

    image = (release.images or {}).get("gpu")
    if not isinstance(image, dict):
        raise GpuLifecycleError("Desired GPU release has no GPU image.")
    payload = image.get("provenance_payload")
    if not isinstance(payload, str) or not payload:
        raise GpuLifecycleError("Desired GPU release has no canonical provenance.")
    try:
        provenance = load_canonical_provenance(payload)
    except Exception as exc:  # noqa: BLE001 - normalized into the lifecycle contract
        raise GpuLifecycleError("Desired GPU release provenance is invalid.") from exc
    environment = next(
        (
            item
            for item in provenance.get("launch_environments", [])
            if item.get("profile_id") == group.profile_id
        ),
        None,
    )
    measurement = next(
        (
            item
            for item in provenance.get("measurements", [])
            if item.get("profile_id") == group.profile_id
            and item.get("management_mode") == reservation.management_mode
        ),
        None,
    )
    artifacts = provenance.get("artifacts")
    if (
        environment is None
        or measurement is None
        or not isinstance(artifacts, dict)
        or provenance.get("profile_contract_sha256") != group.profile_contract_sha256
    ):
        raise GpuLifecycleError(
            "Desired GPU release does not contain the reservation's exact signed profile."
        )
    return _gpu_release_target_sha256(
        release=release,
        image=image,
        group=group,
        management_mode=reservation.management_mode,
        measurement_name=measurement["name"],
        environment=environment,
        artifacts=artifacts,
    )


async def _ensure_locked_release_rollover(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    group: GpuAllocationGroup,
    desired_release: GuestRelease,
    *,
    expected: GpuReleaseRolloverEnsureRequestV1 | None = None,
) -> GpuReleaseRolloverResponseV1:
    existing_row = (
        await db.execute(
            select(GpuLifecycleOperation)
            .where(
                GpuLifecycleOperation.allocation_group_id
                == reservation.allocation_group_id,
                GpuLifecycleOperation.allocation_group_generation
                == reservation.allocation_group_generation,
                GpuLifecycleOperation.reservation_id == reservation.reservation_id,
            )
            .order_by(GpuLifecycleOperation.created_at, GpuLifecycleOperation.operation_id)
            .with_for_update()
        )
    ).scalars().first()
    if existing_row is not None:
        if existing_row.operation_type != "release_rollover":
            raise GpuLifecycleError(
                "GPU reservation already has another authoritative lifecycle operation."
            )
        if expected is not None and (
            expected.reservation_id != reservation.reservation_id
            or expected.reservation_generation != reservation.reservation_generation
            or not secrets.compare_digest(expected.claims_sha256, reservation.claims_sha256)
            or expected.current_gpu_release_id != reservation.gpu_release_id
            or expected.desired_gpu_release_id != existing_row.desired_gpu_release_id
            or not secrets.compare_digest(
                expected.desired_release_target_sha256,
                existing_row.desired_release_target_sha256 or "",
            )
        ):
            raise GpuLifecycleError(
                "GPU release rollover request differs from locked reservation identity."
            )
        operation = await gpu_lifecycle_operation_response(db, existing_row, group=group)
        return GpuReleaseRolloverResponseV1(
            host_id=reservation.host_id,
            reservation_id=reservation.reservation_id,
            reservation_generation=reservation.reservation_generation,
            claims_sha256=reservation.claims_sha256,
            current_gpu_release_id=operation.current_gpu_release_id,
            desired_gpu_release_id=operation.desired_gpu_release_id,
            desired_release_target_sha256=operation.desired_release_target_sha256,
            operation=operation,
        )
    desired_target_sha256 = _release_rollover_target_sha256(
        desired_release,
        reservation,
        group,
    )
    if reservation.gpu_release_id == desired_release.release_id:
        raise GpuLifecycleError("GPU reservation already uses the active release.")
    if expected is not None and (
        expected.reservation_id != reservation.reservation_id
        or expected.reservation_generation != reservation.reservation_generation
        or not secrets.compare_digest(expected.claims_sha256, reservation.claims_sha256)
        or expected.current_gpu_release_id != reservation.gpu_release_id
        or expected.desired_gpu_release_id != desired_release.release_id
        or not secrets.compare_digest(
            expected.desired_release_target_sha256,
            desired_target_sha256,
        )
    ):
        raise GpuLifecycleError(
            "GPU release rollover request differs from locked reservation or desired release."
        )
    now = _now()
    reservation.teardown_requested_at = reservation.teardown_requested_at or now
    reservation.teardown_reason = "GPU release rolled"
    operation = await ensure_reservation_lifecycle_operation(
        db,
        reservation.reservation_id,
        operation_type="release_rollover",
        current_gpu_release_id=reservation.gpu_release_id,
        desired_gpu_release_id=desired_release.release_id,
        desired_release_target_sha256=desired_target_sha256,
    )
    return GpuReleaseRolloverResponseV1(
        host_id=reservation.host_id,
        reservation_id=reservation.reservation_id,
        reservation_generation=reservation.reservation_generation,
        claims_sha256=reservation.claims_sha256,
        current_gpu_release_id=operation.current_gpu_release_id,
        desired_gpu_release_id=operation.desired_gpu_release_id,
        desired_release_target_sha256=operation.desired_release_target_sha256,
        operation=operation,
    )


async def ensure_gpu_release_rollover(
    db: AsyncSession,
    authenticated_host: Host,
    request: GpuReleaseRolloverEnsureRequestV1,
) -> GpuReleaseRolloverResponseV1:
    """Atomically create or replay one host-authenticated release-rollover operation."""

    await acquire_gpu_lifecycle_lock(db)
    host = await _locked_host(db, authenticated_host)
    if (
        authenticated_host.host_id != host.host_id
        or authenticated_host.active_key_generation != host.active_key_generation
        or authenticated_host.boot_generation != host.boot_generation
        or host.compute_type != "gpu"
        or host.tee_type != "tdx"
    ):
        raise GpuLifecycleError(
            "Authenticated GPU host identity changed before release rollover."
        )
    reservation = await _locked_reservation(db, request.reservation_id)
    if reservation is None or reservation.host_id != host.host_id:
        raise GpuLifecycleError("GPU release rollover reservation belongs to another host.")
    group = await _locked_group(db, reservation.allocation_group_id)
    desired_release, _image, _provenance = await _active_gpu_release(db, host)
    return await _ensure_locked_release_rollover(
        db,
        reservation,
        group,
        desired_release,
        expected=request,
    )


async def ensure_release_rollovers_for_release(
    db: AsyncSession,
    desired_release: GuestRelease,
    *,
    host_id: str | None = None,
) -> list[GpuReleaseRolloverResponseV1]:
    """Produce rollover intents for every live reservation in one activated GPU stream."""

    if desired_release.compute_type != "gpu" or desired_release.tee_type != "tdx":
        return []
    await acquire_gpu_lifecycle_lock(db)
    query = (
        select(GpuLaunchReservation)
        .join(Host, Host.host_id == GpuLaunchReservation.host_id)
        .where(
            Host.compute_type == "gpu",
            Host.tee_type == "tdx",
            Host.release_channel == desired_release.channel,
            GpuLaunchReservation.gpu_release_id != desired_release.release_id,
            GpuLaunchReservation.management_mode.in_(("platform", "miner")),
            GpuLaunchReservation.state.in_(("reserved", "claimed", "launching", "running")),
        )
        .order_by(
            GpuLaunchReservation.host_id,
            GpuLaunchReservation.allocation_group_id,
            GpuLaunchReservation.reservation_generation,
        )
        .with_for_update()
    )
    if host_id is not None:
        query = query.where(GpuLaunchReservation.host_id == host_id)
    reservations = (await db.execute(query)).scalars().all()
    responses: list[GpuReleaseRolloverResponseV1] = []
    for reservation in reservations:
        group = await _locked_group(db, reservation.allocation_group_id)
        responses.append(
            await _ensure_locked_release_rollover(
                db,
                reservation,
                group,
                desired_release,
            )
        )
    return responses


async def existing_release_rollovers_for_host(
    db: AsyncSession,
    host_id: str,
    _desired_release: GuestRelease,
) -> list[GpuReleaseRolloverResponseV1]:
    """Read-only projection of already-produced rollover operations for manifest polling."""

    rows = (
        (
            await db.execute(
                select(GpuLifecycleOperation, GpuLaunchReservation, GpuAllocationGroup)
                .join(
                    GpuLaunchReservation,
                    GpuLaunchReservation.reservation_id == GpuLifecycleOperation.reservation_id,
                )
                .join(
                    GpuAllocationGroup,
                    GpuAllocationGroup.allocation_group_id
                    == GpuLaunchReservation.allocation_group_id,
                )
                .where(
                    GpuLifecycleOperation.host_id == host_id,
                    GpuLifecycleOperation.operation_type == "release_rollover",
                    GpuLifecycleOperation.phase.notin_(
                        ("local_release_acked", "finalized", "quarantined")
                    ),
                )
                .order_by(
                    GpuLaunchReservation.reservation_generation,
                    GpuLifecycleOperation.operation_id,
                )
            )
        )
        .all()
    )
    responses: list[GpuReleaseRolloverResponseV1] = []
    for operation_row, reservation, group in rows:
        operation = await gpu_lifecycle_operation_response(
            db,
            operation_row,
            group=group,
        )
        responses.append(
            GpuReleaseRolloverResponseV1(
                host_id=reservation.host_id,
                reservation_id=reservation.reservation_id,
                reservation_generation=reservation.reservation_generation,
                claims_sha256=reservation.claims_sha256,
                current_gpu_release_id=operation.current_gpu_release_id,
                desired_gpu_release_id=operation.desired_gpu_release_id,
                desired_release_target_sha256=operation.desired_release_target_sha256,
                operation=operation,
            )
        )
    return responses


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
    terminal_group_state: Optional[str] = None
    if row.phase == "finalized":
        terminal_group_state = (
            "recovery_required"
            if row.operation_type == "forced_dead_guest_recovery"
            else "available"
        )
    elif row.phase == "quarantined":
        terminal_group_state = "quarantined"
    elif group is None:
        group = await db.get(GpuAllocationGroup, row.allocation_group_id)
    document = dict(row.intent)
    document.update(
        {
            "phase": row.phase,
            "group_state": (
                terminal_group_state
                if terminal_group_state is not None
                else group.state
                if group is not None
                else None
            ),
            "physical_result_sha256": row.physical_result_sha256,
            "result_outcome": row.result_outcome,
            "receipt_id": row.receipt_id,
            "receipt_sha256": row.receipt_sha256,
            "local_release_ack_sha256": row.local_release_ack_sha256,
            # Post-receipt inventory fencing is an internal finalization
            # directive until the exact local-release ACK makes quarantine
            # terminal. V1 permits failure fields only on a quarantined phase.
            "failure_code": row.failure_code if row.phase == "quarantined" else None,
            "failure_reason": row.failure_reason if row.phase == "quarantined" else None,
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
    if row.phase in {"finalized", "quarantined"}:
        await _locked_current_logical_host(db, authenticated_host, row)
    else:
        await _locked_authenticated_host(db, authenticated_host, row, allow_reboot_resume=True)
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
            raise GpuLifecycleError("Forced GPU recovery requires an exact source-reader result.")
        if result.source_reader_result.migration_id != row.migration_id:
            raise GpuLifecycleError("Forced GPU source-reader result changed migration identity.")
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
    receipt = GpuResetReceiptV1(
        operation_id=row.operation_id,
        receipt_id=row.receipt_id,
        result_sha256=row.physical_result_sha256,
        outcome=row.result_outcome,
        local_release_required=row.result_outcome == "accepted",
        phase="receipt_accepted" if row.result_outcome == "accepted" else "quarantined",
        accepted_at=row.receipt_accepted_at,
    )
    if row.receipt_sha256 is not None and not secrets.compare_digest(
        row.receipt_sha256,
        canonical_sha256(receipt),
    ):
        raise GpuLifecycleError("GPU lifecycle receipt audit bytes changed.")
    return receipt


async def _accept_physical_result(
    db: AsyncSession,
    authenticated_host: Host,
    operation_id: str,
    result_sha256: str,
    *,
    exact_persisted_replay: bool = False,
) -> GpuResetReceiptV1:
    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    if exact_persisted_replay:
        await _locked_current_logical_host(db, authenticated_host, row)
    else:
        await _locked_authenticated_host(db, authenticated_host, row, allow_reboot_resume=True)
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
            raise GpuLifecycleError("Ownerless GPU custody changed before reset receipt.")
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
        receipt = _reset_receipt(row)
        row.receipt_sha256 = canonical_sha256(receipt)
        row.updated_at = now
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
            else ("gpu_infra_unclosed" if infra_failure else "gpu_reset_evidence_mismatch")
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
        receipt = _reset_receipt(row)
        row.receipt_sha256 = canonical_sha256(receipt)
        row.updated_at = now
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
    _assert_result_snapshot(row, result)
    exact_persisted_replay = row.physical_result_sha256 is not None
    if exact_persisted_replay:
        if (
            not secrets.compare_digest(row.physical_result_sha256 or "", result_sha256)
            or row.physical_result != result_document
        ):
            raise GpuLifecycleError("GPU lifecycle result replay changed canonical bytes.")
        current_host = await _locked_current_logical_host(db, authenticated_host, row)
        if row.phase in {
            "receipt_accepted",
            "local_release_acked",
            "finalized",
            "quarantined",
        }:
            return _reset_receipt(row)
    else:
        current_host = await _locked_authenticated_host(
            db, authenticated_host, row, allow_reboot_resume=True
        )
        if row.operation_type in {
            "ownerless_group_recovery",
            "forced_dead_guest_recovery",
        }:
            await _validate_recovery_authorization(db, current_host, row, require_started=True)
    if row.physical_result_sha256 is None:
        if row.phase != "intent":
            raise GpuLifecycleError("GPU lifecycle operation cannot accept a physical result.")
        group = await _locked_group(db, row.allocation_group_id)
        reservation = await _locked_reservation(db, row.reservation_id)
        if group.generation != row.allocation_group_generation:
            raise GpuLifecycleError("GPU group generation changed before physical result.")
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
        exact_persisted_replay=exact_persisted_replay,
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
    # The exact persisted ACK is the authority for finalization. The current
    # logical host may finish it after a boot or key-generation change without
    # rewriting the operation's immutable original lineage.
    await _locked_current_logical_host(db, authenticated_host, row)
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
    # Wall time can step backwards between the durable local ACK and finalization.
    # Never make completion precede either that ACK or an authorized recovery start.
    now = max(
        timestamp
        for timestamp in (
            _now(),
            row.local_release_acked_at,
            row.receipt_accepted_at,
            row.created_at,
            group.recovery_started_at,
        )
        if timestamp is not None
    )
    if group.failure_code == "gpu_inventory_changed_during_release":
        reason = group.failure_reason or (
            "GPU inventory changed after reset began; the group cannot be reused."
        )
        if reservation is not None:
            _quarantine_reservation(
                reservation,
                group,
                code=group.failure_code,
                reason=reason,
                metadata={
                    "lifecycle_operation_id": row.operation_id,
                    "receipt_id": row.receipt_id,
                },
                now=now,
            )
            await _retire_gpu_runtime_lineage(db, reservation, now, reason=reason)
        else:
            _quarantine_group(
                group,
                code=group.failure_code,
                reason=reason,
                metadata={
                    "lifecycle_operation_id": row.operation_id,
                    "receipt_id": row.receipt_id,
                },
                now=now,
            )
        row.phase = "quarantined"
        row.reporting_state = "quarantined"
        row.failure_code = group.failure_code
        row.failure_reason = reason
        row.finalized_at = now
        row.updated_at = now
        await _append_recovery_event(db, row, "quarantined", occurred_at=now)
        await db.flush()
        return await gpu_lifecycle_operation_response(db, row, group=group)
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
    exact_persisted_replay = row.local_release_ack_sha256 is not None
    if exact_persisted_replay:
        if (
            not secrets.compare_digest(row.local_release_ack_sha256 or "", ack_sha256)
            or row.local_release_ack != ack_document
        ):
            raise GpuLifecycleError("GPU local-release ACK replay changed canonical bytes.")
        await _locked_current_logical_host(db, authenticated_host, row)
        if row.phase in {"finalized", "quarantined"}:
            return await gpu_lifecycle_operation_response(db, row)
    else:
        # Only the original L0 credential may make the first local-absence
        # assertion. A successor key may replay an ACK only after its exact bytes
        # are durable above; logical host identity alone does not prove custody of
        # the old CHUTES_DATA journal or physical device state.
        await _locked_authenticated_host(db, authenticated_host, row, allow_reboot_resume=True)
        if row.phase != "receipt_accepted" or row.result_outcome != "accepted":
            raise GpuLifecycleError("GPU lifecycle operation cannot accept local release.")
        row.local_release_ack = ack_document
        row.local_release_ack_sha256 = ack_sha256
        row.local_release_acked_at = max(
            timestamp
            for timestamp in (
                _now(),
                row.receipt_accepted_at,
                row.created_at,
            )
            if timestamp is not None
        )
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


async def finalize_gpu_host_loss(
    db: AsyncSession,
    operation_id: str,
    request: GpuHostLossFinalizeRequestV1,
    *,
    authorized_by: str,
) -> GpuLifecycleOperationV1:
    """Permanently fence custody when a phase-two L0 can never ACK again."""

    await acquire_gpu_lifecycle_lock(db)
    row = await _locked_operation(db, operation_id)
    existing = (
        await db.execute(
            select(GpuHostLossEvent)
            .where(GpuHostLossEvent.operation_id == operation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        expected = {
            "operation_id": request.operation_id,
            "allocation_group_id": request.allocation_group_id,
            "allocation_group_generation": request.allocation_group_generation,
            "receipt_sha256": request.receipt_sha256,
            "reason": request.reason,
            "authorized_by": authorized_by,
        }
        actual = {key: getattr(existing, key) for key in expected}
        if actual != expected or row.phase != "quarantined":
            raise GpuLifecycleError(
                "Permanent GPU host-loss authorization replay changed audit bytes."
            )
        return await gpu_lifecycle_operation_response(db, row)

    if (
        request.operation_id != row.operation_id
        or request.allocation_group_id != row.allocation_group_id
        or request.allocation_group_generation != row.allocation_group_generation
        or request.receipt_sha256 != row.receipt_sha256
        or row.phase not in {"receipt_accepted", "local_release_acked"}
        or row.result_outcome != "accepted"
        or row.physical_result_sha256 is None
        or row.receipt_id is None
        or row.receipt_accepted_at is None
    ):
        raise GpuLifecycleError(
            "Permanent GPU host-loss authorization differs from the phase-two receipt."
        )
    group = await _locked_group(db, row.allocation_group_id)
    reservation = await _locked_reservation(db, row.reservation_id)
    if (
        group.state != "release_pending"
        or group.generation != row.allocation_group_generation
        or group.reservation_id != row.reservation_id
        or group.process_incarnation != row.process_incarnation
        or (
            reservation is not None
            and (
                reservation.allocation_group_id != row.allocation_group_id
                or reservation.allocation_group_generation != row.allocation_group_generation
                or reservation.process_incarnation != row.process_incarnation
            )
        )
    ):
        raise GpuLifecycleError(
            "Permanent GPU host-loss authorization no longer matches exact custody."
        )

    now = _now()
    reason = request.reason[:2000]
    metadata = {
        "lifecycle_operation_id": row.operation_id,
        "receipt_id": row.receipt_id,
        "receipt_sha256": row.receipt_sha256,
        "authorized_by": authorized_by,
    }
    if reservation is not None:
        _quarantine_reservation(
            reservation,
            group,
            code="gpu_host_permanently_lost",
            reason=reason,
            metadata=metadata,
            now=now,
        )
        await _retire_gpu_runtime_lineage(db, reservation, now, reason=reason)
    else:
        _quarantine_group(
            group,
            code="gpu_host_permanently_lost",
            reason=reason,
            metadata=metadata,
            now=now,
        )
    row.phase = "quarantined"
    row.reporting_state = "quarantined"
    row.failure_code = "gpu_host_permanently_lost"
    row.failure_reason = reason
    row.finalized_at = now
    row.updated_at = now
    db.add(
        GpuHostLossEvent(
            event_id=f"gpu-host-loss-{generate_uuid()}",
            operation_id=row.operation_id,
            host_id=row.host_id,
            allocation_group_id=row.allocation_group_id,
            allocation_group_generation=row.allocation_group_generation,
            reservation_id=row.reservation_id,
            receipt_sha256=row.receipt_sha256,
            reason=reason,
            authorized_by=authorized_by,
            created_at=now,
        )
    )
    await db.flush()
    return await gpu_lifecycle_operation_response(db, row, group=group)


def lifecycle_http_error(exc: GpuLifecycleError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
