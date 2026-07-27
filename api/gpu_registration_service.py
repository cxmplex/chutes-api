"""Database-atomic GPU Registration V2 issuance, replay, and processing."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import generate_uuid
from api.gpu_contracts import (
    GpuRegistrationNonceRequestV2,
    GpuRegistrationNonceV2,
    GpuRegistrationRequestV2,
    GpuRegistrationResponseV2,
    gpu_registration_client_request_id,
)
from api.gpu_hotplug_service import (
    GpuHotplugError,
    dispatch_gpu_hotplug_command,
    ensure_gpu_hotplug_command,
)
from api.gpu_models import (
    GpuHotplugCommand,
    GpuRegistrationAttempt,
    GpuRegistrationConflict,
    GpuRegistrationNonce,
)
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    GpuLaunchReservationClaimsV1,
    canonical_sha256,
)
from api.server.exceptions import (
    AttestationError,
    InvalidGpuEvidenceError,
    ServerRegistrationError,
)
from api.server.schemas import Host, Server, ServerAttestation
from api.server.service import (
    _selected_gpu_inventory_devices,
    _validate_runtime_gpu_selection,
    register_gpu_server,
    verify_gpu_registration_evidence,
)
from api.server.util import get_nonce_expiry_seconds

_PROCESSING_LEASE_SECONDS = 90
_REPLAY_SECONDS = 15 * 60
_RETRY_AFTER_SECONDS = 2


class GpuRegistrationLeaseLost(RuntimeError):
    """A processor lost authority while bounded external verification ran."""


@dataclass(frozen=True)
class _RegistrationAttemptSnapshot:
    attempt_id: str
    lease_owner: str
    request: GpuRegistrationRequestV2
    request_sha256: str
    cert_pem: str
    certificate_sha256: str
    spki_sha256: str
    server_ip_audit: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_reservation_token(token: str) -> tuple[str, str]:
    try:
        reservation_id, secret = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(
            status_code=409, detail="GPU launch reservation token is malformed."
        ) from exc
    if not reservation_id or not secret:
        raise HTTPException(
            status_code=409, detail="GPU launch reservation token is malformed."
        )
    return reservation_id, hashlib.sha256(token.encode("ascii")).hexdigest()


def _status_url(attempt_id: str) -> str:
    return f"/servers/gpu/registration/attempts/{attempt_id}"


def _processing_response(attempt: GpuRegistrationAttempt) -> GpuRegistrationResponseV2:
    return GpuRegistrationResponseV2(
        attempt_id=attempt.attempt_id,
        state="processing",
        status_url=_status_url(attempt.attempt_id),
        retry_after_seconds=_RETRY_AFTER_SECONDS,
    )


def _failed_response(attempt: GpuRegistrationAttempt) -> GpuRegistrationResponseV2:
    return GpuRegistrationResponseV2(
        attempt_id=attempt.attempt_id,
        state="failed",
        status_url=_status_url(attempt.attempt_id),
        failure_code=attempt.failure_code,
        failure_detail=attempt.failure_detail,
    )


def _registration_request_audit(
    request: GpuRegistrationRequestV2,
    expected_cert_hash: str,
    cert_pem: str,
) -> dict:
    """Canonical immutable identities persisted around external verification."""

    return {
        "request_payload": request.model_dump(mode="json", exclude_none=True),
        "request_sha256": request.request_sha256(),
        "peer_certificate_pem": cert_pem,
        "peer_certificate_sha256": hashlib.sha256(cert_pem.encode("utf-8")).hexdigest(),
        "peer_spki_sha256": expected_cert_hash.lower(),
        "quote_sha256": hashlib.sha256(request.quote.encode("utf-8")).hexdigest(),
        "evidence_sha256": canonical_sha256({"gpu_evidence": request.gpu_evidence}),
        "signature_sha256": hashlib.sha256(
            request.td_signature.encode("utf-8")
        ).hexdigest(),
    }


async def _scrub_terminal_registration_material(
    db: AsyncSession,
    nonce: GpuRegistrationNonce,
    attempt: GpuRegistrationAttempt,
    now: datetime,
) -> bool:
    """Remove every nonce/token-bearing payload after the bounded replay window."""

    if (
        attempt.state not in {"completed", "failed"}
        or attempt.registration_replay_until is None
        or attempt.registration_replay_until > now
    ):
        return False
    conflicts = list(
        (
            await db.execute(
                select(GpuRegistrationConflict)
                .where(GpuRegistrationConflict.attempt_id == attempt.attempt_id)
                .order_by(GpuRegistrationConflict.conflict_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for conflict in conflicts:
        if conflict.state in {"recorded", "verifying"}:
            conflict.state = "dismissed"
            conflict.processing_lease_owner = None
            conflict.processing_lease_expires_at = None
            conflict.verification_detail = (
                "registration replay window expired before conflict completion"
            )
            conflict.verified_at = now
        conflict.request_payload = None
    attempt.request_payload = None
    nonce.state = "revoked" if nonce.state == "revoked" else "expired"
    nonce.nonce_value = None
    return True


def _registration_processing_lineage_current(
    reservation: GpuLaunchReservation | None,
    group: GpuAllocationGroup | None,
) -> bool:
    return bool(
        reservation is not None
        and group is not None
        and reservation.state in {"launching", "running"}
        and group.state in {"launching", "running"}
        and group.reservation_id == reservation.reservation_id
        and group.generation == reservation.allocation_group_generation
        and group.reservation_generation == reservation.reservation_generation
        and group.process_incarnation == reservation.process_incarnation
        and group.host_id == reservation.host_id
        and group.host_key_generation == reservation.host_key_generation
        and group.host_boot_generation == reservation.host_boot_generation
    )


async def _fail_stale_processing_attempt(
    db: AsyncSession,
    attempt: GpuRegistrationAttempt,
    now: datetime,
) -> None:
    attempt.state = "failed"
    attempt.processing_lease_owner = None
    attempt.processing_lease_expires_at = None
    attempt.failure_code = "gpu_registration_lineage_ended"
    attempt.failure_detail = (
        "GPU registration could not resume because its reservation lineage ended."
    )
    attempt.completed_at = now
    attempt.updated_at = now
    attempt.registration_replay_until = now + timedelta(seconds=_REPLAY_SECONDS)
    conflicts = list(
        (
            await db.execute(
                select(GpuRegistrationConflict)
                .where(
                    GpuRegistrationConflict.attempt_id == attempt.attempt_id,
                    GpuRegistrationConflict.state.in_(
                        ("recorded", "verifying", "verified_competitor")
                    ),
                )
                .order_by(GpuRegistrationConflict.conflict_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for conflict in conflicts:
        conflict.state = "dismissed"
        conflict.processing_lease_owner = None
        conflict.processing_lease_expires_at = None
        conflict.verification_detail = "primary registration lineage ended"
        conflict.verified_at = now


async def cleanup_expired_gpu_registration_nonces(
    db: AsyncSession,
    *,
    limit: int = 500,
) -> int:
    """Bound plaintext nonce retention even when no client performs a final replay."""

    await acquire_gpu_lifecycle_lock(db)
    now = _now()
    rows = list(
        (
            await db.execute(
                select(GpuRegistrationNonce)
                .outerjoin(
                    GpuRegistrationAttempt,
                    GpuRegistrationAttempt.attempt_id
                    == GpuRegistrationNonce.claimed_attempt_id,
                )
                .outerjoin(
                    GpuLaunchReservation,
                    GpuLaunchReservation.reservation_id
                    == GpuRegistrationAttempt.reservation_id,
                )
                .outerjoin(
                    GpuAllocationGroup,
                    GpuAllocationGroup.allocation_group_id
                    == GpuLaunchReservation.allocation_group_id,
                )
                .where(
                    or_(
                        (
                            (GpuRegistrationNonce.state == "issued")
                            & (GpuRegistrationNonce.expires_at <= now)
                        ),
                        GpuRegistrationNonce.state == "revoked",
                        (
                            (GpuRegistrationNonce.state == "claimed")
                            & GpuRegistrationAttempt.state.in_(("completed", "failed"))
                            & (GpuRegistrationAttempt.registration_replay_until <= now)
                        ),
                        (
                            (GpuRegistrationNonce.state == "claimed")
                            & (GpuRegistrationAttempt.state == "processing")
                            & or_(
                                GpuRegistrationAttempt.processing_lease_expires_at.is_(
                                    None
                                ),
                                GpuRegistrationAttempt.processing_lease_expires_at
                                <= now,
                            )
                            & or_(
                                GpuLaunchReservation.reservation_id.is_(None),
                                ~GpuLaunchReservation.state.in_(
                                    ("launching", "running")
                                ),
                                GpuAllocationGroup.allocation_group_id.is_(None),
                                ~GpuAllocationGroup.state.in_(("launching", "running")),
                                GpuAllocationGroup.reservation_id
                                != GpuLaunchReservation.reservation_id,
                                GpuAllocationGroup.generation
                                != GpuLaunchReservation.allocation_group_generation,
                                GpuAllocationGroup.reservation_generation
                                != GpuLaunchReservation.reservation_generation,
                                GpuAllocationGroup.process_incarnation
                                != GpuLaunchReservation.process_incarnation,
                                GpuAllocationGroup.host_id
                                != GpuLaunchReservation.host_id,
                                GpuAllocationGroup.host_key_generation
                                != GpuLaunchReservation.host_key_generation,
                                GpuAllocationGroup.host_boot_generation
                                != GpuLaunchReservation.host_boot_generation,
                            )
                        ),
                    )
                )
                .order_by(
                    GpuRegistrationNonce.expires_at,
                    GpuRegistrationNonce.nonce_id,
                )
                .limit(limit)
                .with_for_update(of=GpuRegistrationNonce, skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    changed = 0
    for row in rows:
        attempt = (
            (
                await db.execute(
                    select(GpuRegistrationAttempt)
                    .where(GpuRegistrationAttempt.attempt_id == row.claimed_attempt_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row.claimed_attempt_id is not None
            else None
        )
        if attempt is not None and attempt.state == "processing":
            lease_current = bool(
                attempt.processing_lease_expires_at is not None
                and attempt.processing_lease_expires_at > now
            )
            reservation = (
                await db.execute(
                    select(GpuLaunchReservation)
                    .where(
                        GpuLaunchReservation.reservation_id == attempt.reservation_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            group = (
                (
                    await db.execute(
                        select(GpuAllocationGroup)
                        .where(
                            GpuAllocationGroup.allocation_group_id
                            == reservation.allocation_group_id
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if reservation is not None
                else None
            )
            if (
                row.state == "claimed"
                and not lease_current
                and not _registration_processing_lineage_current(reservation, group)
            ):
                await _fail_stale_processing_attempt(db, attempt, now)
                changed += 1
                continue
        if (
            row.state == "revoked"
            and attempt is not None
            and attempt.state == "processing"
        ):
            attempt.state = "failed"
            attempt.processing_lease_owner = None
            attempt.processing_lease_expires_at = None
            attempt.failure_code = "gpu_registration_nonce_revoked"
            attempt.failure_detail = "GPU registration nonce was revoked."
            attempt.completed_at = now
            attempt.updated_at = now
            attempt.registration_replay_until = now + timedelta(seconds=_REPLAY_SECONDS)
        if attempt is not None and await _scrub_terminal_registration_material(
            db, row, attempt, now
        ):
            changed += 1
            continue
        row.state = "expired" if row.state != "revoked" else "revoked"
        row.nonce_value = None
        changed += 1
    await db.flush()
    return changed


async def issue_gpu_registration_nonce(
    db: AsyncSession,
    server_ip: str,
    request: GpuRegistrationNonceRequestV2,
    expected_cert_hash: str,
) -> GpuRegistrationNonceV2:
    """Issue/replay one SPKI-bound nonce generation under exact lineage locks."""

    reservation_id, token_hash = _parse_reservation_token(request.launch_reservation)
    expected_spki = expected_cert_hash.lower()
    expected_request_id = gpu_registration_client_request_id(
        reservation_id,
        request.server_id,
        expected_spki,
        request.request_generation,
    )
    try:
        request.client_request_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                "GPU registration client_request_id is not canonical for this "
                "generation."
            ),
        ) from exc
    if not secrets.compare_digest(request.client_request_id, expected_request_id):
        raise HTTPException(
            status_code=409,
            detail="GPU registration client_request_id is not canonical for this generation.",
        )
    await acquire_gpu_lifecycle_lock(db)
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise HTTPException(
            status_code=409, detail="GPU launch reservation is unknown."
        )
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
    now = _now()
    base_lineage_valid = bool(
        group is not None
        and reservation.server_id == request.server_id
        and reservation.claims_sha256 == request.claims_sha256
        and secrets.compare_digest(reservation.token_hash, token_hash)
        and group.reservation_id == reservation.reservation_id
        and group.generation == reservation.allocation_group_generation
        and group.reservation_generation == reservation.reservation_generation
        and group.process_incarnation == reservation.process_incarnation
    )
    if not base_lineage_valid:
        raise HTTPException(
            status_code=409,
            detail="GPU registration nonce request does not match current reservation lineage.",
        )

    existing = (
        await db.execute(
            select(GpuRegistrationNonce)
            .where(
                GpuRegistrationNonce.reservation_id == reservation_id,
                GpuRegistrationNonce.client_request_id == request.client_request_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if existing is not None:
        if (
            existing.request_generation != request.request_generation
            or not secrets.compare_digest(existing.peer_spki_sha256, expected_spki)
        ):
            raise HTTPException(
                status_code=409,
                detail="GPU registration nonce generation is bound to another identity.",
            )
        if existing.state == "claimed" and existing.claimed_attempt_id:
            claimed_attempt = (
                await db.execute(
                    select(GpuRegistrationAttempt)
                    .where(
                        GpuRegistrationAttempt.attempt_id == existing.claimed_attempt_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            replay_valid = bool(
                claimed_attempt is not None
                and secrets.compare_digest(
                    claimed_attempt.peer_spki_sha256, expected_spki
                )
                and (
                    claimed_attempt.state == "processing"
                    or (
                        claimed_attempt.registration_replay_until is not None
                        and claimed_attempt.registration_replay_until > now
                    )
                )
            )
            if replay_valid and existing.nonce_value:
                return GpuRegistrationNonceV2(
                    client_request_id=existing.client_request_id,
                    request_generation=existing.request_generation,
                    nonce_id=existing.nonce_id,
                    reservation_id=existing.reservation_id,
                    nonce=existing.nonce_value,
                    expires_at=existing.expires_at,
                    claimed_attempt_id=claimed_attempt.attempt_id,
                    status_url=_status_url(claimed_attempt.attempt_id),
                )
        if (
            existing.state == "issued"
            and existing.expires_at > now
            and existing.nonce_value
            and reservation.state == "launching"
            and group.state == "launching"
        ):
            return GpuRegistrationNonceV2(
                client_request_id=existing.client_request_id,
                request_generation=existing.request_generation,
                nonce_id=existing.nonce_id,
                reservation_id=existing.reservation_id,
                nonce=existing.nonce_value,
                expires_at=existing.expires_at,
            )
        if existing.state == "issued" and existing.expires_at <= now:
            existing.state = "expired"
            existing.nonce_value = None
        raise HTTPException(
            status_code=409,
            detail=(
                "GPU registration nonce generation is terminal; advance "
                "request_generation without reusing its audit row."
            ),
        )

    if (
        reservation.state != "launching"
        or group.state != "launching"
        or reservation.expires_at <= now
    ):
        raise HTTPException(
            status_code=409,
            detail="GPU registration nonce request does not match a launching reservation.",
        )
    prior_active_attempt = (
        (
            await db.execute(
                select(GpuRegistrationAttempt)
                .join(
                    GpuRegistrationNonce,
                    GpuRegistrationNonce.nonce_id == GpuRegistrationAttempt.nonce_id,
                )
                .where(
                    GpuRegistrationAttempt.reservation_id == reservation_id,
                    GpuRegistrationAttempt.state.in_(("processing", "completed")),
                    or_(
                        GpuRegistrationAttempt.state == "processing",
                        GpuRegistrationAttempt.registration_replay_until > now,
                    ),
                )
                .order_by(
                    GpuRegistrationNonce.request_generation.desc(),
                    GpuRegistrationAttempt.created_at.desc(),
                )
                .with_for_update(of=GpuRegistrationAttempt)
            )
        )
        .scalars()
        .first()
    )
    if prior_active_attempt is not None:
        raise HTTPException(
            status_code=409,
            detail="A prior GPU registration attempt remains authoritative.",
        )
    active = (
        await db.execute(
            select(GpuRegistrationNonce)
            .where(
                GpuRegistrationNonce.reservation_id == reservation_id,
                GpuRegistrationNonce.state == "issued",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if active is not None:
        if active.expires_at <= now:
            active.state = "expired"
            active.nonce_value = None
        else:
            raise HTTPException(
                status_code=409,
                detail="Another registration nonce generation is active.",
            )
    nonce_value = secrets.token_hex(32)
    expires_at = now + timedelta(seconds=get_nonce_expiry_seconds())
    row = GpuRegistrationNonce(
        nonce_id=generate_uuid(),
        client_request_id=request.client_request_id,
        request_generation=request.request_generation,
        peer_spki_sha256=expected_spki,
        reservation_id=reservation_id,
        server_ip=server_ip,
        nonce_value=nonce_value,
        nonce_hash=hashlib.sha256(bytes.fromhex(nonce_value)).hexdigest(),
        state="issued",
        issued_at=now,
        expires_at=expires_at,
    )
    db.add(row)
    await db.flush()
    return GpuRegistrationNonceV2(
        client_request_id=row.client_request_id,
        request_generation=row.request_generation,
        nonce_id=row.nonce_id,
        reservation_id=row.reservation_id,
        nonce=nonce_value,
        expires_at=expires_at,
    )


def _registration_lineage_current(
    host: Host | None,
    group: GpuAllocationGroup | None,
    report: GpuInventoryReport | None,
    reservation: GpuLaunchReservation | None,
    request: GpuRegistrationRequestV2,
    token_hash: str,
    *,
    allowed_states: set[str],
) -> bool:
    """Validate the complete host/group/report/reservation custody snapshot."""

    if host is None or group is None or report is None or reservation is None:
        return False
    try:
        report_claims = GpuInventoryReportV1.model_validate(report.claims)
    except ValueError:
        return False
    claims = request.quote_commitment.claims
    matching = [
        item
        for item in report_claims.groups
        if item.topology_fingerprint == group.topology_fingerprint
        and [device.bdf for device in item.devices] == list(group.gpu_bdfs)
        and [device.uuid for device in item.devices] == list(group.gpu_uuids)
        and [device.attestation_certificate_sha256 for device in item.devices]
        == list(group.gpu_attestation_certificate_sha256s)
    ]
    return bool(
        len(matching) == 1
        and reservation.state in allowed_states
        and group.state == reservation.state
        and host.compute_type == "gpu"
        and host.tee_type == "tdx"
        and host.storage_enabled is True
        and host.provisioning_state == "ready"
        and reservation.host_id == group.host_id == host.host_id == claims.host_id
        and reservation.host_key_generation
        == group.host_key_generation
        == report.host_key_generation
        == host.active_key_generation
        == claims.host_key_generation
        and reservation.host_boot_generation
        == group.host_boot_generation
        == report.host_boot_generation
        == host.boot_generation
        == claims.host_boot_generation
        and group.last_report_id == report.report_id
        and report.host_id == host.host_id
        and report.reconciliation_status == "accepted"
        and report.claims_sha256 == canonical_sha256(report_claims)
        and reservation.allocation_group_id
        == group.allocation_group_id
        == claims.allocation_group_id
        and reservation.allocation_group_generation
        == group.generation
        == claims.allocation_group_generation
        and reservation.reservation_id == group.reservation_id == claims.reservation_id
        and reservation.reservation_generation
        == group.reservation_generation
        == claims.reservation_generation
        and reservation.process_incarnation
        == group.process_incarnation
        == claims.process_incarnation
        and reservation.owner_hotkey == host.miner_hotkey == claims.owner_hotkey
        and group.reservation_owner
        == reservation.workload_owner
        == claims.workload_owner
        and reservation.management_mode
        == group.management_mode
        == claims.management_mode
        and reservation.server_id == request.server_id == claims.server_id
        and reservation.topology_fingerprint
        == group.topology_fingerprint
        == report.topology_fingerprint
        == claims.topology_fingerprint
        and list(reservation.gpu_bdfs) == list(group.gpu_bdfs) == claims.gpu_bdfs
        and list(reservation.gpu_uuids) == list(group.gpu_uuids) == claims.gpu_uuids
        and list(reservation.gpu_identifiers)
        == list(group.gpu_identifiers)
        == claims.gpu_identifiers
        and list(reservation.gpu_attestation_certificate_sha256s)
        == list(group.gpu_attestation_certificate_sha256s)
        == claims.gpu_attestation_certificate_sha256s
        and reservation.gpu_release_id == group.gpu_release_id == claims.gpu_release_id
        and reservation.profile_id == group.profile_id == claims.gpu_profile_id
        and reservation.profile_contract_sha256
        == group.profile_contract_sha256
        == report.profile_contract_sha256
        == claims.profile_contract_sha256
        and reservation.claims == claims.model_dump(mode="json", exclude_none=True)
        and secrets.compare_digest(
            reservation.claims_sha256, request.quote_commitment.reservation_sha256
        )
        and secrets.compare_digest(reservation.token_hash, token_hash)
    )


async def _claim_attempt(
    db: AsyncSession,
    server_ip: str,
    request: GpuRegistrationRequestV2,
    expected_cert_hash: str,
    cert_pem: str,
) -> tuple[
    GpuRegistrationAttempt,
    Optional[str],
    Optional[GpuRegistrationConflict],
]:
    """Atomically claim the nonce and insert the attempt, or classify an exact replay."""

    await acquire_gpu_lifecycle_lock(db)
    nonce = (
        await db.execute(
            select(GpuRegistrationNonce)
            .where(GpuRegistrationNonce.nonce_id == request.nonce_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _now()
    reservation_id, token_hash = _parse_reservation_token(request.launch_reservation)
    if (
        nonce is None
        or nonce.reservation_id != reservation_id
        or (nonce.state == "issued" and nonce.expires_at <= now)
        or not nonce.nonce_value
        or not secrets.compare_digest(nonce.nonce_value, request.nonce)
        or not secrets.compare_digest(
            nonce.nonce_hash,
            hashlib.sha256(bytes.fromhex(request.nonce)).hexdigest(),
        )
    ):
        raise HTTPException(
            status_code=401, detail="GPU registration nonce is invalid or expired."
        )
    identity = (
        await db.execute(
            select(
                GpuLaunchReservation.host_id,
                GpuLaunchReservation.allocation_group_id,
            ).where(GpuLaunchReservation.reservation_id == reservation_id)
        )
    ).one_or_none()
    host = (
        (
            await db.execute(
                select(Host).where(Host.host_id == identity.host_id).with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    group = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(
                    GpuAllocationGroup.allocation_group_id
                    == identity.allocation_group_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    report = (
        (
            await db.execute(
                select(GpuInventoryReport)
                .where(GpuInventoryReport.report_id == group.last_report_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if group is not None
        else None
    )
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    allowed_states = (
        {"launching", "running", "quarantined"}
        if nonce.state == "claimed"
        else {"launching"}
    )
    lineage_current = _registration_lineage_current(
        host,
        group,
        report,
        reservation,
        request,
        token_hash,
        allowed_states=allowed_states,
    )
    if (
        not lineage_current
        or request.quote_commitment.attested_spki_sha256 != expected_cert_hash.lower()
        or (
            nonce.state == "issued"
            and (
                not secrets.compare_digest(
                    nonce.peer_spki_sha256, expected_cert_hash.lower()
                )
                or reservation.expires_at <= now
                or group.state != "launching"
                or reservation.state != "launching"
            )
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="GPU registration lineage is stale or mismatched.",
        )
    request_sha256 = request.request_sha256()
    certificate_sha256 = hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()
    if nonce.state == "claimed":
        attempt = (
            await db.execute(
                select(GpuRegistrationAttempt)
                .where(GpuRegistrationAttempt.attempt_id == nonce.claimed_attempt_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if attempt is None:
            raise HTTPException(
                status_code=409, detail="Claimed GPU registration nonce is incomplete."
            )
        exact = (
            secrets.compare_digest(attempt.request_sha256, request_sha256)
            and secrets.compare_digest(
                attempt.peer_spki_sha256, expected_cert_hash.lower()
            )
            and secrets.compare_digest(
                attempt.peer_certificate_sha256, certificate_sha256
            )
        )
        if not exact:
            conflict = (
                await db.execute(
                    select(GpuRegistrationConflict)
                    .where(
                        GpuRegistrationConflict.nonce_id == nonce.nonce_id,
                        GpuRegistrationConflict.request_sha256 == request_sha256,
                        GpuRegistrationConflict.peer_spki_sha256
                        == expected_cert_hash.lower(),
                        GpuRegistrationConflict.peer_certificate_sha256
                        == certificate_sha256,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if conflict is None:
                conflict = GpuRegistrationConflict(
                    conflict_id=generate_uuid(),
                    attempt_id=attempt.attempt_id,
                    nonce_id=nonce.nonce_id,
                    request_sha256=request_sha256,
                    request_payload=request.model_dump(mode="json", exclude_none=True),
                    peer_certificate_pem=cert_pem,
                    peer_certificate_sha256=certificate_sha256,
                    peer_spki_sha256=expected_cert_hash.lower(),
                    quote_sha256=hashlib.sha256(
                        request.quote.encode("utf-8")
                    ).hexdigest(),
                    evidence_sha256=canonical_sha256(
                        {"gpu_evidence": request.gpu_evidence}
                    ),
                    signature_sha256=hashlib.sha256(
                        request.td_signature.encode("utf-8")
                    ).hexdigest(),
                    state="recorded",
                )
                db.add(conflict)
                await db.flush()
            return attempt, None, conflict
        should_process = bool(
            attempt.state == "processing"
            and (
                attempt.processing_lease_expires_at is None
                or attempt.processing_lease_expires_at <= now
            )
        )
        lease_owner = None
        if should_process:
            lease_owner = generate_uuid()
            attempt.processing_lease_owner = lease_owner
            attempt.processing_lease_expires_at = now + timedelta(
                seconds=_PROCESSING_LEASE_SECONDS
            )
            attempt.updated_at = now
        return attempt, lease_owner, None
    if nonce.state != "issued":
        raise HTTPException(
            status_code=409, detail="GPU registration nonce is no longer claimable."
        )
    lease_owner = generate_uuid()
    attempt = GpuRegistrationAttempt(
        attempt_id=generate_uuid(),
        nonce_id=nonce.nonce_id,
        reservation_id=reservation_id,
        request_sha256=request_sha256,
        request_payload=request.model_dump(mode="json", exclude_none=True),
        peer_certificate_pem=cert_pem,
        peer_certificate_sha256=certificate_sha256,
        peer_spki_sha256=expected_cert_hash.lower(),
        state="processing",
        processing_lease_owner=lease_owner,
        processing_lease_expires_at=now + timedelta(seconds=_PROCESSING_LEASE_SECONDS),
        created_at=now,
        updated_at=now,
    )
    db.add(attempt)
    await db.flush()
    nonce.state = "claimed"
    nonce.claimed_attempt_id = attempt.attempt_id
    await db.flush()
    return attempt, lease_owner, None


async def _claim_processing_lease(
    db: AsyncSession,
    attempt_id: str,
    expected_cert_hash: str,
) -> tuple[GpuRegistrationAttempt, Optional[str]]:
    """Claim an expired/unowned processing lease for POST or status-GET resume."""

    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == attempt_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if attempt is None or not secrets.compare_digest(
        attempt.peer_spki_sha256, expected_cert_hash.lower()
    ):
        raise HTTPException(
            status_code=404, detail="GPU registration attempt not found."
        )
    now = _now()
    if attempt.state != "processing":
        return attempt, None
    if (
        attempt.processing_lease_owner is not None
        and attempt.processing_lease_expires_at is not None
        and attempt.processing_lease_expires_at > now
    ):
        return attempt, None
    lease_owner = generate_uuid()
    attempt.processing_lease_owner = lease_owner
    attempt.processing_lease_expires_at = now + timedelta(
        seconds=_PROCESSING_LEASE_SECONDS
    )
    attempt.updated_at = now
    await db.flush()
    return attempt, lease_owner


async def _locked_processing_snapshot(
    db: AsyncSession,
    attempt_id: str,
    lease_owner: str,
) -> _RegistrationAttemptSnapshot:
    """Validate the immutable persisted request and exact current reservation custody."""

    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == attempt_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _now()
    if (
        attempt is None
        or attempt.state != "processing"
        or attempt.processing_lease_owner != lease_owner
        or attempt.processing_lease_expires_at is None
        or attempt.processing_lease_expires_at <= now
    ):
        raise GpuRegistrationLeaseLost(
            "GPU registration processing lease is no longer authoritative."
        )
    if attempt.request_payload is None:
        raise ServerRegistrationError(
            "Persisted GPU registration processing request was prematurely scrubbed."
        )
    try:
        request = GpuRegistrationRequestV2.model_validate(attempt.request_payload)
    except ValueError as exc:
        raise ServerRegistrationError(
            "Persisted GPU registration request is malformed."
        ) from exc
    request_sha256 = request.request_sha256()
    certificate_sha256 = hashlib.sha256(
        attempt.peer_certificate_pem.encode("utf-8")
    ).hexdigest()
    nonce = (
        await db.execute(
            select(GpuRegistrationNonce)
            .where(GpuRegistrationNonce.nonce_id == attempt.nonce_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    reservation_id, token_hash = _parse_reservation_token(request.launch_reservation)
    identity = (
        await db.execute(
            select(
                GpuLaunchReservation.host_id,
                GpuLaunchReservation.allocation_group_id,
            ).where(GpuLaunchReservation.reservation_id == reservation_id)
        )
    ).one_or_none()
    host = (
        (
            await db.execute(
                select(Host).where(Host.host_id == identity.host_id).with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    group = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(
                    GpuAllocationGroup.allocation_group_id
                    == identity.allocation_group_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    report = (
        (
            await db.execute(
                select(GpuInventoryReport)
                .where(GpuInventoryReport.report_id == group.last_report_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if group is not None
        else None
    )
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    exact = bool(
        nonce is not None
        and reservation is not None
        and group is not None
        and host is not None
        and report is not None
        and nonce.state == "claimed"
        and nonce.claimed_attempt_id == attempt.attempt_id
        and nonce.reservation_id == attempt.reservation_id
        and nonce.nonce_value
        and secrets.compare_digest(nonce.nonce_value, request.nonce)
        and secrets.compare_digest(
            nonce.nonce_hash,
            hashlib.sha256(bytes.fromhex(request.nonce)).hexdigest(),
        )
        and secrets.compare_digest(attempt.request_sha256, request_sha256)
        and secrets.compare_digest(attempt.peer_certificate_sha256, certificate_sha256)
        and request.quote_commitment.attested_spki_sha256 == attempt.peer_spki_sha256
        and secrets.compare_digest(nonce.peer_spki_sha256, attempt.peer_spki_sha256)
        and reservation.reservation_id == attempt.reservation_id
        and _registration_lineage_current(
            host,
            group,
            report,
            reservation,
            request,
            token_hash,
            allowed_states={"launching", "running"},
        )
    )
    if not exact:
        raise ServerRegistrationError(
            "Persisted GPU registration attempt no longer matches exact lineage."
        )
    return _RegistrationAttemptSnapshot(
        attempt_id=attempt.attempt_id,
        lease_owner=lease_owner,
        request=request,
        request_sha256=request_sha256,
        cert_pem=attempt.peer_certificate_pem,
        certificate_sha256=certificate_sha256,
        spki_sha256=attempt.peer_spki_sha256,
        server_ip_audit=nonce.server_ip,
    )


async def _assert_processing_lease_before_publish(
    db: AsyncSession,
    snapshot: _RegistrationAttemptSnapshot,
) -> None:
    current = await _locked_processing_snapshot(
        db, snapshot.attempt_id, snapshot.lease_owner
    )
    if (
        current.request_sha256 != snapshot.request_sha256
        or current.certificate_sha256 != snapshot.certificate_sha256
        or current.spki_sha256 != snapshot.spki_sha256
    ):
        raise GpuRegistrationLeaseLost(
            "GPU registration immutable processor snapshot changed."
        )


async def _mark_attempt_failed(
    db: AsyncSession,
    attempt_id: str,
    lease_owner: str,
    code: str,
    detail: str,
) -> GpuRegistrationAttempt:
    """Fail one attempt without treating unauthenticated evidence as fencing authority."""

    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == attempt_id)
            .with_for_update()
        )
    ).scalar_one()
    if attempt.state == "completed":
        return attempt
    now = _now()
    if (
        attempt.state != "processing"
        or attempt.processing_lease_owner != lease_owner
        or attempt.processing_lease_expires_at is None
        or attempt.processing_lease_expires_at <= now
    ):
        return attempt
    attempt.state = "failed"
    attempt.registration_id = None
    attempt.attestation_id = None
    attempt.stable_response = None
    attempt.stable_response_sha256 = None
    attempt.registration_replay_until = now + timedelta(seconds=_REPLAY_SECONDS)
    attempt.processing_lease_owner = None
    attempt.processing_lease_expires_at = None
    attempt.failure_code = code[:128]
    attempt.failure_detail = detail[:2000]
    attempt.completed_at = now
    attempt.updated_at = now
    conflicts = list(
        (
            await db.execute(
                select(GpuRegistrationConflict)
                .where(
                    GpuRegistrationConflict.attempt_id == attempt.attempt_id,
                    GpuRegistrationConflict.state.in_(
                        ("recorded", "verifying", "verified_competitor")
                    ),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for conflict in conflicts:
        conflict.state = "dismissed"
        conflict.processing_lease_owner = None
        conflict.processing_lease_expires_at = None
        conflict.verification_detail = "primary registration attempt failed"
        conflict.verified_at = now
    await db.flush()
    return attempt


async def _complete_attempt(
    db: AsyncSession,
    attempt_id: str,
    lease_owner: str,
    result: dict,
) -> GpuRegistrationAttempt:
    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == attempt_id)
            .with_for_update()
        )
    ).scalar_one()
    if attempt.state == "completed":
        return attempt
    if attempt.state != "processing" or attempt.processing_lease_owner != lease_owner:
        return attempt
    now = _now()
    registration_id = generate_uuid()
    stable = {
        key: value
        for key, value in result.items()
        if key not in {"runtime_session", "runtime_session_expires_at"}
    }
    stable["registration_id"] = registration_id
    attempt.state = "completed"
    attempt.registration_id = registration_id
    attempt.attestation_id = result["attestation_id"]
    attempt.stable_response = stable
    attempt.stable_response_sha256 = canonical_sha256(stable)
    attempt.registration_replay_until = now + timedelta(seconds=_REPLAY_SECONDS)
    attempt.processing_lease_owner = None
    attempt.processing_lease_expires_at = None
    attempt.completed_at = now
    attempt.updated_at = now
    await db.flush()
    competitor_ids = list(
        (
            await db.execute(
                select(GpuRegistrationConflict.conflict_id)
                .where(
                    GpuRegistrationConflict.attempt_id == attempt_id,
                    GpuRegistrationConflict.state == "verified_competitor",
                )
                .order_by(GpuRegistrationConflict.conflict_id)
                .with_for_update()
            )
        ).scalars()
    )
    if competitor_ids:
        from api.host.gpu_allocations import request_gpu_lifecycle_fence

        await request_gpu_lifecycle_fence(
            db,
            attempt.reservation_id,
            code="gpu_registration_verified_competitor",
            reason="Independently verified requests competed for the completed nonce.",
            operation_type="normal_delete",
            metadata={
                "attempt_id": attempt.attempt_id,
                "conflict_ids": competitor_ids,
            },
        )
    return attempt


async def registration_attempt_response(
    db: AsyncSession,
    attempt: GpuRegistrationAttempt,
    expected_cert_hash: str,
) -> GpuRegistrationResponseV2:
    if not secrets.compare_digest(attempt.peer_spki_sha256, expected_cert_hash.lower()):
        raise HTTPException(
            status_code=404, detail="GPU registration attempt not found."
        )
    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == attempt.attempt_id)
            .with_for_update()
        )
    ).scalar_one()
    if attempt.state == "processing":
        return _processing_response(attempt)
    now = _now()
    if (
        attempt.registration_replay_until is None
        or attempt.registration_replay_until <= now
    ):
        nonce = (
            await db.execute(
                select(GpuRegistrationNonce)
                .where(GpuRegistrationNonce.nonce_id == attempt.nonce_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if nonce is not None:
            await _scrub_terminal_registration_material(db, nonce, attempt, now)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="GPU registration replay expired.",
        )
    if attempt.state == "failed":
        return _failed_response(attempt)

    stable = dict(attempt.stable_response or {})
    if (
        not stable
        or attempt.stable_response_sha256 is None
        or not secrets.compare_digest(
            attempt.stable_response_sha256, canonical_sha256(stable)
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="GPU registration stable response audit is invalid.",
        )
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == attempt.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    try:
        stable_claims = (
            GpuLaunchReservationClaimsV1.model_validate(reservation.claims)
            if reservation is not None
            else None
        )
    except ValueError:
        stable_claims = None
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(
                GpuAllocationGroup.allocation_group_id
                == stable.get("allocation_group_id")
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == stable.get("server_id"))
            .with_for_update()
        )
    ).scalar_one_or_none()
    attestation = (
        await db.execute(
            select(ServerAttestation)
            .where(ServerAttestation.attestation_id == attempt.attestation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    from api.node.schemas import Node

    host = (
        await db.execute(
            select(Host)
            .where(Host.host_id == (reservation.host_id if reservation else None))
            .with_for_update()
        )
    ).scalar_one_or_none()
    nodes = list(
        (
            await db.execute(
                select(Node)
                .where(
                    Node.server_id == stable.get("server_id"),
                    Node.gpu_retired_at.is_(None),
                )
                .order_by(Node.uuid)
                .with_for_update(of=Node)
            )
        )
        .scalars()
        .all()
    )
    node_uuids = [item.uuid for item in nodes]
    registration_report_ids = {
        item.gpu_inventory_report_id
        for item in nodes
        if item.gpu_inventory_report_id is not None
    }
    registration_report_id = (
        next(iter(registration_report_ids))
        if len(registration_report_ids) == 1
        else None
    )
    registration_report = (
        (
            await db.execute(
                select(GpuInventoryReport)
                .where(GpuInventoryReport.report_id == registration_report_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if registration_report_id is not None
        else None
    )
    current_report = (
        (
            await db.execute(
                select(GpuInventoryReport)
                .where(GpuInventoryReport.report_id == group.last_report_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if group is not None
        else None
    )
    from api.server.gpu_sessions import _gpu_inventory_report_matches_group

    exact_nodes = bool(
        reservation is not None
        and group is not None
        and host is not None
        and node_uuids == stable.get("gpu_uuids")
        and len(registration_report_ids) == 1
        and _gpu_inventory_report_matches_group(
            host=host,
            group=group,
            report=registration_report,
            expected_host_key_generation=reservation.host_key_generation,
            expected_host_boot_generation=reservation.host_boot_generation,
            require_host_latest=False,
            require_group_report_link=False,
        )
        and _gpu_inventory_report_matches_group(
            host=host,
            group=group,
            report=current_report,
            expected_host_key_generation=host.active_key_generation,
            expected_host_boot_generation=host.boot_generation,
            require_host_latest=True,
            require_group_report_link=True,
        )
        and all(
            item.gpu_allocation_group_id == stable.get("allocation_group_id")
            and item.gpu_allocation_group_generation
            == stable.get("allocation_group_generation")
            and item.gpu_launch_reservation_id == reservation.reservation_id
            and item.gpu_process_incarnation == reservation.process_incarnation
            and item.gpu_inventory_report_id == registration_report_id
            for item in nodes
        )
    )
    hotplug = None
    if reservation is not None and reservation.legacy_migration_id is not None:
        hotplug = (
            await db.execute(
                select(GpuHotplugCommand)
                .where(
                    GpuHotplugCommand.reservation_id == reservation.reservation_id,
                    GpuHotplugCommand.reservation_generation
                    == reservation.reservation_generation,
                    GpuHotplugCommand.claims_sha256 == reservation.claims_sha256,
                    GpuHotplugCommand.host_id == reservation.host_id,
                    GpuHotplugCommand.host_key_generation
                    == reservation.host_key_generation,
                    GpuHotplugCommand.host_boot_generation
                    == reservation.host_boot_generation,
                    GpuHotplugCommand.allocation_group_id
                    == reservation.allocation_group_id,
                    GpuHotplugCommand.allocation_group_generation
                    == reservation.allocation_group_generation,
                    GpuHotplugCommand.process_incarnation
                    == reservation.process_incarnation,
                    GpuHotplugCommand.stable_server_id == reservation.server_id,
                    GpuHotplugCommand.migration_id == reservation.legacy_migration_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if hotplug is None:
            raise HTTPException(
                status_code=409,
                detail="GPU legacy registration has no exact durable hotplug command.",
            )
        if hotplug.state == "failed":
            return GpuRegistrationResponseV2(
                attempt_id=attempt.attempt_id,
                state="failed",
                status_url=_status_url(attempt.attempt_id),
                failure_code=hotplug.failure_code or "gpu_hotplug_failed",
                failure_detail=hotplug.failure_reason or "Legacy GPU hotplug failed.",
            )

    exact = bool(
        reservation is not None
        and group is not None
        and server is not None
        and attestation is not None
        and host is not None
        and stable_claims is not None
        and reservation.claims
        == stable_claims.model_dump(mode="json", exclude_none=True)
        and reservation.claims_sha256 == canonical_sha256(stable_claims)
        and stable_claims.owner_hotkey == reservation.owner_hotkey
        and stable_claims.workload_owner == reservation.workload_owner
        and stable_claims.reservation_id == reservation.reservation_id
        and stable_claims.reservation_generation == reservation.reservation_generation
        and reservation.state == "running"
        and group.state == "running"
        and host.provisioning_state == "ready"
        and host.active_key_generation == reservation.host_key_generation
        and host.boot_generation == reservation.host_boot_generation
        and group.reservation_id == reservation.reservation_id
        and group.reservation_generation == reservation.reservation_generation
        and group.generation == reservation.allocation_group_generation
        and group.process_incarnation == reservation.process_incarnation
        and group.reservation_owner == reservation.workload_owner
        and host.miner_hotkey == reservation.owner_hotkey
        and group.management_mode == reservation.management_mode
        and reservation.registration_attestation_id == attempt.attestation_id
        and reservation.claims_sha256 == stable.get("claims_sha256")
        and reservation.server_id == stable.get("server_id")
        and reservation.owner_hotkey == stable.get("owner_hotkey")
        and reservation.allocation_group_id == stable.get("allocation_group_id")
        and reservation.allocation_group_generation
        == stable.get("allocation_group_generation")
        and reservation.process_incarnation == stable.get("process_incarnation")
        and reservation.management_mode == stable.get("management_mode")
        and server.gpu_retired_at is None
        and server.gpu_launch_reservation_id == reservation.reservation_id
        and server.gpu_allocation_group_id == reservation.allocation_group_id
        and server.gpu_allocation_group_generation
        == reservation.allocation_group_generation
        and server.gpu_process_incarnation == reservation.process_incarnation
        and server.gpu_management_mode == reservation.management_mode
        and server.attested_cert_pubkey_hash == attempt.peer_spki_sha256
        and server.attested_cert == attempt.peer_certificate_pem
        and attestation.server_id == server.server_id
        and attestation.verified_at is not None
        and attestation.verification_error is None
        and attestation.gpu_retired_at is None
        and attestation.gpu_launch_reservation_id == reservation.reservation_id
        and attestation.gpu_allocation_group_id == reservation.allocation_group_id
        and attestation.gpu_allocation_group_generation
        == reservation.allocation_group_generation
        and attestation.gpu_process_incarnation == reservation.process_incarnation
        and attestation.gpu_claims_sha256 == reservation.claims_sha256
        and attempt.registration_id == stable.get("registration_id")
        and attempt.attestation_id == stable.get("attestation_id")
        and exact_nodes
    )
    if not exact:
        raise HTTPException(
            status_code=409,
            detail="GPU registration lineage is no longer active.",
        )
    if hotplug is not None and hotplug.state in {"pending", "leased", "dispatched"}:
        # Registration/attestation identity is complete, but runtime authority
        # remains withheld until the exact backend+frontend QMP ACK is durable.
        return _processing_response(attempt)
    if hotplug is not None and (
        hotplug.state != "acked"
        or hotplug.ack is None
        or hotplug.ack_sha256 is None
        or hotplug.acknowledged_at is None
    ):
        raise HTTPException(
            status_code=409,
            detail="GPU legacy hotplug acknowledgement is incomplete.",
        )

    from api.server.gpu_sessions import latest_gpu_runtime_session

    (
        runtime_session,
        runtime_expiry,
        operational_attestation_id,
    ) = await latest_gpu_runtime_session(db, server)
    server.gpu_runtime_session_attestation_id = operational_attestation_id
    server.gpu_runtime_session_expires_at = runtime_expiry
    await db.commit()
    return GpuRegistrationResponseV2(
        attempt_id=attempt.attempt_id,
        state="completed",
        status_url=_status_url(attempt.attempt_id),
        registration_replay_until=attempt.registration_replay_until,
        runtime_session=runtime_session,
        runtime_session_expires_at=runtime_expiry,
        **stable,
    )


async def get_gpu_registration_attempt(
    db: AsyncSession,
    attempt_id: str,
    expected_cert_hash: str,
) -> GpuRegistrationResponseV2:
    attempt, lease_owner = await _claim_processing_lease(
        db, attempt_id, expected_cert_hash
    )
    await db.commit()
    if lease_owner is not None:
        return await _run_registration_attempt(
            db,
            attempt.attempt_id,
            lease_owner,
            expected_cert_hash,
        )
    return await registration_attempt_response(db, attempt, expected_cert_hash)


async def _verify_recorded_conflict(
    db: AsyncSession,
    conflict: GpuRegistrationConflict,
    request: GpuRegistrationRequestV2,
    expected_cert_hash: str,
    cert_pem: str,
) -> str:
    """Verify a competitor outside locks, then publish only under exact lineage CAS."""

    lease_owner = generate_uuid()
    audit = _registration_request_audit(request, expected_cert_hash, cert_pem)
    await acquire_gpu_lifecycle_lock(db)
    row = (
        await db.execute(
            select(GpuRegistrationConflict)
            .where(GpuRegistrationConflict.conflict_id == conflict.conflict_id)
            .with_for_update()
        )
    ).scalar_one()
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == row.attempt_id)
            .with_for_update()
        )
    ).scalar_one()
    now = _now()
    if attempt.state == "failed":
        if row.state not in {"invalid", "dismissed"}:
            row.state = "dismissed"
            row.processing_lease_owner = None
            row.processing_lease_expires_at = None
            row.verification_detail = "primary registration attempt failed"
            row.verified_at = now
        await db.commit()
        return row.state
    if row.state in {"invalid", "verified_competitor", "dismissed"}:
        await db.commit()
        return row.state
    if (
        row.state == "verifying"
        and row.processing_lease_expires_at is not None
        and row.processing_lease_expires_at > now
    ):
        await db.commit()
        return "verifying"
    immutable_conflict = bool(
        row.attempt_id == attempt.attempt_id
        and row.nonce_id == request.nonce_id
        and row.request_payload == audit["request_payload"]
        and secrets.compare_digest(row.request_sha256, str(audit["request_sha256"]))
        and row.peer_certificate_pem == audit["peer_certificate_pem"]
        and secrets.compare_digest(
            row.peer_certificate_sha256,
            str(audit["peer_certificate_sha256"]),
        )
        and secrets.compare_digest(row.peer_spki_sha256, str(audit["peer_spki_sha256"]))
        and secrets.compare_digest(row.quote_sha256, str(audit["quote_sha256"]))
        and secrets.compare_digest(row.evidence_sha256, str(audit["evidence_sha256"]))
        and secrets.compare_digest(row.signature_sha256, str(audit["signature_sha256"]))
    )
    if not immutable_conflict:
        row.state = "invalid"
        row.processing_lease_owner = None
        row.processing_lease_expires_at = None
        row.verification_detail = "conflict audit bytes changed before verification"
        row.verified_at = now
        await db.commit()
        return row.state
    row.state = "verifying"
    row.processing_lease_owner = lease_owner
    row.processing_lease_expires_at = now + timedelta(seconds=_PROCESSING_LEASE_SECONDS)
    await db.commit()

    verified_gpu_evidence = None
    try:
        _, _, verified_gpu_evidence = await verify_gpu_registration_evidence(
            db,
            request,
            request.nonce,
            expected_cert_hash,
            cert_pem,
        )
        evidence_valid = True
        detail = "conflicting request independently verified"
    except Exception as exc:  # evidence failures are audit data, not fencing authority
        evidence_valid = False
        detail = str(getattr(exc, "detail", exc))[:2000]

    await acquire_gpu_lifecycle_lock(db)
    row = (
        await db.execute(
            select(GpuRegistrationConflict)
            .where(GpuRegistrationConflict.conflict_id == conflict.conflict_id)
            .with_for_update()
        )
    ).scalar_one()
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(GpuRegistrationAttempt.attempt_id == row.attempt_id)
            .with_for_update()
        )
    ).scalar_one()
    nonce = (
        await db.execute(
            select(GpuRegistrationNonce)
            .where(GpuRegistrationNonce.nonce_id == row.nonce_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    identity = (
        await db.execute(
            select(
                GpuLaunchReservation.host_id,
                GpuLaunchReservation.allocation_group_id,
            ).where(GpuLaunchReservation.reservation_id == attempt.reservation_id)
        )
    ).one_or_none()
    host = (
        (
            await db.execute(
                select(Host).where(Host.host_id == identity.host_id).with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    group = (
        (
            await db.execute(
                select(GpuAllocationGroup)
                .where(
                    GpuAllocationGroup.allocation_group_id
                    == identity.allocation_group_id
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if identity is not None
        else None
    )
    report = (
        (
            await db.execute(
                select(GpuInventoryReport)
                .where(GpuInventoryReport.report_id == group.last_report_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if group is not None
        else None
    )
    reservation = (
        await db.execute(
            select(GpuLaunchReservation)
            .where(GpuLaunchReservation.reservation_id == attempt.reservation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    server = (
        (
            await db.execute(
                select(Server)
                .where(Server.server_id == reservation.server_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if reservation is not None
        else None
    )
    if row.state in {"invalid", "verified_competitor", "dismissed"}:
        await db.commit()
        return row.state
    if row.state != "verifying" or row.processing_lease_owner != lease_owner:
        await db.commit()
        return row.state

    now = _now()
    if attempt.state == "failed":
        final_state = "dismissed"
        detail = "primary registration attempt failed"
    elif not evidence_valid:
        final_state = "invalid"
    elif attempt.state == "processing":
        primary_request = None
        if attempt.request_payload is not None:
            try:
                primary_request = GpuRegistrationRequestV2.model_validate(
                    attempt.request_payload
                )
            except ValueError:
                primary_request = None
        try:
            _, conflict_token_hash = _parse_reservation_token(
                request.launch_reservation
            )
            _, primary_token_hash = (
                _parse_reservation_token(primary_request.launch_reservation)
                if primary_request is not None
                else ("", "")
            )
        except HTTPException:
            conflict_token_hash = ""
            primary_token_hash = ""
        claims_document = request.quote_commitment.claims.model_dump(
            mode="json", exclude_none=True
        )
        primary_claims_document = (
            primary_request.quote_commitment.claims.model_dump(
                mode="json", exclude_none=True
            )
            if primary_request is not None
            else None
        )
        exact = bool(
            nonce is not None
            and reservation is not None
            and group is not None
            and report is not None
            and host is not None
            and verified_gpu_evidence is not None
            and row.attempt_id == attempt.attempt_id
            and row.nonce_id == nonce.nonce_id == attempt.nonce_id
            and request.nonce_id == nonce.nonce_id
            and nonce.state == "claimed"
            and nonce.claimed_attempt_id == attempt.attempt_id
            and nonce.reservation_id
            == attempt.reservation_id
            == reservation.reservation_id
            and nonce.nonce_value is not None
            and primary_request is not None
            and secrets.compare_digest(nonce.nonce_value, request.nonce)
            and secrets.compare_digest(nonce.nonce_value, primary_request.nonce)
            and secrets.compare_digest(
                nonce.nonce_hash,
                hashlib.sha256(bytes.fromhex(request.nonce)).hexdigest(),
            )
            and secrets.compare_digest(nonce.peer_spki_sha256, attempt.peer_spki_sha256)
            and row.request_payload == audit["request_payload"]
            and secrets.compare_digest(row.request_sha256, str(audit["request_sha256"]))
            and row.peer_certificate_pem == audit["peer_certificate_pem"]
            and secrets.compare_digest(
                row.peer_certificate_sha256,
                str(audit["peer_certificate_sha256"]),
            )
            and secrets.compare_digest(
                row.peer_spki_sha256, str(audit["peer_spki_sha256"])
            )
            and secrets.compare_digest(row.quote_sha256, str(audit["quote_sha256"]))
            and secrets.compare_digest(
                row.evidence_sha256, str(audit["evidence_sha256"])
            )
            and secrets.compare_digest(
                row.signature_sha256, str(audit["signature_sha256"])
            )
            and attempt.request_payload
            == primary_request.model_dump(mode="json", exclude_none=True)
            and secrets.compare_digest(
                attempt.request_sha256, primary_request.request_sha256()
            )
            and request.quote_commitment.attested_spki_sha256 == row.peer_spki_sha256
            and primary_request.quote_commitment.attested_spki_sha256
            == attempt.peer_spki_sha256
            and not secrets.compare_digest(attempt.request_sha256, row.request_sha256)
            and secrets.compare_digest(reservation.token_hash, conflict_token_hash)
            and secrets.compare_digest(reservation.token_hash, primary_token_hash)
            and reservation.claims == claims_document == primary_claims_document
            and secrets.compare_digest(
                reservation.claims_sha256, canonical_sha256(claims_document)
            )
            and _registration_lineage_current(
                host,
                group,
                report,
                reservation,
                request,
                conflict_token_hash,
                allowed_states={"launching", "running"},
            )
        )
        if exact:
            try:
                selected_devices = await _selected_gpu_inventory_devices(
                    db,
                    reservation,
                    group,
                    request.gpu_uuids,
                    verified_gpu_evidence,
                )
                exact = [item.uuid for item in selected_devices] == request.gpu_uuids
            except ServerRegistrationError as exc:
                exact = False
                detail = str(getattr(exc, "detail", exc))[:2000]
        final_state = "verified_competitor" if exact else "invalid"
        if exact:
            detail = (
                "conflicting request independently verified; fencing is deferred "
                "until primary completion"
            )
        elif detail == "conflicting request independently verified":
            detail = (
                "conflicting request evidence verified but processing lineage, "
                "inventory selection, or immutable audit bytes changed"
            )
    elif attempt.state != "completed":
        final_state = "dismissed"
        detail = "primary registration attempt is not replayable"
    else:
        primary_request = None
        if attempt.request_payload is not None:
            try:
                primary_request = GpuRegistrationRequestV2.model_validate(
                    attempt.request_payload
                )
            except ValueError:
                primary_request = None
        try:
            _, conflict_token_hash = _parse_reservation_token(
                request.launch_reservation
            )
            _, primary_token_hash = (
                _parse_reservation_token(primary_request.launch_reservation)
                if primary_request is not None
                else ("", "")
            )
        except HTTPException:
            conflict_token_hash = ""
            primary_token_hash = ""
        claims = request.quote_commitment.claims
        claims_document = claims.model_dump(mode="json", exclude_none=True)
        primary_claims_document = (
            primary_request.quote_commitment.claims.model_dump(
                mode="json", exclude_none=True
            )
            if primary_request is not None
            else None
        )
        audit_unchanged = bool(
            row.request_payload == audit["request_payload"]
            and secrets.compare_digest(row.request_sha256, str(audit["request_sha256"]))
            and row.peer_certificate_pem == audit["peer_certificate_pem"]
            and secrets.compare_digest(
                row.peer_certificate_sha256,
                str(audit["peer_certificate_sha256"]),
            )
            and secrets.compare_digest(
                row.peer_spki_sha256, str(audit["peer_spki_sha256"])
            )
            and secrets.compare_digest(row.quote_sha256, str(audit["quote_sha256"]))
            and secrets.compare_digest(
                row.evidence_sha256, str(audit["evidence_sha256"])
            )
            and secrets.compare_digest(
                row.signature_sha256, str(audit["signature_sha256"])
            )
        )
        exact = bool(
            attempt.registration_replay_until is not None
            and attempt.registration_replay_until > now
            and nonce is not None
            and reservation is not None
            and group is not None
            and report is not None
            and host is not None
            and server is not None
            and row.attempt_id == attempt.attempt_id
            and row.nonce_id == nonce.nonce_id == attempt.nonce_id
            and request.nonce_id == nonce.nonce_id
            and nonce.state == "claimed"
            and nonce.claimed_attempt_id == attempt.attempt_id
            and nonce.reservation_id
            == attempt.reservation_id
            == reservation.reservation_id
            and nonce.nonce_value is not None
            and primary_request is not None
            and secrets.compare_digest(nonce.nonce_value, request.nonce)
            and secrets.compare_digest(nonce.nonce_value, primary_request.nonce)
            and secrets.compare_digest(
                nonce.nonce_hash,
                hashlib.sha256(bytes.fromhex(request.nonce)).hexdigest(),
            )
            and secrets.compare_digest(nonce.peer_spki_sha256, attempt.peer_spki_sha256)
            and audit_unchanged
            and attempt.request_payload
            == primary_request.model_dump(mode="json", exclude_none=True)
            and secrets.compare_digest(
                attempt.request_sha256, primary_request.request_sha256()
            )
            and attempt.peer_certificate_pem is not None
            and secrets.compare_digest(
                attempt.peer_certificate_sha256,
                hashlib.sha256(
                    attempt.peer_certificate_pem.encode("utf-8")
                ).hexdigest(),
            )
            and primary_request.quote_commitment.attested_spki_sha256
            == attempt.peer_spki_sha256
            and request.quote_commitment.attested_spki_sha256 == row.peer_spki_sha256
            and not (
                secrets.compare_digest(attempt.request_sha256, row.request_sha256)
                and secrets.compare_digest(
                    attempt.peer_spki_sha256, row.peer_spki_sha256
                )
                and secrets.compare_digest(
                    attempt.peer_certificate_sha256,
                    row.peer_certificate_sha256,
                )
            )
            and secrets.compare_digest(reservation.token_hash, conflict_token_hash)
            and secrets.compare_digest(reservation.token_hash, primary_token_hash)
            and reservation.claims == claims_document == primary_claims_document
            and secrets.compare_digest(
                reservation.claims_sha256, canonical_sha256(claims_document)
            )
            and request.quote_commitment.reservation_sha256 == reservation.claims_sha256
            and primary_request.quote_commitment.reservation_sha256
            == reservation.claims_sha256
            and reservation.guest_consumed_at is not None
            and reservation.registration_attestation_id == attempt.attestation_id
            and _registration_lineage_current(
                host,
                group,
                report,
                reservation,
                request,
                conflict_token_hash,
                allowed_states={"running"},
            )
            and server.server_id == reservation.server_id == request.server_id
            and server.miner_hotkey == reservation.owner_hotkey
            and server.gpu_launch_reservation_id == reservation.reservation_id
            and server.gpu_allocation_group_id == reservation.allocation_group_id
            and server.gpu_allocation_group_generation
            == reservation.allocation_group_generation
            and server.gpu_management_mode == reservation.management_mode
            and server.gpu_process_incarnation == reservation.process_incarnation
            and server.gpu_retired_at is None
        )
        if exact:
            try:
                selected_uuids = await _validate_runtime_gpu_selection(
                    db,
                    server,
                    reservation,
                    claims,
                    verified_gpu_evidence,
                )
                exact = selected_uuids == request.gpu_uuids
            except (InvalidGpuEvidenceError, ServerRegistrationError) as exc:
                exact = False
                detail = str(getattr(exc, "detail", exc))[:2000]
        final_state = "verified_competitor" if exact else "invalid"
        if (
            evidence_valid
            and not exact
            and detail == "conflicting request independently verified"
        ):
            detail = (
                "conflicting request evidence verified but post-verification "
                "lineage, node selection, or immutable audit bytes changed"
            )
    row.state = final_state
    row.processing_lease_owner = None
    row.processing_lease_expires_at = None
    row.verification_detail = detail
    row.verified_at = _now()
    if final_state == "verified_competitor" and attempt.state == "completed":
        from api.host.gpu_allocations import request_gpu_lifecycle_fence

        await request_gpu_lifecycle_fence(
            db,
            reservation.reservation_id,
            code="gpu_registration_verified_competitor",
            reason=(
                "A second independently verified request used the completed "
                "registration nonce."
            ),
            operation_type="normal_delete",
            metadata={
                "attempt_id": attempt.attempt_id,
                "conflict_id": row.conflict_id,
            },
        )
    await db.commit()
    return final_state


async def _run_registration_attempt(
    db: AsyncSession,
    attempt_id: str,
    lease_owner: str,
    expected_cert_hash: str,
) -> GpuRegistrationResponseV2:
    """Resume one persisted attempt through external verification and lease-CAS publish."""

    snapshot: Optional[_RegistrationAttemptSnapshot] = None
    try:
        snapshot = await _locked_processing_snapshot(db, attempt_id, lease_owner)
        await db.commit()
        result = await register_gpu_server(
            db,
            snapshot.server_ip_audit,
            snapshot.request,
            snapshot.request.nonce,
            snapshot.spki_sha256,
            snapshot.cert_pem,
            before_publish=lambda: _assert_processing_lease_before_publish(
                db, snapshot
            ),
        )
        attempt = await _complete_attempt(db, attempt_id, lease_owner, result)
        completed_reservation = (
            (
                await db.execute(
                    select(GpuLaunchReservation)
                    .where(
                        GpuLaunchReservation.reservation_id
                        == snapshot.request.quote_commitment.claims.reservation_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if attempt.state == "completed"
            else None
        )
        completed_group = (
            (
                await db.execute(
                    select(GpuAllocationGroup)
                    .where(
                        GpuAllocationGroup.allocation_group_id
                        == completed_reservation.allocation_group_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if completed_reservation is not None
            else None
        )
        hotplug_command = (
            await ensure_gpu_hotplug_command(db, completed_reservation.reservation_id)
            if completed_reservation is not None
            and completed_group is not None
            and completed_reservation.state == "running"
            and completed_group.state == "running"
            and completed_reservation.registration_attestation_id
            == attempt.attestation_id
            and completed_group.reservation_id == completed_reservation.reservation_id
            and completed_group.reservation_generation
            == completed_reservation.reservation_generation
            and completed_group.process_incarnation
            == completed_reservation.process_incarnation
            else None
        )
        await db.commit()
        if hotplug_command is not None and attempt.state == "completed":
            try:
                await dispatch_gpu_hotplug_command(hotplug_command.command_id)
            except Exception as dispatch_exc:  # noqa: BLE001
                logger.error(
                    "Durable GPU hotplug dispatch remains retryable for "
                    f"{hotplug_command.command_id}: {dispatch_exc}"
                )
    except GpuRegistrationLeaseLost:
        await db.rollback()
        attempt = await db.get(GpuRegistrationAttempt, attempt_id)
        if attempt is None:
            raise HTTPException(
                status_code=404, detail="GPU registration attempt not found."
            )
        return await registration_attempt_response(db, attempt, expected_cert_hash)
    except GpuHotplugError as exc:
        await db.rollback()
        attempt = await _mark_attempt_failed(
            db,
            attempt_id,
            lease_owner,
            "gpu_legacy_hotplug_custody_mismatch",
            str(exc),
        )
        if (
            attempt.state == "failed"
            and attempt.failure_code == "gpu_legacy_hotplug_custody_mismatch"
        ):
            from api.host.gpu_allocations import (
                quarantine_gpu_reservation_control_plane,
            )

            await quarantine_gpu_reservation_control_plane(
                db,
                attempt.reservation_id,
                code="gpu_legacy_hotplug_custody_mismatch",
                reason=str(exc)[:2000],
                metadata={"registration_attempt_id": attempt.attempt_id},
            )
        await db.commit()
        if attempt.state == "failed":
            return _failed_response(attempt)
        return await registration_attempt_response(db, attempt, expected_cert_hash)
    except (AttestationError, ServerRegistrationError, HTTPException) as exc:
        await db.rollback()
        detail = str(getattr(exc, "detail", exc))
        attempt = await _mark_attempt_failed(
            db,
            attempt_id,
            lease_owner,
            "gpu_registration_verification_failed",
            detail,
        )
        await db.commit()
        if attempt.state == "failed":
            return _failed_response(attempt)
        return await registration_attempt_response(db, attempt, expected_cert_hash)
    return await registration_attempt_response(db, attempt, expected_cert_hash)


async def process_gpu_registration(
    db: AsyncSession,
    server_ip: str,
    request: GpuRegistrationRequestV2,
    expected_cert_hash: str,
    cert_pem: str,
) -> tuple[GpuRegistrationResponseV2, int]:
    attempt, lease_owner, conflict = await _claim_attempt(
        db,
        server_ip,
        request,
        expected_cert_hash,
        cert_pem,
    )
    await (
        db.commit()
    )  # nonce claim and attempt creation become durable before verification
    if conflict is not None:
        conflict_state = await _verify_recorded_conflict(
            db,
            conflict,
            request,
            expected_cert_hash,
            cert_pem,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "code": "gpu_registration_conflict",
                "conflict_id": conflict.conflict_id,
                "state": conflict_state,
                "retry_after_seconds": (
                    _RETRY_AFTER_SECONDS if conflict_state == "verifying" else None
                ),
            },
        )
    if lease_owner is None:
        response = await registration_attempt_response(db, attempt, expected_cert_hash)
        return response, 202 if response.state == "processing" else 200
    response = await _run_registration_attempt(
        db,
        attempt.attempt_id,
        lease_owner,
        expected_cert_hash,
    )
    return response, 202 if response.state == "processing" else 200
