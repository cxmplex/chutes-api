"""Short-lived, current-attestation-bound GPU miner runtime sessions."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import settings
from api.database import generate_uuid
from api.gpu_hotplug_service import (
    GpuHotplugError,
    require_gpu_hotplug_runtime_ack,
)
from api.gpu_models import GpuRegistrationAttempt
from api.host.locks import acquire_gpu_lifecycle_lock
from api.host.schemas import (
    GpuAllocationGroup,
    GpuInventoryReport,
    GpuInventoryReportV1,
    GpuLaunchReservation,
    canonical_sha256,
)
from api.node.schemas import Node
from api.server.schemas import GpuServerDecommission, Host, Server, ServerAttestation

GPU_RUNTIME_SESSION_HEADER = "X-Chutes-Attested-Session"
GPU_RUNTIME_SESSION_VERSION_HEADER = "X-Chutes-GPU-Runtime-Session-Version"
GPU_RUNTIME_SESSION_VERSION_V1 = 1
GPU_RUNTIME_SESSION_VERSION_V2 = 2
GPU_RUNTIME_SESSION_PURPOSES_V1 = (
    "cache",
    "gpu-infra",
    "instances",
    "launch",
    "miner",
    "nodes",
    "registry",
    "sockets",
)
GPU_RUNTIME_SESSION_PURPOSES_V2 = (
    "cache",
    "gpu-decommission",
    "gpu-infra",
    "instances",
    "launch",
    "miner",
    "nodes",
    "registry",
    "sockets",
)
# The unqualified name remains the immutable production v1 contract. Callers
# that opt into v2 must do so explicitly so an API-first rollout keeps serving
# byte-compatible responses to old agents.
GPU_RUNTIME_SESSION_PURPOSES = GPU_RUNTIME_SESSION_PURPOSES_V1
GPU_PLATFORM_RUNTIME_SESSION_PURPOSES = ("registry",)
GPU_RUNTIME_SESSION_LIFETIME_SECONDS = 900
GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS = 5


def _gpu_runtime_session_purposes(
    management_mode: str,
    version: int,
) -> tuple[str, ...]:
    if type(version) is not int or version not in {
        GPU_RUNTIME_SESSION_VERSION_V1,
        GPU_RUNTIME_SESSION_VERSION_V2,
    }:
        raise ValueError("Unsupported GPU runtime session version")
    if management_mode == "platform":
        return GPU_PLATFORM_RUNTIME_SESSION_PURPOSES
    if management_mode == "miner":
        return (
            GPU_RUNTIME_SESSION_PURPOSES_V1
            if version == GPU_RUNTIME_SESSION_VERSION_V1
            else GPU_RUNTIME_SESSION_PURPOSES_V2
        )
    raise ValueError("Unsupported GPU runtime session management mode")


def _gpu_decommission_reservation_is_terminal(reservation: GpuLaunchReservation) -> bool:
    """Require positive pre-launch expiry or completed physical reset evidence."""

    if reservation.state == "released":
        return reservation.reset_completed_at is not None and reservation.released_at is not None
    if reservation.state == "expired":
        return all(
            getattr(reservation, field) is None
            for field in ("claimed_at", "launching_at", "running_at", "launch_dispatched_at")
        )
    return False


def _runtime_session_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class CompletedGpuRegistrationAuthority:
    """Immutable Registration V2 authority kept separate from operational evidence."""

    attempt: GpuRegistrationAttempt
    registration_attestation: ServerAttestation
    gpu_uuids: tuple[str, ...]
    gpu_identifiers: tuple[str, ...]
    gpu_certificate_sha256s: tuple[str, ...]


def _revocation_failed(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_revocation_failed(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_revocation_failed(item) for item in value)
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in {
        "good",
        "not_revoked",
        "not-revoked",
        "unrevoked",
        "authenticated_outage_grace",
        "revocation_not_advertised",
    }:
        return False
    # New verifier states must be explicitly classified before they can grant
    # runtime authority. Unknown scalar values fail closed.
    return True


def _current_attestation_identity(
    server: Server,
    attestation: ServerAttestation | None,
    *,
    expected_id: str | None = None,
) -> ServerAttestation:
    """Require the latest CPU or GPU attempt to preserve active server authority."""

    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.release_attestation_max_age_seconds
    )
    if (
        attestation is None
        or (expected_id is not None and attestation.attestation_id != expected_id)
        or attestation.server_id != server.server_id
        or attestation.verification_error is not None
        or attestation.verified_at is None
        or attestation.verified_at < cutoff
        or attestation.measurement_name != server.measurement_name
        or attestation.measurement_config_fingerprint != server.measurement_config_fingerprint
        or attestation.trust_set_fingerprint != server.trust_set_fingerprint
        or dict(attestation.revocation_status or {})
        != dict(server.attestation_revocation_status or {})
        or _revocation_failed(attestation.revocation_status)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Latest attestation attempt is not current and successful.",
        )
    return attestation


def _current_attestation(
    server: Server,
    attestation: ServerAttestation | None,
    *,
    expected_id: str | None = None,
) -> ServerAttestation:
    try:
        attestation = _current_attestation_identity(server, attestation, expected_id=expected_id)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Latest GPU attestation attempt is not current and successful.",
        ) from exc
    if (
        attestation.gpu_retired_at is not None
        or attestation.gpu_launch_reservation_id != server.gpu_launch_reservation_id
        or attestation.gpu_allocation_group_id != server.gpu_allocation_group_id
        or attestation.gpu_allocation_group_generation != server.gpu_allocation_group_generation
        or attestation.gpu_management_mode != server.gpu_management_mode
        or attestation.gpu_process_incarnation != server.gpu_process_incarnation
        or attestation.gpu_topology_fingerprint != server.gpu_topology_fingerprint
        or not attestation.gpu_evidence_sha256
        or not attestation.gpu_evidence_certificate_sha256s
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Latest GPU attestation attempt is not current and successful.",
        )
    return attestation


async def _latest_attestation_attempt(
    db: AsyncSession,
    server_id: str,
    *,
    for_update: bool = False,
) -> ServerAttestation | None:
    query = (
        select(ServerAttestation)
        .where(ServerAttestation.server_id == server_id)
        .order_by(ServerAttestation.attempt_sequence.desc())
        .limit(1)
    )
    if for_update:
        query = query.with_for_update()
    return (await db.execute(query)).scalar_one_or_none()


def _gpu_inventory_report_matches_group(
    *,
    host: Host,
    group: GpuAllocationGroup,
    report: GpuInventoryReport | None,
    expected_host_key_generation: int,
    expected_host_boot_generation: int,
    require_host_latest: bool,
    require_group_report_link: bool,
) -> bool:
    """Validate immutable registration evidence or the mutable current closure."""

    if report is None:
        return False
    try:
        claims = GpuInventoryReportV1.model_validate(report.claims)
    except ValueError:
        return False
    matching_groups = [
        item
        for item in claims.groups
        if item.topology_fingerprint == group.topology_fingerprint
        and [device.bdf for device in item.devices] == list(group.gpu_bdfs)
        and [device.uuid for device in item.devices] == list(group.gpu_uuids)
        and [device.gpu_identifier for device in item.devices] == list(group.gpu_identifiers)
        and [device.attestation_certificate_sha256 for device in item.devices]
        == list(group.gpu_attestation_certificate_sha256s)
    ]
    return bool(
        len(matching_groups) == 1
        and report.reconciliation_status == "accepted"
        and secrets.compare_digest(report.claims_sha256, canonical_sha256(claims))
        and report.report_id == claims.report_id
        and report.report_generation == claims.report_generation
        and report.host_id == claims.host_id == host.host_id == group.host_id
        and report.host_key_generation == claims.host_key_generation == expected_host_key_generation
        and report.host_boot_generation
        == claims.host_boot_generation
        == expected_host_boot_generation
        and claims.host_boot_id == host.boot_id
        and report.gpu_release_id == claims.gpu_release_id == group.gpu_release_id
        and report.profile_contract_sha256
        == claims.profile_contract_sha256
        == group.profile_contract_sha256
        and report.topology_fingerprint == group.topology_fingerprint
        and (not require_group_report_link or group.last_report_id == report.report_id)
        and (
            not require_host_latest
            or (
                expected_host_key_generation == host.active_key_generation
                and expected_host_boot_generation == host.boot_generation
                and report.report_generation == host.gpu_inventory_report_generation
            )
        )
    )


async def _completed_gpu_registration_authority(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    operational_attestation: ServerAttestation | None,
    server: Server,
) -> CompletedGpuRegistrationAuthority:
    """Validate completed Registration V2 authority and optional operational evidence."""

    await acquire_gpu_lifecycle_lock(db)
    attempt = (
        await db.execute(
            select(GpuRegistrationAttempt)
            .where(
                GpuRegistrationAttempt.reservation_id == reservation.reservation_id,
                GpuRegistrationAttempt.registration_generation
                == reservation.registration_generation,
                GpuRegistrationAttempt.state == "completed",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if attempt is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU registration attempt is not durably completed.",
        )
    registration_attestation = (
        (
            await db.execute(
                select(ServerAttestation)
                .where(ServerAttestation.attestation_id == reservation.registration_attestation_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if reservation.registration_attestation_id is not None
        else None
    )
    group = (
        await db.execute(
            select(GpuAllocationGroup)
            .where(GpuAllocationGroup.allocation_group_id == reservation.allocation_group_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    host = (
        await db.execute(select(Host).where(Host.host_id == reservation.host_id).with_for_update())
    ).scalar_one_or_none()
    stable = dict(attempt.stable_response or {})
    expected_stable_keys = {
        "server_id",
        "owner_hotkey",
        "reservation_id",
        "claims_sha256",
        "allocation_group_id",
        "allocation_group_generation",
        "process_incarnation",
        "gpu_uuids",
        "gpu_identifiers",
        "management_mode",
        "measurement_version",
        "measurement_name",
        "measurement_config_fingerprint",
        "trust_set_fingerprint",
        "attestation_id",
        "verified_at",
        "status",
        "registration_id",
    }
    stable_uuids = stable.get("gpu_uuids")
    stable_identifiers = stable.get("gpu_identifiers")
    expected_evidence_certificates: list[str] = []
    try:
        inventory_by_uuid = dict(
            zip(reservation.gpu_uuids, reservation.gpu_identifiers, strict=True)
        )
        certificate_by_uuid = dict(
            zip(
                reservation.gpu_uuids,
                reservation.gpu_attestation_certificate_sha256s,
                strict=True,
            )
        )
        expected_evidence_certificates = [
            certificate_by_uuid[gpu_uuid] for gpu_uuid in stable_uuids
        ]
    except (KeyError, TypeError, ValueError):
        selected_matches = False
    else:
        selected_matches = bool(
            isinstance(stable_uuids, list)
            and all(isinstance(gpu_uuid, str) for gpu_uuid in stable_uuids)
            and stable_uuids
            and stable_uuids == sorted(set(stable_uuids))
            and isinstance(stable_identifiers, list)
            and len(stable_identifiers) == len(stable_uuids)
            and stable_identifiers == [inventory_by_uuid[gpu_uuid] for gpu_uuid in stable_uuids]
            and registration_attestation is not None
            and registration_attestation.gpu_evidence_certificate_sha256s
            == expected_evidence_certificates
            and _gpu_selection_matches_registration(
                management_mode=reservation.management_mode,
                reservation_uuids=list(reservation.gpu_uuids),
                registered_uuids=stable_uuids,
                registered_certificates=expected_evidence_certificates,
            )
        )
    try:
        from api.host.gpu_allocations import _validate_row_claims

        _validate_row_claims(reservation)
        claims_current = True
    except ValueError:
        claims_current = False
    selection_uuids = stable_uuids if isinstance(stable_uuids, list) else []
    nodes = list(
        (
            await db.execute(
                select(Node)
                .where(Node.uuid.in_(selection_uuids))
                .order_by(Node.uuid)
                .with_for_update(of=Node)
            )
        ).scalars()
    )
    nodes_by_uuid = {node.uuid: node for node in nodes}
    registration_report_ids = {
        node.gpu_inventory_report_id for node in nodes if node.gpu_inventory_report_id is not None
    }
    registration_report_id = (
        next(iter(registration_report_ids)) if len(registration_report_ids) == 1 else None
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
    nodes_current = bool(
        group is not None
        and host is not None
        and len(nodes_by_uuid) == len(selection_uuids)
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
            (node := nodes_by_uuid.get(gpu_uuid)) is not None
            and node.server_id == server.server_id
            and node.miner_hotkey == server.miner_hotkey
            and node.gpu_identifier == stable_identifiers[index]
            and node.gpu_allocation_group_id == reservation.allocation_group_id
            and node.gpu_allocation_group_generation == reservation.allocation_group_generation
            and node.gpu_launch_reservation_id == reservation.reservation_id
            and node.gpu_process_incarnation == reservation.process_incarnation
            and node.gpu_inventory_report_id == registration_report_id
            and node.gpu_retired_at is None
            for index, gpu_uuid in enumerate(selection_uuids)
        )
    )
    certificate_sha256 = (
        hashlib.sha256(server.attested_cert.encode("utf-8")).hexdigest()
        if server.attested_cert is not None
        else None
    )
    registration_exact = bool(
        set(stable) == expected_stable_keys
        and selected_matches
        and attempt.registration_generation == reservation.registration_generation
        and attempt.attestation_id
        == registration_attestation.attestation_id
        == reservation.registration_attestation_id
        and attempt.registration_id is not None
        and attempt.stable_response_sha256 is not None
        and secrets.compare_digest(attempt.stable_response_sha256, canonical_sha256(stable))
        and stable.get("registration_id") == attempt.registration_id
        and stable.get("attestation_id") == attempt.attestation_id
        and stable.get("server_id") == reservation.server_id
        and stable.get("reservation_id") == reservation.reservation_id
        and stable.get("claims_sha256") == reservation.claims_sha256
        and stable.get("allocation_group_id") == reservation.allocation_group_id
        and stable.get("allocation_group_generation") == reservation.allocation_group_generation
        and stable.get("process_incarnation") == reservation.process_incarnation
        and stable.get("management_mode") == reservation.management_mode
        and stable.get("owner_hotkey") == reservation.owner_hotkey
        and stable.get("measurement_version") == registration_attestation.measurement_version
        and stable.get("measurement_name") == registration_attestation.measurement_name
        and stable.get("measurement_config_fingerprint")
        == registration_attestation.measurement_config_fingerprint
        and stable.get("trust_set_fingerprint") == registration_attestation.trust_set_fingerprint
        and stable.get("verified_at") == registration_attestation.verified_at.isoformat()
        and stable.get("status") == "registered"
        and server.server_id == reservation.server_id == registration_attestation.server_id
        and server.gpu_launch_reservation_id == reservation.reservation_id
        and server.gpu_allocation_group_id == reservation.allocation_group_id
        and server.gpu_allocation_group_generation == reservation.allocation_group_generation
        and server.gpu_process_incarnation == reservation.process_incarnation
        and server.gpu_management_mode == reservation.management_mode
        and registration_attestation.verification_error is None
        and registration_attestation.verified_at is not None
        and registration_attestation.gpu_retired_at is None
        and registration_attestation.gpu_host_boot_generation == reservation.host_boot_generation
        and registration_attestation.gpu_reservation_generation
        == reservation.reservation_generation
        and registration_attestation.gpu_management_mode == reservation.management_mode
        and registration_attestation.gpu_topology_fingerprint == reservation.topology_fingerprint
        and registration_attestation.gpu_release_id == reservation.gpu_release_id
        and registration_attestation.gpu_profile_id == reservation.profile_id
        and registration_attestation.gpu_chute_id == reservation.chute_id
        and registration_attestation.gpu_job_id == reservation.job_id
        and registration_attestation.gpu_launch_reservation_id == reservation.reservation_id
        and registration_attestation.gpu_allocation_group_id == reservation.allocation_group_id
        and registration_attestation.gpu_allocation_group_generation
        == reservation.allocation_group_generation
        and registration_attestation.gpu_process_incarnation == reservation.process_incarnation
        and registration_attestation.gpu_claims_sha256 == reservation.claims_sha256
        and server.attested_cert is not None
        and server.attested_cert == attempt.peer_certificate_pem
        and certificate_sha256 is not None
        and attempt.state == "completed"
        and attempt.completed_at is not None
        and attempt.registration_id is not None
        and attempt.peer_spki_sha256 == attempt.peer_spki_sha256.lower()
        and secrets.compare_digest(attempt.peer_certificate_sha256, certificate_sha256)
        and server.attested_cert_pubkey_hash is not None
        and secrets.compare_digest(attempt.peer_spki_sha256, server.attested_cert_pubkey_hash)
    )
    if not registration_exact:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU registration completion audit is not exact.",
        )
    group_current = bool(
        group is not None
        and claims_current
        and nodes_current
        and group.state == reservation.state
        and group.allocation_group_id == reservation.allocation_group_id
        and group.host_id == reservation.host_id
        and group.host_key_generation == reservation.host_key_generation
        and group.host_boot_generation == reservation.host_boot_generation
        and group.generation == reservation.allocation_group_generation
        and group.gpu_release_id == reservation.gpu_release_id
        and group.profile_id == reservation.profile_id
        and group.profile_contract_sha256 == reservation.profile_contract_sha256
        and group.topology_fingerprint == reservation.topology_fingerprint
        and list(group.gpu_bdfs) == list(reservation.gpu_bdfs)
        and list(group.gpu_uuids) == list(reservation.gpu_uuids)
        and list(group.gpu_identifiers) == list(reservation.gpu_identifiers)
        and list(group.gpu_attestation_certificate_sha256s)
        == list(reservation.gpu_attestation_certificate_sha256s)
        and group.management_mode == reservation.management_mode
        and group.reservation_owner == reservation.workload_owner
        and group.reservation_id == reservation.reservation_id
        and group.reservation_generation == reservation.reservation_generation
        and group.process_incarnation == reservation.process_incarnation
    )
    if not group_current:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU reservation/group/node lineage is not current.",
        )
    if operational_attestation is not None:
        try:
            _current_attestation(server, operational_attestation)
        except HTTPException as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Latest GPU operational attestation is not current.",
            ) from exc
    operational_exact = bool(
        operational_attestation is None
        or (
            operational_attestation.server_id == server.server_id
            and operational_attestation.gpu_launch_reservation_id == reservation.reservation_id
            and operational_attestation.gpu_allocation_group_id == reservation.allocation_group_id
            and operational_attestation.gpu_allocation_group_generation
            == reservation.allocation_group_generation
            and operational_attestation.gpu_host_boot_generation == reservation.host_boot_generation
            and operational_attestation.gpu_reservation_generation
            == reservation.reservation_generation
            and operational_attestation.gpu_management_mode == reservation.management_mode
            and operational_attestation.gpu_process_incarnation == reservation.process_incarnation
            and operational_attestation.gpu_topology_fingerprint == reservation.topology_fingerprint
            and operational_attestation.gpu_release_id == reservation.gpu_release_id
            and operational_attestation.gpu_profile_id == reservation.profile_id
            and operational_attestation.gpu_chute_id == reservation.chute_id
            and operational_attestation.gpu_job_id == reservation.job_id
            and operational_attestation.gpu_claims_sha256 == reservation.claims_sha256
            and operational_attestation.gpu_evidence is not None
            and operational_attestation.gpu_evidence_sha256
            == canonical_sha256(operational_attestation.gpu_evidence)
            and _gpu_selection_matches_registration(
                management_mode=reservation.management_mode,
                reservation_uuids=list(reservation.gpu_uuids),
                registered_uuids=selection_uuids,
                registered_certificates=expected_evidence_certificates,
                operational_certificates=list(
                    operational_attestation.gpu_evidence_certificate_sha256s or []
                ),
            )
        )
    )
    if not operational_exact:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU operational attestation does not match registration authority.",
        )
    return CompletedGpuRegistrationAuthority(
        attempt=attempt,
        registration_attestation=registration_attestation,
        gpu_uuids=tuple(selection_uuids),
        gpu_identifiers=tuple(stable_identifiers),
        gpu_certificate_sha256s=tuple(expected_evidence_certificates),
    )


async def build_completed_gpu_registration_authority(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    server: Server,
) -> CompletedGpuRegistrationAuthority:
    """Build immutable completed-registration authority without operational evidence."""

    return await _completed_gpu_registration_authority(
        db,
        reservation,
        None,
        server,
    )


async def require_completed_gpu_registration(
    db: AsyncSession,
    reservation: GpuLaunchReservation,
    operational_attestation: ServerAttestation,
    server: Server,
) -> CompletedGpuRegistrationAuthority:
    """Require completed registration plus a current exact operational attestation."""

    if operational_attestation is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU operational attestation is required.",
        )
    return await _completed_gpu_registration_authority(
        db,
        reservation,
        operational_attestation,
        server,
    )


def mint_gpu_runtime_session(
    server: Server,
    attestation: ServerAttestation,
    *,
    version: int = GPU_RUNTIME_SESSION_VERSION_V1,
) -> tuple[str, datetime]:
    mode = server.gpu_management_mode
    if (
        server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or mode not in {"miner", "platform"}
        or not server.gpu_launch_reservation_id
        or not server.attested_cert_pubkey_hash
        or attestation.server_id != server.server_id
    ):
        raise ValueError(
            "GPU runtime sessions require a current attested server and exact mode scope"
        )
    allowed_purposes = _gpu_runtime_session_purposes(mode, version)
    _current_attestation(server, attestation)
    now = _runtime_session_now()
    expires_at = now + timedelta(seconds=GPU_RUNTIME_SESSION_LIFETIME_SECONDS)
    payload = {
        "schema": "chutes.gpu-runtime-session",
        "version": version,
        "iss": "chutes",
        "purpose": "gpu_runtime_session",
        "jti": generate_uuid(),
        "server_id": server.server_id,
        "owner_hotkey": server.miner_hotkey,
        "reservation_id": server.gpu_launch_reservation_id,
        "attestation_id": attestation.attestation_id,
        "attested_spki_sha256": server.attested_cert_pubkey_hash.lower(),
        "management_mode": mode,
        "allowed_purposes": list(allowed_purposes),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return (
        jwt.encode(payload, settings.launch_config_key, algorithm="HS256"),
        expires_at,
    )


async def validate_gpu_runtime_session(
    db: AsyncSession,
    token: str,
    *,
    required_purpose: str | None,
    allow_resetting: bool = False,
) -> tuple[Server, dict[str, Any]]:
    validation_now = _runtime_session_now()
    try:
        payload = jwt.decode(
            token,
            settings.launch_config_key,
            algorithms=["HS256"],
            issuer="chutes",
            options={
                "require": ["exp", "iat", "iss", "jti"],
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session is invalid or expired.",
        ) from exc
    iat = payload.get("iat") if isinstance(payload, dict) else None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if (
        type(iat) is not int
        or type(exp) is not int
        or iat > int(validation_now.timestamp()) + GPU_RUNTIME_SESSION_IAT_SKEW_SECONDS
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session is invalid or expired.",
        )
    session_expired = exp <= int(validation_now.timestamp())
    if session_expired and required_purpose != "gpu-decommission":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session is invalid or expired.",
        )
    required_keys = {
        "schema",
        "version",
        "iss",
        "purpose",
        "jti",
        "server_id",
        "owner_hotkey",
        "reservation_id",
        "attestation_id",
        "attested_spki_sha256",
        "management_mode",
        "allowed_purposes",
        "iat",
        "exp",
    }
    mode = payload.get("management_mode") if isinstance(payload, dict) else None
    version = payload.get("version") if isinstance(payload, dict) else None
    try:
        expected_purposes = _gpu_runtime_session_purposes(mode, version)
    except ValueError:
        expected_purposes = ()
    if (
        not isinstance(payload, dict)
        or set(payload) != required_keys
        or payload["schema"] != "chutes.gpu-runtime-session"
        or type(version) is not int
        or payload["purpose"] != "gpu_runtime_session"
        or payload["allowed_purposes"] != list(expected_purposes)
        or required_purpose not in expected_purposes
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session scope is invalid.",
        )
    await acquire_gpu_lifecycle_lock(db)
    server = await db.get(Server, payload["server_id"])
    attestation = await db.get(ServerAttestation, payload["attestation_id"])
    reservation = await db.get(GpuLaunchReservation, payload["reservation_id"])
    latest_attestation = (
        await _latest_attestation_attempt(db, server.server_id) if server is not None else None
    )
    if required_purpose == "gpu-decommission":
        audit = (
            await db.get(GpuServerDecommission, payload["server_id"])
            if isinstance(payload.get("server_id"), str)
            else None
        )
        if audit is not None:
            # The service clears live server authority only after persisting this
            # immutable terminal audit. The exact prior certificate is persisted
            # for this one purpose, so its signed session plus live certificate
            # possession (checked by the route) may recover the ACK even after JWT
            # expiry without reviving any broader runtime purpose.
            replay_attested_spki_sha256 = (
                audit.replay_attested_spki_sha256 or ""
            ).lower()
            if (
                server is None
                or server.compute_type != "gpu"
                or server.miner_hotkey != payload["owner_hotkey"]
                or audit.owner_hotkey != payload["owner_hotkey"]
                or (
                    replay_attested_spki_sha256
                    and not secrets.compare_digest(
                        replay_attested_spki_sha256,
                        str(payload["attested_spki_sha256"]).lower(),
                    )
                )
                or (session_expired and not replay_attested_spki_sha256)
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="GPU decommission replay identity is invalid.",
                )
            await db.commit()
            return server, payload

        # Teardown/reset can legitimately outlive the 15-minute JWT. For this
        # first decommission only, the route's live exact mTLS certificate plus
        # current terminal custody and attestation replace token freshness.
        terminal_reservation = bool(
            server is not None
            and attestation is not None
            and reservation is not None
            and latest_attestation is not None
            and _gpu_decommission_reservation_is_terminal(reservation)
        )
        if terminal_reservation:
            retirement_consistent = (
                server.gpu_retired_at is None and attestation.gpu_retired_at is None
            ) or (
                server.gpu_retired_at is not None
                and attestation.gpu_retired_at == server.gpu_retired_at
            )
            if (
                server.compute_type != "gpu"
                or server.tee_type != "tdx"
                or server.gpu_management_mode != "miner"
                or payload["management_mode"] != "miner"
                or server.miner_hotkey != payload["owner_hotkey"]
                or server.gpu_launch_reservation_id != payload["reservation_id"]
                or server.attested_cert_pubkey_hash != payload["attested_spki_sha256"]
                or reservation.reservation_id != payload["reservation_id"]
                or reservation.server_id != server.server_id
                or reservation.management_mode != "miner"
                or reservation.allocation_group_id != server.gpu_allocation_group_id
                or reservation.allocation_group_generation
                != server.gpu_allocation_group_generation
                or reservation.process_incarnation != server.gpu_process_incarnation
                or reservation.topology_fingerprint != server.gpu_topology_fingerprint
                or attestation.attestation_id != payload["attestation_id"]
                or latest_attestation.attestation_id != attestation.attestation_id
                or attestation.gpu_claims_sha256 != reservation.claims_sha256
                or attestation.gpu_release_id != reservation.gpu_release_id
                or attestation.gpu_profile_id != reservation.profile_id
                or attestation.gpu_host_boot_generation != reservation.host_boot_generation
                or attestation.gpu_reservation_generation
                != reservation.reservation_generation
                or not retirement_consistent
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="GPU decommission session identity is no longer exact.",
                )
            try:
                _current_attestation_identity(
                    server,
                    latest_attestation,
                    expected_id=payload["attestation_id"],
                )
            except HTTPException as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="GPU decommission attestation is not current.",
                ) from exc
            await db.commit()
            return server, payload
        if session_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="GPU runtime session is invalid or expired.",
            )
    if (
        server is None
        or attestation is None
        or reservation is None
        or server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or server.gpu_management_mode != mode
        or server.gpu_retired_at is not None
        or server.miner_hotkey != payload["owner_hotkey"]
        or server.gpu_launch_reservation_id != payload["reservation_id"]
        or server.attested_cert_pubkey_hash != payload["attested_spki_sha256"]
        or server.gpu_runtime_session_attestation_id != payload["attestation_id"]
        or server.gpu_runtime_session_expires_at is None
        or server.gpu_runtime_session_expires_at <= validation_now
        or reservation.state
        not in (
            {"running", "resetting"}
            if allow_resetting and required_purpose == "gpu-infra"
            else {"running"}
        )
        or reservation.registration_attestation_id is None
        or reservation.server_id != server.server_id
        or reservation.management_mode != server.gpu_management_mode
        or reservation.allocation_group_id != server.gpu_allocation_group_id
        or reservation.allocation_group_generation != server.gpu_allocation_group_generation
        or reservation.process_incarnation != server.gpu_process_incarnation
        or reservation.topology_fingerprint != server.gpu_topology_fingerprint
        or attestation.gpu_claims_sha256 != reservation.claims_sha256
        or attestation.gpu_release_id != reservation.gpu_release_id
        or attestation.gpu_profile_id != reservation.profile_id
        or attestation.gpu_host_boot_generation != reservation.host_boot_generation
        or attestation.gpu_reservation_generation != reservation.reservation_generation
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU runtime session identity is no longer current.",
        )
    try:
        await require_completed_gpu_registration(db, reservation, attestation, server)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GPU registration is not durably completed.",
        ) from exc
    try:
        await require_gpu_hotplug_runtime_ack(db, reservation, server.server_id)
    except GpuHotplugError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Legacy GPU hotplug custody is not ready for runtime access.",
        ) from exc
    try:
        _current_attestation(
            server,
            latest_attestation,
            expected_id=payload["attestation_id"],
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A newer GPU attestation attempt invalidated this session.",
        ) from exc
    await db.commit()
    return server, payload


async def latest_gpu_runtime_session(
    db: AsyncSession,
    server: Server,
    *,
    version: int = GPU_RUNTIME_SESSION_VERSION_V1,
) -> tuple[str, datetime, str]:
    await acquire_gpu_lifecycle_lock(db)
    server = (
        await db.execute(
            select(Server).where(Server.server_id == server.server_id).with_for_update()
        )
    ).scalar_one_or_none()
    reservation = (
        (
            await db.execute(
                select(GpuLaunchReservation)
                .where(GpuLaunchReservation.reservation_id == server.gpu_launch_reservation_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if server is not None and server.gpu_launch_reservation_id is not None
        else None
    )
    if (
        server is None
        or reservation is None
        or reservation.state != "running"
        or reservation.server_id != server.server_id
        or reservation.management_mode != server.gpu_management_mode
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GPU runtime session reservation is not current.",
        )
    attestation = _current_attestation(
        server,
        await _latest_attestation_attempt(db, server.server_id, for_update=True),
    )
    await require_completed_gpu_registration(db, reservation, attestation, server)
    try:
        await require_gpu_hotplug_runtime_ack(db, reservation, server.server_id)
    except GpuHotplugError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Legacy GPU hotplug custody is not ready for runtime access.",
        ) from exc
    token, expires_at = mint_gpu_runtime_session(
        server,
        attestation,
        version=version,
    )
    return token, expires_at, attestation.attestation_id


def _gpu_selection_matches_registration(
    *,
    management_mode: str,
    reservation_uuids: list[str],
    registered_uuids: list[str],
    registered_certificates: list[str],
    operational_certificates: list[str] | None = None,
) -> bool:
    """Apply mode policy once, then require byte-order-identical operational identity."""

    registered = bool(
        registered_uuids
        and registered_uuids == sorted(set(registered_uuids))
        and len(registered_certificates) == len(registered_uuids)
    )
    if not registered:
        return False
    if management_mode == "platform":
        mode_selection = registered_uuids == reservation_uuids
    elif management_mode == "miner":
        mode_selection = set(registered_uuids).issubset(set(reservation_uuids))
    else:
        return False
    return bool(
        mode_selection
        and (
            operational_certificates is None or operational_certificates == registered_certificates
        )
    )
