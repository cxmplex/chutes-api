"""Launch-bound ChuteFS session issuance, rotation, and exact lineage validation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, lazyload

from api.chute.schemas import Chute
from api.config import settings
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation
from api.instance.schemas import Instance, LaunchConfig
from api.instance.util import (
    _decode_chutes_jwt,
    _require_current_attestation_identity,
    launch_identity_claims,
    launch_management_mode,
    load_launch_config_from_jwt,
)
from api.job.schemas import Job
from api.server.gpu_sessions import _current_attestation, _latest_attestation_attempt
from api.server.schemas import (
    ChuteFSLaunchSession,
    DefaultChuteFSVolumeBinding,
    Server,
    StorageVolume,
)
from api.server.util import _get_client_certificate, get_public_key_hash
from api.storage.schemas import LaunchStorageContext, LaunchStorageSessionResponse

ACCESS_TTL_SECONDS = 15 * 60
REFRESH_TTL_SECONDS = 24 * 60 * 60
ALLOWED_OPERATIONS = ["put", "get", "list", "delete"]
_ACCESS_PREFIX = "cfsas_"
_REFRESH_PREFIX = "cfsrs_"


async def lock_launch_storage_lifecycle(db: AsyncSession, config_id: str) -> None:
    """Serialize every launch-storage transition before locking lifecycle rows."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:config_id, 0))"),
        {"config_id": config_id},
    )


@dataclass(frozen=True)
class AuthorizedDefaultVolume:
    session: ChuteFSLaunchSession
    config: LaunchConfig
    instance: Instance
    binding: DefaultChuteFSVolumeBinding
    volume: StorageVolume
    context: LaunchStorageContext


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token(prefix: str, session_id: str) -> str:
    return f"{prefix}{session_id}.{secrets.token_urlsafe(48)}"


def _session_id_from_token(token: str, prefix: str) -> str:
    value = (token or "").strip()
    if not value.startswith(prefix) or "." not in value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch session token is malformed.",
        )
    session_id, secret = value[len(prefix) :].split(".", 1)
    if not session_id or len(session_id) > 64 or len(secret) < 32 or len(secret) > 128:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch session token is malformed.",
        )
    return session_id


def _bearer(authorization: str) -> str:
    scheme, separator, token = (authorization or "").strip().partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A ChuteFS launch session bearer token is required.",
        )
    return token.strip()


async def _require_not_disabled(instance_id: str) -> None:
    try:
        disabled = await settings.redis_client.get(f"instance_disabled:{instance_id}")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to verify current instance revocation state.",
        ) from exc
    if disabled is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The launch instance is disabled.",
        )


async def _require_presented_attested_cert(
    request: Request,
    server: Server,
) -> str:
    if not settings.require_mtls_client_verify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Launch-bound platform storage requires a verifying mTLS terminator.",
        )
    try:
        cert_hash = get_public_key_hash(
            _get_client_certificate(request, require_proxy_verified=True)
        ).lower()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current attested mTLS possession could not be verified.",
        ) from exc
    if not server.attested_cert_pubkey_hash or not hmac.compare_digest(
        server.attested_cert_pubkey_hash.lower(), cert_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented mTLS identity is not the launch server's attested identity.",
        )
    return cert_hash


async def _load_current_lineage(
    db: AsyncSession,
    config_id: str,
    *,
    request: Optional[Request],
    lock_session_id: Optional[str] = None,
    require_client_mtls: bool = True,
) -> tuple[
    LaunchConfig,
    Instance,
    DefaultChuteFSVolumeBinding,
    StorageVolume,
    Server,
    Optional[GpuLaunchReservation],
    Optional[GpuAllocationGroup],
    Optional[str],
]:
    await lock_launch_storage_lifecycle(db, config_id)
    config_query = (
        select(LaunchConfig).where(LaunchConfig.config_id == config_id).options(lazyload("*"))
    )
    if lock_session_id is not None:
        config_query = config_query.with_for_update()
    config = (await db.execute(config_query)).unique().scalar_one_or_none()
    instance_query = select(Instance).where(Instance.config_id == config_id).options(lazyload("*"))
    if lock_session_id is not None:
        instance_query = instance_query.with_for_update()
    instance = (await db.execute(instance_query)).unique().scalar_one_or_none()
    if (
        config is None
        or instance is None
        or config.failed_at is not None
        or config.completed_at is not None
        or config.verified_at is None
        or not instance.verified
        or instance.config_id != config.config_id
        or instance.chute_id != config.chute_id
        or (instance.activated_at is not None and not instance.active)
        or not config.storage_session_exchange_allowed
        or not config.default_volume_id
        or not config.user_id
        or not config.compute_type
        or not config.server_id
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch storage identity is inactive or incomplete.",
        )
    await _require_not_disabled(instance.instance_id)

    chute = (
        (
            await db.execute(
                select(Chute)
                .where(Chute.chute_id == config.chute_id)
                .options(joinedload(Chute.image))
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    job = await db.get(Job, config.job_id) if config.job_id else None
    current_owner = job.user_id if job is not None else chute.user_id if chute is not None else None
    current_compute = (
        getattr(getattr(chute, "image", None), "compute_type", None) if chute is not None else None
    )
    if (
        chute is None
        or chute.disabled
        or current_owner != config.user_id
        or current_compute != config.compute_type
        or (config.job_id is not None and job is None)
        or (
            job is not None
            and (
                job.chute_id != config.chute_id
                or job.instance_id != instance.instance_id
                or job.finished_at is not None
            )
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch owner, chute, job, or compute identity is no longer current.",
        )

    binding = (
        await db.execute(
            select(DefaultChuteFSVolumeBinding).where(
                DefaultChuteFSVolumeBinding.user_id == config.user_id,
                DefaultChuteFSVolumeBinding.chute_id == config.chute_id,
                DefaultChuteFSVolumeBinding.volume_id == config.default_volume_id,
                DefaultChuteFSVolumeBinding.lifecycle_state == "active",
            )
        )
    ).scalar_one_or_none()
    volume = await db.get(StorageVolume, config.default_volume_id)
    if (
        binding is None
        or volume is None
        or volume.user_id != config.user_id
        or volume.deleted
        or volume.purged_at is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The launch default-volume binding is no longer active.",
        )

    server = await db.get(Server, config.server_id)
    if (
        server is None
        or instance.server_id != server.server_id
        or server.server_id != config.server_id
        or server.compute_type != config.compute_type
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The launch server identity is no longer current.",
        )

    mode = launch_management_mode(config)
    presented_cert_hash: Optional[str] = None
    reservation: Optional[GpuLaunchReservation] = None
    group: Optional[GpuAllocationGroup] = None
    if config.compute_type == "cpu":
        if mode != "platform" or server.storage_role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="CPU launch storage scope is invalid.",
            )
        await _require_current_attestation_identity(db, server)
        if require_client_mtls:
            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current launch mTLS possession is required.",
                )
            presented_cert_hash = await _require_presented_attested_cert(request, server)
    else:
        reservation = await db.get(GpuLaunchReservation, config.gpu_launch_reservation_id)
        group = (
            await db.get(GpuAllocationGroup, reservation.allocation_group_id)
            if reservation is not None
            else None
        )
        latest = await _latest_attestation_attempt(db, server.server_id)
        try:
            _current_attestation(
                server,
                latest,
                expected_id=server.gpu_runtime_session_attestation_id,
            )
        except HTTPException as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The latest GPU attestation attempt is not current and successful.",
            ) from exc
        if (
            mode not in {"platform", "miner"}
            or server.gpu_management_mode != mode
            or instance.gpu_management_mode != mode
            or instance.gpu_launch_reservation_id != config.gpu_launch_reservation_id
            or server.gpu_retired_at is not None
            or server.gpu_runtime_session_expires_at is None
            or server.gpu_runtime_session_expires_at <= _now()
            or reservation is None
            or group is None
            or reservation.state != "running"
            or group.state != "running"
            or reservation.registration_attestation_id is None
            or reservation.reservation_id != config.gpu_launch_reservation_id
            or reservation.server_id != server.server_id
            or reservation.management_mode != mode
            or (
                mode == "platform"
                and (reservation.chute_id != config.chute_id or reservation.job_id != config.job_id)
            )
            or (
                mode == "miner"
                and (reservation.chute_id is not None or reservation.job_id is not None)
            )
            or reservation.allocation_group_id != instance.gpu_allocation_group_id
            or reservation.allocation_group_generation != instance.gpu_allocation_group_generation
            or reservation.process_incarnation != instance.gpu_process_incarnation
            or group.allocation_group_id != reservation.allocation_group_id
            or group.generation != reservation.allocation_group_generation
            or group.reservation_id != reservation.reservation_id
            or group.management_mode != mode
            or group.process_incarnation != reservation.process_incarnation
            or server.gpu_allocation_group_id != reservation.allocation_group_id
            or server.gpu_allocation_group_generation != reservation.allocation_group_generation
            or server.gpu_process_incarnation != reservation.process_incarnation
            or (mode == "platform" and reservation.workload_owner != config.user_id)
            or (
                job is not None
                and (
                    job.gpu_management_mode != mode
                    or job.gpu_launch_reservation_id != reservation.reservation_id
                )
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="GPU launch reservation or allocation identity is no longer current.",
            )
        if mode == "platform" and require_client_mtls:
            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current launch mTLS possession is required.",
                )
            presented_cert_hash = await _require_presented_attested_cert(request, server)

    return (
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
        group,
        presented_cert_hash,
    )


def _context(
    config: LaunchConfig,
    instance: Instance,
) -> LaunchStorageContext:
    return LaunchStorageContext(
        user_id=config.user_id,
        chute_id=config.chute_id,
        config_id=config.config_id,
        instance_id=instance.instance_id,
        job_id=config.job_id,
        compute_type=config.compute_type,
        management_mode=launch_management_mode(config),
        server_id=config.server_id,
        default_volume_id=config.default_volume_id,
        verified_at=config.verified_at.isoformat(),
    )


def _session_response(
    row: ChuteFSLaunchSession,
    access_token: str,
    refresh_token: str,
) -> LaunchStorageSessionResponse:
    return LaunchStorageSessionResponse(
        access_token=access_token,
        access_expires_at=row.access_expires_at.isoformat(),
        refresh_token=refresh_token,
        refresh_expires_at=row.refresh_expires_at.isoformat(),
        allowed_operations=list(row.allowed_operations),
        generation=row.generation,
    )


async def issue_launch_storage_session(
    db: AsyncSession,
    config_id: str,
    request: Request,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    (
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
        _group,
        presented_cert_hash,
    ) = await _load_current_lineage(
        db,
        config_id,
        request=request,
        lock_session_id=config_id,
    )
    latest = (
        await _latest_attestation_attempt(db, server.server_id)
        if config.compute_type == "gpu"
        else None
    )
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.config_id == config_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _now()
    session_id = row.session_id if row is not None else secrets.token_urlsafe(24)
    access_token = _new_token(_ACCESS_PREFIX, session_id)
    refresh_token = _new_token(_REFRESH_PREFIX, session_id)
    immutable_identity = {
        "config_id": config.config_id,
        "instance_id": instance.instance_id,
        "binding_id": binding.binding_id,
        "user_id": config.user_id,
        "chute_id": config.chute_id,
        "job_id": config.job_id,
        "compute_type": config.compute_type,
        "management_mode": launch_management_mode(config),
        "server_id": server.server_id,
        "volume_id": volume.volume_id,
        "reservation_id": reservation.reservation_id if reservation is not None else None,
        "allocation_group_id": (
            reservation.allocation_group_id if reservation is not None else None
        ),
        "allocation_group_generation": (
            reservation.allocation_group_generation if reservation is not None else None
        ),
        "process_incarnation": (
            reservation.process_incarnation if reservation is not None else None
        ),
        "attested_cert_pubkey_hash": (
            server.attested_cert_pubkey_hash.lower()
            if server.attested_cert_pubkey_hash
            else presented_cert_hash
        ),
    }
    if row is None:
        row = ChuteFSLaunchSession(
            session_id=session_id,
            **immutable_identity,
            attestation_id=latest.attestation_id if latest is not None else None,
            allowed_operations=list(ALLOWED_OPERATIONS),
            generation=1,
            access_token_hash=_token_hash(access_token),
            refresh_token_hash=_token_hash(refresh_token),
            access_expires_at=now + timedelta(seconds=ACCESS_TTL_SECONDS),
            refresh_expires_at=now + timedelta(seconds=REFRESH_TTL_SECONDS),
            rotated_at=now,
        )
        db.add(row)
    else:
        actual_identity = {field: getattr(row, field) for field in immutable_identity}
        if actual_identity != immutable_identity or row.allowed_operations != ALLOWED_OPERATIONS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Existing ChuteFS launch session has different immutable identity.",
            )
        row.attestation_id = latest.attestation_id if latest is not None else None
        row.generation += 1
        row.access_token_hash = _token_hash(access_token)
        row.refresh_token_hash = _token_hash(refresh_token)
        row.access_expires_at = now + timedelta(seconds=ACCESS_TTL_SECONDS)
        row.refresh_expires_at = now + timedelta(seconds=REFRESH_TTL_SECONDS)
        row.rotated_at = now
        row.revoked_at = None
    await db.commit()
    await db.refresh(row)
    return _context(config, instance), _session_response(row, access_token, refresh_token)


async def exchange_launch_token(
    db: AsyncSession,
    config_id: str,
    launch_token: str,
    request: Request,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    await lock_launch_storage_lifecycle(db, config_id)
    try:
        payload = _decode_chutes_jwt(launch_token, require_exp=True)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch token is invalid or expired.",
        ) from exc
    if (
        payload.get("sub") != config_id
        or payload.get("storage_session_exchange_allowed") is not True
        or payload.get("permissions") != ["storage_session:exchange"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch token has no storage-session exchange permission.",
        )
    config = await load_launch_config_from_jwt(
        db,
        config_id,
        launch_token,
        allow_retrieved=True,
    )
    if launch_identity_claims(config) != {
        key: payload.get("sub") if key == "config_id" else payload.get(key)
        for key in launch_identity_claims(config)
    }:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch token identity is stale.",
        )
    return await issue_launch_storage_session(db, config_id, request)


async def authorize_default_volume(
    db: AsyncSession,
    authorization: str,
    request: Request,
    operation: str,
) -> AuthorizedDefaultVolume:
    if operation not in ALLOWED_OPERATIONS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unknown launch storage operation.",
        )
    token = _bearer(authorization)
    session_id = _session_id_from_token(token, _ACCESS_PREFIX)
    row = await db.get(ChuteFSLaunchSession, session_id)
    now = _now()
    if (
        row is None
        or row.revoked_at is not None
        or row.access_expires_at <= now
        or operation not in row.allowed_operations
        or not hmac.compare_digest(row.access_token_hash, _token_hash(token))
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch access session is invalid, expired, or revoked.",
        )
    (
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
        _group,
        _presented_cert_hash,
    ) = await _load_current_lineage(db, row.config_id, request=request)
    current = {
        "config_id": config.config_id,
        "instance_id": instance.instance_id,
        "binding_id": binding.binding_id,
        "user_id": config.user_id,
        "chute_id": config.chute_id,
        "job_id": config.job_id,
        "compute_type": config.compute_type,
        "management_mode": launch_management_mode(config),
        "server_id": server.server_id,
        "volume_id": volume.volume_id,
        "reservation_id": reservation.reservation_id if reservation is not None else None,
        "allocation_group_id": (
            reservation.allocation_group_id if reservation is not None else None
        ),
        "allocation_group_generation": (
            reservation.allocation_group_generation if reservation is not None else None
        ),
        "process_incarnation": (
            reservation.process_incarnation if reservation is not None else None
        ),
        "attested_cert_pubkey_hash": (
            server.attested_cert_pubkey_hash.lower() if server.attested_cert_pubkey_hash else None
        ),
    }
    if any(getattr(row, field) != value for field, value in current.items()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch session no longer matches its exact binding.",
        )
    return AuthorizedDefaultVolume(
        session=row,
        config=config,
        instance=instance,
        binding=binding,
        volume=volume,
        context=_context(config, instance),
    )


async def validate_launch_bound_grant(
    db: AsyncSession,
    session_id: str,
    user_id: str,
    volume_id: str,
    generation: int,
) -> bool:
    """Revalidate a launch grant when an attested storage node presents it."""
    row = await db.get(ChuteFSLaunchSession, session_id)
    if (
        row is None
        or row.revoked_at is not None
        or row.access_expires_at <= _now()
        or row.user_id != user_id
        or row.volume_id != volume_id
        or row.generation != generation
    ):
        return False
    try:
        (
            config,
            instance,
            binding,
            volume,
            server,
            reservation,
            _group,
            _presented_cert_hash,
        ) = await _load_current_lineage(
            db,
            row.config_id,
            request=None,
            require_client_mtls=False,
        )
    except HTTPException:
        return False
    current = {
        "config_id": config.config_id,
        "instance_id": instance.instance_id,
        "binding_id": binding.binding_id,
        "user_id": config.user_id,
        "chute_id": config.chute_id,
        "job_id": config.job_id,
        "compute_type": config.compute_type,
        "management_mode": launch_management_mode(config),
        "server_id": server.server_id,
        "volume_id": volume.volume_id,
        "reservation_id": reservation.reservation_id if reservation is not None else None,
        "allocation_group_id": (
            reservation.allocation_group_id if reservation is not None else None
        ),
        "allocation_group_generation": (
            reservation.allocation_group_generation if reservation is not None else None
        ),
        "process_incarnation": (
            reservation.process_incarnation if reservation is not None else None
        ),
        "attested_cert_pubkey_hash": (
            server.attested_cert_pubkey_hash.lower() if server.attested_cert_pubkey_hash else None
        ),
    }
    return all(getattr(row, field) == value for field, value in current.items())


async def refresh_launch_storage_session(
    db: AsyncSession,
    authorization: str,
    request: Request,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    token = _bearer(authorization)
    session_id = _session_id_from_token(token, _REFRESH_PREFIX)
    config_id = (
        await db.execute(
            select(ChuteFSLaunchSession.config_id).where(
                ChuteFSLaunchSession.session_id == session_id
            )
        )
    ).scalar_one_or_none()
    if config_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch refresh is invalid, expired, replayed, or revoked.",
        )
    await lock_launch_storage_lifecycle(db, config_id)
    (
        config,
        instance,
        _binding,
        _volume,
        server,
        _reservation,
        _group,
        _presented_cert_hash,
    ) = await _load_current_lineage(
        db,
        config_id,
        request=request,
        lock_session_id=session_id,
    )
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.session_id == session_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _now()
    if (
        row is None
        or row.revoked_at is not None
        or row.refresh_expires_at <= now
        or not hmac.compare_digest(row.refresh_token_hash, _token_hash(token))
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch refresh is invalid, expired, replayed, or revoked.",
        )
    latest = (
        await _latest_attestation_attempt(db, server.server_id)
        if config.compute_type == "gpu"
        else None
    )
    access_token = _new_token(_ACCESS_PREFIX, row.session_id)
    refresh_token = _new_token(_REFRESH_PREFIX, row.session_id)
    row.attestation_id = latest.attestation_id if latest is not None else None
    row.generation += 1
    row.access_token_hash = _token_hash(access_token)
    row.refresh_token_hash = _token_hash(refresh_token)
    row.access_expires_at = now + timedelta(seconds=ACCESS_TTL_SECONDS)
    row.refresh_expires_at = now + timedelta(seconds=REFRESH_TTL_SECONDS)
    row.rotated_at = now
    row.revoked_at = None
    await db.commit()
    await db.refresh(row)
    return _context(config, instance), _session_response(row, access_token, refresh_token)
