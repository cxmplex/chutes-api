"""Launch-bound ChuteFS session issuance, rotation, and exact lineage validation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, joinedload, lazyload

from api.chute.schemas import Chute
from api.config import settings
from api.host.locks import assert_gpu_external_work_allowed
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation
from api.instance.locking import lock_launch_configs_before_instances
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
    ChuteFSTokenKeyEpoch,
    DefaultChuteFSVolumeBinding,
    Server,
    StorageVolume,
)
from api.server.util import require_live_attested_client_cert
from api.storage import startup as storage_startup
from api.storage.schemas import LaunchStorageContext, LaunchStorageSessionResponse
from api.storage.key_epochs import lock_token_key_epoch_for_session
from api.user.schemas import User

ACCESS_TTL_SECONDS = 15 * 60
REFRESH_TTL_SECONDS = 24 * 60 * 60
ALLOWED_OPERATIONS = ["put", "get", "list", "delete"]
_ACCESS_PREFIX = "cfsas_"
_REFRESH_PREFIX = "cfsrs_"
_REEXCHANGE_PREFIX = "cfsxs_"
_TOKEN_DOMAIN = b"chutes.chutefs-session-token.v1\0"
_SCHEMA_FENCE_ADVISORY_LOCK = "chutes.chutefs-schema-fence.v1"


def _require_clean_preflight_session(db: AsyncSession) -> None:
    """Refuse to turn a caller's pending ORM mutation into a preflight commit."""

    if db.new or db.dirty or db.deleted:
        raise RuntimeError(
            "ChuteFS lifecycle locking requires a session with no pending ORM writes."
        )


async def lock_launch_storage_configurations(
    db: AsyncSession,
    config_ids: list[str],
    *,
    additional_user_ids: Optional[list[str]] = None,
) -> None:
    """Preflight revocation, then lock users, lifecycle, and launch identity rows.

    The initial lookup is deliberately non-authoritative: it discovers only
    which canonical users must be locked. Every value used for authorization
    is force-refetched after the user and lifecycle locks are held.
    """
    ordered_ids = sorted(set(config_ids))
    additional_user_ids = sorted(set(additional_user_ids or []))
    if not ordered_ids and not additional_user_ids:
        return
    _require_clean_preflight_session(db)
    hints = list(
        (
            await db.execute(
                select(LaunchConfig.config_id, LaunchConfig.user_id).where(
                    LaunchConfig.config_id.in_(ordered_ids)
                )
            )
        ).all()
    )
    if sorted(config_id for config_id, _user_id in hints) != ordered_ids:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch storage identity is inactive or incomplete.",
        )
    # Redis is only a revocation preflight. Perform it before any trust-bearing
    # row lock is acquired, then force-refetch every database identity below.
    instance_ids = list(
        (
            await db.execute(
                select(Instance.instance_id)
                .where(Instance.config_id.in_(ordered_ids))
                .order_by(Instance.config_id, Instance.instance_id)
            )
        ).scalars()
    )
    for instance_id in instance_ids:
        await _require_not_disabled(db, instance_id)
    # The lookups above are non-authoritative and Redis is external work. End
    # their transaction before taking either shared schema fence: even ordinary
    # SELECTs retain ACCESS SHARE table locks until transaction end, which
    # would invert the down-migration order (exclusive advisory, then table
    # locks). Refuse to commit any caller-owned ORM mutation accidentally.
    _require_clean_preflight_session(db)
    await db.commit()
    # Every runtime path takes these shared transaction fences before its first
    # trust-bearing row lock. Destructive schema rollback and token-key epoch
    # transitions take the matching exclusive advisory lock first, so neither
    # can invert the User/config/session lock hierarchy.
    await db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:lock_name, 0))"),
        {"lock_name": _SCHEMA_FENCE_ADVISORY_LOCK},
    )
    await lock_token_key_epoch_for_session(db)
    user_ids = sorted({user_id for _config_id, user_id in hints} | set(additional_user_ids))
    locked_users = list(
        (
            await db.execute(
                select(User)
                .where(User.user_id.in_(user_ids))
                .order_by(User.user_id)
                .with_for_update(of=User)
            )
        )
        .scalars()
        .all()
    )
    if [user.user_id for user in locked_users] != user_ids:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch storage owner is no longer current.",
        )
    # The shared order is user rows first, then the lifecycle advisory lock,
    # then launch configuration and identity rows. This matches binding
    # creation, scheduling, and launch activation without holding row locks
    # across the Redis revocation preflight above.
    await lock_launch_configs_before_instances(
        db,
        config_ids=ordered_ids,
    )
    locked_configs = list(
        (
            await db.execute(
                select(LaunchConfig)
                .where(LaunchConfig.config_id.in_(ordered_ids))
                .order_by(LaunchConfig.config_id)
                .options(lazyload("*"))
                .execution_options(populate_existing=True)
            )
        )
        .unique()
        .scalars()
        .all()
    )
    expected_config_owners = sorted((config_id, user_id) for config_id, user_id in hints)
    actual_config_owners = sorted((config.config_id, config.user_id) for config in locked_configs)
    if actual_config_owners != expected_config_owners:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch storage configuration ownership is no longer current.",
        )
    await db.execute(
        select(ChuteFSLaunchSession)
        .where(ChuteFSLaunchSession.config_id.in_(ordered_ids))
        .order_by(
            ChuteFSLaunchSession.config_id,
            ChuteFSLaunchSession.generation,
            ChuteFSLaunchSession.session_id,
        )
        .options(lazyload("*"))
        .with_for_update(of=ChuteFSLaunchSession)
        .execution_options(populate_existing=True)
    )


async def lock_launch_storage_lifecycle(db: AsyncSession, config_id: str) -> None:
    """Compatibility wrapper for one configuration using the shared order."""
    await lock_launch_storage_configurations(db, [config_id])


@dataclass(frozen=True)
class AuthorizedDefaultVolume:
    session: ChuteFSLaunchSession
    config: LaunchConfig
    instance: Instance
    binding: DefaultChuteFSVolumeBinding
    volume: StorageVolume
    context: LaunchStorageContext


def default_volume_authorization_sha256(
    authorized: AuthorizedDefaultVolume,
    operation: str,
) -> str:
    """Hash every immutable authority used across one staged external observation."""

    row = authorized.session
    document = {
        "operation": operation,
        "session_id": row.session_id,
        "config_id": row.config_id,
        "instance_id": row.instance_id,
        "binding_id": row.binding_id,
        "user_id": row.user_id,
        "chute_id": row.chute_id,
        "job_id": row.job_id,
        "compute_type": row.compute_type,
        "management_mode": row.management_mode,
        "server_id": row.server_id,
        "volume_id": row.volume_id,
        "reservation_id": row.reservation_id,
        "allocation_group_id": row.allocation_group_id,
        "allocation_group_generation": row.allocation_group_generation,
        "process_incarnation": row.process_incarnation,
        "attestation_id": row.attestation_id,
        "attested_cert_pubkey_hash": row.attested_cert_pubkey_hash,
        "allowed_operations": sorted(row.allowed_operations),
        "generation": row.generation,
        "revocation_epoch": row.revocation_epoch,
        "access_token_hash": row.access_token_hash,
        "access_expires_at": row.access_expires_at.isoformat(),
        "config_verified_at": authorized.config.verified_at.isoformat(),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_key(key_id: str) -> bytes:
    key = settings.chutefs_token_keys.get(key_id)
    if key is None or not storage_startup.token_key_material_is_validated(key_id, key):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The ChuteFS session token key is unavailable.",
        )
    return key.encode("utf-8")


def _derived_token(row: ChuteFSLaunchSession, prefix: str, purpose: str) -> str:
    if (
        not row.token_seed
        or not row.token_key_id
        or len(row.token_seed) != 64
        or len(row.session_id) > 64
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The ChuteFS session response cannot be recovered.",
        )
    material = (
        _TOKEN_DOMAIN
        + purpose.encode("ascii")
        + b"\0"
        + row.session_id.encode("ascii")
        + b"\0"
        + str(row.generation).encode("ascii")
        + b"\0"
        + row.token_seed.encode("ascii")
    )
    secret = hmac.new(_token_key(row.token_key_id), material, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
    return f"{prefix}{row.session_id}.{encoded}"


def _rotation_request_digest(
    session_id: str,
    token_hash: str,
    purpose: str,
) -> str:
    if purpose not in {"refresh", "reexchange"}:
        raise ValueError("Unsupported ChuteFS session rotation purpose.")
    return _canonical_digest(f"chutes.chutefs-session-{purpose}.v1\0{session_id}\0{token_hash}")


def _issue_request_digest(config_id: str, instance_id: str) -> str:
    return _canonical_digest(f"chutes.chutefs-session-issue.v1\0{config_id}\0{instance_id}")


async def _active_token_key_id(db: AsyncSession) -> str:
    """Return the sole database-active key, provided this replica has it."""

    key_ids = list(
        (
            await db.execute(
                select(ChuteFSTokenKeyEpoch.key_id)
                .where(ChuteFSTokenKeyEpoch.state == "active")
                .order_by(ChuteFSTokenKeyEpoch.key_id)
            )
        ).scalars()
    )
    key = settings.chutefs_token_keys.get(key_ids[0]) if len(key_ids) == 1 else None
    if (
        len(key_ids) != 1
        or key is None
        or not storage_startup.token_key_material_is_validated(key_ids[0], key)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The database-active ChuteFS token key is unavailable.",
        )
    return key_ids[0]


def _current_session_identity(
    config: LaunchConfig,
    instance: Instance,
    binding: DefaultChuteFSVolumeBinding,
    volume: StorageVolume,
    server: Server,
    reservation: Optional[GpuLaunchReservation],
) -> dict[str, object]:
    """Build the complete immutable authority expected on a launch session."""

    return {
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
        "attestation_id": (
            server.gpu_runtime_session_attestation_id if config.compute_type == "gpu" else None
        ),
        "attested_cert_pubkey_hash": (
            server.attested_cert_pubkey_hash.lower() if server.attested_cert_pubkey_hash else None
        ),
        "revocation_epoch": instance.storage_revocation_epoch,
    }


def _session_matches_current(
    row: ChuteFSLaunchSession,
    current: dict[str, object],
) -> bool:
    return all(getattr(row, field) == value for field, value in current.items())


async def _prune_expired_session_lineage(
    db: AsyncSession,
    config_id: str,
    *,
    now: datetime,
    limit: int = 128,
) -> int:
    """Bound revoked replay history after its exact-response window closes."""

    replay_successor = aliased(ChuteFSLaunchSession)
    session_ids = list(
        (
            await db.execute(
                select(ChuteFSLaunchSession.session_id)
                .where(
                    ChuteFSLaunchSession.config_id == config_id,
                    ChuteFSLaunchSession.revoked_at.is_not(None),
                    ChuteFSLaunchSession.access_expires_at <= now,
                    ChuteFSLaunchSession.refresh_expires_at <= now,
                    ChuteFSLaunchSession.response_replay_until.is_not(None),
                    ChuteFSLaunchSession.response_replay_until <= now,
                    ~select(replay_successor.session_id)
                    .where(
                        replay_successor.rotated_from_session_id == ChuteFSLaunchSession.session_id,
                        replay_successor.revoked_at.is_(None),
                        replay_successor.response_replay_until > now,
                    )
                    .exists(),
                )
                .order_by(
                    ChuteFSLaunchSession.response_replay_until,
                    ChuteFSLaunchSession.session_id,
                )
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).scalars()
    )
    if session_ids:
        await db.execute(
            delete(ChuteFSLaunchSession).where(ChuteFSLaunchSession.session_id.in_(session_ids))
        )
    return len(session_ids)


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


async def _require_not_disabled(db: AsyncSession, instance_id: str) -> None:
    assert_gpu_external_work_allowed(db, "ChuteFS instance revocation Redis GET")
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
    return require_live_attested_client_cert(request, server)


async def _load_current_lineage(
    db: AsyncSession,
    config_id: str,
    *,
    request: Optional[Request],
    lock_session_id: Optional[str] = None,
    require_client_mtls: bool = True,
    locks_held: bool = False,
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
    if not locks_held:
        await lock_launch_storage_lifecycle(db, config_id)
    config_query = (
        select(LaunchConfig)
        .where(LaunchConfig.config_id == config_id)
        .options(lazyload("*"))
        .execution_options(populate_existing=True)
    )
    if lock_session_id is not None:
        config_query = config_query.with_for_update()
    config = (await db.execute(config_query)).unique().scalar_one_or_none()
    instance_query = (
        select(Instance)
        .where(Instance.config_id == config_id)
        .options(lazyload("*"))
        .execution_options(populate_existing=True)
    )
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

    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == config.server_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
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
        reservation = (
            await db.execute(
                select(GpuLaunchReservation)
                .where(GpuLaunchReservation.reservation_id == config.gpu_launch_reservation_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        group = (
            (
                await db.execute(
                    select(GpuAllocationGroup)
                    .where(
                        GpuAllocationGroup.allocation_group_id == reservation.allocation_group_id
                    )
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).scalar_one_or_none()
            if reservation is not None
            else None
        )
        latest = await _latest_attestation_attempt(
            db,
            server.server_id,
            for_update=True,
        )
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
        if require_client_mtls:
            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current launch mTLS possession is required.",
                )
            presented_cert_hash = await _require_presented_attested_cert(request, server)

    # Binding and volume custody are locked last, after token/session callers
    # and all launch, operation, lineage, and latest-attestation checks.
    binding = (
        await db.execute(
            select(DefaultChuteFSVolumeBinding)
            .where(
                DefaultChuteFSVolumeBinding.user_id == config.user_id,
                DefaultChuteFSVolumeBinding.chute_id == config.chute_id,
                DefaultChuteFSVolumeBinding.volume_id == config.default_volume_id,
                DefaultChuteFSVolumeBinding.lifecycle_state == "active",
            )
            .order_by(DefaultChuteFSVolumeBinding.binding_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    volume = (
        await db.execute(
            select(StorageVolume)
            .where(StorageVolume.volume_id == config.default_volume_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
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
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    reexchange_token: Optional[str] = None,
) -> LaunchStorageSessionResponse:
    if access_token is None:
        access_token = _derived_token(row, _ACCESS_PREFIX, "access")
    if refresh_token is None:
        refresh_token = _derived_token(row, _REFRESH_PREFIX, "refresh")
    if reexchange_token is None:
        reexchange_token = _derived_token(row, _REEXCHANGE_PREFIX, "reexchange")
    return LaunchStorageSessionResponse(
        access_token=access_token,
        access_expires_at=row.access_expires_at.isoformat(),
        refresh_token=refresh_token,
        refresh_expires_at=row.refresh_expires_at.isoformat(),
        reexchange_token=reexchange_token,
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
        _presented_cert_hash,
    ) = await _load_current_lineage(
        db,
        config_id,
        request=request,
        lock_session_id=config_id,
    )
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(
                ChuteFSLaunchSession.config_id == config_id,
                ChuteFSLaunchSession.revoked_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = _now()
    immutable_identity = _current_session_identity(
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
    )
    issue_digest = _issue_request_digest(config.config_id, instance.instance_id)
    if row is not None:
        if (
            not _session_matches_current(row, immutable_identity)
            or row.allowed_operations != ALLOWED_OPERATIONS
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Existing ChuteFS launch session has different immutable identity.",
            )
        if (
            row.rotated_from_session_id is None
            and row.generation == 1
            and row.token_seed is not None
            and row.rotation_request_sha256 == issue_digest
            and row.response_replay_until is not None
            and row.response_replay_until > now
        ):
            response = _session_response(row)
            await _prune_expired_session_lineage(db, config_id, now=now)
            await db.commit()
            return _context(config, instance), response
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The active ChuteFS launch session has advanced beyond this issue request.",
        )

    active_key_id = await _active_token_key_id(db)
    successor = ChuteFSLaunchSession(
        session_id=secrets.token_urlsafe(24),
        rotated_from_session_id=None,
        rotated_from_session_sha256=None,
        **immutable_identity,
        allowed_operations=list(ALLOWED_OPERATIONS),
        generation=1,
        access_token_hash="0" * 64,
        refresh_token_hash="0" * 64,
        reexchange_token_hash="0" * 64,
        access_expires_at=now + timedelta(seconds=ACCESS_TTL_SECONDS),
        refresh_expires_at=now + timedelta(seconds=REFRESH_TTL_SECONDS),
        rotation_request_sha256=issue_digest,
        token_seed=secrets.token_hex(32),
        token_key_id=active_key_id,
        response_replay_until=now + timedelta(seconds=ACCESS_TTL_SECONDS),
        rotated_at=now,
    )
    access_token = _derived_token(successor, _ACCESS_PREFIX, "access")
    refresh_token = _derived_token(successor, _REFRESH_PREFIX, "refresh")
    reexchange_token = _derived_token(
        successor,
        _REEXCHANGE_PREFIX,
        "reexchange",
    )
    successor.access_token_hash = _token_hash(access_token)
    successor.refresh_token_hash = _token_hash(refresh_token)
    successor.reexchange_token_hash = _token_hash(reexchange_token)
    db.add(successor)
    await db.flush()
    await _prune_expired_session_lineage(db, config_id, now=now)
    await db.commit()
    await db.refresh(successor)
    return _context(config, instance), _session_response(
        successor,
        access_token,
        refresh_token,
        reexchange_token,
    )


async def exchange_launch_token(
    db: AsyncSession,
    config_id: str,
    launch_token: str,
    request: Request,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    if launch_token.startswith(_REEXCHANGE_PREFIX):
        return await _rotate_launch_storage_session(
            db,
            launch_token,
            request,
            prefix=_REEXCHANGE_PREFIX,
            token_hash_attribute="reexchange_token_hash",
            purpose="reexchange",
            expected_config_id=config_id,
            require_refresh_expiry=False,
        )
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
        acquire_lifecycle_lock=False,
    )
    if launch_identity_claims(config) != {
        key: payload.get("sub") if key == "config_id" else payload.get(key)
        for key in launch_identity_claims(config)
    }:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Launch token identity is stale.",
        )
    # Release any ORM transaction established by the non-authoritative lookup before
    # ChuteFS checks Redis and acquires its user/configuration lock hierarchy.
    await db.commit()
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
            detail="ChuteFS launch access session is invalid, expired, or revoked.",
        )
    await lock_launch_storage_lifecycle(db, config_id)
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.session_id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
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
    ) = await _load_current_lineage(
        db,
        row.config_id,
        request=request,
        locks_held=True,
    )
    current = _current_session_identity(
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
    )
    if not _session_matches_current(row, current):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch session no longer matches its exact binding.",
        )
    await _prune_expired_session_lineage(db, config_id, now=now)
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
    config_id = (
        await db.execute(
            select(ChuteFSLaunchSession.config_id).where(
                ChuteFSLaunchSession.session_id == session_id
            )
        )
    ).scalar_one_or_none()
    if config_id is None:
        return False
    try:
        await lock_launch_storage_lifecycle(db, config_id)
    except HTTPException:
        return False
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.session_id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
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
            locks_held=True,
        )
    except HTTPException:
        return False
    current = _current_session_identity(
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
    )
    return _session_matches_current(row, current)


async def _rotate_launch_storage_session(
    db: AsyncSession,
    token: str,
    request: Request,
    *,
    prefix: str,
    token_hash_attribute: str,
    purpose: str,
    expected_config_id: Optional[str],
    require_refresh_expiry: bool,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    failure_detail = (
        "ChuteFS launch refresh is invalid, expired, replayed, or revoked."
        if purpose == "refresh"
        else "ChuteFS launch re-exchange is invalid, replayed, or revoked."
    )
    session_id = _session_id_from_token(token, prefix)
    config_id = (
        await db.execute(
            select(ChuteFSLaunchSession.config_id).where(
                ChuteFSLaunchSession.session_id == session_id
            )
        )
    ).scalar_one_or_none()
    if config_id is None or (expected_config_id is not None and config_id != expected_config_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=failure_detail,
        )
    await lock_launch_storage_lifecycle(db, config_id)
    row = (
        await db.execute(
            select(ChuteFSLaunchSession)
            .where(ChuteFSLaunchSession.session_id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    now = _now()
    token_digest = _token_hash(token)
    if row is None or not hmac.compare_digest(
        getattr(row, token_hash_attribute),
        token_digest,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=failure_detail,
        )
    request_digest = _rotation_request_digest(
        row.session_id,
        token_digest,
        purpose,
    )
    if row.revoked_at is not None:
        successor = (
            await db.execute(
                select(ChuteFSLaunchSession)
                .where(
                    ChuteFSLaunchSession.rotated_from_session_id == row.session_id,
                    ChuteFSLaunchSession.rotation_request_sha256 == request_digest,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            successor is None
            or successor.revoked_at is not None
            or successor.response_replay_until is None
            or successor.response_replay_until <= now
            or successor.rotated_from_session_sha256 != _canonical_digest(row.session_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=failure_detail,
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
        ) = await _load_current_lineage(
            db,
            config_id,
            request=request,
            lock_session_id=session_id,
            locks_held=True,
        )
        current = _current_session_identity(
            config,
            instance,
            binding,
            volume,
            server,
            reservation,
        )
        if not _session_matches_current(row, current) or not _session_matches_current(
            successor,
            current,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ChuteFS launch rotation lineage is no longer current.",
            )
        response = _session_response(successor)
        await _prune_expired_session_lineage(db, config_id, now=now)
        await db.commit()
        return _context(config, instance), response

    if require_refresh_expiry and row.refresh_expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=failure_detail,
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
    ) = await _load_current_lineage(
        db,
        config_id,
        request=request,
        lock_session_id=session_id,
        locks_held=True,
    )
    current = _current_session_identity(
        config,
        instance,
        binding,
        volume,
        server,
        reservation,
    )
    if not _session_matches_current(row, current):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ChuteFS launch rotation lineage is no longer current.",
        )
    active_key_id = await _active_token_key_id(db)
    successor = ChuteFSLaunchSession(
        session_id=secrets.token_urlsafe(24),
        rotated_from_session_id=row.session_id,
        rotated_from_session_sha256=_canonical_digest(row.session_id),
        **current,
        allowed_operations=list(row.allowed_operations),
        generation=row.generation + 1,
        access_token_hash="0" * 64,
        refresh_token_hash="0" * 64,
        reexchange_token_hash="0" * 64,
        access_expires_at=now + timedelta(seconds=ACCESS_TTL_SECONDS),
        refresh_expires_at=now + timedelta(seconds=REFRESH_TTL_SECONDS),
        rotation_request_sha256=request_digest,
        token_seed=secrets.token_hex(32),
        token_key_id=active_key_id,
        response_replay_until=now + timedelta(seconds=ACCESS_TTL_SECONDS),
        rotated_at=now,
    )
    access_token = _derived_token(successor, _ACCESS_PREFIX, "access")
    refresh_token = _derived_token(successor, _REFRESH_PREFIX, "refresh")
    reexchange_token = _derived_token(
        successor,
        _REEXCHANGE_PREFIX,
        "reexchange",
    )
    successor.access_token_hash = _token_hash(access_token)
    successor.refresh_token_hash = _token_hash(refresh_token)
    successor.reexchange_token_hash = _token_hash(reexchange_token)
    row.revoked_at = now
    await db.flush()
    db.add(successor)
    await db.flush()
    await _prune_expired_session_lineage(db, config_id, now=now)
    await db.commit()
    await db.refresh(successor)
    return _context(config, instance), _session_response(
        successor,
        access_token,
        refresh_token,
        reexchange_token,
    )


async def refresh_launch_storage_session(
    db: AsyncSession,
    authorization: str,
    request: Request,
) -> tuple[LaunchStorageContext, LaunchStorageSessionResponse]:
    token = _bearer(authorization)
    return await _rotate_launch_storage_session(
        db,
        token,
        request,
        prefix=_REFRESH_PREFIX,
        token_hash_attribute="refresh_token_hash",
        purpose="refresh",
        expected_config_id=None,
        require_refresh_expiry=True,
    )
