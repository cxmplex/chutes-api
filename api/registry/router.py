"""Registry authorization for Model A/GPU miners and reservation-attested Model-B TDs."""

from datetime import datetime, timedelta, timezone
import re
from typing import Annotated, Optional
from urllib.parse import parse_qs, urlsplit

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.x509 import Certificate
from loguru import logger

from api.config import settings
from api.constants import (
    AUTHORIZATION_HEADER,
    HOTKEY_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
)
from api.database import generate_uuid, get_db_session
from api.host.schemas import (
    GpuAllocationGroup,
    GpuLaunchReservation,
    RegistrySession,
    RegistrySessionClaimsV1,
    RegistrySessionRequestV1,
    RegistrySessionResponseV1,
    TdLaunchReservation,
    canonical_sha256,
)
from api.server.schemas import Server, ServerAttestation
from api.host.locks import (
    acquire_gpu_lifecycle_lock,
    acquire_registry_subject_locks,
    assert_gpu_external_work_allowed,
)
from api.instance.schemas import Instance, LaunchConfig
from api.job.schemas import Job
from api.server.gpu_sessions import (
    GPU_RUNTIME_SESSION_HEADER,
    _current_attestation,
    _latest_attestation_attempt,
    validate_gpu_runtime_session,
)
from api.server.util import extract_client_cert_hash
from api.user.service import get_current_user
from api.registry.oci import (
    OciClosureError,
    OciDescriptorClosure,
    resolve_oci_descriptor_closure,
)
from api.server.service import lookup_server_by_ip
from api.server.util import (
    verify_server_cert,
    require_registry_proxy_secret,
    extract_optional_client_cert,
)
from api.server.exceptions import AttestationError
from api.log import update_log_context
from api.util import semcomp


router = APIRouter()


async def _miner_launch_scope_current(
    db: AsyncSession,
    server: Server,
    launch_config: LaunchConfig | None,
    *,
    for_update: bool = False,
) -> bool:
    if (
        launch_config is None
        or launch_config.server_id != server.server_id
        or launch_config.miner_hotkey != server.miner_hotkey
        or launch_config.gpu_management_mode != "miner"
        or launch_config.gpu_launch_reservation_id != server.gpu_launch_reservation_id
        or launch_config.failed_at is not None
        or launch_config.completed_at is not None
        or launch_config.verification_error is not None
        or launch_config.registry_scope_active is not True
        or launch_config.registry_scope_revoked_at is not None
    ):
        return False
    instance_query = select(Instance).where(Instance.config_id == launch_config.config_id)
    if for_update:
        instance_query = instance_query.with_for_update()
    instance = (await db.execute(instance_query)).unique().scalar_one_or_none()
    if instance is not None:
        return bool(
            instance.server_id == server.server_id
            and instance.gpu_management_mode == "miner"
            and instance.gpu_launch_reservation_id == server.gpu_launch_reservation_id
            and instance.verification_error is None
            and instance.stop_billing_at is None
            and (instance.active or not instance.verified)
        )
    if launch_config.job_id is not None:
        job_query = select(Job).where(Job.job_id == launch_config.job_id)
        if for_update:
            job_query = job_query.with_for_update()
        job = (await db.execute(job_query)).scalar_one_or_none()
        return bool(
            job is not None
            and job.gpu_management_mode == "miner"
            and job.gpu_launch_reservation_id == server.gpu_launch_reservation_id
            and job.finished_at is None
            and job.miner_terminated is not True
        )
    # The scope is created before containerd can pull the image and therefore
    # before an Instance exists. The explicit active bit is set only by the
    # launch-config transaction and is cleared by every terminal lifecycle.
    return launch_config.retrieved_at is None


_legacy_registry_auth = get_current_user(
    purpose="registry",
    registered_to=settings.netuid,
    raise_not_found=False,
    force_hotkey_auth=True,
)


async def _current_attested_registry_server(db: AsyncSession, cert_hash: str) -> Server:
    server = (
        await db.execute(
            select(Server).where(
                Server.attested_cert_pubkey_hash == cert_hash.lower(),
                Server.self_registered.is_(True),
                Server.is_tee.is_(True),
            )
        )
    ).scalar_one_or_none()
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented certificate is not a current registry-capable TD identity.",
        )
    if server.compute_type == "gpu":
        if (
            server.tee_type != "tdx"
            or server.gpu_management_mode not in {"platform", "miner"}
            or not server.gpu_launch_reservation_id
            or server.gpu_retired_at is not None
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GPU registry access requires a current attested reservation.",
            )
        _current_attestation(
            server,
            await _latest_attestation_attempt(db, server.server_id),
        )
        return server
    if server.compute_type != "cpu" or not server.launch_reservation_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TD identity is not registry-capable.",
        )
    latest = await _latest_attestation_attempt(db, server.server_id)
    _cpu_registry_attestation_current(server, latest)
    return server


def _cpu_registry_attestation_current(
    server: Server,
    latest: ServerAttestation | None,
) -> ServerAttestation:
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.release_attestation_max_age_seconds
    )
    if (
        latest is None
        or latest.server_id != server.server_id
        or latest.verification_error is not None
        or latest.verified_at is None
        or latest.verified_at < cutoff
        or latest.measurement_name != server.measurement_name
        or latest.measurement_config_fingerprint != server.measurement_config_fingerprint
        or latest.trust_set_fingerprint != server.trust_set_fingerprint
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TD does not have a fresh exact attestation.",
        )
    return latest


def _gpu_registry_snapshot(
    server: Server,
    runtime_payload: dict,
    cert_hash: str,
) -> dict:
    return {
        "kind": "gpu",
        "server_id": server.server_id,
        "cert_hash": cert_hash.lower(),
        "runtime_payload": dict(runtime_payload),
    }


async def _cpu_registry_snapshot(
    db: AsyncSession,
    server: Server,
    cert_hash: str,
) -> dict:
    latest = await _latest_attestation_attempt(db, server.server_id)
    _cpu_registry_attestation_current(server, latest)
    return {
        "kind": "cpu",
        "server_id": server.server_id,
        "cert_hash": cert_hash.lower(),
        "launch_reservation_id": server.launch_reservation_id,
        "attestation_id": latest.attestation_id,
    }


async def _locked_registry_authority(
    db: AsyncSession,
    snapshot: dict,
) -> tuple[Server, GpuLaunchReservation | TdLaunchReservation]:
    """Refetch the exact attestation and reservation after descriptor resolution."""

    server = (
        await db.execute(
            select(Server)
            .where(Server.server_id == snapshot["server_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if (
        server is None
        or server.attested_cert_pubkey_hash != snapshot["cert_hash"]
        or not server.self_registered
        or not server.is_tee
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry attestation identity changed during descriptor resolution.",
        )

    if snapshot["kind"] == "gpu":
        payload = snapshot["runtime_payload"]
        reservation = (
            await db.execute(
                select(GpuLaunchReservation)
                .where(GpuLaunchReservation.reservation_id == payload["reservation_id"])
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        group = (
            (
                await db.execute(
                    select(GpuAllocationGroup)
                    .where(GpuAllocationGroup.allocation_group_id == server.gpu_allocation_group_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).scalar_one_or_none()
            if server.gpu_allocation_group_id is not None
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
                expected_id=payload["attestation_id"],
            )
        except HTTPException as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GPU registry attestation changed during descriptor resolution.",
            ) from exc
        now = datetime.now(timezone.utc)
        if (
            datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc) <= now
            or server.compute_type != "gpu"
            or server.tee_type != "tdx"
            or server.gpu_retired_at is not None
            or server.server_id != payload["server_id"]
            or server.miner_hotkey != payload["owner_hotkey"]
            or server.gpu_management_mode != payload["management_mode"]
            or server.gpu_launch_reservation_id != payload["reservation_id"]
            or server.attested_cert_pubkey_hash != payload["attested_spki_sha256"]
            or server.gpu_runtime_session_attestation_id != payload["attestation_id"]
            or server.gpu_runtime_session_expires_at is None
            or server.gpu_runtime_session_expires_at <= now
            or reservation is None
            or group is None
            or reservation.state != "running"
            or group.state != "running"
            or reservation.registration_attestation_id is None
            or reservation.server_id != server.server_id
            or reservation.management_mode != server.gpu_management_mode
            or reservation.allocation_group_id != server.gpu_allocation_group_id
            or reservation.allocation_group_generation != server.gpu_allocation_group_generation
            or reservation.process_incarnation != server.gpu_process_incarnation
            or reservation.topology_fingerprint != server.gpu_topology_fingerprint
            or group.management_mode != reservation.management_mode
            or group.reservation_id != reservation.reservation_id
            or group.generation != reservation.allocation_group_generation
            or group.reservation_generation != reservation.reservation_generation
            or group.process_incarnation != reservation.process_incarnation
            or latest is None
            or latest.gpu_claims_sha256 != reservation.claims_sha256
            or latest.gpu_release_id != reservation.gpu_release_id
            or latest.gpu_profile_id != reservation.profile_id
            or latest.gpu_host_boot_generation != reservation.host_boot_generation
            or latest.gpu_reservation_generation != reservation.reservation_generation
            or latest.gpu_evidence_certificate_sha256s
            != reservation.gpu_attestation_certificate_sha256s
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GPU runtime lineage changed during descriptor resolution.",
            )
        return server, reservation

    latest_query = (
        select(ServerAttestation)
        .where(ServerAttestation.server_id == server.server_id)
        .order_by(ServerAttestation.attempt_sequence.desc())
        .limit(1)
        .with_for_update()
    )
    latest = (await db.execute(latest_query)).scalar_one_or_none()
    reservation = (
        await db.execute(
            select(TdLaunchReservation)
            .where(TdLaunchReservation.reservation_id == snapshot["launch_reservation_id"])
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    _cpu_registry_attestation_current(server, latest)
    if (
        server.compute_type != "cpu"
        or server.launch_reservation_id != snapshot["launch_reservation_id"]
        or latest is None
        or latest.attestation_id != snapshot["attestation_id"]
        or reservation is None
        or reservation.consumed_at is None
        or reservation.invalidated_at is not None
        or reservation.server_id != server.server_id
        or reservation.role != "chute"
        or reservation.consumed_cert_pubkey_hash != snapshot["cert_hash"]
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CPU runtime lineage changed during descriptor resolution.",
        )
    return server, reservation


def _encode_registry_session(row: RegistrySession) -> str:
    claims = RegistrySessionClaimsV1(
        session_id=row.session_id,
        server_id=row.server_id,
        scope_id=row.scope_id,
        launch_config_id=row.launch_config_id,
        attested_cert_sha256=row.attested_cert_pubkey_hash,
        repository=row.repository,
        actions=row.actions,
        manifest_digest=row.manifest_digest,
        descriptor_closure_sha256=row.descriptor_closure_sha256,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
    )
    return jwt.encode(
        {
            **claims.model_dump(mode="json"),
            "iss": "chutes",
            "purpose": "registry_session",
            "jti": row.token_id,
            "iat": int(row.issued_at.timestamp()),
            "exp": int(row.expires_at.timestamp()),
        },
        settings.launch_config_key,
        algorithm="HS256",
    )


def _registry_session_response(
    row: RegistrySession,
    token: str,
) -> RegistrySessionResponseV1:
    return RegistrySessionResponseV1(
        token=token,
        expires_at=row.expires_at,
        launch_config_id=row.launch_config_id,
        repository=row.repository,
        manifest_digest=row.manifest_digest,
        descriptor_closure_sha256=row.descriptor_closure_sha256,
        allowed_manifests=list(row.allowed_manifests),
        allowed_blobs=list(row.allowed_blobs),
        allowed_manifest_tags=list(row.allowed_manifest_tags),
        manifest_tag_digests=dict(row.manifest_tag_digests),
    )


@router.post("/sessions", response_model=RegistrySessionResponseV1)
async def create_registry_session(
    body: RegistrySessionRequestV1,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    attested_session: Annotated[
        str | None,
        Header(alias=GPU_RUNTIME_SESSION_HEADER),
    ] = None,
):
    """Mint one short current-attestation-bound repository/digest pull session."""

    cert_hash = await extract_client_cert_hash(require_proxy_verified=True)(request)
    runtime_payload = None
    if attested_session:
        server, runtime_payload = await validate_gpu_runtime_session(
            db,
            attested_session,
            required_purpose="registry",
        )
        if server.attested_cert_pubkey_hash != cert_hash.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Runtime session certificate does not match the presented identity.",
            )
    else:
        server = await _current_attested_registry_server(db, cert_hash)
        if server.compute_type == "gpu":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="GPU registry session creation requires an attested runtime session.",
            )
    platform_runtime = bool(
        runtime_payload is not None and server.gpu_management_mode == "platform"
    )
    authority_snapshot = (
        _gpu_registry_snapshot(server, runtime_payload, cert_hash)
        if runtime_payload is not None
        else await _cpu_registry_snapshot(db, server, cert_hash)
    )
    # Release the authentication read transaction before bounded registry I/O.  The exact
    # attestation/reservation/certificate lineage is compared under the lifecycle lock below.
    await db.commit()
    resolved_closure = None
    if not platform_runtime:
        assert_gpu_external_work_allowed(db, "registry descriptor closure resolution")
        try:
            resolved_closure = await resolve_oci_descriptor_closure(
                body.repository,
                body.manifest_digest,
            )
        except OciClosureError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The reserved OCI descriptor closure could not be verified.",
            ) from exc
    await acquire_gpu_lifecycle_lock(db)
    server, authority_reservation = await _locked_registry_authority(
        db,
        authority_snapshot,
    )
    scope_id = ""
    launch_config = None
    platform_closure = None
    if runtime_payload is not None:
        if server.gpu_management_mode == "miner":
            if body.launch_config_id is not None:
                launch_config = (
                    (
                        await db.execute(
                            select(LaunchConfig)
                            .where(LaunchConfig.config_id == body.launch_config_id)
                            .with_for_update()
                        )
                    )
                    .unique()
                    .scalar_one_or_none()
                )
            valid_scope = bool(
                await _miner_launch_scope_current(db, server, launch_config, for_update=True)
                and launch_config.container_repository == body.repository
                and launch_config.container_manifest_digest == body.manifest_digest
            )
            scope_id = f"launch-config:{body.launch_config_id}"
        else:
            reservation = authority_reservation
            valid_scope = bool(
                body.launch_config_id is None
                and reservation is not None
                and reservation.state == "running"
                and reservation.server_id == server.server_id
                and reservation.management_mode == "platform"
                and reservation.container_repository == body.repository
                and reservation.container_manifest_digest == body.manifest_digest
            )
            scope_id = f"gpu-reservation:{server.gpu_launch_reservation_id}"
            if valid_scope:
                expected_closure_sha256 = canonical_sha256(
                    {
                        "schema": "chutes.oci-descriptor-closure",
                        "version": 1,
                        "root_manifest": reservation.container_manifest_digest,
                        "manifests": reservation.allowed_manifests,
                        "blobs": reservation.allowed_blobs,
                        "manifest_tags": reservation.allowed_manifest_tags,
                        "manifest_tag_digests": reservation.manifest_tag_digests,
                    }
                )
                if (
                    reservation.descriptor_closure_sha256 != expected_closure_sha256
                    or reservation.container_manifest_digest not in reservation.allowed_manifests
                    or not reservation.allowed_manifest_tags
                    or set(reservation.manifest_tag_digests)
                    != set(reservation.allowed_manifest_tags)
                ):
                    valid_scope = False
                else:
                    platform_closure = OciDescriptorClosure(
                        manifests=tuple(reservation.allowed_manifests),
                        blobs=tuple(reservation.allowed_blobs),
                        manifest_tags=tuple(reservation.allowed_manifest_tags),
                        manifest_tag_digests=tuple(
                            sorted(reservation.manifest_tag_digests.items())
                        ),
                        sha256=reservation.descriptor_closure_sha256,
                    )
    else:
        reservation = authority_reservation
        valid_scope = bool(
            body.launch_config_id is None
            and reservation is not None
            and reservation.consumed_at is not None
            and reservation.invalidated_at is None
            and reservation.server_id == server.server_id
            and reservation.role == "chute"
            and reservation.container_repository == body.repository
            and reservation.container_manifest_digest == body.manifest_digest
        )
        scope_id = f"td-reservation:{server.launch_reservation_id}"
    if not valid_scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry request does not match its exact server-bound launch scope.",
        )
    existing = (
        await db.execute(
            select(RegistrySession)
            .where(
                RegistrySession.server_id == server.server_id,
                RegistrySession.scope_id == scope_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        existing is not None
        and existing.revoked_at is None
        and existing.expires_at > now
        and existing.attested_cert_pubkey_hash == cert_hash.lower()
        and existing.repository == body.repository
        and existing.launch_config_id == body.launch_config_id
        and existing.actions == ["pull"]
        and existing.manifest_digest == body.manifest_digest
        and _registry_request_matches(
            existing,
            "GET",
            f"/v2/{existing.repository}/manifests/{existing.manifest_digest}",
        )
    ):
        return _registry_session_response(
            existing,
            _encode_registry_session(existing),
        )
    if platform_closure is not None:
        closure = platform_closure
    else:
        if resolved_closure is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The reserved OCI descriptor closure could not be verified.",
            )
        closure = resolved_closure
    expires_at = now + timedelta(minutes=10)
    token_id = generate_uuid()
    if existing is None:
        row = RegistrySession(
            session_id=generate_uuid(),
            token_id=token_id,
            server_id=server.server_id,
            scope_id=scope_id,
        )
        db.add(row)
    else:
        row = existing
        row.token_id = token_id
    row.attested_cert_pubkey_hash = cert_hash.lower()
    row.scope_id = scope_id
    row.launch_config_id = body.launch_config_id
    row.repository = body.repository
    row.actions = ["pull"]
    row.manifest_digest = body.manifest_digest
    row.allowed_manifests = list(closure.manifests)
    row.allowed_blobs = list(closure.blobs)
    row.allowed_manifest_tags = list(closure.manifest_tags)
    row.manifest_tag_digests = dict(closure.manifest_tag_digests)
    row.descriptor_closure_sha256 = closure.sha256
    row.issued_at = now
    row.expires_at = expires_at
    row.revoked_at = None
    row.last_used_at = None
    token = _encode_registry_session(row)
    await db.commit()
    return _registry_session_response(row, token)


@router.delete("/sessions/{launch_config_id}")
async def revoke_registry_session(
    launch_config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    attested_session: Annotated[
        str | None,
        Header(alias=GPU_RUNTIME_SESSION_HEADER),
    ] = None,
):
    if not attested_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry revocation requires the current attested runtime session.",
        )
    server, _payload = await validate_gpu_runtime_session(
        db,
        attested_session,
        required_purpose="registry",
    )
    cert_hash = await extract_client_cert_hash(require_proxy_verified=True)(request)
    if server.attested_cert_pubkey_hash != cert_hash.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry revocation certificate does not match the session.",
        )
    await acquire_gpu_lifecycle_lock(db)
    config = (
        (
            await db.execute(
                select(LaunchConfig)
                .where(LaunchConfig.config_id == launch_config_id)
                .with_for_update()
            )
        )
        .unique()
        .scalar_one_or_none()
    )
    if (
        config is None
        or config.server_id != server.server_id
        or config.gpu_management_mode != "miner"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry revocation does not match this logical server.",
        )
    now = datetime.now(timezone.utc)
    config.registry_scope_active = False
    config.registry_scope_revoked_at = config.registry_scope_revoked_at or now
    rows = (
        (
            await db.execute(
                select(RegistrySession)
                .where(RegistrySession.launch_config_id == launch_config_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        row.revoked_at = row.revoked_at or now
    await db.commit()
    return {"revoked": True, "launch_config_id": launch_config_id}


def _registry_request_matches(
    session: RegistrySession, original_method: str, original_uri: str
) -> bool:
    method = original_method.upper()
    if method not in {"GET", "HEAD"}:
        return False
    parsed = urlsplit(original_uri)
    path = parsed.path
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    if path == "/v2/":
        return not parsed.query
    if path == "/v2/_token":
        if method != "GET":
            return False
        try:
            query = parse_qs(
                parsed.query,
                strict_parsing=True,
                keep_blank_values=True,
            )
        except ValueError:
            return False
        if not set(query).issubset({"scope", "service"}):
            return False
        scopes = query.get("scope") or []
        services = query.get("service") or []
        return bool(
            scopes == [f"repository:{session.repository}:pull"]
            and (not services or services == ["registry.chutes.ai"])
        )
    if parsed.query or not session.descriptor_closure_sha256:
        return False
    manifests = session.allowed_manifests
    blobs = session.allowed_blobs
    tags = session.allowed_manifest_tags
    tag_digests = session.manifest_tag_digests
    if (
        not isinstance(manifests, list)
        or not isinstance(blobs, list)
        or not isinstance(tags, list)
        or not isinstance(tag_digests, dict)
        or not 1 <= len(manifests) <= 128
        or len(blobs) > 2048
        or len(tags) > 32
    ):
        return False
    if (
        manifests != sorted(set(manifests))
        or blobs != sorted(set(blobs))
        or tags != sorted(set(tags))
        or set(tag_digests) != set(tags)
        or any(value not in manifests for value in tag_digests.values())
        or session.manifest_digest not in manifests
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in manifests)
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in blobs)
        or any(not re.fullmatch(r"sha256-[0-9a-f]{64}\.sig", item) for item in tags)
        or canonical_sha256(
            {
                "schema": "chutes.oci-descriptor-closure",
                "version": 1,
                "root_manifest": session.manifest_digest,
                "manifests": manifests,
                "blobs": blobs,
                "manifest_tags": tags,
                "manifest_tag_digests": tag_digests,
            }
        )
        != session.descriptor_closure_sha256
    ):
        return False
    prefix = f"/v2/{session.repository}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix) :]
    if suffix.startswith("manifests/"):
        reference = suffix.removeprefix("manifests/")
        return "/" not in reference and (reference in manifests or reference in tags)
    if suffix.startswith("blobs/"):
        reference = suffix.removeprefix("blobs/")
        return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", reference) and reference in blobs)
    return False


def _validated_registry_session_row(
    row: RegistrySession | None,
    payload: dict,
    cert_hash: str,
    original_method: str,
    original_uri: str,
    launch_config_id: str | None,
) -> RegistrySession:
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry session does not authorize this certificate/repository/action.",
        )
    expected = {
        "session_id": row.session_id,
        "jti": row.token_id,
        "server_id": row.server_id,
        "scope_id": row.scope_id,
        "launch_config_id": row.launch_config_id,
        "attested_cert_sha256": row.attested_cert_pubkey_hash,
        "repository": row.repository,
        "actions": row.actions,
        "manifest_digest": row.manifest_digest,
        "descriptor_closure_sha256": row.descriptor_closure_sha256,
    }
    now = datetime.now(timezone.utc)
    if (
        row.revoked_at is not None
        or row.expires_at <= now
        or row.attested_cert_pubkey_hash != cert_hash.lower()
        or row.launch_config_id != launch_config_id
        or any(payload.get(key) != value for key, value in expected.items())
        or not _registry_request_matches(row, original_method, original_uri)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry session does not authorize this certificate/repository/action.",
        )
    return row


async def _validate_registry_session(
    db: AsyncSession,
    token: str,
    cert_hash: str,
    original_method: str,
    original_uri: str,
    launch_config_id: str | None,
) -> RegistrySession:
    try:
        payload = jwt.decode(
            token,
            settings.launch_config_key,
            algorithms=["HS256"],
            issuer="chutes",
            options={
                "require": [
                    "iss",
                    "purpose",
                    "jti",
                    "iat",
                    "exp",
                    "session_id",
                    "server_id",
                    "scope_id",
                    "launch_config_id",
                    "attested_cert_sha256",
                    "repository",
                    "actions",
                    "manifest_digest",
                    "descriptor_closure_sha256",
                    "issued_at",
                    "expires_at",
                ]
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry session is invalid or expired.",
        ) from exc
    if payload.get("purpose") != "registry_session":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry session purpose is invalid.",
        )
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id or session_id != session_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Registry session identity is invalid.",
        )
    preflight = (
        await db.execute(select(RegistrySession).where(RegistrySession.session_id == session_id))
    ).scalar_one_or_none()
    preflight = _validated_registry_session_row(
        preflight,
        payload,
        cert_hash,
        original_method,
        original_uri,
        launch_config_id,
    )
    await acquire_registry_subject_locks(
        db,
        server_id=preflight.server_id,
        launch_config_id=preflight.launch_config_id,
    )
    row = (
        await db.execute(
            select(RegistrySession)
            .where(RegistrySession.session_id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    row = _validated_registry_session_row(
        row,
        payload,
        cert_hash,
        original_method,
        original_uri,
        launch_config_id,
    )
    server = await _current_attested_registry_server(db, cert_hash)
    if server.server_id != row.server_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry session server identity changed.",
        )
    if server.compute_type == "gpu":
        scope_current = False
        if server.gpu_management_mode == "miner" and row.launch_config_id:
            launch_config = await db.get(LaunchConfig, row.launch_config_id)
            scope_current = bool(
                await _miner_launch_scope_current(db, server, launch_config)
                and launch_config.container_repository == row.repository
                and launch_config.container_manifest_digest == row.manifest_digest
                and row.scope_id == f"launch-config:{launch_config.config_id}"
            )
        elif server.gpu_management_mode == "platform" and row.launch_config_id is None:
            reservation = await db.get(
                GpuLaunchReservation,
                server.gpu_launch_reservation_id,
            )
            scope_current = bool(
                reservation is not None
                and reservation.state == "running"
                and reservation.management_mode == "platform"
                and reservation.server_id == server.server_id
                and reservation.container_repository == row.repository
                and reservation.container_manifest_digest == row.manifest_digest
                and reservation.descriptor_closure_sha256 == row.descriptor_closure_sha256
                and reservation.allowed_manifests == row.allowed_manifests
                and reservation.allowed_blobs == row.allowed_blobs
                and reservation.allowed_manifest_tags == row.allowed_manifest_tags
                and reservation.manifest_tag_digests == row.manifest_tag_digests
                and row.scope_id == f"gpu-reservation:{server.gpu_launch_reservation_id}"
            )
        if not scope_current:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GPU registry session no longer matches its exact launch scope.",
            )
    row.last_used_at = datetime.now(timezone.utc)
    await db.commit()
    return row


def _canonical_registry_upstream_uri(
    row: RegistrySession,
    original_uri: str,
) -> str:
    parsed = urlsplit(original_uri)
    prefix = f"/v2/{row.repository}/manifests/"
    if parsed.path.startswith(prefix):
        reference = parsed.path.removeprefix(prefix)
        digest = dict(row.manifest_tag_digests or {}).get(reference)
        if digest:
            return f"{prefix}{digest}"
    return original_uri


@router.get("/auth")
async def registry_auth(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    registry_session: str | None = Header(None, alias="X-Chutes-Registry-Session"),
    attested_session: str | None = Header(
        None,
        alias=GPU_RUNTIME_SESSION_HEADER,
    ),
    original_method: str | None = Header(None, alias="X-Chutes-Registry-Method"),
    original_uri: str | None = Header(None, alias="X-Chutes-Registry-Uri"),
    launch_config_id: str | None = Header(None, alias="X-Chutes-Launch-Config-ID"),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
    nonce: str | None = Header(None, alias=NONCE_HEADER),
    authorization: str | None = Header(None, alias=AUTHORIZATION_HEADER),
    sig_version: str | None = Header(None, alias=SIG_VERSION_HEADER),
    client_verify: str | None = Header(None, alias="X-Client-Verify"),
    client_cert_header: str | None = Header(None, alias="X-Client-Cert"),
    response: Response = None,
    _proxy=Depends(require_registry_proxy_secret()),
    client_cert: Optional[Certificate] = Depends(extract_optional_client_cert()),
):
    """Authorize registry bytes without weakening exact repository/digest scope.

    New mTLS-capable VMs must present a CA-authenticated client certificate *and* an exact,
    current registry session. The certificate authenticates the VM transport; the session remains
    the only authority for repository, manifest, descriptor closure, and request action. Older or
    unknown VMs may use the legacy miner signature path until the configured cutoff.
    """

    # Direct unit calls leave FastAPI parameter markers in defaulted arguments. Production
    # injection always supplies strings or None; normalize markers to that same contract.
    def _header_value(value):
        return value if isinstance(value, str) else None

    registry_session = _header_value(registry_session)
    attested_session = _header_value(attested_session)
    original_method = _header_value(original_method)
    original_uri = _header_value(original_uri)
    launch_config_id = _header_value(launch_config_id)
    hotkey = _header_value(hotkey)
    signature = _header_value(signature)
    nonce = _header_value(nonce)
    authorization = _header_value(authorization)
    sig_version = _header_value(sig_version)
    client_verify = _header_value(client_verify)
    client_cert_header = _header_value(client_cert_header)

    if attested_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Broad attested sessions cannot authorize registry bytes; "
                "mint an exact registry session."
            ),
        )

    # FastAPI resolves the dependency to a Certificate. Direct unit calls that omit it leave the
    # Depends marker in place; treat that as absent rather than as authenticated evidence.
    parsed_client_cert = client_cert if isinstance(client_cert, Certificate) else None
    state_ip = getattr(getattr(request, "state", None), "client_ip", None)
    peer_ip = getattr(getattr(request, "client", None), "host", None)
    client_ip = state_ip if isinstance(state_ip, str) and state_ip else None
    if client_ip is None and isinstance(peer_ip, str) and peer_ip:
        client_ip = peer_ip
    server = await lookup_server_by_ip(db, client_ip) if client_ip else None
    update_log_context(
        ip=client_ip,
        server_id=getattr(server, "server_id", None),
        server_name=getattr(server, "name", None),
        miner_hotkey=hotkey or request.headers.get(HOTKEY_HEADER),
    )
    requires_mtls = bool(
        server is not None
        and server.version
        and semcomp(server.version, settings.registry_mtls_min_version) >= 0
    )
    certificate_presented = bool(
        parsed_client_cert
        or client_cert_header
        or (client_verify and client_verify.strip().upper() not in {"", "NONE"})
    )
    if registry_session or certificate_presented:
        if not registry_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Certificate-presenting registry requests require an attested session.",
            )
        if not original_method or not original_uri:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Registry session request context is missing.",
            )
        if requires_mtls:
            _verify_mtls_client_cert(parsed_client_cert, server, client_ip)
        cert_hash = await extract_client_cert_hash(require_proxy_verified=True)(request)
        row = await _validate_registry_session(
            db,
            registry_session,
            cert_hash,
            original_method,
            original_uri,
            launch_config_id,
        )
        if response is not None:
            response.headers["X-Chutes-Registry-Upstream-Uri"] = _canonical_registry_upstream_uri(
                row, original_uri
            )
        return {"authenticated": True, "auth_type": "attested_registry_session"}
    if requires_mtls:
        _verify_mtls_client_cert(None, server, client_ip)
    await _legacy_registry_auth(
        request,
        hotkey=hotkey,
        signature=signature,
        nonce=nonce,
        authorization=authorization,
        sig_version=sig_version,
    )
    return {"authenticated": True, "auth_type": "legacy_miner"}


def _verify_mtls_client_cert(
    client_cert: Optional[Certificate], server, client_ip: str | None
) -> None:
    """Require a valid mTLS client cert for VMs at/above registry_mtls_min_version.

    Delegates to the shared verify_server_cert: the client leaf (extracted from X-Client-Cert
    by extract_optional_client_cert) is verified against the CA the VM recorded via
    POST /servers/{vm_name}/provision, adding registry-context logging.

    Raises NoClientCertError (403) if no client cert is presented or the VM has no CA on file,
    or InvalidClientCertError (403) if the leaf fails verification (both are AttestationError).
    """
    try:
        verify_server_cert(client_cert, server)
    except AttestationError as e:
        logger.warning(
            f"registry: mTLS rejected for VM at {client_ip} "
            f"(server={server.name}, version={server.version})"
        )
        raise HTTPException(status_code=e.http_status, detail=e.message)
    logger.info(f"registry: mTLS auth accepted for VM at {client_ip} (server={server.name})")


async def _legacy_registry_auth(
    request: Request,
    *,
    hotkey: str | None = None,
    signature: str | None = None,
    nonce: str | None = None,
    authorization: str | None = None,
    sig_version: str | None = None,
) -> None:
    """
    Perform legacy Bittensor SS58 hotkey/signature/nonce auth for registry pulls.

    Manually extracts auth headers from the request and calls the authenticator so
    that we can invoke it outside of FastAPI's dependency injection (it runs only on
    the legacy branch, not unconditionally as a route dependency).

    Raises HTTPException(401) if the credentials are absent or invalid.
    """
    authenticator = get_current_user(purpose="registry", registered_to=settings.netuid)
    hotkey = hotkey or request.headers.get(HOTKEY_HEADER)
    signature = signature or request.headers.get(SIGNATURE_HEADER)
    nonce = nonce or request.headers.get(NONCE_HEADER)
    authorization = authorization or request.headers.get(AUTHORIZATION_HEADER)
    sig_version = sig_version or request.headers.get(SIG_VERSION_HEADER)
    await authenticator(
        request=request,
        api_key=None,
        hotkey=hotkey,
        signature=signature,
        nonce=nonce,
        authorization=authorization,
        sig_version=sig_version,
    )
