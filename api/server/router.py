"""
FastAPI routes for server management and TDX attestation.
"""

import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Request, status, Header, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError, DatabaseError
from loguru import logger

from api.agent_channel import send_agent_command
from api.database import get_db_session
from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.node.util import check_node_inventory
from api.host.schemas import canonical_sha256
from api.user.schemas import User
from api.user.service import get_current_user
from api.constants import (
    HOTKEY_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    NoncePurpose,
)

from api.server.schemas import (
    BootAttestationArgs,
    RuntimeAttestationArgs,
    RuntimeAttestationNonceContext,
    ServerArgs,
    CpuServerRegistrationArgs,
    CpuServerRegistrationResponse,
    GpuServerRegistrationArgs,
    GpuServerRegistrationResponse,
    GpuRuntimeSessionResponse,
    GpuInfraLeaseRequestV1,
    GpuInfraLeaseResponseV1,
    GpuInfraConfirmRequestV1,
    GpuInfraConfirmResponseV1,
    GpuInfraAcknowledgeRequestV1,
    GpuInfraAcknowledgeResponseV1,
    GpuInfraAbandonRequestV1,
    GpuInfraAbandonResponseV1,
    GpuInfraCloseRequestV1,
    GpuInfraCloseResponseV1,
    GpuInfraMigrationPromoteRequestV1,
    GpuInfraMigrationPromoteResponseV1,
    GpuInfraMigrationRefreshRequestV1,
    GpuInfraMigrationRefreshResponseV1,
    GpuInfraRetireRequestV1,
    GpuInfraRetireResponseV1,
    GpuInfraMigrationCompleteRequestV1,
    GpuInfraMigrationCompleteResponseV1,
    GpuLegacyCloseRequestV1,
    GpuLegacyCloseResponseV1,
    GpuLegacyMigration,
    Server,
    ServerAttestation,
    Host,
    NonceResponse,
    BootAttestationResponse,
    RuntimeAttestationResponse,
    LuksAttestRequest,
    LuksAttestResponse,
    LuksVolumeInfo,
    LuksConfirmRequest,
    LuksConfirmResponse,
    PreflightResult,
    ConfirmMaintenanceResult,
    MaintenancePolicyResponse,
    ServerUpgradeStatus,
    TeeUpgradeWindow,
    UpgradeWindowInfo,
    TeeMeasurementResponse,
)
from api.server.gpu_sessions import (
    GPU_PLATFORM_RUNTIME_SESSION_PURPOSES,
    GPU_RUNTIME_SESSION_HEADER,
    GPU_RUNTIME_SESSION_PURPOSES,
    latest_gpu_runtime_session,
    validate_gpu_runtime_session,
)
from api.server.gpu_infra import (
    abandon_gpu_infra,
    acknowledge_gpu_infra_closed,
    acknowledge_gpu_infra,
    close_legacy_gpu_sources,
    complete_gpu_infra_migration,
    confirm_gpu_infra,
    lease_gpu_infra,
    promote_gpu_infra_migration,
    refresh_gpu_infra_migration,
    retire_gpu_infra_key,
)
from api.server.service import (
    create_nonce,
    validate_and_consume_nonce,
    issue_boot_attestation_nonce,
    process_boot_attestation,
    register_server,
    register_cpu_server,
    register_gpu_server,
    check_server_ownership,
    get_server_by_name_or_id,
    update_server_name,
    process_runtime_attestation,
    runtime_attestation_context_for_server_db,
    get_server_attestation_status,
    delete_server,
    validate_request_nonce,
    require_boot_attestation_nonce,
    require_luks_quote_nonce,
    require_confirm_nonce,
    process_luks_attest_request,
    process_luks_confirm,
    get_latest_upgrade_window,
    is_window_open,
    preflight_maintenance,
    confirm_maintenance,
    _count_active_maintenance_slots,
)
from api.server.util import (
    extract_client_cert_hash,
    extract_client_cert_pem,
)
from api.server.exceptions import (
    AttestationError,
    NoClientCertError,
    NonceError,
    ServerNotFoundError,
    ServerRegistrationError,
)
from api.miner.util import is_miner_blacklisted
from api.util import is_valid_host, semcomp


async def _runtime_expected_cert_hash(
    request: Request,
    db: AsyncSession,
    server_id: str,
) -> str:
    """Resolve the cert binding for a runtime quote.

    Model-B agents may not present their self-signed serving cert on the nonce/quote HTTP request.
    Their launch registration already bound that cert to a one-use reservation and hardware quote,
    so runtime freshness can safely bind the new quote to the immutable registered hash. Peer and
    secret-bearing storage operations continue to require live mTLS certificate possession.
    """

    try:
        return await extract_client_cert_hash(require_proxy_verified=True)(request)
    except NoClientCertError:
        server = await db.get(Server, server_id)
        cpu_reservation = (
            server.launch_reservation_id
            if server is not None
            and isinstance(server.launch_reservation_id, str)
            and server.launch_reservation_id
            else None
        )
        gpu_reservation = (
            server.gpu_launch_reservation_id
            if server is not None
            and isinstance(server.gpu_launch_reservation_id, str)
            and server.gpu_launch_reservation_id
            else None
        )
        if (
            server is None
            or (cpu_reservation is None and gpu_reservation is None)
            or not server.attested_cert_pubkey_hash
        ):
            raise
        return server.attested_cert_pubkey_hash.lower()


router = APIRouter()


# Registered-server Boot Attestation Endpoints


@router.get("/nonce", response_model=NonceResponse)
async def get_nonce(
    request: Request,
    server_id: str = Query(..., description="Registered server authorized for boot attestation"),
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    authorization_nonce: str | None = Header(None, alias=NONCE_HEADER),
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    """
    Generate a server-bound nonce for boot attestation.

    The miner signs ``{hotkey}:{authorization_nonce}:boot_luks_nonce:{server_id}:{cert_hash}``
    with a fresh ``{timestamp}.{random}`` authorization nonce. Ownership, non-storage role, source
    address, and live possession of the stored serving certificate are checked before a quote nonce
    is issued, so a caller cannot name another miner's VM and obtain a capability.
    """
    try:
        nonce_info = await issue_boot_attestation_nonce(
            db,
            request.state.client_ip,
            server_id,
            hotkey,
            authorization_nonce,
            signature,
            expected_cert_hash,
        )

        return NonceResponse(nonce=nonce_info["nonce"], expires_at=nonce_info["expires_at"])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate boot nonce: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate nonce",
        )


@router.post("/boot/attestation", response_model=BootAttestationResponse)
async def verify_boot_attestation(
    request: Request,
    args: BootAttestationArgs,
    db: AsyncSession = Depends(get_db_session),
    validated_nonce=Depends(require_boot_attestation_nonce),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    """
    Verify boot attestation and return a scoped follow-up capability.

    The response contains only a one-use exact-identity LUKS quote capability for the
    boot volume namespace. No global key or legacy ambiguous-finalization path exists.
    """
    try:
        server_ip = request.state.client_ip
        nonce, nonce_context = validated_nonce
        luks_quote_nonce = await process_boot_attestation(
            db, server_ip, args, nonce, nonce_context, expected_cert_hash
        )

        return BootAttestationResponse(luks_quote_nonce=luks_quote_nonce)
    except NonceError as e:
        logger.warning(f"Boot attestation nonce error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AttestationError as e:
        logger.warning(f"Boot attestation failed: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error in boot attestation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Boot attestation failed",
        )


# 1-Click CPU TEE Server Self-Registration (push attestation; anonymous nonce, signed register)


@router.get("/cpu/nonce", response_model=NonceResponse)
async def get_cpu_register_nonce(request: Request):
    """
    Issue a single-use attestation nonce for 1-click CPU TEE server self-registration.

    Called by a freshly-booted CPU TEE server before it submits its quote. No auth is required
    (the server is not yet registered); the nonce is bound to the caller IP + purpose and is
    consumed when the server posts to /cpu/register.
    """
    try:
        server_ip = request.state.client_ip
        nonce_info = await create_nonce(server_ip, purpose=NoncePurpose.CPU_REGISTER)
        return NonceResponse(nonce=nonce_info["nonce"], expires_at=nonce_info["expires_at"])
    except Exception as e:
        logger.error(f"Failed to generate CPU register nonce: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate nonce",
        )


@router.post("/cpu/register", response_model=CpuServerRegistrationResponse)
async def register_cpu_server_endpoint(
    request: Request,
    args: CpuServerRegistrationArgs,
    db: AsyncSession = Depends(get_db_session),
    nonce=Depends(validate_request_nonce(NoncePurpose.CPU_REGISTER)),
    expected_cert_hash=Depends(extract_client_cert_hash()),
    expected_cert_pem=Depends(extract_client_cert_pem()),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    signature: str | None = Header(None, alias=SIGNATURE_HEADER),
):
    """
    Self-registration for a 1-click CPU TEE server (push attestation).

    The booted server submits its own runtime TDX quote + CPU benchmark. Trust is established by:
    the single-use attestation nonce (X-Chutes-Nonce, bound into the quote report_data), the mTLS
    client cert (also bound into report_data), and either a Model-B reservation plus signature from
    that attested key or the separate Model-A miner signature. Quote measurements must match the
    exact reserved CPU/storage release profile.
    """
    model_b = bool(args.launch_reservation)
    if not model_b and (not hotkey or not signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing miner hotkey/signature headers.",
        )
    if model_b and (hotkey or signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Model-B registration derives ownership from its launch reservation.",
        )
    try:
        # In dev (skip_metagraph_check) the self-registering hotkey is not on the metagraph yet;
        # register_cpu_server auto-creates the row + verifies the signature. Mirror that bypass here
        # so the route-level membership/blacklist check does not reject the first registration.
        if not model_b and not settings.skip_metagraph_check:
            reason = await is_miner_blacklisted(db, hotkey)
            if reason:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
        server_ip = request.state.client_ip
        return await register_cpu_server(
            db,
            server_ip,
            args,
            hotkey,
            nonce,
            signature,
            expected_cert_hash,
            expected_cert_pem,
        )
    except (AttestationError, ServerRegistrationError) as e:
        logger.warning(
            f"CPU server registration rejected: server_id={args.server_id} "
            f"miner_hotkey={hotkey} detail={getattr(e, 'detail', str(e))}"
        )
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error in CPU server registration: server_id={args.server_id} "
            f"miner_hotkey={hotkey} error={str(e)}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CPU server registration failed",
        )


@router.get("/gpu/nonce", response_model=NonceResponse)
async def get_gpu_register_nonce(request: Request):
    nonce_info = await create_nonce(request.state.client_ip, purpose=NoncePurpose.GPU_REGISTER)
    return NonceResponse(nonce=nonce_info["nonce"], expires_at=nonce_info["expires_at"])


@router.post("/gpu/register", response_model=GpuServerRegistrationResponse)
async def register_gpu_server_endpoint(
    request: Request,
    args: GpuServerRegistrationArgs,
    db: AsyncSession = Depends(get_db_session),
    nonce=Depends(validate_request_nonce(NoncePurpose.GPU_REGISTER)),
    expected_cert_hash=Depends(extract_client_cert_hash()),
    expected_cert_pem=Depends(extract_client_cert_pem()),
):
    try:
        result = await register_gpu_server(
            db,
            request.state.client_ip,
            args,
            nonce,
            expected_cert_hash,
            expected_cert_pem,
        )
        if result["management_mode"] == "miner":
            from api.host.schemas import GpuLaunchReservation

            reservation = await db.get(
                GpuLaunchReservation,
                result["reservation_id"],
            )
            if reservation is None:
                raise RuntimeError(
                    "registered GPU reservation disappeared before post-attest gates"
                )
            migration = (
                await db.get(
                    GpuLegacyMigration,
                    reservation.legacy_migration_id,
                )
                if reservation.legacy_migration_id is not None
                else None
            )
            if migration is not None and migration.state in {
                "ready",
                "leased",
                "promoted",
            }:
                await send_agent_command(
                    reservation.host_id,
                    "hotplug_gpu_legacy",
                    {
                        "server_id": reservation.server_id,
                        "reservation_id": reservation.reservation_id,
                        "reservation_claims_sha256": reservation.claims_sha256,
                        "process_incarnation": reservation.process_incarnation,
                    },
                )
        return result
    except (AttestationError, ServerRegistrationError) as exc:
        await db.rollback()
        current = await db.get(Server, args.server_id)
        try:
            from api.host.gpu_allocations import (
                _parse_reservation_token,
                _validate_row_claims,
            )
            from api.host.schemas import GpuLaunchReservation
            from api.server.service import _gpu_attestation_lineage

            reservation_id, token_hash = _parse_reservation_token(args.launch_reservation)
            reservation = await db.get(GpuLaunchReservation, reservation_id)
            gpu_lineage = {}
            claims = None
            if (
                reservation is not None
                and secrets.compare_digest(reservation.token_hash, token_hash)
                and reservation.server_id == args.server_id
                and reservation.claims_sha256 == args.quote_commitment.reservation_sha256
                and reservation.state in {"launching", "running", "quarantined"}
            ):
                claims = _validate_row_claims(reservation)
            if claims is not None and args.quote_commitment.claims == claims:
                if current is None:
                    current = Server(
                        server_id=claims.server_id,
                        netuid=settings.netuid,
                        name=claims.server_id,
                        ip=request.state.client_ip,
                        miner_hotkey=claims.owner_hotkey,
                        is_tee=True,
                        self_registered=True,
                        compute_type="gpu",
                        tee_type="tdx",
                        host_id=claims.host_id,
                        storage_role=False,
                        gpu_launch_reservation_id=reservation.reservation_id,
                        gpu_allocation_group_id=claims.allocation_group_id,
                        gpu_allocation_group_generation=(claims.allocation_group_generation),
                        gpu_management_mode=claims.management_mode,
                        gpu_process_incarnation=claims.process_incarnation,
                        gpu_topology_fingerprint=claims.topology_fingerprint,
                        gpu_retired_at=datetime.now(timezone.utc),
                        gpu_retirement_reason="initial GPU registration attempt failed",
                    )
                    db.add(current)
                    await db.flush()
                if (
                    current.compute_type == "gpu"
                    and current.gpu_launch_reservation_id == reservation.reservation_id
                ):
                    gpu_lineage = _gpu_attestation_lineage(
                        reservation,
                        claims,
                        list(args.gpu_evidence or []),
                        None,
                    )
                    failed_attestation = ServerAttestation(
                        server_id=current.server_id,
                        quote_data=args.quote,
                        verification_error=str(getattr(exc, "detail", exc)),
                        created_at=datetime.now(timezone.utc),
                        **gpu_lineage,
                    )
                    db.add(failed_attestation)
                    await db.flush()
                    from api.host.gpu_allocations import (
                        quarantine_gpu_reservation_control_plane,
                    )

                    await quarantine_gpu_reservation_control_plane(
                        db,
                        reservation.reservation_id,
                        code="gpu_registration_attestation_failed",
                        reason=str(getattr(exc, "detail", exc)),
                        metadata={"attestation_id": (failed_attestation.attestation_id)},
                    )
                    await db.commit()
        except Exception as audit_exc:  # noqa: BLE001 - never mask attestation rejection
            await db.rollback()
            logger.error(
                f"Could not persist failed GPU attestation attempt for "
                f"{args.server_id}: {audit_exc}"
            )
        raise
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            f"Unexpected GPU guest registration failure for {args.server_id}: {exc}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GPU guest registration failed",
        )


@router.post(
    "/gpu/{server_id}/session",
    response_model=GpuRuntimeSessionResponse,
)
async def refresh_gpu_runtime_session(
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    server = await db.get(Server, server_id)
    if (
        server is None
        or server.compute_type != "gpu"
        or server.tee_type != "tdx"
        or server.gpu_management_mode not in {"miner", "platform"}
        or server.gpu_retired_at is not None
        or server.attested_cert_pubkey_hash != expected_cert_hash.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Presented attested identity is not the current GPU server.",
        )
    token, expires_at, attestation_id = await latest_gpu_runtime_session(db, server)
    server.gpu_runtime_session_attestation_id = attestation_id
    server.gpu_runtime_session_expires_at = expires_at
    await db.commit()
    return GpuRuntimeSessionResponse(
        server_id=server.server_id,
        owner_hotkey=server.miner_hotkey,
        runtime_session=token,
        runtime_session_expires_at=expires_at.isoformat(),
        allowed_purposes=list(
            GPU_RUNTIME_SESSION_PURPOSES
            if server.gpu_management_mode == "miner"
            else GPU_PLATFORM_RUNTIME_SESSION_PURPOSES
        ),
    )


@router.post(
    "/gpu/{server_id}/legacy-migration/close",
    response_model=GpuLegacyCloseResponseV1,
)
async def close_legacy_gpu_migration_endpoint(
    server_id: str,
    body: GpuLegacyCloseRequestV1,
    db: AsyncSession = Depends(get_db_session),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    result = await close_legacy_gpu_sources(
        db,
        server_id,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


async def _gpu_infra_session(
    db: AsyncSession,
    server_id: str,
    attested_session: str | None,
) -> tuple[Server, dict]:
    if not attested_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="gpu-infra requires an attested GPU runtime session.",
        )
    server, payload = await validate_gpu_runtime_session(
        db,
        attested_session,
        required_purpose="gpu-infra",
    )
    if server.server_id != server_id or server.gpu_management_mode != "miner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="gpu-infra path does not match the miner runtime session.",
        )
    return server, payload


@router.post(
    "/gpu/{server_id}/infra/lease",
    response_model=GpuInfraLeaseResponseV1,
)
async def lease_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraLeaseRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await lease_gpu_infra(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/abandon",
    response_model=GpuInfraAbandonResponseV1,
)
async def abandon_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraAbandonRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await abandon_gpu_infra(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/retire",
    response_model=GpuInfraRetireResponseV1,
)
async def retire_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraRetireRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await retire_gpu_infra_key(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/close",
    response_model=GpuInfraCloseResponseV1,
)
async def close_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraCloseRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    if not attested_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="gpu-infra close requires an attested GPU runtime session.",
        )
    runtime_server, payload = await validate_gpu_runtime_session(
        db,
        attested_session,
        required_purpose="gpu-infra",
        allow_resetting=True,
    )
    if runtime_server.server_id != server_id or runtime_server.gpu_management_mode != "miner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="gpu-infra close path does not match the miner runtime session.",
        )
    result = await acknowledge_gpu_infra_closed(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/migration-refresh",
    response_model=GpuInfraMigrationRefreshResponseV1,
)
async def refresh_gpu_infra_migration_endpoint(
    server_id: str,
    body: GpuInfraMigrationRefreshRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await refresh_gpu_infra_migration(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/migration-promote",
    response_model=GpuInfraMigrationPromoteResponseV1,
)
async def promote_gpu_infra_migration_endpoint(
    server_id: str,
    body: GpuInfraMigrationPromoteRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await promote_gpu_infra_migration(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/confirm",
    response_model=GpuInfraConfirmResponseV1,
)
async def confirm_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraConfirmRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await confirm_gpu_infra(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/acknowledge",
    response_model=GpuInfraAcknowledgeResponseV1,
)
async def acknowledge_gpu_infra_endpoint(
    server_id: str,
    body: GpuInfraAcknowledgeRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await acknowledge_gpu_infra(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


@router.post(
    "/gpu/{server_id}/infra/migration-complete",
    response_model=GpuInfraMigrationCompleteResponseV1,
)
async def complete_gpu_infra_migration_endpoint(
    server_id: str,
    body: GpuInfraMigrationCompleteRequestV1,
    db: AsyncSession = Depends(get_db_session),
    attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    runtime_server, payload = await _gpu_infra_session(db, server_id, attested_session)
    result = await complete_gpu_infra_migration(
        db,
        runtime_server,
        payload,
        expected_cert_hash,
        body,
    )
    await db.commit()
    return result


def _manifest_for_server(server: Server) -> dict | None:
    """Return the exact active pin persisted by this server's successful attestation."""
    if (
        not server.version
        or not server.measurement_name
        or not server.measurement_config_fingerprint
        or not server.trust_set_fingerprint
    ):
        return None
    measurements = settings.tee_measurements
    trust_set_fingerprint = measurement_trust_set_fingerprint(measurements)
    if server.trust_set_fingerprint != trust_set_fingerprint:
        return None
    measurement = next(
        (
            config
            for config in measurements
            if config.name == server.measurement_name
            and config.version == server.version
            and (config.gpu_count or 0) == 0
        ),
        None,
    )
    if measurement is None:
        return None
    config_fingerprint = measurement_config_fingerprint(measurement)
    if server.measurement_config_fingerprint != config_fingerprint:
        return None

    tee_type = getattr(measurement, "tee_type", "tdx")
    provider = getattr(measurement, "provider", None) or "bare-metal"
    exact_pin = {
        "version": measurement.version,
        "name": measurement.name,
        "tee_type": tee_type,
        "provider": provider,
        "mrtd": measurement.mrtd,
        "boot_rtmrs": measurement.boot_rtmrs,
        "runtime_rtmrs": measurement.runtime_rtmrs,
        "expected_gpus": measurement.expected_gpus,
        "gpu_count": measurement.gpu_count,
        "measurement": getattr(measurement, "measurement", None),
        "policy": getattr(measurement, "policy", None),
        "min_tcb": getattr(measurement, "min_tcb", None),
        "processor_model": getattr(measurement, "processor_model", None),
        "expected_vmpl": getattr(measurement, "expected_vmpl", None),
        "id_key_digest": getattr(measurement, "id_key_digest", None),
        "vtpm_pcrs": getattr(measurement, "vtpm_pcrs", None),
        "vtpm_security_flags": getattr(measurement, "vtpm_security_flags", None),
        "debug": bool(getattr(measurement, "debug", False)),
        "image_sha256": getattr(measurement, "image_sha256", None),
        "image_measurement_names": getattr(measurement, "image_measurement_names", None),
        "config_fingerprint": config_fingerprint,
        "trust_set_fingerprint": trust_set_fingerprint,
    }
    if getattr(measurement, "profile_id", None) is not None:
        exact_pin.update(
            {
                "profile_id": measurement.profile_id,
                "vcpus": measurement.vcpus,
                "memory_mib": measurement.memory_mib,
            }
        )
    manifest = {
        "schema_version": 1,
        "image": (
            f"chutes-cpu-snp-{measurement.name}"
            if tee_type in ("sev-snp", "snp", "amd-snp")
            else f"chutes-cpu-tee-{measurement.name}"
        ),
        "image_version": measurement.version,
        "provider": provider,
        "tee_type": ("sev-snp" if tee_type in ("sev-snp", "snp", "amd-snp") else "tdx"),
        "measurement_name": measurement.name,
        "config_fingerprint": config_fingerprint,
        "trust_set_fingerprint": trust_set_fingerprint,
        "debug": exact_pin["debug"],
        "image_sha256": exact_pin["image_sha256"],
        "image_measurement_names": exact_pin["image_measurement_names"],
        "expected_gpus": list(measurement.expected_gpus or []),
        "gpu_count": measurement.gpu_count,
        "exact_pin": exact_pin,
    }
    if tee_type in ("sev-snp", "snp", "amd-snp"):
        manifest["snp"] = {
            "measurement": measurement.measurement,
            "policy": measurement.policy,
            "processor_model": measurement.processor_model,
            "min_tcb": measurement.min_tcb,
            "expected_vmpl": measurement.expected_vmpl,
            "id_key_digest": measurement.id_key_digest,
            "vtpm_pcrs": measurement.vtpm_pcrs,
            "vtpm_security_flags": measurement.vtpm_security_flags,
        }
    else:
        runtime = measurement.runtime_rtmrs or {}
        manifest["measurements"] = {
            "mrtd": measurement.mrtd,
            "rtmr0": runtime.get("RTMR0") or runtime.get("rtmr0"),
            "rtmr1": runtime.get("RTMR1") or runtime.get("rtmr1"),
            "rtmr2": runtime.get("RTMR2") or runtime.get("rtmr2"),
            "rtmr3": runtime.get("RTMR3") or runtime.get("rtmr3"),
        }
    return manifest


async def _caller_owns_server_workload(db: AsyncSession, server_id: str, user: User | None) -> bool:
    """True if ``user`` owns the chute or job whose instance is running on this CPU server.

    This authorizes the RENTER (the user who deployed the ssh/jupyter rental the scheduler placed on
    a miner's server) to discover + provision their own instance, resolving
    server_id -> Instance -> (Chute.user_id | Job.user_id). The miner who registered the server is
    NOT this user, so miner-ownership alone cannot gate a rental's owner-connect.
    """
    if user is None:
        return False
    from api.chute.schemas import Chute
    from api.instance.schemas import Instance
    from api.job.schemas import Job

    rows = (
        await db.execute(
            select(Instance.instance_id, Instance.chute_id).where(Instance.server_id == server_id)
        )
    ).all()
    if not rows:
        return False
    instance_ids = {r.instance_id for r in rows if r.instance_id}

    # A JOB instance's true owner is the JOB's user, NOT the chute author -- a job can run on a
    # PUBLIC chute someone else authored, so authorizing by chute ownership would let the chute
    # author owner-connect to another user's running rental. So: job instance -> job owner only;
    # cord (job-less) instance -> chute author.
    job_owner_by_instance: dict = {}
    if instance_ids:
        for iid, juid in (
            await db.execute(
                select(Job.instance_id, Job.user_id).where(Job.instance_id.in_(instance_ids))
            )
        ).all():
            job_owner_by_instance[iid] = juid
    cord_chute_ids = {
        r.chute_id for r in rows if r.chute_id and r.instance_id not in job_owner_by_instance
    }
    chute_owner_by_id: dict = {}
    if cord_chute_ids:
        for cid, cuid in (
            await db.execute(
                select(Chute.chute_id, Chute.user_id).where(Chute.chute_id.in_(cord_chute_ids))
            )
        ).all():
            chute_owner_by_id[cid] = cuid
    for r in rows:
        owner = (
            job_owner_by_instance.get(r.instance_id)
            if r.instance_id in job_owner_by_instance
            else chute_owner_by_id.get(r.chute_id)
        )
        if owner is not None and owner == user.user_id:
            return True
    return False


@router.get("/cpu/{server_id}/connection")
async def get_cpu_server_connection(
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User | None = Depends(get_current_user(purpose="tee", raise_not_found=False)),
):
    """Authorized DISCOVERY for a user-attestable CPU TEE instance (miner owner OR the renter).

    Returns where the instance is (the host + attest/provision/ssh/wg ports its in-TEE agent
    advertised), a short-lived provisioning token, and an explicitly untrusted transparency view
    of the matched measurement. This is discovery + authorization ONLY: the trust decision is the
    client verifying the quote against a separately published cosign-signed manifest and trusted
    public key, NOT this response. The connection goes directly to the instance, never through this
    API.

    Authorization (two roles): the miner hotkey that registered the server (ops/debug), OR the
    RENTER -- the user who owns the chute/job whose instance the scheduler placed on this server.
    Both are derived from the AUTHENTICATED principal (current_user): a raw X-Chutes-Hotkey header
    must NEVER gate this, because get_current_user returns None for an unsigned request while the
    header is still attacker-supplied -- trusting it would let anyone who knows the (public) miner
    hotkey mint a provisioning token for someone else's rental. Each call mints a fresh SINGLE-USE
    provisioning token (random jti, server-bound), so a renter only gets one for a server running
    their own workload.
    """
    from api.instance.util import create_provision_jwt

    # Fail closed on an unauthenticated caller (no valid signature / API key). Without this, an
    # unsigned request carrying only X-Chutes-Hotkey would otherwise reach the authz check.
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (sign the request with your hotkey or use an API key).",
        )
    server = (
        await db.execute(select(Server).where(Server.server_id == server_id))
    ).scalar_one_or_none()
    if not server or not getattr(server, "self_registered", False) or server.compute_type != "cpu":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not a self-registered CPU TEE instance.",
        )
    # Miner-owner check uses the AUTHENTICATED user's hotkey, never a raw header.
    is_miner_owner = bool(current_user.hotkey) and server.miner_hotkey == current_user.hotkey
    if not is_miner_owner and not await _caller_owns_server_workload(db, server_id, current_user):
        # Neither the registering miner nor the workload's owner -> not authorized to discover or
        # provision this instance. 404 (not 403) so a server's existence/ownership isn't probeable.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not a self-registered CPU TEE instance.",
        )
    endpoints = server.tee_endpoints or {}
    # Informational hardware telemetry: a TD runs on its L0 host's physical CPU, so surface that host's
    # CPU (model/freq/cache/flags from the node-agent inventory) plus this TD's vCPU/RAM slice. Not
    # attested (the node-agent is a launcher), purely for the renter's visibility.
    host_cpu = None
    if server.host_id:
        host = (
            await db.execute(select(Host).where(Host.host_id == server.host_id))
        ).scalar_one_or_none()
        if host and host.specs:
            host_cpu = host.specs.get("cpu")
    manifest = _manifest_for_server(server)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This server's exact attested measurement identity is retired, revoked, "
                "or stale; fresh registration is required."
            ),
        )
    return {
        "server_id": server.server_id,
        "host": endpoints.get("host") or server.ip,
        "attest_port": endpoints.get("attest_port", 8443),
        "provision_port": endpoints.get("provision_port", 8444),
        "ssh_port": endpoints.get("ssh_port", 22),
        "wg_port": endpoints.get("wg_port", 51820),
        "provision_token": create_provision_jwt(server.server_id),
        # Discovery is authenticated, but this unsigned view is not an independent image trust
        # root. The CLI requires a separately published cosign-signed manifest and trusted key.
        "untrusted_manifest": manifest,
        "specs": {"cpu": host_cpu, "vcpus": server.cpu_cores, "ram_gb": server.ram_gb},
    }


@router.post(
    "/{server_id}/luks/attest",
    response_model=LuksAttestResponse,
    response_model_exclude_none=True,
)
async def attest_luks(
    server_id: str,
    body: LuksAttestRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
    validated_capability=Depends(require_luks_quote_nonce),
):
    """
    Rotate LUKS passphrases for new-format VMs (version >= 1.3.0).

    The opaque nonce carries the registered server ID, owner, cert, exact measurement, role, and
    allowed volume namespace. The handler revalidates all of them before looking up any key.
    Storage capabilities can release only ``chutefs-data`` and never receive a k3s key.
    """
    try:
        result = await process_luks_attest_request(
            db,
            server_id,
            hotkey,
            body,
            validated_capability,
            expected_cert_hash,
        )
        return LuksAttestResponse(
            volumes={
                vol: LuksVolumeInfo(
                    current=r.current,
                    next=r.next,
                    generation=r.generation,
                    confirmed_generation=r.confirmed_generation,
                    lease_reused=r.lease_reused,
                )
                for vol, r in result.volumes.items()
            },
            confirm_nonce=result.confirm_nonce,
            k3s_encryption_key=result.k3s_encryption_key,
        )
    except AttestationError as e:
        logger.warning(f"LUKS attest quote verification failed: {str(e)}")
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in LUKS attest: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LUKS attestation failed",
        )


@router.post("/{server_id}/luks/confirm", response_model=LuksConfirmResponse)
async def confirm_luks_rotation(
    server_id: str,
    body: LuksConfirmRequest,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    capability=Depends(require_confirm_nonce),
    expected_cert_hash=Depends(extract_client_cert_hash(require_proxy_verified=True)),
):
    """
    Confirm exact LUKS generation leases and finalize their pending passphrases.

    The VM reports the exact generation durably written for every issued volume.
    A first-format pending passphrase is promoted only with rotated=True; an existing
    current key remains active with rotated=False. Exact duplicate confirmations are
    idempotent, while stale, skipped, or mismatched lease generations are rejected.
    """
    try:
        result = await process_luks_confirm(
            db,
            server_id,
            hotkey,
            body,
            capability,
            expected_cert_hash,
        )
        return LuksConfirmResponse(status="confirmed", volumes=result.volumes)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in LUKS confirm: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LUKS confirm failed",
        )


# Server Management Endpoints (Post-boot via CLI)
# ToDo: Not sure we will want to keep this, ideally want to integrate with miner add-node command
@router.post("/", response_model=Dict[str, str], status_code=status.HTTP_201_CREATED)
async def create_server(
    args: ServerArgs,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(get_current_user(raise_not_found=False, registered_to=settings.netuid)),
):
    """
    Register a new server.

    This is called via CLI after the server has booted and decrypted its disk.
    Links the server to any existing boot attestation history via server ip.
    """
    try:
        reason = await is_miner_blacklisted(db, hotkey)
        if reason:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=reason,
            )

        gpu_uuids = [gpu.uuid for gpu in args.gpus]
        existing_nodes = await check_node_inventory(db, gpu_uuids)
        if existing_nodes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Nodes already exist in inventory, please contact chutes team to resolve: {existing_nodes}",
            )

        valid_host = await is_valid_host(args.host)
        if not valid_host:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification host provided.",
            )

        # TEE servers require globally unique IPs (across TEE and non-TEE). Model-B co-tenant
        # TD servers legitimately share their L0 host's IP, so multiple rows may match; any
        # match at all rejects this registration (first() avoids MultipleResultsFound).
        existing_server = (
            (await db.execute(select(Server).where(Server.ip == args.host))).scalars().first()
        )
        if existing_server:
            logger.error(
                f"TEE server registration rejected: IP {args.host} already registered to server_id={existing_server.server_id} name={existing_server.name} miner_hotkey={existing_server.miner_hotkey}; requesting miner_hotkey={hotkey}"
            )
            if existing_server.miner_hotkey == hotkey:
                detail = (
                    f"IP {args.host} is already registered to your server {existing_server.server_id} ({existing_server.name}). "
                    "IPs must be unique across all servers. Use GET /miner/servers to review your inventory."
                )
            else:
                detail = "Conflict with an existing server. Please contact support to resolve."
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

        await register_server(db, args, hotkey)

        return {"message": "Server registered successfully."}

    except ServerRegistrationError as e:
        logger.error(
            f"Server registration failed: server_id={args.id} host={args.host} miner_hotkey={hotkey} error={e.detail}"
        )
        raise e
    except HTTPException:
        # Re-raise HTTPExceptions (like blacklist, node conflicts, invalid host) as-is
        raise
    except (IntegrityError, DatabaseError) as e:
        # Handle database errors that might occur before register_server is called
        # (e.g., in check_node_inventory)
        logger.error(
            f"Database error in server registration: server_id={args.id} host={args.host} miner_hotkey={hotkey} error={str(e)}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server registration failed - database error. Please contact support with your server ID and miner hotkey.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error in server registration: server_id={args.id} host={args.host} miner_hotkey={hotkey} error={str(e)}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server registration failed",
        )


@router.get("/tee/measurements", response_model=List[TeeMeasurementResponse])
async def get_tee_measurements():
    """
    Return the list of currently accepted TEE measurement configurations.

    These are the reference values (MRTD + RTMRs) that the platform accepts
    during boot and runtime attestation. Clients can use these to independently
    verify that a server is running approved software before trusting it.
    No authentication required — public transparency endpoint.
    """
    try:
        measurements = settings.tee_measurements
    except Exception as e:
        logger.error(f"TEE measurement config is invalid: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read TEE measurements",
        )

    trust_set_fingerprint = measurement_trust_set_fingerprint(measurements)
    return [
        TeeMeasurementResponse(
            version=m.version,
            name=m.name,
            tee_type=getattr(m, "tee_type", "tdx"),
            provider=getattr(m, "provider", None),
            mrtd=m.mrtd,
            boot_rtmrs=m.boot_rtmrs,
            runtime_rtmrs=m.runtime_rtmrs,
            profile_id=getattr(m, "profile_id", None),
            vcpus=getattr(m, "vcpus", None),
            memory_mib=getattr(m, "memory_mib", None),
            expected_gpus=m.expected_gpus,
            gpu_count=m.gpu_count,
            measurement=getattr(m, "measurement", None),
            policy=getattr(m, "policy", None),
            min_tcb=getattr(m, "min_tcb", None),
            processor_model=getattr(m, "processor_model", None),
            expected_vmpl=getattr(m, "expected_vmpl", None),
            id_key_digest=getattr(m, "id_key_digest", None),
            vtpm_pcrs=getattr(m, "vtpm_pcrs", None),
            vtpm_security_flags=getattr(m, "vtpm_security_flags", None),
            debug=bool(getattr(m, "debug", False)),
            image_sha256=getattr(m, "image_sha256", None),
            image_measurement_names=getattr(m, "image_measurement_names", None),
            config_fingerprint=measurement_config_fingerprint(m),
            trust_set_fingerprint=trust_set_fingerprint,
        )
        for m in measurements
        if not m.rc
    ]


@router.get("/maintenance/policy", response_model=MaintenancePolicyResponse)
async def get_maintenance_policy(
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(get_current_user(purpose="tee", raise_not_found=False, registered_to=None)),
):
    """Return the latest upgrade target and whether its maintenance window is open."""
    if not hotkey:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hotkey header required")

    window = await get_latest_upgrade_window(db)
    window_open = window is not None and is_window_open(window)
    window_info: UpgradeWindowInfo | None = None
    current_slots = 0
    server_statuses: list[ServerUpgradeStatus] = []

    if window is not None:
        target_version = window.target_measurement_version
        window_info = UpgradeWindowInfo(
            id=window.id,
            target_measurement_version=target_version,
            upgrade_window_start=str(window.upgrade_window_start),
            upgrade_window_end=str(window.upgrade_window_end),
            max_concurrent_per_miner=window.max_concurrent_per_miner,
        )
        current_slots = await _count_active_maintenance_slots(db, hotkey, window)

        tee_servers = (
            (
                await db.execute(
                    select(Server).where(Server.miner_hotkey == hotkey, Server.is_tee.is_(True))
                )
            )
            .scalars()
            .all()
        )

        for srv in tee_servers:
            server_statuses.append(
                ServerUpgradeStatus(
                    server_id=srv.server_id,
                    name=srv.name,
                    version=srv.version,
                    needs_upgrade=srv.version is None or semcomp(srv.version, target_version) < 0,
                    in_maintenance=srv.in_maintenance,
                )
            )

    return MaintenancePolicyResponse(
        active_window=window_info,
        window_open=window_open,
        current_slots=current_slots,
        servers=server_statuses,
    )


@router.patch("/{server_id}", response_model=Dict[str, Any])
async def patch_server_name(
    server_id: str,
    server_name: str = Query(..., description="New VM name to set"),
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="tee", raise_not_found=False, registered_to=settings.netuid)
    ),
):
    """
    Update name for an existing server. Path is server_id; query param is the new name.
    The server row is updated when hotkey and server_id match.
    """
    if not hotkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hotkey header required",
        )
    try:
        server = await update_server_name(db, hotkey, server_id, server_name)
        return {
            "name": server.name,
            "ip": server.ip,
            "created_at": server.created_at.isoformat(),
            "updated_at": server.updated_at.isoformat() if server.updated_at else None,
        }
    except ServerNotFoundError as e:
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to patch server name: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to patch server name",
        )


@router.get("/{server_id}", response_model=Dict[str, Any])
async def get_server_details(
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="tee", raise_not_found=False, registered_to=settings.netuid)
    ),
):
    """
    Get details for a specific server by miner hotkey and server id.
    """
    try:
        server = await check_server_ownership(db, server_id, hotkey)

        response: dict = {
            "server_id": server.server_id,
            "name": server.name,
            "ip": server.ip,
            "version": server.version,
            "maintenance_pending_window_id": server.maintenance_pending_window_id,
            "created_at": server.created_at.isoformat(),
            "updated_at": server.updated_at.isoformat() if server.updated_at else None,
        }
        if server.in_maintenance:
            window = await db.get(TeeUpgradeWindow, server.maintenance_pending_window_id)
            if window is not None:
                response["target_version"] = window.target_measurement_version

        return response

    except ServerNotFoundError as e:
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get server details: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get server details",
        )


@router.get("/{server_name_or_id}/maintenance/preflight", response_model=PreflightResult)
async def get_maintenance_preflight(
    server_name_or_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(get_current_user(purpose="tee", raise_not_found=False, registered_to=None)),
):
    """Check maintenance eligibility for a server without entering maintenance."""
    server = await get_server_by_name_or_id(db, hotkey, server_name_or_id)
    return await preflight_maintenance(db, server, hotkey)


@router.put("/{server_name_or_id}/maintenance", response_model=ConfirmMaintenanceResult)
async def put_confirm_maintenance(
    server_name_or_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="tee", raise_not_found=False, registered_to=settings.netuid)
    ),
):
    """Enter maintenance: purge instances and mark server for upgrade."""
    server = await get_server_by_name_or_id(db, hotkey, server_name_or_id)
    return await confirm_maintenance(db, server, hotkey)


@router.delete("/{server_name_or_id}", response_model=Dict[str, str])
async def remove_server(
    server_name_or_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="tee", raise_not_found=False, registered_to=settings.netuid)
    ),
):
    """
    Remove a server by miner hotkey and server id or VM name (path param server_name_or_id).
    """
    try:
        server = await get_server_by_name_or_id(db, hotkey, server_name_or_id)
        await delete_server(db, server.server_id, hotkey)

        return {"name": server.name, "message": "Server removed successfully"}

    except ServerNotFoundError as e:
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove server: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove server",
        )


# Runtime Attestation Endpoints (Post-registration)


@router.get("/{server_id}/nonce", response_model=NonceResponse)
async def get_runtime_nonce(
    request: Request,
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(get_current_user(purpose="tee", raise_not_found=False, registered_to=None)),
):
    """
    Generate a nonce for runtime attestation.
    """
    try:
        expected_cert_hash = await _runtime_expected_cert_hash(request, db, server_id)
        server = await check_server_ownership(db, server_id, hotkey, expected_cert_hash)

        actual_ip = request.state.client_ip
        if server.ip != actual_ip:
            raise Exception()

        context = await runtime_attestation_context_for_server_db(db, server)
        nonce_info = await create_nonce(
            server.ip,
            purpose=NoncePurpose.RUNTIME,
            context=context.model_dump(),
        )

        return NonceResponse(
            nonce=nonce_info["nonce"],
            expires_at=nonce_info["expires_at"],
            context_sha256=(canonical_sha256(context) if server.compute_type == "gpu" else None),
        )

    except ServerNotFoundError as e:
        raise e
    except AttestationError as e:
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate runtime nonce: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate nonce",
        )


@router.post("/{server_id}/attestation", response_model=RuntimeAttestationResponse)
async def verify_runtime_attestation(
    request: Request,
    server_id: str,
    args: RuntimeAttestationArgs,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(get_current_user(purpose="tee", raise_not_found=False, registered_to=None)),
    nonce: str | None = Header(None, alias=NONCE_HEADER),
):
    """
    Verify runtime attestation with full measurement validation.
    """
    try:
        expected_cert_hash = await _runtime_expected_cert_hash(request, db, server_id)
        server = await check_server_ownership(db, server_id, hotkey, expected_cert_hash)
        actual_ip = request.state.client_ip
        stored_nonce = await validate_and_consume_nonce(nonce, actual_ip, NoncePurpose.RUNTIME)
        try:
            nonce_context = RuntimeAttestationNonceContext.model_validate(
                stored_nonce.get("context")
            )
        except (AttributeError, ValueError, TypeError) as exc:
            raise NonceError(
                "Runtime nonce is missing its exact registered identity context."
            ) from exc
        result = await process_runtime_attestation(
            db,
            server.server_id,
            actual_ip,
            args,
            hotkey,
            nonce,
            expected_cert_hash,
            nonce_context,
        )

        return RuntimeAttestationResponse(
            attestation_id=result["attestation_id"],
            verified_at=result["verified_at"],
            status=result["status"],
            revocation_status=result["revocation_status"],
            luks_quote_nonce=result.get("luks_quote_nonce"),
            gpu_evidence_sha256=result.get("gpu_evidence_sha256"),
        )

    except ServerNotFoundError as e:
        raise e
    except HTTPException:
        raise
    except NonceError as e:
        logger.warning(f"Runtime attestation nonce error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AttestationError as e:
        logger.warning(f"Runtime attestation failed: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error in runtime attestation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Runtime attestation failed",
        )


# ToDo: Also likely to remove this
@router.get("/{server_id}/attestation/status", response_model=Dict[str, Any])
async def get_attestation_status(
    server_id: str,
    db: AsyncSession = Depends(get_db_session),
    hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
    _: User = Depends(
        get_current_user(purpose="tee", raise_not_found=False, registered_to=settings.netuid)
    ),
):
    """
    Get current attestation status for a server by miner hotkey and server id.
    """
    try:
        server = await check_server_ownership(db, server_id, hotkey)
        status_info = await get_server_attestation_status(db, server.server_id, hotkey)
        status_info["name"] = server.name
        return status_info

    except ServerNotFoundError as e:
        raise e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get attestation status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get attestation status",
        )
