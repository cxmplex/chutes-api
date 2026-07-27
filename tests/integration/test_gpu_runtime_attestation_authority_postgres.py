"""Real-Postgres coverage for immutable registration A and operational attestation B."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from api.gpu_registration_service import _claim_attempt, _complete_attempt
from api.host.schemas import GpuLaunchReservation, canonical_sha256
from api.server.gpu_infra import _locked_current_lineage
from api.server.gpu_sessions import (
    latest_gpu_runtime_session,
    require_completed_gpu_registration,
    validate_gpu_runtime_session,
)
from api.server.schemas import Server, ServerAttestation
from tests.integration import test_gpu_allocations_postgres as gpu_pg

postgres_schema = gpu_pg.postgres_schema
unsigned_debug_provenance = gpu_pg.unsigned_debug_provenance
nv_attest = gpu_pg.nv_attest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for GPU attestation authority tests",
    ),
]


async def _completed_registration(session, mode: str):
    (
        response,
        request,
        cert_pem,
        spki_sha256,
    ) = await gpu_pg._prepare_registration_request(session, mode)
    attempt, lease_owner, conflict = await _claim_attempt(
        session,
        "192.0.2.30",
        request,
        spki_sha256,
        cert_pem,
    )
    assert lease_owner is not None
    assert conflict is None
    result = await gpu_pg._publish_completed_registration_fixture(
        session,
        response,
        request,
        cert_pem,
        spki_sha256,
    )
    registration_a = await session.get(
        ServerAttestation,
        result["attestation_id"],
    )
    reservation = await session.get(
        GpuLaunchReservation,
        response.claims.reservation_id,
    )
    registration_a.gpu_chute_id = reservation.chute_id
    registration_a.gpu_job_id = reservation.job_id
    registration_a.gpu_evidence_sha256 = canonical_sha256(registration_a.gpu_evidence)
    completed = await _complete_attempt(
        session,
        attempt.attempt_id,
        lease_owner,
        result,
    )
    completed.completed_at = datetime.now(timezone.utc) - timedelta(minutes=20)
    completed.response_ready_at = completed.completed_at
    completed.registration_replay_until = completed.completed_at + timedelta(minutes=15)
    await session.commit()
    return response, request, cert_pem, spki_sha256, registration_a, completed


def _operational_b(
    registration_a: ServerAttestation,
    reservation: GpuLaunchReservation,
    *,
    certificates: list[str] | None = None,
    failed: bool = False,
    stale: bool = False,
) -> ServerAttestation:
    now = datetime.now(timezone.utc)
    evidence = {
        "schema": "chutes.persisted-nvidia-evidence",
        "version": 1,
        "raw": [{"runtime": item} for item in (certificates or [])],
        "verified": {"certificate_sha256s": certificates or []},
    }
    return ServerAttestation(
        server_id=registration_a.server_id,
        quote_data="fresh-operational-quote",
        verification_error="operational evidence failed" if failed else None,
        created_at=now + timedelta(seconds=1),
        verified_at=(None if failed else now - timedelta(days=1) if stale else now),
        measurement_version=registration_a.measurement_version,
        measurement_name=registration_a.measurement_name,
        measurement_config_fingerprint=(registration_a.measurement_config_fingerprint),
        trust_set_fingerprint=registration_a.trust_set_fingerprint,
        revocation_status={},
        gpu_evidence=evidence,
        gpu_evidence_sha256=canonical_sha256(evidence),
        gpu_evidence_certificate_sha256s=list(certificates or []),
        gpu_launch_reservation_id=reservation.reservation_id,
        gpu_allocation_group_id=reservation.allocation_group_id,
        gpu_allocation_group_generation=reservation.allocation_group_generation,
        gpu_host_boot_generation=reservation.host_boot_generation,
        gpu_reservation_generation=reservation.reservation_generation,
        gpu_management_mode=reservation.management_mode,
        gpu_process_incarnation=reservation.process_incarnation,
        gpu_topology_fingerprint=reservation.topology_fingerprint,
        gpu_release_id=reservation.gpu_release_id,
        gpu_profile_id=reservation.profile_id,
        gpu_chute_id=reservation.chute_id,
        gpu_job_id=reservation.job_id,
        gpu_claims_sha256=reservation.claims_sha256,
    )


async def _add_operational_b(session, registration_a, reservation, **kwargs):
    certificates = kwargs.pop(
        "certificates",
        list(registration_a.gpu_evidence_certificate_sha256s),
    )
    operational_b = _operational_b(
        registration_a,
        reservation,
        certificates=certificates,
        **kwargs,
    )
    session.add(operational_b)
    await session.commit()
    return operational_b


async def test_registration_a_operational_b_mint_validate_and_gpu_infra(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        (
            response,
            request,
            _cert,
            spki,
            registration_a,
            completed,
        ) = await _completed_registration(session, "miner")
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        operational_b = await _add_operational_b(
            session,
            registration_a,
            reservation,
        )
        server = await session.get(Server, response.claims.server_id)
        authority = await require_completed_gpu_registration(
            session,
            reservation,
            operational_b,
            server,
        )
        assert (
            authority.registration_attestation.attestation_id
            == registration_a.attestation_id
        )
        assert authority.gpu_uuids == tuple(request.gpu_uuids)
        assert completed.registration_replay_until < datetime.now(timezone.utc)

        token, expires_at, attestation_id = await latest_gpu_runtime_session(
            session,
            server,
        )
        assert attestation_id == operational_b.attestation_id
        server.gpu_runtime_session_attestation_id = attestation_id
        server.gpu_runtime_session_expires_at = expires_at
        await session.commit()
        runtime_server, payload = await validate_gpu_runtime_session(
            session,
            token,
            required_purpose="gpu-infra",
        )
        assert payload["attestation_id"] == operational_b.attestation_id
        assert payload["attestation_id"] != registration_a.attestation_id

        readiness = SimpleNamespace(
            trusted_storage_ready=True,
            control_channel_eligible=True,
            reason="ready",
        )
        with (
            patch(
                "api.server.gpu_infra.observe_gpu_storage_liveness",
                AsyncMock(return_value=set()),
            ),
            patch(
                "api.server.gpu_infra.gpu_host_storage_readiness",
                AsyncMock(return_value=readiness),
            ),
        ):
            (
                locked_server,
                locked_reservation,
                _group,
                _host,
            ) = await _locked_current_lineage(
                session,
                runtime_server,
                payload,
                spki,
            )
        assert locked_server.server_id == registration_a.server_id
        assert (
            locked_reservation.registration_attestation_id
            == registration_a.attestation_id
        )
        await session.rollback()


async def test_tampered_registration_a_is_not_runtime_authority(postgres_schema):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        (
            response,
            _request,
            _cert,
            _spki,
            registration_a,
            _attempt,
        ) = await _completed_registration(session, "miner")
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        await _add_operational_b(session, registration_a, reservation)
        registration_a.gpu_claims_sha256 = "d" * 64
        await session.commit()
        server = await session.get(Server, response.claims.server_id)
        with pytest.raises(HTTPException, match="completion audit"):
            await latest_gpu_runtime_session(session, server)


@pytest.mark.parametrize("kind", ["stale", "failed"])
async def test_stale_or_failed_operational_b_blocks_runtime_authority(
    postgres_schema,
    kind,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        (
            response,
            _request,
            _cert,
            _spki,
            registration_a,
            _attempt,
        ) = await _completed_registration(session, "miner")
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        await _add_operational_b(
            session,
            registration_a,
            reservation,
            stale=kind == "stale",
            failed=kind == "failed",
        )
        server = await session.get(Server, response.claims.server_id)
        with pytest.raises(HTTPException, match="Latest GPU attestation attempt"):
            await latest_gpu_runtime_session(session, server)


@pytest.mark.parametrize("selection", ["added", "substituted"])
async def test_miner_operational_selection_must_equal_registered_subset(
    postgres_schema,
    selection,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        (
            response,
            request,
            _cert,
            _spki,
            registration_a,
            _attempt,
        ) = await _completed_registration(session, "miner")
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        registered = list(registration_a.gpu_evidence_certificate_sha256s)
        replacement = reservation.gpu_attestation_certificate_sha256s[2]
        certificates = (
            [*registered, replacement]
            if selection == "added"
            else [registered[0], replacement]
        )
        operational_b = await _add_operational_b(
            session,
            registration_a,
            reservation,
            certificates=certificates,
        )
        server = await session.get(Server, response.claims.server_id)
        with pytest.raises(HTTPException, match="operational attestation"):
            await require_completed_gpu_registration(
                session,
                reservation,
                operational_b,
                server,
            )
        assert len(request.gpu_uuids) == 2
        assert len(reservation.gpu_uuids) > len(request.gpu_uuids)


async def test_platform_operational_subset_is_rejected(postgres_schema):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    async with sessions() as session:
        (
            response,
            _request,
            _cert,
            _spki,
            registration_a,
            _attempt,
        ) = await _completed_registration(session, "platform")
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        operational_b = await _add_operational_b(
            session,
            registration_a,
            reservation,
            certificates=list(registration_a.gpu_evidence_certificate_sha256s[:2]),
        )
        server = await session.get(Server, response.claims.server_id)
        with pytest.raises(HTTPException, match="operational attestation"):
            await require_completed_gpu_registration(
                session,
                reservation,
                operational_b,
                server,
            )
        assert len(registration_a.gpu_evidence_certificate_sha256s) == len(
            reservation.gpu_uuids
        )
