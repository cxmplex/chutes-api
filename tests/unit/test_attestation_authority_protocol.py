"""Behavioral regressions for monotonic attestation publication authority."""

import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.host.gpu_allocations import GpuAllocationError
from api.host.schemas import (
    TdLaunchReservationClaimsV1,
    TdQuoteCommitmentV1,
    canonical_sha256,
)
from api.server.exceptions import (
    AttestationSupersededError,
    AttestationVerifierUnavailableError,
    MeasurementMismatchError,
    NonceError,
)
from api.server.router import register_cpu_server_endpoint
from api.server.schemas import (
    CpuServerRegistrationArgs,
    RuntimeAttestationArgs,
    RuntimeAttestationNonceContext,
    ServerAttestation,
)
from api.server.service import (
    process_runtime_attestation,
    register_cpu_server,
    runtime_attestation_context_for_server,
    runtime_attestation_context_for_server_db,
)


SERVER_ID = "td-authority-test"
OWNER = "5FAttestationAuthorityOwner"
HOST_ID = "host-authority-test"
SERVER_IP = "203.0.113.20"
CERT_HASH = "a" * 64
NONCE = "b" * 64
CONFIG_FINGERPRINT = "c" * 64
TRUST_FINGERPRINT = "d" * 64
CPU_RESERVATION_ID = "cpu-reservation-r1"
CPU_BOOT_GENERATION = 11
CPU_PROCESS_INCARNATION = "cpu-process-r1"
CPU_CLAIMS_SHA256 = "1" * 64
CPU_REGISTRATION_ATTESTATION_ID = "cpu-registration-r1"


def _async_db() -> AsyncMock:
    db = AsyncMock(spec=AsyncSession)
    db.add = Mock()
    db.execute = AsyncMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.get = AsyncMock()
    return db


def _scalar_result(value) -> Mock:
    result = Mock()
    result.scalar_one_or_none.return_value = value
    return result


def _membership_result() -> Mock:
    result = Mock()
    result.scalar.return_value = True
    return result


def _runtime_server(*, compute_type: str, storage_role: bool = False):
    return SimpleNamespace(
        server_id=SERVER_ID,
        ip=SERVER_IP,
        miner_hotkey=OWNER,
        name=SERVER_ID,
        is_tee=True,
        compute_type=compute_type,
        storage_role=storage_role,
        self_registered=True,
        tee_type="tdx",
        host_id=HOST_ID,
        launch_reservation_id=(
            CPU_RESERVATION_ID if compute_type == "cpu" else None
        ),
        launch_boot_generation=(
            CPU_BOOT_GENERATION if compute_type == "cpu" else None
        ),
        gpu_retired_at=None,
        attested_cert="attested-certificate",
        attested_cert_pubkey_hash=CERT_HASH,
        version="1.0.0",
        measurement_name="storage-runtime" if storage_role else "gpu-runtime",
        measurement_config_fingerprint=CONFIG_FINGERPRINT,
        trust_set_fingerprint=TRUST_FINGERPRINT,
        attestation_revocation_status={"authority": "prior"},
    )


def _cpu_runtime_context() -> RuntimeAttestationNonceContext:
    return RuntimeAttestationNonceContext(
        server_id=SERVER_ID,
        miner_hotkey=OWNER,
        vm_name=SERVER_ID,
        cert_hash=CERT_HASH,
        role="storage",
        compute_type="cpu",
        tee_type="tdx",
        provider="bare-metal",
        deployment_model="bare-metal-model-b",
        host_id=HOST_ID,
        measurement_name="storage-runtime",
        measurement_version="1.0.0",
        measurement_config_fingerprint=CONFIG_FINGERPRINT,
        trust_set_fingerprint=TRUST_FINGERPRINT,
        cpu_launch_reservation_id=CPU_RESERVATION_ID,
        cpu_launch_boot_generation=CPU_BOOT_GENERATION,
        cpu_process_incarnation=CPU_PROCESS_INCARNATION,
        cpu_claims_sha256=CPU_CLAIMS_SHA256,
        cpu_registration_attestation_id=CPU_REGISTRATION_ATTESTATION_ID,
    )


def _cpu_launch_reservation():
    now = datetime.now(timezone.utc)
    claims = TdLaunchReservationClaimsV1(
        reservation_id=CPU_RESERVATION_ID,
        token_id="cpu-token-r1",
        owner_hotkey=OWNER,
        host_id=HOST_ID,
        host_key_generation=7,
        server_id=SERVER_ID,
        role="storage",
        compute_type="cpu",
        tee_type="tdx",
        process_incarnation=CPU_PROCESS_INCARNATION,
        boot_generation=CPU_BOOT_GENERATION,
        release_id="cpu-release-r1",
        image_sha256="3" * 64,
        image_version="1.0.0",
        profile_id="storage-runtime",
        storage_intent_id="storage-intent-r1",
        storage_intent_generation=4,
        launch_nonce=base64.b64encode(b"n" * 32).decode("ascii"),
        release_target_sha256="4" * 64,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    return SimpleNamespace(
        **claims.model_dump(mode="python"),
        claims_version=claims.version,
        host_compute_type="cpu",
        gpu_release_id=None,
        active_cpu_release_id=None,
        claims=claims.model_dump(mode="json", exclude_none=True),
        claims_sha256=canonical_sha256(claims),
        invalidated_at=None,
        consumed_at=now,
        consumed_attestation_id=CPU_REGISTRATION_ATTESTATION_ID,
        consumed_cert_pubkey_hash=CERT_HASH,
    )


def _gpu_runtime_context() -> RuntimeAttestationNonceContext:
    return RuntimeAttestationNonceContext(
        server_id=SERVER_ID,
        miner_hotkey=OWNER,
        vm_name=SERVER_ID,
        cert_hash=CERT_HASH,
        role="compute",
        compute_type="gpu",
        tee_type="tdx",
        provider="bare-metal",
        deployment_model="bare-metal-model-b",
        host_id=HOST_ID,
        measurement_name="gpu-runtime",
        measurement_version="1.0.0",
        measurement_config_fingerprint=CONFIG_FINGERPRINT,
        trust_set_fingerprint=TRUST_FINGERPRINT,
        gpu_launch_reservation_id="gpu-reservation-new",
        gpu_allocation_group_id="gpu-group-new",
        gpu_allocation_group_generation=3,
        gpu_host_boot_generation=5,
        gpu_reservation_generation=7,
        gpu_management_mode="platform",
        gpu_process_incarnation="gpu-process-new",
        gpu_topology_fingerprint="e" * 64,
        gpu_release_id="gpu-release-new",
        gpu_profile_id="gpu-runtime",
        gpu_chute_id="chute-new",
        gpu_job_id=None,
        gpu_claims_sha256="f" * 64,
    )


def _measurement(*, storage: bool):
    return SimpleNamespace(
        name="storage-runtime" if storage else "gpu-runtime",
        version="1.0.0",
        provider="bare-metal",
        gpu_count=0 if storage else 1,
        expected_gpus=[] if storage else ["h200"],
    )


def _quote():
    return SimpleNamespace(
        mrtd="0" * 96,
        rtmrs={"rtmr0": "0" * 96, "rtmr1": "0" * 96, "rtmr2": "0" * 96, "rtmr3": "0" * 96},
    )


def test_cpu_runtime_context_projects_exact_consumed_reservation_lineage():
    server = _runtime_server(compute_type="cpu", storage_role=True)
    reservation = _cpu_launch_reservation()
    measurement = _measurement(storage=True)
    measurement.tee_type = "tdx"
    with (
        patch(
            "api.server.service.settings",
            SimpleNamespace(tee_measurements=[measurement]),
        ),
        patch(
            "api.server.service.measurement_config_fingerprint",
            return_value=CONFIG_FINGERPRINT,
        ),
        patch(
            "api.server.service.measurement_trust_set_fingerprint",
            return_value=TRUST_FINGERPRINT,
        ),
    ):
        context = runtime_attestation_context_for_server(
            server,
            cpu_reservation=reservation,
        )

        assert context.cpu_launch_reservation_id == CPU_RESERVATION_ID
        assert context.cpu_launch_boot_generation == CPU_BOOT_GENERATION
        assert context.cpu_process_incarnation == CPU_PROCESS_INCARNATION
        assert context.cpu_claims_sha256 == canonical_sha256(
            TdLaunchReservationClaimsV1.model_validate(reservation.claims)
        )
        assert (
            context.cpu_registration_attestation_id
            == CPU_REGISTRATION_ATTESTATION_ID
        )

        reservation.process_incarnation = "row-claims-drift"
        with pytest.raises(
            MeasurementMismatchError,
            match="no longer the exact consumed server lineage",
        ):
            runtime_attestation_context_for_server(
                server,
                cpu_reservation=reservation,
            )


def test_model_b_cpu_nonce_rejects_partial_reservation_lineage():
    document = _cpu_runtime_context().model_dump()
    document["cpu_registration_attestation_id"] = None
    with pytest.raises(ValueError, match="complete launch reservation lineage"):
        RuntimeAttestationNonceContext.model_validate(document)


@pytest.mark.asyncio
async def test_cpu_runtime_db_reload_refreshes_cached_reenrollment_identity():
    cached_r1 = SimpleNamespace(
        server_id=SERVER_ID,
        compute_type="cpu",
        host_id=HOST_ID,
        launch_reservation_id=CPU_RESERVATION_ID,
    )
    committed_r2 = SimpleNamespace(
        server_id=SERVER_ID,
        compute_type="cpu",
        host_id=HOST_ID,
        launch_reservation_id="cpu-reservation-r2",
    )
    r2_reservation = SimpleNamespace(reservation_id="cpu-reservation-r2")
    db = _async_db()
    db.info = {}
    db.execute.side_effect = [
        Mock(),
        _scalar_result(committed_r2),
        _scalar_result(r2_reservation),
    ]
    expected = _cpu_runtime_context().model_copy(
        update={
            "cpu_launch_reservation_id": "cpu-reservation-r2",
            "cpu_launch_boot_generation": CPU_BOOT_GENERATION + 1,
            "cpu_process_incarnation": "cpu-process-r2",
            "cpu_claims_sha256": "2" * 64,
            "cpu_registration_attestation_id": "cpu-registration-r2",
        }
    )

    with patch(
        "api.server.service.runtime_attestation_context_for_server",
        return_value=expected,
    ) as project_context:
        result = await runtime_attestation_context_for_server_db(db, cached_r1)

    assert result == expected
    server_query = db.execute.await_args_list[1].args[0]
    reservation_query = db.execute.await_args_list[2].args[0]
    assert server_query.get_execution_options()["populate_existing"] is True
    assert reservation_query.get_execution_options()["populate_existing"] is True
    project_context.assert_called_once_with(
        committed_r2,
        cpu_reservation=r2_reservation,
    )


@pytest.mark.asyncio
async def test_older_runtime_success_cannot_overwrite_newer_failure_or_issue_luks():
    db = _async_db()
    server = _runtime_server(compute_type="cpu", storage_role=True)
    context = _cpu_runtime_context()
    newer_failure = SimpleNamespace(
        attestation_id="newer-failure",
        verification_error="newer verification failed",
    )
    authority_before = (
        server.version,
        server.measurement_name,
        server.measurement_config_fingerprint,
        server.trust_set_fingerprint,
        dict(server.attestation_revocation_status),
    )

    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch(
            "api.server.service._ensure_attestation_subject",
            new_callable=AsyncMock,
        ),
        patch(
            "api.server.service.runtime_attestation_context_for_server_db",
            new_callable=AsyncMock,
            return_value=context,
        ),
        patch(
            "api.server.service.acquire_gpu_lifecycle_lock",
            new_callable=AsyncMock,
        ),
        patch("api.server.service.generate_uuid", return_value="older-success"),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={"authority": "candidate"}),
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_measurement(storage=True),
        ),
        patch(
            "api.server.service._measurement_fingerprints",
            return_value=(CONFIG_FINGERPRINT, TRUST_FINGERPRINT),
        ),
        patch(
            "api.server.gpu_sessions._latest_attestation_attempt",
            new_callable=AsyncMock,
            return_value=newer_failure,
        ),
        patch("api.server.service._stamp_server_measurement") as stamp_server,
        patch(
            "api.server.service.generate_luks_quote_nonce",
            new_callable=AsyncMock,
        ) as issue_luks,
    ):
        with pytest.raises(AttestationSupersededError):
            await process_runtime_attestation(
                db,
                SERVER_ID,
                SERVER_IP,
                RuntimeAttestationArgs(quote="runtime-quote", tee_type="tdx"),
                OWNER,
                NONCE,
                CERT_HASH,
                context,
            )

    [older_attempt] = [
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], ServerAttestation)
    ]
    assert older_attempt.attestation_id == "older-success"
    assert older_attempt.verification_error is None
    assert newer_failure.verification_error == "newer verification failed"
    assert authority_before == (
        server.version,
        server.measurement_name,
        server.measurement_config_fingerprint,
        server.trust_set_fingerprint,
        dict(server.attestation_revocation_status),
    )
    stamp_server.assert_not_called()
    issue_luks.assert_not_awaited()
    db.refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_cpu_reenrollment_lineage_change_rejects_stale_runtime_success():
    db = _async_db()
    server = _runtime_server(compute_type="cpu", storage_role=True)
    r1_context = _cpu_runtime_context()
    r2_context = r1_context.model_copy(
        update={
            "cpu_launch_reservation_id": "cpu-reservation-r2",
            "cpu_launch_boot_generation": CPU_BOOT_GENERATION + 1,
            "cpu_process_incarnation": "cpu-process-r2",
            "cpu_claims_sha256": "2" * 64,
            "cpu_registration_attestation_id": "cpu-registration-r2",
        }
    )
    current_attempt = SimpleNamespace(
        attestation_id="stale-r1-runtime",
        verification_error="Runtime attestation verification did not complete.",
    )
    authority_before = (
        server.version,
        server.measurement_name,
        server.measurement_config_fingerprint,
        server.trust_set_fingerprint,
        dict(server.attestation_revocation_status),
    )

    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch(
            "api.server.service._ensure_attestation_subject",
            new_callable=AsyncMock,
        ),
        patch(
            "api.server.service.runtime_attestation_context_for_server_db",
            new_callable=AsyncMock,
            side_effect=[r1_context, r2_context, r2_context],
        ),
        patch(
            "api.server.service.acquire_gpu_lifecycle_lock",
            new_callable=AsyncMock,
        ),
        patch(
            "api.server.service.generate_uuid",
            return_value=current_attempt.attestation_id,
        ),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={"authority": "candidate"}),
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_measurement(storage=True),
        ),
        patch(
            "api.server.service._measurement_fingerprints",
            return_value=(CONFIG_FINGERPRINT, TRUST_FINGERPRINT),
        ),
        patch(
            "api.server.gpu_sessions._latest_attestation_attempt",
            new_callable=AsyncMock,
            return_value=current_attempt,
        ),
        patch("api.server.service._stamp_server_measurement") as stamp_server,
        patch(
            "api.server.service.generate_luks_quote_nonce",
            new_callable=AsyncMock,
        ) as issue_luks,
    ):
        with pytest.raises(
            NonceError,
            match="lineage changed before failed evidence could be recorded",
        ):
            await process_runtime_attestation(
                db,
                SERVER_ID,
                SERVER_IP,
                RuntimeAttestationArgs(quote="runtime-quote", tee_type="tdx"),
                OWNER,
                NONCE,
                CERT_HASH,
                r1_context,
            )

    [attempt] = [
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], ServerAttestation)
    ]
    assert attempt.attestation_id == current_attempt.attestation_id
    assert (
        attempt.verification_error
        == "Runtime reservation lineage changed during evidence verification."
    )
    assert authority_before == (
        server.version,
        server.measurement_name,
        server.measurement_config_fingerprint,
        server.trust_set_fingerprint,
        dict(server.attestation_revocation_status),
    )
    stamp_server.assert_not_called()
    issue_luks.assert_not_awaited()
    db.refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_older_runtime_failure_cannot_fence_newer_gpu_success():
    db = _async_db()
    server = _runtime_server(compute_type="gpu")
    context = _gpu_runtime_context()
    reservation = SimpleNamespace(state="running")
    db.execute.return_value = _scalar_result(reservation)
    newer_success = SimpleNamespace(
        attestation_id="newer-success",
        verification_error=None,
    )
    verifier_error = AttestationVerifierUnavailableError("runtime verifier unavailable")

    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch(
            "api.server.service._ensure_attestation_subject",
            new_callable=AsyncMock,
        ),
        patch(
            "api.server.service.runtime_attestation_context_for_server_db",
            new_callable=AsyncMock,
            return_value=context,
        ),
        patch(
            "api.server.service.acquire_gpu_lifecycle_lock",
            new_callable=AsyncMock,
        ),
        patch("api.server.service.generate_uuid", return_value="older-failure"),
        patch("api.server.service.canonical_sha256", return_value="f" * 64),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            side_effect=verifier_error,
        ),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_measurement(storage=False),
        ),
        patch(
            "api.host.gpu_allocations._validate_row_claims",
            return_value=SimpleNamespace(),
        ),
        patch(
            "api.server.gpu_sessions._latest_attestation_attempt",
            new_callable=AsyncMock,
            return_value=newer_success,
        ),
        patch(
            "api.host.gpu_allocations.request_gpu_lifecycle_fence",
            new_callable=AsyncMock,
        ) as lifecycle_fence,
    ):
        with pytest.raises(AttestationSupersededError):
            await process_runtime_attestation(
                db,
                SERVER_ID,
                SERVER_IP,
                RuntimeAttestationArgs(
                    quote="runtime-quote",
                    tee_type="tdx",
                    gpu_evidence=[{"evidence": "candidate"}],
                ),
                OWNER,
                NONCE,
                CERT_HASH,
                context,
            )

    [older_attempt] = [
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], ServerAttestation)
    ]
    assert older_attempt.attestation_id == "older-failure"
    assert older_attempt.verification_error == "runtime verifier unavailable"
    assert newer_success.verification_error is None
    lifecycle_fence.assert_not_awaited()



@pytest.mark.asyncio
async def test_gpu_claim_corruption_finalizes_durable_pending_attempt_before_verification():
    db = _async_db()
    server = _runtime_server(compute_type="gpu")
    context = _gpu_runtime_context()
    reservation = SimpleNamespace(state="running")
    db.execute.return_value = _scalar_result(reservation)

    with (
        patch(
            "api.server.service.check_server_ownership",
            new_callable=AsyncMock,
            return_value=server,
        ),
        patch(
            "api.server.service._ensure_attestation_subject",
            new_callable=AsyncMock,
        ),
        patch(
            "api.server.service.runtime_attestation_context_for_server_db",
            new_callable=AsyncMock,
            return_value=context,
        ),
        patch(
            "api.server.service.acquire_gpu_lifecycle_lock",
            new_callable=AsyncMock,
        ),
        patch("api.server.service.generate_uuid", return_value="claims-corrupt-attempt"),
        patch(
            "api.host.gpu_allocations._validate_row_claims",
            side_effect=GpuAllocationError("durable claims drift"),
        ),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
        ) as verify_quote,
    ):
        with pytest.raises(MeasurementMismatchError, match="claims are invalid"):
            await process_runtime_attestation(
                db,
                SERVER_ID,
                SERVER_IP,
                RuntimeAttestationArgs(
                    quote="runtime-quote",
                    tee_type="tdx",
                    gpu_evidence=[{"evidence": "candidate"}],
                ),
                OWNER,
                NONCE,
                CERT_HASH,
                context,
            )

    [attempt] = [
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], ServerAttestation)
    ]
    assert attempt.attestation_id == "claims-corrupt-attempt"
    assert attempt.verification_error == "Persisted GPU reservation claims are invalid."
    assert db.commit.await_count == 2
    db.flush.assert_awaited_once()
    verify_quote.assert_not_awaited()


def _model_b_registration_args() -> CpuServerRegistrationArgs:
    commitment = TdQuoteCommitmentV1(
        reservation_sha256="1" * 64,
        launch_nonce=base64.b64encode(b"n" * 32).decode("ascii"),
        attested_spki_sha256=CERT_HASH,
        release_target_sha256="2" * 64,
        boot_generation=4,
    )
    return CpuServerRegistrationArgs(
        server_id=SERVER_ID,
        name=SERVER_ID,
        quote="cpu-runtime-quote",
        tee_type="tdx",
        benchmark={"untrusted": True},
        launch_reservation="opaque-reservation-token",
        quote_commitment=commitment,
        td_signature="signature",
    )


def _model_b_reservation():
    reservation = SimpleNamespace(
        reservation_id="reservation-authority-test",
        boot_generation=4,
    )
    claims = SimpleNamespace(
        version=1,
        owner_hotkey=OWNER,
        host_id=HOST_ID,
        server_id=SERVER_ID,
        tee_type="tdx",
        role="chute",
        profile_id="cpu-runtime",
        image_sha256="3" * 64,
        process_incarnation="cpu-process-authority-test",
        host_compute_type="cpu",
    )
    return reservation, claims


@pytest.mark.asyncio
async def test_model_b_reenrollment_commits_pending_attempt_before_verification_failure():
    db = _async_db()
    args = _model_b_registration_args()
    reservation, claims = _model_b_reservation()
    existing_server = SimpleNamespace(
        server_id=SERVER_ID,
        miner_hotkey=OWNER,
        compute_type="cpu",
        tee_type="tdx",
        version="prior-version",
        measurement_name="prior-measurement",
        measurement_config_fingerprint="4" * 64,
        trust_set_fingerprint="5" * 64,
        attestation_revocation_status={"authority": "prior"},
        attested_cert_pubkey_hash=CERT_HASH,
    )
    authority_before = dict(vars(existing_server))
    attempts = []
    events = []

    def add(obj):
        attempts.append(obj)
        events.append(("add", getattr(obj, "verification_error", None)))

    async def flush():
        events.append(("flush", attempts[-1].verification_error))

    async def commit():
        detail = attempts[-1].verification_error if attempts else None
        events.append(("commit", detail))

    async def fail_verification(*_args, **_kwargs):
        events.append(("verify", None))
        raise AttestationVerifierUnavailableError("cpu verifier unavailable")

    db.add.side_effect = add
    db.flush.side_effect = flush
    db.commit.side_effect = commit
    attempt_result = Mock()
    attempt_result.scalar_one_or_none.side_effect = lambda: attempts[0]
    db.execute.side_effect = [
        _scalar_result(existing_server),
        _scalar_result(SERVER_ID),
        _membership_result(),
        attempt_result,
    ]

    with (
        patch("api.server.service.settings", SimpleNamespace(skip_metagraph_check=False, netuid=64)),
        patch(
            "api.server.service.resolve_launch_reservation",
            new_callable=AsyncMock,
            return_value=(reservation, claims),
        ),
        patch("api.server.service._verify_td_registration_signature"),
        patch("api.server.service.generate_uuid", return_value="cpu-pending-attempt"),
        patch("api.server.service.reservation_bound_attestation_nonce", return_value=NONCE),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            side_effect=fail_verification,
        ),
    ):
        with pytest.raises(AttestationVerifierUnavailableError):
            await register_cpu_server(
                db,
                SERVER_IP,
                args,
                None,
                NONCE,
                None,
                CERT_HASH,
                "attested-certificate",
            )

    assert len(attempts) == 1
    pending = attempts[0]
    assert isinstance(pending, ServerAttestation)
    assert pending.attestation_id == "cpu-pending-attempt"
    assert pending.verification_error == "cpu verifier unavailable"
    first_commit = next(index for index, event in enumerate(events) if event[0] == "commit")
    verify = next(index for index, event in enumerate(events) if event[0] == "verify")
    assert events[:3] == [
        ("add", "CPU registration attestation did not complete."),
        ("flush", "CPU registration attestation did not complete."),
        ("commit", "CPU registration attestation did not complete."),
    ]
    assert first_commit < verify
    assert events[-1] == ("commit", "cpu verifier unavailable")
    assert authority_before == vars(existing_server)


@pytest.mark.asyncio
async def test_model_b_first_registration_failure_persists_attributed_attempt_without_server():
    db = _async_db()
    args = _model_b_registration_args()
    reservation, claims = _model_b_reservation()
    attempts = []
    events = []

    def add(obj):
        attempts.append(obj)
        events.append(("add", getattr(obj, "verification_error", None)))

    async def flush():
        events.append(("flush", attempts[-1].verification_error))

    async def commit():
        events.append(("commit", attempts[-1].verification_error))

    async def fail_verification(*_args, **_kwargs):
        events.append(("verify", None))
        raise AttestationVerifierUnavailableError("first verifier unavailable")

    db.add.side_effect = add
    db.flush.side_effect = flush
    db.commit.side_effect = commit
    attempt_result = Mock()
    attempt_result.scalar_one_or_none.side_effect = lambda: attempts[0]
    db.execute.side_effect = [
        _scalar_result(None),
        _scalar_result(SERVER_ID),
        _membership_result(),
        attempt_result,
    ]

    with (
        patch("api.server.service.settings", SimpleNamespace(skip_metagraph_check=False, netuid=64)),
        patch(
            "api.server.service.resolve_launch_reservation",
            new_callable=AsyncMock,
            return_value=(reservation, claims),
        ),
        patch("api.server.service._verify_td_registration_signature"),
        patch("api.server.service.generate_uuid", return_value="cpu-first-attempt"),
        patch("api.server.service.reservation_bound_attestation_nonce", return_value=NONCE),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            side_effect=fail_verification,
        ),
    ):
        with pytest.raises(AttestationVerifierUnavailableError):
            await register_cpu_server(
                db,
                SERVER_IP,
                args,
                None,
                NONCE,
                None,
                CERT_HASH,
                "attested-certificate",
            )

    assert len(attempts) == 1
    pending = attempts[0]
    assert isinstance(pending, ServerAttestation)
    assert pending.attestation_id == "cpu-first-attempt"
    assert pending.server_id == SERVER_ID
    assert pending.attribution_reservation_id == reservation.reservation_id
    assert pending.attribution_owner_hotkey == OWNER
    assert pending.verification_error == "first verifier unavailable"
    assert events[:3] == [
        ("add", "CPU registration attestation did not complete."),
        ("flush", "CPU registration attestation did not complete."),
        ("commit", "CPU registration attestation did not complete."),
    ]
    assert events.index(("commit", "CPU registration attestation did not complete.")) < events.index(
        ("verify", None)
    )
    assert events[-1] == ("commit", "first verifier unavailable")
    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_older_model_b_success_reaches_sequence_cas_after_newer_consumption():
    db = _async_db()
    args = _model_b_registration_args()
    reservation, claims = _model_b_reservation()
    reservation.consumed_at = object()
    reservation.consumed_attestation_id = "newer-success"
    reservation.invalidated_at = None
    current_server = SimpleNamespace(
        server_id=SERVER_ID,
        miner_hotkey=OWNER,
        compute_type="cpu",
        tee_type="tdx",
        launch_reservation_id=reservation.reservation_id,
        version="newer-version",
        measurement_name="cpu-runtime",
        measurement_config_fingerprint=CONFIG_FINGERPRINT,
        trust_set_fingerprint=TRUST_FINGERPRINT,
        attestation_revocation_status={"authority": "newer"},
    )
    authority_before = dict(vars(current_server))
    attempts = []
    db.add.side_effect = attempts.append
    attempt_result = Mock()
    attempt_result.scalar_one_or_none.side_effect = lambda: attempts[0]
    db.execute.side_effect = [
        _scalar_result(None),
        _scalar_result(SERVER_ID),
        _membership_result(),
        _scalar_result(current_server),
        attempt_result,
    ]
    measurement = SimpleNamespace(
        name="cpu-runtime",
        version="1.0.0",
        provider="bare-metal",
        gpu_count=0,
        expected_gpus=[],
        image_sha256="3" * 64,
    )
    latest = SimpleNamespace(attestation_id="newer-success", verification_error=None)

    with (
        patch("api.server.service.settings", SimpleNamespace(skip_metagraph_check=False, netuid=64)),
        patch(
            "api.server.service.resolve_launch_reservation",
            new_callable=AsyncMock,
            side_effect=[(reservation, claims), (reservation, claims)],
        ) as resolve,
        patch("api.server.service._verify_td_registration_signature"),
        patch("api.server.service.generate_uuid", return_value="older-success"),
        patch("api.server.service.reservation_bound_attestation_nonce", return_value=NONCE),
        patch("api.server.service.build_runtime_quote", return_value=_quote()),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={"authority": "candidate"}),
        ),
        patch("api.server.service.get_matching_measurement_config", return_value=measurement),
        patch(
            "api.server.service._measurement_fingerprints",
            return_value=(CONFIG_FINGERPRINT, TRUST_FINGERPRINT),
        ),
        patch(
            "api.server.service._validate_cpu_registration_host",
            new_callable=AsyncMock,
        ),
        patch("api.server.service._validate_existing_model_b_server_identity"),
        patch(
            "api.server.service.validate_cpu_benchmark",
            return_value={
                "cpu_cores": 8,
                "ram_gb": 32,
                "composite_score": 1.0,
            },
        ),
        patch(
            "api.server.gpu_sessions._latest_attestation_attempt",
            new_callable=AsyncMock,
            return_value=latest,
        ),
    ):
        with pytest.raises(AttestationSupersededError):
            await register_cpu_server(
                db,
                SERVER_IP,
                args,
                None,
                NONCE,
                None,
                CERT_HASH,
                "attested-certificate",
            )

    pending = attempts[0]
    assert isinstance(pending, ServerAttestation)
    assert pending.attestation_id == "older-success"
    assert pending.verification_error is None
    assert pending.verified_at is not None
    assert authority_before == vars(current_server)
    assert len(resolve.await_args_list) == 2
    assert resolve.await_args_list[1].kwargs == {"allow_consumed_for_publication": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("service_error", "expected_status"),
    [
        (AttestationSupersededError(), 409),
        (AttestationVerifierUnavailableError(), 503),
    ],
)
async def test_cpu_registration_route_preserves_attestation_status_mapping(
    service_error, expected_status
):
    args = _model_b_registration_args()
    request = SimpleNamespace(state=SimpleNamespace(client_ip=SERVER_IP))
    db = _async_db()

    with patch(
        "api.server.router.register_cpu_server",
        new_callable=AsyncMock,
        side_effect=service_error,
    ):
        with pytest.raises(HTTPException) as raised:
            await register_cpu_server_endpoint(
                request,
                args,
                db,
                NONCE,
                CERT_HASH,
                "attested-certificate",
                None,
                None,
            )

    assert raised.value.status_code == expected_status
    assert raised.value.detail == service_error.message
