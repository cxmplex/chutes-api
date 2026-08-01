"""Focused generation, replay, and wire-contract regressions for GPU rekey."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api import gpu_registration_service
from api.gpu_contracts import (
    GpuRegistrationNonceRequestV2,
    GpuRegistrationRequestV2,
    GpuRegistrationResponseV2,
    gpu_registration_client_request_id,
)
from api.gpu_registration_service import (
    _complete_attempt,
    _registration_nonce_matches_operation,
    issue_gpu_registration_nonce,
)
from api.server.exceptions import AttestationSupersededError
from api.server.service import _publish_gpu_registration_generation


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalar_one(self):
        return self._value


class _ManyResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return self

    def first(self):
        return self._values[0] if self._values else None

    def all(self):
        return list(self._values)


class _NonceDb:
    def __init__(self, results):
        self._results = iter(results)
        self.added = []

    async def execute(self, _statement):
        return next(self._results)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        return None


def _nonce_request(
    *,
    reservation_id: str = "reservation-1",
    server_id: str = "server-1",
    spki: str = "b" * 64,
    request_generation: int = 1,
):
    token = f"{reservation_id}.{'x' * 64}"
    return token, GpuRegistrationNonceRequestV2(
        client_request_id=gpu_registration_client_request_id(
            reservation_id,
            server_id,
            spki,
            request_generation,
        ),
        request_generation=request_generation,
        launch_reservation=token,
        claims_sha256="a" * 64,
        server_id=server_id,
    )


def _lineage(*, token: str, state: str, registration_generation: int):
    reservation = SimpleNamespace(
        reservation_id="reservation-1",
        allocation_group_id="group-1",
        server_id="server-1",
        claims_sha256="a" * 64,
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        allocation_group_generation=7,
        reservation_generation=9,
        process_incarnation="process-1",
        state=state,
        registration_generation=registration_generation,
    )
    group = SimpleNamespace(
        allocation_group_id="group-1",
        reservation_id=reservation.reservation_id,
        generation=reservation.allocation_group_generation,
        reservation_generation=reservation.reservation_generation,
        process_incarnation=reservation.process_incarnation,
        state=state,
    )
    return reservation, group


def _registration_request_fixture():
    document = json.loads(
        (
            Path(__file__).resolve().parents[1] / "fixtures/gpu_runtime_contracts_v1_v2.json"
        ).read_text()
    )
    return document["registration_v2"]["request"]


def test_generation_cas_loser_cannot_replace_winner_attestation():
    reservation = SimpleNamespace(
        registration_generation=1,
        registration_attestation_id="attestation-1",
    )

    _publish_gpu_registration_generation(reservation, 2, "attestation-2")

    assert reservation.registration_generation == 2
    assert reservation.registration_attestation_id == "attestation-2"
    with pytest.raises(AttestationSupersededError, match="generation changed"):
        _publish_gpu_registration_generation(
            reservation, 2, "attestation-losing-concurrent-attempt"
        )
    assert reservation.registration_generation == 2
    assert reservation.registration_attestation_id == "attestation-2"


@pytest.mark.parametrize(
    ("generation", "initial_matches", "rekey_matches"),
    [
        (0, False, False),
        (1, True, False),
        (2, False, True),
        (1024, False, True),
    ],
)
def test_nonce_operation_scope_is_generation_disjoint(
    generation,
    initial_matches,
    rekey_matches,
):
    nonce = SimpleNamespace(registration_generation=generation)

    assert _registration_nonce_matches_operation(nonce, rekey=False) is initial_matches
    assert _registration_nonce_matches_operation(nonce, rekey=True) is rekey_matches


@pytest.mark.asyncio
async def test_running_initial_nonce_request_requires_rekey_with_exact_gone_body(
    monkeypatch,
):
    token, request = _nonce_request()
    reservation, group = _lineage(
        token=token,
        state="running",
        registration_generation=1,
    )
    db = _NonceDb(
        [
            _ScalarResult(reservation),
            _ScalarResult(group),
            _ScalarResult(None),
        ]
    )
    monkeypatch.setattr(
        gpu_registration_service,
        "acquire_gpu_lifecycle_lock",
        AsyncMock(),
    )
    current_server = AsyncMock()
    monkeypatch.setattr(
        gpu_registration_service,
        "_current_gpu_registration_server",
        current_server,
    )

    with pytest.raises(HTTPException) as exc:
        await issue_gpu_registration_nonce(
            db,
            "127.0.0.1",
            request,
            "b" * 64,
        )

    assert exc.value.status_code == 410
    assert exc.value.detail == {"code": "gpu_registration_rekey_required"}
    current_server.assert_awaited_once_with(
        db,
        reservation,
        group,
    )


@pytest.mark.asyncio
async def test_rekey_nonce_targets_exact_next_registration_generation(monkeypatch):
    token, request = _nonce_request(request_generation=2)
    reservation, group = _lineage(
        token=token,
        state="running",
        registration_generation=4,
    )
    db = _NonceDb(
        [
            _ScalarResult(reservation),
            _ScalarResult(group),
            _ScalarResult(None),
            _ManyResult([]),
            _ScalarResult(None),
        ]
    )
    monkeypatch.setattr(
        gpu_registration_service,
        "acquire_gpu_lifecycle_lock",
        AsyncMock(),
    )
    current_server = AsyncMock()
    monkeypatch.setattr(
        gpu_registration_service,
        "_current_gpu_registration_server",
        current_server,
    )

    response = await issue_gpu_registration_nonce(
        db,
        "127.0.0.1",
        request,
        "b" * 64,
        rekey=True,
    )

    assert response.request_generation == 2
    assert len(db.added) == 1
    assert db.added[0].registration_generation == 5
    current_server.assert_awaited_once_with(
        db,
        reservation,
        group,
    )


@pytest.mark.asyncio
async def test_successful_rekey_exact_nonce_retry_uses_published_generation(
    monkeypatch,
):
    token, request = _nonce_request(request_generation=2)
    reservation, group = _lineage(
        token=token,
        state="running",
        registration_generation=5,
    )
    now = datetime.now(timezone.utc)
    existing = SimpleNamespace(
        request_generation=request.request_generation,
        registration_generation=5,
        peer_spki_sha256="b" * 64,
        state="claimed",
        claimed_attempt_id="attempt-5",
        nonce_value="c" * 64,
        client_request_id=request.client_request_id,
        nonce_id="nonce-5",
        reservation_id=reservation.reservation_id,
        expires_at=now + timedelta(minutes=5),
    )
    attempt = SimpleNamespace(
        attempt_id="attempt-5",
        registration_generation=5,
        peer_spki_sha256="b" * 64,
        state="completed",
        registration_replay_until=now + timedelta(minutes=5),
    )
    db = _NonceDb(
        [
            _ScalarResult(reservation),
            _ScalarResult(group),
            _ScalarResult(existing),
            _ScalarResult(attempt),
        ]
    )
    monkeypatch.setattr(
        gpu_registration_service,
        "acquire_gpu_lifecycle_lock",
        AsyncMock(),
    )
    current_server = AsyncMock()
    monkeypatch.setattr(
        gpu_registration_service,
        "_current_gpu_registration_server",
        current_server,
    )

    response = await issue_gpu_registration_nonce(
        db,
        "127.0.0.1",
        request,
        "b" * 64,
        rekey=True,
    )

    assert response.claimed_attempt_id == attempt.attempt_id
    assert response.nonce == existing.nonce_value
    current_server.assert_awaited_once_with(
        db,
        reservation,
        group,
        "b" * 64,
        require_current_spki=True,
    )


@pytest.mark.asyncio
async def test_successful_completion_retains_nonce_only_for_bounded_replay(monkeypatch):
    now = datetime.now(timezone.utc)
    attempt = SimpleNamespace(
        attempt_id="attempt-2",
        nonce_id="nonce-2",
        state="processing",
        processing_lease_owner="lease-2",
        request_payload_ciphertext="ciphertext",
        request_payload_key_id="key-1",
    )
    nonce = SimpleNamespace(state="claimed", nonce_value="d" * 64)
    db = _NonceDb(
        [
            _ScalarResult(attempt),
            _ScalarResult(nonce),
            _ManyResult([]),
        ]
    )
    monkeypatch.setattr(
        gpu_registration_service,
        "acquire_gpu_lifecycle_lock",
        AsyncMock(),
    )
    monkeypatch.setattr(gpu_registration_service, "_now", lambda: now)

    completed = await _complete_attempt(
        db,
        attempt.attempt_id,
        "lease-2",
        {"attestation_id": "attestation-2"},
    )

    assert completed.state == "completed"
    assert completed.registration_replay_until == now + timedelta(minutes=15)
    assert nonce.state == "claimed"
    assert nonce.nonce_value == "d" * 64


@pytest.mark.parametrize("coercive_value", ["2", True, 2.0])
def test_nonce_request_rejects_coercive_version_types(coercive_value):
    _, request = _nonce_request()
    document = request.model_dump(mode="json")
    document["version"] = coercive_value

    with pytest.raises(ValidationError):
        GpuRegistrationNonceRequestV2.model_validate(document)


@pytest.mark.parametrize("coercive_value", ["1", True, 1.0])
def test_nonce_request_rejects_coercive_request_generation(coercive_value):
    _, request = _nonce_request()
    document = request.model_dump(mode="json")
    document["request_generation"] = coercive_value

    with pytest.raises(ValidationError):
        GpuRegistrationNonceRequestV2.model_validate(document)


@pytest.mark.parametrize("coercive_value", ["2", True, 2.0])
def test_registration_request_rejects_coercive_version_types(coercive_value):
    document = _registration_request_fixture()
    document["version"] = coercive_value

    with pytest.raises(ValidationError):
        GpuRegistrationRequestV2.model_validate(document)


@pytest.mark.parametrize(
    "failure_code",
    [
        "gpu_registration_verification_failed",
        "gpu_registration_lineage_ended",
        "gpu_registration_nonce_revoked",
        "gpu_legacy_hotplug_custody_mismatch",
        "gpu_legacy_hotplug_failed",
        "gpu_registration_generation_superseded",
    ],
)
def test_shared_registration_failure_codes_are_accepted(failure_code):
    response = GpuRegistrationResponseV2(
        attempt_id="attempt-1",
        state="failed",
        status_url="/servers/gpu/registration/attempts/attempt-1",
        failure_code=failure_code,
        failure_detail="terminal",
    )

    assert response.failure_code == failure_code


def test_arbitrary_registration_failure_code_is_rejected():
    with pytest.raises(ValidationError):
        GpuRegistrationResponseV2(
            attempt_id="attempt-1",
            state="failed",
            status_url="/servers/gpu/registration/attempts/attempt-1",
            failure_code="arbitrary_hotplug_error",
            failure_detail="must stay in the audit row only",
        )
