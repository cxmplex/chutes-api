"""Real API/sek8s Registration V2 generation-transition fixtures.

These tests deliberately run the sibling sek8s ``register_gpu_v2`` state
machine.  Its HTTP transport is adapted to the real API service functions and
an isolated PostgreSQL schema.  Only quote/measurement/GPU hardware boundaries
are deterministic: the API consumes the agent's real EC request signature.
The shared PostgreSQL seed isolates signed-release provenance, which is covered
by the release suites, while the release preverification service still runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import func, select

from api.gpu_contracts import (
    GpuRegistrationNonceRequestV2,
    GpuRegistrationRequestV2,
)
from api.gpu_models import (
    GpuHotplugCommand,
    GpuRegistrationAttempt,
    GpuRegistrationNonce,
)
from api.gpu_registration_service import (
    get_gpu_registration_attempt,
    issue_gpu_registration_nonce,
    process_gpu_registration,
)
from api.host import gpu_allocations
from api.releases.schemas import GuestReleaseTarget
from api.server import service as server_service
from api.server.exceptions import AttestationSupersededError
from api.server.gpu_sessions import validate_gpu_runtime_session
from api.server.schemas import Server
from api.server.service import _publish_gpu_registration_generation
from cross_repo_tests import repository_root
from tests.integration import test_gpu_allocations_postgres as gpu_pg


postgres_schema = gpu_pg.postgres_schema
unsigned_debug_provenance = gpu_pg.unsigned_debug_provenance
nv_attest = gpu_pg.nv_attest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for the cross-repository GPU test",
    ),
]


@dataclass(frozen=True)
class _GuestIdentity:
    cert_path: str
    key_path: str
    cert_pem: str
    spki_sha256: str


def _new_guest_identity(tmp_path: Path, name: str) -> _GuestIdentity:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    private_key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_path = tmp_path / f"{name}.crt"
    key_path = tmp_path / f"{name}.key"
    cert_path.write_bytes(certificate_bytes)
    key_path.write_bytes(private_key_bytes)
    spki_bytes = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _GuestIdentity(
        cert_path=str(cert_path),
        key_path=str(key_path),
        cert_pem=certificate_bytes.decode("ascii"),
        spki_sha256=hashlib.sha256(spki_bytes).hexdigest(),
    )


def _load_agent_modules(monkeypatch):
    sek8s = repository_root("sek8s", start=Path(__file__))
    for source in (
        sek8s / "src/chutes-agent",
        sek8s / "src/sek8s",
        sek8s / "src/sek8s-common",
    ):
        monkeypatch.syspath_prepend(str(source))

    # GPU registration never constructs a substrate keypair.  The shared CPU
    # registration module imports the optional Model-A wallet dependency at
    # module load, so provide only that unused name in the API-only test env.
    try:
        __import__("substrateinterface")
    except ModuleNotFoundError:
        substrate = types.ModuleType("substrateinterface")
        substrate.Keypair = object
        monkeypatch.setitem(sys.modules, "substrateinterface", substrate)

    from chutes_agent import gpu_registration_v2, registration

    assert Path(gpu_registration_v2.__file__).resolve().is_relative_to(sek8s)
    assert Path(registration.__file__).resolve().is_relative_to(sek8s)
    return gpu_registration_v2, registration


def _selected_identifiers(response, selected_uuids: list[str]) -> list[str]:
    inventory = dict(
        zip(
            response.claims.gpu_uuids,
            response.claims.gpu_identifiers,
            strict=True,
        )
    )
    return [inventory[gpu_uuid] for gpu_uuid in selected_uuids]


def _agent_config(
    tmp_path: Path,
    response,
    selected_uuids: list[str],
    identity: _GuestIdentity,
) -> SimpleNamespace:
    return SimpleNamespace(
        api_url="https://validator.example",
        cert_path=identity.cert_path,
        key_path=identity.key_path,
        send_client_cert_header=False,
        gpu_registration_attempt_path=str(tmp_path / "registration-attempt.json"),
        gpu_reservation_claims=response.claims.model_dump(mode="json", exclude_none=True),
        reservation_sha256=response.claims_sha256,
        assigned_gpu_uuids=list(selected_uuids),
        assigned_gpu_identifiers=_selected_identifiers(response, selected_uuids),
        launch_reservation=response.token,
        release_target_sha256=response.claims.release_target_sha256,
        launch_nonce=response.claims.launch_nonce,
        external_host=None,
        external_ports=None,
        tee_endpoints=None,
    )


async def _prepare_launching_reservation(sessions):
    await gpu_pg._seed(sessions)
    async with sessions() as db:
        (
            response,
            request,
            _certificate,
            _spki,
        ) = await gpu_pg._prepare_registration_request(db, "miner")
        synthetic_nonce = await db.get(GpuRegistrationNonce, request.nonce_id)
        assert synthetic_nonce is not None
        await db.delete(synthetic_nonce)
        await db.commit()
    return response, list(request.gpu_uuids)


def _measurement(response) -> SimpleNamespace:
    claims = response.claims
    return SimpleNamespace(
        version=claims.image_version,
        name=claims.measurement_name,
        compute_type="gpu",
        role="gpu",
        gpu_profile_id=claims.gpu_profile_id,
        management_mode=claims.management_mode,
        gpu_profile_contract_sha256=claims.profile_contract_sha256,
        image_sha256=claims.image_sha256,
        gpu_count=len(claims.gpu_uuids),
        expected_gpus=sorted(set(claims.gpu_identifiers)),
        config_fingerprint="a" * 64,
        trust_set_fingerprint="b" * 64,
    )


def _canonical_sha256(document: dict) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class _ServiceHttpAdapter:
    """Dispatch the real sek8s client's requests into API service methods."""

    def __init__(self, sessions, identities: list[_GuestIdentity]):
        self.sessions = sessions
        self.identities = {identity.cert_path: identity for identity in identities}
        self.calls: list[dict] = []
        self.drop_completed_generation_one = False
        self.lost_completed_response: dict | None = None

    def client_type(self):
        adapter = self

        class Client:
            def __init__(self, *, cert, **_kwargs):
                self.identity = adapter.identities[cert[0]]

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def post(self, path, json, headers):
                assert headers == {}
                return await adapter.dispatch("POST", path, self.identity, json)

            async def get(self, path, headers):
                assert headers == {}
                return await adapter.dispatch("GET", path, self.identity, None)

        return Client

    @staticmethod
    def _response(method: str, path: str, status_code: int, document: dict):
        request = httpx.Request(method, f"https://validator.example{path}")
        return httpx.Response(
            status_code,
            json=document,
            request=request,
        )

    async def dispatch(
        self,
        method: str,
        path: str,
        identity: _GuestIdentity,
        document: dict | None,
    ) -> httpx.Response:
        call = {
            "method": method,
            "path": path,
            "spki": identity.spki_sha256,
            "request_generation": (
                document.get("request_generation") if document is not None else None
            ),
            "registration_generation": None,
            "request_sha256": (_canonical_sha256(document) if document is not None else None),
        }
        self.calls.append(call)
        async with self.sessions() as db:
            try:
                if method == "POST" and path in {
                    "/servers/gpu/registration/nonces",
                    "/servers/gpu/registration/rekey/nonces",
                }:
                    body = GpuRegistrationNonceRequestV2.model_validate(document)
                    result = await issue_gpu_registration_nonce(
                        db,
                        "192.0.2.31",
                        body,
                        identity.spki_sha256,
                        rekey=path.endswith("/rekey/nonces"),
                    )
                    nonce = await db.get(GpuRegistrationNonce, result.nonce_id)
                    call["registration_generation"] = nonce.registration_generation
                    await db.commit()
                    return self._response(
                        method,
                        path,
                        200,
                        result.model_dump(mode="json", exclude_none=True),
                    )

                if method == "POST" and path == "/servers/gpu/registration/attempts":
                    body = GpuRegistrationRequestV2.model_validate(document)
                    nonce = await db.get(GpuRegistrationNonce, body.nonce_id)
                    assert nonce is not None
                    call["request_generation"] = nonce.request_generation
                    call["registration_generation"] = nonce.registration_generation
                    result, status_code = await process_gpu_registration(
                        db,
                        "192.0.2.31",
                        body,
                        identity.spki_sha256,
                        identity.cert_pem,
                    )
                    response_document = result.model_dump(mode="json", exclude_none=True)
                    if (
                        self.drop_completed_generation_one
                        and call["registration_generation"] == 1
                        and response_document["state"] == "completed"
                    ):
                        self.drop_completed_generation_one = False
                        self.lost_completed_response = response_document
                        raise httpx.ReadError(
                            "simulated response loss after durable API completion",
                            request=httpx.Request(method, f"https://validator.example{path}"),
                        )
                    return self._response(
                        method,
                        path,
                        status_code,
                        response_document,
                    )

                if method == "GET" and path.startswith("/servers/gpu/registration/attempts/"):
                    attempt_id = path.rsplit("/", 1)[1]
                    attempt = await db.get(GpuRegistrationAttempt, attempt_id)
                    if attempt is not None:
                        nonce = await db.get(GpuRegistrationNonce, attempt.nonce_id)
                        call["request_generation"] = nonce.request_generation
                        call["registration_generation"] = attempt.registration_generation
                    result = await get_gpu_registration_attempt(
                        db,
                        attempt_id,
                        identity.spki_sha256,
                    )
                    status_code = 202 if result.state == "processing" else 200
                    return self._response(
                        method,
                        path,
                        status_code,
                        result.model_dump(mode="json", exclude_none=True),
                    )
                raise AssertionError(f"unexpected client request: {method} {path}")
            except HTTPException as exc:
                await db.rollback()
                return self._response(
                    method,
                    path,
                    exc.status_code,
                    {"detail": exc.detail},
                )


def _install_externality_fixtures(
    monkeypatch,
    gpu_registration_v2,
    registration,
    adapter: _ServiceHttpAdapter,
    selected_uuids: list[str],
) -> None:
    class QuoteProvider:
        async def get_quote(self, nonce, *, cert_path):
            assert len(nonce) == 64
            assert cert_path in adapter.identities
            return b"deterministic-cross-repository-tdx-quote"

    async def gpu_evidence(_server_id, nonce, gpu_uuids):
        assert len(nonce) == 64
        assert gpu_uuids == selected_uuids
        return [{"device": gpu_uuid} for gpu_uuid in gpu_uuids]

    monkeypatch.setattr(
        gpu_registration_v2.httpx,
        "AsyncClient",
        adapter.client_type(),
    )
    monkeypatch.setattr(
        gpu_registration_v2,
        "get_quote_provider",
        lambda tee_type: QuoteProvider() if tee_type == "tdx" else None,
    )
    monkeypatch.setattr(registration, "_build_verify", lambda _config: True)
    monkeypatch.setattr(registration, "_actual_gpu_uuids", lambda: selected_uuids)
    monkeypatch.setattr(registration, "_gpu_evidence", gpu_evidence)


async def _published_identity(sessions, response):
    async with sessions() as db:
        server = await db.get(Server, response.claims.server_id)
        assert server is not None
        return (
            server.created_at,
            await gpu_pg._registration_node_identity(db, server.server_id),
        )


async def _assert_generation_two_authority(
    sessions,
    response,
    *,
    expected_identity: _GuestIdentity,
    baseline_server_created_at,
    baseline_nodes,
    old_runtime_session: str,
    completed: dict,
) -> None:
    async with sessions() as db:
        reservation = await db.get(
            gpu_allocations.GpuLaunchReservation,
            response.claims.reservation_id,
        )
        server = await db.get(Server, response.claims.server_id)
        target = (
            await db.execute(
                select(GuestReleaseTarget).where(
                    GuestReleaseTarget.release_id == reservation.gpu_release_id,
                    GuestReleaseTarget.host_id == reservation.host_id,
                    GuestReleaseTarget.miner_hotkey == response.claims.owner_hotkey,
                    GuestReleaseTarget.tee_type == response.claims.tee_type,
                    GuestReleaseTarget.compute_type == "gpu",
                    GuestReleaseTarget.role == "gpu",
                )
            )
        ).scalar_one()
        attempts = list(
            (
                await db.execute(
                    select(GpuRegistrationAttempt).order_by(
                        GpuRegistrationAttempt.registration_generation
                    )
                )
            )
            .scalars()
            .all()
        )
        assert reservation.registration_generation == 2
        assert reservation.registration_attestation_id == completed["attestation_id"]
        assert server is not None
        assert server.created_at == baseline_server_created_at
        assert server.attested_cert_pubkey_hash == expected_identity.spki_sha256
        assert server.attested_cert == expected_identity.cert_pem
        assert await gpu_pg._registration_node_identity(db, server.server_id) == baseline_nodes
        assert target.consumed_at is not None
        assert target.consumed_server_id == server.server_id
        assert target.consumed_attestation_id == completed["attestation_id"]
        assert target.consumed_attestation_id == reservation.registration_attestation_id
        assert target.consumed_cert_pubkey_hash == expected_identity.spki_sha256
        assert target.consumed_measurement_name == completed["measurement_name"]
        assert target.consumed_measurement_version == completed["measurement_version"]
        assert (
            target.consumed_measurement_config_fingerprint
            == completed["measurement_config_fingerprint"]
        )
        assert target.consumed_trust_set_fingerprint == completed["trust_set_fingerprint"]
        assert [attempt.registration_generation for attempt in attempts] == [1, 2]
        assert [attempt.state for attempt in attempts] == ["completed", "completed"]
        assert await db.scalar(select(func.count(GpuHotplugCommand.command_id))) == 0
        with pytest.raises(AttestationSupersededError, match="generation changed"):
            _publish_gpu_registration_generation(
                reservation,
                2,
                "stale-cross-repository-publisher",
            )
        await db.rollback()

    async with sessions() as db:
        with pytest.raises(HTTPException) as old_session:
            await validate_gpu_runtime_session(
                db,
                old_runtime_session,
                required_purpose="miner",
            )
        assert old_session.value.status_code == 401
        await db.rollback()
        server, payload = await validate_gpu_runtime_session(
            db,
            completed["runtime_session"],
            required_purpose="miner",
        )
        assert server.server_id == response.claims.server_id
        assert payload["attestation_id"] == completed["attestation_id"]


def _call_projection(adapter: _ServiceHttpAdapter):
    return [
        (
            call["method"],
            call["path"],
            call["request_generation"],
            call["registration_generation"],
            call["spki"],
        )
        for call in adapter.calls
    ]


async def test_actual_agent_reboots_with_new_spki_into_generation_two(
    postgres_schema,
    tmp_path,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    response, selected_uuids = await _prepare_launching_reservation(sessions)
    old_identity = _new_guest_identity(tmp_path, "gpu-old-boot")
    new_identity = _new_guest_identity(tmp_path, "gpu-new-boot")
    unrelated_identity = _new_guest_identity(tmp_path, "gpu-unrelated")
    gpu_registration_v2, registration = _load_agent_modules(monkeypatch)
    adapter = _ServiceHttpAdapter(
        sessions,
        [old_identity, new_identity, unrelated_identity],
    )
    _install_externality_fixtures(
        monkeypatch,
        gpu_registration_v2,
        registration,
        adapter,
        selected_uuids,
    )
    quote_verifier = AsyncMock(return_value=SimpleNamespace(revocation_status={}))
    gpu_evidence_verifier = AsyncMock(return_value=gpu_pg._verified_gpu_subset(1, 2))

    old_config = _agent_config(tmp_path, response, selected_uuids, old_identity)
    with (
        patch.object(
            server_service,
            "build_runtime_quote",
            return_value=SimpleNamespace(),
        ),
        patch.object(server_service, "verify_quote", quote_verifier),
        patch.object(
            server_service,
            "get_matching_measurement_config",
            return_value=_measurement(response),
        ),
        patch.object(
            server_service,
            "verify_gpu_evidence",
            gpu_evidence_verifier,
        ),
        patch.object(
            server_service,
            "_verify_td_registration_signature",
            wraps=server_service._verify_td_registration_signature,
        ) as signature_consumer,
    ):
        generation_one = await gpu_registration_v2.register_gpu_v2(
            old_config,
            response.claims.server_id,
        )
        assert generation_one["state"] == "completed"
        assert old_config.launch_reservation is None
        baseline_created_at, baseline_nodes = await _published_identity(sessions, response)

        # The registrar clears response-loss state only after persisting the
        # completed response.  A reboot then recreates AgentConfig from the
        # immutable launch input while /run is empty and the serving SPKI is new.
        gpu_registration_v2.clear_client_state(old_config)
        assert not Path(old_config.gpu_registration_attempt_path).exists()
        new_config = _agent_config(tmp_path, response, selected_uuids, new_identity)
        generation_two = await gpu_registration_v2.register_gpu_v2(
            new_config,
            response.claims.server_id,
        )

    assert generation_two["state"] == "completed"
    assert new_config.launch_reservation is None
    assert signature_consumer.call_count == 2
    assert quote_verifier.await_count == 2
    assert gpu_evidence_verifier.await_count == 2
    assert _call_projection(adapter) == [
        (
            "POST",
            "/servers/gpu/registration/nonces",
            1,
            1,
            old_identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/attempts",
            1,
            1,
            old_identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/nonces",
            1,
            None,
            new_identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/rekey/nonces",
            1,
            2,
            new_identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/attempts",
            1,
            2,
            new_identity.spki_sha256,
        ),
    ]
    await _assert_generation_two_authority(
        sessions,
        response,
        expected_identity=new_identity,
        baseline_server_created_at=baseline_created_at,
        baseline_nodes=baseline_nodes,
        old_runtime_session=generation_one["runtime_session"],
        completed=generation_two,
    )

    current_replay = await adapter.dispatch(
        "GET",
        generation_two["status_url"],
        new_identity,
        None,
    )
    assert current_replay.status_code == 200
    stale_replay = await adapter.dispatch(
        "GET",
        generation_two["status_url"],
        old_identity,
        None,
    )
    assert stale_replay.status_code == 404
    unrelated_replay = await adapter.dispatch(
        "GET",
        generation_two["status_url"],
        unrelated_identity,
        None,
    )
    assert unrelated_replay.status_code == 404


async def test_actual_agent_recovers_expired_same_spki_response_loss_by_rekeying(
    postgres_schema,
    tmp_path,
    monkeypatch,
):
    sessions, _schema = postgres_schema
    response, selected_uuids = await _prepare_launching_reservation(sessions)
    identity = _new_guest_identity(tmp_path, "gpu-response-loss")
    unrelated_identity = _new_guest_identity(tmp_path, "gpu-unrelated")
    gpu_registration_v2, registration = _load_agent_modules(monkeypatch)
    adapter = _ServiceHttpAdapter(sessions, [identity, unrelated_identity])
    adapter.drop_completed_generation_one = True
    _install_externality_fixtures(
        monkeypatch,
        gpu_registration_v2,
        registration,
        adapter,
        selected_uuids,
    )
    quote_verifier = AsyncMock(return_value=SimpleNamespace(revocation_status={}))
    gpu_evidence_verifier = AsyncMock(return_value=gpu_pg._verified_gpu_subset(1, 2))
    config = _agent_config(tmp_path, response, selected_uuids, identity)

    with (
        patch.object(
            server_service,
            "build_runtime_quote",
            return_value=SimpleNamespace(),
        ),
        patch.object(server_service, "verify_quote", quote_verifier),
        patch.object(
            server_service,
            "get_matching_measurement_config",
            return_value=_measurement(response),
        ),
        patch.object(
            server_service,
            "verify_gpu_evidence",
            gpu_evidence_verifier,
        ),
        patch.object(
            server_service,
            "_verify_td_registration_signature",
            wraps=server_service._verify_td_registration_signature,
        ) as signature_consumer,
    ):
        with pytest.raises(httpx.ReadError, match="response loss"):
            await gpu_registration_v2.register_gpu_v2(
                config,
                response.claims.server_id,
            )
        assert adapter.lost_completed_response is not None
        generation_one = adapter.lost_completed_response
        assert config.launch_reservation == response.token
        persisted = json.loads(
            Path(config.gpu_registration_attempt_path).read_text(encoding="ascii")
        )
        assert persisted["stage"] == "request_ready"
        assert persisted["operation"] == "initial"
        assert persisted["request_generation"] == 1
        assert persisted["request"] is not None
        baseline_created_at, baseline_nodes = await _published_identity(sessions, response)

        replay_until = datetime.fromisoformat(
            generation_one["registration_replay_until"].replace("Z", "+00:00")
        )
        with patch(
            "api.gpu_registration_service._now",
            return_value=replay_until + timedelta(seconds=1),
        ):
            generation_two = await gpu_registration_v2.register_gpu_v2(
                config,
                response.claims.server_id,
            )

    assert generation_two["state"] == "completed"
    assert config.launch_reservation is None
    assert signature_consumer.call_count == 2
    assert quote_verifier.await_count == 2
    assert gpu_evidence_verifier.await_count == 2
    projection = _call_projection(adapter)
    assert projection == [
        (
            "POST",
            "/servers/gpu/registration/nonces",
            1,
            1,
            identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/attempts",
            1,
            1,
            identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/attempts",
            1,
            1,
            identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/nonces",
            2,
            None,
            identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/rekey/nonces",
            2,
            2,
            identity.spki_sha256,
        ),
        (
            "POST",
            "/servers/gpu/registration/attempts",
            2,
            2,
            identity.spki_sha256,
        ),
    ]
    assert adapter.calls[1]["request_sha256"] == adapter.calls[2]["request_sha256"]
    await _assert_generation_two_authority(
        sessions,
        response,
        expected_identity=identity,
        baseline_server_created_at=baseline_created_at,
        baseline_nodes=baseline_nodes,
        old_runtime_session=generation_one["runtime_session"],
        completed=generation_two,
    )

    current_replay = await adapter.dispatch(
        "GET",
        generation_two["status_url"],
        identity,
        None,
    )
    assert current_replay.status_code == 200
    unrelated_replay = await adapter.dispatch(
        "GET",
        generation_two["status_url"],
        unrelated_identity,
        None,
    )
    assert unrelated_replay.status_code == 404
    gpu_registration_v2.clear_client_state(config)
