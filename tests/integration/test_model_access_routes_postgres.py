"""Real-route launch-bound model access tests against PostgreSQL."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import multiprocessing
import os
import shutil
import ssl
import subprocess
import sys
import types
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
import pytest_asyncio
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from api.chute.schemas import Chute
from api.config import (
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.database import get_db_session
from api.image.schemas import Image
from api.instance.schemas import Instance, LaunchConfig
from api.instance.locking import lock_launch_configs_before_instances
from api.instance.util import create_launch_jwt_v2
from api.job.schemas import Job
from api.server.schemas import (
    DefaultChuteFSVolumeBinding,
    Server,
    ServerAttestation,
    StorageVolume,
    StorageVolumeKey,
)
from api.server.util import get_public_key_hash
from api.storage import service as storage_service
from api.storage.router import router as storage_router
from tests.integration import test_storage_reconciliation_postgres as api_pg

pytest_plugins = ["tests.integration.test_storage_reconciliation_postgres"]

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for real-route model access tests",
    ),
]

COMMIT = "a" * 40
REPO_ID = "org/model"
REQUEST_ID = "00000000-0000-0000-0000-000000000010"


@pytest.fixture(autouse=True)
def nv_attest():
    """These storage route tests never invoke the external GPU attestation CLI."""
    yield


@pytest.fixture(autouse=True)
def launch_signing_keys(monkeypatch):
    """Exercise the production ES256 sign/verify path with an ephemeral test key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setattr(settings, "launch_config_private_key_bytes", private_pem)


@pytest_asyncio.fixture
async def real_capability_redis(pg_session, tmp_path, monkeypatch):
    """Use Redis' real atomic GETDEL for capability issue/consume route coverage."""
    from redis.asyncio import Redis
    from redis.exceptions import ConnectionError as RedisConnectionError

    configured_url = os.getenv("TEST_REDIS_URL")
    if configured_url:
        client = Redis.from_url(configured_url, decode_responses=False)
        try:
            await client.ping()
            await client.flushdb()
            monkeypatch.setattr(settings, "_redis_client", client)
            yield client
        finally:
            await client.flushdb()
            await client.aclose()
        return

    executable = shutil.which("redis-server")
    if executable is None:
        pytest.skip("redis-server is required for atomic capability integration coverage")
    socket_path = tmp_path / "capabilities.redis.sock"
    process = subprocess.Popen(
        [
            executable,
            "--port",
            "0",
            "--unixsocket",
            str(socket_path),
            "--unixsocketperm",
            "700",
            "--save",
            "",
            "--appendonly",
            "no",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = Redis(unix_socket_path=str(socket_path), decode_responses=False)
    try:
        for _ in range(100):
            try:
                if await client.ping():
                    break
            except (RedisConnectionError, OSError):
                await asyncio.sleep(0.01)
        else:
            pytest.fail("local redis-server did not start")
        monkeypatch.setattr(settings, "_redis_client", client)
        yield client
    finally:
        await client.aclose()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _cert_headers(identity, verify: str | None) -> dict[str, str]:
    pem = identity[1].public_bytes(serialization.Encoding.PEM).decode()
    headers = {"X-Client-Cert": quote(pem, safe="")}
    if verify is not None:
        headers["X-Client-Verify"] = verify
    return headers


def _route_app(bind, *, include_misc: bool = False) -> FastAPI:
    app = FastAPI()
    app.include_router(storage_router, prefix="/storage")
    if include_misc:
        from api.misc.router import router as misc_router

        app.include_router(misc_router, prefix="/misc")
    factory = sessionmaker(bind, class_=AsyncSession, expire_on_commit=False)

    async def _database():
        async with factory() as db:
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    app.dependency_overrides[get_db_session] = _database
    return app


async def _seed_launch(
    db: AsyncSession,
    redis,
    *,
    env_type: str,
    requester_identity=None,
    requested_revision: str = COMMIT,
    job_id: str | None = None,
):
    suffix = uuid.uuid4().hex
    image_id = f"image-{suffix}"
    chute_id = f"chute-{suffix}"
    config_id = f"config-{suffix}"
    instance_id = f"instance-{suffix}"
    await db.execute(
        Image.__table__.insert().values(
            image_id=image_id,
            user_id=api_pg.USER_ID,
            name=f"route-image-{suffix}",
            tag="latest",
            status="built and pushed",
            public=False,
            compute_type="cpu" if env_type == "tee" else "gpu",
        )
    )
    code = (
        "from chutes.chute.template.vllm import build_vllm_chute\n"
        "chute = build_vllm_chute("
        f"model_name={REPO_ID!r}, revision={requested_revision!r})\n"
    )
    await db.execute(
        Chute.__table__.insert().values(
            chute_id=chute_id,
            user_id=api_pg.USER_ID,
            name=f"route-model-{suffix}",
            tagline="",
            readme="",
            image_id=image_id,
            public=False,
            standard_template="vllm",
            cords=[],
            node_selector={"compute_type": "cpu" if env_type == "tee" else "gpu"},
            code=code,
            filename="app.py",
            ref_str="app:chute",
            version="1",
            revision=requested_revision,
            tee=env_type == "tee",
        )
    )

    requester = None
    if requester_identity is not None:
        cert_pem = requester_identity[1].public_bytes(serialization.Encoding.PEM).decode()
        measurement = next(
            config
            for config in settings.tee_measurements
            if config.provider == "bare-metal"
            and config.tee_type == "sev-snp"
            and not (config.name or "").startswith("storage-")
            and config.gpu_count == 0
            and not list(config.expected_gpus or [])
        )
        config_fingerprint = measurement.config_fingerprint or measurement_config_fingerprint(
            measurement
        )
        trust_set_fingerprint = measurement_trust_set_fingerprint(settings.tee_measurements)
        verified_at = datetime.now(timezone.utc)
        requester = Server(
            server_id=f"requester-{suffix}",
            ip="127.0.0.10",
            miner_hotkey=api_pg.MINER,
            name=f"requester-{suffix}",
            netuid=api_pg.settings.netuid,
            is_tee=True,
            self_registered=True,
            compute_type="cpu",
            tee_type="sev-snp",
            host_id=None,
            storage_role=False,
            attested_cert=cert_pem,
            attested_cert_pubkey_hash=get_public_key_hash(requester_identity[1]),
            version=measurement.version,
            measurement_name=measurement.name,
            measurement_config_fingerprint=config_fingerprint,
            trust_set_fingerprint=trust_set_fingerprint,
        )
        db.add(requester)
        await db.flush()
        db.add(
            ServerAttestation(
                server_id=requester.server_id,
                quote_data="current-cpu-model-requester-attestation",
                measurement_version=measurement.version,
                measurement_name=measurement.name,
                measurement_config_fingerprint=config_fingerprint,
                trust_set_fingerprint=trust_set_fingerprint,
                created_at=verified_at,
                verified_at=verified_at,
            )
        )

    default_volume = StorageVolume(
        user_id=api_pg.USER_ID,
        name=f"default-{suffix}",
        replication_factor=3,
        quota_bytes=1024**3,
        used_bytes=0,
    )
    db.add(default_volume)
    await db.flush()
    db.add_all(
        [
            StorageVolumeKey(
                volume_id=default_volume.volume_id,
                encrypted_key="test-only-model-access-key",
            ),
            DefaultChuteFSVolumeBinding(
                user_id=api_pg.USER_ID,
                chute_id=chute_id,
                volume_id=default_volume.volume_id,
            ),
        ]
    )
    await db.flush()
    job = None
    if job_id is not None:
        job = Job(
            job_id=job_id,
            user_id=api_pg.USER_ID,
            chute_id=chute_id,
            version="1",
            method="run",
            instance_id=None,
            active=True,
            verified=True,
            job_args={},
            status="running",
            miner_history=[],
            compute_multiplier=1.0,
        )
        db.add(job)
        # LaunchConfig.job_id is immutable storage identity, so the job must exist before
        # the launch is created and the relationship must be bound on the initial INSERT.
        await db.flush()
    launch = LaunchConfig(
        config_id=config_id,
        seed=1,
        env_key=f"env-{suffix}",
        chute_id=chute_id,
        user_id=api_pg.USER_ID,
        compute_type="cpu" if env_type == "tee" else "gpu",
        default_volume_id=default_volume.volume_id,
        storage_session_exchange_allowed=False,
        job_id=job_id,
        host="127.0.0.20",
        port=8000,
        env_type=env_type,
        miner_uid=1,
        miner_hotkey=api_pg.MINER,
        miner_coldkey="coldkey",
        server_id=requester.server_id if requester else None,
        verified_at=datetime.now(),
    )
    instance = Instance(
        instance_id=instance_id,
        host=f"127.0.1.{int(suffix[:2], 16) % 200 + 1}",
        port=10000 + int(suffix[:4], 16) % 40000,
        chute_id=chute_id,
        version="1",
        miner_uid=1,
        miner_hotkey=api_pg.MINER,
        miner_coldkey="coldkey",
        active=True,
        verified=True,
        config_id=config_id,
        deployment_id=f"deployment-{suffix}",
        server_id=requester.server_id if requester else None,
    )
    db.add_all([launch, instance])
    await db.flush()
    if job is not None:
        job.instance_id = instance_id
    target_identity = api_pg._attested_identity(f"target-{suffix}")
    target = await api_pg._server(
        db,
        redis,
        f"target-{suffix}",
        f"target-host-{suffix}",
        attested_identity=target_identity,
    )
    await db.commit()
    return launch, requester, requester_identity, target, target_identity


async def _consume(
    client: AsyncClient,
    issued: dict,
    target_identity,
):
    return await client.post(
        "/storage/model/capabilities/consume",
        headers=_cert_headers(
            target_identity,
            "FAILED:self-signed certificate",
        ),
        json={
            "capability": issued["capability"],
            "request_id": REQUEST_ID,
            "repo_id": REPO_ID,
            "revision": COMMIT,
            "requested_revision": COMMIT,
        },
    )


def _write_identity(tmp_path: Path, name: str, identity) -> tuple[Path, Path, str]:
    key_path = tmp_path / f"{name}.key"
    cert_path = tmp_path / f"{name}.crt"
    cert_pem = identity[1].public_bytes(serialization.Encoding.PEM).decode()
    key_path.write_bytes(
        identity[0].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_text(cert_pem)
    return cert_path, key_path, cert_pem


def _validator_tls_material(tmp_path: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-validator-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "validator-ca.crt"
    cert_path = tmp_path / "validator.crt"
    key_path = tmp_path / "validator.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def _tls_server_context(
    cert_path: Path,
    key_path: Path,
    *,
    trusted_clients: list[str],
    require_client: bool,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    if trusted_clients:
        context.load_verify_locations(cadata="\n".join(trusted_clients))
    context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_OPTIONAL
    return context


class _AsgiHttpsServer:
    """Local TLS terminator that overwrites proxy-owned client-cert headers after a real handshake.

    The deployed nginx ``optional_no_ca`` generation of ``FAILED:<reason>`` remains the only
    live-edge boundary; route coverage below separately sends that production verdict verbatim.
    """

    def __init__(self, runner, client, port: int, calls: dict[str, int]):
        self.runner = runner
        self.client = client
        self.port = port
        self.calls = calls

    @classmethod
    async def start(cls, app: FastAPI, ssl_context: ssl.SSLContext):
        internal = AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://asgi.internal",
        )
        calls: dict[str, int] = {}

        async def _forward(request: web.Request) -> web.Response:
            calls[request.path] = calls.get(request.path, 0) + 1
            body = await request.read()
            headers = {
                key: value
                for key, value in request.headers.items()
                if key.lower()
                not in {
                    "connection",
                    "content-length",
                    "host",
                    "transfer-encoding",
                    "x-client-cert",
                    "x-client-verify",
                }
            }
            ssl_object = request.transport.get_extra_info("ssl_object")
            peer_der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            if peer_der:
                mtls_key = f"mtls:{request.path}"
                calls[mtls_key] = calls.get(mtls_key, 0) + 1
                peer = x509.load_der_x509_certificate(peer_der)
                peer_pem = peer.public_bytes(serialization.Encoding.PEM).decode()
                headers["X-Client-Cert"] = quote(peer_pem, safe="")
                headers["X-Client-Verify"] = "SUCCESS"
            response = await internal.request(
                request.method,
                request.path_qs,
                content=body,
                headers=headers,
            )
            response_headers = {}
            if content_type := response.headers.get("content-type"):
                response_headers["Content-Type"] = content_type
            return web.Response(
                status=response.status_code,
                body=response.content,
                headers=response_headers,
            )

        gateway = web.Application()
        gateway.router.add_route("*", "/{path:.*}", _forward)
        runner = web.AppRunner(gateway)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return cls(runner, internal, port, calls)

    async def close(self) -> None:
        await self.runner.cleanup()
        await self.client.aclose()


async def test_model_access_route_verifies_real_launch_jwt_and_consumes_once(
    pg_session,
    real_capability_redis,
):
    db, _ = pg_session
    redis = real_capability_redis
    launch, _, _, target, target_identity = await _seed_launch(db, redis, env_type="graval")
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        forged_signature = ("A" if encoded_signature[0] != "A" else "B") + encoded_signature[1:]
        forged = ".".join((encoded_header, encoded_payload, forged_signature))
        rejected = await client.post(
            "/storage/model/access",
            headers={"Authorization": f"Bearer {forged}"},
            json={
                "request_id": REQUEST_ID,
                "repo_id": REPO_ID,
                "revision": COMMIT,
                "requested_revision": COMMIT,
            },
        )
        assert rejected.status_code == 401

        response = await client.post(
            "/storage/model/access",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "request_id": REQUEST_ID,
                "repo_id": REPO_ID,
                "revision": COMMIT,
                "requested_revision": COMMIT,
            },
        )
        assert response.status_code == 200, response.text
        issued = response.json()
        assert issued["peer"]["server_id"] == target.server_id
        assert issued["peer"]["attested_cert"]

        consumed = await _consume(client, issued, target_identity)
        assert consumed.status_code == 200, consumed.text
        binding = consumed.json()
        assert binding["requester_kind"] == "launch_instance"
        assert binding["requester_instance_id"].startswith("instance-")
        assert binding["target_server_id"] == target.server_id

        replay = await _consume(client, issued, target_identity)
        assert replay.status_code == 401


async def test_model_capability_revocation_race_after_locked_revalidation_fails_closed(
    pg_session,
    real_capability_redis,
    monkeypatch,
):
    db, _ = pg_session
    redis = real_capability_redis
    launch, _, _, _target, target_identity = await _seed_launch(
        db,
        redis,
        env_type="graval",
    )
    instance = await db.scalar(select(Instance).where(Instance.config_id == launch.config_id))
    assert instance is not None
    token = create_launch_jwt_v2(launch)
    factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)

    class RevokingRedis:
        def __getattr__(self, name):
            return getattr(redis, name)

        async def setex(self, key, ttl, value):
            # This runs at the exact durable-check -> Redis-publication boundary. It can acquire
            # lifecycle custody only if issuance released its transaction first.
            async with factory() as terminal:
                await lock_launch_configs_before_instances(
                    terminal,
                    config_ids=(launch.config_id,),
                    instance_ids=(instance.instance_id,),
                )
                await terminal.execute(
                    update(Instance)
                    .where(Instance.instance_id == instance.instance_id)
                    .values(verified=False)
                )
                await terminal.commit()
            return await redis.setex(key, ttl, value)

    monkeypatch.setattr(settings, "_redis_client", RevokingRedis())
    app = _route_app(db.bind)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        issued = await asyncio.wait_for(
            client.post(
                "/storage/model/access",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "request_id": REQUEST_ID,
                    "repo_id": REPO_ID,
                    "revision": COMMIT,
                    "requested_revision": COMMIT,
                },
            ),
            timeout=5,
        )
        assert issued.status_code == 200, issued.text
        rejected = await _consume(client, issued.json(), target_identity)
        assert rejected.status_code == 403
        assert "revoked or changed" in rejected.text


@pytest.mark.parametrize(
    "revocation",
    ("completed_config", "disabled_chute", "finished_job"),
)
async def test_model_capability_consume_rechecks_terminal_chute_and_job_authority(
    pg_session,
    real_capability_redis,
    revocation,
):
    db, _ = pg_session
    redis = real_capability_redis
    job_id = f"job-{uuid.uuid4().hex}" if revocation == "finished_job" else None
    launch, _, _, _target, target_identity = await _seed_launch(
        db,
        redis,
        env_type="graval",
        job_id=job_id,
    )
    instance = await db.scalar(select(Instance).where(Instance.config_id == launch.config_id))
    assert instance is not None
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        issued = await client.post(
            "/storage/model/access",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "request_id": REQUEST_ID,
                "repo_id": REPO_ID,
                "revision": COMMIT,
                "requested_revision": COMMIT,
            },
        )
        assert issued.status_code == 200, issued.text

        factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
        async with factory() as revoker:
            if revocation == "completed_config":
                await revoker.execute(
                    update(LaunchConfig)
                    .where(LaunchConfig.config_id == launch.config_id)
                    .values(completed_at=datetime.now(timezone.utc))
                )
            elif revocation == "disabled_chute":
                await revoker.execute(
                    update(Chute)
                    .where(Chute.chute_id == launch.chute_id)
                    .values(public=True, disabled=True)
                )
            else:
                await revoker.execute(
                    update(Job)
                    .where(Job.job_id == job_id)
                    .values(finished_at=datetime.now(), status="finished")
                )
            await revoker.commit()

        rejected = await _consume(client, issued.json(), target_identity)
        assert rejected.status_code == 403
        assert "revoked or changed" in rejected.text


async def test_model_capability_consume_rechecks_latest_target_attestation(
    pg_session,
    real_capability_redis,
):
    db, _ = pg_session
    redis = real_capability_redis
    launch, _, _, target, _ = await _seed_launch(
        db,
        redis,
        env_type="graval",
    )
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        issued = await client.post(
            "/storage/model/access",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "request_id": REQUEST_ID,
                "repo_id": REPO_ID,
                "revision": COMMIT,
                "requested_revision": COMMIT,
            },
        )
        assert issued.status_code == 200, issued.text
        assert await storage_service.is_freshly_attested_storage_server(db, target)

        factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
        async with factory() as revoker:
            revoker.add(
                ServerAttestation(
                    server_id=target.server_id,
                    quote_data="newer-failed-model-target-attestation",
                    verification_error="injected latest-attempt failure",
                )
            )
            await revoker.commit()

        with pytest.raises(HTTPException, match="target attestation") as rejected:
            await storage_service.consume_model_ensure_capability(
                db,
                target,
                issued.json()["capability"],
                REQUEST_ID,
                REPO_ID,
                COMMIT,
                COMMIT,
            )
        assert rejected.value.status_code == 403


async def test_cpu_launch_without_server_binding_cannot_use_bearer_model_access(
    pg_session,
    real_capability_redis,
):
    db, _ = pg_session
    redis = real_capability_redis
    launch, _, _, _, _ = await _seed_launch(db, redis, env_type="tee")
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        rejected = await client.post(
            "/storage/model/access",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "request_id": REQUEST_ID,
                "repo_id": REPO_ID,
                "revision": COMMIT,
                "requested_revision": COMMIT,
            },
        )
    assert rejected.status_code == 403
    assert "same non-null attested mTLS server" in rejected.text


async def test_model_capabilities_route_requires_live_cpu_mtls_and_consumes_once(
    pg_session,
    real_capability_redis,
):
    db, _ = pg_session
    redis = real_capability_redis
    requester_identity = api_pg._attested_identity("cpu-requester")
    launch, requester, _, target, target_identity = await _seed_launch(
        db,
        redis,
        env_type="tee",
        requester_identity=requester_identity,
    )
    assert requester.host_id is None
    assert requester.launch_reservation_id is None
    assert requester.launch_boot_generation is None
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)
    body = {
        "request_id": REQUEST_ID,
        "target_server_id": target.server_id,
        "repo_id": REPO_ID,
        "revision": COMMIT,
        "requested_revision": COMMIT,
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        header_only = await client.post(
            "/storage/model/capabilities",
            headers={
                "Authorization": f"Bearer {token}",
                **_cert_headers(requester_identity, None),
            },
            json=body,
        )
        assert header_only.status_code == 401

        response = await client.post(
            "/storage/model/capabilities",
            headers={
                "Authorization": f"Bearer {token}",
                **_cert_headers(
                    requester_identity,
                    "FAILED:self-signed certificate",
                ),
            },
            json=body,
        )
        assert response.status_code == 200, response.text
        issued = response.json()

        consumed = await _consume(client, issued, target_identity)
        assert consumed.status_code == 200, consumed.text
        binding = consumed.json()
        assert binding["requester_kind"] == "attested_server"
        assert binding["requester_server_id"] == requester.server_id
        assert binding["requester_cert_pubkey_hash"] == requester.attested_cert_pubkey_hash
        assert binding["target_server_id"] == target.server_id

        replay = await _consume(client, issued, target_identity)
        assert replay.status_code == 401


async def test_model_capability_consume_rechecks_latest_cpu_requester_attestation(
    pg_session,
    real_capability_redis,
):
    db, _ = pg_session
    redis = real_capability_redis
    requester_identity = api_pg._attested_identity("cpu-requester-revoked")
    launch, requester, _, target, target_identity = await _seed_launch(
        db,
        redis,
        env_type="tee",
        requester_identity=requester_identity,
    )
    token = create_launch_jwt_v2(launch)
    app = _route_app(db.bind)
    body = {
        "request_id": REQUEST_ID,
        "target_server_id": target.server_id,
        "repo_id": REPO_ID,
        "revision": COMMIT,
        "requested_revision": COMMIT,
    }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://validator.test",
    ) as client:
        issued = await client.post(
            "/storage/model/capabilities",
            headers={
                "Authorization": f"Bearer {token}",
                **_cert_headers(
                    requester_identity,
                    "FAILED:self-signed certificate",
                ),
            },
            json=body,
        )
        assert issued.status_code == 200, issued.text

        factory = sessionmaker(db.bind, class_=AsyncSession, expire_on_commit=False)
        async with factory() as revoker:
            revoker.add(
                ServerAttestation(
                    server_id=requester.server_id,
                    quote_data="newer-failed-cpu-model-requester-attestation",
                    verification_error="injected latest-attempt failure",
                )
            )
            await revoker.commit()

        rejected = await _consume(client, issued.json(), target_identity)
        assert rejected.status_code == 403
        assert "Latest attestation attempt is not current" in rejected.text


@pytest.mark.cross_repo
async def test_cpu_cold_start_crosses_real_routes_tls_storage_and_template(
    pg_session,
    real_capability_redis,
    tmp_path,
    monkeypatch,
):
    from cross_repo_tests import repository_root

    sdk_root = repository_root("sdk", start=Path(__file__))
    sek8s_worktree = repository_root("sek8s", start=Path(__file__))
    sek8s_root = sek8s_worktree / "src" / "sek8s"
    sek8s_common_root = sek8s_worktree / "src" / "sek8s-common"
    from prometheus_client import REGISTRY

    original_collector_to_names = dict(REGISTRY._collector_to_names)
    original_names_to_collectors = dict(REGISTRY._names_to_collectors)
    REGISTRY._collector_to_names.clear()
    REGISTRY._names_to_collectors.clear()
    original_sibling_modules = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "chutes"
        or name.startswith("chutes.")
        or name == "sek8s"
        or name.startswith("sek8s.")
    }
    for name in original_sibling_modules:
        sys.modules.pop(name, None)
    monkeypatch.syspath_prepend(str(sek8s_common_root))
    monkeypatch.syspath_prepend(str(sek8s_root))
    monkeypatch.syspath_prepend(str(sdk_root))

    import importlib.metadata

    metadata_version = importlib.metadata.version
    monkeypatch.setattr(
        importlib.metadata,
        "version",
        lambda distribution: (
            "0+source" if distribution == "sek8s-common" else metadata_version(distribution)
        ),
    )
    from api.chute import util as chute_util
    from api.misc import router as misc
    from api.user import service as user_service
    from chutes.chute import NodeSelector
    from chutes.chute.template import vllm
    from chutes.entrypoint import _shared
    from chutes.util import hf as sdk_hf
    from sek8s import integrity as storage_integrity
    from sek8s.storage_node.config import StorageNodeConfig
    from sek8s.storage_node.router import StorageNodeContext, build_app
    from sek8s.storage_node.store import ContentStore
    from sek8s.storage_node.tracker import StorageTracker

    db, _ = pg_session
    redis = real_capability_redis
    requester_identity = api_pg._attested_identity("cpu-cold-start")
    launch, requester, _, target, target_identity = await _seed_launch(
        db,
        redis,
        env_type="tee",
        requester_identity=requester_identity,
        requested_revision="main",
    )
    launch_token = create_launch_jwt_v2(launch)

    content = b'{"model_type":"cross-layer"}\n' * 90_000
    git_blob = hashlib.sha1(usedforsecurity=False)
    git_blob.update(f"blob {len(content)}\0".encode())
    git_blob.update(content)
    manifest = {
        "repo_id": REPO_ID,
        "repo_type": "model",
        "revision": COMMIT,
        "commit_hash": COMMIT,
        "files": [
            {
                "path": "config.json",
                "size": len(content),
                "blob_id": git_blob.hexdigest(),
                "is_lfs": False,
            }
        ],
        "directories": [],
    }
    # The only substituted boundary is the external HuggingFace/proxy lookup. Validator
    # authorization, route models, PostgreSQL bindings, Redis GETDEL, mTLS possession, storage
    # ensure/file handlers, SDK hashing, and template launch all execute their production code.
    hf_boundary_calls = {"resolve": 0, "manifest": 0}

    def _resolve_manifest(*_args, **_kwargs):
        hf_boundary_calls["resolve"] += 1
        return COMMIT

    def _fetch_manifest(*_args, **_kwargs):
        hf_boundary_calls["manifest"] += 1
        return manifest

    monkeypatch.setattr(misc, "_resolve_repo_revision_sync", _resolve_manifest)
    monkeypatch.setattr(misc, "_fetch_repo_manifest_sync", _fetch_manifest)

    session_factory = sessionmaker(
        db.bind,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    @asynccontextmanager
    async def _test_session(*_args, **_kwargs):
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    monkeypatch.setattr(chute_util, "get_session", _test_session)
    monkeypatch.setattr(misc, "get_session", _test_session)
    monkeypatch.setattr(user_service, "get_session", _test_session)
    monkeypatch.setattr(user_service.router, "_chutes_user_id", None, raising=False)
    chute_util._get_one.cache_clear()

    ca_path, validator_cert_path, validator_key_path = _validator_tls_material(tmp_path)
    requester_cert_path, requester_key_path, requester_pem = _write_identity(
        tmp_path,
        "requester",
        requester_identity,
    )
    target_cert_path, target_key_path, target_pem = _write_identity(
        tmp_path,
        "target",
        target_identity,
    )
    validator_tls = _tls_server_context(
        validator_cert_path,
        validator_key_path,
        trusted_clients=[requester_pem, target_pem],
        require_client=False,
    )
    validator = await _AsgiHttpsServer.start(
        _route_app(db.bind, include_misc=True),
        validator_tls,
    )
    storage = None

    try:
        validator_url = f"https://127.0.0.1:{validator.port}"
        storage_config = StorageNodeConfig(
            CHUTES_API_URL=validator_url,
            CHUTES_SERVER_ID=target.server_id,
            CHUTES_HOST_ID=target.host_id,
            CHUTES_MINER_SEED="1" * 64,
            CHUTES_API_CA=str(ca_path),
            TLS_CERT_PATH=str(target_cert_path),
            TLS_KEY_PATH=str(target_key_path),
            CHUTEFS_DATA_DIR=str(tmp_path / "storage-data"),
            CHUTEFS_MIN_FREE_DISK_GB=0,
            CHUTEFS_MODEL_CACHE_MAX_BYTES=1024**3,
            _env_file=None,
        )
        store = ContentStore(
            storage_config.data_dir,
            storage_config.models_dir,
            storage_config.objects_dir,
        )
        held_snapshot = store.snapshot_dir(REPO_ID, COMMIT)
        held_snapshot.mkdir(parents=True, exist_ok=True)
        (held_snapshot / "config.json").write_bytes(content)
        tracker = StorageTracker(
            storage_config,
            target.storage_incarnation,
        )
        storage_app = build_app(StorageNodeContext(storage_config, store, tracker))
        storage_tls = _tls_server_context(
            target_cert_path,
            target_key_path,
            trusted_clients=[requester_pem],
            require_client=True,
        )
        storage = await _AsgiHttpsServer.start(storage_app, storage_tls)
        target.external_host = "127.0.0.1"
        target.external_ports = {"storage": storage.port}
        await db.commit()

        monkeypatch.setenv("CHUTES_API_URL", validator_url)
        monkeypatch.setenv("CHUTES_LAUNCH_JWT", launch_token)
        monkeypatch.delenv("CHUTES_HOST_ID", raising=False)
        monkeypatch.setenv(
            "CHUTES_API_CA_B64",
            base64.b64encode(ca_path.read_bytes()).decode(),
        )
        monkeypatch.setenv(
            "CHUTES_TEE_TLS_CERT",
            base64.b64encode(requester_cert_path.read_bytes()).decode(),
        )
        monkeypatch.setenv(
            "CHUTES_TEE_TLS_KEY",
            base64.b64encode(requester_key_path.read_bytes()).decode(),
        )
        monkeypatch.delenv("CHUTES_NVIDIA_DEVICES", raising=False)
        monkeypatch.delenv("HF_TOKEN", raising=False)
        monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
        monkeypatch.setattr(
            sdk_hf,
            "PROXY_URL",
            f"{validator_url}/fixed-proxy-must-not-be-used",
        )
        _shared.get_launch_token.cache_clear()
        _shared.get_launch_token_data.cache_clear()
        _shared.is_tee_env.cache_clear()
        _shared.is_cpu_tee_env.cache_clear()
        sdk_hf._manifest_cache.clear()
        sdk_hf._ref_commit_cache.clear()
        storage_integrity._repo_info_cache.clear()
        storage_integrity._ref_commit_cache.clear()
        monkeypatch.setitem(
            sdk_hf.verified_model_download.__kwdefaults__,
            "cache_dir",
            str(tmp_path / "chute-cache"),
        )
        monkeypatch.setitem(
            sdk_hf.verified_model_download.__kwdefaults__,
            "attempts",
            1,
        )
        monkeypatch.setitem(
            sdk_hf.verified_model_download.__kwdefaults__,
            "retry_delay",
            0,
        )

        torch = types.ModuleType("torch")
        torch.cuda = types.SimpleNamespace(
            empty_cache=lambda: None,
            init=lambda: None,
            set_device=lambda _device: None,
            device_count=lambda: 1,
            get_device_name=lambda _device: "Test GPU",
        )
        monkeypatch.setitem(sys.modules, "torch", torch)
        monkeypatch.setattr(
            multiprocessing,
            "set_start_method",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(vllm, "set_default_cache_dirs", lambda *_args: None)
        monkeypatch.setattr(vllm, "set_nccl_flags", lambda *_args: None)
        monkeypatch.setattr(vllm, "mtls_enabled", lambda: False)
        captured: dict[str, list[str]] = {}

        class EngineLaunchCaptured(RuntimeError):
            pass

        def _capture_popen(command, **_kwargs):
            captured["command"] = command
            raise EngineLaunchCaptured

        monkeypatch.setattr(subprocess, "Popen", _capture_popen)
        pack = vllm.build_vllm_chute(
            username="integration",
            model_name=REPO_ID,
            node_selector=NodeSelector(),
            revision="main",
            engine_args="--dtype float16",
        )
        startup = pack.chute._startup_hooks[0][1]
        with pytest.raises(EngineLaunchCaptured):
            await startup()

        command = captured["command"]
        assert command.count("--model") == 1
        verified_path = Path(command[command.index("--model") + 1])
        assert verified_path.name == COMMIT
        assert (verified_path / "config.json").read_bytes() == content
        assert validator.calls.get("/fixed-proxy-must-not-be-used", 0) == 0
        assert validator.calls["/misc/hf_repo_info"] >= 1
        assert validator.calls.get("/storage/peers/local", 0) == 0
        assert validator.calls["/storage/peers/model-target"] == 1
        assert validator.calls["/storage/model/capabilities"] == 1
        assert validator.calls["/storage/model/capabilities/consume"] == 1
        assert validator.calls["mtls:/storage/model/capabilities"] == 1
        assert validator.calls["mtls:/storage/model/capabilities/consume"] == 1
        assert storage.calls["/storage/model/ensure"] == 1
        assert storage.calls["/storage/model/file"] == 1
        assert storage.calls["mtls:/storage/model/ensure"] == 1
        assert storage.calls["mtls:/storage/model/file"] == 1
        assert hf_boundary_calls == {"resolve": 1, "manifest": 1}
        assert not await redis.keys("storage:model_ensure_capability:*")
    finally:
        if storage is not None:
            await storage.close()
        await validator.close()
        _shared.get_launch_token.cache_clear()
        _shared.get_launch_token_data.cache_clear()
        _shared.is_tee_env.cache_clear()
        _shared.is_cpu_tee_env.cache_clear()
        chute_util._get_one.cache_clear()
        for name in tuple(sys.modules):
            if (
                name == "chutes"
                or name.startswith("chutes.")
                or name == "sek8s"
                or name.startswith("sek8s.")
            ):
                sys.modules.pop(name, None)
        sys.modules.update(original_sibling_modules)
        REGISTRY._collector_to_names.clear()
        REGISTRY._collector_to_names.update(original_collector_to_names)
        REGISTRY._names_to_collectors.clear()
        REGISTRY._names_to_collectors.update(original_names_to_collectors)
