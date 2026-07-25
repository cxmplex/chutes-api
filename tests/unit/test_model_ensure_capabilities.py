from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from api.storage import service
from api.storage.schemas import StoragePeer


COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
REQUESTED_REVISION = "main"


class FakeRedis:
    def __init__(self):
        self.values = {}

    async def setex(self, key, _ttl, value):
        self.values[key] = value

    async def getdel(self, key):
        return self.values.pop(key, None)


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def unique(self):
        return self


def _server(server_id: str, cert_hash: str, *, storage: bool):
    return SimpleNamespace(
        server_id=server_id,
        attested_cert_pubkey_hash=cert_hash,
        attested_cert="certificate",
        storage_role=storage,
        storage_incarnation="00000000-0000-0000-0000-000000000001" if storage else None,
    )


async def _issue(redis: FakeRedis):
    requester = {
        "requester_kind": "launch_instance",
        "requester_server_id": None,
        "requester_cert_pubkey_hash": None,
        "requester_instance_id": "instance",
        "requester_config_id": "config",
        "requester_chute_id": "chute",
        "requester_deployment_id": "deployment",
    }
    target = _server("target", "2" * 64, storage=True)
    db = AsyncMock()
    db.get.return_value = target
    with patch.object(service.settings, "_redis_client", redis):
        issued = await service.issue_model_ensure_capability(
            db,
            requester,
            "00000000-0000-0000-0000-000000000010",
            target.server_id,
            "org/model",
            COMMIT,
            REQUESTED_REVISION,
        )
    return issued, target


@pytest.mark.asyncio
async def test_model_capability_is_one_use_and_exactly_bound():
    redis = FakeRedis()
    issued, target = await _issue(redis)
    with patch.object(service.settings, "_redis_client", redis):
        binding = await service.consume_model_ensure_capability(
            target,
            issued["capability"],
            "00000000-0000-0000-0000-000000000010",
            "org/model",
            COMMIT,
            REQUESTED_REVISION,
        )
        assert binding["requester_instance_id"] == "instance"
        assert binding["requester_chute_id"] == "chute"
        assert binding["target_server_id"] == "target"
        assert binding["repo_id"] == "org/model"
        assert binding["revision"] == COMMIT
        assert binding["requested_revision"] == REQUESTED_REVISION

        with pytest.raises(HTTPException) as replay:
            await service.consume_model_ensure_capability(
                target,
                issued["capability"],
                "00000000-0000-0000-0000-000000000010",
                "org/model",
                COMMIT,
                REQUESTED_REVISION,
            )
    assert replay.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mismatch", ["target", "repo", "revision", "requested_revision", "request"]
)
async def test_model_capability_rejects_every_wrong_binding(mismatch):
    redis = FakeRedis()
    issued, target = await _issue(redis)
    request_id = "00000000-0000-0000-0000-000000000010"
    repo_id = "org/model"
    revision = COMMIT
    requested_revision = REQUESTED_REVISION
    if mismatch == "target":
        target = _server("other-target", "3" * 64, storage=True)
    elif mismatch == "repo":
        repo_id = "org/other"
    elif mismatch == "revision":
        revision = OTHER_COMMIT
    elif mismatch == "requested_revision":
        requested_revision = "release/v2"
    else:
        request_id = "00000000-0000-0000-0000-000000000011"

    with patch.object(service.settings, "_redis_client", redis):
        with pytest.raises(HTTPException) as rejected:
            await service.consume_model_ensure_capability(
                target,
                issued["capability"],
                request_id,
                repo_id,
                revision,
                requested_revision,
            )
    assert rejected.value.status_code == 403


def _launch_identity_db(*, server_id=None):
    launch_config = SimpleNamespace(
        config_id="config",
        user_id="user",
        chute_id="chute",
        job_id=None,
        compute_type="gpu" if server_id is None else "cpu",
        default_volume_id="volume",
        storage_session_exchange_allowed=False,
        gpu_management_mode=None,
        server_id=server_id,
        env_type="graval" if server_id is None else "tee",
        retrieved_at=object(),
        failed_at=None,
        verified_at=object(),
    )
    instance = SimpleNamespace(
        instance_id="instance",
        config_id="config",
        chute_id="chute",
        verified=True,
        server_id=server_id,
        deployment_id="deployment",
    )
    chute = SimpleNamespace(
        chute_id="chute",
        revision=COMMIT,
        code=(
            "from chutes.chute.template.vllm import build_vllm_chute\n"
            "chute = build_vllm_chute(model_name='org/model', revision='" + COMMIT + "')\n"
        ),
    )
    db = AsyncMock()
    db.execute.side_effect = [
        ScalarResult(None),
        ScalarResult(launch_config),
        ScalarResult(instance),
        ScalarResult(chute),
    ]
    return db


def _launch_payload(*, server_id=None):
    compute_type = "gpu" if server_id is None else "cpu"
    return {
        "sub": "config",
        "user_id": "user",
        "chute_id": "chute",
        "job_id": None,
        "compute_type": compute_type,
        "management_mode": "miner" if compute_type == "gpu" else "platform",
        "server_id": server_id,
        "instance_id": None,
        "default_volume_id": "volume",
        "env_type": "graval" if server_id is None else "tee",
        "storage_session_exchange_allowed": False,
        "permissions": [],
    }


@pytest.mark.asyncio
async def test_verified_gpu_launch_token_binds_instance_chute_model_and_commit():
    db = _launch_identity_db()
    with patch(
        "api.instance.util._decode_chutes_jwt",
        return_value=_launch_payload(),
    ):
        identity = await service.authorize_launch_model_request(
            db,
            "Bearer signed-launch-token",
            "org/model",
            COMMIT,
            COMMIT,
        )

    assert identity == {
        "requester_kind": "launch_instance",
        "requester_server_id": None,
        "requester_cert_pubkey_hash": None,
        "requester_instance_id": "instance",
        "requester_config_id": "config",
        "requester_chute_id": "chute",
        "requester_deployment_id": "deployment",
    }


@pytest.mark.asyncio
async def test_cpu_launch_token_requires_matching_attested_mtls_server():
    with patch(
        "api.instance.util._decode_chutes_jwt",
        return_value=_launch_payload(server_id="cpu-server"),
    ):
        with pytest.raises(HTTPException, match="must authorize model access over mTLS"):
            await service.authorize_launch_model_request(
                _launch_identity_db(server_id="cpu-server"),
                "Bearer signed-launch-token",
                "org/model",
                COMMIT,
                COMMIT,
            )

        identity = await service.authorize_launch_model_request(
            _launch_identity_db(server_id="cpu-server"),
            "Bearer signed-launch-token",
            "org/model",
            COMMIT,
            COMMIT,
            expected_server_id="cpu-server",
        )
    assert identity["requester_kind"] == "attested_server"
    assert identity["requester_server_id"] == "cpu-server"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("repo_id", "revision", "requested_revision"),
    [
        ("org/other", COMMIT, COMMIT),
        ("org/model", OTHER_COMMIT, COMMIT),
        ("org/model", COMMIT, OTHER_COMMIT),
    ],
)
async def test_launch_model_authorization_rejects_cross_model_or_commit_use(
    repo_id, revision, requested_revision
):
    with patch(
        "api.instance.util._decode_chutes_jwt",
        return_value=_launch_payload(),
    ):
        with pytest.raises(HTTPException):
            await service.authorize_launch_model_request(
                _launch_identity_db(),
                "Bearer signed-launch-token",
                repo_id,
                revision,
                requested_revision,
            )


@pytest.mark.asyncio
async def test_model_target_prefers_local_then_accepts_remote_holder():
    local = StoragePeer(
        server_id="local",
        host="local.example",
        port=8445,
        cert_pubkey_hash="1" * 64,
        storage_incarnation="00000000-0000-0000-0000-000000000001",
    )
    remote = local.model_copy(update={"server_id": "remote", "host": "remote.example"})
    db = AsyncMock()
    with (
        patch.object(service, "local_storage_peer", AsyncMock(return_value=local)),
        patch.object(service, "peer_cert", AsyncMock(return_value=("local-cert", "1" * 64))),
        patch.object(service, "model_peers", AsyncMock()) as model_peers,
    ):
        selected = await service.model_ensure_target(
            db,
            "org/model",
            COMMIT,
            preferred_host_id="gpu-host",
        )
    assert selected.server_id == "local"
    assert selected.attested_cert == "local-cert"
    model_peers.assert_not_awaited()

    with (
        patch.object(service, "local_storage_peer", AsyncMock(return_value=None)),
        patch.object(service, "model_peers", AsyncMock(return_value=[remote])),
        patch.object(
            service,
            "peer_cert",
            AsyncMock(return_value=("remote-cert", "1" * 64)),
        ),
    ):
        selected = await service.model_ensure_target(
            db,
            "org/model",
            COMMIT,
            preferred_host_id="gpu-host",
        )
    assert selected.server_id == "remote"
    assert selected.attested_cert == "remote-cert"
