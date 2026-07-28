"""Real-PostgreSQL coverage for durable miner launch-response replay."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from api.chute.schemas import Chute, NodeSelector
from api.host.gpu_allocations import request_gpu_teardown, reserve_gpu_group
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation
from api.gpu_models import GpuLifecycleOperation
from api.image.schemas import Image
from api.instance import router as instance_router
from api.instance.schemas import LaunchConfig
from api.job.schemas import Job
from api.server.schemas import (
    DefaultChuteFSVolumeBinding,
    Server,
    StorageVolume,
    StorageVolumeKey,
)
from api.user.schemas import User
from tests.integration.test_gpu_allocations_postgres import (
    _request,
    _seed,
    nv_attest,  # noqa: F401
    postgres_schema,  # noqa: F401
    unsigned_debug_provenance,  # noqa: F401
)


pytestmark = pytest.mark.asyncio


async def _seed_launch_authority(sessions, *, with_job: bool) -> dict[str, str | None]:
    await _seed(sessions)
    now = datetime.now(timezone.utc)
    async with sessions() as session:
        response = await reserve_gpu_group(session, "gpu-host", _request())
        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            response.claims.allocation_group_id,
        )
        reservation.state = "running"
        reservation.claimed_at = now
        reservation.launching_at = now
        reservation.running_at = now
        group.state = "running"
        group.management_mode = "miner"
        group.reservation_owner = "owner"
        group.reservation_id = reservation.reservation_id
        group.reservation_generation = reservation.reservation_generation
        group.process_incarnation = reservation.process_incarnation
        group.launching_at = now
        group.running_at = now

        user = User(
            user_id="miner-launch-owner",
            coldkey="owner-coldkey",
            username="launch-owner",
            fingerprint_hash="miner-launch-owner-fingerprint",
        )
        image = Image(
            image_id="miner-launch-image",
            artifact_id="miner-launch-artifact",
            user_id=user.user_id,
            name="miner-launch-image",
            tag="v1",
            compute_type="gpu",
        )
        chute = Chute(
            chute_id="miner-launch-chute",
            user_id=user.user_id,
            image_id=image.image_id,
            name="miner-launch-chute",
            cords=[],
            node_selector=NodeSelector(compute_type="gpu", gpu_count=8),
            code="from chutes import Chute",
            filename="launch.py",
            ref_str="launch:launch",
            version="v1",
            revision="a" * 40,
            chutes_version="0.4.9",
            public=True,
            tee=True,
            allow_external_egress=False,
            lock_modules=False,
        )
        volume = StorageVolume(
            volume_id="miner-launch-volume",
            user_id=user.user_id,
            name="miner-launch-volume",
            replication_factor=1,
            quota_bytes=1024,
            used_bytes=0,
        )
        server = Server(
            server_id=reservation.server_id,
            ip="192.0.2.90",
            miner_hotkey="owner",
            name=reservation.server_id,
            compute_type="gpu",
            tee_type="tdx",
            self_registered=True,
            gpu_launch_reservation_id=reservation.reservation_id,
            gpu_allocation_group_id=group.allocation_group_id,
            gpu_allocation_group_generation=group.generation,
            gpu_management_mode="miner",
            gpu_process_incarnation=reservation.process_incarnation,
            gpu_topology_fingerprint=reservation.topology_fingerprint,
            gpu_runtime_session_attestation_id="runtime-attestation-a",
            gpu_runtime_session_expires_at=now + timedelta(minutes=15),
            attested_cert_pubkey_hash="9" * 64,
        )
        session.add(user)
        await session.flush()
        image.user_id = user.user_id
        chute.user_id = user.user_id
        volume.user_id = user.user_id
        session.add(image)
        await session.flush()
        session.add(chute)
        await session.flush()
        session.add(volume)
        await session.flush()
        session.add_all(
            [
                StorageVolumeKey(
                    volume_id=volume.volume_id,
                    encrypted_key="encrypted-test-key",
                ),
                DefaultChuteFSVolumeBinding(
                    binding_id="miner-launch-binding",
                    user_id=user.user_id,
                    chute_id=chute.chute_id,
                    volume_id=volume.volume_id,
                ),
                server,
            ]
        )
        job_id = None
        if with_job:
            job_id = "miner-launch-job"
            session.add(
                Job(
                    job_id=job_id,
                    user_id=user.user_id,
                    chute_id=chute.chute_id,
                    version=chute.version,
                    chutes_version=chute.chutes_version,
                    method="run",
                    job_args={"_disk_gb": 25},
                    status="pending",
                    miner_history=[],
                    compute_multiplier=1.0,
                )
            )
        await session.commit()
    return {
        "chute_id": "miner-launch-chute",
        "job_id": job_id,
        "server_id": response.claims.server_id,
    }


def _request_context(server_id: str):
    return SimpleNamespace(state=SimpleNamespace(gpu_runtime_server_id=server_id))


async def _issue(
    session,
    lineage: dict[str, str | None],
    request_id: str,
):
    return await instance_router.get_launch_config(
        chute_id=lineage["chute_id"],
        request=_request_context(lineage["server_id"]),
        server_id=lineage["server_id"],
        job_id=lineage["job_id"],
        miner_launch_request_id=request_id,
        db=session,
        hotkey="owner",
        _=None,
    )


async def test_lost_response_replays_same_config_without_side_effects(
    postgres_schema,  # noqa: F811
    monkeypatch,
):
    sessions, _schema = postgres_schema
    lineage = await _seed_launch_authority(sessions, with_job=True)
    request_id = "11111111-1111-4111-8111-111111111111"
    redis = SimpleNamespace(set=AsyncMock(), publish=AsyncMock())
    tokens = []

    def _token(_config, **policy):
        tokens.append(policy)
        return f"fresh-token-{len(tokens)}"

    monkeypatch.setattr(instance_router.settings, "_redis_client", redis)
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        AsyncMock(
            return_value={
                "scale_value": None,
                "inventory_history": None,
                "bounty_exists": None,
                "registry_repository": "owner/miner-launch-image",
                "registry_manifest_digest": f"sha256:{'7' * 64}",
            }
        ),
    )
    monkeypatch.setattr(
        instance_router,
        "_verify_tee_version_support",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(instance_router, "create_launch_jwt_v2", _token)

    async with sessions() as session:
        first = await _issue(session, lineage, request_id)
    assert first == {
        "token": "fresh-token-1",
        "config_id": first["config_id"],
        "registry": {
            "repository": "owner/miner-launch-image",
            "manifest_digest": f"sha256:{'7' * 64}",
        },
    }

    # Exact replay must return before any demand, volume-creation, scaling, or
    # event adapter.  The persisted nonce may be republished only after commit.
    monkeypatch.setattr(
        instance_router,
        "_load_chute",
        AsyncMock(side_effect=AssertionError("replay loaded chute before locks")),
    )
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        AsyncMock(side_effect=AssertionError("replay repeated external demand")),
    )
    monkeypatch.setattr(
        instance_router,
        "ensure_default_volume_binding",
        AsyncMock(
            side_effect=AssertionError("replay created/looked up default volume")
        ),
    )
    redis.publish.side_effect = AssertionError("replay duplicated launch event")
    async with sessions() as session:
        second = await _issue(session, lineage, request_id)

    assert second["config_id"] == first["config_id"]
    assert second["registry"] == first["registry"]
    assert second["token"] == "fresh-token-2"
    assert tokens == [
        {"egress": False, "lock_modules": False, "disk_gb": 25},
        {"egress": False, "lock_modules": False, "disk_gb": 25},
    ]
    assert redis.set.await_count == 2
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(LaunchConfig)) == 1
        job = await session.get(Job, lineage["job_id"])
        assert job.miner_history == ["owner"]
    async with sessions() as session:
        columns = (
            await session.execute(
                text(
                    "SELECT column_name, character_maximum_length "
                    "FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = 'launch_configs' "
                    "AND column_name LIKE 'miner_launch_request%' "
                    "ORDER BY column_name"
                )
            )
        ).all()
        assert columns == [
            ("miner_launch_request_id", 36),
            ("miner_launch_request_sha256", 64),
        ]
        constraint = await session.scalar(
            text(
                "SELECT 1 FROM pg_constraint "
                "WHERE conrelid = 'launch_configs'::regclass "
                "AND conname = 'ck_launch_config_miner_request_replay'"
            )
        )
        index = await session.scalar(
            text(
                "SELECT 1 FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND indexname = 'uq_launch_configs_miner_request'"
            )
        )
        trigger = await session.scalar(
            text(
                "SELECT 1 FROM pg_trigger "
                "WHERE tgrelid = 'launch_configs'::regclass "
                "AND tgname = 'trg_miner_launch_request_immutable' "
                "AND NOT tgisinternal"
            )
        )
        assert constraint == 1
        assert index == 1
        assert trigger == 1
        with pytest.raises(
            DBAPIError, match="miner launch request identity is immutable"
        ):
            await session.execute(
                text(
                    "UPDATE launch_configs "
                    "SET miner_launch_request_sha256 = repeat('b', 64) "
                    "WHERE config_id = :config_id"
                ),
                {"config_id": first["config_id"]},
            )
        await session.rollback()


async def test_replay_accepts_fresh_attestation_but_rejects_policy_or_secret_mutation(
    postgres_schema,  # noqa: F811
    monkeypatch,
):
    sessions, _schema = postgres_schema
    lineage = await _seed_launch_authority(sessions, with_job=False)
    request_id = "22222222-2222-4222-8222-222222222222"
    redis = SimpleNamespace(set=AsyncMock(), publish=AsyncMock())
    monkeypatch.setattr(instance_router.settings, "_redis_client", redis)
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        AsyncMock(
            return_value={
                "scale_value": None,
                "inventory_history": None,
                "bounty_exists": None,
                "registry_repository": "owner/miner-launch-image",
                "registry_manifest_digest": f"sha256:{'7' * 64}",
            }
        ),
    )
    monkeypatch.setattr(instance_router, "_check_scalable", AsyncMock())
    monkeypatch.setattr(
        instance_router,
        "_verify_tee_version_support",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        instance_router,
        "create_launch_jwt_v2",
        lambda *_args, **_kwargs: "token",
    )
    async with sessions() as session:
        first = await _issue(session, lineage, request_id)

    async with sessions() as session:
        server = await session.get(Server, lineage["server_id"])
        server.gpu_runtime_session_attestation_id = "runtime-attestation-b"
        server.gpu_runtime_session_expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=15
        )
        await session.commit()
    async with sessions() as session:
        replay = await _issue(session, lineage, request_id)
    assert replay["config_id"] == first["config_id"]

    async with sessions() as session:
        chute = await session.get(Chute, lineage["chute_id"])
        chute.allow_external_egress = True
        await session.commit()
    async with sessions() as session:
        with pytest.raises(HTTPException, match="JWT policy changed") as exc:
            await _issue(session, lineage, request_id)
        assert exc.value.status_code == 409

    async with sessions() as session:
        chute = await session.get(Chute, lineage["chute_id"])
        chute.allow_external_egress = False
        config = await session.get(LaunchConfig, first["config_id"])
        config.env_key = "mutated-env-key"
        await session.commit()
    async with sessions() as session:
        with pytest.raises(HTTPException, match="JWT policy changed") as exc:
            await _issue(session, lineage, request_id)
        assert exc.value.status_code == 409


async def test_integrity_error_fallback_replays_winning_config(
    postgres_schema,  # noqa: F811
    monkeypatch,
):
    sessions, _schema = postgres_schema
    lineage = await _seed_launch_authority(sessions, with_job=False)
    request_id = "33333333-3333-4333-8333-333333333333"
    redis = SimpleNamespace(set=AsyncMock(), publish=AsyncMock())
    monkeypatch.setattr(instance_router.settings, "_redis_client", redis)
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        AsyncMock(
            return_value={
                "scale_value": None,
                "inventory_history": None,
                "bounty_exists": None,
                "registry_repository": "owner/miner-launch-image",
                "registry_manifest_digest": f"sha256:{'7' * 64}",
            }
        ),
    )
    monkeypatch.setattr(instance_router, "_check_scalable", AsyncMock())
    monkeypatch.setattr(instance_router, "_verify_tee_version_support", AsyncMock())
    monkeypatch.setattr(
        instance_router,
        "create_launch_jwt_v2",
        lambda *_args, **_kwargs: "token",
    )
    async with sessions() as session:
        winner = await _issue(session, lineage, request_id)

    original_try = instance_router._try_replay_miner_launch_config
    try_calls = 0

    async def _hide_early_winner(*args, **kwargs):
        nonlocal try_calls
        try_calls += 1
        if try_calls == 1:
            return None
        return await original_try(*args, **kwargs)

    async def _hide_locked_winner(
        db,
        *,
        launch_owner_id,
        chute_id,
        job_id,
        hotkey,
        request_id,
    ):
        volume = await instance_router._lock_default_volume_before_gpu_workload(
            db,
            launch_owner_id=launch_owner_id,
            chute_id=chute_id,
            job_id=job_id,
        )
        return volume, None

    monkeypatch.setattr(
        instance_router,
        "_try_replay_miner_launch_config",
        _hide_early_winner,
    )
    monkeypatch.setattr(
        instance_router,
        "_lock_new_miner_launch_storage_before_gpu_workload",
        _hide_locked_winner,
    )
    async with sessions() as session:
        recovered = await _issue(session, lineage, request_id)
    assert recovered["config_id"] == winner["config_id"]
    assert try_calls == 2
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(LaunchConfig)) == 1


async def test_node_selector_or_demand_posture_change_rejects_replay(
    postgres_schema,  # noqa: F811
    monkeypatch,
):
    sessions, _schema = postgres_schema
    lineage = await _seed_launch_authority(sessions, with_job=False)
    request_id = "55555555-5555-4555-8555-555555555555"
    redis = SimpleNamespace(set=AsyncMock(), publish=AsyncMock())
    demand = AsyncMock(
        return_value={
            "scale_value": None,
            "inventory_history": None,
            "bounty_exists": None,
            "registry_repository": "owner/miner-launch-image",
            "registry_manifest_digest": f"sha256:{'7' * 64}",
        }
    )
    token = Mock(return_value="token")
    monkeypatch.setattr(instance_router.settings, "_redis_client", redis)
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        demand,
    )
    monkeypatch.setattr(instance_router, "_check_scalable", AsyncMock())
    monkeypatch.setattr(instance_router, "_verify_tee_version_support", AsyncMock())
    monkeypatch.setattr(instance_router, "create_launch_jwt_v2", token)

    async with sessions() as session:
        first = await _issue(session, lineage, request_id)
    async with sessions() as session:
        chute = await session.get(Chute, lineage["chute_id"])
        original_selector = dict(chute.node_selector)
        chute.node_selector = NodeSelector(
            **{**original_selector, "gpu_count": 4}
        )
        await session.commit()
    async with sessions() as session:
        with pytest.raises(HTTPException) as exc:
            await _issue(session, lineage, request_id)
        assert exc.value.status_code == 409

    async with sessions() as session:
        chute = await session.get(Chute, lineage["chute_id"])
        original_version = chute.version
        chute.node_selector = NodeSelector(**original_selector)
        chute.public = False
        await session.commit()
        assert chute.version == original_version

    async with sessions() as session:
        with pytest.raises(HTTPException) as exc:
            await _issue(session, lineage, request_id)
        assert exc.value.status_code == 409

    assert demand.await_count == 1
    assert token.call_count == 1
    assert redis.set.await_count == 1
    assert redis.publish.await_count == 1
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(LaunchConfig)) == 1
        config = await session.get(LaunchConfig, first["config_id"])
        assert config.retrieved_at is None


async def test_stop_intent_and_active_operation_independently_fence_launches(
    postgres_schema,  # noqa: F811
    monkeypatch,
):
    sessions, _schema = postgres_schema
    lineage = await _seed_launch_authority(sessions, with_job=True)
    request_id = "66666666-6666-4666-8666-666666666666"
    redis = SimpleNamespace(set=AsyncMock(), publish=AsyncMock())
    demand = AsyncMock(
        return_value={
            "scale_value": None,
            "inventory_history": None,
            "bounty_exists": None,
            "registry_repository": "owner/miner-launch-image",
            "registry_manifest_digest": f"sha256:{'7' * 64}",
        }
    )
    token = Mock(return_value="token")
    monkeypatch.setattr(instance_router.settings, "_redis_client", redis)
    monkeypatch.setattr(
        instance_router,
        "_collect_launch_demand_external_work",
        demand,
    )
    monkeypatch.setattr(
        instance_router,
        "_verify_tee_version_support",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(instance_router, "create_launch_jwt_v2", token)

    async with sessions() as session:
        first = await _issue(session, lineage, request_id)
    async with sessions() as session:
        server = await session.get(Server, lineage["server_id"])
        reservation = await session.get(
            GpuLaunchReservation,
            server.gpu_launch_reservation_id,
        )
        reservation.teardown_requested_at = datetime.now(timezone.utc)
        reservation.teardown_reason = "focused stop-intent replay fence test"
        await session.commit()
    async with sessions() as session:
        with pytest.raises(HTTPException) as exc:
            await _issue(session, lineage, request_id)
        assert exc.value.status_code == 409

    async with sessions() as session:
        server = await session.get(Server, lineage["server_id"])
        reservation = await session.get(
            GpuLaunchReservation,
            server.gpu_launch_reservation_id,
        )
        reservation.teardown_requested_at = None
        reservation.teardown_reason = None
        await session.commit()
    async with sessions() as session:
        server = await session.get(Server, lineage["server_id"])
        await request_gpu_teardown(
            session,
            server.gpu_launch_reservation_id,
            reason="focused replay fence test",
        )
        reservation = await session.get(
            GpuLaunchReservation,
            server.gpu_launch_reservation_id,
        )
        group = await session.get(
            GpuAllocationGroup,
            server.gpu_allocation_group_id,
        )
        # Prove the durable operation is authoritative even if mutable projections
        # are stale or incorrectly restored to their pre-teardown values.
        reservation.state = "running"
        reservation.teardown_requested_at = None
        reservation.teardown_reason = None
        group.state = "running"
        await session.commit()

    async with sessions() as session:
        with pytest.raises(HTTPException) as exc:
            await _issue(
                session,
                lineage,
                "77777777-7777-4777-8777-777777777777",
            )
        assert exc.value.status_code == 409

    assert demand.await_count == 1
    assert token.call_count == 1
    assert redis.set.await_count == 1
    assert redis.publish.await_count == 1
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(LaunchConfig)) == 1
        assert (
            await session.scalar(
                select(func.count()).select_from(GpuLifecycleOperation)
            )
            == 1
        )
        job = await session.get(Job, lineage["job_id"])
        assert job.miner_history == ["owner"]
        assert first["config_id"] is not None
