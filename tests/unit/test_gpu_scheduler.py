from pathlib import Path
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.chute.schemas import NodeSelector
from api.gpu_scheduler import (
    _create_platform_launch_config,
    _dispatch_workload_or_teardown,
    _platform_gpu_selector,
    _tick_with_lock,
    group_matches_selector,
    inventory_budget_matches,
)
from api.host.gpu_allocations import (
    GpuAllocationError,
    _trusted_platform_workload,
    gpu_reservation_token,
)
from api.host.schemas import GpuPlatformReservationRequestV1
from api.registry.oci import OciDescriptorClosure
from tests.unit.test_gpu_allocations import _report


def _group(**overrides):
    values = {
        "state": "available",
        "management_mode": None,
        "reservation_id": None,
        "gpu_count": 8,
        "vram_mib": 196608,
        "gpu_identifiers": ["b200"] * 8,
        "model": "B200",
        "profile_id": "b200-8gpu",
        "topology_fingerprint": "a" * 64,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_platform_group_matches_exact_selector_profile_and_topology():
    selector = NodeSelector(
        compute_type="gpu",
        gpu_count=8,
        min_vram_gb_per_gpu=140,
        include=["b200"],
        exclude=["h200"],
    )
    assert group_matches_selector(_group(), selector)

    assert not group_matches_selector(_group(gpu_count=4), selector)
    assert not group_matches_selector(_group(vram_mib=128 * 1024), selector)
    assert not group_matches_selector(_group(gpu_identifiers=["h200"] * 8), selector)
    assert not group_matches_selector(_group(state="quarantined"), selector)


def test_platform_group_fails_closed_for_b300_mixed_and_unknown():
    selector = NodeSelector(
        compute_type="gpu",
        gpu_count=8,
        include=["b200"],
    )
    assert not group_matches_selector(
        _group(model="B300", gpu_identifiers=["b300"] * 8),
        selector,
    )
    assert not group_matches_selector(
        _group(gpu_identifiers=["b200", "h200"] * 4),
        selector,
    )
    assert not group_matches_selector(
        _group(gpu_identifiers=["unknown"] * 8),
        selector,
    )


def test_default_selector_can_match_characterized_gpu_without_selecting_b300():
    selector = _platform_gpu_selector(
        SimpleNamespace(
            tee=True,
            disabled=False,
            node_selector={"compute_type": "gpu", "gpu_count": 8},
            image=SimpleNamespace(compute_type="gpu"),
        )
    )
    assert "b200" in selector.supported_gpus
    assert group_matches_selector(_group(), selector)
    assert not group_matches_selector(
        _group(model="B300", gpu_identifiers=["b300"] * 8),
        selector,
    )


def test_gpu_selector_include_exclude_are_canonical_lowercase():
    selector = NodeSelector(
        compute_type="gpu",
        include=["B200"],
        exclude=["H100_SXM"],
        min_vram_gb_per_gpu=16,
    )
    assert selector.include == ["b200"]
    assert selector.exclude == ["h100_sxm"]
    assert "b200" in selector.supported_gpus


def test_job_selector_overrides_chute_for_count_and_model_matching():
    chute = SimpleNamespace(
        tee=True,
        disabled=False,
        node_selector={
            "compute_type": "gpu",
            "gpu_count": 8,
            "include": ["b200"],
        },
        image=SimpleNamespace(compute_type="gpu"),
    )
    job = SimpleNamespace(
        node_selector={
            "compute_type": "gpu",
            "gpu_count": 4,
            "include": ["h200"],
            "min_vram_gb_per_gpu": 16,
        }
    )
    selector = _platform_gpu_selector(chute, job)
    assert selector.gpu_count == 4
    assert selector.supported_gpus == ["h200"]
    assert group_matches_selector(
        _group(
            gpu_count=4,
            gpu_identifiers=["h200"] * 4,
            model="H200",
        ),
        selector,
    )


@pytest.mark.asyncio
async def test_shared_job_uses_job_owner_with_chute_image_owner():
    chute = SimpleNamespace(
        chute_id="chute",
        user_id="chute-owner",
        tee=True,
        disabled=False,
        image_id="image",
        version="v1",
        node_selector={
            "compute_type": "gpu",
            "gpu_count": 8,
            "include": ["b200"],
            "min_vram_gb_per_gpu": 16,
        },
    )
    image = SimpleNamespace(
        image_id="image",
        user_id="chute-owner",
        compute_type="gpu",
        status="built and pushed",
        user=SimpleNamespace(username="publisher"),
        name="image",
        tag="latest",
        patch_version=None,
    )
    job = SimpleNamespace(
        job_id="job",
        chute_id="chute",
        user_id="job-owner",
        version="v1",
        finished_at=None,
        gpu_management_mode=None,
        node_selector=chute.node_selector,
    )

    def scalar(value):
        result = MagicMock()
        result.scalar_one_or_none.return_value = value
        return result

    db = AsyncMock()
    db.execute.side_effect = [
        MagicMock(),
        scalar(chute),
        scalar(image),
        scalar(job),
    ]
    root = f"sha256:{'a' * 64}"
    signature = f"sha256:{'b' * 64}"
    tag = f"sha256-{'a' * 64}.sig"
    closure = OciDescriptorClosure(
        manifests=(root, signature),
        blobs=(f"sha256:{'c' * 64}",),
        manifest_tags=(tag,),
        manifest_tag_digests=((tag, signature),),
        sha256="d" * 64,
    )
    with (
        patch(
            "api.image.forge.get_image_digest",
            AsyncMock(return_value=root),
        ),
        patch(
            "api.registry.oci.resolve_oci_descriptor_closure",
            AsyncMock(return_value=closure),
        ),
    ):
        (
            owner,
            version,
            repository,
            manifest,
            descriptor,
        ) = await _trusted_platform_workload(
            db,
            GpuPlatformReservationRequestV1(
                server_id="server",
                process_incarnation="process",
                gpu_identifier="b200",
                gpu_count=8,
                minimum_vram_mib=196608,
                chute_id="chute",
                job_id="job",
            ),
        )
    assert owner == "job-owner"
    assert version == "v1"
    assert repository == "publisher/image"
    assert manifest == root
    assert descriptor["manifest_tag_digests"] == {tag: signature}


def test_platform_inventory_budget_fails_closed_on_disk_cpu_or_ram_shortfall():
    report = _report()
    assert inventory_budget_matches(report, required_disk_mib=10 * 1024)
    assert not inventory_budget_matches(
        report,
        required_disk_mib=report.resources.gpu_scratch_disk_mib + 1,
    )
    cpu_starved = report.model_copy(
        update={
            "resources": report.resources.model_copy(
                update={
                    "logical_cpus": (
                        report.resources.storage_vcpus + report.resources.l0_reserved_vcpus
                    )
                }
            )
        }
    )
    assert not inventory_budget_matches(cpu_starved, required_disk_mib=1)
    ram_starved = report.model_copy(
        update={
            "resources": report.resources.model_copy(
                update={
                    "memory_mib": (
                        report.resources.storage_memory_mib
                        + report.resources.storage_overhead_mib
                        + report.resources.gpu_overhead_mib
                        + report.resources.l0_reserved_memory_mib
                    )
                }
            )
        }
    )
    assert not inventory_budget_matches(ram_starved, required_disk_mib=1)


def test_gpu_reservation_token_is_retry_stable_and_hash_bound():
    first = gpu_reservation_token("reservation-id")
    second = gpu_reservation_token("reservation-id")
    assert first == second
    assert first.startswith("reservation-id.")
    with pytest.raises(GpuAllocationError, match="derivation changed"):
        gpu_reservation_token("reservation-id", "0" * 64)


@pytest.mark.asyncio
async def test_scheduler_leadership_release_is_atomic_compare_and_delete():
    redis = AsyncMock()
    redis.set.return_value = True
    with (
        patch(
            "api.gpu_scheduler.settings",
            SimpleNamespace(redis_client=redis),
        ),
        patch("api.gpu_scheduler.schedule_once", AsyncMock()),
    ):
        await _tick_with_lock()
    redis.eval.assert_awaited_once()
    redis.get.assert_not_awaited()
    redis.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_owner_disappearance_enters_teardown():
    teardown = AsyncMock()
    with (
        patch(
            "api.gpu_scheduler._dispatch_workload",
            AsyncMock(
                side_effect=GpuAllocationError(
                    "GPU server owner is absent from the current metagraph."
                )
            ),
        ),
        patch(
            "api.gpu_scheduler.send_gpu_reservation_teardown",
            teardown,
        ),
    ):
        await _dispatch_workload_or_teardown("reservation")
    teardown.assert_awaited_once()
    assert "metagraph" in teardown.await_args.kwargs["reason"]


@pytest.mark.asyncio
async def test_platform_dispatch_rejects_miner_managed_server_before_config_creation():
    reservation = SimpleNamespace(
        reservation_id="reservation",
        allocation_group_id="group",
        allocation_group_generation=1,
        process_incarnation="process",
    )
    server = SimpleNamespace(
        server_id="server",
        gpu_management_mode="miner",
        gpu_launch_reservation_id="reservation",
        gpu_allocation_group_id="group",
        gpu_allocation_group_generation=1,
        gpu_process_incarnation="process",
        gpu_retired_at=None,
    )
    with pytest.raises(GpuAllocationError, match="miner-managed"):
        await _create_platform_launch_config(
            AsyncMock(),
            reservation,
            server,
            SimpleNamespace(),
            None,
        )


def test_gpu_scheduler_has_chart_and_dev_lifecycle_wiring():
    root = Path(__file__).resolve().parents[2]
    chart = (root / "charts/templates/gpu-platform-scheduler-deployment.yaml").read_text()
    values = (root / "charts/values.yaml").read_text()
    compose = (root / "docker-compose.dev.yml").read_text()

    assert 'command: ["uv", "run", "python", "-m", "api.gpu_scheduler"]' in chart
    assert "gpuPlatformScheduler:" in values
    assert "gpu_platform_scheduler:" in compose
    assert '"api.gpu_scheduler"' in compose
    assert "TRUSTED_L0_PUBLISHER_KEYS_PATH" in chart
    assert "l0-publisher-public-keys" in chart
    assert "TRUSTED_L0_PUBLISHER_KEYS_PATH" in compose
    assert "l0-publisher-keys.json" in compose


def test_miner_inventory_and_events_exclude_platform_resources():
    from api.miner import router as miner_router
    from api import util

    assert 'gpu_management_mode != "platform"' in inspect.getsource(miner_router.list_servers)
    assert 'gpu_management_mode != "platform"' in inspect.getsource(miner_router.list_instances)
    assert "gpu_retired_at.is_(None)" in inspect.getsource(miner_router.list_nodes)
    assert "gpu_management_mode" in inspect.getsource(miner_router.list_available_jobs)
    for notifier in (
        util.notify_created,
        util.notify_deleted,
        util.notify_verified,
        util.notify_activated,
        util.notify_disabled,
    ):
        assert "gpu_management_mode" in inspect.getsource(notifier)
        assert '"platform"' in inspect.getsource(notifier)


@pytest.mark.asyncio
async def test_platform_teardown_survives_event_bus_failure():
    from api import util

    instance = SimpleNamespace(
        chute_id="chute",
        miner_hotkey="owner",
        instance_id="instance",
        config_id="config",
        server_id="gpu-server",
        gpu_management_mode="platform",
    )
    teardown = AsyncMock(return_value="command")
    with (
        patch.object(
            util.settings.redis_client,
            "publish",
            AsyncMock(side_effect=RuntimeError("redis unavailable")),
        ),
        patch("api.agent_channel.send_instance_teardown", teardown),
    ):
        await util.notify_deleted(instance)
    teardown.assert_awaited_once_with(
        "chute",
        instance_id="instance",
        server_id="gpu-server",
        config_id="config",
    )
