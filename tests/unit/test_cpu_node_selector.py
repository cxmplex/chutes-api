"""
Unit tests for CPU support in api.chute.schemas.NodeSelector.

Covers CPU field validation, gpu_count==0 handling, serialization round-trip, CPU pricing,
and that the GPU path is unchanged.
"""

import pytest
from unittest.mock import AsyncMock, patch

from api.chute.schemas import NodeSelector
from api.cpu import cpu_compute_multiplier
from api.gpu import COMPUTE_UNIT_PRICE_BASIS


def test_default_compute_type_is_gpu():
    ns = NodeSelector()
    assert ns.compute_type == "gpu"
    assert ns.gpu_count == 1


def test_absent_compute_type_is_gpu():
    ns = NodeSelector(gpu_count=2, include=["h100"])
    assert ns.compute_type == "gpu"
    assert ns.gpu_count == 2


def test_invalid_compute_type_raises():
    with pytest.raises(Exception):
        NodeSelector(compute_type="tpu")


def test_cpu_compute_type_forces_gpu_count_zero():
    ns = NodeSelector(compute_type="cpu", cpu_cores=8, ram_gb=32)
    assert ns.compute_type == "cpu"
    assert ns.gpu_count == 0
    assert ns.cpu_cores == 8
    assert ns.ram_gb == 32


def test_cpu_compute_type_ignores_supplied_gpu_count():
    # Even if a gpu_count is supplied for a CPU selector, it is treated as 0.
    ns = NodeSelector(compute_type="cpu", gpu_count=4)
    assert ns.gpu_count == 0


def test_cpu_supported_gpus_is_empty():
    ns = NodeSelector(compute_type="cpu")
    assert ns.supported_gpus == []


def test_cpu_compute_multiplier_uses_cpu_formula():
    ns = NodeSelector(compute_type="cpu", cpu_cores=4, ram_gb=16, min_benchmark_score=1500.0)
    expected = cpu_compute_multiplier(1500.0, cpu_cores=4, ram_gb=16)
    assert ns.compute_multiplier == pytest.approx(expected)


def test_cpu_compute_multiplier_does_not_raise_without_gpus():
    # GPU path raises "No GPUs match" when empty; CPU path must not.
    ns = NodeSelector(compute_type="cpu")
    assert ns.compute_multiplier > 0


def test_cpu_serialization_includes_new_fields():
    ns = NodeSelector(compute_type="cpu", cpu_cores=8, ram_gb=64, min_benchmark_score=1200.0)
    dumped = ns.model_dump()
    assert dumped["compute_type"] == "cpu"
    assert dumped["cpu_cores"] == 8
    assert dumped["ram_gb"] == 64
    assert dumped["min_benchmark_score"] == 1200.0
    assert dumped["gpu_count"] == 0
    assert dumped["supported_gpus"] == []


def test_cpu_node_selector_round_trips_through_dict():
    # The serialized form (gpu_count=0) must reconstruct without tripping the gpu ge=1 rule.
    ns = NodeSelector(compute_type="cpu", cpu_cores=2, ram_gb=8, min_benchmark_score=900.0)
    rebuilt = NodeSelector(**ns.model_dump())
    assert rebuilt.compute_type == "cpu"
    assert rebuilt.gpu_count == 0
    assert rebuilt.cpu_cores == 2
    assert rebuilt.ram_gb == 8
    assert rebuilt.min_benchmark_score == 900.0


def test_gpu_path_unchanged_compute_multiplier():
    ns = NodeSelector(gpu_count=2, include=["a100"])
    # Two GPUs, minimum multiplier across the single included GPU.
    assert ns.compute_multiplier > 0
    assert "a100" in ns.supported_gpus


def test_gpu_empty_selector_still_raises():
    ns = NodeSelector(include=["a100"], exclude=["a100"])
    assert ns.supported_gpus == []
    with pytest.raises(ValueError, match="No GPUs match"):
        _ = ns.compute_multiplier


@pytest.mark.asyncio
async def test_cpu_current_estimated_price():
    ns = NodeSelector(compute_type="cpu", cpu_cores=4, ram_gb=16, min_benchmark_score=1500.0)
    with patch("api.chute.schemas.get_fetcher") as mock_fetcher:
        mock_fetcher.return_value.get_price = AsyncMock(return_value=2.0)
        price = await ns.current_estimated_price()
    assert price is not None
    expected_usd_hour = COMPUTE_UNIT_PRICE_BASIS * ns.compute_multiplier
    assert price["usd"]["hour"] == pytest.approx(expected_usd_hour)
    assert price["usd"]["second"] == pytest.approx(expected_usd_hour / 3600)
    # tao price = 2.0 USD/tao
    assert price["tao"]["hour"] == pytest.approx(expected_usd_hour / 2.0)
