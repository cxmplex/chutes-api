"""
Unit tests for api/cpu.py: CPU pricing multiplier and benchmark validation.
"""

import pytest

from api.cpu import (
    CPU_CORE_HOURLY_USD,
    CPU_RAM_HOURLY_USD_PER_GB,
    CPU_REFERENCE_COMPOSITE_SCORE,
    cpu_compute_multiplier,
    validate_cpu_benchmark,
)
from api.gpu import COMPUTE_UNIT_PRICE_BASIS


def _valid_benchmark(**overrides):
    benchmark = {
        "schema_version": 1,
        "cpu_cores": 8,
        "ram_gb": 32,
        "int_score": 1234.5,
        "float_score": 2345.6,
        "memory_bandwidth_mb_s": 15000.0,
        "hash_score": 999.9,
        "composite_score": 1500.0,
        "duration_ms": 4200,
    }
    benchmark.update(overrides)
    return benchmark


def test_cpu_multiplier_at_reference_score():
    """A single core/GB at the reference score yields the documented USD/hour."""
    multiplier = cpu_compute_multiplier(CPU_REFERENCE_COMPOSITE_SCORE, cpu_cores=1, ram_gb=1)
    expected_usd_hour = CPU_CORE_HOURLY_USD * 1 + CPU_RAM_HOURLY_USD_PER_GB * 1
    assert multiplier == pytest.approx(expected_usd_hour / COMPUTE_UNIT_PRICE_BASIS)
    # The pricing line usd_price = COMPUTE_UNIT_PRICE_BASIS * multiplier recovers the USD/hour.
    assert COMPUTE_UNIT_PRICE_BASIS * multiplier == pytest.approx(expected_usd_hour)


def test_cpu_multiplier_scales_with_composite_score():
    """Higher composite_score (faster CPU) is priced higher."""
    low = cpu_compute_multiplier(500.0, cpu_cores=4, ram_gb=8)
    high = cpu_compute_multiplier(2000.0, cpu_cores=4, ram_gb=8)
    assert high > low


def test_cpu_multiplier_scales_with_cores_and_ram():
    base = cpu_compute_multiplier(1000.0, cpu_cores=1, ram_gb=1)
    more_cores = cpu_compute_multiplier(1000.0, cpu_cores=8, ram_gb=1)
    more_ram = cpu_compute_multiplier(1000.0, cpu_cores=1, ram_gb=64)
    assert more_cores > base
    assert more_ram > base


def test_cpu_multiplier_none_score_uses_reference():
    """When no composite_score is provided, the reference score is used."""
    assert cpu_compute_multiplier(None, cpu_cores=2, ram_gb=4) == cpu_compute_multiplier(
        CPU_REFERENCE_COMPOSITE_SCORE, cpu_cores=2, ram_gb=4
    )


def test_cpu_multiplier_zero_score_uses_reference():
    assert cpu_compute_multiplier(0, cpu_cores=1, ram_gb=1) == cpu_compute_multiplier(
        CPU_REFERENCE_COMPOSITE_SCORE, cpu_cores=1, ram_gb=1
    )


def test_validate_cpu_benchmark_valid_returns_dict():
    benchmark = _valid_benchmark()
    assert validate_cpu_benchmark(benchmark) is benchmark


def test_validate_cpu_benchmark_rejects_non_dict():
    with pytest.raises(ValueError, match="must be a JSON object"):
        validate_cpu_benchmark(None)


def test_validate_cpu_benchmark_missing_field():
    benchmark = _valid_benchmark()
    del benchmark["composite_score"]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_cpu_benchmark(benchmark)


def test_validate_cpu_benchmark_wrong_type():
    benchmark = _valid_benchmark(cpu_cores="eight")
    with pytest.raises(ValueError, match="cpu_cores"):
        validate_cpu_benchmark(benchmark)


def test_validate_cpu_benchmark_rejects_bool_for_numeric():
    # bool is a subclass of int and must be rejected for numeric fields.
    benchmark = _valid_benchmark(composite_score=True)
    with pytest.raises(ValueError, match="composite_score"):
        validate_cpu_benchmark(benchmark)


def test_validate_cpu_benchmark_non_positive_composite():
    benchmark = _valid_benchmark(composite_score=0.0)
    with pytest.raises(ValueError, match="composite_score must be greater than 0"):
        validate_cpu_benchmark(benchmark)


def test_validate_cpu_benchmark_requires_min_capacity():
    benchmark = _valid_benchmark(cpu_cores=0)
    with pytest.raises(ValueError, match="cpu_cores and ram_gb must be >= 1"):
        validate_cpu_benchmark(benchmark)
