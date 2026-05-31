"""
CPU (GPU-less) TEE chute pricing and benchmark handling.

This is the single, documented place for CPU pricing. CPU chutes run on TEE (Intel TDX)
servers that have no GPU; they are priced from the sek8s CPU benchmark `composite_score`
(the canonical benchmark scalar, higher == faster CPU), optionally weighted by the
requested ``cpu_cores`` and ``ram_gb``.

The result is expressed as a multiplier of ``COMPUTE_UNIT_PRICE_BASIS`` (reused from
``api.gpu``) so it plugs directly into the existing pricing line used for GPU chutes::

    usd_price = COMPUTE_UNIT_PRICE_BASIS * multiplier

Formula::

    per_core_usd = CPU_CORE_HOURLY_USD * (composite_score / CPU_REFERENCE_COMPOSITE_SCORE)
    usd_hour     = per_core_usd * cpu_cores + CPU_RAM_HOURLY_USD_PER_GB * ram_gb
    multiplier   = usd_hour / COMPUTE_UNIT_PRICE_BASIS

``CPU_REFERENCE_COMPOSITE_SCORE`` is the calibration point: a server (or requested minimum)
that scores exactly this value on the sek8s benchmark is billed ``CPU_CORE_HOURLY_USD`` per
core-hour. It MUST be calibrated to the magnitude of the sek8s ``composite_score`` output
(produced by the sek8s repo); changing these constants is the only knob needed to retune
CPU pricing.
"""

from typing import Optional, Union

from api.gpu import COMPUTE_UNIT_PRICE_BASIS

# Schema version of the CPU benchmark result JSON produced by sek8s and consumed here.
CPU_BENCHMARK_SCHEMA_VERSION = 1

# Calibration: a composite_score of this magnitude corresponds to one reference CPU core.
CPU_REFERENCE_COMPOSITE_SCORE = 1000.0

# USD/hour billed per CPU core for a server scoring exactly CPU_REFERENCE_COMPOSITE_SCORE.
CPU_CORE_HOURLY_USD = 0.01

# USD/hour billed per GB of RAM requested.
CPU_RAM_HOURLY_USD_PER_GB = 0.002

# Required keys of the CPU benchmark result JSON (contract with sek8s) and their accepted
# Python types. composite_score is the canonical scalar used for pricing + scheduling.
CPU_BENCHMARK_FIELD_TYPES = {
    "schema_version": (int,),
    "cpu_cores": (int,),
    "ram_gb": (int,),
    "int_score": (int, float),
    "float_score": (int, float),
    "memory_bandwidth_mb_s": (int, float),
    "hash_score": (int, float),
    "composite_score": (int, float),
    "duration_ms": (int,),
}


def cpu_compute_multiplier(
    composite_score: Optional[float],
    cpu_cores: int = 1,
    ram_gb: int = 1,
) -> float:
    """
    Compute the CPU pricing multiplier from a benchmark composite_score.

    The returned value is intended to be plugged into the existing pricing line
    ``usd_price = COMPUTE_UNIT_PRICE_BASIS * multiplier``.

    Args:
        composite_score: sek8s benchmark composite score. When falsy (e.g. a chute that
            specified no min_benchmark_score), CPU_REFERENCE_COMPOSITE_SCORE is used.
        cpu_cores: Number of CPU cores being priced (>= 1).
        ram_gb: GB of RAM being priced (>= 1).

    Returns:
        Pricing multiplier (float).
    """
    score = (
        composite_score
        if composite_score and composite_score > 0
        else CPU_REFERENCE_COMPOSITE_SCORE
    )
    cores = max(int(cpu_cores or 1), 1)
    ram = max(int(ram_gb or 1), 1)
    per_core_usd = CPU_CORE_HOURLY_USD * (score / CPU_REFERENCE_COMPOSITE_SCORE)
    usd_hour = per_core_usd * cores + CPU_RAM_HOURLY_USD_PER_GB * ram
    return usd_hour / COMPUTE_UNIT_PRICE_BASIS


def validate_cpu_benchmark(benchmark: Union[dict, None]) -> dict:
    """
    Validate a CPU benchmark result JSON against the sek8s contract.

    The validator gathers this result itself (via the attestation service); it must never
    trust a miner-supplied benchmark, so the shape is validated strictly here.

    Args:
        benchmark: Parsed benchmark result (dict) from the attestation response.

    Returns:
        The validated benchmark dict.

    Raises:
        ValueError: If the benchmark is missing required fields, has wrong types, or has a
            non-positive composite_score.
    """
    if not isinstance(benchmark, dict):
        raise ValueError("CPU benchmark result must be a JSON object")

    missing = [key for key in CPU_BENCHMARK_FIELD_TYPES if key not in benchmark]
    if missing:
        raise ValueError(f"CPU benchmark result missing required fields: {missing}")

    for key, accepted_types in CPU_BENCHMARK_FIELD_TYPES.items():
        value = benchmark[key]
        # bool is a subclass of int; reject it explicitly for numeric fields.
        if isinstance(value, bool) or not isinstance(value, accepted_types):
            raise ValueError(
                f"CPU benchmark field {key!r} must be of type "
                f"{'/'.join(t.__name__ for t in accepted_types)}"
            )

    if benchmark["composite_score"] <= 0:
        raise ValueError("CPU benchmark composite_score must be greater than 0")
    if benchmark["cpu_cores"] < 1 or benchmark["ram_gb"] < 1:
        raise ValueError("CPU benchmark cpu_cores and ram_gb must be >= 1")

    return benchmark
