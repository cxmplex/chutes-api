import pytest

from api.chute.schemas import NodeSelector
from api.job.router import job_compute_multiplier


def test_cpu_job_never_receives_h200_boost():
    selector = NodeSelector(
        compute_type="cpu",
        cpu_cores=4,
        ram_gb=8,
        min_benchmark_score=1000,
    )
    assert job_compute_multiplier(selector) == pytest.approx(selector.compute_multiplier)


def test_h200_gpu_job_receives_gpu_only_boost():
    selector = NodeSelector(compute_type="gpu", include=["h200"], gpu_count=1)
    assert job_compute_multiplier(selector) == pytest.approx(selector.compute_multiplier * 16)


def test_mixed_gpu_job_does_not_receive_h200_only_boost():
    selector = NodeSelector(compute_type="gpu", include=["h100", "h200"], gpu_count=1)
    assert job_compute_multiplier(selector) == pytest.approx(selector.compute_multiplier)
