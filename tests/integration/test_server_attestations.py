import pytest

from api.server.service import verify_gpu_evidence
from tests.fixtures.gpus import TEST_GPU_NONCE


@pytest.mark.asyncio
async def test_verify_gpu_evidence_success(sample_gpu_evidence):
    result = await verify_gpu_evidence(sample_gpu_evidence, TEST_GPU_NONCE)
    assert result.schema == "chutes.nvidia-verification-result"
    assert result.nonce == TEST_GPU_NONCE
    assert len(result.devices) == len(sample_gpu_evidence)


@pytest.mark.asyncio
async def test_verify_gpu_evidence_bad_nonce(sample_gpu_evidence):
    with pytest.raises(Exception):
        await verify_gpu_evidence(sample_gpu_evidence, "abcd1234")
