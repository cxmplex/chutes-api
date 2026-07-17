from typing import get_args
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.chute.schemas import NodeSelector
from api.image.forge import upload_filesystem_verification_data
from api.image.response import ImageResponse, MinimalImageResponse
from api.image.router import create_image
from api.image.schemas import Image
from api.image.util import image_id_for


def test_image_identity_includes_compute_type():
    cpu_id = image_id_for("Alice", "model", "v1", "cpu")
    gpu_id = image_id_for("alice", "model", "v1", "gpu")
    assert cpu_id != gpu_id
    assert cpu_id == image_id_for("ALICE", "model", "V1", "CPU")


def test_image_schema_and_responses_use_compute_type_only():
    assert "compute_type" in Image.__table__.columns
    assert "artifact_id" in Image.__table__.columns
    assert "cpu" not in Image.__table__.columns
    assert "compute_type" in ImageResponse.model_fields
    assert "compute_type" in MinimalImageResponse.model_fields
    assert "artifact_id" not in ImageResponse.model_fields
    assert "artifact_id" not in MinimalImageResponse.model_fields


@pytest.mark.asyncio
async def test_existing_image_artifacts_keep_their_pre_cutover_namespace():
    image = SimpleNamespace(
        image_id="canonical-compute-id",
        artifact_id="legacy-build-id",
        patch_version="initial",
    )
    s3 = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = s3

    forge_settings = SimpleNamespace(
        storage_bucket="test-bucket",
        s3_client=lambda: context,
    )
    with patch("api.image.forge.settings", forge_settings):
        await upload_filesystem_verification_data(image, "/tmp/chutesfs.data")

    s3.upload_file.assert_awaited_once()
    assert s3.upload_file.await_args.args[2] == "image_hash_blobs/legacy-build-id/initial.data"


def test_build_request_requires_exact_compute_type_literal():
    field = create_image.__annotations__["compute_type"]
    assert set(get_args(field)) == {"cpu", "gpu"}


def test_node_selector_contract_is_explicit_for_sdk_parity():
    assert set(NodeSelector.model_fields) == {
        "compute_type",
        "gpu_count",
        "min_vram_gb_per_gpu",
        "max_hourly_price_per_gpu",
        "exclude",
        "include",
        "dynamic",
        "cpu_cores",
        "ram_gb",
        "min_benchmark_score",
    }
