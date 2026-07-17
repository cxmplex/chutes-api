from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.instance.schemas import LaunchConfigArgs, LaunchConfigResponse


with patch("ctypes.CDLL", return_value=MagicMock()):
    from api.instance.router import (
        MIN_SECURE_SOURCE_RUNTIME_VERSION,
        _require_secure_source_delivery,
    )


def _chute(version):
    return SimpleNamespace(chute_id="chute-id", chutes_version=version)


def test_launch_config_schemas_have_no_miner_source_submission_field():
    assert "code" not in LaunchConfigArgs.model_fields
    assert "run_code" not in LaunchConfigArgs.model_fields
    assert set(LaunchConfigResponse.model_fields) == {"token", "config_id"}


@pytest.mark.parametrize(
    "version",
    [None, "", "garbage", "0.3.60", "0.3.60.rc1"],
)
def test_legacy_source_delivery_versions_fail_closed(version):
    with pytest.raises(HTTPException) as exc_info:
        _require_secure_source_delivery(_chute(version))

    assert exc_info.value.status_code == 400
    assert "Unsupported chutes runtime version" in exc_info.value.detail
    assert (
        f"minimum supported version is {MIN_SECURE_SOURCE_RUNTIME_VERSION}" in exc_info.value.detail
    )
    assert "Legacy miner-mounted source delivery has been removed" in exc_info.value.detail


@pytest.mark.parametrize("version", ["0.3.61", "0.3.61.rc1", "0.3.62"])
def test_secure_launch_delivery_boundary_is_supported(version):
    _require_secure_source_delivery(_chute(version))
