from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.image import remote_forge


class _Process:
    returncode = 0

    def kill(self):
        return None

    async def communicate(self):
        return b"", b""


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Session:
    def __init__(self, image):
        self.image = image

    async def execute(self, _query):
        return _Result(self.image)

    async def refresh(self, _image, _attrs=None):
        return None


class _SessionContext:
    def __init__(self, image):
        self.session = _Session(image)

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *_args):
        return False


@pytest.mark.asyncio
async def test_remote_cpu_build_skips_gpu_runtime_and_cfsv(tmp_path):
    build_dir = Path(tmp_path)
    (build_dir / "Dockerfile").write_text("FROM scratch\n")
    image = MagicMock()
    image.user.username = "alice"
    image.user.has_role.return_value = True
    image.name = "cpu-image"
    image.tag = "v1"
    image.patch_version = None
    image.chutes_version = "0.6.10"
    image.image_id = "image-1"
    image.compute_type = "cpu"

    settings = MagicMock()
    settings.build_timeout = 60
    settings.redis_client.client.xadd = AsyncMock()
    build_calls = []

    async def depot_build(args, cwd, capture_logs, timeout):
        build_calls.append(args)
        if "--metadata-file" in args:
            Path(args[args.index("--metadata-file") + 1]).write_text('{"buildID":"build-1"}')
        return _Process()

    with (
        patch.object(remote_forge, "settings", settings),
        patch.object(
            remote_forge,
            "_safe_intermediate_tag",
            AsyncMock(side_effect=["forgebuild-original", "forgebuild-chutes"]),
        ),
        patch.object(remote_forge, "_depot_build", side_effect=depot_build),
        patch.object(remote_forge, "_depot_push", AsyncMock()),
        patch.object(remote_forge, "trivy_image_scan", AsyncMock()),
        patch.object(remote_forge, "sign_image", AsyncMock()),
        patch.object(remote_forge, "_stream_status", AsyncMock()),
    ):
        result = await remote_forge.build_and_push_image(image, str(build_dir))

    assert result == "alice/cpu-image:v1"
    assert len(build_calls) == 3
    chutes_dockerfile = (build_dir / "Dockerfile.chutes").read_text()
    assert "pip install chutes==0.6.10" in chutes_dockerfile
    assert "chutes[gpu]" not in chutes_dockerfile
    assert "chutes-aegis" not in chutes_dockerfile
    assert "chutes-netnanny" not in chutes_dockerfile
    assert "mkdir -p /cache" in chutes_dockerfile
    final_dockerfile = (build_dir / "Dockerfile.final").read_text()
    assert "chutesfs.index" not in final_dockerfile
    assert "bytecode.manifest" not in final_dockerfile
    assert not (build_dir / "Dockerfile.fsv").exists()


@pytest.mark.asyncio
async def test_remote_cpu_update_dispatches_cpu_safe_patch_path():
    image = MagicMock()
    image.image_id = "image-1"
    image.compute_type = "cpu"
    image.chutes_version = "0.6.9"
    image.user.username = "alice"
    cpu_update = AsyncMock()

    with (
        patch.object(remote_forge, "get_session", return_value=_SessionContext(image)),
        patch.object(remote_forge, "_update_cpu_chutes_lib", cpu_update),
        patch.object(remote_forge, "_copy_cfsv_binary") as copy_cfsv,
    ):
        await remote_forge._update_chutes_lib("image-1", "0.6.10")

    cpu_update.assert_awaited_once()
    copy_cfsv.assert_not_called()
