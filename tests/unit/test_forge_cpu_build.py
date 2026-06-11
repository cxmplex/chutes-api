"""Unit tests for the CPU-TEE branch of the image forge (api/image/forge.py).

CPU-TEE chutes ship NO confidential-runtime layer (no aegis/netnanny/cfsv/inspecto/
graval): the Trust Domain is the security boundary. These tests run
build_and_push_image with buildah/push subprocesses faked and assert the generated
Dockerfiles + skipped stages differ correctly between cpu=True and cpu=False images.
"""

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import api.image.forge as forge


class _FakeStream:
    async def readline(self):
        return b""


class _FakeProcess:
    def __init__(self):
        self.stdout = _FakeStream()
        self.stderr = _FakeStream()
        self.returncode = 0

    async def wait(self):
        return 0

    async def communicate(self):
        return b"", b""

    def kill(self):
        pass


def _image(cpu: bool):
    image = MagicMock()
    image.user.username = "TestUser"
    image.name = "testimage"  # not sglang/vllm: skips the chutes_user_id branch
    image.tag = "0.1"
    image.patch_version = None
    image.chutes_version = "0.6.10"
    image.image_id = "img-1"
    image.cpu = cpu
    image.user_id = "user-1"
    return image


@pytest.fixture
def forge_env(tmp_path):
    """Build dir + patched settings/subprocesses; returns handles for assertions."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "Dockerfile").write_text("FROM scratch\n")
    cfsv_stub = tmp_path / "cfsv_v4"
    cfsv_stub.write_bytes(b"#!/bin/sh\n")

    settings = MagicMock()
    settings.registry_host = "registry:5000"
    settings.registry_insecure = True
    settings.build_timeout = 60
    settings.push_timeout = 60
    settings.redis_client.client.xadd = AsyncMock()

    calls = []

    async def fake_exec(*argv, **kwargs):
        calls.append(list(argv))
        return _FakeProcess()

    extract = AsyncMock(
        return_value=("/tmp/fsv.data", {"pkg": "hash"}, "inspecto-hash", None, None)
    )
    upload_fsv = AsyncMock()

    with (
        patch("api.image.forge.settings", settings),
        patch("api.image.forge.CFSV_V4_PATH", str(cfsv_stub)),
        patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        patch("api.image.forge.trivy_image_scan", AsyncMock()),
        patch("api.image.forge.sign_image", AsyncMock()),
        patch("api.image.forge.extract_cfsv_data_from_verification_image", extract),
        patch("api.image.forge.upload_filesystem_verification_data", upload_fsv),
        patch("api.image.forge.upload_bytecode_manifest", AsyncMock()),
        patch("api.image.forge.upload_bytecode_manifest_json", AsyncMock()),
    ):
        yield SimpleNamespace(
            build_dir=str(build_dir),
            calls=calls,
            extract=extract,
            upload_fsv=upload_fsv,
        )


def _build_invocations(calls):
    return [argv for argv in calls if argv[:2] == ["buildah", "build"]]


def _push_invocations(calls):
    return [argv for argv in calls if "push" in argv[:3]]


def _dockerfile(env, name):
    with open(os.path.join(env.build_dir, name)) as infile:
        return infile.read()


class TestCpuBuildBranch:
    @pytest.mark.asyncio
    async def test_cpu_image_skips_confidential_runtime(self, forge_env):
        short_tag = await forge.build_and_push_image(_image(cpu=True), forge_env.build_dir)
        assert short_tag == "testuser/testimage:0.1"

        chutes_df = _dockerfile(forge_env, "Dockerfile.chutes")
        # Base chutes SDK, never the gpu extra (no graval/CUDA/torch).
        assert "RUN pip install chutes==0.6.10" in chutes_df
        assert "chutes[gpu]" not in chutes_df
        # No LD_PRELOAD .so injection of any kind.
        assert "chutes-aegis.so" not in chutes_df
        assert "chutes-netnanny.so" not in chutes_df
        assert "chutes-cfsv.so" not in chutes_df
        # The no-aegis runtime needs writable /cache + /app prepared at build time.
        assert "mkdir -p /cache && chmod 1777 /cache" in chutes_df
        assert "mkdir -p /app && chown -R chutes:chutes /app" in chutes_df

        final_df = _dockerfile(forge_env, "Dockerfile.final")
        # No filesystem-verification stage, index, bytecode manifest, or ld.so.preload.
        assert "as fsv" not in final_df
        assert "chutesfs.index" not in final_df
        assert "bytecode.manifest" not in final_df
        assert "ld.so.preload" not in final_df
        assert "LD_PRELOAD" not in final_df
        assert final_df.rstrip().endswith("ENTRYPOINT []")

        # Three builds (original, chutes-inject, final) -- the fsv build never runs.
        assert len(_build_invocations(forge_env.calls)) == 3
        forge_env.extract.assert_not_awaited()
        forge_env.upload_fsv.assert_not_awaited()
        # The image is still pushed.
        assert len(_push_invocations(forge_env.calls)) == 1

    @pytest.mark.asyncio
    async def test_gpu_image_keeps_confidential_runtime(self, forge_env):
        image = _image(cpu=False)
        short_tag = await forge.build_and_push_image(image, forge_env.build_dir)
        assert short_tag == "testuser/testimage:0.1"

        chutes_df = _dockerfile(forge_env, "Dockerfile.chutes")
        assert "pip install 'chutes[gpu]==0.6.10'" in chutes_df
        # chutes >= 0.5.5: aegis injected and preloaded.
        assert "chutes-aegis.so" in chutes_df
        assert "LD_PRELOAD=/usr/local/lib/chutes-aegis.so" in chutes_df

        final_df = _dockerfile(forge_env, "Dockerfile.final")
        assert "as fsv" in final_df
        assert "COPY --from=fsv /etc/chutesfs.index /etc/chutesfs.index" in final_df
        assert "ld.so.preload" in final_df

        # Four builds: original, chutes-inject, filesystem-verification, final.
        assert len(_build_invocations(forge_env.calls)) == 4
        forge_env.extract.assert_awaited_once()
        forge_env.upload_fsv.assert_awaited_once()
        # cfsv extraction results recorded on the image row.
        assert image.inspecto == "inspecto-hash"
        assert image.package_hashes == {"pkg": "hash"}
