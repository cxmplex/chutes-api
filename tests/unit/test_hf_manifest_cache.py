from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from api.misc import router
from api.util import extract_hf_model_name


COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


class FakeRedis:
    def __init__(self):
        self.now = 0
        self.values = {}

    async def get(self, key):
        value = self.values.get(key)
        if value is None:
            return None
        payload, expires = value
        if expires is not None and expires <= self.now:
            self.values.pop(key, None)
            return None
        return payload

    async def set(self, key, value, ex=None):
        self.values[key] = (value, self.now + ex if ex is not None else None)

    async def delete(self, key):
        self.values.pop(key, None)


@pytest.mark.asyncio
async def test_mutable_ref_revalidates_while_commit_manifest_stays_cached():
    redis = FakeRedis()
    resolutions = iter([COMMIT_A, COMMIT_B])
    fetched = []

    def resolve(*_args):
        return next(resolutions)

    def manifest(repo_id, repo_type, commit, _token):
        fetched.append(commit)
        return {
            "repo_id": repo_id,
            "repo_type": repo_type,
            "revision": commit,
            "commit_hash": commit,
            "files": [],
            "directories": [],
        }

    with (
        patch.object(router.settings, "_redis_client", redis),
        patch.object(router, "get_one", AsyncMock(return_value=object())),
        patch.object(router, "_resolve_repo_revision_sync", side_effect=resolve),
        patch.object(router, "_fetch_repo_manifest_sync", side_effect=manifest),
    ):
        first = await router.get_hf_repo_info(
            repo_id="org/model",
            repo_type="model",
            revision="main",
            x_hf_token=None,
        )
        assert first["commit_hash"] == COMMIT_A

        redis.now += router.HF_REF_CACHE_TTL_SECONDS + 1
        second = await router.get_hf_repo_info(
            repo_id="org/model",
            repo_type="model",
            revision="main",
            x_hf_token=None,
        )
        assert second["commit_hash"] == COMMIT_B

        immutable = await router.get_hf_repo_info(
            repo_id="org/model",
            repo_type="model",
            revision=COMMIT_A,
            x_hf_token=None,
        )
        assert immutable["commit_hash"] == COMMIT_A

    assert fetched == [COMMIT_A, COMMIT_B]
    immutable_entries = [
        (key, expires) for key, (_value, expires) in redis.values.items() if ":commit:" in key
    ]
    assert immutable_entries and all(expires is None for _key, expires in immutable_entries)


def test_manifest_includes_underscore_prefixed_files_at_immutable_commit():
    api = Mock()
    api.list_repo_tree.return_value = [
        SimpleNamespace(
            path="__init__.py",
            size=3,
            lfs=None,
            blob_id="c" * 40,
        )
    ]
    with patch.object(router, "HfApi", return_value=api):
        result = router._fetch_repo_manifest_sync("org/model", "model", COMMIT_A, None)

    assert result["commit_hash"] == COMMIT_A
    assert result["files"] == [
        {
            "path": "__init__.py",
            "size": 3,
            "blob_id": "c" * 40,
            "is_lfs": False,
        }
    ]
    api.list_repo_tree.assert_called_once_with(
        repo_id="org/model",
        revision=COMMIT_A,
        repo_type="model",
        recursive=True,
    )


@pytest.mark.parametrize(
    ("builder", "keyword"),
    [
        ("build_vllm_chute", "model_name"),
        ("build_sglang_chute", "model_name"),
        ("build_embedding_chute", "model_name"),
        ("build_diffusion_chute", "model_name_or_url"),
    ],
)
def test_all_model_templates_expose_literal_repo_for_launch_bound_access(builder, keyword):
    code = (
        f"from chutes.chute.template import {builder}\nchute = {builder}({keyword}='org/model')\n"
    )
    assert extract_hf_model_name(f"chute-{builder}", code) == "org/model"
