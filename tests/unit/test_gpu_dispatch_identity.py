"""Regressions for immutable platform GPU workload publication."""

from __future__ import annotations

from copy import deepcopy
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from api import gpu_scheduler
from api.host.gpu_allocations import (
    GpuAllocationError,
    _platform_workload_identity,
    _validated_platform_workload_identity,
)
from api.host.schemas import (
    GpuPlatformWorkloadIdentityV1,
    canonical_sha256,
)


_MANIFEST = f"sha256:{'a' * 64}"


def _workload_objects():
    chute = SimpleNamespace(
        chute_id="chute-1",
        user_id="chute-owner",
        image_id="image-1",
        version="version-1",
        revision="b" * 40,
        tee=True,
        disabled=False,
        ref_str="entrypoint:handler",
        chutes_version="0.6.1",
        allow_external_egress=False,
        standard_template=None,
        lock_modules=True,
        jobs=[
            {
                "name": "notebook",
                "ports": [
                    {"port": 8888, "proto": "http"},
                    {"port": 2202, "proto": "tcp"},
                ],
            }
        ],
    )
    image = SimpleNamespace(
        image_id="image-1",
        user_id="chute-owner",
        compute_type="gpu",
        status="built and pushed",
        user=SimpleNamespace(username="publisher"),
        name="image",
        tag="stable",
        patch_version="patch1",
    )
    job = SimpleNamespace(
        job_id="job-1",
        chute_id="chute-1",
        user_id="job-owner",
        version="version-1",
        chutes_version="0.6.1",
        finished_at=None,
        gpu_management_mode="platform",
        method="notebook",
        job_args={"_disk_gb": 64},
    )
    return chute, image, job


def _reservation(identity: GpuPlatformWorkloadIdentityV1):
    return SimpleNamespace(
        management_mode="platform",
        workload_identity=identity.model_dump(mode="json", exclude_none=True),
        workload_identity_sha256=canonical_sha256(identity),
        workload_owner=identity.workload_owner,
        chute_id=identity.chute_id,
        job_id=identity.job_id,
        chute_version=identity.chute_version,
        container_repository=identity.container_repository,
        container_manifest_digest=identity.container_manifest_digest,
    )


def test_platform_workload_snapshot_captures_version_ref_and_policy():
    chute, image, job = _workload_objects()
    identity = _platform_workload_identity(
        chute,
        image,
        job,
        image_username=image.user.username,
        manifest_digest=_MANIFEST,
    )

    assert identity.image_ref == "publisher/image:stable-patch1"
    assert identity.chute_version == "version-1"
    assert identity.ref_str == "entrypoint:handler"
    assert identity.chutes_version == "0.6.1"
    assert identity.lock_modules is True
    assert identity.allow_external_egress is False
    assert identity.disk_gb == 64
    assert [item.model_dump() for item in identity.job_ports] == [
        {"port": 8888, "proto": "http"},
        {"port": 2202, "proto": "tcp"},
    ]
    assert _validated_platform_workload_identity(_reservation(identity)) == identity


def test_every_published_mutable_field_changes_the_snapshot_or_fails_closed():
    chute, image, job = _workload_objects()
    original = _platform_workload_identity(
        chute,
        image,
        job,
        image_username=image.user.username,
        manifest_digest=_MANIFEST,
    )

    changed_chute, changed_image, changed_job = deepcopy((chute, image, job))
    changed_chute.ref_str = "entrypoint:replacement"
    assert (
        _platform_workload_identity(
            changed_chute,
            changed_image,
            changed_job,
            image_username=changed_image.user.username,
            manifest_digest=_MANIFEST,
        )
        != original
    )

    changed_chute, changed_image, changed_job = deepcopy((chute, image, job))
    changed_chute.allow_external_egress = True
    assert (
        _platform_workload_identity(
            changed_chute,
            changed_image,
            changed_job,
            image_username=changed_image.user.username,
            manifest_digest=_MANIFEST,
        )
        != original
    )

    changed_chute, changed_image, changed_job = deepcopy((chute, image, job))
    changed_image.tag = "replacement"
    assert (
        _platform_workload_identity(
            changed_chute,
            changed_image,
            changed_job,
            image_username=changed_image.user.username,
            manifest_digest=_MANIFEST,
        )
        != original
    )

    changed_chute, changed_image, changed_job = deepcopy((chute, image, job))
    changed_job.job_args["_disk_gb"] = 96
    assert (
        _platform_workload_identity(
            changed_chute,
            changed_image,
            changed_job,
            image_username=changed_image.user.username,
            manifest_digest=_MANIFEST,
        )
        != original
    )

    changed_chute, changed_image, changed_job = deepcopy((chute, image, job))
    changed_chute.version = "version-2"
    with pytest.raises(GpuAllocationError, match="job identity"):
        _platform_workload_identity(
            changed_chute,
            changed_image,
            changed_job,
            image_username=changed_image.user.username,
            manifest_digest=_MANIFEST,
        )


def test_platform_snapshot_hash_and_exact_shape_fail_closed():
    chute, image, job = _workload_objects()
    identity = _platform_workload_identity(
        chute,
        image,
        job,
        image_username=image.user.username,
        manifest_digest=_MANIFEST,
    )
    reservation = _reservation(identity)
    reservation.workload_identity_sha256 = "0" * 64
    with pytest.raises(GpuAllocationError, match="does not match"):
        _validated_platform_workload_identity(reservation)

    document = identity.model_dump(mode="json", exclude_none=True)
    document["unexpected"] = True
    with pytest.raises(ValueError):
        GpuPlatformWorkloadIdentityV1.model_validate(document)

    miner = SimpleNamespace(
        management_mode="miner",
        workload_identity=document,
        workload_identity_sha256=canonical_sha256(document),
    )
    with pytest.raises(GpuAllocationError, match="Miner GPU reservation"):
        _validated_platform_workload_identity(miner)


def test_dispatch_builds_snapshot_payload_before_commit_and_never_reloads_mutable_rows():
    source = inspect.getsource(gpu_scheduler._dispatch_workload)
    payload = source.index("command_payload =")
    commit = source.index("await session.commit()", payload)
    publish = source.index("await send_agent_command", commit)
    assert payload < commit < publish
    assert ".with_for_update(of=Chute)" in source
    assert ".with_for_update(of=Image)" in source
    after_commit = source[commit:publish]
    assert "chute." not in after_commit
    assert "job." not in after_commit
    assert "reservation." not in after_commit


def test_unshipped_scheduler_migration_owns_snapshot_columns_and_rollback_guard():
    root = Path(__file__).resolve().parents[2]
    sql = (
        root / "api/migrations/20260724100000_gpu_platform_scheduler.sql"
    ).read_text()
    assert "ADD COLUMN IF NOT EXISTS workload_identity JSONB" in sql
    assert "ADD COLUMN IF NOT EXISTS workload_identity_sha256 TEXT" in sql
    assert "jsonb_typeof(workload_identity) = 'object'" in sql
    assert "cannot migrate pre-identity platform GPU reservations" in sql
    assert "OR workload_identity IS NOT NULL" in sql
    assert "DROP COLUMN IF EXISTS workload_identity_sha256" in sql
    assert "DROP COLUMN IF EXISTS workload_identity" in sql
