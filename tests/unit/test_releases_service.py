"""Unit tests for the fleet image release service -- the activation measurement-pin gate + manifest.

The gate is the load-bearing safety property: a release may only become the fleet's desired state if
the validator already has the measurements its images attest as pinned, so a rollout can never point
the fleet at an image whose attestation can't be verified.
"""

from unittest.mock import AsyncMock, patch

import pytest

from api.releases import service as rsvc
from api.releases.schemas import (
    RELEASE_STATUS_ACTIVE,
    RELEASE_STATUS_DRAFT,
    GuestRelease,
)


def _pinned(*names):
    """Patch the gate's view of pinned measurement names (tee_measurements is a computed property)."""
    return patch.object(rsvc, "_loaded_measurement_names", return_value=set(names))


def _release(**images):
    return GuestRelease(
        release_id="rel-1",
        channel="stable",
        tee_type="sev-snp",
        status=RELEASE_STATUS_DRAFT,
        images=images,
    )


def _db(release):
    db = AsyncMock()
    db.get = AsyncMock(return_value=release)
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _chute(names, sha="a" * 64):
    return {"url": "http://x/y.qcow2", "sha256": sha, "measurement_names": list(names)}


@pytest.mark.asyncio
async def test_activate_refused_when_measurement_not_pinned():
    rel = _release(chute=_chute(["cpu-snp-1.7.0"]))
    db = _db(rel)
    with _pinned("cpu-snp-1.6.0"):
        with pytest.raises(rsvc.ReleaseError, match="not pinned"):
            await rsvc.activate_release(db, "rel-1")
    assert rel.status == RELEASE_STATUS_DRAFT  # left untouched -> no partial activation
    assert not db.commit.called


@pytest.mark.asyncio
async def test_activate_refused_when_storage_measurement_missing():
    """The gate must consider the storage image's measurements too, not just the chute image."""
    rel = _release(
        chute=_chute(["cpu-snp-1.6.0"]),
        storage=_chute(["storage-snp-1.7.0"]),
    )
    db = _db(rel)
    with _pinned("cpu-snp-1.6.0"):
        with pytest.raises(rsvc.ReleaseError, match="storage-snp-1.7.0"):
            await rsvc.activate_release(db, "rel-1")


@pytest.mark.asyncio
async def test_activate_refused_when_no_measurement_names():
    rel = _release(chute=_chute([]))
    db = _db(rel)
    with _pinned("cpu-snp-1.6.0"):
        with pytest.raises(rsvc.ReleaseError, match="no measurement names"):
            await rsvc.activate_release(db, "rel-1")


@pytest.mark.asyncio
async def test_activate_succeeds_when_all_measurements_pinned():
    rel = _release(
        chute=_chute(["cpu-snp-1.6.0"]),
        storage=_chute(["storage-snp-1.6.0"]),
    )
    db = _db(rel)
    with _pinned("cpu-snp-1.6.0", "storage-snp-1.6.0"):
        out = await rsvc.activate_release(db, "rel-1")
    assert out.status == RELEASE_STATUS_ACTIVE
    assert out.activated_at is not None
    assert db.execute.called  # supersede-prior-active UPDATE issued
    assert db.commit.called


@pytest.mark.asyncio
async def test_activate_missing_release_raises():
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)
    with pytest.raises(rsvc.ReleaseError, match="not found"):
        await rsvc.activate_release(db, "nope")


@pytest.mark.asyncio
async def test_already_active_is_idempotent():
    rel = _release(chute=_chute(["cpu-snp-1.6.0"]))
    rel.status = RELEASE_STATUS_ACTIVE
    db = _db(rel)
    out = await rsvc.activate_release(db, "rel-1")
    assert out.status == RELEASE_STATUS_ACTIVE
    assert not db.commit.called  # no-op, no re-supersede


def test_release_manifest_shapes_chute_and_storage():
    rel = _release(
        chute={"url": "http://x/c.qcow2", "sha256": "c" * 64, "version": "1.6.1", "measurement_names": ["m1"]},
        storage={"url": "http://x/s.qcow2", "sha256": "d" * 64, "measurement_names": ["m2"]},
    )
    m = rsvc.release_manifest(rel)
    assert m.release_id == "rel-1" and m.tee_type == "sev-snp"
    assert m.chute.url == "http://x/c.qcow2" and m.chute.sha256 == "c" * 64
    assert m.storage.sha256 == "d" * 64


def test_release_manifest_chute_only():
    rel = _release(chute={"url": "http://x/c.qcow2", "sha256": "c" * 64, "measurement_names": ["m1"]})
    m = rsvc.release_manifest(rel)
    assert m.chute is not None and m.storage is None
