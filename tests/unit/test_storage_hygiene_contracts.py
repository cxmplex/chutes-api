"""Strict API contracts for trusted ChuteFS accounting and erasure."""

import base64
import uuid

import pytest
from pydantic import ValidationError

from api.config import _max_plaintext_for_ciphertext_limit, settings
from api.storage.schemas import (
    CommitObjectRequest,
    CreateVolumeRequest,
    EraseTaskResultRequest,
    GrantRequest,
    InventoryObject,
    LegacyReplicaAdoptionReceipt,
    PlacementRequest,
    ReplicaPlacementUpdate,
    ReplicationCapabilityCompleteRequest,
    ReplicationCapabilityIssueRequest,
)


def test_api_plaintext_limit_fits_node_ciphertext_limit_after_framing():
    assert settings.storage_max_object_bytes <= _max_plaintext_for_ciphertext_limit(
        settings.storage_max_ciphertext_bytes
    )


def test_volume_owner_cannot_choose_quota():
    with pytest.raises(ValidationError, match="quota_bytes"):
        CreateVolumeRequest(
            name="volume",
            replication_factor=3,
            quota_bytes=10**18,
        )


def test_commit_rejects_client_accounting_and_hash_fields():
    salt = base64.b64encode(b"s" * 32).decode()
    with pytest.raises(ValidationError):
        CommitObjectRequest(
            object_id="generation",
            key="key",
            salt=salt,
            size_bytes=0,
            sha256="a" * 64,
            plaintext_sha256="b" * 64,
            holder_server_ids=["holder"],
        )
    assert (
        CommitObjectRequest(
            object_id="generation",
            key="key",
            salt=salt,
        ).object_id
        == "generation"
    )


@pytest.mark.parametrize("size", [True, -1, 9_223_372_036_854_775_808])
def test_placement_size_bounds_are_strict(size):
    with pytest.raises(ValidationError):
        PlacementRequest(
            request_id=str(uuid.uuid4()),
            key="key",
            size_bytes=size,
        )


def test_direct_receipt_requires_exact_plaintext_and_ciphertext_evidence():
    with pytest.raises(ValidationError):
        ReplicaPlacementUpdate(
            object_id="generation",
            status="stored",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=10,
        )
    receipt = ReplicaPlacementUpdate(
        object_id="generation",
        status="stored",
        ciphertext_sha256="A" * 64,
        ciphertext_size_bytes=10,
        plaintext_size_bytes=0,
        plaintext_sha256="B" * 64,
    )
    assert receipt.ciphertext_sha256 == "a" * 64
    assert receipt.plaintext_sha256 == "b" * 64


@pytest.mark.parametrize("size", [True, -1, 9_223_372_036_854_775_808])
@pytest.mark.parametrize(
    "factory",
    [
        lambda size: InventoryObject(
            volume_id="volume",
            object_id="generation",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=size,
        ),
        lambda size: ReplicaPlacementUpdate(
            object_id="generation",
            status="stored",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=size,
            plaintext_size_bytes=1,
            plaintext_sha256="b" * 64,
        ),
        lambda size: LegacyReplicaAdoptionReceipt(
            object_id="generation",
            result="verified",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=size,
            plaintext_size_bytes=1,
            plaintext_sha256="b" * 64,
        ),
        lambda size: LegacyReplicaAdoptionReceipt(
            object_id="generation",
            result="verified",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=1,
            plaintext_size_bytes=size,
            plaintext_sha256="b" * 64,
        ),
        lambda size: ReplicationCapabilityIssueRequest(
            object_id="generation",
            target_server_id="target",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=size,
        ),
        lambda size: ReplicationCapabilityCompleteRequest(
            capability="capability",
            ciphertext_sha256="a" * 64,
            ciphertext_size_bytes=size,
        ),
    ],
)
def test_all_plaintext_and_ciphertext_requests_reject_non_bigint_sizes(factory, size):
    with pytest.raises(ValidationError):
        factory(size)


@pytest.mark.parametrize("digest", ["", "a" * 63, "g" * 64])
def test_inventory_rejects_malformed_hashes(digest):
    with pytest.raises(ValidationError):
        InventoryObject(
            volume_id="volume",
            object_id="generation",
            ciphertext_sha256=digest,
            ciphertext_size_bytes=1,
        )


def test_erase_ack_and_failure_have_explicit_evidence():
    with pytest.raises(ValidationError):
        EraseTaskResultRequest(status="erased")
    with pytest.raises(ValidationError):
        EraseTaskResultRequest(status="failed")
    assert EraseTaskResultRequest(status="erased", file_was_present=False).file_was_present is False


def test_owner_grants_are_single_operation_for_semantic_api_key_scopes():
    with pytest.raises(ValidationError, match="exactly one"):
        GrantRequest(volume_id="volume", ops=["get", "put"])
