"""Mode-specific Registration V2 UUID-selection contract tests."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from api.gpu_contracts import GpuRegistrationRequestV2
from api.host.schemas import GpuLaunchReservationClaimsV1, canonical_sha256

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "gpu_runtime_contracts_v1_v2.json"
_SECOND_UUID = "GPU-00000000-0000-0000-0000-000000000002"
_THIRD_UUID = "GPU-00000000-0000-0000-0000-000000000003"


def _request_document(mode: str, selected_uuids: list[str]) -> dict:
    document = copy.deepcopy(json.loads(_FIXTURE.read_text())["registration_v2"]["request"] )
    claims = document["quote_commitment"]["claims"]
    claims["gpu_bdfs"] = ["0000:01:00.0", "0000:02:00.0"]
    claims["gpu_uuids"] = [claims["gpu_uuids"][0], _SECOND_UUID]
    claims["gpu_identifiers"] = ["b200", "b200"]
    claims["gpu_attestation_certificate_sha256s"] = ["1" * 64, "2" * 64]
    claims["management_mode"] = mode
    if mode == "miner":
        claims["chute_id"] = None
        claims["job_id"] = None
        claims["container_repository"] = None
        claims["container_manifest_digest"] = None
        claims["descriptor_closure_sha256"] = None
        claims["allowed_manifests"] = []
        claims["allowed_blobs"] = []
        claims["allowed_manifest_tags"] = []
        claims["manifest_tag_digests"] = {}
        claims["miner_hourly_cost"] = 12.5
    validated_claims = GpuLaunchReservationClaimsV1.model_validate(claims)
    document["quote_commitment"]["claims"] = validated_claims.model_dump(
        mode="json", exclude_none=True
    )
    document["quote_commitment"]["reservation_sha256"] = canonical_sha256(
        validated_claims
    )
    document["gpu_uuids"] = selected_uuids
    document["gpu_evidence"] = [
        {"evidence": f"selected-{index}"}
        for index, _uuid in enumerate(selected_uuids, start=1)
    ] or [{"evidence": "pydantic-minimum-placeholder"}]
    return document


def test_platform_registration_accepts_only_exact_reservation_uuid_set() -> None:
    exact = _request_document(
        "platform",
        ["GPU-00000000-0000-0000-0000-000000000001", _SECOND_UUID],
    )
    assert GpuRegistrationRequestV2.model_validate(exact).gpu_uuids == exact["gpu_uuids"]

    strict_subset = _request_document(
        "platform", ["GPU-00000000-0000-0000-0000-000000000001"]
    )
    with pytest.raises(ValidationError, match="management mode"):
        GpuRegistrationRequestV2.model_validate(strict_subset)

    superset = _request_document(
        "platform",
        [
            "GPU-00000000-0000-0000-0000-000000000001",
            _SECOND_UUID,
            _THIRD_UUID,
        ],
    )
    with pytest.raises(ValidationError, match="management mode"):
        GpuRegistrationRequestV2.model_validate(superset)


def test_miner_registration_accepts_only_nonempty_reservation_subset() -> None:
    subset = _request_document(
        "miner", ["GPU-00000000-0000-0000-0000-000000000001"]
    )
    assert GpuRegistrationRequestV2.model_validate(subset).gpu_uuids == subset["gpu_uuids"]

    cross_lineage = _request_document("miner", [_THIRD_UUID])
    with pytest.raises(ValidationError, match="management mode"):
        GpuRegistrationRequestV2.model_validate(cross_lineage)

    empty = _request_document("miner", [])
    with pytest.raises(ValidationError, match="at least 1 item"):
        GpuRegistrationRequestV2.model_validate(empty)
