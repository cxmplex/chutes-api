"""Producer-side byte and schema checks for shared GPU runtime fixtures."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from api.gpu_contracts import (
    GpuHotplugCommandAckV1,
    GpuHotplugCommandV1,
    GpuLifecycleOperationV1,
    GpuLocalReleaseAckV1,
    GpuPhysicalResultV1,
    GpuRecoveryAuthorizationEnvelopeV1,
    GpuRecoveryEventV1,
    GpuRegistrationNonceRequestV2,
    GpuRegistrationNonceV2,
    GpuRegistrationRequestV2,
    GpuRegistrationResponseV2,
    GpuResetReceiptV1,
    GpuSourceReaderResultV1,
)
from api.gpu_lifecycle_service import (
    GpuLifecycleError,
    gpu_lifecycle_intent_document,
    gpu_lifecycle_operation_response,
    gpu_recovery_authorization_bytes,
    gpu_recovery_authorization_document,
)
from api.gpu_models import GpuLifecycleOperation
from api.host.schemas import canonical_json_bytes, canonical_sha256

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "gpu_runtime_contracts_v1_v2.json"
_FIXTURE_SHA256 = "b4849121e3110fad7350dd79b764bf3cdc5dd7324b4de7fd48e1409414d4881f"


def _load_fixture() -> dict:
    raw = _FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _FIXTURE_SHA256
    document = json.loads(raw)
    assert raw == (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    assert document["schema"] == "chutes.gpu-runtime-contract-fixtures.v1"
    assert document["version"] == 1
    return document


def test_registration_v2_fixture_bytes_validate() -> None:
    registration = _load_fixture()["registration_v2"]
    GpuRegistrationNonceRequestV2.model_validate(registration["nonce_request"])
    GpuRegistrationNonceV2.model_validate(registration["nonce_issued"])
    GpuRegistrationNonceV2.model_validate(registration["nonce_claimed"])
    GpuRegistrationRequestV2.model_validate(registration["request"])
    for key in ("processing_response", "completed_response", "failed_response"):
        GpuRegistrationResponseV2.model_validate(registration[key])


def test_lifecycle_v1_fixture_bytes_validate() -> None:
    lifecycle = _load_fixture()["lifecycle_v1"]
    intents = [GpuLifecycleOperationV1.model_validate(item) for item in lifecycle["intents"]]
    assert [item.operation_type for item in intents] == [
        "pre_slot_claim_quarantine",
        "launch_rollback",
        "release_rollover",
        "normal_delete",
        "ownerless_group_recovery",
        "forced_dead_guest_recovery",
    ]
    for key in ("accepted_frontiers", "quarantined_frontiers"):
        for item in lifecycle[key]:
            GpuLifecycleOperationV1.model_validate(item)
    assert [item["phase"] for item in lifecycle["accepted_frontiers"]] == [
        "intent",
        "physical_result",
        "receipt_accepted",
        "local_release_acked",
        "finalized",
    ]
    assert all(
        item["phase"] == "quarantined" and item["failure_code"] and item["failure_reason"]
        for item in lifecycle["quarantined_frontiers"]
    )
    GpuPhysicalResultV1.model_validate(lifecycle["physical_result"])
    GpuPhysicalResultV1.model_validate(lifecycle["forced_physical_result"])
    GpuResetReceiptV1.model_validate(lifecycle["reset_receipt"])
    GpuLocalReleaseAckV1.model_validate(lifecycle["local_release_ack"])
    GpuSourceReaderResultV1.model_validate(lifecycle["source_reader_result"])
    GpuRecoveryAuthorizationEnvelopeV1.model_validate(lifecycle["recovery_authorization"])
    for event in lifecycle["recovery_events"]:
        GpuRecoveryEventV1.model_validate(event)
    GpuHotplugCommandV1.model_validate(lifecycle["hotplug_command"])
    GpuHotplugCommandAckV1.model_validate(lifecycle["hotplug_acked"])
    GpuHotplugCommandAckV1.model_validate(lifecycle["hotplug_failed"])


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (
            lambda ack: ack.pop("schema"),
            "Field required",
        ),
        (
            lambda ack: ack.pop("version"),
            "Field required",
        ),
        (
            lambda ack: ack["objects"][0]["source_identity"].pop("schema"),
            "Field required",
        ),
        (
            lambda ack: ack["objects"][0]["source_identity"].pop("version"),
            "Field required",
        ),
        (
            lambda ack: ack["objects"][0]["source_identity"].__setitem__("inode", "1001"),
            "integer",
        ),
        (
            lambda ack: ack["objects"][0].__setitem__("block_node_present", 1),
            "boolean",
        ),
        (
            lambda ack: ack["objects"][0].__setitem__("device_id", "gpu-legacy-cache-device"),
            "namespace binding tuple",
        ),
        (
            lambda ack: ack["objects"][1].__setitem__(
                "source_identity", deepcopy(ack["objects"][0]["source_identity"])
            ),
            "source identities must be distinct",
        ),
    ],
)
def test_hotplug_ack_shared_fixture_negatives_fail_closed(mutation, match) -> None:
    ack = deepcopy(_load_fixture()["lifecycle_v1"]["hotplug_acked"])
    mutation(ack)
    unsigned = {key: value for key, value in ack.items() if key != "ack_sha256"}
    ack["ack_sha256"] = canonical_sha256(unsigned)

    with pytest.raises((ValidationError, ValueError), match=match):
        GpuHotplugCommandAckV1.model_validate(ack)


def test_hotplug_source_identity_has_no_reboot_local_device_number() -> None:
    ack = GpuHotplugCommandAckV1.model_validate(_load_fixture()["lifecycle_v1"]["hotplug_acked"])

    assert all(
        set(item.source_identity.model_dump())
        == {
            "schema",
            "version",
            "filesystem_uuid",
            "inode",
            "size_bytes",
            "luks_uuid",
        }
        for item in ack.objects
    )


def test_lifecycle_dispatch_projection_matches_shared_fixture_bytes() -> None:
    lifecycle = _load_fixture()["lifecycle_v1"]
    response = GpuLifecycleOperationV1.model_validate(lifecycle["intents"][-1])
    expected = lifecycle["recovery_authorization"]["operation"]

    document = gpu_lifecycle_intent_document(response)

    assert document == expected
    assert canonical_json_bytes(document) == canonical_json_bytes(expected)
    assert not {"group_state", "created_at", "updated_at"}.intersection(document)


def test_recovery_authorization_uses_one_shared_canonical_document() -> None:
    lifecycle = _load_fixture()["lifecycle_v1"]
    expected = lifecycle["recovery_authorization"]
    envelope = GpuRecoveryAuthorizationEnvelopeV1.model_validate(expected)

    document = gpu_recovery_authorization_document(envelope)

    assert document == expected
    assert document["operation"] == gpu_lifecycle_intent_document(envelope.operation)
    assert gpu_recovery_authorization_bytes(envelope) == canonical_json_bytes(expected)


def test_recovery_authorization_omits_optional_fields_and_rejects_response_fields() -> None:
    lifecycle = _load_fixture()["lifecycle_v1"]
    reference = GpuRecoveryAuthorizationEnvelopeV1.model_validate(
        lifecycle["recovery_authorization"]
    )
    ownerless_response = GpuLifecycleOperationV1.model_validate(lifecycle["intents"][4])
    ownerless_intent = GpuLifecycleOperationV1.model_validate(
        gpu_lifecycle_intent_document(ownerless_response)
    )
    envelope = reference.model_copy(
        update={
            "authorization_id": ownerless_intent.recovery_authorization_id,
            "operation": ownerless_intent,
        }
    )

    document = gpu_recovery_authorization_document(envelope)

    assert not {
        "reservation_id",
        "reservation_generation",
        "claims_sha256",
        "process_incarnation",
        "stable_server_id",
        "management_mode",
        "migration_id",
    }.intersection(document["operation"])
    assert b"null" not in gpu_recovery_authorization_bytes(envelope)

    contaminated = envelope.model_copy(
        update={"operation": ownerless_intent.model_copy(update={"group_state": "resetting"})}
    )
    with pytest.raises(GpuLifecycleError, match="accepts an intent only"):
        gpu_recovery_authorization_document(contaminated)


@pytest.mark.asyncio
async def test_service_projection_matches_quarantined_fixture_bytes() -> None:
    item = _load_fixture()["lifecycle_v1"]["quarantined_frontiers"][-1]
    wire = GpuLifecycleOperationV1.model_validate(item)
    intent = gpu_lifecycle_intent_document(wire)
    row = GpuLifecycleOperation(
        operation_id=wire.operation_id,
        operation_type=wire.operation_type,
        phase=wire.phase,
        host_id=wire.host_id,
        host_key_generation=wire.host_key_generation,
        host_boot_generation=wire.host_boot_generation,
        allocation_group_id=wire.allocation_group_id,
        allocation_group_generation=wire.allocation_group_generation,
        reservation_id=wire.reservation_id,
        reservation_generation=wire.reservation_generation,
        claims_sha256=wire.claims_sha256,
        process_incarnation=wire.process_incarnation,
        topology_fingerprint=wire.topology_fingerprint,
        gpu_bdfs=wire.gpu_bdfs,
        gpu_uuids=wire.gpu_uuids,
        owner_hotkey=wire.owner_hotkey,
        stable_server_id=wire.stable_server_id,
        management_mode=wire.management_mode,
        migration_id=wire.migration_id,
        recovery_authorization_id=wire.recovery_authorization_id,
        intent=intent,
        intent_sha256="e" * 64,
        physical_result={"fixture": True},
        physical_result_sha256=wire.physical_result_sha256,
        result_outcome=wire.result_outcome,
        receipt_id=wire.receipt_id,
        receipt_sha256=wire.receipt_sha256,
        local_release_ack={"fixture": True},
        local_release_ack_sha256=wire.local_release_ack_sha256,
        reporting_state="quarantined",
        failure_code=wire.failure_code,
        failure_reason=wire.failure_reason,
        created_at=wire.created_at,
        updated_at=wire.updated_at,
        finalized_at=wire.finalized_at,
    )
    response = await gpu_lifecycle_operation_response(
        None, row, group=SimpleNamespace(state=wire.group_state)
    )
    assert response.model_dump(mode="json", exclude_none=True) == item


def test_quarantined_contract_requires_terminal_timestamp() -> None:
    item = dict(_load_fixture()["lifecycle_v1"]["quarantined_frontiers"][0])
    item.pop("finalized_at")
    with pytest.raises(ValueError, match="finalized_at"):
        GpuLifecycleOperationV1.model_validate(item)
