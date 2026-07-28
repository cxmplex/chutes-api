"""Focused real-PostgreSQL acceptance checks for follow-up GPU fences."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from api.chute.schemas import Chute
from api.gpu_models import GpuLifecycleOperation
from api.host.gpu_allocations import _retire_gpu_runtime_lineage
from api.host.schemas import GpuLaunchReservation
from api.instance.schemas import Instance
from api.user.schemas import User
from tests.integration import test_gpu_allocations_postgres as gpu_pg

postgres_schema = gpu_pg.postgres_schema
unsigned_debug_provenance = gpu_pg.unsigned_debug_provenance

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.getenv("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL is required for GPU follow-up acceptance tests",
    ),
]


@pytest.fixture(autouse=True)
def nv_attest():
    """These database-state tests never invoke the external evidence verifier."""
    yield


async def _assert_sql_rejected(
    session,
    statement: str,
    expected_message: str,
    parameters: dict | None = None,
) -> None:
    with pytest.raises(DBAPIError) as captured:
        async with session.begin_nested():
            await session.execute(text(statement), parameters or {})
    assert expected_message in str(captured.value.orig)


async def test_create_all_then_registry_migration_has_one_named_launch_fk(
    postgres_schema,
):
    sessions, schema = postgres_schema
    await gpu_pg._apply_migration(
        schema,
        "up",
        "20260724100500_registry_launch_scope.sql",
    )

    async with sessions() as session:
        names = (
            (
                await session.execute(
                    text(
                        """
                        SELECT constraint_row.conname
                          FROM pg_constraint AS constraint_row
                          JOIN pg_class AS relation
                            ON relation.oid = constraint_row.conrelid
                          JOIN pg_namespace AS namespace
                            ON namespace.oid = relation.relnamespace
                         WHERE namespace.nspname = current_schema()
                           AND relation.relname = 'registry_sessions'
                           AND constraint_row.contype = 'f'
                           AND EXISTS (
                               SELECT 1
                                 FROM unnest(constraint_row.conkey) AS key(attnum)
                                 JOIN pg_attribute AS attribute
                                   ON attribute.attrelid = relation.oid
                                  AND attribute.attnum = key.attnum
                                WHERE attribute.attname = 'launch_config_id'
                           )
                         ORDER BY constraint_row.conname
                        """
                    )
                )
            )
            .scalars()
            .all()
        )

    assert names == ["fk_registry_session_launch_config"]


async def test_gpu_runtime_billing_cutoff_is_first_write_wins(postgres_schema):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    response = await gpu_pg._seed_running_miner_nodes(sessions)
    first_cutoff = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
    later_receipt = first_cutoff + timedelta(hours=6)

    async with sessions() as session:
        await session.execute(
            User.__table__.insert().values(
                user_id="billing-user",
                coldkey="billing-coldkey",
                username="billing-user",
                fingerprint_hash="billing-fingerprint",
            )
        )
        await session.execute(
            Chute.__table__.insert().values(
                chute_id="billing-chute",
                user_id="billing-user",
                name="billing-chute",
                cords=[],
                node_selector={"compute_type": "gpu", "gpu_count": 8},
                code="from chutes import Chute",
                filename="billing.py",
                ref_str="billing:chute",
                version="1",
            )
        )
        instance = Instance(
            instance_id="billing-instance",
            host="192.0.2.80",
            port=8000,
            chute_id="billing-chute",
            version="1",
            miner_uid=1,
            miner_hotkey=response.claims.owner_hotkey,
            miner_coldkey="billing-coldkey",
            active=True,
            verified=True,
            activated_at=first_cutoff - timedelta(hours=1),
            server_id=response.claims.server_id,
            gpu_management_mode="miner",
            gpu_launch_reservation_id=response.claims.reservation_id,
            gpu_allocation_group_id=response.claims.allocation_group_id,
            gpu_allocation_group_generation=(
                response.claims.allocation_group_generation
            ),
            gpu_process_incarnation=response.claims.process_incarnation,
        )
        session.add(instance)
        await session.commit()

        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        await _retire_gpu_runtime_lineage(
            session,
            reservation,
            first_cutoff,
            reason="control-plane fence",
        )
        await session.commit()
        await session.refresh(instance)
        assert instance.stop_billing_at == first_cutoff.replace(tzinfo=None)

        reservation = await session.get(
            GpuLaunchReservation,
            response.claims.reservation_id,
        )
        await _retire_gpu_runtime_lineage(
            session,
            reservation,
            later_receipt,
            reason="late physical-reset receipt",
        )
        await session.commit()
        await session.refresh(instance)
        assert instance.stop_billing_at == first_cutoff.replace(tzinfo=None)


async def test_lifecycle_sql_rejects_skipped_phase(postgres_schema):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        "intent",
    )

    async with sessions() as session:
        await _assert_sql_rejected(
            session,
            """
            INSERT INTO gpu_lifecycle_operations(
                operation_id, operation_type, phase, reporting_state,
                host_id, host_key_generation, host_boot_generation,
                allocation_group_id, allocation_group_generation,
                topology_fingerprint, gpu_bdfs, gpu_uuids, owner_hotkey,
                intent, intent_sha256, physical_result, physical_result_sha256
            )
            SELECT
                :new_operation_id, operation_type, 'physical_result',
                'physical_result', host_id, host_key_generation,
                host_boot_generation, allocation_group_id,
                allocation_group_generation + 1, topology_fingerprint,
                gpu_bdfs, gpu_uuids, owner_hotkey, intent, intent_sha256,
                '{}'::jsonb, :physical_result_sha256
              FROM gpu_lifecycle_operations
             WHERE operation_id = :operation_id
            """,
            "GPU lifecycle operations must begin at intent",
            {
                "new_operation_id": "non-intent-direct-insert",
                "operation_id": operation.operation_id,
                "physical_result_sha256": "a" * 64,
            },
        )
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET phase = 'receipt_accepted',
                   reporting_state = 'receipt_accepted'
             WHERE operation_id = :operation_id
            """,
            "invalid GPU lifecycle phase transition intent -> receipt_accepted",
            {"operation_id": operation.operation_id},
        )


async def test_lifecycle_sql_rejects_regression_and_evidence_mutation(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        "local_release_acked",
    )

    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        row.phase = "finalized"
        row.reporting_state = "finalized"
        row.finalized_at = datetime.now(timezone.utc)
        await session.commit()

        original_physical_sha256 = row.physical_result_sha256
        original_receipt_sha256 = row.receipt_sha256
        original_ack_sha256 = row.local_release_ack_sha256

        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET phase = 'intent', reporting_state = 'pending'
             WHERE operation_id = :operation_id
            """,
            "invalid GPU lifecycle phase transition finalized -> intent",
            {"operation_id": row.operation_id},
        )
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET physical_result = physical_result || '{"tampered": true}'::jsonb,
                   physical_result_sha256 = :digest
             WHERE operation_id = :operation_id
            """,
            "GPU lifecycle physical result is immutable",
            {"operation_id": row.operation_id, "digest": "b" * 64},
        )
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET receipt_sha256 = :digest
             WHERE operation_id = :operation_id
            """,
            "GPU lifecycle receipt is immutable",
            {"operation_id": row.operation_id, "digest": "c" * 64},
        )
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET local_release_ack_sha256 = :digest
             WHERE operation_id = :operation_id
            """,
            "GPU lifecycle local-release ACK is immutable",
            {"operation_id": row.operation_id, "digest": "d" * 64},
        )

        await session.refresh(row)
        assert row.phase == "finalized"
        assert row.physical_result_sha256 == original_physical_sha256
        assert row.receipt_sha256 == original_receipt_sha256
        assert row.local_release_ack_sha256 == original_ack_sha256
