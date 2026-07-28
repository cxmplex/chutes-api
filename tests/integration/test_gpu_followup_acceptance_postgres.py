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
from api.host.schemas import GpuAllocationGroup, GpuLaunchReservation
from api.instance.schemas import Instance
from api.user.schemas import User
from tests.integration import test_gpu_allocations_postgres as gpu_pg
from tests.integration import test_gpu_migration_guards_postgres as migration_pg

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
    migrated_schema = migration_pg._create_schema(
        "registry_catalog_parity",
        migration_pg.REGISTRY_PREDECESSOR,
    )
    try:
        up, _down = migration_pg._migration(migration_pg.REGISTRY)
        migrated = migration_pg._apply(up, migrated_schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        fk_sql = """
        SELECT constraint_row.conname || '|' ||
               pg_get_constraintdef(constraint_row.oid, true)
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
         WHERE constraint_row.connamespace = current_schema()::regnamespace
           AND relation.relname = 'registry_sessions'
           AND constraint_row.contype = 'f'
           AND pg_get_constraintdef(constraint_row.oid, true)
               LIKE 'FOREIGN KEY (launch_config_id)%'
         ORDER BY constraint_row.conname;
        """
        create_all_fk = migration_pg._psql(fk_sql, schema)
        migrated_fk = migration_pg._psql(fk_sql, migrated_schema)
        assert create_all_fk.returncode == 0, create_all_fk.stderr.decode()
        assert migrated_fk.returncode == 0, migrated_fk.stderr.decode()
        assert create_all_fk.stdout == migrated_fk.stdout
        assert create_all_fk.stdout.count(b"fk_registry_session_launch_config") == 1
    finally:
        migration_pg._drop_schema(migrated_schema)


async def test_lifecycle_create_all_and_migration_catalogs_match(postgres_schema):
    _sessions, create_all_schema = postgres_schema
    migrated_schema = migration_pg._create_schema(
        "lifecycle_catalog_parity",
        migration_pg.LIFECYCLE_PREDECESSOR,
    )
    try:
        up, _down = migration_pg._migration(migration_pg.LIFECYCLE)
        migrated = migration_pg._apply(up, migrated_schema)
        assert migrated.returncode == 0, migrated.stderr.decode()
        catalog_sql = """
        SELECT table_name || '|' || column_name || '|' || udt_name || '|' ||
               COALESCE(character_maximum_length::text, '') || '|' ||
               COALESCE(column_default, '')
          FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND (table_name, column_name) IN (
               ('gpu_registration_nonces', 'state'),
               ('gpu_registration_attempts', 'state'),
               ('gpu_lifecycle_operations', 'phase'),
               ('gpu_lifecycle_operations', 'reporting_state'),
               ('gpu_recovery_authorizations', 'recovery_nonce')
           )
         ORDER BY table_name, column_name;
        SELECT indexname || '|' ||
               (indexdef LIKE '%(reservation_id, created_at DESC)%')::text
          FROM pg_indexes
         WHERE schemaname = current_schema()
           AND indexname = 'idx_gpu_registration_attempt_reservation';
        SELECT relation.relname || '|' || constraint_row.conname || '|' ||
               pg_get_constraintdef(constraint_row.oid, true)
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
         WHERE constraint_row.connamespace = current_schema()::regnamespace
           AND relation.relname = 'gpu_allocation_groups'
           AND constraint_row.conname = 'ck_gpu_allocation_group_failure';
        """
        create_all_catalog = migration_pg._psql(
            catalog_sql,
            create_all_schema,
        )
        migrated_catalog = migration_pg._psql(catalog_sql, migrated_schema)
        assert create_all_catalog.returncode == 0, create_all_catalog.stderr.decode()
        assert migrated_catalog.returncode == 0, migrated_catalog.stderr.decode()
        assert create_all_catalog.stdout == migrated_catalog.stdout
        assert b"idx_gpu_registration_attempt_reservation|true" in (
            migrated_catalog.stdout
        )
    finally:
        migration_pg._drop_schema(migrated_schema)


async def test_release_pending_inventory_failure_projection_is_narrow(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        "receipt_accepted",
    )

    async with sessions() as session:
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_allocation_groups
               SET failure_code = 'arbitrary_release_failure',
                   failure_reason = 'must not broaden the release frontier',
                   failure_metadata = '{"inventory_report_id":"report-arbitrary"}'::jsonb
             WHERE allocation_group_id = :group_id
            """,
            "ck_gpu_allocation_group_failure",
            {"group_id": operation.allocation_group_id},
        )
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_allocation_groups
               SET failure_code = 'gpu_inventory_changed_during_release',
                   failure_reason = 'metadata is mandatory'
             WHERE allocation_group_id = :group_id
            """,
            "ck_gpu_allocation_group_failure",
            {"group_id": operation.allocation_group_id},
        )
        await session.execute(
            text(
                """
                UPDATE gpu_allocation_groups
                   SET failure_code = 'gpu_inventory_changed_during_release',
                       failure_reason = 'current signed inventory conflicts',
                       failure_metadata = '{"inventory_report_id":"report-current"}'::jsonb
                 WHERE allocation_group_id = :group_id
                """
            ),
            {"group_id": operation.allocation_group_id},
        )
        await session.commit()

        group = await session.get(GpuAllocationGroup, operation.allocation_group_id)
        assert group.state == "release_pending"
        assert group.quarantined_at is None
        assert group.failure_code == "gpu_inventory_changed_during_release"
        assert group.failure_metadata == {"inventory_report_id": "report-current"}


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
        original_physical_sha256 = row.physical_result_sha256
        original_receipt_sha256 = row.receipt_sha256
        original_ack_sha256 = row.local_release_ack_sha256

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

        row.phase = "finalized"
        row.reporting_state = "finalized"
        row.finalized_at = datetime.now(timezone.utc)
        await session.commit()
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET phase = 'intent', reporting_state = 'pending'
             WHERE operation_id = :operation_id
            """,
            "terminal GPU lifecycle evidence is immutable",
            {"operation_id": row.operation_id},
        )

        await session.refresh(row)
        assert row.phase == "finalized"
        assert row.physical_result_sha256 == original_physical_sha256
        assert row.receipt_sha256 == original_receipt_sha256
        assert row.local_release_ack_sha256 == original_ack_sha256


@pytest.mark.parametrize(
    ("phase", "expected_message"),
    [
        ("receipt_accepted", "ck_gpu_lifecycle_result"),
        ("local_release_acked", "ck_gpu_lifecycle_result"),
        ("finalized", "terminal GPU lifecycle evidence is immutable"),
    ],
)
async def test_lifecycle_sql_rejects_failure_on_success_frontiers(
    postgres_schema,
    phase,
    expected_message,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    seed_phase = "local_release_acked" if phase == "finalized" else phase
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        seed_phase,
    )
    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        if phase == "finalized":
            row.phase = "finalized"
            row.reporting_state = "finalized"
            row.finalized_at = datetime.now(timezone.utc)
            await session.commit()
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET failure_code = 'contradictory_success_failure',
                   failure_reason = 'successful closure cannot carry failure evidence'
             WHERE operation_id = :operation_id
            """,
            expected_message,
            {"operation_id": operation.operation_id},
        )


@pytest.mark.parametrize(
    ("phase", "mutation"),
    [
        (
            "intent",
            "physical_result_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        ),
        ("physical_result", "receipt_accepted_at = NOW()"),
        (
            "receipt_accepted",
            "local_release_ack_sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
        ),
        ("local_release_acked", "finalized_at = NOW()"),
    ],
)
async def test_lifecycle_sql_rejects_orphan_digest_or_timestamp(
    postgres_schema,
    phase,
    mutation,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        phase,
    )
    async with sessions() as session:
        await _assert_sql_rejected(
            session,
            f"""
            UPDATE gpu_lifecycle_operations
               SET {mutation}
             WHERE operation_id = :operation_id
            """,
            "ck_gpu_lifecycle_result",
            {"operation_id": operation.operation_id},
        )


async def test_lifecycle_terminal_rows_reject_mutation_delete_and_truncate(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        "intent",
    )
    async with sessions() as session:
        row = await session.get(GpuLifecycleOperation, operation.operation_id)
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET phase = 'quarantined',
                   reporting_state = 'quarantined',
                   physical_result = '{}'::jsonb,
                   physical_result_sha256 = :physical_digest,
                   result_outcome = 'accepted',
                   receipt_id = 'fabricated-receipt',
                   receipt_sha256 = :receipt_digest,
                   receipt_accepted_at = NOW(),
                   local_release_ack = '{}'::jsonb,
                   local_release_ack_sha256 = :ack_digest,
                   local_release_acked_at = NOW(),
                   failure_code = 'fabricated_terminal_closure',
                   failure_reason = 'intent cannot synthesize reset closure',
                   finalized_at = NOW()
             WHERE operation_id = :operation_id
            """,
            "intent quarantine cannot acquire lifecycle closure evidence",
            {
                "operation_id": operation.operation_id,
                "physical_digest": "a" * 64,
                "receipt_digest": "b" * 64,
                "ack_digest": "c" * 64,
            },
        )
        now = datetime.now(timezone.utc)
        row.phase = "quarantined"
        row.reporting_state = "quarantined"
        row.failure_code = "focused_terminal_failure"
        row.failure_reason = "focused evidence-less terminal state"
        row.finalized_at = now
        await session.commit()

        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET physical_result = '{}'::jsonb,
                   physical_result_sha256 = :physical_digest,
                   result_outcome = 'accepted',
                   receipt_id = 'late-receipt',
                   receipt_sha256 = :receipt_digest,
                   receipt_accepted_at = NOW()
             WHERE operation_id = :operation_id
            """,
            "terminal GPU lifecycle evidence is immutable",
            {
                "operation_id": operation.operation_id,
                "physical_digest": "c" * 64,
                "receipt_digest": "d" * 64,
            },
        )
        await _assert_sql_rejected(
            session,
            "DELETE FROM gpu_lifecycle_operations WHERE operation_id = :operation_id",
            "GPU lifecycle operations are immutable audit rows",
            {"operation_id": operation.operation_id},
        )
        await _assert_sql_rejected(
            session,
            "TRUNCATE TABLE gpu_lifecycle_operations CASCADE",
            "GPU lifecycle operations are immutable audit rows",
        )


async def test_physical_result_quarantine_cannot_claim_accepted_receipt(
    postgres_schema,
):
    sessions, _schema = postgres_schema
    await gpu_pg._seed(sessions)
    operation, _result, _receipt, _ack = await gpu_pg._seed_ordinary_lifecycle_phase(
        sessions,
        "physical_result",
    )
    async with sessions() as session:
        await _assert_sql_rejected(
            session,
            """
            UPDATE gpu_lifecycle_operations
               SET phase = 'quarantined',
                   reporting_state = 'quarantined',
                   result_outcome = 'accepted',
                   receipt_id = 'fabricated-accepted-receipt',
                   receipt_sha256 = :receipt_digest,
                   receipt_accepted_at = NOW(),
                   failure_code = 'fabricated_accepted_result',
                   failure_reason = 'physical-result quarantine must reject acceptance',
                   finalized_at = NOW()
             WHERE operation_id = :operation_id
            """,
            "physical-result quarantine has invalid receipt or ACK evidence",
            {
                "operation_id": operation.operation_id,
                "receipt_digest": "d" * 64,
            },
        )
