from pathlib import Path

from api import gpu_models


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "api/migrations/20260725120000_gpu_lifecycle_durability.sql"
PREFLIGHT = ROOT / "scripts/preflight_gpu_lifecycle_migration.sql"


def test_node_backfill_repairs_only_exact_lineage_and_lists_blocking_live_ids():
    migration = MIGRATION.read_text()
    preflight = PREFLIGHT.read_text()

    assert "reservation.gpu_uuids ? node.uuid" in migration
    assert "candidate.candidate_count = 1" in migration
    assert "gpu_retired_at IS NULL" in migration
    assert "string_agg(uuid::text, ', ' ORDER BY uuid::text)" in migration
    assert "blocking_live" in preflight
    assert "reservation_ids" in preflight
    assert (
        "current_reservation.allocation_group_id = allocation_group.allocation_group_id"
    ) in preflight
    assert (
        "current_reservation.allocation_group_generation = allocation_group.generation"
    ) in preflight
    assert "current_reservation.server_id = server.server_id" in preflight
    assert not any(
        token in preflight.upper()
        for token in ("UPDATE ", "DELETE ", "INSERT ", "ALTER ", "LOCK TABLE")
    )


def test_lifecycle_transition_trigger_is_cumulative_and_evidence_immutable():
    migration = MIGRATION.read_text()
    orm_ddl = str(gpu_models._GPU_LIFECYCLE_TRANSITION_FUNCTION)

    for source in (migration, orm_ddl):
        assert "GPU lifecycle failure evidence is immutable" in source
        assert "GPU lifecycle physical result is immutable" in source
        assert "GPU lifecycle receipt is immutable" in source
        assert "GPU lifecycle local-release ACK is immutable" in source
        assert "OLD.phase = 'receipt_accepted'" in source
        assert "NEW.phase IN ('local_release_acked', 'quarantined')" in source

    assert "phase = 'finalized' AND physical_result IS NOT NULL" in migration
    assert "receipt_accepted_at IS NOT NULL" in migration
    assert "local_release_acked_at IS NOT NULL" in migration


def test_create_all_installs_audit_function_before_dependent_audit_tables():
    source = (ROOT / "api/gpu_models.py").read_text()
    function_listener = source.index(
        'event.listen(\n    GpuLifecycleOperation.__table__,\n    "after_create",\n'
        "    _GPU_RECOVERY_AUDIT_FUNCTION"
    )
    authorization_trigger = source.index("trg_gpu_recovery_authorizations_immutable")
    event_trigger = source.index("trg_gpu_recovery_events_immutable")
    host_loss_trigger = source.index("trg_gpu_host_loss_events_immutable")

    assert function_listener < authorization_trigger
    assert function_listener < event_trigger
    assert function_listener < host_loss_trigger
