"""Static catalog contracts shared by ORM bootstrap and unshipped SQL migrations."""

from pathlib import Path

import pytest

from api.host.schemas import RegistrySession, TdLaunchReservation
from api.instance.schemas import Instance, LaunchConfig
from api.node.schemas import Node
from api.server.schemas import Server, ServerAttestation, ServerAttestationSubject


MIGRATIONS = Path(__file__).resolve().parents[2] / "api/migrations"


def _foreign_key(model, column_name):
    foreign_keys = list(model.__table__.columns[column_name].foreign_keys)
    assert len(foreign_keys) == 1
    return foreign_keys[0]


@pytest.mark.parametrize(
    ("model", "column", "name", "ondelete"),
    [
        (Server, "launch_reservation_id", "fk_servers_launch_reservation", "RESTRICT"),
        (
            Server,
            "gpu_launch_reservation_id",
            "fk_servers_gpu_launch_reservation",
            "RESTRICT",
        ),
        (
            Server,
            "gpu_allocation_group_id",
            "fk_servers_gpu_allocation_group",
            "RESTRICT",
        ),
        (Instance, "server_id", "fk_instances_server", "SET NULL"),
        (
            Instance,
            "gpu_launch_reservation_id",
            "fk_instances_gpu_launch_reservation",
            "RESTRICT",
        ),
        (
            Instance,
            "gpu_allocation_group_id",
            "fk_instances_gpu_allocation_group",
            "RESTRICT",
        ),
        (LaunchConfig, "server_id", "fk_launch_configs_server", "RESTRICT"),
        (
            LaunchConfig,
            "gpu_launch_reservation_id",
            "fk_launch_configs_gpu_launch_reservation",
            "RESTRICT",
        ),
        (
            Node,
            "gpu_allocation_group_id",
            "fk_nodes_gpu_allocation_group",
            "RESTRICT",
        ),
    ],
)
def test_lineage_foreign_keys_are_explicit_and_match_immutable_delete_policy(
    model, column, name, ondelete
):
    foreign_key = _foreign_key(model, column)
    assert foreign_key.constraint.name == name
    assert foreign_key.ondelete == ondelete


def test_unshipped_migrations_create_the_same_named_lineage_constraints():
    migration_sources = "\n".join(
        (MIGRATIONS / migration).read_text()
        for migration in (
            "20260529160000_instance_server_id.sql",
            "20260720200000_seedless_model_b.sql",
            "20260723050000_gpu_allocation_groups.sql",
            "20260724100000_gpu_platform_scheduler.sql",
        )
    )
    for constraint_name in (
        "fk_servers_launch_reservation",
        "fk_servers_gpu_launch_reservation",
        "fk_servers_gpu_allocation_group",
        "fk_instances_server",
        "fk_instances_gpu_launch_reservation",
        "fk_instances_gpu_allocation_group",
        "fk_launch_configs_server",
        "fk_launch_configs_gpu_launch_reservation",
        "fk_nodes_gpu_allocation_group",
    ):
        assert f"ADD CONSTRAINT {constraint_name}" in migration_sources
    server_migration = (MIGRATIONS / "20260529160000_instance_server_id.sql").read_text()
    assert (
        "CONSTRAINT fk_launch_configs_server\n"
        "            FOREIGN KEY (server_id) REFERENCES servers(server_id) ON DELETE RESTRICT"
        in server_migration
    )


def test_registry_closure_check_matches_final_manifest_tag_shape():
    check = next(
        constraint
        for constraint in RegistrySession.__table__.constraints
        if constraint.name == "ck_registry_session_closure"
    )
    orm_expression = str(check.sqltext)
    assert "jsonb_typeof(manifest_tag_digests) = 'object'" in orm_expression

    migration = (MIGRATIONS / "20260724100000_gpu_platform_scheduler.sql").read_text()
    up, down = migration.split("-- migrate:down", maxsplit=1)
    registry_rewrite = up.split(
        "ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS ck_registry_session_closure;",
        maxsplit=1,
    )[1]
    assert "jsonb_typeof(manifest_tag_digests) = 'object'" in registry_rewrite
    assert down.index("DROP CONSTRAINT IF EXISTS ck_registry_session_closure") < down.index(
        "DROP COLUMN IF EXISTS manifest_tag_digests"
    )
    restored = down.split("ADD CONSTRAINT ck_registry_session_closure", maxsplit=1)[1].split(
        "DROP COLUMN IF EXISTS manifest_tag_digests", maxsplit=1
    )[0]
    assert "manifest_tag_digests" not in restored


def test_attestation_attempt_order_is_database_generated_and_catalog_aligned():
    column = ServerAttestation.__table__.columns["attempt_sequence"]
    assert column.nullable is False
    assert "server_attestation_attempt_sequence" in str(column.server_default.arg)
    index = next(
        item
        for item in ServerAttestation.__table__.indexes
        if item.name == "idx_server_attestations_attempt_sequence"
    )
    assert index.unique is True

    migration = (MIGRATIONS / "20260714070000_release_attestation_identity.sql").read_text()
    up = migration.split("-- migrate:down", maxsplit=1)[0]
    assert "CREATE SEQUENCE server_attestation_attempt_sequence" in up
    assert "partial server attestation attempt sequence catalog" in up
    assert "server_attestation_attempt_sequence has invalid identity" in up
    assert "idx_server_attestations_attempt_sequence has invalid definition" in up
    assert "ROW_NUMBER() OVER" in up
    assert "ORDER BY created_at ASC NULLS LAST, attestation_id ASC" in up
    assert "SET DEFAULT nextval(''server_attestation_attempt_sequence''::regclass)" in up
    assert "ON server_attestations (server_id, attempt_sequence DESC)" in up

    release_index = next(
        item
        for item in ServerAttestation.__table__.indexes
        if item.name == "idx_server_attestations_release_identity"
    )
    assert release_index.dialect_options["postgresql"]["include"] == [
        "measurement_name",
        "measurement_version",
        "measurement_config_fingerprint",
        "trust_set_fingerprint",
        "verification_error",
        "verified_at",
    ]
    trust_migration = (
        (MIGRATIONS / "20260714100000_attestation_trust_fingerprints.sql")
        .read_text()
        .split("-- migrate:down", maxsplit=1)[0]
    )
    release_rebuild = trust_migration.split(
        "DROP INDEX IF EXISTS idx_server_attestations_release_identity;", maxsplit=1
    )[1]
    for included in release_index.dialect_options["postgresql"]["include"]:
        assert included in release_rebuild
    assert "ON server_attestations (server_id, attempt_sequence DESC)" in release_rebuild

    gpu_migration = (
        (MIGRATIONS / "20260724100000_gpu_platform_scheduler.sql")
        .read_text()
        .split("-- migrate:down", maxsplit=1)[0]
    )
    gpu_index = gpu_migration.split(
        "CREATE INDEX IF NOT EXISTS idx_server_attestations_gpu_lineage",
        maxsplit=1,
    )[1].split(";", maxsplit=1)[0]
    assert "attempt_sequence DESC" in gpu_index
    assert "created_at DESC" not in gpu_index


def test_attestation_subject_and_model_b_attribution_catalogs_are_fail_closed():
    subject_fk = next(
        foreign_key
        for foreign_key in ServerAttestation.__table__.columns["server_id"].foreign_keys
        if foreign_key.constraint.name == "fk_server_attestations_subject"
    )
    assert subject_fk.constraint.name == "fk_server_attestations_subject"
    assert subject_fk.target_fullname == "server_attestation_subjects.server_id"
    assert subject_fk.ondelete == "RESTRICT"
    assert Server.runtime_attestations.property.viewonly is True
    assert ServerAttestation.server.property.viewonly is True

    subject_constraints = {
        constraint.name for constraint in ServerAttestationSubject.__table__.constraints
    }
    assert {
        "uq_server_attestation_subject_owner",
        "ck_server_attestation_subject_compute_type",
        "ck_server_attestation_subject_tee_type",
        "ck_server_attestation_subject_deployment_model",
    }.issubset(subject_constraints)
    attestation_constraints = {
        constraint.name for constraint in ServerAttestation.__table__.constraints
    }
    assert {
        "fk_server_attestations_attribution_owner",
        "fk_server_attestations_td_reservation_attribution",
        "ck_server_attestation_attribution",
    }.issubset(attestation_constraints)
    reservation_constraints = {
        constraint.name for constraint in TdLaunchReservation.__table__.constraints
    }
    assert "uq_td_launch_reservation_attribution" in reservation_constraints

    identity_migration = (
        MIGRATIONS / "20260714070000_release_attestation_identity.sql"
    ).read_text()
    identity_up, identity_down = identity_migration.split("-- migrate:down", maxsplit=1)
    for marker in (
        "CREATE TABLE IF NOT EXISTS server_attestation_subjects",
        "pg_get_constraintdef(actual.oid, TRUE)",
        "expected exact legacy or final server attestation FK shape",
        "ADD CONSTRAINT fk_server_attestations_subject",
        "ON CONFLICT (server_id) DO NOTHING",
        "CREATE TRIGGER enforce_server_attestation_subject",
        "CREATE TRIGGER preserve_server_attestation_audit",
        "CREATE TRIGGER preserve_server_attestation_subject_identity",
        "has invalid trigger shape",
        "NEW.attestation_id IS DISTINCT FROM OLD.attestation_id",
        "NEW.created_at IS DISTINCT FROM OLD.created_at",
    ):
        assert marker in identity_up
    assert "LEFT JOIN servers AS server_row" in identity_down
    assert "cannot restore legacy attestation FK" in identity_down
    assert "ON DELETE CASCADE" in identity_down

    seedless = (MIGRATIONS / "20260720200000_seedless_model_b.sql").read_text()
    seedless_up, seedless_down = seedless.split("-- migrate:down", maxsplit=1)
    for marker in (
        "uq_td_launch_reservation_attribution",
        "ADD COLUMN IF NOT EXISTS attribution_reservation_id VARCHAR",
        "ADD COLUMN IF NOT EXISTS attribution_owner_hotkey VARCHAR",
        "pg_get_constraintdef(actual.oid, TRUE)",
        "server attestation attribution check has an unexpected name",
        "ADD CONSTRAINT fk_server_attestations_attribution_owner",
        "ADD CONSTRAINT fk_server_attestations_td_reservation_attribution",
        "has invalid or duplicate authority",
    ):
        assert marker in seedless_up
    assert seedless_down.index(
        "DROP CONSTRAINT IF EXISTS fk_server_attestations_td_reservation_attribution"
    ) < seedless_down.index("DROP TABLE IF EXISTS td_launch_reservations")


def test_default_volume_migration_contains_final_unshipped_authority_shape():
    migration = (MIGRATIONS / "20260724234500_gpu_chutefs_default_volume.sql").read_text()
    up = migration.split("-- migrate:down", maxsplit=1)[0]
    session_table = up.split("CREATE TABLE IF NOT EXISTS chutefs_launch_sessions (", maxsplit=1)[
        1
    ].split(");", maxsplit=1)[0]
    assert "revocation_epoch               BIGINT NOT NULL," in session_table
    assert "revocation_epoch               BIGINT NOT NULL DEFAULT" not in session_table
    scope = up.split("CONSTRAINT ck_chutefs_launch_session_scope CHECK (", maxsplit=1)[1].split(
        "CONSTRAINT ck_chutefs_launch_session_access_hash", maxsplit=1
    )[0]
    assert "attested_cert_pubkey_hash ~ '^[0-9a-f]{64}$'" in scope
    identity = up.split(
        "CREATE OR REPLACE FUNCTION enforce_chutefs_launch_session_identity()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    for field in (
        "attestation_id",
        "generation",
        "revocation_epoch",
        "access_token_hash",
        "refresh_token_hash",
        "reexchange_token_hash",
        "access_expires_at",
        "refresh_expires_at",
        "rotated_at",
    ):
        assert f"NEW.{field} IS DISTINCT FROM OLD.{field}" in identity
    server_change = up.split(
        "CREATE OR REPLACE FUNCTION revoke_chutefs_session_on_server_change()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    assert "NEW.attested_cert_pubkey_hash" in server_change
    trigger = up.split("CREATE TRIGGER trg_revoke_chutefs_session_on_server_change", maxsplit=1)[
        1
    ].split(";", maxsplit=1)[0]
    assert "attested_cert_pubkey_hash ON servers" in trigger
    terminal = up.split(
        "CREATE OR REPLACE FUNCTION revoke_registry_scope_on_launch_terminal()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    assert "NEW.completed_at IS NOT NULL" in terminal
