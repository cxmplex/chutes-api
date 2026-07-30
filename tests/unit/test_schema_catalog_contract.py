"""Static catalog contracts shared by ORM bootstrap and unshipped SQL migrations."""

from pathlib import Path

import pytest

from api.host.schemas import RegistrySession
from api.instance.schemas import Instance, LaunchConfig
from api.node.schemas import Node
from api.server.schemas import Server


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
    server_migration = (
        MIGRATIONS / "20260529160000_instance_server_id.sql"
    ).read_text()
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

    migration = (
        MIGRATIONS / "20260724100000_gpu_platform_scheduler.sql"
    ).read_text()
    up, down = migration.split("-- migrate:down", maxsplit=1)
    registry_rewrite = up.split(
        "ALTER TABLE registry_sessions DROP CONSTRAINT IF EXISTS "
        "ck_registry_session_closure;",
        maxsplit=1,
    )[1]
    assert "jsonb_typeof(manifest_tag_digests) = 'object'" in registry_rewrite
    assert down.index("DROP CONSTRAINT IF EXISTS ck_registry_session_closure") < down.index(
        "DROP COLUMN IF EXISTS manifest_tag_digests"
    )
    restored = down.split(
        "ADD CONSTRAINT ck_registry_session_closure", maxsplit=1
    )[1].split("DROP COLUMN IF EXISTS manifest_tag_digests", maxsplit=1)[0]
    assert "manifest_tag_digests" not in restored


def test_default_volume_migration_contains_final_unshipped_authority_shape():
    migration = (
        MIGRATIONS / "20260724234500_gpu_chutefs_default_volume.sql"
    ).read_text()
    up = migration.split("-- migrate:down", maxsplit=1)[0]
    scope = up.split(
        "CONSTRAINT ck_chutefs_launch_session_scope CHECK (", maxsplit=1
    )[1].split("CONSTRAINT ck_chutefs_launch_session_access_hash", maxsplit=1)[0]
    assert "attested_cert_pubkey_hash ~ '^[0-9a-f]{64}$'" in scope
    identity = up.split(
        "CREATE OR REPLACE FUNCTION enforce_chutefs_launch_session_identity()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    for field in (
        "attestation_id",
        "generation",
        "access_token_hash",
        "refresh_token_hash",
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
    trigger = up.split(
        "CREATE TRIGGER trg_revoke_chutefs_session_on_server_change", maxsplit=1
    )[1].split(";", maxsplit=1)[0]
    assert "attested_cert_pubkey_hash ON servers" in trigger
    terminal = up.split(
        "CREATE OR REPLACE FUNCTION revoke_registry_scope_on_launch_terminal()",
        maxsplit=1,
    )[1].split("$$;", maxsplit=1)[0]
    assert "NEW.completed_at IS NOT NULL" in terminal
