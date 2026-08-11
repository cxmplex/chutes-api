"""Exact, schema-independent catalog contract for the immutable production base.

The production-base SQL deliberately operates on a small set of raw PostgreSQL objects that
SQLAlchemy cannot model.  This module collects only that reviewed allowlist, normalizes schema
qualification, and compares the result with the checked-in fresh-install manifest.  Objects not
owned by the production-base contract are intentionally ignored.
"""

from __future__ import annotations

import difflib
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from sqlalchemy import text


CATALOG_FORMAT_VERSION = 1
CATALOG_MANIFEST_PATH = Path(__file__).with_name("production_base_catalog.json")
PRODUCTION_BASE_SQL_PATH = Path(__file__).with_name("production_base.sql")
PRODUCTION_BASE_CATALOG_SHA256 = (
    "f332c557e993529c54ae45b726375edd8d73f590b6f0a91e00323a5146b90416"
)
SCHEMA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
DAILY_REVENUE_SUMMARY_HISTORICAL_VARIANT = "historical_subscription_history"
DAILY_REVENUE_SUMMARY_QUOTA_VARIANT = "quota_current_activation_approximation"
DAILY_REVENUE_SUMMARY_HISTORICAL_MD5 = "1ead487721cab340a03ffc40397ea6e5"
DAILY_REVENUE_SUMMARY_QUOTA_COMMENT = (
    "Compatibility cache only: current paid invocation-quota activations; "
    "not authoritative historical subscription revenue."
)

OWNED_RELATIONS = (
    "audit_entries",
    "bounties",
    "bounty_history",
    "chute_manual_boosts",
    "daily_instance_revenue",
    "daily_revenue_summary",
    "diffusion_metrics",
    "inference_sponsorships",
    "instance_audit",
    "instance_compute_history",
    "instance_node_history",
    "invocations",
    "node_history",
    "p_llm_metrics",
    "partitioned_invocations",
    "sponsorship_chutes",
    "user_current_balance",
    "vllm_metrics",
)

RAW_RELATIONS = (
    "audit_entries",
    "bounties",
    "bounty_history",
    "chute_manual_boosts",
    "diffusion_metrics",
    "inference_sponsorships",
    "instance_audit",
    "instance_compute_history",
    "instance_node_history",
    "node_history",
    "p_llm_metrics",
    "partitioned_invocations",
    "sponsorship_chutes",
    "vllm_metrics",
)

OWNED_VIEWS = (
    "daily_instance_revenue",
    "daily_revenue_summary",
    "invocations",
    "user_current_balance",
)

OWNED_INDEXES = (
    "idx_audit_date",
    "idx_audit_path",
    "idx_billing_ia",
    "idx_chute_history_chute_id",
    "idx_daily_instance_revenue_date",
    "idx_daily_revenue_summary_date",
    "idx_ich_instance_open",
    "idx_ich_instance_time",
    "idx_ich_time_range",
    "idx_image_history_image_id",
    "idx_instance_audit_miner",
    "idx_instance_audit_ts",
    "idx_instance_node_history_hk_node",
    "idx_instance_node_history_instance_id",
    "idx_instance_node_history_miner_hotkey",
    "idx_instance_node_history_node_id",
    "idx_inv_chute_err",
    "idx_inv_id",
    "idx_inv_response",
    "idx_model_aliases_user_alias_lower",
    "idx_node_history_node_id",
    "idx_p_llm_metrics_date",
    "idx_parent_inv_id",
    "idx_user_current_balance_user_id",
    "idx_user_fingerprint_hash",
)

# Function identity is determined only by input argument types.  Argument names and defaults are
# captured separately and therefore cannot drift silently.
OWNED_FUNCTION_IDENTITIES = (
    ("backfill_llm_metrics", "date, date"),
    ("create_llm_metrics_part", "date"),
    ("fn_chute_history_delete", ""),
    ("fn_chute_history_insert", ""),
    ("fn_chute_history_update", ""),
    ("fn_image_history_delete", ""),
    ("fn_image_history_insert", ""),
    ("fn_image_history_update", ""),
    ("fn_instance_audit_delete", ""),
    ("fn_instance_audit_insert", ""),
    ("fn_instance_audit_update", ""),
    ("fn_instance_compute_history_delete", ""),
    ("fn_instance_compute_history_update", ""),
    ("fn_node_history_delete", ""),
    ("fn_node_history_insert", ""),
    ("fn_reset_job_assignment", ""),
    ("gen_llm_metrics_for_day", "date"),
    ("get_diffusion_metrics", "date, date"),
    ("get_llm_metrics", "date, date"),
    ("increase_bounty", "text"),
    ("initialize_bounty", ""),
    ("insert_invocation", ""),
    ("populate_llm_metrics_for_day", "date"),
    ("refresh_llm_metrics_for_day", "date"),
    ("track_instance_node_assignment", ""),
    ("update_balance_on_instance_delete", ""),
    ("version_numbers", "text"),
)

OWNED_TRIGGERS = (
    "after_chute_insert",
    "invocations_insert_trigger",
    "tr_chute_history_delete",
    "tr_chute_history_insert",
    "tr_chute_history_update",
    "tr_ich_delete",
    "tr_ich_update",
    "tr_image_history_delete",
    "tr_image_history_insert",
    "tr_image_history_update",
    "tr_instance_audit_delete",
    "tr_instance_audit_insert",
    "tr_instance_audit_update",
    "tr_node_history_delete",
    "tr_node_history_insert",
    "tr_reset_jobs_on_fail",
    "track_instance_node_assignment_trigger",
    "trigger_update_balance_on_delete",
)

PARTITION_FAMILY_INDEXES = {
    "p_llm_metrics": (
        "idx_p_llm_metrics_date",
        "p_llm_metrics_pkey",
    ),
    "partitioned_invocations": (
        "idx_inv_chute_err",
        "idx_inv_id",
        "idx_inv_response",
        "idx_parent_inv_id",
    ),
}
PARTITION_FAMILY_PREFIXES = {
    "p_llm_metrics": "p_llm_metrics_",
    "partitioned_invocations": "partitioned_invocations_",
}

RAW_CONSTRAINT_IDENTITIES = (
    ("audit_entries", "audit_entries_pkey", "p"),
    ("bounties", "bounties_chute_id_fkey", "f"),
    ("bounties", "bounties_pkey", "p"),
    ("bounty_history", "bounty_history_pkey", "p"),
    ("chute_manual_boosts", "chute_manual_boosts_pkey", "p"),
    ("inference_sponsorships", "inference_sponsorships_pkey", "p"),
    ("instance_audit", "instance_audit_pkey", "p"),
    ("instance_compute_history", "instance_compute_history_pkey", "p"),
    ("instance_node_history", "instance_node_history_pkey", "p"),
    ("node_history", "node_history_pkey", "p"),
    ("p_llm_metrics", "p_llm_metrics_pkey", "p"),
    ("sponsorship_chutes", "sponsorship_chutes_pkey", "p"),
    (
        "sponsorship_chutes",
        "sponsorship_chutes_sponsorship_id_fkey",
        "f",
    ),
)

RAW_INDEX_IDENTITIES = (
    ("audit_entries", "audit_entries_pkey"),
    ("audit_entries", "idx_audit_date"),
    ("audit_entries", "idx_audit_path"),
    ("bounties", "bounties_pkey"),
    ("bounty_history", "bounty_history_pkey"),
    ("chute_manual_boosts", "chute_manual_boosts_pkey"),
    ("inference_sponsorships", "inference_sponsorships_pkey"),
    ("instance_audit", "idx_billing_ia"),
    ("instance_audit", "idx_instance_audit_miner"),
    ("instance_audit", "idx_instance_audit_ts"),
    ("instance_audit", "instance_audit_pkey"),
    ("instance_compute_history", "idx_ich_instance_open"),
    ("instance_compute_history", "idx_ich_instance_time"),
    ("instance_compute_history", "idx_ich_time_range"),
    ("instance_compute_history", "instance_compute_history_pkey"),
    ("instance_node_history", "idx_instance_node_history_hk_node"),
    ("instance_node_history", "idx_instance_node_history_instance_id"),
    ("instance_node_history", "idx_instance_node_history_miner_hotkey"),
    ("instance_node_history", "idx_instance_node_history_node_id"),
    ("instance_node_history", "instance_node_history_pkey"),
    ("node_history", "idx_node_history_node_id"),
    ("node_history", "node_history_pkey"),
    ("p_llm_metrics", "idx_p_llm_metrics_date"),
    ("p_llm_metrics", "p_llm_metrics_pkey"),
    ("partitioned_invocations", "idx_inv_chute_err"),
    ("partitioned_invocations", "idx_inv_id"),
    ("partitioned_invocations", "idx_inv_response"),
    ("partitioned_invocations", "idx_parent_inv_id"),
    ("sponsorship_chutes", "sponsorship_chutes_pkey"),
)


class ProductionBaseCatalogMismatch(RuntimeError):
    """The installed production-base catalog differs from the immutable manifest."""


def _assert_schema_name(schema: str) -> None:
    if not SCHEMA_NAME.fullmatch(schema):
        raise ValueError(f"unsafe PostgreSQL schema name: {schema!r}")


def normalize_catalog_sql(value: Any, schema: str) -> str | None:
    """Normalize generated PostgreSQL DDL for human-readable catalog evidence."""

    if value is None:
        return None
    rendered = str(value)
    rendered = rendered.replace(f'"{schema}".', "<schema>.")
    rendered = rendered.replace(f"{schema}.", "<schema>.")
    return " ".join(rendered.split())


def function_body_sha256(body: str) -> str:
    """Fingerprint exact ``pg_proc.prosrc`` bytes without schema-dependent rewriting."""

    if not isinstance(body, str):
        raise TypeError("PostgreSQL function body must be text")
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def production_base_contract_sha256(sql_sha256: str) -> str:
    """Derive the marker digest from the reviewed SQL and catalog-manifest byte hashes."""

    if not re.fullmatch(r"[0-9a-f]{64}", sql_sha256):
        raise ValueError("production-base SQL digest must be lowercase SHA256 hex")
    payload = (
        b"production-base-contract-v1\0"
        + bytes.fromhex(sql_sha256)
        + bytes.fromhex(PRODUCTION_BASE_CATALOG_SHA256)
    )
    return hashlib.sha256(payload).hexdigest()


def _normalize_sql(value: Any, schema: str) -> str | None:
    return normalize_catalog_sql(value, schema)


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("ascii")
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return str(value)


async def _query(
    connection, statement: str, schema: str, **parameters
) -> list[dict[str, Any]]:
    result = await connection.execute(text(statement), {"schema": schema, **parameters})
    return [
        {key: _json_value(value) for key, value in row._mapping.items()}
        for row in result
    ]


def _normalize_fields(rows: list[dict[str, Any]], schema: str, *fields: str):
    for row in rows:
        for field in fields:
            row[field] = _normalize_sql(row[field], schema)
    return rows


async def _resolved_schema(connection, schema: str | None) -> str:
    if schema is None:
        schema = await connection.scalar(text("SELECT current_schema()"))
    if not isinstance(schema, str):
        raise ValueError("PostgreSQL current_schema() did not resolve to a schema name")
    _assert_schema_name(schema)
    return schema


def _relation_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["name"],)


def _constraint_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["table"], row["name"])


def _index_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["name"], row["table"])


def _function_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["name"], row["argument_types"])


def _trigger_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["name"], row["table"])


async def collect_production_base_catalog(
    connection, schema: str | None = None
) -> dict[str, Any]:
    """Collect the exact allowlisted production-base catalog from ``schema``.

    ``connection`` must be an async SQLAlchemy connection.  Collection is read-only and ignores
    every relation, function, trigger, and index not named by this module's ownership allowlist.
    """

    schema = await _resolved_schema(connection, schema)
    relation_names = list(OWNED_RELATIONS)
    raw_relation_names = list(RAW_RELATIONS)
    index_names = list(OWNED_INDEXES)
    function_names = sorted({name for name, _ in OWNED_FUNCTION_IDENTITIES})
    trigger_names = list(OWNED_TRIGGERS)

    relations = await _query(
        connection,
        """
        SELECT relation.relname AS name,
               relation.relkind::text AS kind,
               relation.relpersistence::text AS persistence,
               relation.relrowsecurity AS row_security,
               relation.relforcerowsecurity AS force_row_security,
               relation.relispopulated AS populated,
               relation.relreplident::text AS replica_identity,
               (SELECT count(*)
                  FROM pg_attribute AS physical_attribute
                 WHERE physical_attribute.attrelid = relation.oid
                   AND physical_attribute.attnum > 0) AS physical_attribute_count,
               (SELECT count(*)
                  FROM pg_attribute AS physical_attribute
                 WHERE physical_attribute.attrelid = relation.oid
                   AND physical_attribute.attnum > 0
                   AND physical_attribute.attisdropped) AS dropped_attribute_count,
               (SELECT count(*)
                  FROM pg_policy AS policy
                 WHERE policy.polrelid = relation.oid) AS policy_count,
               (SELECT count(*)
                  FROM pg_inherits AS inheritance
                 WHERE inheritance.inhrelid = relation.oid) AS inheritance_parent_count,
               ARRAY(
                   SELECT parent.relname
                     FROM pg_inherits AS inheritance
                     JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
                    WHERE inheritance.inhrelid = relation.oid
                    ORDER BY parent.relname
               ) AS inheritance_parents,
               (SELECT count(*)
                  FROM pg_inherits AS inheritance
                 WHERE inheritance.inhparent = relation.oid) AS inheritance_child_count,
               ARRAY(
                   SELECT child.relname
                     FROM pg_inherits AS inheritance
                     JOIN pg_class AS child ON child.oid = inheritance.inhrelid
                    WHERE inheritance.inhparent = relation.oid
                    ORDER BY child.relname
               ) AS inheritance_children,
               pg_get_userbyid(relation.relowner) = current_user AS owner_is_current_user,
               relation.relacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         relation.relacl,
                         acldefault('r', relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl,
               access_method.amname AS access_method,
               tablespace.spcname AS tablespace,
               relation.reloptions AS options,
               pg_get_partkeydef(relation.oid) AS partition_key
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          LEFT JOIN pg_am AS access_method ON access_method.oid = relation.relam
          LEFT JOIN pg_tablespace AS tablespace ON tablespace.oid = relation.reltablespace
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:names AS text[]))
         ORDER BY relation.relname
        """,
        schema,
        names=relation_names,
    )
    _normalize_fields(relations, schema, "partition_key")

    columns = await _query(
        connection,
        """
        SELECT relation.relname AS relation,
               attribute.attnum AS position,
               attribute.attname AS name,
               format_type(attribute.atttypid, attribute.atttypmod) AS type,
               attribute.attnotnull AS not_null,
               CASE
                   WHEN attribute.attcollation = 0 THEN '<none>'
                   WHEN attribute.attcollation = type_row.typcollation THEN '<type_default>'
                   ELSE format('%I.%I', collation_namespace.nspname, collation_row.collname)
               END AS collation,
               pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true)
                   AS default,
               attribute.attidentity::text AS identity,
               attribute.attgenerated::text AS generated,
               attribute.attstorage::text AS storage,
               attribute.attcompression::text AS compression,
               attribute.attstattarget AS statistics_target,
               attribute.attoptions AS options,
               attribute.attfdwoptions AS fdw_options,
               attribute.attacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         attribute.attacl,
                         acldefault('c', relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
          JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid
          LEFT JOIN pg_collation AS collation_row
            ON collation_row.oid = attribute.attcollation
          LEFT JOIN pg_namespace AS collation_namespace
            ON collation_namespace.oid = collation_row.collnamespace
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = relation.oid
           AND attribute_default.adnum = attribute.attnum
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:names AS text[]))
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY relation.relname, attribute.attnum
        """,
        schema,
        names=relation_names,
    )
    _normalize_fields(columns, schema, "default")

    constraints = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               constraint_row.conname AS name,
               constraint_row.contype::text AS type,
               constraint_row.condeferrable AS deferrable,
               constraint_row.condeferred AS initially_deferred,
               constraint_row.convalidated AS validated,
               constraint_row.connoinherit AS no_inherit,
               constraint_row.conislocal AS local,
               constraint_row.coninhcount AS inheritance_count,
               parent_constraint.conname AS parent_constraint,
               constraint_row.confmatchtype::text AS match_type,
               constraint_row.confupdtype::text AS update_action,
               constraint_row.confdeltype::text AS delete_action,
               referenced_namespace.nspname AS referenced_schema,
               referenced_relation.relname AS referenced_table,
               pg_get_constraintdef(constraint_row.oid, true) AS definition
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          LEFT JOIN pg_class AS referenced_relation
            ON referenced_relation.oid = constraint_row.confrelid
          LEFT JOIN pg_namespace AS referenced_namespace
            ON referenced_namespace.oid = referenced_relation.relnamespace
          LEFT JOIN pg_constraint AS parent_constraint
            ON parent_constraint.oid = constraint_row.conparentid
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:names AS text[]))
           AND constraint_row.contype IN ('p', 'f', 'c', 'u', 'x')
         ORDER BY relation.relname, constraint_row.conname
        """,
        schema,
        names=raw_relation_names,
    )
    _normalize_fields(constraints, schema, "definition")
    for constraint in constraints:
        if constraint["referenced_schema"] == schema:
            constraint["referenced_schema"] = "<schema>"

    indexes = await _query(
        connection,
        """
        SELECT index_relation.relname AS name,
               relation.relname AS table,
               index_row.indisunique AS unique,
               index_row.indisprimary AS primary,
               index_row.indisexclusion AS exclusion,
               index_row.indimmediate AS immediate,
               index_row.indisclustered AS clustered,
               index_row.indisvalid AS valid,
               index_row.indisready AS ready,
               index_row.indislive AS live,
               index_row.indisreplident AS replica_identity,
               index_row.indnullsnotdistinct AS nulls_not_distinct,
               index_row.indnatts AS attribute_count,
               index_row.indnkeyatts AS key_attribute_count,
               access_method.amname AS access_method,
               tablespace.spcname AS tablespace,
               index_relation.reloptions AS options,
               ARRAY(
                   SELECT pg_get_indexdef(index_row.indexrelid, position, true)
                     FROM generate_series(1, index_row.indnkeyatts) AS position
                    ORDER BY position
               ) AS keys,
               pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate,
               pg_get_indexdef(index_row.indexrelid, 0, true) AS definition
          FROM pg_index AS index_row
          JOIN pg_class AS relation ON relation.oid = index_row.indrelid
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_namespace AS namespace ON namespace.oid = index_relation.relnamespace
          JOIN pg_am AS access_method ON access_method.oid = index_relation.relam
          LEFT JOIN pg_tablespace AS tablespace ON tablespace.oid = index_relation.reltablespace
         WHERE namespace.nspname = :schema
           AND (
               index_relation.relname = ANY(CAST(:names AS text[]))
               OR relation.relname = ANY(CAST(:raw_names AS text[]))
           )
         ORDER BY index_relation.relname, relation.relname
        """,
        schema,
        names=index_names,
        raw_names=raw_relation_names,
    )
    _normalize_fields(indexes, schema, "predicate", "definition")
    for index in indexes:
        index["keys"] = [_normalize_sql(key, schema) for key in index["keys"]]

    partition_root_indexes = await _query(
        connection,
        """
        SELECT index_relation.relname AS name,
               relation.relname AS table,
               pg_get_userbyid(index_relation.relowner) = current_user
                   AS owner_is_current_user,
               index_relation.relpersistence::text AS persistence,
               index_row.indisunique AS unique,
               index_row.indisprimary AS primary,
               index_row.indisexclusion AS exclusion,
               index_row.indimmediate AS immediate,
               index_row.indisclustered AS clustered,
               index_row.indisvalid AS valid,
               index_row.indisready AS ready,
               index_row.indislive AS live,
               index_row.indisreplident AS replica_identity,
               index_row.indnullsnotdistinct AS nulls_not_distinct,
               index_row.indnatts AS attribute_count,
               index_row.indnkeyatts AS key_attribute_count,
               access_method.amname AS access_method,
               tablespace.spcname AS tablespace,
               index_relation.reloptions AS options,
               ARRAY(
                   SELECT pg_get_indexdef(index_row.indexrelid, position, true)
                     FROM generate_series(1, index_row.indnkeyatts) AS position
                    ORDER BY position
               ) AS keys,
               pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate
          FROM pg_index AS index_row
          JOIN pg_class AS relation ON relation.oid = index_row.indrelid
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_namespace AS namespace ON namespace.oid = index_relation.relnamespace
          JOIN pg_am AS access_method ON access_method.oid = index_relation.relam
          LEFT JOIN pg_tablespace AS tablespace ON tablespace.oid = index_relation.reltablespace
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:roots AS text[]))
           AND index_relation.relname = ANY(CAST(:names AS text[]))
         ORDER BY relation.relname, index_relation.relname
        """,
        schema,
        roots=list(PARTITION_FAMILY_INDEXES),
        names=sorted(
            index_name
            for index_names in PARTITION_FAMILY_INDEXES.values()
            for index_name in index_names
        ),
    )
    _normalize_fields(partition_root_indexes, schema, "predicate")
    for index in partition_root_indexes:
        index["keys"] = [_normalize_sql(key, schema) for key in index["keys"]]

    partition_relations = await _query(
        connection,
        """
        SELECT relation.relname AS name,
               COALESCE(
                   (SELECT root.relname
                      FROM pg_class AS root
                      JOIN pg_namespace AS root_namespace
                        ON root_namespace.oid = root.relnamespace
                     WHERE root.oid = pg_partition_root(relation.oid)
                       AND root_namespace.nspname = :schema
                       AND root.relname = ANY(CAST(:roots AS text[]))),
                   CASE
                       WHEN strpos(relation.relname, :metrics_prefix) = 1
                           THEN 'p_llm_metrics'
                       WHEN strpos(relation.relname, :invocations_prefix) = 1
                           THEN 'partitioned_invocations'
                   END
               ) AS family_root,
               relation.relkind::text AS kind,
               relation.relpersistence::text AS persistence,
               relation.relispartition AS is_partition,
               relation.relrowsecurity AS row_security,
               relation.relforcerowsecurity AS force_row_security,
               relation.relreplident::text AS replica_identity,
               (SELECT count(*)
                  FROM pg_attribute AS physical_attribute
                 WHERE physical_attribute.attrelid = relation.oid
                   AND physical_attribute.attnum > 0) AS physical_attribute_count,
               (SELECT count(*)
                  FROM pg_attribute AS physical_attribute
                 WHERE physical_attribute.attrelid = relation.oid
                   AND physical_attribute.attnum > 0
                   AND physical_attribute.attisdropped) AS dropped_attribute_count,
               access_method.amname AS access_method,
               tablespace.spcname AS tablespace,
               relation.reloptions AS options,
               pg_get_userbyid(relation.relowner) = current_user AS owner_is_current_user,
               relation.relacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         relation.relacl,
                         acldefault('r', relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl,
               (SELECT count(*)
                  FROM pg_inherits AS inheritance
                 WHERE inheritance.inhrelid = relation.oid) AS direct_parent_count,
               (SELECT parent.relname
                  FROM pg_inherits AS inheritance
                  JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
                 WHERE inheritance.inhrelid = relation.oid
                 ORDER BY parent.oid
                 LIMIT 1) AS direct_parent,
               CASE WHEN relation.relkind IN ('r', 'p')
                    THEN (SELECT root.relname
                            FROM pg_class AS root
                           WHERE root.oid = pg_partition_root(relation.oid))
               END AS partition_root,
               pg_get_expr(relation.relpartbound, relation.oid, true) AS bound,
               CASE
                   WHEN relation.relname ~ '^p_llm_metrics_[0-9]{8}$' THEN
                       to_char(to_date(substr(relation.relname, 15), 'YYYYMMDD'), 'YYYYMMDD')
                           = substr(relation.relname, 15)
                       AND pg_get_expr(relation.relpartbound, relation.oid, true)
                           = format(
                               'FOR VALUES FROM (%L) TO (%L)',
                               to_date(substr(relation.relname, 15), 'YYYYMMDD'),
                               to_date(substr(relation.relname, 15), 'YYYYMMDD') + 1
                           )
                   WHEN relation.relname ~ '^partitioned_invocations_[0-9]{4}_[0-9]{2}$'
                   THEN
                       to_char(
                           to_date(substr(relation.relname, 25), 'IYYY_IW'), 'IYYY_IW'
                       ) = substr(relation.relname, 25)
                       AND pg_get_expr(relation.relpartbound, relation.oid, true)
                           = format(
                               'FOR VALUES FROM (%L) TO (%L)',
                               to_date(substr(relation.relname, 25), 'IYYY_IW')::timestamp,
                               (to_date(substr(relation.relname, 25), 'IYYY_IW') + 7)::timestamp
                           )
                   ELSE false
               END AS name_bound_aligned
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          LEFT JOIN pg_am AS access_method ON access_method.oid = relation.relam
          LEFT JOIN pg_tablespace AS tablespace ON tablespace.oid = relation.reltablespace
         WHERE namespace.nspname = :schema
           AND relation.relkind NOT IN ('i', 'I')
           AND (
               strpos(relation.relname, :metrics_prefix) = 1
               OR strpos(relation.relname, :invocations_prefix) = 1
               OR (
                   relation.relispartition
                   AND pg_partition_root(relation.oid) IN (
                       SELECT root.oid
                         FROM pg_class AS root
                         JOIN pg_namespace AS root_namespace
                           ON root_namespace.oid = root.relnamespace
                        WHERE root_namespace.nspname = :schema
                          AND root.relname = ANY(CAST(:roots AS text[]))
                   )
               )
           )
         ORDER BY family_root, relation.relname
        """,
        schema,
        roots=list(PARTITION_FAMILY_PREFIXES),
        metrics_prefix=PARTITION_FAMILY_PREFIXES["p_llm_metrics"],
        invocations_prefix=PARTITION_FAMILY_PREFIXES["partitioned_invocations"],
    )
    partition_candidate_names = [relation["name"] for relation in partition_relations]

    partition_columns = await _query(
        connection,
        """
        SELECT relation.relname AS relation,
               attribute.attnum AS position,
               attribute.attname AS name,
               format_type(attribute.atttypid, attribute.atttypmod) AS type,
               attribute.attnotnull AS not_null,
               CASE
                   WHEN attribute.attcollation = 0 THEN '<none>'
                   WHEN attribute.attcollation = type_row.typcollation THEN '<type_default>'
                   ELSE format('%I.%I', collation_namespace.nspname, collation_row.collname)
               END AS collation,
               pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true)
                   AS default,
               attribute.attidentity::text AS identity,
               attribute.attgenerated::text AS generated,
               attribute.attstorage::text AS storage,
               attribute.attcompression::text AS compression,
               attribute.attstattarget AS statistics_target,
               attribute.attoptions AS options,
               attribute.attfdwoptions AS fdw_options,
               attribute.attacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         attribute.attacl,
                         acldefault('c', relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
          JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid
          LEFT JOIN pg_collation AS collation_row
            ON collation_row.oid = attribute.attcollation
          LEFT JOIN pg_namespace AS collation_namespace
            ON collation_namespace.oid = collation_row.collnamespace
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = relation.oid
           AND attribute_default.adnum = attribute.attnum
         WHERE namespace.nspname = :schema
           AND relation.relkind NOT IN ('i', 'I')
           AND relation.relname = ANY(CAST(:candidate_names AS text[]))
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY relation.relname, attribute.attnum
        """,
        schema,
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(partition_columns, schema, "default")

    partition_indexes = await _query(
        connection,
        """
        SELECT index_relation.relname AS name,
               relation.relname AS table,
               parent_index.relname AS parent_index,
               pg_get_userbyid(index_relation.relowner) = current_user
                   AS owner_is_current_user,
               index_relation.relpersistence::text AS persistence,
               index_row.indisunique AS unique,
               index_row.indisprimary AS primary,
               index_row.indisexclusion AS exclusion,
               index_row.indimmediate AS immediate,
               index_row.indisclustered AS clustered,
               index_row.indisvalid AS valid,
               index_row.indisready AS ready,
               index_row.indislive AS live,
               index_row.indisreplident AS replica_identity,
               index_row.indnullsnotdistinct AS nulls_not_distinct,
               index_row.indnatts AS attribute_count,
               index_row.indnkeyatts AS key_attribute_count,
               access_method.amname AS access_method,
               tablespace.spcname AS tablespace,
               index_relation.reloptions AS options,
               ARRAY(
                   SELECT pg_get_indexdef(index_row.indexrelid, position, true)
                     FROM generate_series(1, index_row.indnkeyatts) AS position
                    ORDER BY position
               ) AS keys,
               pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate
          FROM pg_index AS index_row
          JOIN pg_class AS relation ON relation.oid = index_row.indrelid
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_namespace AS namespace ON namespace.oid = index_relation.relnamespace
          JOIN pg_am AS access_method ON access_method.oid = index_relation.relam
          LEFT JOIN pg_tablespace AS tablespace ON tablespace.oid = index_relation.reltablespace
          LEFT JOIN pg_inherits AS index_inheritance
            ON index_inheritance.inhrelid = index_relation.oid
          LEFT JOIN pg_class AS parent_index
            ON parent_index.oid = index_inheritance.inhparent
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:candidate_names AS text[]))
         ORDER BY relation.relname, index_relation.relname
        """,
        schema,
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(partition_indexes, schema, "predicate")
    for index in partition_indexes:
        index["keys"] = [_normalize_sql(key, schema) for key in index["keys"]]

    partition_constraints = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               constraint_row.conname AS name,
               constraint_row.contype::text AS type,
               constraint_row.condeferrable AS deferrable,
               constraint_row.condeferred AS initially_deferred,
               constraint_row.convalidated AS validated,
               constraint_row.connoinherit AS no_inherit,
               constraint_row.conislocal AS local,
               constraint_row.coninhcount AS inheritance_count,
               parent_constraint.conname AS parent_constraint,
               constraint_row.confmatchtype::text AS match_type,
               constraint_row.confupdtype::text AS update_action,
               constraint_row.confdeltype::text AS delete_action,
               referenced_namespace.nspname AS referenced_schema,
               referenced_relation.relname AS referenced_table,
               pg_get_constraintdef(constraint_row.oid, true) AS definition
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          LEFT JOIN pg_constraint AS parent_constraint
            ON parent_constraint.oid = constraint_row.conparentid
          LEFT JOIN pg_class AS referenced_relation
            ON referenced_relation.oid = constraint_row.confrelid
          LEFT JOIN pg_namespace AS referenced_namespace
            ON referenced_namespace.oid = referenced_relation.relnamespace
         WHERE namespace.nspname = :schema
           AND constraint_row.contype IN ('p', 'f', 'c', 'u', 'x')
           AND relation.relname = ANY(CAST(:candidate_names AS text[]))
         ORDER BY relation.relname, constraint_row.conname
        """,
        schema,
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(partition_constraints, schema, "definition")
    for constraint in partition_constraints:
        if constraint["referenced_schema"] == schema:
            constraint["referenced_schema"] = "<schema>"

    partition_triggers = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               trigger_row.tgname AS name,
               trigger_row.tgconstraint AS constraint_oid,
               pg_get_triggerdef(trigger_row.oid, true) AS definition
          FROM pg_trigger AS trigger_row
          JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND NOT trigger_row.tgisinternal
           AND relation.relname = ANY(CAST(:candidate_names AS text[]))
         ORDER BY relation.relname, trigger_row.tgname
        """,
        schema,
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(partition_triggers, schema, "definition")

    partition_rules = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               rewrite.rulename AS name,
               rewrite.ev_type::text AS event_type,
               rewrite.is_instead AS instead,
               rewrite.ev_enabled::text AS enabled,
               pg_get_ruledef(rewrite.oid, true) AS definition
          FROM pg_rewrite AS rewrite
          JOIN pg_class AS relation ON relation.oid = rewrite.ev_class
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND rewrite.rulename <> '_RETURN'
           AND relation.relname = ANY(CAST(:candidate_names AS text[]))
         ORDER BY relation.relname, rewrite.rulename
        """,
        schema,
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(partition_rules, schema, "definition")

    partition_policies = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               policy.polname AS name,
               policy.polpermissive AS permissive,
               policy.polcmd::text AS command,
               ARRAY(
                   SELECT CASE
                              WHEN role_oid = 0 THEN '<public>'
                              WHEN pg_get_userbyid(role_oid) = current_user
                                  THEN '<current_user>'
                              ELSE pg_get_userbyid(role_oid)
                          END
                     FROM unnest(policy.polroles) AS role_oid
                    ORDER BY 1
               ) AS roles,
               pg_get_expr(policy.polqual, policy.polrelid, true) AS using_expression,
               pg_get_expr(policy.polwithcheck, policy.polrelid, true) AS check_expression
          FROM pg_policy AS policy
          JOIN pg_class AS relation ON relation.oid = policy.polrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND (
               relation.relname = ANY(CAST(:roots AS text[]))
               OR relation.relname = ANY(CAST(:candidate_names AS text[]))
           )
         ORDER BY relation.relname, policy.polname
        """,
        schema,
        roots=list(PARTITION_FAMILY_PREFIXES),
        candidate_names=partition_candidate_names,
    )
    _normalize_fields(
        partition_policies, schema, "using_expression", "check_expression"
    )

    partition_families = []
    for root, prefix in sorted(PARTITION_FAMILY_PREFIXES.items()):
        children = []
        for relation in partition_relations:
            if relation["family_root"] != root:
                continue
            child = dict(relation)
            child.pop("family_root")
            child["columns"] = [
                column
                for column in partition_columns
                if column["relation"] == child["name"]
            ]
            child["indexes"] = [
                index for index in partition_indexes if index["table"] == child["name"]
            ]
            child["constraints"] = [
                constraint
                for constraint in partition_constraints
                if constraint["table"] == child["name"]
            ]
            child["triggers"] = [
                trigger
                for trigger in partition_triggers
                if trigger["table"] == child["name"]
            ]
            child["rules"] = [
                rule for rule in partition_rules if rule["table"] == child["name"]
            ]
            child["policies"] = [
                policy
                for policy in partition_policies
                if policy["table"] == child["name"]
            ]
            children.append(child)
        partition_families.append(
            {
                "root": root,
                "prefix": prefix,
                "expected_parent_indexes": list(PARTITION_FAMILY_INDEXES[root]),
                "root_policies": [
                    policy for policy in partition_policies if policy["table"] == root
                ],
                "children": children,
            }
        )

    views = await _query(
        connection,
        """
        SELECT relation.relname AS name,
               relation.relkind::text AS kind,
               pg_get_viewdef(relation.oid, false) AS definition,
               md5(regexp_replace(
                   replace(pg_get_viewdef(relation.oid, true), :schema || '.', ''),
                   '[[:space:]]+', ' ', 'g'
               )) AS definition_md5,
               obj_description(relation.oid, 'pg_class') AS comment
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:names AS text[]))
         ORDER BY relation.relname
        """,
        schema,
        names=list(OWNED_VIEWS),
    )
    _normalize_fields(views, schema, "definition")

    sequences = await _query(
        connection,
        """
        SELECT sequence_relation.relname AS name,
               sequence_relation.relpersistence::text AS persistence,
               pg_get_userbyid(sequence_relation.relowner) = current_user
                   AS owner_is_current_user,
               sequence_relation.relacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = sequence_relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = sequence_relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         sequence_relation.relacl,
                         acldefault('s', sequence_relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl,
               format_type(sequence_row.seqtypid, NULL) AS type,
               sequence_row.seqstart AS start,
               sequence_row.seqincrement AS increment,
               sequence_row.seqmax AS maximum,
               sequence_row.seqmin AS minimum,
               sequence_row.seqcache AS cache,
               sequence_row.seqcycle AS cycle,
               dependency.deptype::text AS dependency_type,
               owned_relation.relname AS owned_by_table,
               owned_attribute.attname AS owned_by_column,
               pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true)
                   AS column_default
          FROM pg_class AS sequence_relation
          JOIN pg_namespace AS namespace ON namespace.oid = sequence_relation.relnamespace
          JOIN pg_sequence AS sequence_row ON sequence_row.seqrelid = sequence_relation.oid
          LEFT JOIN pg_depend AS dependency
            ON dependency.classid = 'pg_class'::regclass
           AND dependency.objid = sequence_relation.oid
           AND dependency.refclassid = 'pg_class'::regclass
           AND dependency.deptype IN ('a', 'i')
          LEFT JOIN pg_class AS owned_relation ON owned_relation.oid = dependency.refobjid
          LEFT JOIN pg_attribute AS owned_attribute
            ON owned_attribute.attrelid = dependency.refobjid
           AND owned_attribute.attnum = dependency.refobjsubid
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = dependency.refobjid
           AND attribute_default.adnum = dependency.refobjsubid
         WHERE namespace.nspname = :schema
           AND sequence_relation.relname = 'instance_compute_history_id_seq'
         ORDER BY sequence_relation.relname
        """,
        schema,
    )
    _normalize_fields(sequences, schema, "column_default")

    functions = await _query(
        connection,
        """
        SELECT procedure.proname AS name,
               oidvectortypes(procedure.proargtypes) AS argument_types,
               pg_get_function_identity_arguments(procedure.oid) AS identity_arguments,
               pg_get_function_result(procedure.oid) AS result,
               procedure.prokind::text AS kind,
               language.lanname AS language,
               pg_get_userbyid(procedure.proowner) = current_user AS owner_is_current_user,
               procedure.proacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = procedure.proowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = procedure.proowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         procedure.proacl,
                         acldefault('f', procedure.proowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl,
               procedure.provolatile::text AS volatility,
               procedure.proisstrict AS strict,
               procedure.prosecdef AS security_definer,
               procedure.proleakproof AS leakproof,
               procedure.proparallel::text AS parallel,
               CASE WHEN procedure.prosupport = 0 THEN '-'
                    ELSE procedure.prosupport::regprocedure::text
               END AS support,
               procedure.probin AS binary,
               procedure.prosqlbody IS NULL AS sql_body_is_null,
               procedure.proretset AS returns_set,
               procedure.procost AS cost,
               procedure.prorows AS rows,
               procedure.proconfig AS config,
               procedure.proargnames AS argument_names,
               procedure.proargmodes AS argument_modes,
               ARRAY(
                   SELECT format_type(argument_type, NULL)
                     FROM unnest(COALESCE(
                         procedure.proallargtypes,
                         procedure.proargtypes::oid[]
                     )) WITH ORDINALITY AS argument(argument_type, position)
                    ORDER BY position
               ) AS all_argument_types,
               pg_get_expr(procedure.proargdefaults, 0, true) AS argument_defaults,
               procedure.prosrc AS body
          FROM pg_proc AS procedure
          JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
          JOIN pg_language AS language ON language.oid = procedure.prolang
         WHERE namespace.nspname = :schema
           AND procedure.proname = ANY(CAST(:names AS text[]))
         ORDER BY procedure.proname, oidvectortypes(procedure.proargtypes)
        """,
        schema,
        names=function_names,
    )
    function_identities = set(OWNED_FUNCTION_IDENTITIES)
    unexpected_function_overloads = [
        {
            "name": function["name"],
            "argument_types": function["argument_types"],
            "identity_arguments": _normalize_sql(
                function["identity_arguments"], schema
            ),
            "result": _normalize_sql(function["result"], schema),
            "kind": function["kind"],
            "language": function["language"],
        }
        for function in functions
        if (function["name"], function["argument_types"]) not in function_identities
    ]
    functions = [
        function
        for function in functions
        if (function["name"], function["argument_types"]) in function_identities
    ]
    _normalize_fields(
        functions, schema, "identity_arguments", "result", "argument_defaults"
    )
    for function in functions:
        body = function.pop("body")
        function["body_sha256"] = function_body_sha256(body)

    triggers = await _query(
        connection,
        """
        SELECT trigger_row.tgname AS name,
               relation.relname AS table,
               trigger_row.tgenabled::text AS enabled,
               trigger_row.tgtype AS type_mask,
               trigger_row.tgisinternal AS internal,
               trigger_row.tgdeferrable AS deferrable,
               trigger_row.tginitdeferred AS initially_deferred,
               trigger_row.tgconstraint AS constraint_oid,
               trigger_row.tgnargs AS argument_count,
               encode(trigger_row.tgargs, 'hex') AS arguments_hex,
               trigger_row.tgoldtable AS old_transition_table,
               trigger_row.tgnewtable AS new_transition_table,
               ARRAY(
                   SELECT attribute.attname
                     FROM unnest(trigger_row.tgattr::smallint[]) WITH ORDINALITY
                          AS trigger_attribute(attribute_number, position)
                     JOIN pg_attribute AS attribute
                       ON attribute.attrelid = trigger_row.tgrelid
                      AND attribute.attnum = trigger_attribute.attribute_number
                    ORDER BY trigger_attribute.position
               ) AS update_columns,
               pg_get_expr(trigger_row.tgqual, trigger_row.tgrelid, true) AS condition,
               function_namespace.nspname AS function_schema,
               procedure.proname AS function_name,
               oidvectortypes(procedure.proargtypes) AS function_argument_types,
               pg_get_triggerdef(trigger_row.oid, true) AS definition
          FROM pg_trigger AS trigger_row
          JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_proc AS procedure ON procedure.oid = trigger_row.tgfoid
          JOIN pg_namespace AS function_namespace
            ON function_namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = :schema
           AND NOT trigger_row.tgisinternal
           AND (
               trigger_row.tgname = ANY(CAST(:names AS text[]))
               OR relation.relname = ANY(CAST(:raw_names AS text[]))
           )
         ORDER BY trigger_row.tgname, relation.relname
        """,
        schema,
        names=trigger_names,
        raw_names=raw_relation_names,
    )
    _normalize_fields(triggers, schema, "condition", "definition")
    for trigger in triggers:
        if trigger["function_schema"] == schema:
            trigger["function_schema"] = "<schema>"

    rules = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               rewrite.rulename AS name,
               rewrite.ev_type::text AS event_type,
               rewrite.is_instead AS instead,
               rewrite.ev_enabled::text AS enabled,
               pg_get_ruledef(rewrite.oid, true) AS definition
          FROM pg_rewrite AS rewrite
          JOIN pg_class AS relation ON relation.oid = rewrite.ev_class
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND relation.relname = ANY(CAST(:names AS text[]))
           AND rewrite.rulename <> '_RETURN'
         ORDER BY relation.relname, rewrite.rulename
        """,
        schema,
        names=sorted(set(RAW_RELATIONS) | {"invocations"}),
    )
    _normalize_fields(rules, schema, "definition")

    supplemental_columns = await _query(
        connection,
        """
        SELECT relation.relname AS relation,
               attribute.attname AS name,
               format_type(attribute.atttypid, attribute.atttypmod) AS type,
               attribute.attnotnull AS not_null,
               CASE
                   WHEN attribute.attcollation = 0 THEN '<none>'
                   WHEN attribute.attcollation = type_row.typcollation THEN '<type_default>'
                   ELSE format('%I.%I', collation_namespace.nspname, collation_row.collname)
               END AS collation,
               pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true)
                   AS default,
               attribute.attidentity::text AS identity,
               attribute.attgenerated::text AS generated,
               attribute.attstorage::text AS storage,
               attribute.attcompression::text AS compression,
               attribute.attstattarget AS statistics_target,
               attribute.attoptions AS options,
               attribute.attfdwoptions AS fdw_options,
               attribute.attacl IS NULL AS acl_is_default,
               ARRAY(
                   SELECT format(
                       '%s:%s:%s:%s',
                       CASE
                           WHEN acl.grantee = 0 THEN '<public>'
                           WHEN acl.grantee = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantee) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantee)
                       END,
                       acl.privilege_type,
                       acl.is_grantable,
                       CASE
                           WHEN acl.grantor = relation.relowner THEN '<owner>'
                           WHEN pg_get_userbyid(acl.grantor) = current_user
                               THEN '<current_user>'
                           ELSE pg_get_userbyid(acl.grantor)
                       END
                   )
                     FROM aclexplode(COALESCE(
                         attribute.attacl,
                         acldefault('c', relation.relowner)
                     )) AS acl
                    ORDER BY 1
               ) AS acl
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
          JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid
          LEFT JOIN pg_collation AS collation_row
            ON collation_row.oid = attribute.attcollation
          LEFT JOIN pg_namespace AS collation_namespace
            ON collation_namespace.oid = collation_row.collnamespace
          LEFT JOIN pg_attrdef AS attribute_default
            ON attribute_default.adrelid = relation.oid
           AND attribute_default.adnum = attribute.attnum
         WHERE namespace.nspname = :schema
           AND relation.relname = 'chute_history'
           AND attribute.attname = 'jobs'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
        """,
        schema,
    )
    _normalize_fields(supplemental_columns, schema, "default")

    supplemental_constraints = await _query(
        connection,
        """
        SELECT relation.relname AS table,
               constraint_row.conname AS name,
               constraint_row.contype::text AS type,
               constraint_row.convalidated AS validated,
               constraint_row.connoinherit AS no_inherit,
               pg_get_constraintdef(constraint_row.oid, true) AS definition
          FROM pg_constraint AS constraint_row
          JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = :schema
           AND relation.relname = 'model_aliases'
           AND constraint_row.conname = 'alias_ascii_no_colon'
        """,
        schema,
    )
    _normalize_fields(supplemental_constraints, schema, "definition")

    extensions = await _query(
        connection,
        """
        SELECT extension.extname AS name,
               extension.extversion AS version,
               extension.extrelocatable AS relocatable,
               pg_get_userbyid(extension.extowner) = current_user AS owner_is_current_user,
               namespace.nspname AS schema
          FROM pg_extension AS extension
          JOIN pg_namespace AS namespace ON namespace.oid = extension.extnamespace
         WHERE extension.extname = 'pgcrypto'
        """,
        schema,
    )

    sql_digest = hashlib.sha256(PRODUCTION_BASE_SQL_PATH.read_bytes()).hexdigest()
    server_version_num = await connection.scalar(
        text("SELECT current_setting('server_version_num')::INTEGER")
    )
    return {
        "format_version": CATALOG_FORMAT_VERSION,
        "postgres_major": server_version_num // 10000,
        "production_base_sql_sha256": sql_digest,
        "extensions": extensions,
        "relations": sorted(relations, key=_relation_key),
        "columns": columns,
        "constraints": sorted(constraints, key=_constraint_key),
        "indexes": sorted(indexes, key=_index_key),
        "partition_root_indexes": sorted(partition_root_indexes, key=_index_key),
        "partition_families": partition_families,
        "views": views,
        "sequences": sequences,
        "functions": sorted(functions, key=_function_key),
        "unexpected_function_overloads": sorted(
            unexpected_function_overloads,
            key=lambda item: (item["name"], item["argument_types"]),
        ),
        "triggers": sorted(triggers, key=_trigger_key),
        "rules": rules,
        "supplemental_columns": supplemental_columns,
        "supplemental_constraints": supplemental_constraints,
    }


def _manifest_owned_names(
    manifest: dict[str, Any], section: str, key: str
) -> tuple[str, ...]:
    return tuple(sorted(item[key] for item in manifest[section]))


def _assert_manifest_allowlist(manifest: dict[str, Any]) -> None:
    if manifest.get("format_version") != CATALOG_FORMAT_VERSION:
        raise RuntimeError("unsupported production-base catalog manifest format")
    if manifest.get("postgres_major") != 15:
        raise RuntimeError(
            "production-base catalog manifest is not the qualified PostgreSQL 15 contract"
        )
    if manifest.get("unexpected_function_overloads") != []:
        raise RuntimeError(
            "production-base catalog contains an unexpected same-name function overload"
        )
    expected_sets = {
        "relations": tuple(sorted(OWNED_RELATIONS)),
        "triggers": tuple(sorted(OWNED_TRIGGERS)),
        "views": tuple(sorted(OWNED_VIEWS)),
    }
    for section, expected in expected_sets.items():
        actual = _manifest_owned_names(manifest, section, "name")
        if actual != expected:
            raise RuntimeError(
                f"production-base manifest {section} allowlist mismatch: "
                f"expected={expected!r}, actual={actual!r}"
            )

    index_rows = manifest.get("indexes", [])
    index_names = [item.get("name") for item in index_rows]
    if any(index_names.count(name) != 1 for name in OWNED_INDEXES):
        raise RuntimeError("production-base named-index allowlist mismatch")
    raw_index_identities = tuple(
        sorted(
            (item["table"], item["name"])
            for item in index_rows
            if item.get("table") in RAW_RELATIONS
        )
    )
    if raw_index_identities != tuple(sorted(RAW_INDEX_IDENTITIES)):
        raise RuntimeError("production-base raw-index allowlist mismatch")
    if any(
        item.get("table") not in RAW_RELATIONS and item.get("name") not in OWNED_INDEXES
        for item in index_rows
    ):
        raise RuntimeError("production-base catalog contains an unowned index")

    constraint_identities = tuple(
        sorted(
            (item["table"], item["name"], item["type"])
            for item in manifest.get("constraints", [])
        )
    )
    if constraint_identities != tuple(sorted(RAW_CONSTRAINT_IDENTITIES)):
        raise RuntimeError("production-base raw-constraint allowlist mismatch")
    raw_trigger_identities = tuple(
        sorted(
            (item["table"], item["name"])
            for item in manifest.get("triggers", [])
            if item.get("table") in RAW_RELATIONS
        )
    )
    if raw_trigger_identities:
        raise RuntimeError("production-base raw-trigger allowlist must be empty")
    if manifest.get("rules") != []:
        raise RuntimeError("production-base raw/view rule allowlist must be empty")
    relation_rows = {item["name"]: item for item in manifest.get("relations", [])}
    for name in set(RAW_RELATIONS) - set(PARTITION_FAMILY_PREFIXES):
        relation = relation_rows[name]
        if (
            relation.get("inheritance_parent_count") != 0
            or relation.get("inheritance_parents") != []
            or relation.get("inheritance_child_count") != 0
            or relation.get("inheritance_children") != []
            or relation.get("policy_count") != 0
        ):
            raise RuntimeError(
                f"production-base raw relation has inherited topology or policy: {name}"
            )
    function_identities = tuple(
        sorted((item["name"], item["argument_types"]) for item in manifest["functions"])
    )
    if function_identities != tuple(sorted(OWNED_FUNCTION_IDENTITIES)):
        raise RuntimeError("production-base manifest function allowlist mismatch")
    if any(trigger.get("constraint_oid") != 0 for trigger in manifest["triggers"]):
        raise RuntimeError(
            "production-base ordinary triggers must not be constraint-backed"
        )

    if manifest.get("extensions") != [
        {
            "name": "pgcrypto",
            "owner_is_current_user": True,
            "relocatable": True,
            "schema": "public",
            "version": "1.3",
        }
    ]:
        raise RuntimeError("production-base pgcrypto contract is not exact")

    root_index_identities = tuple(
        sorted(
            (item["table"], item["name"])
            for item in manifest.get("partition_root_indexes", [])
        )
    )
    expected_root_index_identities = tuple(
        sorted(
            (root, index_name)
            for root, index_names in PARTITION_FAMILY_INDEXES.items()
            for index_name in index_names
        )
    )
    if root_index_identities != expected_root_index_identities:
        raise RuntimeError("production-base partition-root index allowlist mismatch")

    partition_families = manifest.get("partition_families")
    expected_partition_families = [
        {
            "root": root,
            "prefix": PARTITION_FAMILY_PREFIXES[root],
            "expected_parent_indexes": list(PARTITION_FAMILY_INDEXES[root]),
            "root_policies": [],
            "children": [],
        }
        for root in sorted(PARTITION_FAMILY_PREFIXES)
    ]
    if partition_families != expected_partition_families:
        raise RuntimeError("production-base dynamic-partition allowlist mismatch")

    variants = manifest.get("daily_revenue_summary_variants")
    if not isinstance(variants, dict) or set(variants) != {
        DAILY_REVENUE_SUMMARY_HISTORICAL_VARIANT,
        DAILY_REVENUE_SUMMARY_QUOTA_VARIANT,
    }:
        raise RuntimeError("production-base summary-view variant allowlist mismatch")
    historical = variants[DAILY_REVENUE_SUMMARY_HISTORICAL_VARIANT]
    quota = variants[DAILY_REVENUE_SUMMARY_QUOTA_VARIANT]
    if historical != {
        "comment": None,
        "definition_md5": DAILY_REVENUE_SUMMARY_HISTORICAL_MD5,
    }:
        raise RuntimeError("historical subscription summary-view variant is not exact")
    if (
        not isinstance(quota, dict)
        or quota.get("comment") != DAILY_REVENUE_SUMMARY_QUOTA_COMMENT
        or not isinstance(quota.get("definition_md5"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", quota["definition_md5"])
    ):
        raise RuntimeError("quota summary-view variant is not exact")
    if (
        manifest.get("daily_revenue_summary_variant")
        != DAILY_REVENUE_SUMMARY_QUOTA_VARIANT
    ):
        raise RuntimeError(
            "checked-in fresh manifest must use the quota summary-view variant"
        )


def _summary_view(catalog: dict[str, Any]) -> dict[str, Any]:
    matches = [
        view
        for view in catalog.get("views", [])
        if view.get("name") == "daily_revenue_summary"
    ]
    if len(matches) != 1:
        raise ProductionBaseCatalogMismatch(
            "daily_revenue_summary must have exactly one collected materialized-view definition"
        )
    return matches[0]


def _classify_daily_revenue_summary(
    catalog: dict[str, Any], variants: dict[str, dict[str, Any]]
) -> str:
    view = _summary_view(catalog)
    recognized = [
        name
        for name, evidence in variants.items()
        if view.get("definition_md5") == evidence.get("definition_md5")
        and view.get("comment") == evidence.get("comment")
    ]
    if len(recognized) != 1:
        raise ProductionBaseCatalogMismatch(
            "daily_revenue_summary has an unknown body/comment pair: "
            f"definition_md5={view.get('definition_md5')!r}, "
            f"comment={view.get('comment')!r}"
        )
    return recognized[0]


def _manifest_from_fresh_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(catalog)
    summary = _summary_view(manifest)
    if summary.get("comment") != DAILY_REVENUE_SUMMARY_QUOTA_COMMENT:
        raise RuntimeError(
            "fresh daily_revenue_summary is missing the exact quota-approximation comment"
        )
    variants = {
        DAILY_REVENUE_SUMMARY_HISTORICAL_VARIANT: {
            "comment": None,
            "definition_md5": DAILY_REVENUE_SUMMARY_HISTORICAL_MD5,
        },
        DAILY_REVENUE_SUMMARY_QUOTA_VARIANT: {
            "comment": DAILY_REVENUE_SUMMARY_QUOTA_COMMENT,
            "definition_md5": summary["definition_md5"],
        },
    }
    manifest["daily_revenue_summary_variants"] = variants
    manifest["daily_revenue_summary_variant"] = _classify_daily_revenue_summary(
        manifest, variants
    )
    _assert_manifest_allowlist(manifest)
    return manifest


def _catalog_for_exact_comparison(catalog: dict[str, Any]) -> dict[str, Any]:
    comparable = deepcopy(catalog)
    comparable.pop("daily_revenue_summary_variant", None)
    comparable.pop("daily_revenue_summary_variants", None)
    summary = _summary_view(comparable)
    # Body/comment are already proven against the two-entry immutable allowlist.  Mask only that
    # variant evidence; relation kind, columns, indexes, options, and every other view stay exact.
    summary["definition"] = "<recognized daily_revenue_summary variant>"
    summary["definition_md5"] = "<recognized daily_revenue_summary variant>"
    summary["comment"] = "<recognized daily_revenue_summary variant>"
    for family in comparable.get("partition_families", []):
        family["children"] = []
    for relation in comparable.get("relations", []):
        if relation.get("name") in PARTITION_FAMILY_PREFIXES:
            relation["inheritance_child_count"] = 0
            relation["inheritance_children"] = []
    return comparable


def _without_keys(row: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key not in keys}


def _validate_dynamic_partitions(catalog: dict[str, Any]) -> None:
    """Validate every relation colliding with either dynamic-partition prefix."""

    relations = {item["name"]: item for item in catalog.get("relations", [])}
    root_columns = {
        root: [
            _without_keys(column, "relation")
            for column in catalog.get("columns", [])
            if column["relation"] == root
        ]
        for root in PARTITION_FAMILY_PREFIXES
    }
    root_indexes = {
        (item["table"], item["name"]): item
        for item in catalog.get("partition_root_indexes", [])
    }
    root_constraints = {
        (item["table"], item["name"]): item for item in catalog.get("constraints", [])
    }
    families = {
        family.get("root"): family for family in catalog.get("partition_families", [])
    }
    if set(families) != set(PARTITION_FAMILY_PREFIXES):
        raise ProductionBaseCatalogMismatch(
            "dynamic-partition family set differs from the immutable allowlist"
        )

    for root, prefix in PARTITION_FAMILY_PREFIXES.items():
        family = families[root]
        if (
            family.get("prefix") != prefix
            or tuple(family.get("expected_parent_indexes", []))
            != PARTITION_FAMILY_INDEXES[root]
        ):
            raise ProductionBaseCatalogMismatch(
                f"dynamic-partition policy drift for {root}"
            )
        root_relation = relations.get(root)
        if root_relation is None:
            raise ProductionBaseCatalogMismatch(f"partition root is missing: {root}")
        if (
            root_relation.get("inheritance_parent_count") != 0
            or root_relation.get("inheritance_parents") != []
        ):
            raise ProductionBaseCatalogMismatch(
                f"partition root must not inherit from another relation: {root}"
            )
        expected_acl = {
            key: root_relation[key]
            for key in ("owner_is_current_user", "acl_is_default", "acl")
        }
        expected_relation_metadata = {
            key: root_relation[key]
            for key in (
                "persistence",
                "row_security",
                "force_row_security",
                "replica_identity",
                "physical_attribute_count",
                "dropped_attribute_count",
                "access_method",
                "tablespace",
                "options",
            )
        }
        expected_relation_metadata["access_method"] = "heap"
        root_policies = [
            _without_keys(policy, "table") for policy in family.get("root_policies", [])
        ]
        seen_names: set[str] = set()
        seen_bounds: set[str] = set()
        for child in family.get("children", []):
            name = child.get("name")
            if (
                not isinstance(name, str)
                or not name.startswith(prefix)
                or name in seen_names
            ):
                raise ProductionBaseCatalogMismatch(
                    f"invalid or duplicate {root} partition-prefix relation: {name!r}"
                )
            seen_names.add(name)
            if (
                child.get("kind") != "r"
                or child.get("is_partition") is not True
                or child.get("direct_parent_count") != 1
                or child.get("direct_parent") != root
                or child.get("partition_root") != root
                or child.get("owner_is_current_user") is not True
                or child.get("name_bound_aligned") is not True
            ):
                raise ProductionBaseCatalogMismatch(
                    f"invalid parent/kind/owner/bound for dynamic partition {name!r}"
                )
            if {
                key: child.get(key) for key in expected_relation_metadata
            } != expected_relation_metadata:
                raise ProductionBaseCatalogMismatch(
                    f"physical/RLS metadata drift on dynamic partition {name!r}"
                )
            if {
                key: child.get(key)
                for key in ("owner_is_current_user", "acl_is_default", "acl")
            } != expected_acl:
                raise ProductionBaseCatalogMismatch(
                    f"ACL drift on dynamic partition {name!r}"
                )
            bound = child.get("bound")
            if not isinstance(bound, str) or bound in seen_bounds:
                raise ProductionBaseCatalogMismatch(
                    f"duplicate or missing bound on dynamic partition {name!r}"
                )
            seen_bounds.add(bound)

            child_columns = [
                _without_keys(column, "relation") for column in child.get("columns", [])
            ]
            if child_columns != root_columns[root]:
                raise ProductionBaseCatalogMismatch(
                    f"column drift on dynamic partition {name!r}"
                )

            indexes = child.get("indexes", [])
            parent_indexes = [index.get("parent_index") for index in indexes]
            if tuple(sorted(parent_indexes)) != tuple(
                sorted(PARTITION_FAMILY_INDEXES[root])
            ) or len({index.get("name") for index in indexes}) != len(indexes):
                raise ProductionBaseCatalogMismatch(
                    f"index attachment drift on dynamic partition {name!r}"
                )
            for index in indexes:
                parent_index_name = index["parent_index"]
                expected_index = root_indexes.get((root, parent_index_name))
                if expected_index is None or _without_keys(
                    index, "name", "table", "parent_index"
                ) != _without_keys(expected_index, "name", "table"):
                    raise ProductionBaseCatalogMismatch(
                        f"index definition drift on dynamic partition {name!r}: "
                        f"{index.get('name')!r}"
                    )

            child_constraints = [
                _without_keys(constraint, "table", "name")
                for constraint in child.get("constraints", [])
            ]
            if root == "p_llm_metrics":
                root_primary_key = root_constraints.get(
                    ("p_llm_metrics", "p_llm_metrics_pkey")
                )
                if root_primary_key is None:
                    raise ProductionBaseCatalogMismatch(
                        "p_llm_metrics root primary-key constraint is missing"
                    )
                expected_child_constraint = _without_keys(
                    root_primary_key, "table", "name"
                )
                expected_child_constraint.update(
                    {
                        "no_inherit": False,
                        "local": False,
                        "inheritance_count": 1,
                        "parent_constraint": "p_llm_metrics_pkey",
                    }
                )
                expected_child_constraints = [expected_child_constraint]
            else:
                expected_child_constraints = []
            if child_constraints != expected_child_constraints:
                raise ProductionBaseCatalogMismatch(
                    f"constraint drift on dynamic partition {name!r}"
                )
            if child.get("triggers"):
                raise ProductionBaseCatalogMismatch(
                    f"unexpected user trigger on dynamic partition {name!r}"
                )
            if child.get("rules"):
                raise ProductionBaseCatalogMismatch(
                    f"unexpected rewrite rule on dynamic partition {name!r}"
                )
            child_policies = [
                _without_keys(policy, "table") for policy in child.get("policies", [])
            ]
            if child_policies != root_policies:
                raise ProductionBaseCatalogMismatch(
                    f"RLS policy drift on dynamic partition {name!r}"
                )
        if root_relation.get("inheritance_child_count") != len(
            seen_names
        ) or root_relation.get("inheritance_children") != sorted(seen_names):
            raise ProductionBaseCatalogMismatch(
                f"partition-root child topology differs from enumerated family: {root}"
            )


def _validate_raw_inheritance(catalog: dict[str, Any]) -> None:
    relations = {item["name"]: item for item in catalog.get("relations", [])}
    for name in RAW_RELATIONS:
        relation = relations.get(name)
        if relation is None:
            continue
        if name in PARTITION_FAMILY_PREFIXES:
            continue
        if (
            relation.get("inheritance_parent_count") != 0
            or relation.get("inheritance_parents") != []
            or relation.get("inheritance_child_count") != 0
            or relation.get("inheritance_children") != []
        ):
            raise ProductionBaseCatalogMismatch(
                f"nonpartition raw relation has unexpected inheritance topology: {name}"
            )


def parse_production_base_catalog_manifest(payload: bytes) -> dict[str, Any]:
    """Verify canonical bytes before decoding and structurally validating the manifest."""

    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != PRODUCTION_BASE_CATALOG_SHA256:
        raise RuntimeError(
            "production-base catalog manifest byte digest mismatch: "
            f"expected={PRODUCTION_BASE_CATALOG_SHA256}, actual={actual_digest}"
        )
    manifest = json.loads(payload.decode("utf-8"))
    _assert_manifest_allowlist(manifest)
    classified = _classify_daily_revenue_summary(
        manifest, manifest["daily_revenue_summary_variants"]
    )
    if classified != manifest["daily_revenue_summary_variant"]:
        raise RuntimeError("checked-in summary-view variant evidence is inconsistent")
    return manifest


def load_production_base_catalog_manifest() -> dict[str, Any]:
    """Load and verify the checked-in deterministic catalog-manifest bytes."""

    return parse_production_base_catalog_manifest(CATALOG_MANIFEST_PATH.read_bytes())


def render_production_base_catalog_manifest(catalog: dict[str, Any]) -> str:
    """Return canonical checked-in JSON bytes for a collected catalog."""

    manifest = (
        deepcopy(catalog)
        if "daily_revenue_summary_variants" in catalog
        else _manifest_from_fresh_catalog(catalog)
    )
    _assert_manifest_allowlist(manifest)
    if (
        _classify_daily_revenue_summary(
            manifest, manifest["daily_revenue_summary_variants"]
        )
        != manifest["daily_revenue_summary_variant"]
    ):
        raise RuntimeError("summary-view manifest evidence is inconsistent")
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _catalog_diff(expected: dict[str, Any], actual: dict[str, Any]) -> str:
    expected_lines = json.dumps(expected, indent=2, sort_keys=True).splitlines()
    actual_lines = json.dumps(actual, indent=2, sort_keys=True).splitlines()
    diff = list(
        difflib.unified_diff(
            expected_lines,
            actual_lines,
            fromfile="expected production-base catalog",
            tofile="actual production-base catalog",
            lineterm="",
        )
    )
    maximum_lines = 240
    if len(diff) > maximum_lines:
        diff = diff[:maximum_lines] + [
            f"... {len(diff) - maximum_lines} diff lines omitted"
        ]
    return "\n".join(diff)


async def validate_production_base_catalog(
    connection, schema: str | None = None
) -> dict[str, Any]:
    """Fail closed unless the installed allowlisted catalog exactly matches the manifest."""

    expected = load_production_base_catalog_manifest()
    actual = await collect_production_base_catalog(connection, schema)
    _validate_raw_inheritance(actual)
    _validate_dynamic_partitions(actual)
    summary_variant = _classify_daily_revenue_summary(
        actual, expected["daily_revenue_summary_variants"]
    )
    if summary_variant != DAILY_REVENUE_SUMMARY_QUOTA_VARIANT:
        raise ProductionBaseCatalogMismatch(
            "historical subscription-backed daily_revenue_summary is disabled pending "
            "an exact dependency-catalog and producer-provenance contract"
        )
    actual["daily_revenue_summary_variant"] = summary_variant
    comparable_expected = _catalog_for_exact_comparison(expected)
    comparable_actual = _catalog_for_exact_comparison(actual)
    if comparable_actual != comparable_expected:
        raise ProductionBaseCatalogMismatch(
            "installed production-base catalog differs from the immutable fresh manifest:\n"
            + _catalog_diff(comparable_expected, comparable_actual)
        )
    return actual
