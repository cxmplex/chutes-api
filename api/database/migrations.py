"""Serialized dbmate startup migrations for every API worker."""

import asyncio
import hashlib
import os
from pathlib import Path
from loguru import logger
from sqlalchemy import text
from sqlalchemy.engine import make_url

import api.database.orms  # noqa: F401
from api.config import settings
from api.database import create_application_tables, engine
from api.database.production_base_catalog import (
    PRODUCTION_BASE_CATALOG_SHA256,
    collect_production_base_catalog,
    load_production_base_catalog_manifest,
    production_base_contract_sha256,
    validate_production_base_catalog,
)


MIGRATION_LOCK_KEY = "chutes-api-dbmate-migrations-v1"
PRODUCTION_BASE_SQL_PATH = Path(__file__).with_name("production_base.sql")
# Updated deliberately whenever the reviewed immutable catalog contract changes.  This is
# independent from api/migrations/SHA256SUMS: the historical 64 migration bytes remain frozen.
PRODUCTION_BASE_SQL_SHA256 = (
    "3ba9b6bdab3fd971709d116dfaa0459321cbb43f6538357c4350c53580150286"
)
PRODUCTION_BASE_CONTRACT_NAME = "production-base-v1"
PRODUCTION_BASE_POSTGRES_MAJOR = 15
PRODUCTION_BASE_CONTRACT_SHA256 = production_base_contract_sha256(
    PRODUCTION_BASE_SQL_SHA256
)

# Immutable versions present in the production API base used for this remediation. Branch-added
# migrations must never be inferred into this set by timestamp: every version outside this exact
# tuple remains visible to dbmate and runs against both existing and freshly bootstrapped schemas.
PRODUCTION_BASE_MIGRATION_VERSIONS: tuple[str, ...] = (
    "20241101123129",
    "20241101150057",
    "20241106123144",
    "20241113191447",
    "20241118131550",
    "20241122174045",
    "20241128104225",
    "20241201113452",
    "20241202095623",
    "20241211122523",
    "20241212104206",
    "20241213085609",
    "20241214121531",
    "20241214123318",
    "20241214144031",
    "20241216101012",
    "20241217110214",
    "20241221115644",
    "20241227084133",
    "20241229094223",
    "20241229142051",
    "20241231195935",
    "20250117101020",
    "20250118143120",
    "20250118204148",
    "20250122121028",
    "20250128185705",
    "20250128185835",
    "20250203180911",
    "20250207120000",
    "20250218081133",
    "20250218081504",
    "20250219081020",
    "20250306143614",
    "20250319073422",
    "20250319074720",
    "20250415103135",
    "20250423083926",
    "20250424134911",
    "20250512084635",
    "20250705010101",
    "20250709175230",
    "20250712111758",
    "20250716111259",
    "20250716155308",
    "20250720084231",
    "20250726171323",
    "20250727133106",
    "20250824113239",
    "20250829115200",
    "20250903081317",
    "20250918104132",
    "20251030165517",
    "20251102184128",
    "20251229142400",
    "20260102190913",
    "20260115120000",
    "20260115120100",
    "20260131120000",
    "20260131120100",
    "20260218120000",
    "20260403120000",
    "20260513000000",
    "20260626120000",
)
# Exact additional ledger witnessed in the backed-up disposable dev snapshot (98 total).  This is
# a one-time WIP adoption shape, not a production claim and not a generic permission to bless gaps.
REVIEWED_DEV_WIP_ADDITIONAL_VERSIONS: tuple[str, ...] = (
    "20260528120000",
    "20260529150000",
    "20260529160000",
    "20260603120000",
    "20260603170000",
    "20260604120000",
    "20260605120000",
    "20260605130000",
    "20260607120000",
    "20260610120000",
    "20260629120000",
    "20260703120000",
    "20260703130000",
    "20260703140000",
    "20260704160000",
    "20260706120000",
    "20260713140000",
    "20260713150000",
    "20260713160000",
    "20260713170000",
    "20260713220000",
    "20260714070000",
    "20260714071000",
    "20260714072000",
    "20260714073000",
    "20260714100000",
    "20260714110000",
    "20260715120000",
    "20260715121000",
    "20260720200000",
    "20260722021500",
    "20260722030000",
    "20260722040000",
    "20260722050000",
)
_DBMATE_SSLMODES = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)
_DBMATE_ENV_ALLOWLIST = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLCRL",
        "PGSSLKEY",
        "PGSSLCERT",
        "PGSSLROOTCERT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
)

# Functions below are replaced by the immutable base because the restored dev catalog contains
# several exact deployed predecessors.  Hash the deterministic pg_get_functiondef output without
# collapsing whitespace (which can be semantic inside string literals).  Any production-only
# predecessor, including an out-of-band get_diffusion_metrics body, remains blocked until an
# authoritative production snapshot supplies its exact fingerprint.
_REPLACEABLE_FUNCTION_BODY_SHA256: dict[tuple[str, str], frozenset[str]] = {
    ("backfill_llm_metrics", "start_date date, end_date date"): frozenset(
        {"2e87381361ee61ec8ad5abf74fb597d9dad3953cf63b0026dea1804f7b79dedb"}
    ),
    ("create_llm_metrics_part", "partition_date date"): frozenset(
        {
            "92218dae683c8820364311353d6d341247387e42ed9acf0e6cb34a58acb3f8e6",
            "9c2dcf3f48335d287e880545f3117256cf82cf9b39d10865f1f05724e3c0ba1f",
        }
    ),
    ("fn_chute_history_delete", ""): frozenset(
        {"f359cd5af84c97b79aba510c5bc7149f6089d4afc578468580acc819bf46d5d3"}
    ),
    ("fn_chute_history_insert", ""): frozenset(
        {"78ef03dfad5feadf590862a6b4c9ed571afe1136bccb72a3ab202d45de9f10cc"}
    ),
    ("fn_chute_history_update", ""): frozenset(
        {"4b569f02d85cfbc95b53d2e33c33b9bb54dbb9e1640226f2b0e4cb8959bd7197"}
    ),
    ("fn_image_history_delete", ""): frozenset(
        {"286d9be633462c3e69c568fc830348eb7e459545a96772faeee040cbd7bee78a"}
    ),
    ("fn_image_history_insert", ""): frozenset(
        {"efff508159203a0246aa30108bb0c011579074692cb1aa45db1e8cda00137e30"}
    ),
    ("fn_image_history_update", ""): frozenset(
        {"efff508159203a0246aa30108bb0c011579074692cb1aa45db1e8cda00137e30"}
    ),
    ("fn_instance_audit_delete", ""): frozenset(
        {
            "5c80544aea04fb3577156d3dc94e7acc9eb4d7b9c9170d2e122c9d793d37246f",
            "549cca1526b974ed14134fdabb62c14023969976a53eff87bf619a6258646049",
        }
    ),
    ("fn_instance_audit_insert", ""): frozenset(
        {
            "700b2330ce256b0849d154224dde88dfdc256674c7b26ebefcd68503f8d4f840",
            "29afe45d14fa1b17c3cc3cc2da78db644c7e7a4ff79eadf1bb080e61d41f42c1",
        }
    ),
    ("fn_instance_audit_update", ""): frozenset(
        {
            "e71b3114b89188cce008dc042d850a23253d335552058b536cc0f3cfb3863c99",
            "bef21f4db79f7c6c2872e2612583cc03dc4e3526c7d9536c431ee3b6b64d2e65",
        }
    ),
    ("fn_instance_compute_history_delete", ""): frozenset(
        {
            "cfee13a10ced8d73f98cf00e8c6056094e796ac00e9e62fc540da13b9c21ca83",
            "15a54d1813d4e8993f2c8e5c672240eb265d84c8a3ee3fad65d99ce7debc55cc",
        }
    ),
    ("fn_instance_compute_history_update", ""): frozenset(
        {
            "b952e1e533c7a8493bbe280af410a7b78419964a743f6f6db017fdeec901a828",
            "ee9ce9de9de715b241136ee2ea3b0950df782c0d58be2a572d189a00ea411bbf",
        }
    ),
    ("fn_node_history_delete", ""): frozenset(
        {"516c026188d4c9e4ec238089f85af59a9c16bc3c1c4f09a6a08bd34a1687e933"}
    ),
    ("fn_node_history_insert", ""): frozenset(
        {"833706cd4966716cd7539aac93376e7031dcdb3816a382e045df450f61bb4d56"}
    ),
    ("fn_reset_job_assignment", ""): frozenset(
        {"4bcf04f156a183786b7f369bd18ddd4f61d8e0d209452a5397075c11d396833e"}
    ),
    ("gen_llm_metrics_for_day", "target_date date"): frozenset(
        {"d2127103f65a187528136080fcac3f0b3f26ecb2a2ff719c6209a06ed37f37df"}
    ),
    ("get_diffusion_metrics", "start_date date, end_date date"): frozenset(
        {"2d5ae76be5f17d6001de656625faf360602f4f6dd72520d8232af9b0082cf783"}
    ),
    ("get_llm_metrics", "start_date date, end_date date"): frozenset(
        {"87255d8899ea7661da6b1692251eb9936101973a070b4840fd050c47f0701031"}
    ),
    ("increase_bounty", "target_chute_id text"): frozenset(
        {
            "26d148a2df3e01bcf1f266997fef4bddc7e5c5985d93cf475ff672d3f5acf82e",
            "ba6ae92aff547d8063866d9d1ff56623d224cd71478a9dffc41c52f32a0068de",
        }
    ),
    ("initialize_bounty", ""): frozenset(
        {
            "a5699b6a6df577ae9354b5f2ac95b13cf73c684ada4d141f5c817b7661480387",
            "c074e3761c3bdf886acf40c88f5c5e81709e18aac98770c5120f2f6092d1d75b",
        }
    ),
    ("insert_invocation", ""): frozenset(
        {
            "11b1b17574226212f49c4409aabad97fa71caf7ebaee0b173cf7b77301b24f49",
            "999b37bc59a9ccbfa36783970c11b876e27adc26601156e938380b3480be69b8",
            "707adc1657a66f16e4132170a498b622b1dac9c5fc462ce83cc50e03e76aec21",
        }
    ),
    ("populate_llm_metrics_for_day", "target_date date"): frozenset(
        {"bda41931c943d6e6566d51923fcb23f93e9a99d08a7a6b91bef95401f166ef27"}
    ),
    ("refresh_llm_metrics_for_day", "target_date date"): frozenset(
        {"1ae44f3cb25c24537e26036a64e199a59f8dfc83d6b64dc29d0b2ac324e266da"}
    ),
    ("track_instance_node_assignment", ""): frozenset(
        {"308759c407101eab367e541d48be92be2b12ca3d8c27a57f587eb735eb79452c"}
    ),
    ("update_balance_on_instance_delete", ""): frozenset(
        {"15761ff1b3bba8cd054d4193a713a8dae7eaa6a19abe56d7454f72cd773ab143"}
    ),
    ("version_numbers", "ver text"): frozenset(
        {
            "5e4626c3df0e22af04a2889817ead508cd743c1855b9aceb88107e4eced28a39",
            "3459f76263eb5becb7132c8d1c8d31a9bf92d5097b31bbc99b86d382a67f9fa1",
        }
    ),
}
_INVOCATIONS_VIEW_BODY_MD5 = "0a673cd6e5d435a9d8fad74efc1c2ab3"


def dbmate_url() -> str:
    """Render dbmate's URL structurally without corrupting credentials or query values."""
    db_url = make_url(settings.sqlalchemy)
    db_url = db_url.set(drivername=db_url.drivername.replace("+asyncpg", ""))
    if "sslmode" not in db_url.query:
        sslmode = str(getattr(settings, "db_ssl", "require")).strip().lower()
        if sslmode not in _DBMATE_SSLMODES:
            raise RuntimeError(f"Unsupported DB_SSL mode for dbmate: {sslmode!r}")
        db_url = db_url.update_query_dict({"sslmode": sslmode})
    return db_url.render_as_string(hide_password=False)


def dbmate_environment() -> dict[str, str]:
    """Pass dbmate only transport essentials and its credential URL outside process argv."""
    child_environment = {
        name: value
        for name, value in os.environ.items()
        if name in _DBMATE_ENV_ALLOWLIST
    }
    child_environment["DATABASE_URL"] = dbmate_url()
    return child_environment


def _dbmate_output_evidence(stream: str, output: bytes, returncode: int) -> str:
    """Describe subprocess diagnostics without decoding or logging their secret-bearing bytes."""
    if stream not in {"stdout", "stderr"}:
        raise ValueError(f"unknown dbmate stream: {stream!r}")
    return (
        f"dbmate {stream}: bytes={len(output)}, "
        f"sha256={hashlib.sha256(output).hexdigest()}, exit_code={returncode}"
    )


def historical_migration_versions() -> list[str]:
    """Return only the immutable production-base versions represented by ORM bootstrap."""
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    files_by_version: dict[str, list[Path]] = {}
    for migration_path in migrations_dir.glob("*.sql"):
        version = migration_path.name.split("_", 1)[0]
        if version in PRODUCTION_BASE_MIGRATION_VERSIONS:
            files_by_version.setdefault(version, []).append(migration_path)

    missing = [
        version
        for version in PRODUCTION_BASE_MIGRATION_VERSIONS
        if version not in files_by_version
    ]
    duplicates = {
        version: paths for version, paths in files_by_version.items() if len(paths) != 1
    }
    if missing or duplicates:
        duplicate_names = {
            version: [path.name for path in paths]
            for version, paths in sorted(duplicates.items())
        }
        raise RuntimeError(
            "The immutable production migration baseline does not match disk: "
            f"missing={missing!r}, duplicates={duplicate_names!r}"
        )
    return list(PRODUCTION_BASE_MIGRATION_VERSIONS)


def migration_versions_on_disk() -> set[str]:
    """Return every unique timestamped migration version currently shipped by the API."""
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    files_by_version: dict[str, list[str]] = {}
    for migration_path in migrations_dir.glob("*.sql"):
        version = migration_path.name.split("_", 1)[0]
        if version.isdigit():
            files_by_version.setdefault(version, []).append(migration_path.name)
    duplicates = {
        version: sorted(names)
        for version, names in files_by_version.items()
        if len(names) != 1
    }
    if duplicates:
        raise RuntimeError(f"Duplicate API migration versions on disk: {duplicates!r}")
    return set(files_by_version)


def production_base_sql() -> str:
    """Load the reviewed production-base DDL and reject unpinned local bytes."""
    source = PRODUCTION_BASE_SQL_PATH.read_text(encoding="utf-8")
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual != PRODUCTION_BASE_SQL_SHA256:
        raise RuntimeError(
            "The immutable production-base SQL digest does not match: "
            f"expected={PRODUCTION_BASE_SQL_SHA256}, actual={actual}"
        )
    return source


async def _execute_production_base_sql(connection) -> None:
    """Execute the complete multi-statement contract through asyncpg unchanged."""
    raw = await connection.get_raw_connection()
    await raw.driver_connection.execute(production_base_sql())


async def _validate_preexisting_replaceable_objects(
    connection,
) -> dict[tuple[str, str], tuple[str, str | None]]:
    """Reject unknown replaceable objects and retain function privilege custody evidence."""
    schema = await connection.scalar(text("SELECT current_schema()"))
    if not isinstance(schema, str):
        raise RuntimeError(
            "current_schema() did not resolve before production-base preflight"
        )
    current_user = await connection.scalar(text("SELECT current_user"))
    names = sorted({name for name, _arguments in _REPLACEABLE_FUNCTION_BODY_SHA256})
    preexisting_catalog = await collect_production_base_catalog(connection, schema)
    if preexisting_catalog["unexpected_function_overloads"]:
        raise RuntimeError(
            "Refusing unexpected same-name production-base function overloads: "
            f"{preexisting_catalog['unexpected_function_overloads']!r}"
        )
    expected_manifest = load_production_base_catalog_manifest()
    expected_functions = {
        (item["name"], item["argument_types"]): item
        for item in expected_manifest["functions"]
    }
    actual_functions = {
        (item["name"], item["argument_types"]): item
        for item in preexisting_catalog["functions"]
    }
    rows = (
        await connection.execute(
            text(
                "SELECT procedure.proname AS function_name, "
                "oidvectortypes(procedure.proargtypes) AS argument_types, "
                "pg_get_function_identity_arguments(procedure.oid) AS identity_arguments, "
                "procedure.prosrc AS body, "
                "pg_get_userbyid(procedure.proowner) AS owner, "
                "procedure.proacl::text AS acl "
                "FROM pg_proc AS procedure "
                "JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND procedure.proname = ANY(:names) "
                "ORDER BY procedure.proname, identity_arguments"
            ),
            {"names": names},
        )
    ).mappings()
    privilege_evidence: dict[tuple[str, str], tuple[str, str | None]] = {}
    for row in rows:
        identity = (row["function_name"], row["identity_arguments"])
        body_sha256 = hashlib.sha256(row["body"].encode("utf-8")).hexdigest()
        allowed = _REPLACEABLE_FUNCTION_BODY_SHA256.get(identity)
        if allowed is None or body_sha256 not in allowed:
            raise RuntimeError(
                "Refusing to replace an unknown production-base function: "
                f"identity={identity!r}, body_sha256={body_sha256!r}"
            )
        type_identity = (row["function_name"], row["argument_types"])
        actual_metadata = dict(actual_functions[type_identity])
        expected_metadata = dict(expected_functions[type_identity])
        actual_metadata.pop("body_sha256")
        expected_metadata.pop("body_sha256")
        if actual_metadata != expected_metadata:
            raise RuntimeError(
                "Refusing to replace a production-base function with unknown metadata: "
                f"identity={identity!r}, expected={expected_metadata!r}, "
                f"actual={actual_metadata!r}"
            )
        if row["owner"] != current_user:
            raise RuntimeError(
                "Refusing to replace a production-base function owned by another role: "
                f"identity={identity!r}, owner={row['owner']!r}"
            )
        privilege_evidence[identity] = (row["owner"], row["acl"])

    view = (
        (
            await connection.execute(
                text(
                    "SELECT relation.relkind::text AS relation_kind, "
                    "md5(regexp_replace(replace(pg_get_viewdef(relation.oid, true), "
                    "current_schema() || '.', ''), '[[:space:]]+', ' ', 'g')) AS body_md5 "
                    "FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = current_schema() "
                    "AND relation.relname = 'invocations'"
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if view is not None and (
        view["relation_kind"] != "v" or view["body_md5"] != _INVOCATIONS_VIEW_BODY_MD5
    ):
        raise RuntimeError(
            "Refusing to replace an unknown invocations relation: "
            f"kind={view['relation_kind']!r}, body_md5={view['body_md5']!r}"
        )

    expected_triggers = {
        (item["name"], item["table"]): item for item in expected_manifest["triggers"]
    }
    actual_triggers = {
        (item["name"], item["table"]): item for item in preexisting_catalog["triggers"]
    }
    for identity, actual_trigger in actual_triggers.items():
        expected_trigger = expected_triggers.get(identity)
        comparable_actual = dict(actual_trigger)
        comparable_expected = (
            None if expected_trigger is None else dict(expected_trigger)
        )
        comparable_actual.pop("definition", None)
        if comparable_expected is not None:
            comparable_expected.pop("definition", None)
        if comparable_expected is None or comparable_actual != comparable_expected:
            raise RuntimeError(
                "Refusing to replace an unknown production-base trigger: "
                f"identity={identity!r}, expected={comparable_expected!r}, "
                f"actual={comparable_actual!r}"
            )

    trigger_rows = (
        await connection.execute(
            text(
                "SELECT trigger_row.tgname AS trigger_name, relation.relname AS table_name, "
                "trigger_row.tgparentid AS parent_oid, trigger_row.tgisinternal AS internal "
                "FROM pg_trigger AS trigger_row "
                "JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND trigger_row.tgname = ANY(:names) "
                "ORDER BY trigger_row.tgname, relation.relname"
            ),
            {"names": sorted({name for name, _table in expected_triggers})},
        )
    ).mappings()
    for row in trigger_rows:
        identity = (row["trigger_name"], row["table_name"])
        if (
            identity not in expected_triggers
            or row["parent_oid"] != 0
            or row["internal"]
        ):
            raise RuntimeError(
                "Refusing a cloned/internal production-base trigger: "
                f"identity={identity!r}, catalog={dict(row)!r}"
            )
    return privilege_evidence


async def _validate_preserved_function_privileges(
    connection, evidence: dict[tuple[str, str], tuple[str, str | None]]
) -> None:
    """Prove CREATE OR REPLACE retained every pre-existing function owner and ACL."""
    if not evidence:
        return
    rows = (
        await connection.execute(
            text(
                "SELECT procedure.proname AS function_name, "
                "pg_get_function_identity_arguments(procedure.oid) AS identity_arguments, "
                "pg_get_userbyid(procedure.proowner) AS owner, procedure.proacl::text AS acl "
                "FROM pg_proc AS procedure "
                "JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND procedure.proname = ANY(:names)"
            ),
            {"names": sorted({identity[0] for identity in evidence})},
        )
    ).mappings()
    actual = {
        (row["function_name"], row["identity_arguments"]): (row["owner"], row["acl"])
        for row in rows
        if (row["function_name"], row["identity_arguments"]) in evidence
    }
    if actual != evidence:
        raise RuntimeError(
            "Production-base function owner/ACL custody changed during replacement: "
            f"expected={evidence!r}, actual={actual!r}"
        )


async def _validate_schema_migrations_catalog(
    connection, *, required: bool, allow_unbounded_predecessor: bool = False
) -> str | None:
    """Validate dbmate's ledger relation before trusting any recorded version value."""
    relation = (
        (
            await connection.execute(
                text(
                    "SELECT relation.relkind::text AS relation_kind, relation.oid AS relation_oid, "
                    "relation.relpersistence::text AS persistence, "
                    "access_method.amname AS access_method, "
                    "relation.relrowsecurity AS row_security, "
                    "relation.relforcerowsecurity AS force_row_security, "
                    "relation.relispartition AS is_partition, "
                    "relation.reloptions AS options, "
                    "relation.relreplident::text AS replica_identity, "
                    "relation.reltablespace AS tablespace_oid, "
                    "pg_get_userbyid(relation.relowner) = current_user AS owner_is_current, "
                    "relation.relacl IS NULL AS acl_is_default, "
                    "(SELECT count(*) FROM pg_policy AS policy "
                    "WHERE policy.polrelid = relation.oid) AS policy_count, "
                    "(SELECT count(*) FROM pg_inherits AS inheritance "
                    "WHERE inheritance.inhrelid = relation.oid "
                    "OR inheritance.inhparent = relation.oid) AS inheritance_count "
                    "FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "LEFT JOIN pg_am AS access_method ON access_method.oid = relation.relam "
                    "WHERE namespace.nspname = current_schema() "
                    "AND relation.relname = 'schema_migrations'"
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if relation is None:
        if required:
            raise RuntimeError("schema_migrations was not created")
        return None
    if (
        relation["relation_kind"] != "r"
        or relation["persistence"] != "p"
        or relation["access_method"] != "heap"
        or relation["row_security"]
        or relation["force_row_security"]
        or relation["is_partition"]
        or relation["options"] is not None
        or relation["replica_identity"] != "d"
        or relation["tablespace_oid"] != 0
        or relation["owner_is_current"] is not True
        or relation["acl_is_default"] is not True
        or relation["policy_count"] != 0
        or relation["inheritance_count"] != 0
    ):
        raise RuntimeError(
            "schema_migrations must be an unmodified permanent heap table: "
            f"catalog={dict(relation)!r}"
        )
    signature = await connection.scalar(
        text(
            "SELECT string_agg(attribute.attnum::text || ':' || attribute.attname || ':' "
            "|| format_type(attribute.atttypid, attribute.atttypmod) || ':' "
            "|| attribute.attnotnull::text || ':' "
            "|| (attribute.attcollation = type_row.typcollation)::text || ':' "
            "|| (attribute.attstorage = type_row.typstorage)::text || ':' "
            "|| attribute.attcompression::text || ':' "
            "|| attribute.attstattarget::text || ':' "
            "|| attribute.attidentity::text || ':' "
            "|| attribute.attgenerated::text || ':' "
            "|| attribute.attislocal::text || ':' "
            "|| attribute.attinhcount::text || ':' "
            "|| (attribute.attacl IS NULL)::text || ':' "
            "|| COALESCE(attribute.attoptions::text, '<null>') || ':' "
            "|| COALESCE(attribute.attfdwoptions::text, '<null>') || ':' "
            "|| COALESCE(pg_get_expr(attribute_default.adbin, "
            "attribute_default.adrelid, true), '<null>'), '|' ORDER BY attribute.attnum) "
            "FROM pg_attribute AS attribute "
            "JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid "
            "LEFT JOIN pg_attrdef AS attribute_default "
            "ON attribute_default.adrelid = attribute.attrelid "
            "AND attribute_default.adnum = attribute.attnum "
            "WHERE attribute.attrelid = :relation_oid "
            "AND attribute.attnum > 0 AND NOT attribute.attisdropped"
        ),
        {"relation_oid": relation["relation_oid"]},
    )
    dropped_attribute_count = await connection.scalar(
        text(
            "SELECT count(*) FROM pg_attribute "
            "WHERE attrelid = :relation_oid AND attnum > 0 AND attisdropped"
        ),
        {"relation_oid": relation["relation_oid"]},
    )
    constraints = list(
        (
            await connection.execute(
                text(
                    "SELECT conname AS name, contype::text AS type, "
                    "convalidated AS validated, condeferrable AS deferrable, "
                    "condeferred AS initially_deferred, conkey::smallint[] AS key_columns, "
                    "conparentid AS parent_oid, conislocal AS is_local, "
                    "coninhcount AS inheritance_count, connoinherit AS no_inherit, "
                    "pg_get_constraintdef(oid, true) AS definition "
                    "FROM pg_constraint WHERE conrelid = :relation_oid "
                    "ORDER BY contype, conname"
                ),
                {"relation_oid": relation["relation_oid"]},
            )
        ).mappings()
    )
    trigger_count = await connection.scalar(
        text("SELECT count(*) FROM pg_trigger WHERE tgrelid = :relation_oid"),
        {"relation_oid": relation["relation_oid"]},
    )
    rule_count = await connection.scalar(
        text(
            "SELECT count(*) FROM pg_rewrite "
            "WHERE ev_class = :relation_oid AND rulename <> '_RETURN'"
        ),
        {"relation_oid": relation["relation_oid"]},
    )
    index_count = await connection.scalar(
        text("SELECT count(*) FROM pg_index WHERE indrelid = :relation_oid"),
        {"relation_oid": relation["relation_oid"]},
    )
    indexes = list(
        (
            await connection.execute(
                text(
                    "SELECT index_relation.relkind::text AS relation_kind, "
                    "index_relation.relispartition AS is_partition, "
                    "index_relation.relispopulated AS is_populated, "
                    "index_row.indisunique AS is_unique, "
                    "index_row.indisprimary AS is_primary, "
                    "index_row.indisexclusion AS is_exclusion, "
                    "index_row.indimmediate AS is_immediate, "
                    "index_row.indisvalid AS is_valid, "
                    "index_row.indisready AS is_ready, "
                    "index_row.indislive AS is_live, "
                    "index_row.indisreplident AS is_replica_identity, "
                    "index_row.indisclustered AS is_clustered, "
                    "index_row.indcheckxmin AS check_xmin, "
                    "index_row.indnullsnotdistinct AS nulls_not_distinct, "
                    "index_row.indnatts AS attribute_count, "
                    "index_row.indnkeyatts AS key_attribute_count, "
                    "access_method.amname AS access_method, "
                    "index_relation.relpersistence::text AS persistence, "
                    "index_relation.reloptions AS options, "
                    "index_relation.reltablespace AS tablespace_oid, "
                    "index_relation.relacl::text AS acl, "
                    "pg_get_userbyid(index_relation.relowner) = current_user "
                    "AS owner_is_current, "
                    "pg_get_expr(index_row.indexprs, index_row.indrelid, true) AS expressions, "
                    "pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate, "
                    "array_agg(attribute.attname ORDER BY key_column.position) AS columns, "
                    "array_agg(operator_class.opcname ORDER BY key_column.position) AS opclasses, "
                    "array_agg(operator_namespace.nspname ORDER BY key_column.position) "
                    "AS opclass_namespaces, "
                    "array_agg(index_row.indoption[key_column.position - 1] "
                    "ORDER BY key_column.position) AS options_by_column, "
                    "bool_and(index_row.indcollation[key_column.position - 1] "
                    "= attribute.attcollation) AS expected_collations "
                    "FROM pg_index AS index_row "
                    "JOIN pg_class AS index_relation "
                    "ON index_relation.oid = index_row.indexrelid "
                    "JOIN pg_am AS access_method ON access_method.oid = index_relation.relam "
                    "JOIN unnest(index_row.indkey) WITH ORDINALITY "
                    "AS key_column(attribute_number, position) ON true "
                    "JOIN pg_attribute AS attribute "
                    "ON attribute.attrelid = index_row.indrelid "
                    "AND attribute.attnum = key_column.attribute_number "
                    "JOIN unnest(index_row.indclass) WITH ORDINALITY "
                    "AS class_column(operator_class_oid, position) "
                    "ON class_column.position = key_column.position "
                    "JOIN pg_opclass AS operator_class "
                    "ON operator_class.oid = class_column.operator_class_oid "
                    "JOIN pg_namespace AS operator_namespace "
                    "ON operator_namespace.oid = operator_class.opcnamespace "
                    "WHERE index_row.indrelid = :relation_oid "
                    "GROUP BY index_row.indexrelid, index_relation.relkind, "
                    "index_relation.relispartition, index_relation.relispopulated, "
                    "index_row.indisunique, "
                    "index_row.indisprimary, index_row.indisexclusion, "
                    "index_row.indimmediate, index_row.indisvalid, index_row.indisready, "
                    "index_row.indislive, index_row.indisreplident, "
                    "index_row.indisclustered, "
                    "index_row.indcheckxmin, "
                    "index_row.indnullsnotdistinct, index_row.indnatts, "
                    "index_row.indnkeyatts, access_method.amname, "
                    "index_relation.relpersistence, index_relation.reloptions, "
                    "index_relation.reltablespace, index_relation.relacl::text, "
                    "index_relation.relowner, "
                    "index_row.indexprs, index_row.indpred, index_row.indrelid, "
                    "index_row.indoption, index_row.indcollation"
                ),
                {"relation_oid": relation["relation_oid"]},
            )
        ).mappings()
    )
    constraint = constraints[0] if len(constraints) == 1 else None
    index = indexes[0] if len(indexes) == 1 else None
    final_signature = (
        "1:version:character varying(255):true:true:true::-1:::true:0:"
        "true:<null>:<null>:<null>"
    )
    reviewed_dev_signature = (
        "1:version:character varying:true:true:true::-1:::true:0:"
        "true:<null>:<null>:<null>"
    )
    signature_is_allowed = signature == final_signature or (
        allow_unbounded_predecessor and signature == reviewed_dev_signature
    )
    if (
        not signature_is_allowed
        or dropped_attribute_count != 0
        or constraint is None
        or constraint["name"] != "schema_migrations_pkey"
        or constraint["type"] != "p"
        or constraint["validated"] is not True
        or constraint["deferrable"] is not False
        or constraint["initially_deferred"] is not False
        or constraint["parent_oid"] != 0
        or constraint["is_local"] is not True
        or constraint["inheritance_count"] != 0
        or constraint["no_inherit"] is not True
        or constraint["key_columns"] != [1]
        or constraint["definition"] != "PRIMARY KEY (version)"
        or trigger_count != 0
        or rule_count != 0
        or index_count != 1
        or index is None
        or index["relation_kind"] != "i"
        or index["is_partition"] is not False
        or index["is_populated"] is not True
        or index["is_unique"] is not True
        or index["is_primary"] is not True
        or index["is_exclusion"] is not False
        or index["is_immediate"] is not True
        or index["is_valid"] is not True
        or index["is_ready"] is not True
        or index["is_live"] is not True
        or index["is_replica_identity"] is not False
        or index["is_clustered"] is not False
        or index["check_xmin"] is not False
        or index["nulls_not_distinct"] is not False
        or index["attribute_count"] != 1
        or index["key_attribute_count"] != 1
        or index["access_method"] != "btree"
        or index["persistence"] != "p"
        or index["options"] is not None
        or index["tablespace_oid"] != 0
        or index["acl"] is not None
        or index["owner_is_current"] is not True
        or index["expressions"] is not None
        or index["predicate"] is not None
        or index["columns"] != ["version"]
        or index["opclasses"] != ["text_ops"]
        or index["opclass_namespaces"] != ["pg_catalog"]
        or index["options_by_column"] != [0]
        or index["expected_collations"] is not True
    ):
        raise RuntimeError(
            "schema_migrations has an unknown catalog shape: "
            f"columns={signature!r}, dropped_columns={dropped_attribute_count!r}, "
            f"constraints={constraints!r}, indexes={indexes!r}, "
            f"index_count={index_count!r}, triggers={trigger_count!r}, rules={rule_count!r}"
        )
    return "final" if signature == final_signature else "reviewed-dev-unbounded"


async def _validate_production_base_postgres_major(connection) -> None:
    """Reject unsupported server deparser/catalog semantics before any contract mutation."""
    server_version_num = await connection.scalar(
        text("SELECT current_setting('server_version_num')::INTEGER")
    )
    if (
        not isinstance(server_version_num, int)
        or server_version_num // 10000 != PRODUCTION_BASE_POSTGRES_MAJOR
    ):
        raise RuntimeError(
            "The immutable production-base catalog is qualified only for PostgreSQL "
            f"{PRODUCTION_BASE_POSTGRES_MAJOR}; server_version_num={server_version_num!r}. "
            "No database changes were attempted."
        )


def _is_exact_prefix(actual: set[str], ordered: list[str]) -> bool:
    return actual == set(ordered[: len(actual)])


async def _validate_initial_ledger(connection, *, marker_installed: bool) -> bool:
    """Return true only for a genuinely empty fresh schema; reject partial/foreign states."""
    ledger_shape = await _validate_schema_migrations_catalog(
        connection,
        required=False,
        allow_unbounded_predecessor=not marker_installed,
    )
    ledger_exists = ledger_shape is not None
    recorded: set[str] = set()
    if ledger_exists:
        recorded = set(
            (
                await connection.execute(text("SELECT version FROM schema_migrations"))
            ).scalars()
        )
    expected = set(historical_migration_versions())
    unknown = sorted(recorded - migration_versions_on_disk())
    if unknown:
        raise RuntimeError(
            "Refusing migration ledger versions that have no source file on disk: "
            f"unknown={unknown!r}"
        )
    if recorded:
        if not expected.issubset(recorded):
            raise RuntimeError(
                "Refusing a nonempty partial production migration baseline: "
                f"missing={sorted(expected - recorded)!r}, "
                f"additional={sorted(recorded - expected)!r}"
            )
        reviewed_dev = expected | set(REVIEWED_DEV_WIP_ADDITIONAL_VERSIONS)
        if not marker_installed:
            if recorded not in (expected, reviewed_dev):
                recorded_digest = hashlib.sha256(
                    ("\n".join(sorted(recorded)) + "\n").encode()
                ).hexdigest()
                raise RuntimeError(
                    "Refusing an unmarked migration ledger that is neither the immutable "
                    "production base nor the exact witnessed dev-WIP snapshot: "
                    f"count={len(recorded)!r}, "
                    f"sha256={recorded_digest}"
                )
        else:
            all_nonbase = sorted(migration_versions_on_disk() - expected)
            remaining_after_dev = sorted(migration_versions_on_disk() - reviewed_dev)
            additions = recorded - expected
            dev_additions = recorded - reviewed_dev
            valid_ancestry = _is_exact_prefix(additions, all_nonbase) or (
                reviewed_dev.issubset(recorded)
                and _is_exact_prefix(dev_additions, remaining_after_dev)
            )
            if not valid_ancestry:
                raise RuntimeError(
                    "Refusing a marked migration ledger with gaps outside either reviewed "
                    "ancestry: "
                    f"recorded={sorted(recorded)!r}"
                )
        if ledger_shape == "reviewed-dev-unbounded":
            if marker_installed or recorded != reviewed_dev:
                raise RuntimeError(
                    "The unbounded schema_migrations predecessor is allowed only for the exact "
                    "witnessed 98-version dev-WIP ledger"
                )
            too_long = await connection.scalar(
                text(
                    "SELECT count(*) FROM ONLY schema_migrations WHERE length(version) > 255"
                )
            )
            if too_long != 0:
                raise RuntimeError(
                    "The reviewed unbounded schema_migrations ledger contains an oversized value"
                )
            await connection.execute(
                text(
                    "ALTER TABLE ONLY schema_migrations "
                    "ALTER COLUMN version TYPE VARCHAR(255)"
                )
            )
            final_shape = await _validate_schema_migrations_catalog(
                connection, required=True
            )
            if final_shape != "final":
                raise RuntimeError(
                    "schema_migrations did not converge to dbmate's final varchar(255) catalog"
                )
        return False

    if marker_installed:
        raise RuntimeError(
            "The production-base marker exists but the migration ledger is empty"
        )

    relations = list(
        (
            await connection.execute(
                text(
                    "SELECT relation.relname FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = current_schema() "
                    "AND relation.relkind IN ('r', 'p', 'v', 'm', 'S') "
                    "AND relation.relname <> 'schema_migrations' "
                    "ORDER BY relation.relname"
                )
            )
        ).scalars()
    )
    if relations:
        raise RuntimeError(
            "Refusing to bless an unledgered nonempty schema as the production base: "
            f"relations={relations!r}"
        )
    return True


async def _production_base_marker(connection) -> tuple[str, str, str, str] | None:
    """Return the exact installed contract marker, rejecting any catalog or row drift."""
    exists = await connection.scalar(
        text(
            "SELECT to_regclass(format('%I.schema_contracts', current_schema())) IS NOT NULL"
        )
    )
    if not exists:
        return None
    relation_metadata = (
        (
            await connection.execute(
                text(
                    "SELECT relation.oid AS relation_oid, relation.relkind::text AS kind, "
                    "relation.relpersistence::text AS persistence, "
                    "access_method.amname AS access_method, "
                    "relation.relrowsecurity AS row_security, "
                    "relation.relforcerowsecurity AS force_row_security, "
                    "relation.reloptions AS options, relation.relacl::text AS acl, "
                    "relation.relispartition AS is_partition, "
                    "relation.relreplident::text AS replica_identity, "
                    "relation.reltablespace AS tablespace_oid, "
                    "relation.relispopulated AS is_populated, "
                    "pg_get_userbyid(relation.relowner) = current_user AS owner_is_current, "
                    "(SELECT count(*) FROM pg_inherits AS inheritance "
                    " WHERE inheritance.inhrelid = relation.oid) AS parent_count, "
                    "(SELECT count(*) FROM pg_inherits AS inheritance "
                    " WHERE inheritance.inhparent = relation.oid) AS child_count, "
                    "(SELECT count(*) FROM pg_policy AS policy "
                    " WHERE policy.polrelid = relation.oid) AS policy_count "
                    "FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "LEFT JOIN pg_am AS access_method ON access_method.oid = relation.relam "
                    "WHERE namespace.nspname = current_schema() "
                    "AND relation.relname = 'schema_contracts'"
                )
            )
        )
        .mappings()
        .one()
    )
    relation_oid = relation_metadata["relation_oid"]
    columns = list(
        (
            await connection.execute(
                text(
                    "SELECT attribute.attnum AS position, attribute.attname AS name, "
                    "format_type(attribute.atttypid, attribute.atttypmod) AS type, "
                    "attribute.attnotnull AS not_null, "
                    "attribute.attcollation = type_row.typcollation AS default_collation, "
                    "attribute.attstorage = type_row.typstorage AS default_storage, "
                    "attribute.attcompression::text AS compression, "
                    "attribute.attstattarget AS statistics_target, "
                    "attribute.attidentity::text AS identity_kind, "
                    "attribute.attgenerated::text AS generated_kind, "
                    "attribute.attislocal AS is_local, "
                    "attribute.attinhcount AS inheritance_count, "
                    "attribute.attisdropped AS dropped, "
                    "attribute.attacl IS NULL AS acl_is_default, "
                    "attribute.attoptions AS options, "
                    "attribute.attfdwoptions AS fdw_options, "
                    "pg_get_expr(attribute_default.adbin, attribute_default.adrelid, true) "
                    "AS default_expression "
                    "FROM pg_attribute AS attribute "
                    "JOIN pg_type AS type_row ON type_row.oid = attribute.atttypid "
                    "LEFT JOIN pg_attrdef AS attribute_default "
                    "ON attribute_default.adrelid = attribute.attrelid "
                    "AND attribute_default.adnum = attribute.attnum "
                    "WHERE attribute.attrelid = :relation_oid AND attribute.attnum > 0 "
                    "ORDER BY attribute.attnum"
                ),
                {"relation_oid": relation_oid},
            )
        ).mappings()
    )
    physical_attribute_count = await connection.scalar(
        text(
            "SELECT count(*) FROM pg_attribute "
            "WHERE attrelid = :relation_oid AND attnum > 0"
        ),
        {"relation_oid": relation_oid},
    )
    expected_columns = [
        {
            "position": position,
            "name": name,
            "type": column_type,
            "not_null": True,
            "default_collation": True,
            "default_storage": True,
            "compression": "",
            "statistics_target": -1,
            "identity_kind": "",
            "generated_kind": "",
            "is_local": True,
            "inheritance_count": 0,
            "dropped": False,
            "acl_is_default": True,
            "options": None,
            "fdw_options": None,
            "default_expression": default,
        }
        for position, (name, column_type, default) in enumerate(
            (
                ("contract_name", "text", None),
                ("sql_sha256", "text", None),
                ("catalog_sha256", "text", None),
                ("contract_sha256", "text", None),
                ("catalog_variant", "text", None),
                ("applied_at", "timestamp with time zone", "now()"),
            ),
            start=1,
        )
    ]
    constraints = list(
        (
            await connection.execute(
                text(
                    "SELECT constraint_row.conname AS name, "
                    "constraint_row.contype::text AS type, "
                    "constraint_row.convalidated AS validated, "
                    "constraint_row.condeferrable AS deferrable, "
                    "constraint_row.condeferred AS initially_deferred, "
                    "constraint_row.conparentid AS parent_oid, "
                    "constraint_row.conislocal AS is_local, "
                    "constraint_row.coninhcount AS inheritance_count, "
                    "constraint_row.connoinherit AS no_inherit, "
                    "constraint_row.conkey::smallint[] AS key_columns, "
                    "constraint_row.conindid AS index_oid, "
                    "pg_get_constraintdef(constraint_row.oid, true) AS definition "
                    "FROM pg_constraint AS constraint_row "
                    "WHERE constraint_row.conrelid = :relation_oid "
                    "ORDER BY constraint_row.contype, constraint_row.conname"
                ),
                {"relation_oid": relation_oid},
            )
        ).mappings()
    )
    indexes = list(
        (
            await connection.execute(
                text(
                    "SELECT index_relation.oid AS index_oid, index_relation.relname AS name, "
                    "index_relation.relkind::text AS relation_kind, "
                    "index_relation.relispartition AS is_partition, "
                    "index_relation.relispopulated AS is_populated, "
                    "index_row.indisunique AS is_unique, "
                    "index_row.indisprimary AS is_primary, "
                    "index_row.indisexclusion AS is_exclusion, "
                    "index_row.indimmediate AS is_immediate, "
                    "index_row.indisvalid AS is_valid, index_row.indisready AS is_ready, "
                    "index_row.indislive AS is_live, "
                    "index_row.indisreplident AS is_replica_identity, "
                    "index_row.indisclustered AS is_clustered, "
                    "index_row.indcheckxmin AS check_xmin, "
                    "index_row.indnullsnotdistinct AS nulls_not_distinct, "
                    "index_row.indnatts AS attribute_count, "
                    "index_row.indnkeyatts AS key_attribute_count, "
                    "access_method.amname AS access_method, "
                    "index_relation.relpersistence::text AS persistence, "
                    "index_relation.reloptions AS options, "
                    "index_relation.reltablespace AS tablespace_oid, "
                    "index_relation.relacl::text AS acl, "
                    "pg_get_userbyid(index_relation.relowner) = current_user "
                    "AS owner_is_current, "
                    "pg_get_expr(index_row.indexprs, index_row.indrelid, true) "
                    "AS expressions, "
                    "pg_get_expr(index_row.indpred, index_row.indrelid, true) AS predicate, "
                    "array_agg(attribute.attname ORDER BY key_column.position) AS columns, "
                    "array_agg(operator_class.opcname ORDER BY key_column.position) "
                    "AS opclasses, "
                    "array_agg(operator_namespace.nspname ORDER BY key_column.position) "
                    "AS opclass_namespaces, "
                    "array_agg(index_row.indoption[key_column.position - 1] "
                    "ORDER BY key_column.position) AS options_by_column, "
                    "bool_and(index_row.indcollation[key_column.position - 1] "
                    "= attribute.attcollation) AS expected_collations "
                    "FROM pg_index AS index_row "
                    "JOIN pg_class AS index_relation "
                    "ON index_relation.oid = index_row.indexrelid "
                    "JOIN pg_am AS access_method ON access_method.oid = index_relation.relam "
                    "JOIN unnest(index_row.indkey) WITH ORDINALITY "
                    "AS key_column(attribute_number, position) ON true "
                    "JOIN pg_attribute AS attribute "
                    "ON attribute.attrelid = index_row.indrelid "
                    "AND attribute.attnum = key_column.attribute_number "
                    "JOIN unnest(index_row.indclass) WITH ORDINALITY "
                    "AS class_column(operator_class_oid, position) "
                    "ON class_column.position = key_column.position "
                    "JOIN pg_opclass AS operator_class "
                    "ON operator_class.oid = class_column.operator_class_oid "
                    "JOIN pg_namespace AS operator_namespace "
                    "ON operator_namespace.oid = operator_class.opcnamespace "
                    "WHERE index_row.indrelid = :relation_oid "
                    "GROUP BY index_relation.oid, index_relation.relname, "
                    "index_relation.relkind, index_relation.relispartition, "
                    "index_relation.relispopulated, "
                    "index_row.indisunique, index_row.indisprimary, "
                    "index_row.indisexclusion, index_row.indimmediate, "
                    "index_row.indisvalid, index_row.indisready, index_row.indislive, "
                    "index_row.indisreplident, index_row.indisclustered, "
                    "index_row.indcheckxmin, "
                    "index_row.indnullsnotdistinct, "
                    "index_row.indnatts, index_row.indnkeyatts, access_method.amname, "
                    "index_relation.relpersistence, index_relation.reloptions, "
                    "index_relation.reltablespace, "
                    "index_relation.relacl::text, index_relation.relowner, "
                    "index_row.indexprs, index_row.indpred, index_row.indrelid, "
                    "index_row.indoption, index_row.indcollation"
                ),
                {"relation_oid": relation_oid},
            )
        ).mappings()
    )
    index_count = await connection.scalar(
        text("SELECT count(*) FROM pg_index WHERE indrelid = :relation_oid"),
        {"relation_oid": relation_oid},
    )
    trigger_count = await connection.scalar(
        text("SELECT count(*) FROM pg_trigger WHERE tgrelid = :relation_oid"),
        {"relation_oid": relation_oid},
    )
    rule_count = await connection.scalar(
        text(
            "SELECT count(*) FROM pg_rewrite WHERE ev_class = :relation_oid "
            "AND rulename <> '_RETURN'"
        ),
        {"relation_oid": relation_oid},
    )
    constraint = constraints[0] if len(constraints) == 1 else None
    index = indexes[0] if len(indexes) == 1 else None
    if (
        {
            key: value
            for key, value in relation_metadata.items()
            if key != "relation_oid"
        }
        != {
            "kind": "r",
            "persistence": "p",
            "access_method": "heap",
            "row_security": False,
            "force_row_security": False,
            "options": None,
            "acl": None,
            "is_partition": False,
            "replica_identity": "d",
            "tablespace_oid": 0,
            "is_populated": True,
            "owner_is_current": True,
            "parent_count": 0,
            "child_count": 0,
            "policy_count": 0,
        }
        or physical_attribute_count != len(expected_columns)
        or [dict(row) for row in columns] != expected_columns
        or constraint is None
        or constraint["name"] != "schema_contracts_pkey"
        or constraint["type"] != "p"
        or constraint["validated"] is not True
        or constraint["deferrable"] is not False
        or constraint["initially_deferred"] is not False
        or constraint["parent_oid"] != 0
        or constraint["is_local"] is not True
        or constraint["inheritance_count"] != 0
        or constraint["no_inherit"] is not True
        or constraint["key_columns"] != [1]
        or constraint["definition"] != "PRIMARY KEY (contract_name)"
        or index is None
        or constraint["index_oid"] != index["index_oid"]
        or index["name"] != "schema_contracts_pkey"
        or index["relation_kind"] != "i"
        or index["is_partition"] is not False
        or index["is_populated"] is not True
        or index["is_unique"] is not True
        or index["is_primary"] is not True
        or index["is_exclusion"] is not False
        or index["is_immediate"] is not True
        or index["is_valid"] is not True
        or index["is_ready"] is not True
        or index["is_live"] is not True
        or index["is_replica_identity"] is not False
        or index["is_clustered"] is not False
        or index["check_xmin"] is not False
        or index["nulls_not_distinct"] is not False
        or index["attribute_count"] != 1
        or index["key_attribute_count"] != 1
        or index["access_method"] != "btree"
        or index["persistence"] != "p"
        or index["options"] is not None
        or index["tablespace_oid"] != 0
        or index["acl"] is not None
        or index["owner_is_current"] is not True
        or index["expressions"] is not None
        or index["predicate"] is not None
        or index["columns"] != ["contract_name"]
        or index["opclasses"] != ["text_ops"]
        or index["opclass_namespaces"] != ["pg_catalog"]
        or index["options_by_column"] != [0]
        or index["expected_collations"] is not True
        or index_count != 1
        or trigger_count != 0
        or rule_count != 0
    ):
        raise RuntimeError(
            "The schema_contracts marker table has an unknown shape: "
            f"relation={dict(relation_metadata)!r}, columns={columns!r}, "
            f"physical_columns={physical_attribute_count!r}, "
            f"constraints={constraints!r}, indexes={indexes!r}, "
            f"index_count={index_count!r}, triggers={trigger_count!r}, rules={rule_count!r}"
        )
    rows = list(
        (
            await connection.execute(
                text(
                    "SELECT contract_name, sql_sha256, catalog_sha256, contract_sha256, "
                    "catalog_variant FROM ONLY schema_contracts ORDER BY contract_name"
                )
            )
        ).mappings()
    )
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["contract_name"] != PRODUCTION_BASE_CONTRACT_NAME:
        raise RuntimeError(
            "The schema_contracts marker row set is unknown: "
            f"rows={[dict(row) for row in rows]!r}"
        )
    marker = rows[0]
    expected_digests = {
        "sql_sha256": PRODUCTION_BASE_SQL_SHA256,
        "catalog_sha256": PRODUCTION_BASE_CATALOG_SHA256,
        "contract_sha256": PRODUCTION_BASE_CONTRACT_SHA256,
    }
    actual_digests = {key: marker[key] for key in expected_digests}
    if actual_digests != expected_digests:
        raise RuntimeError(
            "The installed production-base contract digest is unknown: "
            f"expected={expected_digests!r}, actual={actual_digests!r}"
        )
    return (
        marker["contract_sha256"],
        marker["sql_sha256"],
        marker["catalog_sha256"],
        marker["catalog_variant"],
    )


async def bootstrap_production_base(connection) -> None:
    """Install/validate ORM and raw base objects, then record an empty ledger atomically."""
    await _validate_production_base_postgres_major(connection)
    marker = await _production_base_marker(connection)
    fresh = await _validate_initial_ledger(
        connection, marker_installed=marker is not None
    )
    if marker is not None and marker[0] == PRODUCTION_BASE_CONTRACT_SHA256:
        # The first remediation owner installed the DDL atomically. Every later worker is strictly
        # read-only here: validate bytes/catalog and avoid hot-table DDL during a rolling deploy.
        production_base_sql()
        catalog = await validate_production_base_catalog(connection)
        if marker[3] != catalog["daily_revenue_summary_variant"]:
            raise RuntimeError(
                "The production-base marker catalog variant differs from the database: "
                f"marker={marker[3]!r}, actual={catalog['daily_revenue_summary_variant']!r}"
            )
        await connection.commit()
        return

    await connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)"
        )
    )
    await _validate_schema_migrations_catalog(connection, required=True)
    await connection.run_sync(create_application_tables)
    function_privileges = await _validate_preexisting_replaceable_objects(connection)
    await _execute_production_base_sql(connection)
    await _validate_preserved_function_privileges(connection, function_privileges)
    catalog = await validate_production_base_catalog(connection)

    await connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS schema_contracts ("
            "contract_name TEXT PRIMARY KEY, "
            "sql_sha256 TEXT NOT NULL, "
            "catalog_sha256 TEXT NOT NULL, "
            "contract_sha256 TEXT NOT NULL, "
            "catalog_variant TEXT NOT NULL, "
            "applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
        )
    )
    if marker is None:
        await connection.execute(
            text(
                "INSERT INTO schema_contracts("
                "contract_name, sql_sha256, catalog_sha256, contract_sha256, catalog_variant"
                ") VALUES ("
                ":contract_name, :sql_sha256, :catalog_sha256, :contract_sha256, "
                ":catalog_variant)"
            ),
            {
                "contract_name": PRODUCTION_BASE_CONTRACT_NAME,
                "sql_sha256": PRODUCTION_BASE_SQL_SHA256,
                "catalog_sha256": PRODUCTION_BASE_CATALOG_SHA256,
                "contract_sha256": PRODUCTION_BASE_CONTRACT_SHA256,
                "catalog_variant": catalog["daily_revenue_summary_variant"],
            },
        )

    versions = historical_migration_versions()
    if fresh and versions:
        values = ", ".join(f"('{version}')" for version in versions)
        await connection.execute(
            text(f"INSERT INTO schema_migrations (version) VALUES {values}")
        )
        recorded = set(
            (
                await connection.execute(text("SELECT version FROM schema_migrations"))
            ).scalars()
        )
        if recorded != set(versions):
            raise RuntimeError(
                "The immutable production migration baseline was not recorded exactly: "
                f"expected={versions!r}, actual={sorted(recorded)!r}"
            )
    installed_marker = await _production_base_marker(connection)
    expected_marker = (
        PRODUCTION_BASE_CONTRACT_SHA256,
        PRODUCTION_BASE_SQL_SHA256,
        PRODUCTION_BASE_CATALOG_SHA256,
        catalog["daily_revenue_summary_variant"],
    )
    if installed_marker != expected_marker:
        raise RuntimeError(
            "The production-base marker was not installed exactly: "
            f"expected={expected_marker!r}, actual={installed_marker!r}"
        )
    await connection.commit()


async def _unlock_migration_connection(connection) -> None:
    unlocked = await connection.scalar(
        text("SELECT pg_advisory_unlock(hashtextextended(:lock_key, 0))"),
        {"lock_key": MIGRATION_LOCK_KEY},
    )
    await connection.commit()
    if unlocked is not True:
        raise RuntimeError(
            "The database migration advisory lock was not owned at unlock"
        )


async def _validate_final_migration_ledger(connection) -> None:
    """Require dbmate success to mean every unique migration on disk is recorded exactly."""
    await _validate_schema_migrations_catalog(connection, required=True)
    recorded = list(
        (
            await connection.execute(text("SELECT version FROM schema_migrations"))
        ).scalars()
    )
    expected = migration_versions_on_disk()
    if len(recorded) != len(expected) or set(recorded) != expected:
        raise RuntimeError(
            "dbmate exited successfully without the exact final migration ledger: "
            f"missing={sorted(expected - set(recorded))!r}, "
            f"unexpected={sorted(set(recorded) - expected)!r}, "
            f"recorded_count={len(recorded)!r}, expected_count={len(expected)!r}"
        )


async def _terminate_dbmate_process(process, communication_task) -> None:
    """Stop, drain, and reap dbmate before releasing the application advisory lock."""
    if process is None:
        return
    if communication_task is None:
        # Cancellation can arrive after subprocess creation but before the normal caller stores
        # its communicate task.  Starting it here is the only safe way to drain both PIPEs.
        communication_task = asyncio.create_task(process.communicate())
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        # Keep draining both PIPEs through the original communicate task. Waiting on the process
        # alone can deadlock when a noisy child fills a pipe after cancellation.  This await is
        # required even when returncode is already set: asyncio may still be draining buffered
        # output and resolving communicate(), and the session lock must outlive that work.
        await asyncio.wait_for(asyncio.shield(communication_task), timeout=10)
    except TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await asyncio.shield(communication_task)
    if process.returncode is None:
        raise RuntimeError("dbmate communicate completed without an exit status")


async def _reap_dbmate_despite_cancellation(process, communication_task) -> None:
    """Make repeated task cancellation wait until the independent dbmate child has exited."""
    cleanup_task = asyncio.create_task(
        _terminate_dbmate_process(process, communication_task)
    )
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            # A caller may cancel shutdown repeatedly.  Shield keeps the process-reap task alive;
            # consume only this cleanup-time delivery and let the original BaseException be
            # re-raised after the child is definitively gone and the advisory lock is released.
            continue
    cleanup_task.result()


async def run_database_migrations() -> None:
    """Serialize ORM bootstrap plus every timestamped migration and fail startup closed."""
    async with engine.connect() as connection:
        await connection.execute(
            text("SELECT pg_advisory_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": MIGRATION_LOCK_KEY},
        )
        await connection.commit()
        process = None
        communication_task = None
        try:
            # Historical migrations are deltas over the ORM-created base schema. Bootstrap missing
            # base tables under the same lock, then always run dbmate before application ORM work.
            # Triggers and migration-only invariants are never delegated to create_all().
            await bootstrap_production_base(connection)

            process = await asyncio.create_subprocess_exec(
                "dbmate",
                "--migrations-dir",
                str(Path(__file__).resolve().parents[1] / "migrations"),
                "--migrations-table",
                "schema_migrations",
                "--no-dump-schema",
                "migrate",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dbmate_environment(),
            )
            communication_task = asyncio.create_task(process.communicate())
            stdout, stderr = await asyncio.shield(communication_task)
            if stdout:
                logger.info(
                    _dbmate_output_evidence("stdout", stdout, process.returncode)
                )
            if stderr:
                logger.warning(
                    _dbmate_output_evidence("stderr", stderr, process.returncode)
                )
            if process.returncode != 0:
                raise RuntimeError(
                    f"dbmate migration failed with exit code {process.returncode}"
                )
            await _validate_final_migration_ledger(connection)
            # A pending migration must not silently drift an object owned by the immutable base.
            # Validate again in a new transaction before this worker advertises startup success.
            catalog = await validate_production_base_catalog(connection)
            marker = await _production_base_marker(connection)
            if marker is None or marker[3] != catalog["daily_revenue_summary_variant"]:
                raise RuntimeError(
                    "The post-migration production-base marker/catalog variant is inconsistent: "
                    f"marker={marker!r}, "
                    f"actual={catalog['daily_revenue_summary_variant']!r}"
                )
            await connection.commit()
            logger.success("Applied all database migrations")
        except BaseException as original_error:
            # PostgreSQL marks the transaction failed after any raw asyncpg DDL error. Roll it back
            # before touching the session advisory lock, and never mask the original catalog error
            # if cleanup itself fails.
            while process is not None and (
                process.returncode is None
                or communication_task is None
                or not communication_task.done()
            ):
                try:
                    await _reap_dbmate_despite_cancellation(process, communication_task)
                except BaseException as cleanup_error:
                    # Never leave the session-lock context while an independent migrator might
                    # still be alive. Retrying is intentionally fail-stop: startup/shutdown may
                    # remain blocked, but a successor cannot overlap an un-reaped dbmate process.
                    original_error.add_note(
                        f"dbmate termination/reap attempt failed: {cleanup_error!r}"
                    )
                    logger.exception("Retrying failed dbmate termination/reap")
            try:
                await connection.rollback()
            except BaseException:
                logger.exception(
                    "Failed to roll back the database migration transaction"
                )
            if process is not None and (
                process.returncode is None
                or communication_task is None
                or not communication_task.done()
            ):
                raise AssertionError(
                    "un-reaped or undrained dbmate reached advisory-lock release"
                )
            try:
                await _unlock_migration_connection(connection)
            except BaseException:
                logger.exception(
                    "Failed to release the migration advisory lock after rollback"
                )
            raise
        else:
            await _unlock_migration_connection(connection)
