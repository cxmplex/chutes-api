"""Static and behavioral regressions for API-LOCK-01."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from api.instance.locking import lock_launch_configs_before_instances


class _Rows:
    def __init__(self, rows=()):
        self._rows = list(rows)

    def all(self):
        return list(self._rows)


class _RecordingSession:
    def __init__(self):
        self.info = {}
        self.events = []

    async def execute(self, statement, parameters=None):
        sql = str(statement)
        self.events.append((sql, parameters, statement.compile().params))
        if (
            "instances.instance_id, instances.config_id" in sql
            and "FOR UPDATE" not in sql
        ):
            return _Rows(
                [
                    ("instance-b", "config-b"),
                    ("instance-a", "config-a"),
                ]
            )
        return _Rows()


@pytest.mark.asyncio
async def test_common_helper_locks_lifecycle_then_sorted_configs_then_instances():
    db = _RecordingSession()

    locked = await lock_launch_configs_before_instances(
        db,
        config_ids=["config-c", "config-a"],
        instance_ids=["instance-b", "instance-a", "instance-b"],
    )

    assert "pg_advisory_xact_lock" in db.events[0][0]
    assert "instances.instance_id, instances.config_id" in db.events[1][0]
    assert "FOR UPDATE" not in db.events[1][0]
    assert "FROM launch_configs" in db.events[2][0]
    assert "ORDER BY launch_configs.config_id" in db.events[2][0]
    assert "FOR UPDATE" in db.events[2][0]
    assert db.events[2][2]["config_id_1"] == [
        "config-a",
        "config-b",
        "config-c",
    ]
    assert "instances.instance_id, instances.config_id" in db.events[3][0]
    assert "ORDER BY instances.instance_id" in db.events[3][0]
    assert "FOR UPDATE" not in db.events[3][0]
    assert db.events[3][2]["config_id_1"] == ["config-a", "config-c"]
    assert "FROM instances" in db.events[4][0]
    assert "ORDER BY instances.instance_id" in db.events[4][0]
    assert "FOR UPDATE" in db.events[4][0]
    assert db.events[4][2]["instance_id_1"] == ["instance-a", "instance-b"]
    assert locked.config_ids == ("config-a", "config-b", "config-c")
    assert locked.instance_ids == ("instance-a", "instance-b")


def _terminal_writer_functions() -> dict[str, set[str]]:
    root = Path(__file__).resolve().parents[2] / "api"
    writers: dict[str, set[str]] = {}
    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            function_source = ast.get_source_segment(source, node) or ""
            reasons: set[str] = set()
            if "DELETE FROM instances" in function_source:
                reasons.add("raw delete")
            if "delete(Instance)" in function_source:
                reasons.add("bulk delete")
            if (
                ".delete(instance)" in function_source
                or ".delete(job.instance)" in function_source
            ):
                reasons.add("ORM delete")
            if "update(Instance)" in function_source:
                reasons.add("bulk update")
            if "UPDATE instances" in function_source:
                reasons.add("raw update")
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "delete"
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in {"db", "session"}
                ):
                    reasons.add(
                        f"direct {child.func.value.id}.delete requires explicit classification"
                    )
                    continue
                if not isinstance(child, (ast.Assign, ast.AugAssign)):
                    continue
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                if any(
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "instance"
                    and target.attr
                    in {
                        "active",
                        "verified",
                        "verification_error",
                        "stop_billing_at",
                        "storage_revocation_epoch",
                    }
                    for target in targets
                ):
                    reasons.add("Instance terminal attribute")
            if reasons:
                writers[f"{path.relative_to(root)}:{node.name}"] = reasons
    return writers


def test_every_instance_terminal_writer_uses_the_ordered_helper():
    root = Path(__file__).resolve().parents[2] / "api"
    allowed_nonterminal = {"instance/router.py:_mark_instance_verified"}
    allowed_non_instance_session_deletes = {
        "api_key/router.py:delete_api_key",
        "gpu_registration_keys.py:_acknowledge_configured_epochs",
        "gpu_registration_keys.py:cancel_gpu_registration_recovery_key_epoch",
        "idp/router.py:delete_app",
        "idp/router.py:unshare_app",
        "image/router.py:delete_image",
        "job/router.py:delete_job",
        "node/router.py:delete_node",
        "secret/router.py:delete_secret",
        "server/service.py:register_gpu_server",
        "server/util.py:delete_luks_passphrases_for_server",
        "storage/service.py:_finalize_erasure_batch",
        "storage/service.py:_reconcile_model_inventory_snapshots",
    }
    missing = []
    for identity, reasons in _terminal_writer_functions().items():
        if identity in allowed_nonterminal:
            continue
        if identity in allowed_non_instance_session_deletes:
            assert reasons == {
                "direct db.delete requires explicit classification"
            }, identity
            continue
        relative, function_name = identity.split(":", 1)
        source = (root / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
            and node.name == function_name
        )
        function_source = ast.get_source_segment(source, function) or ""
        if not any(
            marker in function_source
            for marker in (
                "prepare_instance_terminal_writes",
                "lock_launch_configs_before_instances",
                "lock_launch_storage_configurations",
            )
        ):
            missing.append((identity, sorted(reasons)))
    assert not missing, "\n".join(
        f"{identity}: {', '.join(reasons)}" for identity, reasons in missing
    )

    storage_source = (
        root / "storage/launch_sessions.py"
    ).read_text(encoding="utf-8")
    assert "lock_launch_configs_before_instances" in storage_source
    erasure_source = (root / "storage/service.py").read_text(encoding="utf-8")
    assert "lock_launch_storage_configurations" in erasure_source


def _call_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_path(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _awaited_call_paths(node: ast.Await) -> set[str]:
    return {
        _call_path(child.func)
        for child in ast.walk(node.value)
        if isinstance(child, ast.Call)
    }


def _is_external_await(node: ast.Await) -> bool:
    for path in _awaited_call_paths(node):
        terminal = path.rsplit(".", 1)[-1]
        if terminal.startswith("notify_") or terminal in {
            "cleanup_instance_conn_tracking",
            "delete_bounty",
            "invalidate_chute_cache",
            "invalidate_instance_cache",
            "send_instance_teardown",
            "set_chute_disabled",
        }:
            return True
        if "redis_client" in path or "lite_redis_client" in path:
            return True
    return False


def test_lifecycle_helper_calls_commit_before_external_io():
    root = Path(__file__).resolve().parents[2] / "api"
    helper_names = {
        "lock_launch_configs_before_instances",
        "prepare_instance_terminal_writes",
    }
    failures = []
    spawned_deletions = []
    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for function in ast.walk(tree):
            if not isinstance(function, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            helper_lines = sorted(
                call.lineno
                for call in ast.walk(function)
                if isinstance(call, ast.Call)
                and _call_path(call.func).rsplit(".", 1)[-1] in helper_names
            )
            if not helper_lines:
                continue
            commit_lines = sorted(
                call.lineno
                for call in ast.walk(function)
                if isinstance(call, ast.Call)
                and _call_path(call.func).rsplit(".", 1)[-1]
                in {"commit", "rollback"}
            )
            for awaited in (
                child for child in ast.walk(function) if isinstance(child, ast.Await)
            ):
                paths = _awaited_call_paths(awaited)
                if "asyncio.create_task" in paths and any(
                    item.rsplit(".", 1)[-1] == "notify_deleted" for item in paths
                ):
                    spawned_deletions.append(
                        f"{path.relative_to(root)}:{function.name}:{awaited.lineno}"
                    )
                if not _is_external_await(awaited):
                    continue
                preceding_helpers = [line for line in helper_lines if line < awaited.lineno]
                if not preceding_helpers:
                    continue
                helper_line = max(preceding_helpers)
                if not any(helper_line < line < awaited.lineno for line in commit_lines):
                    failures.append(
                        f"{path.relative_to(root)}:{function.name}:"
                        f"helper@{helper_line}->external@{awaited.lineno}"
                    )
    assert not spawned_deletions, "\n".join(spawned_deletions)
    assert not failures, "\n".join(failures)


def test_unshipped_migrations_have_no_instance_to_launch_config_trigger():
    root = Path(__file__).resolve().parents[2]
    migration_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "api/migrations").glob("*.sql")
    )
    assert "complete_launch_config_on_instance_terminal" not in migration_sources
    assert "trg_complete_launch_config_on_instance_terminal" not in migration_sources
    assert "revoke_registry_scope_on_instance_terminal" not in migration_sources
    assert "trg_instance_terminal_registry_scope" not in migration_sources
