"""Deterministic sibling-repository resolution for cross-repository tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_REPOSITORIES = {
    "api": ("chutes-api", "CHUTES_API_ROOT"),
    "sek8s": ("sek8s", "CHUTES_SEK8S_ROOT"),
    "miner": ("chutes-miner", "CHUTES_MINER_ROOT"),
    "sdk": ("chutes", "CHUTES_SDK_ROOT"),
}


def _current_repository(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    raise AssertionError(f"cannot locate repository root from {start}")


def _cohort_suffix(repository: Path) -> str:
    for canonical, _environment in sorted(
        _REPOSITORIES.values(), key=lambda item: len(item[0]), reverse=True
    ):
        if repository.name.startswith(canonical):
            return repository.name[len(canonical) :]
    return ""


def repository_root(name: str, *, start: Path) -> Path:
    """Resolve a sibling repo, failing only when explicitly configured."""
    try:
        canonical, environment = _REPOSITORIES[name]
    except KeyError as exc:
        raise AssertionError(f"unknown cross-repository dependency: {name}") from exc

    configured = os.getenv(environment)
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if not candidate.is_dir():
            raise AssertionError(f"{environment} does not name a directory: {candidate}")
        return candidate

    current = _current_repository(start.resolve())
    configured_workspace = os.getenv("CHUTES_CROSS_REPO_ROOT")
    if configured_workspace:
        root = Path(configured_workspace).expanduser().resolve()
        candidates = [root / canonical]
        suffix = _cohort_suffix(current)
        if suffix:
            candidates.append(root / f"{canonical}{suffix}")
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
        raise AssertionError(
            "CHUTES_CROSS_REPO_ROOT is set but the "
            f"{canonical} repository is missing; checked {candidates}"
        )

    candidate = current.parent / canonical
    if candidate.is_dir():
        return candidate
    pytest.skip(
        f"cross-repository test requires sibling {canonical}; "
        f"set {environment} or CHUTES_CROSS_REPO_ROOT",
    )
