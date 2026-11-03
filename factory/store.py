"""Atomic run-state persistence under the private home."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from factory.config import now
from factory.errors import UsageError
from factory.model import Run
from factory.paths import RuntimePaths, atomic_json, read_json, safe_dir


def run_path(paths: RuntimePaths, issue: int) -> Path:
    return paths.run(issue)


def load_run(paths: RuntimePaths, issue: int) -> Run | None:
    data = read_json(run_path(paths, issue), paths.home)
    return None if data is None else Run.from_dict(data)


def require_run(paths: RuntimePaths, issue: int) -> Run:
    run = load_run(paths, issue)
    if run is None:
        raise UsageError(f"no run state for issue {issue}; run prepare first")
    return run


def save_run(paths: RuntimePaths, run: Run) -> Run:
    updated = replace(run, updated_at=now())
    atomic_json(run_path(paths, run.issue), updated.to_dict(), paths.home)
    return updated


def run_issues(paths: RuntimePaths) -> tuple[int, ...]:
    directory = safe_dir(paths.runs, create=False, root=paths.home)
    if not directory.exists():
        return ()
    issues: list[int] = []
    for entry in directory.iterdir():
        if entry.is_symlink():
            raise UsageError(f"state path is a symlink and is refused: {entry}")
        if entry.suffix == ".json" and entry.stem.isdigit():
            issues.append(int(entry.stem))
    return tuple(sorted(issues))
