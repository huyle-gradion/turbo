"""Filesystem policy for the private runtime home and product repository."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from factory.errors import CorruptState, UsageError
from factory.gitio import require_repo_root

HOME_MODE = 0o700
FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    repo: Path
    home: Path

    @property
    def config(self) -> Path:
        return self.home / "config.json"

    @property
    def runs(self) -> Path:
        return self.home / "runs"

    @property
    def evidence(self) -> Path:
        return self.home / "evidence"

    def run(self, issue: int) -> Path:
        return self.runs / f"{issue}.json"

    def issue_evidence(self, issue: int) -> Path:
        return self.evidence / f"{issue}"


def resolve_paths(repo_arg: str, home_arg: str) -> RuntimePaths:
    repo = require_repo_root(Path(repo_arg).expanduser())
    home = Path(home_arg).expanduser().resolve()
    if home == repo or home.is_relative_to(repo):
        raise UsageError(f"--home must live outside --repo; {home} is inside {repo}")
    return RuntimePaths(repo=repo, home=home)


def ensure_home(paths: RuntimePaths) -> None:
    for directory in (paths.home, paths.runs, paths.evidence):
        if directory.is_symlink():
            raise UsageError(f"state path is a symlink and is refused: {directory}")
        directory.mkdir(parents=True, exist_ok=True, mode=HOME_MODE)
        os.chmod(directory, HOME_MODE)


def safe_dir(path: Path, *, create: bool, root: Path | None = None) -> Path:
    if root is not None:
        if not path.is_relative_to(root):
            raise UsageError(f"state path escapes the private home: {path}")
        current = root
        for part in path.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise UsageError(f"state path is a symlink and is refused: {current}")
            if current.exists() and not current.is_dir():
                raise UsageError(f"state path is not a directory: {current}")
    if path.is_symlink():
        raise UsageError(f"state path is a symlink and is refused: {path}")
    if path.exists() and not path.is_dir():
        raise UsageError(f"state path is not a directory: {path}")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=HOME_MODE)
        os.chmod(path, HOME_MODE)
    return path


def _check_parent(path: Path, home: Path, *, create: bool) -> None:
    if path.is_symlink():
        raise UsageError(f"state file is a symlink and is refused: {path}")
    parent = path.parent
    if not parent.is_relative_to(home):
        raise UsageError(f"state file escapes the private home: {path}")
    safe_dir(parent, create=create, root=home)


def atomic_json(path: Path, payload: dict[str, object], home: Path) -> None:
    _check_parent(path, home, create=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path: Path, home: Path) -> dict[str, object] | None:
    _check_parent(path, home, create=False)
    if not path.exists():
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UsageError(f"cannot open state file {path}: {exc.strerror}") from exc
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorruptState(f"corrupt state file {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CorruptState(f"corrupt state file {path}: expected a JSON object")
    return parsed


def write_evidence(directory: Path, stem: str, text: str, home: Path) -> Path:
    safe_dir(directory, create=True, root=home)
    counter = 1
    while True:
        suffix = "" if counter == 1 else f"-{counter}"
        target = directory / f"{stem}{suffix}.txt"
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        except FileExistsError:
            counter += 1
            continue
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(target, FILE_MODE)
        return target
