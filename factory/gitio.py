"""Read-only git queries. The factory never commits, branches, or pushes."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from factory.errors import UsageError

GIT_TIMEOUT = 60


@dataclass(frozen=True, slots=True)
class GitResult:
    argv: tuple[str, ...]
    exit: int
    output: str

    @property
    def ok(self) -> bool:
        return self.exit == 0


def _env() -> dict[str, str]:
    return dict(os.environ, GIT_TERMINAL_PROMPT="0", PYTHONDONTWRITEBYTECODE="1")


def git(repo: Path, *args: str) -> GitResult:
    argv = ("git", *args)
    try:
        completed = subprocess.run(
            list(argv), cwd=repo, capture_output=True, text=True, timeout=GIT_TIMEOUT, env=_env()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return GitResult(argv, 127, str(exc))
    return GitResult(argv, completed.returncode, (completed.stdout + completed.stderr).strip())


def _git_bytes(repo: Path, *args: str) -> tuple[int, bytes]:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, timeout=GIT_TIMEOUT, env=_env()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UsageError(f"git {' '.join(args)} failed: {exc}") from exc
    return completed.returncode, completed.stdout


def require_repo_root(repo: Path) -> Path:
    resolved = repo.resolve()
    if not resolved.is_dir():
        raise UsageError(f"--repo is not a directory: {resolved}")
    top = git(resolved, "rev-parse", "--show-toplevel")
    if not top.ok:
        raise UsageError(f"--repo is not a git work tree: {resolved}")
    root = Path(top.output).resolve()
    if root != resolved:
        raise UsageError(f"--repo must be the repository root, got {resolved} but root is {root}")
    inside = git(resolved, "rev-parse", "--is-inside-work-tree")
    if not inside.ok or inside.output != "true":
        raise UsageError(f"--repo is not a git work tree: {resolved}")
    head = git(resolved, "rev-parse", "--verify", "HEAD")
    if not head.ok:
        raise UsageError(f"--repo has no commits yet: {resolved}")
    return resolved


def head(repo: Path) -> str:
    result = git(repo, "rev-parse", "HEAD")
    if not result.ok:
        raise UsageError(f"cannot read HEAD: {result.output}")
    return result.output


def branch(repo: Path) -> str:
    result = git(repo, "branch", "--show-current")
    if not result.ok:
        raise UsageError(f"cannot read the current branch: {result.output}")
    return result.output


def _nul_fields(payload: bytes) -> list[str]:
    return [field.decode("utf-8", "surrogateescape") for field in payload.split(b"\0") if field]


def status_entries(repo: Path) -> tuple[tuple[str, str, str | None], ...]:
    code, payload = _git_bytes(repo, "status", "--porcelain", "-z", "--untracked-files=all")
    if code != 0:
        raise UsageError(f"git status failed: {payload.decode('utf-8', 'replace').strip()}")
    fields = _nul_fields(payload)
    entries: list[tuple[str, str, str | None]] = []
    index = 0
    while index < len(fields):
        entry = fields[index]
        status = entry[:2]
        if "R" in status or "C" in status:
            origin = fields[index + 1] if index + 1 < len(fields) else None
            entries.append((status, entry[3:], origin))
            index += 2
        else:
            entries.append((status, entry[3:], None))
            index += 1
    return tuple(entries)


def status_porcelain(repo: Path) -> str:
    lines: list[str] = []
    for status, path, origin in status_entries(repo):
        lines.append(f"{status} {origin} -> {path}" if origin else f"{status} {path}")
    return "\n".join(lines)


def require_clean(repo: Path) -> None:
    dirty = status_porcelain(repo)
    if dirty:
        raise UsageError(f"working tree is dirty; commit or stash before proceeding:\n{dirty}")


def commit_sha(repo: Path, revision: str) -> str:
    result = git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not result.ok:
        raise UsageError(f"not a commit: {revision}")
    return result.output


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    return git(repo, "merge-base", "--is-ancestor", ancestor, descendant).ok


def file_at_head(repo: Path, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"HEAD:{relative}"],
        cwd=repo,
        capture_output=True,
        timeout=GIT_TIMEOUT,
        env=_env(),
    )
    if result.returncode != 0:
        raise UsageError(f"{relative} is not committed at HEAD")
    return result.stdout


def branch_exists(repo: Path, name: str) -> bool:
    return git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}").ok


def remote_ref(repo: Path, name: str) -> str | None:
    result = git(repo, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{name}")
    return result.output if result.ok else None


def changed_paths(repo: Path, base: str, tip: str) -> tuple[str, ...]:
    code, payload = _git_bytes(repo, "diff", "--name-only", "-z", "--no-renames", base, tip)
    if code != 0:
        raise UsageError(f"git diff failed: {payload.decode('utf-8', 'replace').strip()}")
    return tuple(_nul_fields(payload))


def dirty_paths(repo: Path) -> tuple[str, ...]:
    paths: list[str] = []
    for _, path, origin in status_entries(repo):
        paths.append(path)
        if origin is not None:
            paths.append(origin)
    return tuple(paths)
