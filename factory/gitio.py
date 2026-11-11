"""Read-only git queries. The factory never commits, branches, or pushes."""

from __future__ import annotations

import os
import subprocess
import time
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


_NO_EXTERNAL_DIFF = frozenset({"diff", "show", "log"})
# Subcommands that never read or write working-tree files, so no clean/smudge filter can run.
# Every other subcommand pays one `git config` lookup to empty the configured filter drivers.
_FILTER_FREE = frozenset({
    "branch", "cat-file", "config", "fetch", "for-each-ref", "log", "ls-remote", "ls-tree", "merge-base",
    "push", "remote", "rev-list", "rev-parse", "show", "show-ref", "symbolic-ref", "update-ref",
})
_NO_PROGRAMS = (("core.fsmonitor", "false"), ("core.hooksPath", os.devnull))


def _config_env(base: dict[str, str], pairs: list[tuple[str, str]]) -> dict[str, str]:
    env = dict(base, GIT_CONFIG_COUNT=str(len(pairs)))
    for index, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{index}"], env[f"GIT_CONFIG_VALUE_{index}"] = key, value
    return env


def _run_git(repo: Path, args: tuple[str, ...] | list[str], *, input: bytes | None = None,
             timeout: float | None = GIT_TIMEOUT, text: bool = False) -> subprocess.CompletedProcess:
    """Run host git in `repo` so that repository config cannot make it run a program (#125).

    A builder controls its working copy's `.git/config` (and anything it includes), `.git/hooks`
    and `.git/info/attributes`, and the host then runs git there. GIT_CONFIG_COUNT overrides have
    command-line scope, beat repository config and reach child git processes: no fsmonitor, no
    hooks, and (unless the subcommand never touches working-tree files) every configured filter
    driver emptied so clean/smudge/process never run. diff, show and log get `--no-ext-diff
    --no-textconv`, and replace refs are ignored. Operator-owned global
    and system config still apply, so credential helpers keep working for push and fetch.
    Raises OSError or SubprocessError like `subprocess.run`.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    env = _config_env(dict(_env(), GIT_NO_REPLACE_OBJECTS="1"), list(_NO_PROGRAMS))
    argv = list(args)
    sub = next((i for i, arg in enumerate(argv) if not arg.startswith("-")), None)
    drivers: list[str] = []
    if sub is None or argv[sub] not in _FILTER_FREE or any(arg.startswith(("--filters", "--textconv")) for arg in argv):
        listed = subprocess.run(["git", "config", "-z", "--name-only", "--get-regexp", r"^filter\."],
                                cwd=repo, capture_output=True, timeout=timeout, env=env)
        drivers = sorted({key.decode("utf-8", "surrogateescape")[7:].rpartition(".")[0] for key in listed.stdout.split(b"\0") if key})
    pairs = [*_NO_PROGRAMS, *((f"filter.{name}.{key}", value) for name in drivers
              for key, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")))]
    if sub is not None and argv[sub] in _NO_EXTERNAL_DIFF:
        argv[sub + 1:sub + 1] = ["--no-ext-diff", "--no-textconv"]
    remaining = None if deadline is None else max(0.001, deadline - time.monotonic())
    return subprocess.run(["git", *argv], cwd=repo, input=input, capture_output=True, text=text,
                          timeout=remaining, env=_config_env(env, pairs))


def git_result(repo: Path, args: tuple[str, ...], *, timeout: float | None = GIT_TIMEOUT) -> GitResult:
    """Like `git`, but raises OSError or SubprocessError (for example TimeoutExpired) instead of returning 127."""
    completed = _run_git(repo, args, timeout=timeout, text=True)
    return GitResult(("git", *args), completed.returncode, (completed.stdout + completed.stderr).strip())


def git(repo: Path, *args: str) -> GitResult:
    try:
        return git_result(repo, args)
    except (OSError, subprocess.SubprocessError) as exc:
        return GitResult(("git", *args), 127, str(exc))


def _git_bytes(repo: Path, *args: str, input: bytes | None = None, timeout: float | None = GIT_TIMEOUT) -> tuple[int, bytes]:
    try:
        completed = _run_git(repo, args, input=input, timeout=timeout)
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
    code, payload = _git_bytes(repo, "show", f"HEAD:{relative}")
    if code != 0:
        raise UsageError(f"{relative} is not committed at HEAD")
    return payload


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
