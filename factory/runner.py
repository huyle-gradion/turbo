"""Bounded single-child execution with raw output capture. Never uses a shell.

On POSIX the child starts a new session, so a timeout kills the child and its descendants as one
process group. Elsewhere only the direct child is signalled, and a grandchild may outlive it.
"""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

MAX_TIMEOUT_SECONDS = 900


@dataclass(frozen=True, slots=True)
class ChildResult:
    argv: tuple[str, ...]
    exit: int
    output: str
    duration_ms: int
    timed_out: bool = False


def _env() -> dict[str, str]:
    return dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0")


def execute(repo: Path, argv: tuple[str, ...], timeout_seconds: int) -> ChildResult:
    if not argv:
        raise ValueError("empty argv")
    bounded = max(1, min(int(timeout_seconds), MAX_TIMEOUT_SECONDS))
    started = time.monotonic()
    try:
        if os.name == "posix":
            return _run_in_group(repo, argv, bounded, started)
        completed = subprocess.run(
            list(argv), cwd=repo, capture_output=True, timeout=bounded, shell=False, env=_env()
        )
        output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        return ChildResult(argv, completed.returncode, output, _elapsed(started), False)
    except subprocess.TimeoutExpired as exc:
        return _timeout_result(argv, exc, bounded, started)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return ChildResult(argv, 127, f"[factory] command not executed: {exc}\n", _elapsed(started), False)


def _run_in_group(repo: Path, argv: tuple[str, ...], bounded: int, started: float) -> ChildResult:
    process = subprocess.Popen(
        list(argv),
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_env(),
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=bounded)
    except subprocess.TimeoutExpired:
        _kill_group(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
        text = (stdout + stderr).decode("utf-8", "replace") + f"\n[factory] timed out after {bounded}s\n"
        return ChildResult(argv, 124, text, _elapsed(started), True)
    decoded = (stdout + stderr).decode("utf-8", "replace")
    return ChildResult(argv, process.returncode, decoded, _elapsed(started), False)


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (AttributeError, OSError):
        process.kill()


def _timeout_result(argv: tuple[str, ...], exc: subprocess.TimeoutExpired, bounded: int, started: float) -> ChildResult:
    partial = b""
    if exc.stdout:
        partial += exc.stdout
    if exc.stderr:
        partial += exc.stderr
    text = partial.decode("utf-8", "replace") + f"\n[factory] timed out after {bounded}s\n"
    return ChildResult(argv, 124, text, _elapsed(started), True)


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
