"""The separate test-author session that runs before the implementer in `deliver` (Issue #117).

The test author commits failing tests only and declares its red run on a `TURBO-RED: <json>` line.
The factory runs that red command itself, sandboxed without network, at the test-author commit.
After the implementer, the test-author files must be byte-identical at the candidate and the same
command must pass there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib, json, math, os, shutil, subprocess
from pathlib import Path
from typing import Any

from factory import gitio, runner, worker as worker_module
from factory.deliver_checks import AttemptTimeoutError, _verification_argv, inspect_diff_categories, is_test_path, remaining_seconds
from factory.intake import redact_value
from factory.paths import safe_dir, write_evidence

ROLE_MARKER = "ROLE: test-author"
RED_PREFIX = "TURBO-RED:"
IDENTITY_NOTE = (
    "Session identities are host conversation IDs: they show two separate host invocations, "
    "not separate models or separate people."
)


def agy_argv(agy_bin: str, prompt: str) -> tuple[str, ...]:
    return (agy_bin, "--print", prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")


def build_prompt(parent: dict[str, Any], child: dict[str, Any], feature_branch: str) -> str:
    criteria = "\n".join(
        f"- {c['id']}: {c['description']} (Verification: {c['verification']})" for c in (child.get("criteria") or [])
    )
    scope = child.get("scope") or {}
    return (
        f"{ROLE_MARKER}\n"
        f"Write failing tests for prepared Asana sub-task {child['gid']} ({child['name']}) "
        f"of parent feature {parent['gid']} ({parent['name']}).\n"
        f"Target feature branch: {feature_branch}\n"
        f"In scope: {scope.get('in_scope') or 'as specified'}\n"
        f"Out of scope: {scope.get('out_of_scope') or 'none'}\n"
        f"Acceptance criteria:\n{criteria}\n"
        "Change test files only; do not change implementation. Commit the tests to the current worktree HEAD. "
        "Do not push or touch main. The tests must fail against the current implementation.\n"
        f"End your response with one line `{RED_PREFIX} "
        '{"command": "<one of the Verification commands above>", "expect": "<failure marker naming a test>", '
        '"tests": ["<test name>", ...]}`.\n'
    )


def implementer_note(ta_sha: str, files: list[dict[str, str]]) -> str:
    names = ", ".join(f["path"] for f in files)
    return (
        f"A separate test author committed failing tests at {ta_sha} ({names}). "
        "Do not modify, delete or rename those files. Implement the bounded change within scope so they pass, "
        "run verification checks, and commit your changes to the current worktree HEAD. Do not push or touch main.\n"
    )


@dataclass(slots=True)
class Authored:
    status: str
    blockers: list[str]
    final_result: dict[str, Any] | None
    record: dict[str, Any]
    stdout_path: Path
    argv: tuple[str, ...] = ()
    files: list[dict[str, str]] = field(default_factory=list)


def _declaration(response: Any) -> dict[str, Any] | None:
    for line in str(response or "").splitlines():
        if not line.strip().startswith(RED_PREFIX):
            continue
        try:
            decl = json.loads(line.strip()[len(RED_PREFIX):])
        except ValueError:
            return None
        ok = (
            isinstance(decl, dict) and isinstance(decl.get("command"), str) and decl["command"].strip()
            and isinstance(decl.get("expect"), str) and decl["expect"].strip()
            and isinstance(decl.get("tests"), list) and decl["tests"]
            and all(isinstance(t, str) and t.strip() for t in decl["tests"])
        )
        return decl if ok else None
    return None


def _git(worktree: Path, *args: str) -> str:
    """Git with replace objects disabled, so `git replace` cannot change what the factory reads."""
    return gitio.git(worktree, "--no-replace-objects", *args).output


def _blob_sha(worktree: Path, rev: str, path: str) -> str | None:
    code, data = gitio._git_bytes(worktree, "--no-replace-objects", "cat-file", "blob", f"{rev}:{path}")
    return hashlib.sha256(data).hexdigest() if code == 0 else None


def _materialize(repo: Path, sha: str, dest: Path) -> None:
    """Write the committed tree of `sha` into `dest` from raw objects: no index, hooks, filters or replace objects."""
    run = lambda *a, data=None: subprocess.run(  # noqa: E731
        ["git", "--no-replace-objects", *a], cwd=repo, input=data, capture_output=True, check=True, timeout=120,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
    ).stdout
    entries = [e.split(b"\t", 1) for e in run("ls-tree", "-r", "-z", "--full-tree", sha).split(b"\0") if e]
    blobs = [(meta.split(), path.decode()) for meta, path in entries if meta.split()[1] == b"blob"]
    data, pos = run("cat-file", "--batch", data=b"".join(m[2] + b"\n" for m, _ in blobs)), 0
    for (mode, _, _), path in blobs:
        end = data.index(b"\n", pos)
        size = int(data[pos:end].split()[2])
        body, pos = data[end + 1:end + 1 + size], end + 2 + size
        target = dest / path
        if not target.resolve().is_relative_to(dest.resolve()):
            raise ValueError(f"tree path escapes the checkout: {path!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if mode == b"120000":
            target.symlink_to(body.decode())
        else:
            target.write_bytes(body)
            target.chmod(0o755 if mode == b"100755" else 0o644)


def run_check(
    worktree: Path, sha: str, child_dir: Path, home: Path, stem: str, command: str, argv: tuple[str, ...],
    secrets: tuple[str, ...], deadline: float, limit_s: int,
) -> dict[str, Any]:
    """Run `argv` in a fresh checkout of `sha`, sandboxed without network. `output` is unredacted, for marker matching only."""
    sep_dir = safe_dir(child_dir / "test-separation", create=True, root=home)
    run_home, tree = safe_dir(sep_dir / f"{stem}-home", create=True, root=home), sep_dir / f"{stem}-checkout"
    shutil.rmtree(tree, ignore_errors=True)
    tree.mkdir()
    env, _ = worker_module.sanitized_env(dict(os.environ), tree, run_home)
    env["GIT_OPTIONAL_LOCKS"] = env["PYTHONNOUSERSITE"] = "1"
    timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, f"{stem} run", limit_s))))
    try:
        _materialize(worktree, sha, tree)
        code, out, err, _, timed_out = worker_module.execute_stream(
            tree, argv, env, timeout_s, isolated_home=run_home, allow_network=False,
        )
    except (worker_module.SandboxUnavailableError, OSError, ValueError, subprocess.SubprocessError) as exc:
        code, out, err, timed_out = None, "", f"[factory] {stem} execution error: {exc}\n", False
    finally:
        shutil.rmtree(tree, ignore_errors=True)
    if timed_out:
        raise AttemptTimeoutError(f"{stem} run timed out after {limit_s}s")
    text = redact_value(out + err, secrets)
    path = write_evidence(child_dir, f"{stem}-output", text, home)
    return {
        "command": command, "argv": list(argv), "exit": code, "output_sha256": runner.digest_text(text),
        "output_path": str(path), "head_sha": sha, "provenance": "observed-factory-execution", "output": out + err,
    }


def run_test_author(
    *, agy_bin: str, prompt: str, worktree: Path, child_dir: Path, home: Path, child: dict[str, Any],
    base_sha: str, secrets: tuple[str, ...], deadline: float, limit_s: int,
) -> Authored:
    ta_home = worker_module.prepare_isolated_home(safe_dir(child_dir / "test-author", create=True, root=home), Path.home(), root=home)
    env, _ = worker_module.sanitized_env(dict(os.environ), worktree, ta_home)
    timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, "test-author execution", limit_s))))
    try:
        code, out, err, _, timed_out = worker_module.execute_stream(worktree, agy_argv(agy_bin, prompt), env, timeout_s, isolated_home=ta_home)
    except worker_module.SandboxUnavailableError as exc:
        code, out, err, timed_out = None, "", f"[factory] sandbox unavailable: {exc}\n", False
    if timed_out:
        raise AttemptTimeoutError(f"test author timed out after {limit_s}s")
    stdout_path = write_evidence(child_dir, "test-author-stdout", out, home)
    write_evidence(child_dir, "test-author-stderr", err, home)
    _, final, parse_error = worker_module.parse_stream_events(out)
    final = final if isinstance(final, dict) else None
    ta_sha = gitio.head(worktree)
    record: dict[str, Any] = {
        "schema": 1,
        "test_author": {"conversation_id": str((final or {}).get("conversation_id") or "") or None, "commit_sha": None, "tests": []},
        "implementer": {"conversation_id": None}, "identity_note": IDENTITY_NOTE,
        "red": None, "green": None, "byte_identity": None,
    }

    def _out(status: str, blocker: str, argv: tuple[str, ...] = (), files: list[dict[str, str]] | None = None) -> Authored:
        return Authored(status, [blocker] if blocker else [], final, record, stdout_path, argv, files or [])

    decl = _declaration((final or {}).get("response"))
    if parse_error is not None or code != 0 or final is None or final.get("status") != "SUCCESS":
        return _out("test-author-failed", f"test author exited with code {code} and result status {(final or {}).get('status')!r}")
    if decl is None:
        return _out("test-author-failed", f"test author response has no valid `{RED_PREFIX} <json>` declaration")
    if gitio.status_porcelain(worktree):
        return _out("test-author-failed", "test author left uncommitted changes in the worktree")
    if ta_sha == base_sha or not gitio.is_ancestor(worktree, base_sha, ta_sha):
        return _out("test-author-failed", "test author produced no new commit on the feature branch base")
    command, expect, tests = decl["command"].strip(), decl["expect"], [t.strip() for t in decl["tests"]]
    record["test_author"].update(commit_sha=ta_sha, tests=tests)
    diff = inspect_diff_categories(worktree, base_sha, ta_sha, deadline, limit_s)
    if diff["implementation_paths"]:
        return _out("red-refused", f"test-author commit changes implementation paths: {', '.join(diff['implementation_paths'])}")
    if command not in {str(c.get("verification") or "").strip() for c in (child.get("criteria") or [])}:
        return _out("red-refused", f"red command {command!r} is not one of the child's criterion verification commands")
    if not any(t in expect for t in tests):
        return _out("red-refused", f"expected-failure marker {expect!r} names none of the declared tests {tests}")
    added = "\n".join(
        ln[1:] for ln in _git(worktree, "diff", "--no-renames", "--unified=0", base_sha, ta_sha).splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    )
    if not added.strip():
        return _out("red-refused", "test-author commit adds no line to any test file")
    if missing := [t for t in tests if t not in added]:
        return _out("red-refused", f"declared tests {missing} do not appear in the test-author commit's added lines")
    argv = _verification_argv(command)
    if argv is None:
        return _out("red-refused", f"red command {command!r} is not executable")
    red = run_check(worktree, ta_sha, child_dir, home, "red", command, argv, secrets, deadline, limit_s)
    output = red.pop("output")
    record["red"] = {**red, "expect": expect}
    if red["exit"] == 0:
        return _out("red-refused", f"red command {command!r} passed (exit 0) at the test-author commit {ta_sha}")
    if red["exit"] is None or expect not in output:
        return _out("red-refused", f"red command failed without the expected marker {expect!r} (exit {red['exit']})")
    names = _git(worktree, "diff", "--no-renames", "--diff-filter=AMT", "--name-only", base_sha, ta_sha).splitlines()
    files = [{"path": p, "sha256": _blob_sha(worktree, ta_sha, p) or ""} for p in sorted(n for n in names if n)]
    return _out("ok", "", argv, files)


def byte_identity(worktree: Path, ta_sha: str, candidate_sha: str, files: list[dict[str, str]]) -> dict[str, Any]:
    """Byte identity of the test-author files, plus every test path the implementer added, changed, deleted or renamed."""
    modified = [f["path"] for f in files if _blob_sha(worktree, candidate_sha, f["path"]) != f["sha256"]]
    changed = _git(worktree, "diff", "--no-renames", "--name-only", ta_sha, candidate_sha).splitlines()
    return {
        "result": "modified" if modified else "identical", "files": files, "modified": modified,
        "test_paths_changed": sorted(p for p in changed if p and is_test_path(p)),
    }


def summed_final(finals: list[dict[str, Any] | None]) -> dict[str, Any]:
    """A synthetic final result whose usage sums the reported token counts of every session."""
    runs = [f for f in finals if isinstance(f, dict)]
    usage: dict[str, int] = {}
    for key in worker_module.TOKEN_KEYS:
        vals = [u[key] for f in runs if isinstance(u := f.get("usage"), dict) and isinstance(u.get(key), int) and not isinstance(u.get(key), bool)]
        if vals:
            usage[key] = sum(vals)
    costs = [c for f in runs if isinstance(c := f.get("cost_usd", (f.get("usage") or {}).get("cost_usd")), (int, float)) and not isinstance(c, bool)]
    merged: dict[str, Any] = {"usage": usage}
    if costs and len(costs) == len(finals):
        merged["cost_usd"] = sum(costs)
    return merged
