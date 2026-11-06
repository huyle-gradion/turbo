"""Child scope evaluation, isolated verification, and GitHub PR confirmation (#19)."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener

from factory import config as config_module
from factory import gitio
from factory import runner
from factory import worker as worker_module
from factory.errors import UsageError
from factory.intake import _NoRedirectHandler, _same_api_origin
from factory.paths import safe_dir, write_evidence

DEFAULT_GITHUB_API_URL = "https://api.github.com"
REPO_SLUG_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
PATH_TOKEN_RE = re.compile(
    r"(?:`([^`\r\n]+)`|(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+|"
    r"[A-Za-z0-9_.-]+\.(?:py|sh|md|json|ya?ml|toml|ts|tsx|js|jsx|go|rs|sql))(?![A-Za-z0-9_.-]))"
)
NEGATION_CONSTRAINT_RE = re.compile(
    r"\b(?:do\s+not|don't|never|forbid(?:den)?|prohibit(?:ed)?|must\s+not|cannot|no\s+edits?\s+to|untouched)\b",
    re.IGNORECASE,
)
EXECUTABLE_VERIFIERS = frozenset(
    {"python", "python3", "pytest", "unittest", "sh", "bash", "npm", "pnpm", "node", "go", "cargo"}
)
VERIFY_NETWORK_GUARD = (
    "import socket as _s\n"
    "def _deny(*_a, **_kw):\n"
    "    raise PermissionError('external network access is disabled during verification checks')\n"
    "_s.socket.connect = _deny\n"
    "_s.socket.connect_ex = _deny\n"
    "_s.create_connection = _deny\n"
)


class AttemptTimeoutError(Exception):
    """Raised when the overall delivery attempt exceeds its configured time limit."""


class GitHubError(Exception):
    """Raised when GitHub API PR creation or independent verification fails."""


def remaining_seconds(deadline: float, phase: str, limit_s: int) -> float:
    rem = deadline - time.monotonic()
    if rem <= 0:
        raise AttemptTimeoutError(f"attempt timed out during {phase} after {limit_s}s")
    return rem


def git_timed(repo: Path, deadline: float, limit_s: int, phase: str, *args: str) -> gitio.GitResult:
    rem = remaining_seconds(deadline, phase, limit_s)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    cmd = ("git", "-C", str(repo), *args)
    try:
        completed = subprocess.run(
            list(cmd), text=True, capture_output=True, check=False, shell=False, env=env, timeout=rem
        )
    except subprocess.TimeoutExpired as exc:
        raise AttemptTimeoutError(f"attempt timed out during {phase} after {limit_s}s") from exc
    output = (completed.stdout + completed.stderr).strip()
    return gitio.GitResult(cmd, completed.returncode, output)


def run_timed_safety_probes(
    worker_env: dict[str, str], worktree_dir: Path, child_dir: Path, home: Path, deadline: float, limit_s: int
) -> list[dict[str, Any]]:
    cred_script = (
        "import os, pathlib, sys\n"
        "forbidden_env = ('PRODUCTION_DATABASE_URL', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'ASANA_ACCESS_TOKEN')\n"
        "present_env = [k for k in forbidden_env if os.environ.get(k)]\n"
        "h = pathlib.Path.home()\n"
        "present_files = [str(p) for p in (h / '.aws/credentials', h / '.config/gh/hosts.yml', h / '.netrc') if p.exists()]\n"
        "if not present_env and not present_files:\n"
        "    sys.stderr.write('DENIED: forbidden env credentials and home credential stores excluded\\n')\n"
        "    sys.exit(1)\n"
        "print('ALLOWED: ' + ','.join(present_env + present_files))\n"
        "sys.exit(0)\n"
    )
    ext_script = (
        "import os, pathlib, subprocess, sys\n"
        "root = pathlib.Path(os.environ.get('TURBO_DISPOSABLE_ROOT', '')).resolve()\n"
        "confined = pathlib.Path.cwd().resolve() == root and pathlib.Path.home().resolve().is_relative_to(root.parent)\n"
        "try:\n"
        "    pathlib.Path('/etc/turbo-production-sink').write_text('probe', encoding='utf-8')\n"
        "    fs_denied = False\n"
        "except OSError:\n"
        "    fs_denied = True\n"
        "push_denied = subprocess.run(['git', 'push', 'https://127.0.0.1:1/prod.git', 'HEAD'], capture_output=True, timeout=2).returncode != 0\n"
        "if confined and fs_denied and push_denied:\n"
        "    sys.stderr.write('DENIED: external filesystem and git push effects failed closed\\n')\n"
        "    sys.exit(1)\n"
        "print('ALLOWED')\n"
        "sys.exit(0)\n"
    )
    results: list[dict[str, Any]] = []
    for name, stem, script in (
        ("forbidden_credential_access", "probe-credentials", cred_script),
        ("external_effect_restriction", "probe-external-effects", ext_script),
    ):
        rem = remaining_seconds(deadline, f"safety probe {name}", limit_s)
        timeout_s = max(1, min(10, int(math.ceil(rem))))
        code, out_s, err_s, _, timed_out = worker_module._execute_stream(
            worktree_dir, (sys.executable, "-c", script), worker_env, timeout_s
        )
        if timed_out or time.monotonic() >= deadline:
            raise AttemptTimeoutError(f"attempt timed out during safety probe {name} after {limit_s}s")
        combined = (out_s + err_s).strip() + "\n"
        path = write_evidence(child_dir, stem, combined, home)
        results.append(
            {
                "name": name,
                "denied": code != 0,
                "exit": code,
                "output_path": str(path),
                "output_sha256": runner.digest_text(combined),
                "detail": combined.strip(),
            }
        )
    return results


def resolve_github_api() -> tuple[str, bool]:
    raw = os.environ.get("TURBO_GITHUB_API_URL", DEFAULT_GITHUB_API_URL).strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UsageError(f"disallowed GitHub API URL {raw!r}; credentials, query, and fragment are forbidden")
    path = parsed.path.rstrip("/")
    is_canonical = parsed.scheme == "https" and parsed.hostname == "api.github.com" and path in ("", "/api/v3")
    is_loopback = (
        parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1") and path in ("", "/api/v3")
    )
    if is_canonical or is_loopback:
        return raw, is_loopback
    raise UsageError(
        f"disallowed GitHub API URL {raw!r}; only https://api.github.com or loopback test server is permitted"
    )


def resolve_github_token(is_loopback: bool) -> tuple[str, tuple[str, ...]]:
    prod_tokens = tuple(
        s for s in ((os.environ.get("GITHUB_TOKEN") or "").strip(), (os.environ.get("GH_TOKEN") or "").strip()) if s
    )
    test_tokens = tuple(s for s in ((os.environ.get("TURBO_GITHUB_TOKEN") or "").strip(),) if s)
    all_raw = (*test_tokens, *prod_tokens)
    secrets = tuple(dict.fromkeys([*all_raw, *(quote(s, safe="") for s in all_raw)]))
    if is_loopback:
        if prod_tokens and not test_tokens:
            raise GitHubError(
                "refused to send production GITHUB_TOKEN/GH_TOKEN to loopback test server; "
                "set TURBO_GITHUB_TOKEN for disposable test servers"
            )
        return (test_tokens[0] if test_tokens else ""), secrets
    token = prod_tokens[0] if prod_tokens else (test_tokens[0] if test_tokens else "")
    return token, secrets


def parse_repo_slug(repo_url: str) -> str:
    match = REPO_SLUG_RE.fullmatch(repo_url.strip())
    if match is None:
        raise UsageError(f"cannot parse GitHub owner/repo slug from repository target {repo_url!r}")
    return match.group(1)


def verify_origin_remote(repo: Path, expected_slug: str, deadline: float, limit_s: int) -> str | None:
    res = git_timed(repo, deadline, limit_s, "origin remote verification", "remote", "get-url", "origin")
    if not res.ok or not res.output:
        return "repository has no 'origin' remote configured"
    remote_url = res.output.strip()
    match = REPO_SLUG_RE.fullmatch(remote_url)
    if match is not None:
        if match.group(1).lower() != expected_slug.lower():
            return (
                f"local origin remote {remote_url!r} ({match.group(1)}) "
                f"does not match target repository {expected_slug!r}"
            )
        return None
    if Path(remote_url).is_absolute() or remote_url.startswith("file://"):
        return None
    return f"untrusted or unrecognized origin remote URL {remote_url!r} for target {expected_slug!r}"


def extract_explicit_paths(text: str, *, require_negation: bool = False) -> tuple[list[str], str]:
    if not text or text == "none":
        return [], "none"
    paths: list[str] = []
    for clause in re.split(r"[;\n]+", text):
        if require_negation and not NEGATION_CONSTRAINT_RE.search(clause):
            continue
        for match in PATH_TOKEN_RE.finditer(clause):
            candidate = (match.group(1) or match.group(2) or "").strip()
            if not candidate or " " in candidate or "://" in candidate or candidate.startswith("-"):
                continue
            norm = candidate.rstrip("/")
            if ("/" in candidate or "." in norm) and config_module.protected_entry_issue(norm) is None and norm not in paths:
                paths.append(norm)
    return paths, ("deterministic-paths" if paths else "semantic-only")


def _matches_path_rule(changed_path: str, rule_path: str) -> bool:
    changed = PurePosixPath(changed_path)
    rule = PurePosixPath(rule_path.rstrip("/"))
    return changed.match(rule_path) if "*" in rule_path else (changed == rule or rule in changed.parents)


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    parts = [part.lower() for part in pure.parts]
    return (
        "tests" in parts
        or "test" in parts
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".test.js", "_test.go"))
    )


def evaluate_scope(
    changed: tuple[str, ...], child: dict[str, Any], protected_paths: tuple[str, ...]
) -> tuple[bool, list[str], dict[str, Any]]:
    scope = child.get("scope") or {}
    in_raw = str(scope.get("in_scope") or "")
    out_raw = str(scope.get("out_of_scope") or "")
    con_raw = str(scope.get("constraints") or "")
    in_paths, in_mode = extract_explicit_paths(in_raw)
    out_paths, out_mode = extract_explicit_paths(out_raw)
    con_paths, con_mode = extract_explicit_paths(con_raw, require_negation=True)
    violations: list[str] = []
    for path in changed:
        if config_module.protected_match(path, protected_paths):
            violations.append(f"modified protected path {path!r}")
        if any(_matches_path_rule(path, rule) for rule in out_paths):
            violations.append(f"modified out-of-scope path {path!r} (out of scope: {out_raw})")
        if any(_matches_path_rule(path, rule) for rule in con_paths):
            violations.append(f"modified constraint-restricted path {path!r} (constraints: {con_raw})")
        if in_paths and not any(_matches_path_rule(path, rule) for rule in in_paths):
            violations.append(f"modified path {path!r} outside explicit in-scope paths {in_paths}")
    has_semantic_only = "semantic-only" in (in_mode, out_mode, con_mode)
    deterministic_ok = len(violations) == 0
    semantic_verified = deterministic_ok and not has_semantic_only
    status = (
        "violation"
        if not deterministic_ok
        else ("deterministic-only-semantic-unverified" if has_semantic_only else "deterministic-verified")
    )
    provenance = (
        "deterministic path and protected-path rules enforced; natural-language semantic scope "
        "is not machine-verified by the helper and requires independent review (#23) and human review"
        if has_semantic_only
        else "deterministic path and protected-path rules enforced"
    )
    detail = {
        "status": status,
        "deterministic_ok": deterministic_ok,
        "semantic_verified": semantic_verified,
        "provenance": provenance,
        "in_scope": in_raw,
        "in_scope_enforcement": in_mode,
        "in_scope_paths": in_paths,
        "out_of_scope": out_raw,
        "out_of_scope_enforcement": out_mode,
        "out_of_scope_paths": out_paths,
        "constraints": con_raw,
        "constraints_enforcement": con_mode,
        "constraint_paths": con_paths,
        "protected_paths": list(protected_paths),
        "violations": violations,
    }
    return deterministic_ok, violations, detail


def inspect_diff_categories(
    worktree: Path, base_sha: str, head_sha: str, deadline: float, limit_s: int
) -> dict[str, Any]:
    names_res = git_timed(worktree, deadline, limit_s, "diff inspection", "diff", "--name-only", base_sha, head_sha)
    changed = tuple(sorted({line.strip() for line in names_res.output.splitlines() if line.strip()})) if names_res.ok else ()
    diff_res = git_timed(worktree, deadline, limit_s, "diff inspection", "diff", "--unified=0", base_sha, head_sha)
    diff_text = diff_res.output if diff_res.ok else ""
    added_lines = [line[1:] for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++")]
    test_paths = [p for p in changed if is_test_path(p)]
    impl_paths = [p for p in changed if not is_test_path(p)]
    test_line_re = re.compile(
        r"\b(?:def test_|class \w*Test|assert(?:Equal|True|False|Raises|In)?\b|self\.assert|test\(|it\(|expect\()"
    )
    impl_def_re = re.compile(r"^\s*(?:def (?!test_)[A-Za-z_]|class (?!\w*Test\b)[A-Za-z_])")
    has_test_hunks = any(test_line_re.search(line) for line in added_lines)
    has_impl_hunks = any(impl_def_re.search(line) for line in added_lines)
    return {
        "changed_paths": list(changed),
        "implementation_paths": impl_paths,
        "test_paths": test_paths,
        "has_implementation_changes": bool(impl_paths) or has_impl_hunks,
        "has_test_changes": bool(test_paths) or has_test_hunks,
    }


def prepare_verification_env(worker_env: dict[str, str], child_dir: Path, home: Path) -> dict[str, str]:
    verify_home = safe_dir(child_dir / "verify-home", create=True, root=home)
    guard_dir = safe_dir(verify_home / "pyguard", create=True, root=home)
    guard_file = guard_dir / "sitecustomize.py"
    guard_file.write_text(VERIFY_NETWORK_GUARD, encoding="utf-8")
    os.chmod(guard_file, 0o600)
    clean: dict[str, str] = {}
    for key, val in worker_env.items():
        upper = key.upper()
        if "TOKEN" in upper or (upper.startswith("TURBO_") and upper.endswith("_URL")):
            continue
        if upper.endswith("_PROXY") or upper in ("TURBO_LIVE_AGY",):
            continue
        clean[key] = val
    existing_py = clean.get("PYTHONPATH", "").strip()
    py_path = f"{guard_dir}{os.pathsep}{existing_py}" if existing_py else str(guard_dir)
    clean.update(
        {
            "HOME": str(verify_home),
            "XDG_CONFIG_HOME": str(verify_home / ".config"),
            "XDG_CACHE_HOME": str(verify_home / ".cache"),
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "",
            "PIP_NO_INDEX": "1",
            "NPM_CONFIG_OFFLINE": "true",
            "PYTHONPATH": py_path,
        }
    )
    return clean


def _verification_argv(raw: str) -> tuple[str, ...] | None:
    try:
        tokens = tuple(shlex.split(raw.strip()))
    except ValueError:
        return None
    if not tokens or PurePosixPath(tokens[0]).name not in EXECUTABLE_VERIFIERS:
        return None
    return tokens


def _exec_check(
    check_id: str, kind: str, stem: str, argv: tuple[str, ...], worktree: Path,
    child_dir: Path, home: Path, verify_env: dict[str, str], deadline: float, limit_s: int,
) -> dict[str, Any]:
    rem = remaining_seconds(deadline, f"verification {check_id}", limit_s)
    timeout_s = max(1, int(math.ceil(rem)))
    code, out_s, err_s, _, timed_out = worker_module._execute_stream(worktree, argv, verify_env, timeout_s)
    out = (out_s + err_s).strip() + "\n"
    ev_path = write_evidence(child_dir, stem, out, home)
    if timed_out or time.monotonic() >= deadline:
        raise AttemptTimeoutError(f"attempt timed out during verification {check_id} after {limit_s}s")
    return {
        "id": check_id,
        "kind": kind,
        "argv": list(argv),
        "executed": True,
        "exit": code,
        "ok": code == 0,
        "output_path": str(ev_path),
        "output_sha256": runner.digest_text(out),
    }


def run_child_verifications(
    worktree: Path, child: dict[str, Any], conf: config_module.Config, child_dir: Path,
    home: Path, worker_env: dict[str, str], deadline: float, limit_s: int,
) -> tuple[bool, list[dict[str, Any]], list[str]]:
    verify_env = prepare_verification_env(worker_env, child_dir, home)
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    seen_cmds: set[tuple[str, ...]] = set()
    for crit in child.get("criteria") or []:
        cid = str(crit.get("id") or "AC")
        ver_str = str(crit.get("verification") or "").strip()
        argv = _verification_argv(ver_str)
        if argv is None:
            checks.append({"id": cid, "kind": "criterion-evaluation", "command": ver_str, "executed": False, "ok": False})
            failures.append(f"criterion {cid} verification is not an executable check command: {ver_str!r}")
            continue
        seen_cmds.add(argv)
        rec = _exec_check(
            cid, "criterion-verification", f"check-{cid.lower()}", argv, worktree, child_dir, home, verify_env, deadline, limit_s
        )
        if not rec["ok"]:
            failures.append(f"criterion {cid} verification failed (exit {rec['exit']}): {ver_str}")
        checks.append(rec)
    gate2 = conf.gates.get("2")
    if gate2 is not None and gate2.kind == "command" and gate2.argv and gate2.argv not in seen_cmds:
        rec = _exec_check(
            "gate-2", "project-tests", "check-project-tests", gate2.argv, worktree, child_dir, home, verify_env, deadline, limit_s
        )
        if not rec["ok"]:
            failures.append(f"project test check failed (exit {rec['exit']}): {' '.join(gate2.argv)}")
        checks.append(rec)
    return len(failures) == 0, checks, failures


def github_request(
    method: str, url: str, token: str, base_url: str, trace: list[dict[str, Any]],
    deadline: float, limit_s: int, payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rem = remaining_seconds(deadline, "GitHub API request", limit_s)
    target_parsed = urlparse(url)
    if not _same_api_origin(url, base_url):
        trace.append({"method": method, "url": url, "status": "blocked-origin"})
        raise GitHubError(f"refused to send GitHub credentials to untrusted destination: {url}")
    if not token:
        trace.append({"method": method, "url": url, "status": "missing-token"})
        raise GitHubError("missing GitHub authentication token")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with build_opener(_NoRedirectHandler).open(req, timeout=min(15.0, rem)) as resp:
            code = getattr(resp, "status", 200)
            body = resp.read().decode("utf-8", "replace")
    except HTTPError as exc:
        trace.append({"method": method, "url": url, "status": exc.code})
        raise GitHubError(f"GitHub API HTTP {exc.code} on {target_parsed.path}: {exc.reason}") from exc
    except TimeoutError as exc:
        trace.append({"method": method, "url": url, "status": "timeout"})
        raise AttemptTimeoutError(f"attempt timed out during GitHub API request after {limit_s}s") from exc
    except (URLError, OSError) as exc:
        if time.monotonic() >= deadline or isinstance(getattr(exc, "reason", None), TimeoutError):
            trace.append({"method": method, "url": url, "status": "timeout"})
            raise AttemptTimeoutError(f"attempt timed out during GitHub API request after {limit_s}s") from exc
        trace.append({"method": method, "url": url, "status": "network-error"})
        raise GitHubError(f"GitHub API request failed on {target_parsed.path}: {exc}") from exc
    trace.append({"method": method, "url": url, "status": code})
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise GitHubError(f"malformed JSON from GitHub API on {target_parsed.path}") from exc
    if not isinstance(parsed, dict):
        raise GitHubError(f"GitHub API response on {target_parsed.path} must be a JSON object")
    return parsed


def open_and_confirm_pr(
    base_url: str, token: str, repo_slug: str, parent: dict[str, Any], child: dict[str, Any],
    head_branch: str, candidate_sha: str, base_branch: str, checks: list[dict[str, Any]],
    scope_detail: dict[str, Any], trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> dict[str, Any]:
    parent_gid = str(parent["gid"])
    child_gid = str(child["gid"])
    title = f"{child['name']} [Asana {child_gid}]"
    check_lines = [
        f"- `{c['id']}`: {'PASS' if (c['executed'] and c['ok']) else ('UNEXECUTED' if not c['executed'] else 'FAIL')} "
        f"(`{' '.join(c.get('argv', [c.get('command', '')]))}`)"
        for c in checks
    ] or ["- None executed"]
    body = (
        f"## Summary\n\n{child.get('outcome') or child['name']}\n\n"
        f"## Asana Links\n- Parent task: https://app.asana.com/0/0/{parent_gid} (`{parent_gid}`)\n"
        f"- Sub-task: https://app.asana.com/0/0/{child_gid} (`{child_gid}`)\n\n"
        f"## Revision & Evidence\n- Candidate revision: `{candidate_sha}`\n"
        f"- Target feature branch: `{base_branch}`\n- Head branch: `{head_branch}`\n"
        f"- Scope check: `{scope_detail.get('status')}` ({scope_detail.get('provenance')})\n"
        f"- Verification checks:\n" + "\n".join(check_lines) + "\n"
    )
    pulls_url = f"{base_url}/repos/{repo_slug}/pulls"
    created = github_request(
        "POST", pulls_url, token, base_url, trace, deadline, limit_s,
        {"title": title, "head": head_branch, "head_sha": candidate_sha, "base": base_branch, "body": body},
    )
    pr_number = created.get("number")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
        raise GitHubError("GitHub PR creation response is missing a positive integer pull request number")
    verify_url = f"{base_url}/repos/{repo_slug}/pulls/{pr_number}"
    verified = github_request("GET", verify_url, token, base_url, trace, deadline, limit_s)
    state = str(verified.get("state") or "")
    merged = bool(verified.get("merged"))
    head_obj = verified.get("head") if isinstance(verified.get("head"), dict) else {}
    base_obj = verified.get("base") if isinstance(verified.get("base"), dict) else {}
    obs_head_ref = str(head_obj.get("ref") or "")
    obs_head_sha = str(head_obj.get("sha") or "")
    obs_base_ref = str(base_obj.get("ref") or "")
    base_repo = base_obj.get("repo") if isinstance(base_obj.get("repo"), dict) else {}
    obs_repo = str(base_repo.get("full_name") or "")
    if state != "open" or merged:
        raise GitHubError(f"verified PR #{pr_number} is not open and unmerged (state={state!r}, merged={merged})")
    if obs_repo and obs_repo.lower() != repo_slug.lower():
        raise GitHubError(f"verified PR #{pr_number} repository mismatch: expected {repo_slug!r}, got {obs_repo!r}")
    if obs_base_ref != base_branch:
        raise GitHubError(f"verified PR #{pr_number} base branch mismatch: expected {base_branch!r}, got {obs_base_ref!r}")
    if obs_head_ref != head_branch:
        raise GitHubError(f"verified PR #{pr_number} head branch mismatch: expected {head_branch!r}, got {obs_head_ref!r}")
    if obs_head_sha != candidate_sha:
        raise GitHubError(f"verified PR #{pr_number} head SHA mismatch: expected {candidate_sha!r}, got {obs_head_sha!r}")
    return {
        "number": pr_number,
        "url": str(verified.get("html_url") or created.get("html_url") or verify_url),
        "title": str(verified.get("title") or title),
        "body": str(verified.get("body") or body),
        "state": state,
        "merged": merged,
        "repository": obs_repo or repo_slug,
        "base_ref": obs_base_ref,
        "head_ref": obs_head_ref,
        "head_sha": obs_head_sha,
        "verified": True,
    }
