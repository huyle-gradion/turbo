"""Child scope evaluation, isolated verification, and GitHub PR confirmation (#19)."""

from __future__ import annotations

import json, math, os, re, shlex, subprocess, time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener

from factory import config as config_module, gitio, runner, worker as worker_module
from factory.errors import UsageError
from factory.intake import NoRedirectHandler, same_api_origin
from factory.paths import safe_dir, write_evidence

DEFAULT_GITHUB_API_URL = "https://api.github.com"
REPO_SLUG_RE = re.compile(r"^(?:https://github\.com/|git@github\.com:)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$")
KNOWN_FILE_EXTS = frozenset({
    "py", "sh", "md", "json", "yaml", "yml", "toml", "ts", "tsx", "js", "jsx", "go", "rs", "sql", "txt", "cfg", "ini", "lock", "html", "css",
})
REPO_TOP_DIRS = frozenset({
    "src", "tests", "test", "factory", "scripts", "docs", "bin", "lib", "pkg", "cmd", "internal", "app", "config", "examples", "skills", "pilot",
})
PATH_TOKEN_RE = re.compile(
    r"(?:`([^`\r\n]+)`|(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+/?|"
    r"[A-Za-z0-9_.-]+\.(?:py|sh|md|json|ya?ml|toml|ts|tsx|js|jsx|go|rs|sql))(?![A-Za-z0-9_.-]))"
)
NEGATION_CONSTRAINT_RE = re.compile(
    r"\b(?:do\s+not|don't|never|forbid(?:den)?|prohibit(?:ed)?|must\s+not|cannot|no\s+edits?\s+to|untouched)\b", re.IGNORECASE
)
EXECUTABLE_VERIFIERS = frozenset({"python", "python3", "pytest", "unittest", "sh", "bash", "npm", "pnpm", "node", "go", "cargo"})
INLINE_TEST_START_RE = re.compile(r"^\s*(?:def test_[A-Za-z0-9_]*\s*\(|class \w*Test\w*\b)")
INLINE_TEST_CALL_RE = re.compile(r"\b(?:self\.assert\w+\s*\(|(?:describe|it|test)\s*\(|#\[test\])")

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
    cmd = ("git", "-C", str(repo), *args)
    try:
        completed = subprocess.run(
            list(cmd), text=True, capture_output=True, check=False, shell=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=rem
        )
    except subprocess.TimeoutExpired as exc:
        raise AttemptTimeoutError(f"attempt timed out during {phase} after {limit_s}s") from exc
    return gitio.GitResult(cmd, completed.returncode, (completed.stdout + completed.stderr).strip())

def collect_redaction_secrets() -> tuple[str, ...]:
    keys = ("ASANA_ACCESS_TOKEN", "ASANA_PAT", "ASANA_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "TURBO_GITHUB_TOKEN")
    raw = tuple(s for k in keys if (s := (os.environ.get(k) or "").strip()))
    return tuple(dict.fromkeys([*raw, *(quote(s, safe="") for s in raw)]))

def resolve_github_api() -> tuple[str, bool]:
    raw = os.environ.get("TURBO_GITHUB_API_URL", DEFAULT_GITHUB_API_URL).strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UsageError(f"disallowed GitHub API URL {raw!r}; credentials, query, and fragment are forbidden")
    path = parsed.path.rstrip("/")
    is_canonical = parsed.scheme == "https" and parsed.hostname == "api.github.com" and path in ("", "/api/v3")
    is_loopback = parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1") and path in ("", "/api/v3")
    if is_canonical or is_loopback:
        return raw, is_loopback
    raise UsageError(f"disallowed GitHub API URL {raw!r}; only https://api.github.com or loopback test server is permitted")

def resolve_github_token(is_loopback: bool) -> str:
    prod_tokens = tuple(s for k in ("GITHUB_TOKEN", "GH_TOKEN") if (s := (os.environ.get(k) or "").strip()))
    test_tokens = tuple(s for k in ("TURBO_GITHUB_TOKEN",) if (s := (os.environ.get(k) or "").strip()))
    if is_loopback:
        if prod_tokens and not test_tokens:
            raise GitHubError(
                "refused to send production GITHUB_TOKEN/GH_TOKEN to loopback test server; set TURBO_GITHUB_TOKEN for disposable test servers"
            )
        return test_tokens[0] if test_tokens else ""
    return prod_tokens[0] if prod_tokens else (test_tokens[0] if test_tokens else "")

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
            return f"local origin remote {remote_url!r} ({match.group(1)}) does not match target {expected_slug!r}"
        return None
    if Path(remote_url).is_absolute() or remote_url.startswith("file://"):
        return None
    return f"untrusted or unrecognized origin remote URL {remote_url!r} for target {expected_slug!r}"

def _normalize_repo_path_token(raw: str) -> str | None:
    candidate = raw.strip()
    if not candidate or " " in candidate or "://" in candidate or candidate.startswith(("-", "/")):
        return None
    had_trailing_slash = candidate.endswith("/")
    norm = candidate.rstrip("/")
    if not norm or not re.fullmatch(r"[A-Za-z0-9_.*-/]+", norm) or config_module.protected_entry_issue(norm) is not None:
        return None
    if "/" in norm or had_trailing_slash:
        parts = norm.split("/")
        first, last = parts[0].lower(), parts[-1]
        ext = last.rsplit(".", 1)[1].lower() if "." in last else ""
        return norm if (had_trailing_slash or "*" in norm or ext in KNOWN_FILE_EXTS or first in REPO_TOP_DIRS) else None
    if "." not in norm:
        return None
    ext = norm.rsplit(".", 1)[1].lower()
    is_compound_test = norm.lower().endswith((".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js"))
    return norm if ext in KNOWN_FILE_EXTS and (norm.count(".") == 1 or is_compound_test) else None

def extract_explicit_paths(text: str, *, require_negation: bool = False) -> tuple[list[str], str]:
    if not text or text == "none":
        return [], "none"
    paths: list[str] = []
    for clause in re.split(r"[;\n]+", text):
        if require_negation and not NEGATION_CONSTRAINT_RE.search(clause):
            continue
        for match in PATH_TOKEN_RE.finditer(clause):
            norm = _normalize_repo_path_token(match.group(1) or match.group(2) or "")
            if norm is not None and norm not in paths:
                paths.append(norm)
    return paths, ("deterministic-paths" if paths else "semantic-only")

def _glob_to_regex(rule_norm: str) -> re.Pattern[str]:
    segments = [seg for seg in rule_norm.split("/") if seg]
    parts: list[str] = []
    for idx, seg in enumerate(segments):
        if seg == "**":
            parts.append("(?:[^/]+/)*" if idx + 1 < len(segments) else ".*")
            continue
        for ch in seg:
            parts.append("[^/]*" if ch == "*" else ("[^/]" if ch == "?" else re.escape(ch)))
        if idx + 1 < len(segments):
            parts.append("/")
    return re.compile(r"\A" + "".join(parts) + r"\Z")

def _matches_path_rule(changed_path: str, rule_path: str) -> bool:
    changed_norm, rule_norm = changed_path.strip().strip("/"), rule_path.strip().strip("/")
    if not changed_norm or not rule_norm:
        return False
    if "*" in rule_norm or "?" in rule_norm:
        return _glob_to_regex(rule_norm).fullmatch(changed_norm) is not None
    changed, rule = PurePosixPath(changed_norm), PurePosixPath(rule_norm)
    return changed == rule or rule in changed.parents

def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name, parts = pure.name.lower(), [part.lower() for part in pure.parts]
    return (
        "tests" in parts or "test" in parts or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".test.js", "_test.go"))
    )

def evaluate_scope(changed: tuple[str, ...], child: dict[str, Any], protected_paths: tuple[str, ...]) -> tuple[bool, list[str], dict[str, Any]]:
    scope = child.get("scope") or {}
    in_raw, out_raw, con_raw = str(scope.get("in_scope") or ""), str(scope.get("out_of_scope") or ""), str(scope.get("constraints") or "")
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
    status = "violation" if not deterministic_ok else ("deterministic-only-semantic-unverified" if has_semantic_only else "deterministic-verified")
    provenance = (
        "deterministic path and protected-path rules enforced; natural-language semantic scope "
        "is not machine-verified by the helper and requires independent review (#23) and human review"
        if has_semantic_only else "deterministic path and protected-path rules enforced"
    )
    detail = {
        "status": status, "deterministic_ok": deterministic_ok, "semantic_verified": semantic_verified,
        "provenance": provenance, "in_scope": in_raw, "in_scope_enforcement": in_mode, "in_scope_paths": in_paths,
        "out_of_scope": out_raw, "out_of_scope_enforcement": out_mode, "out_of_scope_paths": out_paths,
        "constraints": con_raw, "constraints_enforcement": con_mode, "constraint_paths": con_paths,
        "protected_paths": list(protected_paths), "violations": violations,
    }
    return deterministic_ok, violations, detail

def _classify_impl_file_diff(diff_text: str) -> tuple[bool, bool]:
    has_impl, has_inline_test = False, False
    inline_test_indent: int | None = None
    for raw_line in diff_text.splitlines():
        if raw_line.startswith(("+++", "---", "@@")) or not raw_line.startswith(("+", "-")):
            if raw_line.startswith("@@"):
                inline_test_indent = None
            continue
        content = raw_line[1:]
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" \t"))
        if INLINE_TEST_START_RE.match(content):
            has_inline_test, inline_test_indent = True, indent
            continue
        if inline_test_indent is not None:
            if indent > inline_test_indent:
                continue
            inline_test_indent = None
        if INLINE_TEST_CALL_RE.search(content):
            has_inline_test = True
            continue
        has_impl = True
    return has_impl, has_inline_test

def inspect_diff_categories(worktree: Path, base_sha: str, head_sha: str, deadline: float, limit_s: int) -> dict[str, Any]:
    status_res = git_timed(worktree, deadline, limit_s, "diff inspection", "diff", "--find-renames", "--name-status", base_sha, head_sha)
    path_set: set[str] = set()
    if status_res.ok:
        for line in status_res.output.splitlines():
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            path_set.update(parts[1:])
    changed = tuple(sorted(path_set))
    test_paths = [p for p in changed if is_test_path(p)]
    impl_paths = [p for p in changed if not is_test_path(p)]
    has_test_changes, has_impl_changes = bool(test_paths), False
    for path in impl_paths:
        f_diff = git_timed(worktree, deadline, limit_s, "diff inspection", "diff", "--no-renames", "--unified=0", base_sha, head_sha, "--", path)
        if f_diff.ok and f_diff.output:
            file_impl, file_test = _classify_impl_file_diff(f_diff.output)
            has_impl_changes = has_impl_changes or file_impl
            has_test_changes = has_test_changes or file_test
        else:
            has_impl_changes = True
    return {
        "changed_paths": list(changed), "implementation_paths": impl_paths, "test_paths": test_paths,
        "has_implementation_changes": has_impl_changes, "has_test_changes": has_test_changes,
    }

def prepare_verification_env(worker_env: dict[str, str], child_dir: Path, home: Path) -> dict[str, str]:
    verify_home = safe_dir(child_dir / "verify-home", create=True, root=home)
    tmp_dir = str(safe_dir(verify_home / ".tmp", create=True, root=home))
    clean = {
        key: val for key, val in worker_env.items()
        if "TOKEN" not in key.upper()
        and not (key.upper().startswith("TURBO_") and key.upper().endswith("_URL"))
        and not key.upper().endswith("_PROXY")
        and key.upper() not in ("TURBO_LIVE_AGY", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE")
    }
    clean.update({
        "HOME": str(verify_home), "TMPDIR": tmp_dir, "TMP": tmp_dir, "TEMP": tmp_dir,
        "XDG_CONFIG_HOME": str(verify_home / ".config"), "XDG_CACHE_HOME": str(verify_home / ".cache"),
        "GIT_CONFIG_GLOBAL": str(verify_home / "nonexistent-gitconfig"),
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false", "SSH_AUTH_SOCK": "",
        "GIT_SSH_COMMAND": "false", "GIT_ALLOW_PROTOCOL": "none",
        "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "PIP_NO_INDEX": "1",
        "NPM_CONFIG_OFFLINE": "true",
    })
    return clean

def _verification_argv(raw: str) -> tuple[str, ...] | None:
    try:
        tokens = tuple(shlex.split(raw.strip()))
    except ValueError:
        return None
    return tokens if tokens and PurePosixPath(tokens[0]).name in EXECUTABLE_VERIFIERS else None

def _exec_check(
    check_id: str, kind: str, stem: str, argv: tuple[str, ...], worktree: Path,
    child_dir: Path, home: Path, verify_env: dict[str, str], deadline: float, limit_s: int,
) -> dict[str, Any]:
    rem = remaining_seconds(deadline, f"verification {check_id}", limit_s)
    try:
        code, out_s, err_s, _, timed_out = worker_module.execute_stream(
            worktree, argv, verify_env, max(1, int(math.ceil(rem))),
            isolated_home=Path(verify_env["HOME"]), allow_network=False,
        )
    except OSError as exc:
        out = f"[factory] verification executable failed to start ({argv[0]!r}): {exc}\n"
        ev_path = write_evidence(child_dir, stem, out, home)
        return {
            "id": check_id, "kind": kind, "argv": list(argv), "executed": False, "exit": 127,
            "ok": False, "error": str(exc), "output_path": str(ev_path), "output_sha256": runner.digest_text(out),
        }
    out = (out_s + err_s).strip() + "\n"
    ev_path = write_evidence(child_dir, stem, out, home)
    if timed_out or time.monotonic() >= deadline:
        raise AttemptTimeoutError(f"attempt timed out during verification {check_id} after {limit_s}s")
    return {
        "id": check_id, "kind": kind, "argv": list(argv), "executed": True, "exit": code,
        "ok": code == 0, "output_path": str(ev_path), "output_sha256": runner.digest_text(out),
    }

def run_child_verifications(
    worktree: Path, child: dict[str, Any], conf: config_module.Config, child_dir: Path,
    home: Path, worker_env: dict[str, str], deadline: float, limit_s: int,
) -> tuple[bool, list[dict[str, Any]], list[str]]:
    verify_env = prepare_verification_env(worker_env, child_dir, home)
    checks, failures, seen_cmds = [], [], set()
    for crit in child.get("criteria") or []:
        cid, ver_str = str(crit.get("id") or "AC"), str(crit.get("verification") or "").strip()
        argv = _verification_argv(ver_str)
        if argv is None:
            checks.append({"id": cid, "kind": "criterion-evaluation", "command": ver_str, "executed": False, "ok": False})
            failures.append(f"criterion {cid} verification is not an executable check command: {ver_str!r}")
            continue
        seen_cmds.add(argv)
        rec = _exec_check(cid, "criterion-verification", f"check-{cid.lower()}", argv, worktree, child_dir, home, verify_env, deadline, limit_s)
        if not rec["ok"]:
            failures.append(f"criterion {cid} verification failed (exit {rec['exit']}): {ver_str}")
        checks.append(rec)
    gate2 = conf.gates.get("2")
    if gate2 is not None and gate2.kind == "command" and gate2.argv and gate2.argv not in seen_cmds:
        rec = _exec_check("gate-2", "project-tests", "check-project-tests", gate2.argv, worktree, child_dir, home, verify_env, deadline, limit_s)
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
    if not same_api_origin(url, base_url):
        trace.append({"method": method, "url": url, "status": "blocked-origin"})
        raise GitHubError(f"refused to send GitHub credentials to untrusted destination: {url}")
    if not token:
        trace.append({"method": method, "url": url, "status": "missing-token"})
        raise GitHubError("missing GitHub authentication token")
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with build_opener(NoRedirectHandler).open(req, timeout=min(15.0, rem)) as resp:
            code, body = getattr(resp, "status", 200), resp.read().decode("utf-8", "replace")
    except HTTPError as exc:
        trace.append({"method": method, "url": url, "status": exc.code})
        exc.close()
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
    parent_gid, child_gid = str(parent["gid"]), str(child["gid"])
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
        {"title": title, "head": head_branch, "base": base_branch, "body": body},
    )
    pr_number = created.get("number")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
        raise GitHubError("GitHub PR creation response is missing a positive integer pull request number")
    verify_url = f"{base_url}/repos/{repo_slug}/pulls/{pr_number}"
    verified = github_request("GET", verify_url, token, base_url, trace, deadline, limit_s)
    state, merged = str(verified.get("state") or ""), bool(verified.get("merged"))
    head_obj = verified.get("head") if isinstance(verified.get("head"), dict) else {}
    base_obj = verified.get("base") if isinstance(verified.get("base"), dict) else {}
    obs_head_ref, obs_head_sha = str(head_obj.get("ref") or "").strip(), str(head_obj.get("sha") or "").strip()
    obs_base_ref = str(base_obj.get("ref") or "").strip()
    base_repo = base_obj.get("repo") if isinstance(base_obj.get("repo"), dict) else {}
    head_repo = head_obj.get("repo") if isinstance(head_obj.get("repo"), dict) else {}
    obs_base_repo = str(base_repo.get("full_name") or "").strip()
    obs_head_repo = str(head_repo.get("full_name") or "").strip()
    if state != "open" or merged:
        raise GitHubError(f"verified PR #{pr_number} is not open and unmerged (state={state!r}, merged={merged})")
    for label, obs, exp, ci in (
        ("base repository", obs_base_repo, repo_slug, True),
        ("head repository", obs_head_repo, repo_slug, True),
        ("base branch", obs_base_ref, base_branch, False),
        ("head branch", obs_head_ref, head_branch, False),
        ("head SHA", obs_head_sha, candidate_sha, False),
    ):
        if not obs or (obs.lower() != exp.lower() if ci else obs != exp):
            raise GitHubError(f"verified PR #{pr_number} {label} mismatch: expected {exp!r}, got {obs!r}")
    return {
        "number": pr_number, "url": str(verified.get("html_url") or created.get("html_url") or verify_url),
        "title": str(verified.get("title") or title), "body": str(verified.get("body") or body),
        "state": state, "merged": merged, "repository": obs_base_repo,
        "base_ref": obs_base_ref, "head_ref": obs_head_ref, "head_sha": obs_head_sha, "verified": True,
    }
