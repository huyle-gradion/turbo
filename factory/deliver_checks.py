"""Child scope evaluation, isolated verification, and GitHub PR confirmation (#19)."""

from __future__ import annotations

import io
import json, os, re, shlex, subprocess, time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener
import zipfile

from factory import config as config_module, gitio
from factory.errors import UsageError
from factory.intake import NoRedirectHandler, same_api_origin

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
    try:
        return gitio.git_result(repo, args, timeout=rem)
    except subprocess.TimeoutExpired as exc:
        raise AttemptTimeoutError(f"attempt timed out during {phase} after {limit_s}s") from exc

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


def _verification_argv(raw: str) -> tuple[str, ...] | None:
    try:
        tokens = tuple(shlex.split(raw.strip()))
    except ValueError:
        return None
    return tokens if tokens and PurePosixPath(tokens[0]).name in EXECUTABLE_VERIFIERS else None


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
        "base_ref": obs_base_ref, "head_ref": obs_head_ref, "head_sha": obs_head_sha,
        "pr_confirmed": True, "ci_verified": False, "verified": False,
    }


MAX_ARTIFACT_ZIP_BYTES = 10 * 1024 * 1024
MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024
_READ_CHUNK_BYTES = 65536
RUN_URL_RE = re.compile(r"/actions/runs/([0-9]+)(?:/job/([0-9]+))?")
KEY_VAL_RE = re.compile(r"^\s*([a-z_]+)\s*=\s*(\S+)\s*$", re.MULTILINE)


def _sanitize_url_for_log(raw_url: str) -> str:
    parsed = urlparse(str(raw_url or "").strip())
    if not parsed.scheme or not parsed.hostname:
        return "[redacted-url]"
    port_suffix = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port_suffix}{parsed.path}"


def _is_allowed_redirect_url(redirect_url: str, base_url: str) -> bool:
    parsed = urlparse(redirect_url)
    if not parsed.hostname or parsed.username or parsed.password:
        return False
    if parsed.scheme == "https":
        return True
    base_parsed = urlparse(base_url)
    return (
        parsed.scheme == "http"
        and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        and base_parsed.hostname in ("127.0.0.1", "localhost", "::1")
    )


def _read_bounded_bytes(resp: Any, max_bytes: int, deadline: float, limit_s: int, phase: str) -> bytes:
    headers = getattr(resp, "headers", None)
    if headers is not None and (raw_len := headers.get("Content-Length")) is not None:
        try:
            if int(raw_len) > max_bytes:
                raise GitHubError(f"{phase} exceeds maximum size of {max_bytes} bytes")
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining_seconds(deadline, phase, limit_s)
        chunk = resp.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise GitHubError(f"{phase} exceeds maximum size of {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _download_zip_bytes(
    url: str, token: str, base_url: str, trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> bytes:
    rem = remaining_seconds(deadline, "CI artifact download", limit_s)
    safe_url = _sanitize_url_for_log(url)
    if not same_api_origin(url, base_url):
        trace.append({"method": "GET", "url": safe_url, "status": "blocked-origin"})
        raise GitHubError(f"refused to send GitHub credentials to untrusted artifact URL: {safe_url}")
    req = Request(url, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}, method="GET")
    redirect_loc = ""
    try:
        with build_opener(NoRedirectHandler).open(req, timeout=min(15.0, rem)) as resp:
            trace.append({"method": "GET", "url": safe_url, "status": getattr(resp, "status", 200)})
            return _read_bounded_bytes(resp, MAX_ARTIFACT_ZIP_BYTES, deadline, limit_s, "CI artifact download")
    except HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            redirect_loc = (exc.headers.get("Location") or "").strip() if exc.headers else ""
            exc.close()
            trace.append({"method": "GET", "url": safe_url, "status": exc.code})
        else:
            trace.append({"method": "GET", "url": safe_url, "status": exc.code})
            exc.close()
            raise GitHubError(f"GitHub artifact download HTTP {exc.code} on {safe_url}: {exc.reason}") from exc
    except (URLError, OSError, TimeoutError) as exc:
        if time.monotonic() >= deadline or isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
            raise AttemptTimeoutError(f"attempt timed out during CI artifact download after {limit_s}s") from exc
        raise GitHubError(f"CI artifact download failed on {safe_url}: {exc}") from exc

    safe_redirect = _sanitize_url_for_log(redirect_loc)
    if not _is_allowed_redirect_url(redirect_loc, base_url):
        trace.append({"method": "GET", "url": safe_redirect, "status": "invalid-redirect"})
        raise GitHubError(f"refused insecure artifact redirect Location: {safe_redirect}")
    rem_blob = remaining_seconds(deadline, "CI artifact blob download", limit_s)
    blob_req = Request(redirect_loc, headers={"Accept": "*/*"}, method="GET")
    try:
        with build_opener(NoRedirectHandler).open(blob_req, timeout=min(15.0, rem_blob)) as b_resp:
            trace.append({"method": "GET", "url": safe_redirect, "status": getattr(b_resp, "status", 200)})
            return _read_bounded_bytes(b_resp, MAX_ARTIFACT_ZIP_BYTES, deadline, limit_s, "CI artifact blob download")
    except HTTPError as exc:
        trace.append({"method": "GET", "url": safe_redirect, "status": exc.code})
        exc.close()
        raise GitHubError(f"CI artifact blob download HTTP {exc.code} on {safe_redirect}: {exc.reason}") from exc
    except (URLError, OSError, TimeoutError) as exc:
        if time.monotonic() >= deadline or isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
            raise AttemptTimeoutError(f"attempt timed out during CI artifact blob download after {limit_s}s") from exc
        raise GitHubError(f"CI artifact blob download failed on {safe_redirect}: {exc}") from exc


def _fetch_all_check_runs(
    base_url: str, token: str, repo_slug: str, candidate_sha: str,
    trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> list[dict[str, Any]]:
    all_runs: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    page = 1
    while True:
        url = f"{base_url}/repos/{repo_slug}/commits/{candidate_sha}/check-runs?per_page=100&page={page}"
        payload = github_request("GET", url, token, base_url, trace, deadline, limit_s)
        batch, total_count = payload.get("check_runs"), payload.get("total_count")
        if not isinstance(batch, list) or isinstance(total_count, bool) or not isinstance(total_count, int):
            raise GitHubError("malformed GitHub check-runs response (requires integer total_count and check_runs list)")
        if not batch:
            if len(all_runs) < total_count:
                raise GitHubError(f"truncated GitHub check-runs pagination: got {len(all_runs)} of {total_count}")
            break
        new_in_page = 0
        for item in batch:
            if not isinstance(item, dict) or isinstance(item.get("id"), bool) or not isinstance(item.get("id"), int):
                raise GitHubError("malformed check_run entry in GitHub response")
            cid = int(item["id"])
            if cid not in seen_ids:
                seen_ids.add(cid)
                all_runs.append(item)
                new_in_page += 1
        if len(all_runs) >= total_count:
            break
        if new_in_page == 0 or page >= 50:
            raise GitHubError("cyclic or excessive pagination in GitHub check-runs response")
        page += 1
    return all_runs


def _fetch_workflow_run(
    base_url: str, token: str, repo_slug: str, run_id: int, cache: dict[int, dict[str, Any]],
    trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> dict[str, Any]:
    if run_id not in cache:
        url = f"{base_url}/repos/{repo_slug}/actions/runs/{run_id}"
        cache[run_id] = github_request("GET", url, token, base_url, trace, deadline, limit_s)
    return cache[run_id]


def _extract_wf_run_id(cr: dict[str, Any]) -> int | None:
    for url_field in ("details_url", "html_url"):
        match = RUN_URL_RE.search(str(cr.get(url_field) or ""))
        if match is not None:
            return int(match.group(1))
    return None


def _extract_check_run_attempt(cr: dict[str, Any], wf_info: dict[str, Any] | None = None) -> int | None:
    raw_attempt = cr.get("run_attempt")
    if not isinstance(raw_attempt, bool) and isinstance(raw_attempt, int) and raw_attempt >= 1:
        return raw_attempt
    out_obj = cr.get("output") if isinstance(cr.get("output"), dict) else {}
    summary_kv = dict(KEY_VAL_RE.findall(str(out_obj.get("summary") or "")))
    if "run_attempt" in summary_kv:
        try:
            parsed_att = int(summary_kv["run_attempt"])
            if parsed_att >= 1:
                return parsed_att
        except ValueError:
            return None
    if isinstance(wf_info, dict):
        wf_att = wf_info.get("run_attempt")
        if not isinstance(wf_att, bool) and isinstance(wf_att, int) and wf_att >= 1:
            return wf_att
    return None


def _select_authoritative_check_run(
    rname: str, runs: list[dict[str, Any]], base_url: str, token: str, repo_slug: str,
    wf_cache: dict[int, dict[str, Any]], trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], set[int], str | None]:
    if not runs:
        return None, [], set(), None
    non_completed = [r for r in runs if str(r.get("status") or "") != "completed"]
    if non_completed:
        return non_completed[-1], runs[:-1], set(), None
    if len(runs) == 1:
        return runs[0], [], set(), None
    annotated: list[tuple[int, int, str, str, int, dict[str, Any]]] = []
    for r in runs:
        wf_id = _extract_wf_run_id(r)
        wf_info = (
            _fetch_workflow_run(base_url, token, repo_slug, wf_id, wf_cache, trace, deadline, limit_s)
            if wf_id is not None else None
        )
        attempt = _extract_check_run_attempt(r, wf_info)
        started_at = str(r.get("started_at") or "").strip()
        completed_at = str(r.get("completed_at") or "").strip()
        ts_primary = completed_at or started_at
        if wf_id is None or attempt is None or not ts_primary:
            err = f"ambiguous rerun ordering for required check {rname!r}: missing workflow_run_id, run_attempt, or timestamps"
            return runs[-1], runs[:-1], set(), err
        annotated.append((wf_id, attempt, ts_primary, started_at, int(r.get("id") or 0), r))
    annotated.sort(key=lambda item: (item[0], item[1], item[2], item[3], item[4]))
    for idx in range(len(annotated) - 1):
        prev_wf, prev_att, prev_ts, prev_start, _, _ = annotated[idx]
        next_wf, next_att, next_ts, next_start, _, _ = annotated[idx + 1]
        if (prev_wf, prev_att) == (next_wf, next_att) and (prev_ts, prev_start) == (next_ts, next_start):
            err = f"ambiguous rerun ordering for required check {rname!r}: duplicate ({prev_wf}, attempt {prev_att}) with identical timestamps"
            return annotated[-1][5], [x[5] for x in annotated[:-1]], set(), err
        if (next_wf, next_att) > (prev_wf, prev_att) and next_ts < prev_ts:
            err = f"contradictory rerun ordering for required check {rname!r}: newer ({next_wf}, attempt {next_att}) has earlier timestamp {next_ts!r}"
            return annotated[-1][5], [x[5] for x in annotated[:-1]], set(), err
    selected = annotated[-1][5]
    superseded_runs = [x[5] for x in annotated[:-1]]
    superseded_wf_ids = {x[0] for x in annotated[:-1] if x[0] != annotated[-1][0]}
    return selected, superseded_runs, superseded_wf_ids, None


def _read_manifest_from_zip(raw_zip: bytes, art_id: object) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as zf:
        if "turbo-ci-evidence.json" not in zf.namelist():
            raise GitHubError(f"artifact {art_id} zip is missing turbo-ci-evidence.json")
        info = zf.getinfo("turbo-ci-evidence.json")
        if info.file_size > MAX_EVIDENCE_JSON_BYTES:
            raise GitHubError(f"artifact {art_id} turbo-ci-evidence.json exceeds maximum size of {MAX_EVIDENCE_JSON_BYTES} bytes")
        with zf.open("turbo-ci-evidence.json", "r") as member:
            raw_json = member.read(MAX_EVIDENCE_JSON_BYTES + 1)
            if len(raw_json) > MAX_EVIDENCE_JSON_BYTES:
                raise GitHubError(f"artifact {art_id} turbo-ci-evidence.json exceeds maximum size of {MAX_EVIDENCE_JSON_BYTES} bytes")
    manifest = json.loads(raw_json.decode("utf-8", "replace"))
    if not isinstance(manifest, dict):
        raise GitHubError(f"artifact {art_id} turbo-ci-evidence.json must be a JSON object")
    return manifest


def _fetch_run_evidence_artifacts(
    base_url: str, token: str, repo_slug: str, run_attempts_by_id: dict[int, int],
    trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    merged_checks: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    for run_id in sorted(run_attempts_by_id):
        expected_attempt = run_attempts_by_id[run_id]
        arts_all: list[dict[str, Any]] = []
        page = 1
        while True:
            url = f"{base_url}/repos/{repo_slug}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
            payload = github_request("GET", url, token, base_url, trace, deadline, limit_s)
            batch, total = payload.get("artifacts"), payload.get("total_count")
            if not isinstance(batch, list) or isinstance(total, bool) or not isinstance(total, int):
                issues.append(f"malformed artifacts response for workflow run {run_id}")
                break
            arts_all.extend(a for a in batch if isinstance(a, dict))
            if not batch or len(arts_all) >= total or page >= 20:
                break
            page += 1
        ev_arts = [a for a in arts_all if str(a.get("name") or "").startswith("turbo-ci-evidence")]
        if not ev_arts:
            issues.append(f"missing turbo-ci-evidence artifact on workflow run {run_id}")
            continue
        for art in ev_arts:
            art_id = art.get("id")
            if bool(art.get("expired")):
                issues.append(f"CI evidence artifact {art_id} on workflow run {run_id} is expired")
                continue
            dl_url = str(art.get("archive_download_url") or "").strip()
            if not dl_url:
                issues.append(f"CI evidence artifact {art_id} is missing archive_download_url")
                continue
            art_html = f"https://github.com/{repo_slug}/actions/runs/{run_id}/artifacts/{art_id}"
            try:
                raw_zip = _download_zip_bytes(dl_url, token, base_url, trace, deadline, limit_s)
                manifest = _read_manifest_from_zip(raw_zip, art_id)
            except (GitHubError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
                issues.append(f"failed to read CI evidence artifact {art_id}: {exc}")
                continue
            man_run_id = manifest.get("workflow_run_id")
            if man_run_id is not None and (isinstance(man_run_id, bool) or man_run_id != run_id):
                issues.append(f"artifact {art_id} workflow_run_id {man_run_id!r} does not match workflow run {run_id}")
                continue
            man_attempt = manifest.get("run_attempt")
            if man_attempt is not None and (isinstance(man_attempt, bool) or man_attempt != expected_attempt):
                issues.append(f"artifact {art_id} run_attempt {man_attempt!r} does not match workflow run {run_id} attempt {expected_attempt}")
                continue
            checks_map = manifest.get("checks")
            if not isinstance(checks_map, dict) or not checks_map:
                issues.append(f"artifact {art_id} has empty or invalid checks map")
                continue
            for cname, cdata in checks_map.items():
                if not isinstance(cdata, dict):
                    issues.append(f"artifact {art_id} entry for {cname!r} is not an object")
                    continue
                if str(cdata.get("check_name") or "").strip() != cname:
                    issues.append(f"artifact {art_id} check key {cname!r} does not match entry check_name {cdata.get('check_name')!r}")
                    continue
                rec_run_id = cdata.get("workflow_run_id", man_run_id)
                if rec_run_id is not None and (isinstance(rec_run_id, bool) or rec_run_id != run_id):
                    issues.append(f"artifact {art_id} check {cname!r} workflow_run_id {rec_run_id!r} != {run_id}")
                    continue
                rec_attempt = cdata.get("run_attempt", man_attempt)
                if rec_attempt is not None and (isinstance(rec_attempt, bool) or rec_attempt != expected_attempt):
                    issues.append(f"artifact {art_id} check {cname!r} run_attempt {rec_attempt!r} != expected attempt {expected_attempt}")
                    continue
                if expected_attempt > 1 and rec_attempt != expected_attempt:
                    issues.append(f"artifact {art_id} check {cname!r} is missing explicit run_attempt={expected_attempt} for rerun")
                    continue
                if cname in merged_checks:
                    issues.append(f"duplicate or ambiguous CI evidence artifact entry for required check {cname!r}")
                    continue
                merged_checks[cname] = {
                    **cdata, "artifact_id": art_id, "artifact_url": art_html, "run_id": run_id,
                    "run_attempt": rec_attempt if isinstance(rec_attempt, int) else expected_attempt,
                }
    return merged_checks, issues
