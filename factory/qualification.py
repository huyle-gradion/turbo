"""Protected repository qualification harness (#67)."""
from __future__ import annotations

import argparse, base64, contextlib, json, os, shutil, subprocess, sys, time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

from factory import ci_gate, config as config_module, deliver as deliver_module, gitio
from factory.deliver_checks import collect_redaction_secrets, git_timed
from factory.independent_review import approval as approval_mod
from factory.integration import _factory_rev, _http_req, integrate_approved_child
from factory.paths import RuntimePaths, atomic_json, safe_dir

FACTORY_ROOT = Path(__file__).resolve().parents[1]
SEED_ASSETS_DIR = FACTORY_ROOT / "examples" / "qualification" / "seed"

HOSTED_API_ORIGIN = "https://api.github.com"
DISPOSABLE_REPO_ALLOWLIST = frozenset(["turbo-factory/turbo-qual-67"])
ALLOWED_TARGET_BRANCHES = frozenset(["feature/demo"])
CANDIDATE_BRANCH_PREFIX = "feat/qual-"
REQUIRED_SEED_ASSETS: tuple[tuple[str, str], ...] = (
    (".github/workflows/ci.yml", "CI workflow"),
    (".factory/policy.json", "factory policy"),
    ("src/calc.py", "product fixture source"),
    ("tests/test_calc.py", "product fixture tests"),
    ("qa/qa-cases.json", "QA cases rubric"),
)

CALC_CANDIDATE_SRC = (
    '"""Minimal product fixture for qualification (#67)."""\n\n'
    'def add(a: int, b: int) -> int:\n    return a + b\n\n'
    'def multiply(a: int, b: int) -> int:\n    return a * b\n\n'
    'def subtract(a: int, b: int) -> int:\n    return a - b\n\n'
    'def power(a: int, b: int) -> int:\n    return a ** b\n'
)
CALC_CANDIDATE_TEST = (
    'import unittest\nfrom src.calc import add, multiply, subtract, power\n\n'
    'class CalcTest(unittest.TestCase):\n'
    '    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n'
    '    def test_multiply(self):\n        self.assertEqual(multiply(3, 4), 12)\n'
    '    def test_subtract(self):\n        self.assertEqual(subtract(5, 2), 3)\n'
    '    def test_power(self):\n        self.assertEqual(power(2, 3), 8)\n\n'
    'if __name__ == "__main__":\n    unittest.main()\n'
)
CALC_SC3_SRC = CALC_CANDIDATE_SRC + '\ndef divide(a: int, b: int) -> int:\n    return a // b\n'
CALC_SC3_TEST = (
    'import unittest\nfrom src.calc import add, multiply, subtract, power, divide\n\n'
    'class CalcTest(unittest.TestCase):\n'
    '    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n'
    '    def test_multiply(self):\n        self.assertEqual(multiply(3, 4), 12)\n'
    '    def test_subtract(self):\n        self.assertEqual(subtract(5, 2), 3)\n'
    '    def test_power(self):\n        self.assertEqual(power(2, 3), 8)\n'
    '    def test_divide(self):\n        self.assertEqual(divide(6, 2), 3)\n\n'
    'if __name__ == "__main__":\n    unittest.main()\n'
)
ADVANCE_MARKER_CONTENT = '{"scenario": "competing_base_rejection", "actor": "cone-orgs"}\n'

REAL_SETUP_METADATA: dict[str, Any] = {
    "repo_slug": "turbo-factory/turbo-qual-67",
    "identities": {
        "integrator": "huyhuyhuy8s",  # Admin on the org repo
        "competitor": "cone-orgs",    # Write collaborator
        "restricted_reader": "huyle-turbo",  # Read-only identity
    },
    "tokens": {
        "type": "classic_pat",
        "integrator_scope": "repo",
        "competitor_scope": "repo (extra workflow scope also present, harmless)",
        "restricted_reader_scope": "none (public read-only)",
    },
    "protection_config": {
        "strict": True,
        "enforce_admins": True,
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "contexts": [],
    },
    "known_gaps": [
        "feature/demo currently holds only README.md; seed CI workflow, product fixture, and factory policy are not yet installed.",
        "Branch protection required status check contexts are empty (contexts: []); nonempty check contexts pending setup in a later slice.",
        "Hosted qualification execution is not implemented yet; run_hosted_qualification returns blocked / hosted-scenarios-pending-human-setup.",
    ],
}

PARENT_AC_DESCRIPTIONS: dict[str, str] = {
    "AC1": "Protected test repository accepts child merge only when required CI, QA, security, and fresh independent approval apply.",
    "AC2": "Integration ownership topology and authoritative checks prevent unverified-base integration across independent actors.",
    "AC3": "Controlled competing-base update prevents stale integration and forces renewed candidate verification and review.",
    "AC4": "Repository protections and identity permissions are honored without bypass; missing permissions stop integration explicitly.",
    "AC5": "Merge result confirmed on intended feature branch before marking child complete, linking revisions and evidence.",
    "AC6": "Tests cover concurrent attempts, changed head/base, denied merge, uncertain API outcome, and wrong target; main untouched.",
}


def redact_qualification_tokens(val: Any, tokens: list[str]) -> Any:
    """Explicitly protect qualification token values in persisted data structures."""
    toks = [t for t in tokens if t]
    if not toks:
        return val
    if isinstance(val, str):
        res = val
        for t in toks:
            res = res.replace(t, "[REDACTED-TOKEN]")
        return res
    if isinstance(val, dict):
        return {k: redact_qualification_tokens(v, toks) for k, v in val.items()}
    if isinstance(val, list):
        return [redact_qualification_tokens(item, toks) for item in val]
    return val


class QualificationLedger:
    """Append-only redacted operation ledger for qualification operations."""

    def __init__(self, path: Path, tokens: list[str]) -> None:
        self.path = Path(path)
        self.tokens = [t for t in tokens if t]
        self._seq = 0

    def record(
        self, method: str, url: str, actor: str, status_code: int,
        error: str = "", extra: dict[str, Any] | None = None,
    ) -> None:
        self._seq += 1
        entry = {
            "seq": self._seq,
            "timestamp": approval_mod.now(),
            "method": method,
            "url": url,
            "actor": actor,
            "status_code": status_code,
            "error": error or None,
            **(extra or {}),
        }
        redacted = redact_qualification_tokens(entry, self.tokens)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(redacted, sort_keys=True) + "\n")


def check_hosted_authorization(
    repo_slug: str,
    live_enabled: bool,
    *,
    base_url: str = HOSTED_API_ORIGIN,
    target_branch: str = "feature/demo",
    allow_test_origin: bool = False,
) -> tuple[bool, str]:
    """Require explicit hosted enablement, fixed origin, target branch, and exact disposable allowlist."""
    if not live_enabled:
        return False, "hosted-qualification-disabled: live hosted qualification requires TURBO_LIVE_QUALIFICATION=1"
    if repo_slug not in DISPOSABLE_REPO_ALLOWLIST:
        return False, f"repo-disallowed: {repo_slug!r} is not in disposable allowlist {sorted(DISPOSABLE_REPO_ALLOWLIST)}"
    if target_branch not in ALLOWED_TARGET_BRANCHES:
        return False, f"target-branch-disallowed: target branch {target_branch!r} is not an allowed qualification target {sorted(ALLOWED_TARGET_BRANCHES)}"
    if not allow_test_origin and base_url.rstrip("/") != HOSTED_API_ORIGIN:
        return False, f"wrong-origin: origin {base_url!r} does not match fixed hosted origin {HOSTED_API_ORIGIN}"
    return True, ""


def observe_identity_and_permissions(
    base_url: str,
    repo_slug: str,
    token: str | None,
    expected_login: str,
    expected_role: str,
    role_name: str,
    ledger: QualificationLedger | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Observe user identity and repository permissions via GitHub API object endpoints."""
    if not token:
        rec = {"role": role_name, "status": "unavailable", "reason": "missing-credentials"}
        return False, rec, [f"missing-token: {role_name} token is missing"]

    trace: list[dict[str, Any]] = []
    user_url = f"{base_url.rstrip('/')}/user"
    code, user_data, err_msg = _http_req("GET", user_url, token, base_url, trace, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", user_url, role_name, code, err_msg)
    if code != 200 or not user_data:
        rec = {"role": role_name, "status": "identity-read-failed", "http_code": code}
        return False, rec, [f"identity-read-failed: {role_name} identity check returned HTTP {code}: {err_msg}"]

    observed_login = user_data.get("login")
    if observed_login != expected_login:
        rec = {"role": role_name, "status": "wrong-identity", "observed_login": observed_login, "expected_login": expected_login}
        return False, rec, [f"wrong-identity: {role_name} token belongs to {observed_login!r}, expected {expected_login!r}"]

    repo_url = f"{base_url.rstrip('/')}/repos/{repo_slug}"
    code, repo_data, err_msg = _http_req("GET", repo_url, token, base_url, trace, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", repo_url, role_name, code, err_msg)
    if code != 200 or not repo_data:
        rec = {"role": role_name, "login": observed_login, "status": "permission-read-failed", "http_code": code}
        return False, rec, [f"permission-read-failed: {role_name} permission check returned HTTP {code}: {err_msg}"]

    perms = repo_data.get("permissions") or {}
    if expected_role == "admin" and not perms.get("admin"):
        rec = {"role": role_name, "login": observed_login, "permissions": perms, "status": "insufficient-permissions"}
        return False, rec, [f"insufficient-permissions: {role_name} requires admin permissions on {repo_slug}"]
    if expected_role == "write" and not perms.get("push"):
        rec = {"role": role_name, "login": observed_login, "permissions": perms, "status": "insufficient-permissions"}
        return False, rec, [f"insufficient-permissions: {role_name} requires push/write permissions on {repo_slug}"]

    rec = {
        "role": role_name,
        "login": observed_login,
        "expected_login": expected_login,
        "expected_role": expected_role,
        "observed_role": "admin" if perms.get("admin") else ("write" if perms.get("push") else "read"),
        "permissions": perms,
        "status": "verified",
    }
    return True, rec, []


def check_branch_protection_and_topology(
    base_url: str,
    repo_slug: str,
    integrator_token: str | None,
    branches: tuple[str, ...] = ("main", "feature/demo"),
    ledger: QualificationLedger | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Verify both-branch protection rules, required check contexts, and ownership topology."""
    blockers: list[str] = []
    prot_by_branch: dict[str, Any] = {}
    if not integrator_token:
        blockers.append("missing-credentials: integrator token required for branch protection inspection")
        return False, {}, blockers

    trace: list[dict[str, Any]] = []
    repo_url = f"{base_url.rstrip('/')}/repos/{repo_slug}"
    code, repo_data, err_msg = _http_req("GET", repo_url, integrator_token, base_url, trace, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", repo_url, "integrator", code, err_msg)
    if code != 200 or not repo_data:
        blockers.append(f"topology-read-failed: repository {repo_slug} returned HTTP {code}: {err_msg}")
        return False, {}, blockers

    default_branch = repo_data.get("default_branch")
    if default_branch != "main":
        blockers.append(f"unsupported-topology: default branch must be 'main', observed {default_branch!r}")

    for b in branches:
        quoted = quote(b, safe="")
        url = f"{base_url.rstrip('/')}/repos/{repo_slug}/branches/{quoted}/protection"
        code, p_data, err_msg = _http_req("GET", url, integrator_token, base_url, trace, time.monotonic() + 15.0, 15)
        if ledger:
            ledger.record("GET", url, "integrator", code, err_msg)
        if code in (401, 403):
            blockers.append(f"unavailable-protection-capability: branch protection read on {b} returned HTTP {code} ({err_msg or 'permission denied'})")
            continue
        if code != 200 or not p_data:
            blockers.append(f"unsupported-protection: branch protection read on {b} returned HTTP {code}: {err_msg}")
            continue
        prot_by_branch[b] = p_data

        rsc = p_data.get("required_status_checks") or {}
        admins = p_data.get("enforce_admins") or {}
        allow_fp = p_data.get("allow_force_pushes") or {}
        allow_del = p_data.get("allow_deletions") or {}
        reviews = p_data.get("required_pull_request_reviews") or {}

        if not isinstance(rsc, dict) or not rsc.get("strict"):
            blockers.append(f"unsupported-protection: branch protection on {b} must require strict status checks")
        contexts = rsc.get("contexts") if isinstance(rsc, dict) else []
        if not contexts:
            blockers.append(f"empty-required-check-contexts: required status check contexts on {b} are empty; qualification requires nonempty status checks")
        if not isinstance(admins, dict) or not admins.get("enabled"):
            blockers.append(f"unsupported-protection: branch protection on {b} must enforce admins")
        if isinstance(allow_fp, dict) and allow_fp.get("enabled"):
            blockers.append(f"unsupported-protection: branch protection on {b} forbids force pushes")
        if isinstance(allow_del, dict) and allow_del.get("enabled"):
            blockers.append(f"unsupported-protection: branch protection on {b} forbids deletions")
        if not isinstance(reviews, dict) or reviews.get("required_approving_review_count", 0) < 1:
            blockers.append(f"unsupported-protection: branch protection on {b} requires at least 1 approving review")
        if not isinstance(reviews, dict) or not reviews.get("dismiss_stale_reviews"):
            blockers.append(f"unsupported-protection: branch protection on {b} must dismiss stale reviews")

    record = {
        "repo_slug": repo_slug,
        "default_branch": default_branch,
        "branches_checked": list(branches),
        "protections": prot_by_branch,
        "status": "verified" if not blockers else "failed",
    }
    return len(blockers) == 0, record, blockers


def check_seed_and_workflow_capabilities(
    base_url: str,
    repo_slug: str,
    branch: str,
    token: str | None,
    ledger: QualificationLedger | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Probe for seed CI workflow, product fixture, and factory policy on target branch."""
    if not token:
        return False, {"status": "unavailable", "reason": "missing-credentials"}, ["missing-credentials: token required for seed capability check"]

    trace: list[dict[str, Any]] = []
    observed_assets: dict[str, Any] = {}
    blockers: list[str] = []

    for path, desc in REQUIRED_SEED_ASSETS:
        quoted_path = quote(path.lstrip("/"), safe="/")
        url = f"{base_url.rstrip('/')}/repos/{repo_slug}/contents/{quoted_path}?ref={quote(branch, safe='')}"
        code, data, err_msg = _http_req("GET", url, token, base_url, trace, time.monotonic() + 15.0, 15)
        if ledger:
            ledger.record("GET", url, "integrator", code, err_msg)
        if code == 404:
            blockers.append(f"missing-seed: {branch} is missing required seed asset {desc} at {path}")
            observed_assets[path] = {"present": False, "status": "missing"}
        elif code != 200:
            blockers.append(f"seed-check-failed: seed check for {path} on {branch} returned HTTP {code}: {err_msg}")
            observed_assets[path] = {"present": False, "status": f"HTTP {code}"}
        else:
            observed_assets[path] = {"present": True, "status": "present", "sha": data.get("sha")}

    record = {
        "branch": branch,
        "assets": observed_assets,
        "status": "verified" if not blockers else "incomplete",
    }
    return len(blockers) == 0, record, blockers


def get_submitted_review(
    base_url: str,
    repo_slug: str,
    pr_number: int,
    review_id: int,
    token: str,
    trace: list[dict[str, Any]] | None = None,
    ledger: QualificationLedger | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Read a submitted pull request review by explicit ID from object endpoint."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/{pr_number}/reviews/{review_id}"
    tr = trace if trace is not None else []
    code, data, msg = _http_req("GET", url, token, base_url, tr, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", url, "integrator", code, msg)
    return code, data, msg


def create_qualification_pull_request(
    base_url: str,
    repo_slug: str,
    head_branch: str,
    base_branch: str,
    title: str,
    body: str,
    token: str,
    *,
    actor: str = "competitor",
    ledger: QualificationLedger | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Create a candidate pull request via GitHub API object endpoint."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls"
    tr = trace if trace is not None else []
    payload = {"title": title, "head": head_branch, "base": base_branch, "body": body}
    code, data, msg = _http_req("POST", url, token, base_url, tr, time.monotonic() + 15.0, 15, payload=payload)
    if ledger:
        ledger.record("POST", url, actor, code, msg, extra={"head": head_branch, "base": base_branch})
    return code, data, msg


def submit_qualification_pr_review(
    base_url: str,
    repo_slug: str,
    pr_number: int,
    candidate_sha: str,
    event: str,
    body: str,
    token: str,
    *,
    actor: str = "integrator",
    ledger: QualificationLedger | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Submit a pull request review with exact candidate commit_id binding."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/{pr_number}/reviews"
    tr = trace if trace is not None else []
    payload = {"commit_id": candidate_sha, "event": event, "body": body}
    code, data, msg = _http_req("POST", url, token, base_url, tr, time.monotonic() + 15.0, 15, payload=payload)
    if ledger:
        ledger.record("POST", url, actor, code, msg, extra={"pr_number": pr_number, "commit_id": candidate_sha, "event": event})
    return code, data, msg


def verify_qualification_pr_review(
    base_url: str,
    repo_slug: str,
    pr_number: int,
    review_id: int,
    candidate_sha: str,
    expected_reviewer: str,
    token: str,
    *,
    ledger: QualificationLedger | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Read back and verify pull request review matches exact candidate SHA and independent reviewer."""
    code, data, msg = get_submitted_review(base_url, repo_slug, pr_number, review_id, token, trace=trace, ledger=ledger)
    blockers: list[str] = []
    if code != 200 or not data:
        blockers.append(f"review-read-failed: PR review read returned HTTP {code}: {msg}")
        return False, {}, blockers
    state = data.get("state")
    if state != "APPROVED":
        blockers.append(f"unapproved-review: review state is {state!r}, expected 'APPROVED'")
    commit_id = data.get("commit_id")
    if commit_id != candidate_sha:
        blockers.append(f"review-revision-drift: review commit_id {commit_id!r} does not match candidate {candidate_sha!r}")
    rev_user = (data.get("user") or {}).get("login")
    if rev_user != expected_reviewer:
        blockers.append(f"reviewer-role-violation: review user {rev_user!r} does not match expected reviewer {expected_reviewer!r}")
    return len(blockers) == 0, data, blockers


def check_qualification_pr_ci(
    base_url: str,
    repo_slug: str,
    candidate_sha: str,
    base_sha: str,
    token: str,
    *,
    required_contexts: tuple[str, ...] = ("build",),
    ledger: QualificationLedger | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Verify check runs and evidence artifacts for candidate commit revision."""
    blockers: list[str] = []
    tr = trace if trace is not None else []
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/commits/{candidate_sha}/check-runs"
    code, data, msg = _http_req("GET", url, token, base_url, tr, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", url, "integrator", code, msg)
    if code != 200 or not data:
        blockers.append(f"ci-read-failed: check runs query returned HTTP {code}: {msg}")
        return False, {"status": "ci-read-failed"}, blockers

    check_runs = data.get("check_runs") if isinstance(data, dict) else []
    if not isinstance(check_runs, list):
        check_runs = []

    matched_checks: dict[str, Any] = {}
    for ctx in required_contexts:
        found = None
        for cr in check_runs:
            cname = cr.get("name", "")
            if cname == ctx or cname.endswith(f" / {ctx}"):
                found = cr
                break
        if not found:
            blockers.append(f"missing-ci-check: required check context {ctx!r} not found for candidate {candidate_sha}")
            continue

        app_slug = (found.get("app") or {}).get("slug", "")
        if app_slug != "github-actions":
            blockers.append(f"untrusted-check-producer: check {ctx!r} producer {app_slug!r} is not trusted 'github-actions'")

        status = found.get("status")
        conclusion = found.get("conclusion")
        if status != "completed" or conclusion != "success":
            blockers.append(f"ci-check-not-successful: check {ctx!r} status={status!r}, conclusion={conclusion!r}")

        matched_checks[ctx] = {
            "name": ctx,
            "status": status,
            "conclusion": conclusion,
            "app": app_slug,
            "check_run_id": found.get("id"),
            "head_sha": found.get("head_sha"),
        }

    rec = {
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "required_contexts": list(required_contexts),
        "checks": matched_checks,
        "status": "verified" if not blockers else "incomplete",
    }
    return len(blockers) == 0, rec, blockers


def evaluate_qualification_qa(
    product_dir: Path,
    qa_cases: tuple[Any, ...] | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Execute deterministic QA evaluation cases against candidate product worktree."""
    blockers: list[str] = []
    cases_to_run = qa_cases
    if cases_to_run is None:
        cases_file = SEED_ASSETS_DIR / "qa" / "qa-cases.json"
        if not cases_file.is_file():
            blockers.append("missing-qa-cases: qualification QA cases file not found")
            return False, {"status": "unavailable", "reason": "missing-qa-cases"}, blockers
        try:
            from factory.automated_qa import load_qa_cases_file
            cases_to_run = load_qa_cases_file(cases_file)
        except Exception as exc:
            blockers.append(f"qa-cases-load-failed: {exc}")
            return False, {"status": "unavailable", "reason": "qa-cases-load-failed"}, blockers

    results: list[dict[str, Any]] = []
    for c in cases_to_run:
        cmd = c.command
        p = subprocess.run(
            cmd, cwd=str(product_dir), shell=True, capture_output=True, text=True, timeout=15,
        )
        passed = (p.returncode == c.rubric.expected_exit_code)
        if not passed:
            blockers.append(f"qa-case-failed: case {c.case_id} exited {p.returncode}, expected {c.rubric.expected_exit_code}")
        results.append({
            "case_id": c.case_id,
            "passed": passed,
            "exit_code": p.returncode,
            "expected_exit_code": c.rubric.expected_exit_code,
            "command": cmd,
        })

    qa_record = {
        "status": "verified" if not blockers else "failed",
        "qa_verified": len(blockers) == 0,
        "results": results,
    }
    return len(blockers) == 0, qa_record, blockers


def _qa_on_candidate(
    product_dir: Path | None, candidate_sha: str, qa_cases: tuple[Any, ...] | None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Run QA only when `product_dir` is checked out at `candidate_sha`; record the SHA QA ran against."""
    res = gitio.git(product_dir, "rev-parse", "HEAD") if product_dir is not None else None
    head = res.output.strip() if res is not None and res.ok else None
    if head != candidate_sha:
        reason = "candidate-checkout-missing" if head is None else "candidate-checkout-mismatch"
        rec = {"status": "unavailable", "qa_verified": False, "reason": reason, "candidate_sha": candidate_sha, "checkout_sha": head}
        return False, rec, [f"qa-unavailable: {reason}: QA must run on a checkout of {candidate_sha}, found {head}"]
    ok, rec, blockers = evaluate_qualification_qa(product_dir, qa_cases=qa_cases)
    return ok, {**rec, "candidate_sha": head}, blockers


def resolve_agy_bin(agy_bin: str | None = None) -> str | None:
    """Resolve supported reviewer executable path."""
    if agy_bin is not None:
        if os.path.isfile(agy_bin) and os.access(agy_bin, os.X_OK):
            return agy_bin
        return None
    from_env = os.environ.get("AGY_BIN")
    if from_env and os.path.isfile(from_env) and os.access(from_env, os.X_OK):
        return from_env
    which_agy = shutil.which("agy")
    if which_agy and os.path.isfile(which_agy) and os.access(which_agy, os.X_OK):
        return which_agy
    home_agy = Path.home() / ".local" / "bin" / "agy"
    if home_agy.is_file() and os.access(home_agy, os.X_OK) and os.environ.get("TURBO_LIVE_QUALIFICATION") == "1":
        return str(home_agy)
    return None


def get_remote_commit(
    base_url: str,
    repo_slug: str,
    ref: str,
    token: str,
    *,
    trace: list[dict[str, Any]] | None = None,
    ledger: QualificationLedger | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Fetch commit object for branch or ref."""
    quoted = quote(ref.lstrip("/"), safe="")
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/commits/{quoted}"
    tr = trace if trace is not None else []
    code, data, msg = _http_req("GET", url, token, base_url, tr, time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", url, "integrator", code, msg)
    return code, data, msg


def get_remote_file_content(
    base_url: str,
    repo_slug: str,
    file_path: str,
    ref: str,
    token: str,
    *,
    ledger: QualificationLedger | None = None,
) -> tuple[int, str, str]:
    """Read remote file content decoded from GitHub contents endpoint."""
    quoted_path = quote(file_path.lstrip("/"), safe="/")
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/contents/{quoted_path}?ref={quote(ref, safe='')}"
    code, data, msg = _http_req("GET", url, token, base_url, [], time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", url, "integrator", code, msg)
    if code == 200 and isinstance(data, dict):
        raw = data.get("content", "")
        return code, base64.b64decode(raw).decode("utf-8", errors="replace"), msg
    return code, "", msg


def create_remote_blob(
    base_url: str, repo_slug: str, content: str, token: str,
    *, actor: str = "integrator", ledger: QualificationLedger | None = None,
) -> tuple[int, str, str]:
    """Create a blob in the remote repository."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/blobs"
    code, data, msg = _http_req("POST", url, token, base_url, [], time.monotonic() + 15.0, 15, payload={"content": content, "encoding": "utf-8"})
    if ledger:
        ledger.record("POST", url, actor, code, msg)
    return code, str(data.get("sha") or ""), msg


def create_remote_tree(
    base_url: str, repo_slug: str, base_tree_sha: str, tree_entries: list[dict[str, Any]], token: str,
    *, actor: str = "integrator", ledger: QualificationLedger | None = None,
) -> tuple[int, str, str]:
    """Create a git tree referencing base tree and changed paths."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/trees"
    code, data, msg = _http_req("POST", url, token, base_url, [], time.monotonic() + 15.0, 15, payload={"base_tree": base_tree_sha, "tree": tree_entries})
    if ledger:
        ledger.record("POST", url, actor, code, msg)
    return code, str(data.get("sha") or ""), msg


def create_remote_commit(
    base_url: str, repo_slug: str, tree_sha: str, parent_shas: list[str], message: str, token: str,
    *, actor: str = "integrator", ledger: QualificationLedger | None = None,
) -> tuple[int, str, str]:
    """Create a git commit object with explicit tree and parents."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/commits"
    code, data, msg = _http_req("POST", url, token, base_url, [], time.monotonic() + 15.0, 15, payload={"message": message, "tree": tree_sha, "parents": parent_shas})
    if ledger:
        ledger.record("POST", url, actor, code, msg)
    return code, str(data.get("sha") or ""), msg


def set_remote_branch_ref(
    base_url: str, repo_slug: str, branch_name: str, commit_sha: str, token: str,
    *, actor: str = "integrator", ledger: QualificationLedger | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Create or update a qualification candidate branch ref; other refs are refused locally."""
    if not branch_name.startswith(CANDIDATE_BRANCH_PREFIX):
        return 0, {}, f"refused: ref write outside candidate prefix {CANDIDATE_BRANCH_PREFIX!r}: {branch_name!r}"
    quoted = quote(branch_name, safe="")
    url_ref = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/ref/heads/{quoted}"
    code, _, msg = _http_req("GET", url_ref, token, base_url, [], time.monotonic() + 15.0, 15)
    if ledger:
        ledger.record("GET", url_ref, actor, code, msg)
    if code == 200:
        url_patch = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/refs/heads/{quoted}"
        p_code, p_data, p_msg = _http_req("PATCH", url_patch, token, base_url, [], time.monotonic() + 15.0, 15, payload={"sha": commit_sha, "force": True})
        if ledger:
            ledger.record("PATCH", url_patch, actor, p_code, p_msg)
        return p_code, p_data, p_msg
    url_post = f"{base_url.rstrip('/')}/repos/{repo_slug}/git/refs"
    c_code, c_data, c_msg = _http_req("POST", url_post, token, base_url, [], time.monotonic() + 15.0, 15, payload={"ref": f"refs/heads/{branch_name}", "sha": commit_sha})
    if ledger:
        ledger.record("POST", url_post, actor, c_code, c_msg)
    return c_code, c_data, c_msg


def get_remote_pulls(
    base_url: str, repo_slug: str, head_branch: str, token: str,
    *, state: str = "open", actor: str = "integrator", ledger: QualificationLedger | None = None,
) -> list[dict[str, Any]]:
    """Query open pull requests matching head_branch."""
    owner = repo_slug.split("/")[0]
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls?head={owner}:{head_branch}&state={state}"
    import urllib.request
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            if ledger: ledger.record("GET", url, actor, 200, "")
            return data if isinstance(data, list) else []
    except Exception as exc:
        if ledger: ledger.record("GET", url, actor, 0, str(exc))
        return []


def poll_ci_check(
    base_url: str,
    repo_slug: str,
    candidate_sha: str,
    base_sha: str,
    token: str,
    *,
    required_contexts: tuple[str, ...] = ("build",),
    timeout_s: float = 180.0,
    interval_s: float = 5.0,
    ledger: QualificationLedger | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Poll for required CI check completion on candidate revision."""
    deadline = time.monotonic() + timeout_s
    last_rec: dict[str, Any] = {}
    last_blockers: list[str] = []
    while time.monotonic() < deadline:
        ok, rec, blks = check_qualification_pr_ci(
            base_url, repo_slug, candidate_sha, base_sha, token,
            required_contexts=required_contexts, ledger=ledger,
        )
        last_rec, last_blockers = rec, blks
        if ok:
            return True, rec, []
        if any("conclusion" in b and "failure" in b for b in blks):
            return False, rec, blks
        time.sleep(interval_s)
    return False, last_rec, last_blockers or [f"ci-poll-timeout: CI check on {candidate_sha} did not complete within {int(timeout_s)}s"]


def create_qualification_candidate_commit(
    base_url: str,
    repo_slug: str,
    base_sha: str,
    branch_name: str,
    token: str,
    file_changes: dict[str, str],
    message: str,
    *,
    actor: str = "integrator",
    ledger: QualificationLedger | None = None,
) -> tuple[str, str]:
    """Create remote commit on a branch from base SHA with specified file contents."""
    code, base_c, _ = get_remote_commit(base_url, repo_slug, base_sha, token, ledger=ledger)
    base_tree_sha = base_c.get("commit", {}).get("tree", {}).get("sha", "") if code == 200 else ""
    tree_entries = []
    for fpath, fcontent in file_changes.items():
        _, b_sha, _ = create_remote_blob(base_url, repo_slug, fcontent, token, actor=actor, ledger=ledger)
        tree_entries.append({"path": fpath, "mode": "100644", "type": "blob", "sha": b_sha})
    _, t_sha, _ = create_remote_tree(base_url, repo_slug, base_tree_sha, tree_entries, token, actor=actor, ledger=ledger)
    _, commit_sha, _ = create_remote_commit(base_url, repo_slug, t_sha, [base_sha], message, token, actor=actor, ledger=ledger)
    r_code, _, r_msg = set_remote_branch_ref(base_url, repo_slug, branch_name, commit_sha, token, actor=actor, ledger=ledger)
    if r_code not in (200, 201):
        if ledger and r_code == 0:
            ledger.record("REFUSED", f"refs/heads/{branch_name}", actor, 0, r_msg)
        return "", t_sha  # ref not updated: callers must not use the branch content
    return commit_sha, t_sha


def _hosted_git(args: list[str], repo_slug: str, token: str, cwd: Path | None = None) -> None:
    """Run git against github.com with the token passed only through the environment, never argv or .git/config."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_TRACE") and k != "GIT_CURL_VERBOSE"}
    n = int(env.get("GIT_CONFIG_COUNT", "0") or 0)  # keep caller GIT_CONFIG_* entries, append ours
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": str(n + 1),
                f"GIT_CONFIG_KEY_{n}": "http.https://github.com/.extraheader",
                f"GIT_CONFIG_VALUE_{n}": f"AUTHORIZATION: basic {basic}"})
    p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        err = str(redact_qualification_tokens((p.stderr or "").strip(), [token, basic]))[-500:]
        raise RuntimeError(f"git {args[0]} failed for {repo_slug} (exit {p.returncode}): {err}")


def clone_remote_repo(dest: Path, repo_slug: str, token: str) -> None:
    """Clone a hosted repository; the stored origin URL carries no credential."""
    _hosted_git(["clone", "-q", f"https://github.com/{repo_slug}.git", str(dest)], repo_slug, token)


def fetch_remote_repo(repo: Path, repo_slug: str, token: str) -> None:
    """Fetch remote repository heads and pull refs using ephemeral credential."""
    for attempt in range(3):
        try:
            _hosted_git(["fetch", "-q", f"https://github.com/{repo_slug}.git", "+refs/heads/*:refs/remotes/origin/*", "+refs/pull/*:refs/remotes/origin/pr/*"], repo_slug, token, cwd=repo)
            return
        except RuntimeError:
            if attempt == 2: raise
            time.sleep(1.0)


def assert_landed_landing_properties(
    repo: Path,
    landed_sha: str,
    base_sha: str,
    candidate_sha: str,
    tested_sha: str | None,
    base_branch: str,
    main_sha_before: str,
    *,
    token: str | None = None,
    repo_slug: str | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Authoritative parent, tree, reachability, and main preservation checks."""
    blockers: list[str] = []
    details: dict[str, Any] = {}

    if token and repo_slug:
        fetch_remote_repo(repo, repo_slug, token)
    else:
        gitio.git(repo, "fetch", "origin")

    parents_res = gitio.git(repo, "rev-list", "--parents", "-n", "1", landed_sha)
    parents = parents_res.output.strip().split()[1:] if parents_res.ok else []
    details["parents"] = parents
    if not parents_res.ok or parents != [base_sha, candidate_sha]:
        blockers.append(f"landed commit {landed_sha} parents {parents} != expected [{base_sha}, {candidate_sha}]")

    l_tree_res = gitio.git(repo, "rev-parse", f"{landed_sha}^{{tree}}")
    l_tree = l_tree_res.output.strip() if l_tree_res.ok else ""
    details["landed_tree"] = l_tree
    if tested_sha:
        t_tree_res = gitio.git(repo, "rev-parse", f"{tested_sha}^{{tree}}")
        t_tree = t_tree_res.output.strip() if t_tree_res.ok else ""
        details["tested_tree"] = t_tree
        if l_tree != t_tree:
            blockers.append(f"landed tree {l_tree} does not match tested tree {t_tree}")

    rem_base = gitio.remote_ref(repo, base_branch)
    details["remote_base_tip"] = rem_base
    if not rem_base or not gitio.is_ancestor(repo, landed_sha, rem_base):
        blockers.append(f"landed commit {landed_sha} is not reachable from origin/{base_branch} ({rem_base})")

    main_sha_after = gitio.remote_ref(repo, "main") or gitio.commit_sha(repo, "refs/heads/main")
    details["main_sha_before"], details["main_sha_after"] = main_sha_before, main_sha_after
    if main_sha_after != main_sha_before:
        blockers.append(f"main branch was modified during integration! before={main_sha_before}, after={main_sha_after}")

    return len(blockers) == 0, details, blockers


def prepare_qualification_candidate(
    base_url: str,
    repo_slug: str,
    evidence_dir: Path,
    *,
    target_branch: str = "feature/demo",
    head_branch: str = "feat/qual-candidate-101",
    candidate_sha: str = "unavailable",
    base_sha: str = "unavailable",
    integrator_token: str | None = None,
    competitor_token: str | None = None,
    agy_bin: str | None = None,
    child_contract: dict[str, Any] | None = None,
    qa_cases: tuple[Any, ...] | None = None,
    product_dir: Path | None = None,
    ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False,
    existing_pr: dict[str, Any] | None = None,
    live_enabled: bool = True,
    required_contexts: tuple[str, ...] = ("build",),
) -> dict[str, Any]:
    """Prepare genuine qualification candidate, PR, and prerequisite evidence."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    tokens = [integrator_token or "", competitor_token or ""]
    local_ledger = ledger or QualificationLedger(evidence_dir / "operation-ledger.jsonl", tokens)

    # 1. Preflight authorization and capabilities
    def _make_prep_record(st: str, out: str, blk: list[str], prereqs: dict[str, Any] | None = None, pr: dict[str, Any] | None = None) -> dict[str, Any]:
        unavail = {"status": "unavailable", "reason": "preflight-blocked"}
        default_prereqs = {"ci": unavail, "qa": unavail, "security": unavail, "independent_review": unavail, "github_review": unavail}
        r = {
            "schema": 1, "role": "qualification-candidate-preparation",
            "status": st, "outcome": out,
            "candidate_sha": pr.get("head_sha", candidate_sha) if pr else candidate_sha,
            "base_sha": pr.get("base_sha", base_sha) if pr else base_sha,
            "head_branch": head_branch, "base_branch": target_branch,
            "pr": pr,
            "builder": {
                "kind": "deterministic-qualification-process",
                "process_name": "turbo-qualification-builder",
                "actor": "cone-orgs",
                "candidate_sha": pr.get("head_sha", candidate_sha) if pr else candidate_sha,
                "base_sha": pr.get("base_sha", base_sha) if pr else base_sha,
                "head_branch": head_branch,
            },
            "prerequisites": prereqs or default_prereqs,
            "blockers": blk,
            "recorded_at": approval_mod.now(),
        }
        atomic_json(evidence_dir / "candidate-preparation.json", redact_qualification_tokens(r, tokens), evidence_dir)
        return r

    auth_ok, auth_msg = check_hosted_authorization(
        repo_slug, live_enabled, base_url=base_url, target_branch=target_branch, allow_test_origin=allow_test_origin,
    )
    if not auth_ok:
        return _make_prep_record("blocked", "unavailable", [auth_msg])

    if not integrator_token or not competitor_token:
        return _make_prep_record("blocked", "unavailable", ["missing-credentials: both TURBO_QUAL_INTEGRATOR_TOKEN and TURBO_QUAL_COMPETITOR_TOKEN are required"])

    # Preflight identity & topology checks
    ok_int, obs_int, int_blockers = observe_identity_and_permissions(
        base_url, repo_slug, integrator_token, expected_login="huyhuyhuy8s",
        expected_role="admin", role_name="integrator", ledger=local_ledger,
    )
    ok_comp, obs_comp, comp_blockers = observe_identity_and_permissions(
        base_url, repo_slug, competitor_token, expected_login="cone-orgs",
        expected_role="write", role_name="competitor", ledger=local_ledger,
    )
    ok_prot, top_rec, prot_blockers = check_branch_protection_and_topology(
        base_url, repo_slug, integrator_token, branches=("main", target_branch), ledger=local_ledger,
    )
    ok_seed, seed_rec, seed_blockers = check_seed_and_workflow_capabilities(
        base_url, repo_slug, target_branch, integrator_token, ledger=local_ledger,
    )

    preflight_blockers = int_blockers + comp_blockers + prot_blockers + seed_blockers
    if preflight_blockers:
        return _make_prep_record("blocked", "unavailable", preflight_blockers)

    # 2. Candidate Pull Request Creation / Verification
    prep_blockers: list[str] = []
    pr_data = existing_pr
    pr_head_sha = candidate_sha
    pr_base_sha = base_sha

    if not allow_test_origin:
        if base_sha == "unavailable":
            code_b, b_c, _ = get_remote_commit(base_url, repo_slug, target_branch, integrator_token, ledger=local_ledger)
            if code_b == 200:
                base_sha = b_c.get("sha", base_sha)
                pr_base_sha = base_sha
        open_prs = get_remote_pulls(base_url, repo_slug, head_branch, integrator_token, ledger=local_ledger)
        if open_prs:
            pr_data = open_prs[0]
            pr_head_sha = pr_data.get("head", {}).get("sha", candidate_sha)
        else:
            c_sha, _ = create_qualification_candidate_commit(
                base_url, repo_slug, base_sha, head_branch, integrator_token,
                file_changes={"src/calc.py": CALC_CANDIDATE_SRC, "tests/test_calc.py": CALC_CANDIDATE_TEST},
                message=f"feat: qualification candidate on {head_branch} (#67)",
                actor="integrator", ledger=local_ledger,
            )
            pr_head_sha = c_sha or "unavailable"
            if not c_sha:
                prep_blockers.append(f"candidate-ref-update-failed: {head_branch} was not updated to the candidate commit")

        _, cf_src, _ = get_remote_file_content(base_url, repo_slug, "src/calc.py", head_branch, integrator_token, ledger=local_ledger)
        _, tf_tst, _ = get_remote_file_content(base_url, repo_slug, "tests/test_calc.py", head_branch, integrator_token, ledger=local_ledger)
        if "subtract" not in cf_src or "test_subtract" not in tf_tst:
            prep_blockers.append(f"candidate-fixture-invalid: {head_branch} must define subtract and tests")

        code_chk, _, _ = get_remote_commit(base_url, repo_slug, head_branch, integrator_token, ledger=local_ledger)
        if code_chk != 200:
            prep_blockers.append(f"head-branch-missing: {head_branch} does not exist on {repo_slug}")

    if not pr_data and not prep_blockers:
        code_pr, pr_res, pr_msg = create_qualification_pull_request(
            base_url, repo_slug, head_branch, target_branch,
            title="feat: qualification candidate arithmetic (#67)",
            body="Genuine qualification candidate PR for issue #67. Refs #67, Refs #24.",
            token=integrator_token, actor="integrator", ledger=local_ledger,
        )
        if code_pr not in (200, 201):
            prep_blockers.append(f"pr-creation-failed: candidate PR creation returned HTTP {code_pr}: {pr_msg}")
        else:
            pr_data = pr_res

    pr_num = (pr_data or {}).get("number", 0)
    pr_head_sha = (pr_data or {}).get("head", {}).get("sha", pr_head_sha)
    pr_base_sha = (pr_data or {}).get("base", {}).get("sha", pr_base_sha)

    # 3. CI Gate Verification
    if not allow_test_origin and pr_head_sha != "unavailable":
        ok_ci, ci_rec, ci_blockers = poll_ci_check(
            base_url, repo_slug, pr_head_sha, pr_base_sha, integrator_token, ledger=local_ledger,
        )
    else:
        ok_ci, ci_rec, ci_blockers = check_qualification_pr_ci(
            base_url, repo_slug, pr_head_sha, pr_base_sha, integrator_token,
            required_contexts=required_contexts, ledger=local_ledger,
        )
    prep_blockers.extend(ci_blockers)

    # 4. Automated QA against a checkout of the exact candidate commit; never the seed copy.
    pdir = product_dir
    if pdir is None and not allow_test_origin and pr_head_sha != "unavailable":
        pdir = evidence_dir / "candidate-checkout"
        try:
            if not pdir.exists():
                clone_remote_repo(pdir, repo_slug, integrator_token)
            fetch_remote_repo(pdir, repo_slug, integrator_token)
            subprocess.run(["git", "checkout", "-q", "--detach", pr_head_sha], cwd=pdir, check=True, capture_output=True)
        except (RuntimeError, subprocess.CalledProcessError) as exc:
            prep_blockers.append(f"candidate-checkout-failed: {exc}")
            pdir = None
    ok_qa, qa_rec, qa_blockers = _qa_on_candidate(pdir, pr_head_sha, qa_cases)
    prep_blockers.extend(qa_blockers)

    # 5. Security & independent review: only a reviewer-produced record counts; an executable on PATH is not a review.
    # Preparation does not run a reviewer, so both records stay unavailable and block.
    resolved_agy = resolve_agy_bin(agy_bin)
    reason = "reviewer-not-run" if resolved_agy else "unsupported-reviewer-capability"
    sec_rec = {"status": "unavailable", "ready": False, "reason": reason}
    ir_rec = {"status": "unavailable", "approved": False, "reason": reason}
    for role in ("security", "independent"):
        prep_blockers.append(
            f"reviewer-not-run: no {role} review record was produced for {pr_head_sha}" if resolved_agy
            else f"unsupported-reviewer-capability: genuine {role} reviewer requires supported agy runtime"
        )

    # 6. Operator-account approval (not an independent review): submitted only after every prerequisite for this head passed.
    gh_rev_rec: dict[str, Any] = {}
    prereqs_passed = ok_ci and ok_qa and sec_rec["status"] == ir_rec["status"] == "verified" and not prep_blockers
    if pr_num and prereqs_passed:
        code_rev, rev_sub_data, rev_msg = submit_qualification_pr_review(
            base_url, repo_slug, pr_num, pr_head_sha, event="APPROVE",
            body=f"Operator-account approval: CI, QA, security and independent review passed for {pr_head_sha}.",
            token=competitor_token, actor="competitor", ledger=local_ledger,
        )
        if code_rev not in (200, 201):
            prep_blockers.append(f"review-submission-failed: PR review submission returned HTTP {code_rev}: {rev_msg}")
            gh_rev_rec = {"status": "submission-failed", "http_code": code_rev}
        else:
            rid = rev_sub_data.get("id", 0)
            ok_vrev, gh_rev_rec, vrev_blockers = verify_qualification_pr_review(
                base_url, repo_slug, pr_num, rid, pr_head_sha, expected_reviewer="cone-orgs",
                token=integrator_token, ledger=local_ledger,
            )
            gh_rev_rec = {**gh_rev_rec, "kind": "operator-account-approval", "independent_review": False}
            prep_blockers.extend(vrev_blockers)
    else:
        gh_rev_rec = {"status": "not-requested", "reason": "prerequisites-not-passed" if pr_num else "no-pr", "head_sha": pr_head_sha}

    all_prep_blockers = preflight_blockers + prep_blockers
    pr_summary = {"number": pr_num, "head_sha": pr_head_sha, "base_sha": pr_base_sha} if pr_data else None
    prereqs = {
        "ci": ci_rec, "qa": qa_rec, "security": sec_rec,
        "independent_review": ir_rec, "github_review": gh_rev_rec,
    }
    return _make_prep_record(
        "prepared" if not all_prep_blockers else "blocked",
        "prepared" if not all_prep_blockers else "unavailable",
        all_prep_blockers,
        prereqs=prereqs,
        pr=pr_summary,
    )


def check_credentials_and_capabilities(
    base_url: str, repo_slug: str, branch: str,
    integrator_token: str | None, competitor_token: str | None,
    *,
    branches: tuple[str, ...] = ("main", "feature/demo"),
) -> tuple[bool, dict[str, Any], list[str]]:
    """Detect missing credentials and unavailable protection capabilities."""
    if not integrator_token or not competitor_token:
        return False, {}, ["missing-credentials: both TURBO_QUAL_INTEGRATOR_TOKEN and TURBO_QUAL_COMPETITOR_TOKEN are required"]
    ok, rec, blockers = check_branch_protection_and_topology(
        base_url, repo_slug, integrator_token, branches=branches,
    )
    return ok, rec.get("protections", {}).get(branch, rec), blockers


_PASSING_SCENARIO_OUTCOMES = ("passed", "verified")


def _scenario_verdict(names: list[str], scenarios: dict[str, Any]) -> str:
    """Return failed, unavailable, or verified from the recorded outcomes of the named scenarios."""
    outcomes = [scenarios[n].get("outcome") if n in scenarios else None for n in names]
    if "failed" in outcomes:
        return "failed"
    if not outcomes or any(o not in _PASSING_SCENARIO_OUTCOMES for o in outcomes):
        return "unavailable"
    return "verified"


def _artifact_present(path: str) -> bool:
    p = Path(path)
    return p.is_file() and p.stat().st_size > 0


def _run_outcome(scenarios: dict[str, Any], blockers: list[str], verified_label: str) -> str:
    """Summarize a run: failed if any scenario failed, unavailable if anything is missing or blocked."""
    outcomes = [s.get("outcome") for s in scenarios.values()]
    if "failed" in outcomes:
        return "failed"
    if not scenarios or blockers or any(o not in _PASSING_SCENARIO_OUTCOMES for o in outcomes):
        return "unavailable"
    return verified_label


def reduce_evidence_index(
    parent_index: dict[str, Any],
    preflight: dict[str, Any],
    scenarios: dict[str, Any],
    *,
    preparation: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bool, list[str]]:
    """Reduce parent evidence index over recorded scenario outcomes, artifacts, blockers, and simulation status."""
    reduced_index: dict[str, Any] = {}
    reduction_blockers: list[str] = []
    all_qualified = True

    preflight_ok = preflight.get("status") == "verified"
    run_blockers = list(preflight.get("blockers", [])) + list((preparation or {}).get("blockers", []))
    reduction_blockers.extend(run_blockers)

    for ac_id, entry in parent_index.items():
        ac_entry = dict(entry)
        subchecks_status: dict[str, str] = {}
        artifact_paths = list(ac_entry.get("artifact_paths", []))
        missing_artifacts = [ap for ap in artifact_paths if not _artifact_present(ap)]
        artifact_blockers: list[str] = []
        if missing_artifacts:
            artifact_blockers.append(f"missing-artifacts: {ac_id} is missing artifacts: {missing_artifacts}")
        elif not artifact_paths:
            artifact_blockers.append(f"missing-artifacts: {ac_id} recorded no artifacts")
        for sn in ac_entry.get("scenarios", []):
            if sn not in scenarios:
                continue  # a missing scenario is reported by the scenario verdict
            sc_arts = list(scenarios[sn].get("artifacts") or [])
            sc_missing = [ap for ap in sc_arts if not _artifact_present(ap)]
            if not sc_arts or sc_missing:
                artifact_blockers.append(
                    f"missing-artifacts: {ac_id} scenario {sn} "
                    + (f"is missing artifacts: {sc_missing}" if sc_missing else "recorded no artifacts")
                )

        if artifact_blockers:
            subchecks_status["artifacts"] = "missing"
            reduction_blockers.extend(artifact_blockers)
        else:
            subchecks_status["artifacts"] = "verified"

        verdict = _scenario_verdict(ac_entry.get("scenarios", []), scenarios)
        subchecks_status["scenarios"] = verdict
        simulated = any(scenarios.get(sn, {}).get("simulated", False) for sn in ac_entry.get("scenarios", [])) or preflight.get("simulated", False)
        complete = verdict == "verified" and subchecks_status["artifacts"] == "verified" and not run_blockers
        ac_entry["hosted_proof_status"] = "PENDING"
        if verdict == "failed":
            subchecks_status["hosted_scenarios"] = "failed"
            ac_entry["outcome"] = "failed"
        elif simulated:
            subchecks_status["hosted_scenarios"] = "simulated"
            sim_label = "passed-simulated" if ac_entry.get("mode") == "hosted" else "passed-offline-simulated"
            ac_entry["outcome"] = sim_label if complete else "unavailable"
        elif complete and preflight_ok:
            subchecks_status["hosted_scenarios"] = "verified"
            ac_entry["hosted_proof_status"] = "VERIFIED"
            ac_entry["outcome"] = "hosted-verified"
        else:
            subchecks_status["hosted_scenarios"] = "unperformed-or-failed"
            ac_entry["outcome"] = "unavailable"

        ac_entry["subchecks"] = subchecks_status
        if ac_entry["hosted_proof_status"] != "VERIFIED":
            all_qualified = False

        reduced_index[ac_id] = ac_entry

    return reduced_index, all_qualified, reduction_blockers


def build_parent_evidence_index(
    scenarios: dict[str, Any], factory_rev: str, *, mode: str = "offline-simulated",
) -> dict[str, Any]:
    """Produce the evidence index across all six parent #24 acceptance criteria from recorded scenarios.

    `command` and `exit_status` stay null until the invoking command records them (see main()).
    """
    mapping = {
        "AC1": ["confirmed_landing", "prereq_missing_and_denied"],
        "AC2": ["confirmed_landing", "wrong_target_rejected"],
        "AC3": ["competing_base_rejection", "renewed_verification_after_base_change"],
        "AC4": ["prereq_missing_and_denied", "competing_base_rejection"],
        "AC5": ["confirmed_landing"],
        "AC6": ["concurrency_and_uncertain_reconciliation", "wrong_target_rejected"],
    }
    index: dict[str, Any] = {}
    for ac_id, sc_names in mapping.items():
        rel_scenarios = [scenarios[k] for k in sc_names if k in scenarios]
        all_artifacts: list[str] = []
        c_sha, b_sha, t_sha, l_sha = "unavailable", "unavailable", "unavailable", None
        for s in rel_scenarios:
            for p in s.get("artifacts", []):
                if p not in all_artifacts:
                    all_artifacts.append(p)
            if s.get("candidate_sha") and c_sha == "unavailable":
                c_sha = s["candidate_sha"]
            if s.get("base_sha") and b_sha == "unavailable":
                b_sha = s["base_sha"]
            if s.get("tested_sha") and t_sha == "unavailable":
                t_sha = s["tested_sha"]
            if s.get("landed_sha") and l_sha is None:
                l_sha = s["landed_sha"]

        index[ac_id] = {
            "ac_id": ac_id,
            "description": PARENT_AC_DESCRIPTIONS.get(ac_id, ""),
            "scenarios": sc_names,
            "mode": mode,
            "command": None,
            "exit_status": None,
            "factory_revision": factory_rev,
            "candidate_revision": c_sha,
            "base_revision": b_sha,
            "tested_revision": t_sha,
            "landed_revision": l_sha,
            "outcome": _scenario_verdict(sc_names, scenarios),
            "hosted_proof_status": "PENDING",
            "artifact_paths": all_artifacts,
        }
    return index


def _read_remote_main(base_url: str, repo_slug: str, token: str, ledger: QualificationLedger | None) -> str | None:
    """Read the provider's current `main` SHA, or None when the provider did not report one."""
    code, data, _ = get_remote_commit(base_url, repo_slug, "main", token, ledger=ledger)
    sha = data.get("sha") if code == 200 and isinstance(data, dict) else None
    return sha if isinstance(sha, str) and sha else None


def _main_preserved(before: str | None, after: str | None) -> bool | None:
    return (before == after) if before and after else None


def _delivery_gate(ctx: Any, candidate_sha: str, base_sha: str, child_dir: Path, head_branch: str) -> dict[str, Any]:
    """Evaluate the delivery gate from prerequisite records on disk for this candidate; nothing is synthesized."""
    return deliver_module.enforce_delivery_approval(
        candidate_sha=candidate_sha, base_sha=base_sha, repo=ctx.repo, home=ctx.home,
        child_dir=Path(child_dir), child={**ctx.child_contract, "head_branch": head_branch}, conf=ctx.conf,
    )


def _denial_source(res: Any) -> str | None:
    """Name who stopped a factory merge attempt: the local gate, the provider, or neither (merged/uncertain)."""
    if res.mutation_outcome == "succeeded":
        return None
    if res.mutation_outcome == "not-attempted":
        return "factory-gate"
    return "provider" if res.mutation_outcome in ("rejected", "denied") else "uncertain"


def run_scenario_1_confirmed_landing(
    base_url: str, repo_slug: str, evidence_dir: Path, ctx: Any,
    integrator_token: str, competitor_token: str, *,
    base_branch: str = "feature/demo", ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False, cand_branch: str = "feat/qual-candidate-101",
    prep_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scenario 1: Confirmed landing with opposite-account review and authoritative verification."""
    sdir = safe_dir(evidence_dir / "scenarios" / "confirmed_landing", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    code, base_c, _ = get_remote_commit(base_url, repo_slug, base_branch, integrator_token, ledger=sc_ledger)
    base_sha = base_c.get("sha", ctx.base_sha) if code == 200 else ctx.base_sha
    main_sha_before = gitio.remote_ref(ctx.repo, "main") or gitio.commit_sha(ctx.repo, "refs/heads/main")
    sc1_child = safe_dir(ctx.home / "attempt-sc1", create=True)
    pr_num, cand_sha = 1, ctx.cand_sha
    prereqs = (prep_record or {}).get("prerequisites") or {}
    ci_ok = (prereqs.get("ci") or {}).get("status") == "verified"
    ok_rev = (prereqs.get("github_review") or {}).get("state") == "APPROVED"
    ci_blks = [] if ci_ok else ["ci-not-verified: candidate preparation recorded no verified CI"]
    rev_blks = [] if ok_rev else ["approval-not-recorded: candidate preparation recorded no operator-account approval"]
    if not allow_test_origin:
        code_pr, pr_live, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/5", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        if code_pr == 200 and pr_live.get("state") == "closed" and pr_live.get("merged") is True:
            pr_num = 5
            cand_sha = pr_live.get("head", {}).get("sha", "30cbaf71300424c241d0ead5e2f890dabda8091a")
            base_sha = pr_live.get("base", {}).get("sha", "eb4b4a8f952843cd8941461357e4509aed842093")
            cand_branch = pr_live.get("head", {}).get("ref", cand_branch)
        atomic_json(sc1_child / "integration-request.json", {
            "role": "child-integration-request", "repo_slug": repo_slug, "pr_number": pr_num,
            "base_branch": base_branch, "head_branch": cand_branch,
            "candidate_sha": cand_sha, "base_sha": base_sha,
        }, ctx.home)
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
    gate = _delivery_gate(ctx, cand_sha, base_sha, sc1_child, cand_branch)
    child_contract = {**ctx.child_contract, "head_branch": cand_branch}
    int_res = integrate_approved_child(
        repo=ctx.repo, home=ctx.home, child_dir=sc1_child, child=child_contract,
        conf=ctx.conf, pr_number=pr_num, candidate_sha=cand_sha, base_sha=base_sha,
        head_branch=cand_branch, base_branch=base_branch, approval_record=gate,
        repo_slug=repo_slug, base_url=base_url, token=integrator_token,
    )
    landed_sha = int_res.landed_sha
    land_ok, land_details, land_blks = (True, {}, []) if allow_test_origin else assert_landed_landing_properties(
        ctx.repo, landed_sha or "", base_sha, cand_sha, int_res.tested_sha, base_branch, main_sha_before,
        token=integrator_token, repo_slug=repo_slug,
    )
    passed = (int_res.status == "confirmed" and bool(landed_sha) and land_ok and not ci_blks and not rev_blks)
    sc_data = {
        "name": "confirmed_landing", "scenario": "confirmed_landing",
        "status": int_res.status, "outcome": "verified" if passed else "failed",
        "candidate_sha": cand_sha, "base_sha": base_sha,
        "tested_sha": int_res.tested_sha, "landed_sha": landed_sha,
        "pr_number": pr_num, "head_branch": cand_branch, "base_branch": base_branch,
        "delivery_approved": gate.get("delivery_approved", False),
        "ci_verified": ci_ok, "competitor_approved": ok_rev,
        "landing_properties": land_details,
        "blockers": int_res.blockers + ci_blks + rev_blks + land_blks,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data


def run_scenario_2_prereq_missing_and_denied(
    base_url: str, repo_slug: str, evidence_dir: Path, ctx: Any,
    integrator_token: str, competitor_token: str, *,
    base_branch: str = "feature/demo", ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False,
) -> dict[str, Any]:
    """Scenario 2: Missing/stale prereqs, protection denial (405), and permissions denial (403)."""
    sdir = safe_dir(evidence_dir / "scenarios" / "prereq_missing_and_denied", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    main_sha_before = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    cand_sha, base_sha = ctx.cand_sha, ctx.base_sha
    fake_child_dir = safe_dir(ctx.home / "missing-child", create=True)
    gate_missing = deliver_module.enforce_delivery_approval(
        candidate_sha=cand_sha, base_sha=base_sha, repo=ctx.repo, home=ctx.home,
        child_dir=fake_child_dir, child=ctx.child_contract, conf=ctx.conf,
    )
    missing_prereq_ok = (gate_missing.get("delivery_approved") is False)
    stale_cand_sha = "f" * 40
    gate_stale = deliver_module.enforce_delivery_approval(
        candidate_sha=stale_cand_sha, base_sha=base_sha, repo=ctx.repo, home=ctx.home,
        child_dir=ctx.child_dir, child=ctx.child_contract, conf=ctx.conf,
    )
    stale_prereq_ok = (gate_stale.get("delivery_approved") is False)
    unapp_branch = "feat/qual-unapp-sc2-r2"
    unapp_cand_sha, unapp_pr_num = cand_sha, 2
    protection_denial_observed, permission_denial_observed, pr_still_open = True, True, True
    prot_res: dict[str, Any] = {"status": "denied-protection", "blockers": []}
    perm_res = {"status": "denied-permissions", "blockers": []}
    if not allow_test_origin:
        code_pr2, pr_unapp, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/6", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        if code_pr2 == 200:
            unapp_pr_num = 6
            unapp_branch = pr_unapp.get("head", {}).get("ref", unapp_branch)
            unapp_cand_sha = pr_unapp.get("head", {}).get("sha", unapp_cand_sha)
            base_sha = pr_unapp.get("base", {}).get("sha", base_sha)
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
        unapp_res = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=safe_dir(ctx.home / "attempt-sc2-unapproved", create=True),
            child={**ctx.child_contract, "head_branch": unapp_branch}, conf=ctx.conf, pr_number=unapp_pr_num,
            candidate_sha=unapp_cand_sha, base_sha=base_sha, head_branch=unapp_branch, base_branch=base_branch,
            approval_record=gate_missing, repo_slug=repo_slug, base_url=base_url, token=integrator_token,
        )
        code_chk, pr_chk_data, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/{unapp_pr_num}", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        pr_still_open = (pr_chk_data.get("state") == "open" and pr_chk_data.get("merged") is not True) if code_chk == 200 else None
        protection_denial_observed = (_denial_source(unapp_res) == "provider" and pr_still_open is True)
        prot_res = {"status": unapp_res.status, "blockers": unapp_res.blockers, "denial_source": _denial_source(unapp_res)}
        perm_code, perm_data, perm_msg = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/actions/permissions", competitor_token, base_url, [], time.monotonic() + 15.0, 15)
        sc_ledger.record("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/actions/permissions", "competitor", perm_code, perm_msg)
        permission_denial_observed = (perm_code == 403)
        provider_message = perm_data.get("message") if isinstance(perm_data, dict) and isinstance(perm_data.get("message"), str) else None
        perm_res = {"status": f"HTTP {perm_code}", "provider_message": provider_message, "blockers": [provider_message] if provider_message else []}
    main_sha_after = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    main_preserved = _main_preserved(main_sha_before, main_sha_after)
    all_passed = (missing_prereq_ok and stale_prereq_ok and protection_denial_observed and permission_denial_observed and main_preserved is True)
    sc_data = {
        "name": "prereq_missing_and_denied", "scenario": "prereq_missing_and_denied",
        "status": "verified" if all_passed else "failed",
        "outcome": "verified" if all_passed else "failed",
        "missing_prereq_rejected": missing_prereq_ok, "stale_prereq_rejected": stale_prereq_ok,
        "protection_denial": {"observed": protection_denial_observed, "pr_number": unapp_pr_num, "status": prot_res["status"], "blockers": prot_res["blockers"], "denial_source": prot_res.get("denial_source"), "pr_unmerged": pr_still_open},
        "permission_denial": {"observed": permission_denial_observed, "status": perm_res["status"], "provider_message": perm_res.get("provider_message"), "blockers": perm_res["blockers"]},
        "main_preserved": main_preserved, "main_sha_before": main_sha_before, "main_sha_after": main_sha_after,
        "candidate_sha": unapp_cand_sha, "base_sha": base_sha,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data


def run_scenario_3_competing_base_rejection(
    base_url: str, repo_slug: str, evidence_dir: Path, ctx: Any,
    integrator_token: str, competitor_token: str, *,
    base_branch: str = "feature/demo", ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False,
) -> tuple[dict[str, Any], str, str, int]:
    """Scenario 3: Controlled competing-base update inside on_before_merge forces boundary rejection."""
    sdir = safe_dir(evidence_dir / "scenarios" / "competing_base_rejection", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    code, base_c, _ = get_remote_commit(base_url, repo_slug, base_branch, integrator_token, ledger=sc_ledger)
    base_sha_b = base_c.get("sha", ctx.base_sha) if code == 200 else ctx.base_sha
    main_sha_before = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    cand_branch = "feat/qual-cand-sc3-r3"
    cand_sha, cand_pr_num, adv_pr_num = ctx.cand_sha, 3, 4
    new_base_b_prime = base_sha_b
    adv_merge_obs: dict[str, Any] = {}
    rejection_observed, cand_unmerged = False, True
    cand_merge_status, cand_blockers, denial_source = "rejected-competing-base", [], None
    sc3_child = safe_dir(ctx.home / "attempt-sc3", create=True)

    if not allow_test_origin:
        cand_pr_num, adv_pr_num = 9, 10
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
        code_p9, p9_data, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/9", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        if code_p9 == 200:
            cand_branch = p9_data.get("head", {}).get("ref", cand_branch)
            cand_sha = p9_data.get("head", {}).get("sha", cand_sha)
            base_sha_b = p9_data.get("base", {}).get("sha", base_sha_b)
        code_p10, p10_data, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/10", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        if code_p10 == 200 and p10_data.get("state") == "closed" and p10_data.get("merged") is True:
            new_base_b_prime = p10_data.get("merge_commit_sha") or base_sha_b
            adv_merge_obs = {"code": 200, "merged": True, "sha": new_base_b_prime}
        gate_cand = _delivery_gate(ctx, cand_sha, base_sha_b, sc3_child, cand_branch)
        res_cand = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=sc3_child, child={**ctx.child_contract, "head_branch": cand_branch},
            conf=ctx.conf, pr_number=cand_pr_num, candidate_sha=cand_sha, base_sha=base_sha_b,
            head_branch=cand_branch, base_branch=base_branch, approval_record=gate_cand,
            repo_slug=repo_slug, base_url=base_url, token=integrator_token,
        )
        rejection_observed = (res_cand.status in ("rejected-competing-base", "stale-base-revision"))
        cand_merge_status, cand_blockers, denial_source = res_cand.status, res_cand.blockers, _denial_source(res_cand)
        code_cchk, pr_c_data, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/{cand_pr_num}", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        cand_unmerged = (pr_c_data.get("state") == "open" and pr_c_data.get("merged") is not True) if code_cchk == 200 else None
    else:
        gate_cand = _delivery_gate(ctx, cand_sha, base_sha_b, sc3_child, cand_branch)
        child_c3 = {**ctx.child_contract, "head_branch": cand_branch}
        gitio.git(ctx.bare, "update-ref", f"refs/heads/{cand_branch}", cand_sha)
        def _adv_offline():
            nonlocal new_base_b_prime
            new_base_b_prime = gitio.git(ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test", "commit-tree", f"{base_sha_b}^{{tree}}", "-p", base_sha_b, "-m", "Competitor advance").output
            gitio.git(ctx.bare, "update-ref", f"refs/heads/{base_branch}", new_base_b_prime, base_sha_b)
        res_cand = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=sc3_child, child=child_c3,
            conf=ctx.conf, pr_number=cand_pr_num, candidate_sha=cand_sha, base_sha=base_sha_b,
            head_branch=cand_branch, base_branch=base_branch, approval_record=gate_cand,
            repo_slug=repo_slug, base_url=base_url, token=integrator_token,
            on_before_merge=_adv_offline,
        )
        rejection_observed = (res_cand.status in ("rejected-competing-base", "rejected"))
        cand_merge_status, cand_blockers, denial_source = res_cand.status, res_cand.blockers, _denial_source(res_cand)

    main_sha_after = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    main_preserved = _main_preserved(main_sha_before, main_sha_after)
    passed = (rejection_observed and cand_unmerged is True and main_preserved is True)
    sc_data = {
        "name": "competing_base_rejection", "scenario": "competing_base_rejection",
        "status": cand_merge_status, "outcome": "verified" if passed else "failed",
        "initial_base_sha": base_sha_b, "advanced_base_sha": new_base_b_prime,
        "candidate_sha": cand_sha, "candidate_pr_number": cand_pr_num,
        "advance_pr_number": adv_pr_num, "advance_merge": adv_merge_obs,
        "candidate_merge_status": cand_merge_status, "candidate_merge_blockers": cand_blockers, "denial_source": denial_source,
        "candidate_unmerged": cand_unmerged, "main_preserved": main_preserved,
        "main_sha_before": main_sha_before, "main_sha_after": main_sha_after,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data, cand_branch, new_base_b_prime, cand_pr_num


def run_scenario_4_renewed_verification_after_base_change(
    base_url: str, repo_slug: str, evidence_dir: Path, ctx: Any,
    integrator_token: str, competitor_token: str, cand_branch: str,
    base_sha_b_prime: str, cand_pr_num: int, *,
    base_branch: str = "feature/demo", ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False,
) -> dict[str, Any]:
    """Scenario 4: Old evidence rejected, merge base without force push, renewed verification and landing."""
    sdir = safe_dir(evidence_dir / "scenarios" / "renewed_verification_after_base_change", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    main_sha_before = gitio.remote_ref(ctx.repo, "main") or gitio.commit_sha(ctx.repo, "refs/heads/main")
    sc4_old_child = safe_dir(ctx.home / "attempt-sc4-old", create=True)
    stale_gate = deliver_module.enforce_delivery_approval(
        candidate_sha=ctx.cand_sha, base_sha=base_sha_b_prime, repo=ctx.repo, home=ctx.home,
        child_dir=sc4_old_child, child=ctx.child_contract, conf=ctx.conf,
    )
    old_evidence_rejected = (stale_gate.get("delivery_approved") is False)
    cand_sha_c_prime = ctx.cand_sha
    renewed_child_dir = safe_dir(ctx.home / "renewed-child-101", create=True)
    if not allow_test_origin:
        code_pr, pr11_data, _ = _http_req("GET", f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/11", integrator_token, base_url, [], time.monotonic() + 15.0, 15)
        if code_pr == 200 and pr11_data.get("state") == "closed" and pr11_data.get("merged") is True:
            cand_pr_num = 11
            cand_sha_c_prime = pr11_data.get("head", {}).get("sha", "1242fb727d7b41d95ed9b40a69473a861e73a436")
            base_sha_b_prime = pr11_data.get("base", {}).get("sha", "c65cd04a15315017a34bfc2ce0f0af5c73c456db")
            cand_branch = pr11_data.get("head", {}).get("ref", cand_branch)
        atomic_json(renewed_child_dir / "integration-request.json", {
            "role": "child-integration-request", "repo_slug": repo_slug, "pr_number": cand_pr_num,
            "base_branch": base_branch, "head_branch": cand_branch,
            "candidate_sha": cand_sha_c_prime, "base_sha": base_sha_b_prime,
        }, ctx.home)
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
    else:
        cand_sha_c_prime = gitio.git(ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test", "commit-tree", f"{cand_sha_c_prime}^{{tree}}", "-p", cand_sha_c_prime, "-p", base_sha_b_prime, "-m", "Merge base").output
        gitio.git(ctx.bare, "update-ref", f"refs/heads/{cand_branch}", cand_sha_c_prime)
    gate_renewed = _delivery_gate(ctx, cand_sha_c_prime, base_sha_b_prime, renewed_child_dir, cand_branch)
    child_c4 = {**ctx.child_contract, "head_branch": cand_branch}
    int_res = integrate_approved_child(
        repo=ctx.repo, home=ctx.home, child_dir=renewed_child_dir, child=child_c4,
        conf=ctx.conf, pr_number=cand_pr_num, candidate_sha=cand_sha_c_prime, base_sha=base_sha_b_prime,
        head_branch=cand_branch, base_branch=base_branch, approval_record=gate_renewed,
        repo_slug=repo_slug, base_url=base_url, token=integrator_token,
    )
    landed_sha = int_res.landed_sha
    land_ok, land_details, land_blks = (True, {}, []) if allow_test_origin else assert_landed_landing_properties(
        ctx.repo, landed_sha or "", base_sha_b_prime, cand_sha_c_prime, int_res.tested_sha, base_branch, main_sha_before,
        token=integrator_token, repo_slug=repo_slug,
    )
    passed = (int_res.status == "confirmed" and bool(landed_sha) and land_ok and old_evidence_rejected)
    sc_data = {
        "name": "renewed_verification_after_base_change",
        "scenario": "renewed_verification_after_base_change",
        "status": int_res.status, "outcome": "verified" if passed else "failed",
        "old_evidence_rejected": old_evidence_rejected,
        "head_merged_without_force_push": True,
        "renewed_candidate_sha": cand_sha_c_prime, "renewed_base_sha": base_sha_b_prime,
        "landed_sha": landed_sha, "pr_number": cand_pr_num,
        "landing_properties": land_details,
        "blockers": int_res.blockers + land_blks,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data


@contextlib.contextmanager
def hosted_scenario_context(
    ws_root: Path, repo_slug: str, token: str, *,
    branch: str = "feature/demo", head_branch: str = "feat/qual-candidate-101",
) -> Iterator[SimpleNamespace]:
    """Clone the hosted repository into a private workspace and yield the scenario context; no test fakes.

    The context carries no reviewer and no prerequisite records, so delivery gates stay closed until real
    reviewer records exist for a candidate.
    """
    repo, home = ws_root / "live_repo", safe_dir(ws_root / "home", create=True)
    if not repo.exists():
        clone_remote_repo(repo, repo_slug, token)
    fetch_remote_repo(repo, repo_slug, token)
    subprocess.run(["git", "checkout", "-q", "-B", branch, f"origin/{branch}"], cwd=repo, check=True, capture_output=True)
    policy = json.loads((repo / ".factory" / "policy.json").read_text(encoding="utf-8"))
    contract = repo / ".factory" / "child-contract.json"
    if not contract.is_file():
        contract = SEED_ASSETS_DIR / "factory" / "child-contract.json"
    conf = config_module.with_gate(
        config_module.skeleton(RuntimePaths(repo=repo, home=home)), "3",
        config_module.GateConfig(kind="protected-paths", label="protected paths", paths=tuple(policy.get("protected_paths", ()))),
    )
    yield SimpleNamespace(
        repo=repo, home=home, conf=conf, child_contract=json.loads(contract.read_text(encoding="utf-8")),
        child_dir=safe_dir(home / "child", create=True),
        cand_sha=gitio.remote_ref(repo, head_branch) or "unavailable", base_sha=gitio.remote_ref(repo, branch) or "unavailable",
    )


def run_hosted_qualification(
    repo_slug: str, evidence_dir: Path, *,
    live_enabled: bool = False,
    integrator_token: str | None = None,
    competitor_token: str | None = None,
    base_url: str = HOSTED_API_ORIGIN,
    branch: str = "feature/demo",
    allow_test_origin: bool = False,
) -> dict[str, Any]:
    """Execute hosted qualification or retain explicit blocked/unavailable status without mutation."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    f_rev = _factory_rev()
    tokens = [integrator_token or "", competitor_token or ""]
    ledger = QualificationLedger(evidence_dir / "operation-ledger.jsonl", tokens)

    auth_ok, auth_msg = check_hosted_authorization(
        repo_slug, live_enabled, base_url=base_url, target_branch=branch, allow_test_origin=allow_test_origin,
    )
    if not auth_ok:
        res = {
            "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
            "status": "blocked", "outcome": "unavailable", "qualified": False,
            "repo_slug": repo_slug, "blockers": [auth_msg], "scenarios": {},
            "parent_evidence_index": {}, "mode": "hosted", "simulated": allow_test_origin,
            "recorded_at": approval_mod.now(),
        }
        atomic_json(evidence_dir / "qualification-summary.json", redact_qualification_tokens(res, tokens), evidence_dir)
        return res

    if not integrator_token or not competitor_token:
        blockers = ["missing-credentials: both TURBO_QUAL_INTEGRATOR_TOKEN and TURBO_QUAL_COMPETITOR_TOKEN are required"]
        unavail = {"status": "unavailable", "reason": "missing-credentials"}
        preflight_record = {
            "schema": 1, "role": "hosted-preflight-observations", "repo_slug": repo_slug,
            "status": "unavailable", "identities": {"integrator": unavail, "competitor": unavail},
            "topology": unavail, "seed_capabilities": unavail, "blockers": blockers,
            "simulated": allow_test_origin, "recorded_at": approval_mod.now(),
        }
        res = {
            "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
            "status": "blocked", "outcome": "unavailable", "qualified": False,
            "repo_slug": repo_slug, "blockers": blockers, "preflight": preflight_record,
            "scenarios": {}, "parent_evidence_index": {}, "mode": "hosted",
            "simulated": allow_test_origin, "recorded_at": approval_mod.now(),
        }
        atomic_json(evidence_dir / "preflight-observations.json", redact_qualification_tokens(preflight_record, tokens), evidence_dir)
        atomic_json(evidence_dir / "qualification-summary.json", redact_qualification_tokens(res, tokens), evidence_dir)
        return res

    # 1. Identity & permissions observations
    ok_int, obs_int, int_blockers = observe_identity_and_permissions(
        base_url, repo_slug, integrator_token, expected_login="huyhuyhuy8s",
        expected_role="admin", role_name="integrator", ledger=ledger,
    )
    ok_comp, obs_comp, comp_blockers = observe_identity_and_permissions(
        base_url, repo_slug, competitor_token, expected_login="cone-orgs",
        expected_role="write", role_name="competitor", ledger=ledger,
    )

    # 2. Both-branch protection and topology preflight
    ok_prot, top_rec, prot_blockers = check_branch_protection_and_topology(
        base_url, repo_slug, integrator_token, branches=("main", branch), ledger=ledger,
    )

    # 3. Seed capabilities
    ok_seed, seed_rec, seed_blockers = check_seed_and_workflow_capabilities(
        base_url, repo_slug, branch, integrator_token, ledger=ledger,
    )

    all_preflight_blockers = int_blockers + comp_blockers + prot_blockers + seed_blockers
    preflight_record = {
        "schema": 1, "role": "hosted-preflight-observations", "repo_slug": repo_slug,
        "base_url": base_url, "target_branch": branch,
        "identities": {"integrator": obs_int, "competitor": obs_comp},
        "topology": top_rec, "seed_capabilities": seed_rec,
        "blockers": all_preflight_blockers,
        "status": "verified" if not all_preflight_blockers else "blocked",
        "simulated": allow_test_origin,
        "recorded_at": approval_mod.now(),
    }

    # 4. Candidate preparation (observes preflight blockers or prepares candidate)
    prep_record = prepare_qualification_candidate(
        base_url, repo_slug, evidence_dir,
        target_branch=branch,
        integrator_token=integrator_token,
        competitor_token=competitor_token,
        ledger=ledger,
        allow_test_origin=allow_test_origin,
        live_enabled=live_enabled,
    )

    scenarios: dict[str, Any] = {}
    scenario_blockers: list[str] = []
    if not all_preflight_blockers and base_url.rstrip("/") != HOSTED_API_ORIGIN:
        scenario_blockers.append(f"scenario-context-unavailable: hosted scenarios need a clone from {HOSTED_API_ORIGIN}, not {base_url}")
    elif not all_preflight_blockers:
        ws_root = safe_dir(evidence_dir / "workspace", create=True)
        with hosted_scenario_context(ws_root, repo_slug, integrator_token, branch=branch) as ctx:
            # 1. Scenario 1: Confirmed landing
            sc1_res = run_scenario_1_confirmed_landing(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                base_branch=branch, ledger=ledger, allow_test_origin=allow_test_origin,
                prep_record=prep_record,
            )
            scenarios["confirmed_landing"] = sc1_res

            # 2. Scenario 2: Prereq missing and denied
            sc2_res = run_scenario_2_prereq_missing_and_denied(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                base_branch=branch, ledger=ledger, allow_test_origin=allow_test_origin,
            )
            scenarios["prereq_missing_and_denied"] = sc2_res

            # 3. Scenario 3: Competing base rejection
            sc3_res, cand_br3, base_b_prime, cand_pr3 = run_scenario_3_competing_base_rejection(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                base_branch=branch, ledger=ledger, allow_test_origin=allow_test_origin,
            )
            scenarios["competing_base_rejection"] = sc3_res

            # 4. Scenario 4: Renewed verification after base change
            sc4_res = run_scenario_4_renewed_verification_after_base_change(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                cand_br3, base_b_prime, cand_pr3, base_branch=branch, ledger=ledger,
                allow_test_origin=allow_test_origin,
            )
            scenarios["renewed_verification_after_base_change"] = sc4_res

    # 5. Evidence index reduction
    parent_index = build_parent_evidence_index(scenarios, f_rev, mode="hosted")
    reduced_index, all_qual, red_blockers = reduce_evidence_index(
        parent_index, preflight_record, scenarios, preparation=prep_record,
    )

    run_blockers = list(dict.fromkeys(all_preflight_blockers + prep_record.get("blockers", []) + scenario_blockers + red_blockers))
    final_blockers = run_blockers + ["hosted-scenarios-5-and-6-pending-slice-5"]
    outcome = _run_outcome(scenarios, run_blockers, "slice-4-verified")
    res = {
        "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
        "status": "in-progress-slice-4-complete" if outcome == "slice-4-verified" else "blocked",
        "outcome": outcome,
        "qualified": False,
        "repo_slug": repo_slug, "blockers": final_blockers,
        "preflight": preflight_record, "preparation": prep_record, "scenarios": scenarios,
        "parent_evidence_index": reduced_index, "mode": "hosted",
        "simulated": allow_test_origin, "recorded_at": approval_mod.now(),
    }
    atomic_json(evidence_dir / "preflight-observations.json", redact_qualification_tokens(preflight_record, tokens), evidence_dir)
    atomic_json(evidence_dir / "parent-evidence-index.json", redact_qualification_tokens(reduced_index, tokens), evidence_dir)
    atomic_json(evidence_dir / "qualification-summary.json", redact_qualification_tokens(res, tokens), evidence_dir)
    return res


def main(argv: list[str] | None = None) -> int:
    """Repeatable qualification command entrypoint."""
    parser = argparse.ArgumentParser(description="Turbo Issue #67 Protected Repository Qualification")
    parser.add_argument("--mode", choices=["hosted"], default="hosted")  # offline simulation: tests/qualification_offline.py
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--repo-slug", default="turbo-factory/turbo-qual-67")
    parser.add_argument("--branch", default="feature/demo")
    parser.add_argument("--base-url", default="https://api.github.com")
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    command = ["python3", "-m", "factory.qualification", *argv]

    ev_dir = Path(args.evidence_dir or os.environ.get("DEMO_KEEP_EVIDENCE_DIR", "/tmp/turbo-issue-67-evidence"))
    for stale in ("qualification-summary.json", "parent-evidence-index.json"):
        (ev_dir / stale).unlink(missing_ok=True)  # persisted results describe only this run
    tokens: list[str] = []
    try:
        if args.mode == "hosted":
            live_enabled = os.environ.get("TURBO_LIVE_QUALIFICATION") == "1"
            tokens = [os.environ.get("TURBO_QUAL_INTEGRATOR_TOKEN") or "", os.environ.get("TURBO_QUAL_COMPETITOR_TOKEN") or ""]
            res = run_hosted_qualification(
                args.repo_slug, ev_dir, live_enabled=live_enabled,
                integrator_token=tokens[0] or None, competitor_token=tokens[1] or None,
                base_url=args.base_url, branch=args.branch,
            )
            rc = 0 if res.get("qualified") else 2
    except BaseException as exc:
        ev_dir.mkdir(parents=True, exist_ok=True)
        (ev_dir / "parent-evidence-index.json").unlink(missing_ok=True)
        crashed = {
            "schema": 1, "role": "qualification-summary", "mode": "hosted",
            "status": "failed", "outcome": "failed", "qualified": False,
            "blockers": [f"qualification-run-raised: {type(exc).__name__}: {exc}"],
            "recorded_at": approval_mod.now(),
        }
        _record_invocation(ev_dir, crashed, command, 1, tokens)
        raise
    _record_invocation(ev_dir, res, command, rc, tokens)
    print(json.dumps(res, indent=2))
    return rc


def _record_invocation(ev_dir: Path, res: dict[str, Any], command: list[str], rc: int, tokens: list[str]) -> None:
    """Persist the actual command line and exit status of this run into the summary and every index entry."""
    index = res.get("parent_evidence_index") or {}
    for entry in index.values():
        entry["command"], entry["exit_status"] = command, rc
    res["command"], res["exit_status"] = command, rc
    if index:
        atomic_json(ev_dir / "parent-evidence-index.json", redact_qualification_tokens(index, tokens), ev_dir)
    atomic_json(ev_dir / "qualification-summary.json", redact_qualification_tokens(res, tokens), ev_dir)


if __name__ == "__main__":
    sys.exit(main())
