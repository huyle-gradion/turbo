"""Protected repository qualification harness (#67)."""
from __future__ import annotations

import argparse, base64, contextlib, json, os, shutil, subprocess, sys, time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote, urlparse

from factory import (automated_qa, ci_gate, config as config_module, deliver as deliver_module, gitio, independent_review,
                     security_review)
from factory.ci_selection import build_required_ci_checks
from factory.deliver_checks import collect_redaction_secrets, git_timed
from factory.errors import UsageError
from factory.independent_review import approval as approval_mod
from factory.integration import _factory_rev, _http_req, integrate_approved_child
from factory.paths import RuntimePaths, atomic_json, safe_dir

FACTORY_ROOT = Path(__file__).resolve().parents[1]
SEED_ASSETS_DIR = FACTORY_ROOT / "examples" / "qualification" / "seed"

HOSTED_API_ORIGIN = "https://api.github.com"
# The hosted harness builds the candidate itself; reviewers must run in sessions other than this builder (#104).
QUALIFICATION_BUILDER_SESSION = "qual-builder"
HOSTED_CLONE_URL_TEMPLATE = "https://github.com/{repo_slug}.git"
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

REAL_SETUP_METADATA: dict[str, Any] = {
    "repo_slug": "turbo-factory/turbo-qual-67",
    "identities": {
        "integrator": "admin; login from TURBO_QUAL_EXPECTED_INTEGRATOR",
        "competitor": "write collaborator; login from TURBO_QUAL_EXPECTED_COMPETITOR",
        "restricted_reader": "read-only identity",
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
    expected_login: str | None,
    expected_role: str,
    role_name: str,
    ledger: QualificationLedger | None = None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Observe user identity and repository permissions via GitHub API object endpoints; with no expected login the
    observed one is accepted (the caller records that identities were unconfigured)."""
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
    if expected_login is not None and observed_login != expected_login:
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


def _get_list(url: str, token: str) -> list[dict[str, Any]] | None:
    """GET a JSON list without following redirects (`_http_req` reads lists as {}); None when no list came back."""
    from factory.intake import NoRedirectHandler
    from urllib.request import Request, build_opener
    req = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    try:
        with build_opener(NoRedirectHandler).open(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    return data if isinstance(data, list) else None


def _api(
    method: str, base_url: str, repo_slug: str, path: str, token: str, payload: dict[str, Any] | None = None,
    ledger: QualificationLedger | None = None, actor: str = "integrator",
) -> tuple[int, dict[str, Any], str]:
    """One provider request on the repository, recorded in the ledger."""
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/{path}"
    code, data, msg = _http_req(method, url, token, base_url, [], time.monotonic() + 15.0, 15, payload=payload)
    if ledger:
        ledger.record(method, url, actor, code, msg)
    return code, data, msg


def _candidate_ctx(ctx: Any, branch: str, suffix: str = "") -> SimpleNamespace:
    """The scenario context with this candidate's own child folder, so records of different candidates never mix."""
    sub = ctx.home / "candidates" / (branch.removeprefix(CANDIDATE_BRANCH_PREFIX) + suffix)
    return SimpleNamespace(**{**vars(ctx), "child_dir": safe_dir(sub, create=True)})


def _calc_changes(branch: str) -> dict[str, str]:
    """Candidate content unique to `branch`, so every run's candidate differs from the base it starts from."""
    return {"src/calc.py": CALC_CANDIDATE_SRC + f"\n# qualification candidate {branch}\n", "tests/test_calc.py": CALC_CANDIDATE_TEST}


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
    _hosted_git(["clone", "-q", HOSTED_CLONE_URL_TEMPLATE.format(repo_slug=repo_slug), str(dest)], repo_slug, token)


def fetch_remote_repo(repo: Path, repo_slug: str, token: str) -> None:
    """Fetch remote repository heads and pull refs using ephemeral credential."""
    for attempt in range(3):
        try:
            _hosted_git(["fetch", "-q", HOSTED_CLONE_URL_TEMPLATE.format(repo_slug=repo_slug), "+refs/heads/*:refs/remotes/origin/*", "+refs/pull/*:refs/remotes/origin/pr/*"], repo_slug, token, cwd=repo)
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


GATED_CI_QA_LIMIT_S = 900  # preparation's CI and QA wait (#108); read at call time


def _gated_ci_and_qa(
    ctx: Any, base_url: str, repo_slug: str, token: str, pr_data: dict[str, Any], *,
    head_branch: str, base_branch: str, candidate_sha: str, base_sha: str, tokens: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """CI and QA evidence from the factory's own entry points for the exact candidate head (#108); nothing synthesized."""
    limit_s = GATED_CI_QA_LIMIT_S
    child = {**ctx.child_contract, "head_branch": head_branch}
    parent = {"gid": "qualification-67", "name": "Protected repository qualification (#67)", "criteria": []}
    p = urlparse(base_url)
    fast = p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost", "::1")  # deliver.py's loopback settings
    blockers: list[str] = []
    try:
        fetch_remote_repo(ctx.repo, repo_slug, token)  # the gate and QA read the candidate from the scenario clone
        diff = gitio.git(ctx.repo, "diff", "--name-only", f"{base_sha}...{candidate_sha}")
        changed = tuple(diff.output.split()) if diff.ok else ()
        pr_info = {"number": int(pr_data.get("number") or 0), "url": pr_data.get("html_url"), "state": pr_data.get("state"),
                   "merged": bool(pr_data.get("merged")), "head_ref": head_branch, "base_ref": base_branch,
                   "head_sha": candidate_sha, "base_sha": base_sha, "pr_confirmed": True}
        ci = ci_gate.evaluate_child_pr_ci_gate(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, base_url=base_url, token=token, repo_slug=repo_slug,
            parent=parent, child=child, conf=ctx.conf, pr_info=pr_info, head_branch=head_branch,
            candidate_sha=candidate_sha, base_branch=base_branch, base_sha=base_sha, scope_detail={}, trace=[],
            deadline=time.monotonic() + limit_s, limit_s=limit_s, changed_paths=changed,
            poll_interval_s=0.05 if fast else 2.0, max_missing_polls=3 if fast else 15,
            artifact_retry_delay_s=0.0 if fast else 2.0,
        )
    except Exception as exc:  # the entry point could not run: no record, unavailable, blocked
        msg = str(redact_qualification_tokens(str(exc), tokens))
        unavail = {"status": "unavailable", "reason": f"ci-gate-unavailable: {msg}", "candidate_sha": candidate_sha}
        return unavail, {**unavail, "qa_verified": False, "reason": "ci-not-run"}, [f"ci-unavailable: {msg}"]
    atomic_json(ctx.child_dir / "ci-verification.json", redact_qualification_tokens(ci, tokens), ctx.home)
    ci_ok = ci.get("status") == "verified" and ci.get("verified") is True
    blockers += [f"ci-not-verified ({ci.get('status')}) for {candidate_sha}: {b}" for b in (ci.get("blockers") or [])]
    if not ci_ok:
        blockers += [] if ci.get("blockers") else [f"ci-not-verified: CI gate status {ci.get('status')!r} for {candidate_sha}"]
        return ci, {"status": "not-run", "qa_verified": False, "reason": "ci-not-verified", "candidate_sha": candidate_sha}, blockers
    child_record = {
        "gid": child.get("gid"), "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": ci.get("tested_sha"),
        "head_branch": head_branch, "base_branch": base_branch, "status": ci.get("status"), "verified": ci.get("verified"),
        "ci_verified": ci_ok, "ci_verification": ci, "pr": ci.get("pr"), "diff": {"changed_paths": list(changed)},
    }
    try:
        qa = automated_qa.evaluate_child_qa(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, base_url=base_url, token=token, repo_slug=repo_slug,
            parent=parent, child=child, child_record=child_record, conf=ctx.conf,
            qa_cases=automated_qa.load_qa_cases_file(ctx.repo / "qa" / "qa-cases.json"),
            deadline=time.monotonic() + limit_s, limit_s=limit_s,
        )
    except Exception as exc:
        msg = str(redact_qualification_tokens(str(exc), tokens))
        return ci, {"status": "unavailable", "qa_verified": False, "reason": msg, "candidate_sha": candidate_sha}, blockers + [f"qa-unavailable: {msg}"]
    if qa.get("qa_verified") is not True:
        failed = [c.get("criterion_id") for c in (qa.get("criterion_coverage") or []) if not c.get("passed")]
        blockers.append(f"qa-not-verified ({qa.get('status')}) for {candidate_sha}: failed criteria {failed}, "
                        f"open findings {qa.get('open_finding_ids')}")
    return ci, qa, blockers


def _hosted_reviews(
    ctx: Any, agy: str, qa_rec: dict[str, Any], *, head_branch: str, candidate_sha: str, base_sha: str, tokens: list[str],
    limit_s: int = 900,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Security, then independent review from the factory's own entry points for the exact head (#104), wired as
    delivery wires them for a child; the records they write in `ctx.child_dir` are the evidence."""
    common = {"repo": ctx.repo, "home": ctx.home, "child_dir": ctx.child_dir, "child": {**ctx.child_contract, "head_branch": head_branch},
              "conf": ctx.conf, "base_sha": base_sha, "candidate_sha": candidate_sha, "agy_bin": agy,
              "builder_session_id": QUALIFICATION_BUILDER_SESSION}
    recs: dict[str, dict[str, Any]] = {}
    sec_record: dict[str, Any] | None = None
    blockers: list[str] = []
    for key, role, ok_key in (("security", "security", "ready"), ("independent_review", "independent", "review_verified")):
        base = {"candidate_sha": candidate_sha, "reviewer_bin": agy, "builder_session_id": QUALIFICATION_BUILDER_SESSION}
        if key == "independent_review" and recs["security"]["status"] != "verified":
            recs[key] = {**base, "status": "not-run", "reason": "security-review-not-verified", "reviewer_session_id": None}
            continue
        try:
            if key == "security":
                rec = security_review.review_candidate_security(**common, deadline=time.monotonic() + limit_s, limit_s=limit_s)
            else:
                rec = independent_review.review_candidate_independently(
                    **common, qa_record=qa_rec, security_record=sec_record,
                    deadline=time.monotonic() + limit_s, limit_s=limit_s)
        except Exception as exc:  # the entry point could not run: no record, unavailable, blocked
            msg = str(redact_qualification_tokens(str(exc), tokens))
            recs[key] = {**base, "status": "unavailable", "reason": msg, "reviewer_session_id": None}
            blockers.append(f"{role}-review-unavailable for {candidate_sha}: {msg}")
            continue
        ok = rec.get(ok_key) is True and rec.get("reviewed_revision") == candidate_sha
        sec_record = rec if key == "security" else sec_record
        recs[key] = {**base, "status": "verified" if ok else "not-verified", "outcome": rec.get("outcome"),
                     "reviewer_session_id": rec.get("reviewer_session_id"),
                     "record_path": str(ctx.child_dir / f"{role}-review.json")}  # the entry point's own record
        if not ok:
            blockers.append(f"{role}-review-not-verified ({rec.get('outcome')}) for {candidate_sha}")
    return recs["security"], recs["independent_review"], blockers


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
    scenario_ctx: Any = None,
    file_changes: dict[str, str] | None = None,
    approve: bool = True,
    expected_logins: dict[str, str] | None = None,
    builder: str = "integrator",
) -> dict[str, Any]:
    """Prepare genuine qualification candidate, PR, and prerequisite evidence.

    With `scenario_ctx` (#108), CI and QA come from the delivery chain's own entry points for the exact head. The
    `builder` role's token builds `head_branch` from `file_changes` (or reuses its open PR) and the other role approves;
    `approve=False` stops before the operator-account approval.
    """
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    tokens = [integrator_token or "", competitor_token or ""]
    local_ledger = ledger or QualificationLedger(evidence_dir / "operation-ledger.jsonl", tokens)
    who: dict[str, dict[str, Any]] = {}  # observed identities by role
    approver = "competitor" if builder == "integrator" else "integrator"
    role_tok = {"integrator": integrator_token, "competitor": competitor_token}

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
                "actor": (who.get(builder) or {}).get("login"),  # the builder role's token creates the candidate
                "session_id": QUALIFICATION_BUILDER_SESSION,
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
        base_url, repo_slug, integrator_token, expected_login=(expected_logins or {}).get("integrator"),
        expected_role="admin", role_name="integrator", ledger=local_ledger,
    )
    ok_comp, obs_comp, comp_blockers = observe_identity_and_permissions(
        base_url, repo_slug, competitor_token, expected_login=(expected_logins or {}).get("competitor"),
        expected_role="write", role_name="competitor", ledger=local_ledger,
    )
    ok_prot, top_rec, prot_blockers = check_branch_protection_and_topology(
        base_url, repo_slug, integrator_token, branches=("main", target_branch), ledger=local_ledger,
    )
    ok_seed, seed_rec, seed_blockers = check_seed_and_workflow_capabilities(
        base_url, repo_slug, target_branch, integrator_token, ledger=local_ledger,
    )

    who.update(integrator=obs_int, competitor=obs_comp)
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
                base_url, repo_slug, base_sha, head_branch, role_tok[builder],
                file_changes=file_changes or {"src/calc.py": CALC_CANDIDATE_SRC, "tests/test_calc.py": CALC_CANDIDATE_TEST},
                message=f"feat: qualification candidate on {head_branch} (#67)",
                actor=builder, ledger=local_ledger,
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
            token=role_tok[builder], actor=builder, ledger=local_ledger,
        )
        if code_pr not in (200, 201):
            prep_blockers.append(f"pr-creation-failed: candidate PR creation returned HTTP {code_pr}: {pr_msg}")
        else:
            pr_data = pr_res

    pr_num = (pr_data or {}).get("number", 0)
    pr_head_sha = (pr_data or {}).get("head", {}).get("sha", pr_head_sha)
    pr_base_sha = (pr_data or {}).get("base", {}).get("sha", pr_base_sha)

    # 3-4. CI gate and automated QA for the exact candidate head.
    if scenario_ctx is not None:
        if pr_data and pr_head_sha != "unavailable":
            ci_rec, qa_rec, gated = _gated_ci_and_qa(
                scenario_ctx, base_url, repo_slug, integrator_token, pr_data, head_branch=head_branch,
                base_branch=target_branch, candidate_sha=pr_head_sha, base_sha=pr_base_sha, tokens=tokens,
            )
        else:
            ci_rec = qa_rec = {"status": "unavailable", "reason": "no-candidate-pr", "qa_verified": False}
            gated = ["ci-unavailable: no candidate pull request to verify"]
        ok_ci, ok_qa = ci_rec.get("status") == "verified", qa_rec.get("qa_verified") is True
        prep_blockers.extend(gated)
    else:
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
                safe_dir(pdir, create=False)  # refuse a symlinked checkout; never write through the link
                shutil.rmtree(pdir, ignore_errors=True)  # never reuse a leftover checkout
                clone_remote_repo(pdir, repo_slug, integrator_token)
                fetch_remote_repo(pdir, repo_slug, integrator_token)
                subprocess.run(["git", "checkout", "-q", "--detach", pr_head_sha], cwd=pdir, check=True, capture_output=True)
            except (RuntimeError, subprocess.CalledProcessError, UsageError) as exc:
                prep_blockers.append(f"candidate-checkout-failed: {exc}")
                pdir = None
        ok_qa, qa_rec, qa_blockers = _qa_on_candidate(pdir, pr_head_sha, qa_cases)
        prep_blockers.extend(qa_blockers)

    # 5. Security & independent review: only a reviewer-produced record counts; an executable on PATH is not a review.
    # The real reviewers run (#104) only in the scenario context, after CI and QA verified this exact head.
    resolved_agy = resolve_agy_bin(agy_bin)
    if resolved_agy and scenario_ctx is not None and ok_ci and ok_qa:
        sec_rec, ir_rec, rev_blockers = _hosted_reviews(
            scenario_ctx, resolved_agy, qa_rec, head_branch=head_branch, candidate_sha=pr_head_sha, base_sha=pr_base_sha,
            tokens=tokens)
        prep_blockers.extend(rev_blockers)
    else:
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
    if pr_num and prereqs_passed and approve:
        code_rev, rev_sub_data, rev_msg = submit_qualification_pr_review(
            base_url, repo_slug, pr_num, pr_head_sha, event="APPROVE",
            body=f"Operator-account approval: CI, QA, security and independent review passed for {pr_head_sha}.",
            token=role_tok[approver], actor=approver, ledger=local_ledger,
        )
        if code_rev not in (200, 201):
            prep_blockers.append(f"review-submission-failed: PR review submission returned HTTP {code_rev}: {rev_msg}")
            gh_rev_rec = {"status": "submission-failed", "http_code": code_rev}
        else:
            rid = rev_sub_data.get("id", 0)
            ok_vrev, gh_rev_rec, vrev_blockers = verify_qualification_pr_review(
                base_url, repo_slug, pr_num, rid, pr_head_sha, expected_reviewer=who[approver].get("login"),
                token=integrator_token, ledger=local_ledger,
            )
            gh_rev_rec = {**gh_rev_rec, "kind": "operator-account-approval", "independent_review": False}
            prep_blockers.extend(vrev_blockers)
    else:
        reason = "approval-not-requested" if prereqs_passed and approve is False else "prerequisites-not-passed"
        gh_rev_rec = {"status": "not-requested", "reason": reason if pr_num else "no-pr", "head_sha": pr_head_sha}

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
    """Scenario 1: the PR preparation created in this run lands through the factory boundary, then is verified."""
    sdir = safe_dir(evidence_dir / "scenarios" / "confirmed_landing", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    code, base_c, _ = get_remote_commit(base_url, repo_slug, base_branch, integrator_token, ledger=sc_ledger)
    main_sha_before = gitio.remote_ref(ctx.repo, "main") or gitio.commit_sha(ctx.repo, "refs/heads/main")
    sc1_child = ctx.child_dir  # the folder where preparation stored this head's CI, QA and reviewer records (#104)
    pr = (prep_record or {}).get("pr") or {}  # the PR, head and base preparation created and verified in this run
    pr_num, cand_sha = int(pr.get("number") or 0), pr.get("head_sha") or ctx.cand_sha
    base_sha = pr.get("base_sha") or (base_c.get("sha", ctx.base_sha) if code == 200 else ctx.base_sha)
    cand_branch = (prep_record or {}).get("head_branch") or cand_branch
    if not allow_test_origin:
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
    pre = (prep_record or {}).get("prerequisites") or {}
    ci, rev = pre.get("ci") or {}, pre.get("github_review") or {}  # credited only for the SHA this scenario lands
    ci_ok = ci.get("status") == "verified" and ci.get("candidate_sha") == cand_sha
    ok_rev = rev.get("state") == "APPROVED" and rev.get("commit_id") == cand_sha
    ci_blks = [] if ci_ok else [f"ci-not-verified: candidate preparation recorded no verified CI for {cand_sha}"]
    rev_blks = [] if ok_rev else [f"approval-not-recorded: candidate preparation recorded no operator-account approval for {cand_sha}"]
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
    allow_test_origin: bool = False, run_id: str = "", opened: list[int] | None = None,
) -> dict[str, Any]:
    """Scenario 2: Missing/stale prereqs, protection denial (405), and permissions denial (403).

    Hosted, the run builds its own candidate whose factory prerequisites pass but which has no provider approval, so
    the factory attempts the merge and the provider's protection is what denies it."""
    sdir = safe_dir(evidence_dir / "scenarios" / "prereq_missing_and_denied", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    main_sha_before = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    cand_sha, base_sha = ctx.cand_sha, ctx.base_sha
    unapp_branch, unapp_pr_num = f"{CANDIDATE_BRANCH_PREFIX}{run_id}-sc2", 0
    if not allow_test_origin:
        c2 = _candidate_ctx(ctx, unapp_branch)
        prep2 = prepare_qualification_candidate(
            base_url, repo_slug, sdir, target_branch=base_branch, head_branch=unapp_branch, integrator_token=integrator_token,
            competitor_token=competitor_token, ledger=sc_ledger, file_changes=_calc_changes(unapp_branch), approve=False,
            scenario_ctx=c2)
        pr2 = prep2.get("pr") or {}
        unapp_pr_num, cand_sha, base_sha = int(pr2.get("number") or 0), pr2.get("head_sha") or cand_sha, pr2.get("base_sha") or base_sha
        if opened is not None and unapp_pr_num: opened.append(unapp_pr_num)
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
    unapp_cand_sha = cand_sha
    protection_denial_observed, permission_denial_observed, pr_still_open = True, True, True
    prot_res: dict[str, Any] = {"status": "denied-protection", "blockers": []}
    perm_res = {"status": "denied-permissions", "blockers": []}
    if not allow_test_origin:
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
        unapp_res = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=c2.child_dir,
            child={**ctx.child_contract, "head_branch": unapp_branch}, conf=ctx.conf, pr_number=unapp_pr_num,
            candidate_sha=unapp_cand_sha, base_sha=base_sha, head_branch=unapp_branch, base_branch=base_branch,
            approval_record=_delivery_gate(c2, unapp_cand_sha, base_sha, c2.child_dir, unapp_branch),
            repo_slug=repo_slug, base_url=base_url, token=integrator_token,
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
    allow_test_origin: bool = False, run_id: str = "", opened: list[int] | None = None,
) -> tuple[dict[str, Any], str, str, int]:
    """Scenario 3: a verified candidate of this run meets a competitor advance that the competitor merges inside the
    factory's pre-merge boundary (on_before_merge); integrate_approved_child must reject it and leave it unmerged."""
    sdir = safe_dir(evidence_dir / "scenarios" / "competing_base_rejection", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    main_sha_before = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    cand_branch, adv_branch = f"{CANDIDATE_BRANCH_PREFIX}{run_id}-sc3", f"{CANDIDATE_BRANCH_PREFIX}{run_id}-sc3-advance"
    c3 = _candidate_ctx(ctx, cand_branch)
    prep = prepare_qualification_candidate(
        base_url, repo_slug, sdir, target_branch=base_branch, head_branch=cand_branch, integrator_token=integrator_token,
        competitor_token=competitor_token, ledger=sc_ledger, file_changes=_calc_changes(cand_branch), scenario_ctx=c3)
    pr = prep.get("pr") or {}
    cand_pr_num, cand_sha, base_sha_b = int(pr.get("number") or 0), str(pr.get("head_sha") or ""), str(pr.get("base_sha") or "")
    # The competitor's advance: its own verified candidate from the same base (touching only the tests file, so the
    # renewal merges cleanly), approved by the integrator, and landed by the competitor through the factory.
    adv_ctx = _candidate_ctx(ctx, adv_branch)
    adv = prepare_qualification_candidate(
        base_url, repo_slug, sdir / "advance", target_branch=base_branch, head_branch=adv_branch, base_sha=base_sha_b,
        integrator_token=integrator_token, competitor_token=competitor_token, ledger=sc_ledger, scenario_ctx=adv_ctx,
        file_changes={"tests/test_calc.py": CALC_CANDIDATE_TEST + f"\n# competing base advance {adv_branch}\n"},
        builder="competitor")
    adv_pr = adv.get("pr") or {}
    adv_pr_num, adv_sha = int(adv_pr.get("number") or 0), str(adv_pr.get("head_sha") or "")
    if opened is not None: opened.extend(n for n in (cand_pr_num, adv_pr_num) if n)
    adv_merge: dict[str, Any] = {"attempted": False}

    def _advance() -> None:  # the competitor's own landing, made at the factory's pre-merge boundary
        adv_res = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=adv_ctx.child_dir, child={**ctx.child_contract, "head_branch": adv_branch},
            conf=ctx.conf, pr_number=adv_pr_num, candidate_sha=adv_sha, base_sha=base_sha_b, head_branch=adv_branch,
            base_branch=base_branch, approval_record=_delivery_gate(adv_ctx, adv_sha, base_sha_b, adv_ctx.child_dir, adv_branch),
            repo_slug=repo_slug, base_url=base_url, token=competitor_token,
        )
        adv_merge.update(attempted=True, status=adv_res.status, merged=adv_res.status == "confirmed", sha=adv_res.landed_sha,
                         blockers=adv_res.blockers)

    fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
    res_cand = integrate_approved_child(
        repo=ctx.repo, home=ctx.home, child_dir=c3.child_dir, child={**ctx.child_contract, "head_branch": cand_branch},
        conf=ctx.conf, pr_number=cand_pr_num, candidate_sha=cand_sha, base_sha=base_sha_b, head_branch=cand_branch,
        base_branch=base_branch, approval_record=_delivery_gate(c3, cand_sha, base_sha_b, c3.child_dir, cand_branch),
        repo_slug=repo_slug, base_url=base_url, token=integrator_token, on_before_merge=_advance,
    )
    new_base_b_prime = adv_merge.get("sha") if adv_merge.get("merged") else None
    code_c, pr_c, _ = _api("GET", base_url, repo_slug, f"pulls/{cand_pr_num}", integrator_token, ledger=sc_ledger)
    cand_unmerged = (pr_c.get("state") == "open" and pr_c.get("merged") is not True) if code_c == 200 else None
    rejection_observed = res_cand.status in ("rejected-competing-base", "stale-base-revision") and bool(new_base_b_prime)
    main_sha_after = _read_remote_main(base_url, repo_slug, integrator_token, sc_ledger)
    main_preserved = _main_preserved(main_sha_before, main_sha_after)
    passed = (rejection_observed and cand_unmerged is True and main_preserved is True)
    sc_data = {
        "name": "competing_base_rejection", "scenario": "competing_base_rejection",
        "status": res_cand.status, "outcome": "verified" if passed else "failed",
        "initial_base_sha": base_sha_b, "advanced_base_sha": new_base_b_prime,
        "candidate_sha": cand_sha, "candidate_pr_number": cand_pr_num, "head_branch": cand_branch,
        "candidate_prepared": prep.get("status") == "prepared",
        "advance_pr_number": adv_pr_num, "advance_prepared": adv.get("status") == "prepared",
        "advance_merge": adv_merge, "candidate_merge_status": res_cand.status, "candidate_merge_blockers": res_cand.blockers,
        "denial_source": _denial_source(res_cand), "candidate_unmerged": cand_unmerged, "main_preserved": main_preserved,
        "main_sha_before": main_sha_before, "main_sha_after": main_sha_after,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data, cand_branch, new_base_b_prime or "", cand_pr_num


def run_scenario_4_renewed_verification_after_base_change(
    base_url: str, repo_slug: str, evidence_dir: Path, ctx: Any,
    integrator_token: str, competitor_token: str, cand_branch: str,
    base_sha_b_prime: str, cand_pr_num: int, *,
    base_branch: str = "feature/demo", ledger: QualificationLedger | None = None,
    allow_test_origin: bool = False,
) -> dict[str, Any]:
    """Scenario 4: scenario 3's evidence is rejected as stale against B'; the provider merges B' into the head (no force
    push, read from the provider's ref history); the renewed head is verified, approved and landed on B'."""
    sdir = safe_dir(evidence_dir / "scenarios" / "renewed_verification_after_base_change", create=True)
    tokens = [integrator_token, competitor_token]
    sc_ledger = ledger or QualificationLedger(sdir / "operation-ledger.jsonl", tokens)
    main_sha_before = gitio.remote_ref(ctx.repo, "main") or gitio.commit_sha(ctx.repo, "refs/heads/main")
    _, pr_old, _ = _api("GET", base_url, repo_slug, f"pulls/{cand_pr_num}", integrator_token, ledger=sc_ledger)
    old_sha = str((pr_old.get("head") or {}).get("sha") or "")
    stale_gate = deliver_module.enforce_delivery_approval(  # scenario 3's records for the old head, judged against B'
        candidate_sha=old_sha, base_sha=base_sha_b_prime, repo=ctx.repo, home=ctx.home,
        child_dir=_candidate_ctx(ctx, cand_branch).child_dir, child={**ctx.child_contract, "head_branch": cand_branch}, conf=ctx.conf,
    )
    old_evidence_status = stale_gate.get("status")
    old_evidence_rejected = stale_gate.get("delivery_approved") is False and str(old_evidence_status).startswith("stale-")
    u_code, _, u_msg = _api("PUT", base_url, repo_slug, f"pulls/{cand_pr_num}/update-branch", integrator_token,
                            {"expected_head_sha": old_sha}, sc_ledger)
    new_sha, deadline = old_sha, time.monotonic() + 120.0
    while u_code in (200, 202) and new_sha == old_sha and time.monotonic() < deadline:  # the update is asynchronous
        _, pr_now, _ = _api("GET", base_url, repo_slug, f"pulls/{cand_pr_num}", integrator_token)
        new_sha = str((pr_now.get("head") or {}).get("sha") or old_sha)
        time.sleep(0 if new_sha != old_sha else 2.0)
    ref = quote(f"refs/heads/{cand_branch}", safe="")
    forced = _get_list(f"{base_url.rstrip('/')}/repos/{repo_slug}/activity?ref={ref}&activity_type=force_push", integrator_token)
    no_force_push = (not forced) if forced is not None else None  # None: the provider's ref history was not readable
    int_res, landed_sha, renewed_sha, renewed_base = None, None, None, None
    land_ok, land_details, blockers = False, {}, [] if u_code in (200, 202) else [f"update-branch HTTP {u_code}: {u_msg}"]
    if new_sha != old_sha and no_force_push is True:
        c4 = _candidate_ctx(ctx, cand_branch, "-renewed")
        prep = prepare_qualification_candidate(
            base_url, repo_slug, sdir, target_branch=base_branch, head_branch=cand_branch, base_sha=base_sha_b_prime,
            integrator_token=integrator_token, competitor_token=competitor_token, ledger=sc_ledger, scenario_ctx=c4)
        pr = prep.get("pr") or {}
        renewed_sha, renewed_base = pr.get("head_sha"), pr.get("base_sha")
        fetch_remote_repo(ctx.repo, repo_slug, integrator_token)
        int_res = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=c4.child_dir, child={**ctx.child_contract, "head_branch": cand_branch},
            conf=ctx.conf, pr_number=cand_pr_num, candidate_sha=renewed_sha, base_sha=renewed_base, head_branch=cand_branch,
            base_branch=base_branch, approval_record=_delivery_gate(c4, renewed_sha, renewed_base, c4.child_dir, cand_branch),
            repo_slug=repo_slug, base_url=base_url, token=integrator_token,
        )
        landed_sha = int_res.landed_sha
        land_ok, land_details, land_blks = assert_landed_landing_properties(
            ctx.repo, landed_sha or "", renewed_base, renewed_sha, int_res.tested_sha, base_branch, main_sha_before,
            token=integrator_token, repo_slug=repo_slug,
        )
        blockers += prep.get("blockers", []) + int_res.blockers + land_blks
    passed = (int_res is not None and int_res.status == "confirmed" and bool(landed_sha) and land_ok and old_evidence_rejected
              and renewed_base == base_sha_b_prime)
    sc_data = {
        "name": "renewed_verification_after_base_change",
        "scenario": "renewed_verification_after_base_change",
        "status": int_res.status if int_res else "not-renewed", "outcome": "verified" if passed else "failed",
        "old_evidence_rejected": old_evidence_rejected, "old_evidence_status": old_evidence_status,
        "old_candidate_sha": old_sha, "head_merged_without_force_push": no_force_push,
        "renewed_candidate_sha": renewed_sha or (new_sha if new_sha != old_sha else None), "renewed_base_sha": renewed_base,
        "landed_sha": landed_sha, "pr_number": cand_pr_num, "head_branch": cand_branch,
        "landing_properties": land_details, "blockers": blockers,
        "simulated": allow_test_origin, "artifacts": [str(sdir / "scenario-result.json")],
        "recorded_at": approval_mod.now(),
    }
    atomic_json(sdir / "scenario-result.json", redact_qualification_tokens(sc_data, tokens), evidence_dir)
    return sc_data


class _ScenarioContextUnavailable(Exception):
    """The hosted repository cannot supply a scenario context; the reason is recorded as a blocker."""


def _policy_conf(paths: RuntimePaths, policy: dict[str, Any]) -> config_module.Config:
    """Factory config the gate uses for a seeded repository: gate 3 guards the policy's protected paths."""
    return config_module.with_gate(
        config_module.skeleton(paths), "3",
        config_module.GateConfig(kind="protected-paths", label="protected paths", paths=tuple(policy.get("protected_paths", ()))),
    )


def plan_seed_install(repo_slug: str, branch: str) -> dict[str, Any]:
    """Seed files (factory/X -> .factory/X) and the target branch's required contexts = the gate's check names."""
    if repo_slug not in DISPOSABLE_REPO_ALLOWLIST:
        raise UsageError(f"repo-disallowed: {repo_slug!r} is not in disposable allowlist {sorted(DISPOSABLE_REPO_ALLOWLIST)}")
    if branch not in ALLOWED_TARGET_BRANCHES:
        raise UsageError(f"target-branch-disallowed: {branch!r} is not an allowed seed target {sorted(ALLOWED_TARGET_BRANCHES)}")
    files: dict[str, str] = {}
    for f in sorted(p for p in SEED_ASSETS_DIR.rglob("*") if p.is_file()):
        rel = f.relative_to(SEED_ASSETS_DIR).as_posix()
        files[".factory/" + rel.removeprefix("factory/") if rel.startswith("factory/") else rel] = f.read_text(encoding="utf-8")
    policy, child = json.loads(files[".factory/policy.json"]), json.loads(files[".factory/child-contract.json"])
    conf = _policy_conf(RuntimePaths(repo=SEED_ASSETS_DIR, home=SEED_ASSETS_DIR), policy)
    contexts = [r["name"] for r in build_required_ci_checks(child, conf)]
    return {"repo_slug": repo_slug, "branch": branch, "files": files, "required_status_contexts": contexts}


def install_seed(
    base_url: str, repo_slug: str, branch: str, token: str, *, dry_run: bool,
    files_token: str | None = None, allow_test_origin: bool = False,
) -> dict[str, Any]:
    """Dry run returns the plan with no request. Apply opens a candidate-prefix PR with the seed files into the
    target branch and sets that branch's required status contexts; `main` and other branches are never touched.
    `files_token` (default `token`) authors the seed branch and PR; it needs the `workflow` scope for ci.yml."""
    plan = plan_seed_install(repo_slug, branch)
    if dry_run:
        return {"dry_run": True, "plan": plan}
    if not allow_test_origin and base_url.rstrip("/") != HOSTED_API_ORIGIN:
        raise UsageError(f"wrong-origin: {base_url!r} is not {HOSTED_API_ORIGIN}")
    head, steps = f"{CANDIDATE_BRANCH_PREFIX}seed-install", []
    res: dict[str, Any] = {"dry_run": False, "plan": plan, "head_branch": head, "steps": steps, "status": "failed"}
    ftok = files_token or token
    code, base_c, msg = get_remote_commit(base_url, repo_slug, branch, token)
    base_sha = str(base_c.get("sha") or "") if code == 200 else ""
    steps.append({"step": "read-target-head", "http": code, "sha": base_sha or None, "message": msg})
    if not base_sha:
        return res
    commit_sha, _ = create_qualification_candidate_commit(
        base_url, repo_slug, base_sha, head, ftok, plan["files"], "setup: install gate-compatible qualification seed (#109)")
    steps.append({"step": "seed-commit", "branch": head, "sha": commit_sha or None})
    if not commit_sha:
        return res
    p_code, pr, p_msg = create_qualification_pull_request(
        base_url, repo_slug, head, branch, "setup: install gate-compatible qualification seed",
        "Installs the seed from turbo examples/qualification/seed (#109).", ftok)
    if p_code not in (200, 201):  # an open seed PR from an earlier apply is reused; the branch now holds the new commit
        pr = next(iter(get_remote_pulls(base_url, repo_slug, head, ftok)), {})
    steps.append({"step": "seed-pr", "http": p_code, "number": pr.get("number"), "html_url": pr.get("html_url"), "message": p_msg})
    if not pr.get("number"):
        return res
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/branches/{quote(branch, safe='')}/protection/required_status_checks"
    c_code, c_data, c_msg = _http_req("PATCH", url, token, base_url, [], time.monotonic() + 15.0, 15,
                                      payload={"strict": True, "contexts": plan["required_status_contexts"]})
    steps.append({"step": "required-contexts", "http": c_code, "contexts": c_data.get("contexts"), "message": c_msg})
    res["status"] = "applied" if c_code == 200 else "failed"
    return res


@contextlib.contextmanager
def hosted_scenario_context(
    ws_root: Path, repo_slug: str, token: str, *,
    branch: str = "feature/demo", head_branch: str = "feat/qual-candidate-101", blockers: list[str] | None = None,
) -> Iterator[SimpleNamespace]:
    """Clone the hosted repository into a private workspace and yield the scenario context; no test fakes.

    The context carries no reviewer and no prerequisite records, so delivery gates stay closed until real
    reviewer records exist for a candidate.
    """
    shutil.rmtree(ws_root, ignore_errors=True)  # fresh clone and private home every run
    safe_dir(ws_root, create=True)
    repo, home = ws_root / "live_repo", safe_dir(ws_root / "home", create=True)
    clone_remote_repo(repo, repo_slug, token)
    fetch_remote_repo(repo, repo_slug, token)
    subprocess.run(["git", "checkout", "-q", "-B", branch, f"origin/{branch}"], cwd=repo, check=True, capture_output=True)
    policy = json.loads((repo / ".factory" / "policy.json").read_text(encoding="utf-8"))
    contract = repo / ".factory" / "child-contract.json"
    if not contract.is_file():
        (blockers if blockers is not None else []).append("scenario-context-unavailable: hosted repository has no .factory/child-contract.json")
        raise _ScenarioContextUnavailable(".factory/child-contract.json missing")
    conf = _policy_conf(RuntimePaths(repo=repo, home=home), policy)
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
    expected_logins: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Execute hosted qualification or retain explicit blocked/unavailable status without mutation.

    `expected_logins` ({"integrator", "competitor"}) is configuration; without it the observed logins are accepted,
    recorded as unconfigured, and the run is blocked from qualifying. Each run builds its own uniquely named candidate
    branches and PRs under CANDIDATE_BRANCH_PREFIX and closes every PR it opened that is left unmerged."""
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
        base_url, repo_slug, integrator_token, expected_login=(expected_logins or {}).get("integrator"),
        expected_role="admin", role_name="integrator", ledger=ledger,
    )
    ok_comp, obs_comp, comp_blockers = observe_identity_and_permissions(
        base_url, repo_slug, competitor_token, expected_login=(expected_logins or {}).get("competitor"),
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
    configured = bool((expected_logins or {}).get("integrator") and (expected_logins or {}).get("competitor"))
    id_blockers = [] if configured else [
        "identity-expectations-unconfigured: TURBO_QUAL_EXPECTED_INTEGRATOR and TURBO_QUAL_EXPECTED_COMPETITOR are not "
        "both set; the observed logins were used and the run cannot qualify"]
    preflight_record = {
        "schema": 1, "role": "hosted-preflight-observations", "repo_slug": repo_slug,
        "base_url": base_url, "target_branch": branch,
        "identities": {"integrator": obs_int, "competitor": obs_comp},
        "identity_expectations": "configured" if configured else "unconfigured",
        "topology": top_rec, "seed_capabilities": seed_rec,
        "blockers": all_preflight_blockers + id_blockers,
        "status": "verified" if not all_preflight_blockers + id_blockers else "blocked",
        "simulated": allow_test_origin,
        "recorded_at": approval_mod.now(),
    }

    # 4. Open the hosted scenario context first: preparation records CI and QA evidence into its child folder (#108).
    scenarios: dict[str, Any] = {}
    scenario_blockers: list[str] = []
    run_id = f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{os.urandom(3).hex()}"  # names this run's branches
    opened: list[int] = []  # PRs this run opened; any left unmerged are closed on the way out
    cleanup: list[dict[str, Any]] = []

    def _close_opened() -> None:
        for n in dict.fromkeys(opened):
            code, pr, msg = _api("GET", base_url, repo_slug, f"pulls/{n}", integrator_token, ledger=ledger)
            if code == 200 and pr.get("state") == "open":
                code, pr, msg = _api("PATCH", base_url, repo_slug, f"pulls/{n}", integrator_token, {"state": "closed"}, ledger)
            cleanup.append({"pr_number": n, "http": code, "state": pr.get("state"), "merged": pr.get("merged"), "message": msg or None})

    with contextlib.ExitStack() as stack:
        stack.callback(_close_opened)
        ctx = None
        if not all_preflight_blockers and base_url.rstrip("/") != HOSTED_API_ORIGIN:
            scenario_blockers.append(f"scenario-context-unavailable: hosted scenarios need a clone from {HOSTED_API_ORIGIN}, not {base_url}")
        elif not all_preflight_blockers:
            try:  # a workspace that cannot be made private (e.g. a symlink) blocks; it is never written through
                ws_root = safe_dir(evidence_dir / "workspace", create=True)
                with contextlib.suppress(_ScenarioContextUnavailable):
                    ctx = stack.enter_context(hosted_scenario_context(
                        ws_root, repo_slug, integrator_token, branch=branch, blockers=scenario_blockers))
            except UsageError as exc:
                scenario_blockers.append(f"scenario-context-unavailable: {exc}")

        # 5. Candidate preparation (observes preflight blockers or prepares candidate)
        prep_record = prepare_qualification_candidate(
            base_url, repo_slug, evidence_dir,
            target_branch=branch,
            head_branch=f"{CANDIDATE_BRANCH_PREFIX}{run_id}-sc1",
            integrator_token=integrator_token,
            competitor_token=competitor_token,
            ledger=ledger,
            allow_test_origin=allow_test_origin,
            live_enabled=live_enabled,
            scenario_ctx=ctx,
            file_changes=_calc_changes(f"{CANDIDATE_BRANCH_PREFIX}{run_id}-sc1"),
            expected_logins=expected_logins,
        )
        if n := (prep_record.get("pr") or {}).get("number"): opened.append(n)

        if ctx is not None:
            if prep_record.get("candidate_sha") not in (None, "unavailable"):
                ctx.cand_sha = prep_record["candidate_sha"]  # the context opened before the candidate existed (#108)
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
                base_branch=branch, ledger=ledger, allow_test_origin=allow_test_origin, run_id=run_id, opened=opened,
            )
            scenarios["prereq_missing_and_denied"] = sc2_res

            # 3. Scenario 3: Competing base rejection
            sc3_res, cand_br3, base_b_prime, cand_pr3 = run_scenario_3_competing_base_rejection(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                base_branch=branch, ledger=ledger, allow_test_origin=allow_test_origin, run_id=run_id, opened=opened,
            )
            scenarios["competing_base_rejection"] = sc3_res

            # 4. Scenario 4: Renewed verification after base change
            sc4_res = run_scenario_4_renewed_verification_after_base_change(
                base_url, repo_slug, evidence_dir, ctx, integrator_token, competitor_token,
                cand_br3, base_b_prime, cand_pr3, base_branch=branch, ledger=ledger,
                allow_test_origin=allow_test_origin,
            )
            scenarios["renewed_verification_after_base_change"] = sc4_res

    # 6. Evidence index reduction
    parent_index = build_parent_evidence_index(scenarios, f_rev, mode="hosted")
    reduced_index, all_qual, red_blockers = reduce_evidence_index(
        parent_index, preflight_record, scenarios, preparation=prep_record,
    )

    run_blockers = list(dict.fromkeys(all_preflight_blockers + id_blockers + prep_record.get("blockers", []) + scenario_blockers
                                      + red_blockers))
    final_blockers = run_blockers + ["hosted-scenarios-5-and-6-pending-slice-5"]
    outcome = _run_outcome(scenarios, run_blockers, "slice-4-verified")
    res = {
        "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
        "status": "in-progress-slice-4-complete" if outcome == "slice-4-verified" else "blocked",
        "outcome": outcome,
        "qualified": False,
        "repo_slug": repo_slug, "blockers": final_blockers,
        "run_id": run_id, "preflight": preflight_record, "preparation": prep_record, "scenarios": scenarios, "cleanup": cleanup,
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
    parser.add_argument("--mode", choices=["hosted", "install-seed"], default="hosted")  # offline simulation: tests/qualification_offline.py
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--repo-slug", default="turbo-factory/turbo-qual-67")
    parser.add_argument("--branch", default="feature/demo")
    parser.add_argument("--base-url", default="https://api.github.com")
    parser.add_argument("--dry-run", action="store_true", help="install-seed: print the plan only (the default)")
    parser.add_argument("--apply", action="store_true", help="install-seed: perform the plan (needs live enablement)")
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    if args.mode == "install-seed":
        token, ftok = os.environ.get("TURBO_QUAL_INTEGRATOR_TOKEN") or "", os.environ.get("TURBO_QUAL_COMPETITOR_TOKEN") or None
        try:
            if args.apply and (args.dry_run or os.environ.get("TURBO_LIVE_QUALIFICATION") != "1" or not token):
                raise UsageError("install-seed --apply requires TURBO_LIVE_QUALIFICATION=1 and TURBO_QUAL_INTEGRATOR_TOKEN, without --dry-run")
            res = install_seed(args.base_url, args.repo_slug, args.branch, token, dry_run=not args.apply, files_token=ftok)
        except UsageError as exc:
            print(f"install-seed refused: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(redact_qualification_tokens(res, [token, ftok or ""]), indent=2))
        return 0 if res["dry_run"] or res.get("status") == "applied" else 2
    command = ["python3", "-m", "factory.qualification", *argv]

    ev_dir = Path(args.evidence_dir or os.environ.get("DEMO_KEEP_EVIDENCE_DIR", "/tmp/turbo-issue-67-evidence"))
    for stale in ("qualification-summary.json", "parent-evidence-index.json"):
        (ev_dir / stale).unlink(missing_ok=True)  # persisted results describe only this run
    tokens: list[str] = []
    try:
        if args.mode == "hosted":
            live_enabled = os.environ.get("TURBO_LIVE_QUALIFICATION") == "1"
            tokens = [os.environ.get("TURBO_QUAL_INTEGRATOR_TOKEN") or "", os.environ.get("TURBO_QUAL_COMPETITOR_TOKEN") or ""]
            logins = {role: os.environ.get(f"TURBO_QUAL_EXPECTED_{role.upper()}") or "" for role in ("integrator", "competitor")}
            res = run_hosted_qualification(
                args.repo_slug, ev_dir, live_enabled=live_enabled,
                integrator_token=tokens[0] or None, competitor_token=tokens[1] or None,
                base_url=args.base_url, branch=args.branch, expected_logins={k: v for k, v in logins.items() if v} or None,
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
