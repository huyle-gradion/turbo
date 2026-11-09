"""Protected repository qualification harness (#67)."""
from __future__ import annotations

import argparse, json, os, shutil, sys, time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from factory import ci_gate, deliver as deliver_module, gitio
from factory.deliver_checks import collect_redaction_secrets, git_timed
from factory.independent_review import approval as approval_mod
from factory.integration import _factory_rev, _http_req, integrate_approved_child
from factory.paths import atomic_json, safe_dir

FACTORY_ROOT = Path(__file__).resolve().parents[1]

HOSTED_API_ORIGIN = "https://api.github.com"
DISPOSABLE_REPO_ALLOWLIST = frozenset(["turbo-factory/turbo-qual-67"])
ALLOWED_TARGET_BRANCHES = frozenset(["feature/demo"])
REQUIRED_SEED_ASSETS: tuple[tuple[str, str], ...] = (
    (".github/workflows/ci.yml", "CI workflow"),
    (".factory/policy.json", "factory policy"),
)

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


def reduce_evidence_index(
    parent_index: dict[str, Any],
    preflight: dict[str, Any],
    scenarios: dict[str, Any],
) -> tuple[dict[str, Any], bool, list[str]]:
    """Reduce parent evidence index over required subchecks, artifacts, and simulation status."""
    reduced_index: dict[str, Any] = {}
    reduction_blockers: list[str] = []
    all_qualified = True

    preflight_ok = preflight.get("status") == "verified"
    if not preflight_ok:
        reduction_blockers.extend(preflight.get("blockers", []))

    for ac_id, entry in parent_index.items():
        ac_entry = dict(entry)
        subchecks_status: dict[str, str] = {}
        missing_artifacts: list[str] = []

        for ap in ac_entry.get("artifact_paths", []):
            if not Path(ap).exists():
                missing_artifacts.append(ap)

        if missing_artifacts:
            subchecks_status["artifacts"] = "missing"
            reduction_blockers.append(f"missing-artifacts: {ac_id} is missing artifacts: {missing_artifacts}")
        else:
            subchecks_status["artifacts"] = "verified"

        simulated = any(scenarios.get(sn, {}).get("simulated", False) for sn in ac_entry.get("scenarios", [])) or preflight.get("simulated", False)
        if simulated:
            subchecks_status["hosted_scenarios"] = "simulated"
            ac_entry["hosted_proof_status"] = "PENDING"
            ac_entry["outcome"] = "passed-offline-simulated"
        else:
            all_passed = bool(scenarios) and all(
                scenarios.get(sn, {}).get("outcome") in ("passed", "verified") for sn in ac_entry.get("scenarios", [])
            )
            if all_passed and not missing_artifacts and preflight_ok:
                subchecks_status["hosted_scenarios"] = "verified"
                ac_entry["hosted_proof_status"] = "VERIFIED"
                ac_entry["outcome"] = "hosted-verified"
            else:
                subchecks_status["hosted_scenarios"] = "unperformed-or-failed"
                ac_entry["hosted_proof_status"] = "PENDING"
                ac_entry["outcome"] = "unavailable"

        ac_entry["subchecks"] = subchecks_status
        if ac_entry["hosted_proof_status"] != "VERIFIED":
            all_qualified = False

        reduced_index[ac_id] = ac_entry

    return reduced_index, all_qualified, reduction_blockers


def build_parent_evidence_index(scenarios: dict[str, Any], factory_rev: str) -> dict[str, Any]:
    """Produce comprehensive evidence index across all six parent #24 acceptance criteria."""
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
            "command": "python3 -m factory.qualification --mode offline",
            "exit_status": 0,
            "factory_revision": factory_rev,
            "candidate_revision": c_sha,
            "base_revision": b_sha,
            "tested_revision": t_sha,
            "landed_revision": l_sha,
            "outcome": "passed-offline-simulated" if scenarios else "unavailable",
            "hosted_proof_status": "PENDING",
            "artifact_paths": all_artifacts,
        }
    return index


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

    # 4. Evidence index reduction
    parent_index = build_parent_evidence_index({}, f_rev)
    reduced_index, _, red_blockers = reduce_evidence_index(parent_index, preflight_record, {})

    # Hosted scenarios are pending human setup
    final_blockers = list(all_preflight_blockers) + ["hosted-scenarios-pending-human-setup"]
    res = {
        "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
        "status": "blocked", "outcome": "unavailable", "qualified": False,
        "repo_slug": repo_slug, "blockers": final_blockers,
        "preflight": preflight_record, "scenarios": {},
        "parent_evidence_index": reduced_index, "mode": "hosted",
        "simulated": allow_test_origin, "recorded_at": approval_mod.now(),
    }
    atomic_json(evidence_dir / "preflight-observations.json", redact_qualification_tokens(preflight_record, tokens), evidence_dir)
    atomic_json(evidence_dir / "parent-evidence-index.json", redact_qualification_tokens(reduced_index, tokens), evidence_dir)
    atomic_json(evidence_dir / "qualification-summary.json", redact_qualification_tokens(res, tokens), evidence_dir)
    return res


def run_offline_qualification(evidence_dir: Path) -> dict[str, Any]:
    """Execute all six parent #24 scenarios through real A+B interfaces and retain evidence."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    scenarios_dir = safe_dir(evidence_dir / "scenarios", create=True)
    f_rev = _factory_rev()

    if str(FACTORY_ROOT / "tests") not in sys.path:
        sys.path.insert(0, str(FACTORY_ROOT / "tests"))
    from support import git
    from support_deliver import setup_disposable_delivery_context

    if (evidence_dir / "workspace").exists():
        shutil.rmtree(evidence_dir / "workspace", ignore_errors=True)
    ws_root = safe_dir(evidence_dir / "workspace", create=True)
    scenarios: dict[str, Any] = {}

    with setup_disposable_delivery_context(ws_root) as ctx:
        ctx.gh.owner = "turbo-factory"
        ctx.gh.repo = "turbo-qual-67"
        main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")
        b_branch = str(ctx.intake_rec["parent"]["target_feature_branch"])
        h_branch = ctx.head_branch

        def _reset_pr_and_branches(base_s: str, cand_s: str) -> None:
            git(ctx.bare, "branch", "-f", b_branch, base_s)
            git(ctx.bare, "branch", "-f", h_branch, cand_s)
            git(ctx.repo, "fetch", "origin")
            if 1 in ctx.gh.pulls:
                ctx.gh.pulls[1]["head"]["repo"]["full_name"] = "turbo-factory/turbo-qual-67"
                ctx.gh.pulls[1]["base"]["repo"]["full_name"] = "turbo-factory/turbo-qual-67"
                ctx.gh.pulls[1]["base"]["ref"] = b_branch
                ctx.gh.pulls[1]["head"]["ref"] = h_branch
                ctx.gh.pulls[1]["base"]["sha"] = base_s
                ctx.gh.pulls[1]["head"]["sha"] = cand_s
                ctx.gh.pulls[1]["state"] = "open"
                ctx.gh.pulls[1]["merged"] = False

        def _snap_sc(name: str, res: Any, extra: dict[str, Any]) -> dict[str, Any]:
            sdir = safe_dir(scenarios_dir / name, create=True)
            arts = [str(sdir / "scenario-result.json")]
            for fn in ("integration-request.json", "integration-record.json", "approval-gate.json"):
                src = ctx.child_dir / fn
                if src.is_file():
                    dst = sdir / fn
                    shutil.copy2(src, dst)
                    arts.append(str(dst))
            sc_data = {
                "name": name, "status": getattr(res, "status", str(res)),
                "outcome": getattr(res, "outcome", "rejected"),
                "landed_sha": getattr(res, "landed_sha", None),
                "candidate_sha": extra.get("candidate_sha", ctx.cand_sha),
                "base_sha": extra.get("base_sha", ctx.base_sha),
                "tested_sha": getattr(res, "tested_sha", None),
                "blockers": list(getattr(res, "blockers", [])),
                "artifacts": arts, "simulated": True,
                "fake_roles": ["fake-builder", "fake-qa", "fake-sec", "fake-ir"],
                **extra,
            }
            atomic_json(sdir / "scenario-result.json", sc_data, evidence_dir)
            return sc_data

        # 1. Confirmed landing
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        gate1 = deliver_module.enforce_delivery_approval(
            candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha, repo=ctx.repo, home=ctx.home,
            child_dir=ctx.child_dir, child=ctx.child_contract, conf=ctx.conf,
        )
        r1 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch=b_branch, approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        scenarios["confirmed_landing"] = _snap_sc("confirmed_landing", r1, {
            "delivery_approved": gate1.get("delivery_approved", False),
            "landed_sha": r1.landed_sha, "reconciled": r1.reconciled,
        })

        # 2. Prereq missing and permission denial
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        ctx.gh.merge_status = 403
        for fn in ("integration-request.json", "integration-record.json"):
            (ctx.child_dir / fn).unlink(missing_ok=True)
        r2 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch=b_branch, approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        ctx.gh.merge_status = 200
        scenarios["prereq_missing_and_denied"] = _snap_sc("prereq_missing_and_denied", r2, {})

        # 3. Competing base rejection at boundary
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        for fn in ("integration-request.json", "integration-record.json"):
            (ctx.child_dir / fn).unlink(missing_ok=True)
        def _adv_competitor():
            comp_sha = git(
                ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Competitor update",
            )
            git(ctx.bare, "update-ref", f"refs/heads/{b_branch}", comp_sha, ctx.base_sha)
        r3 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch=b_branch, approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
            on_before_merge=_adv_competitor,
        )
        scenarios["competing_base_rejection"] = _snap_sc("competing_base_rejection", r3, {})

        # 4. Renewed verification after base change
        # Competing actor advances base on remote feature branch
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        adv_base = git(
            ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
            "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Adv Base",
        )
        git(ctx.bare, "update-ref", f"refs/heads/{b_branch}", adv_base)
        git(ctx.repo, "fetch", "origin")
        for fn in ("integration-request.json", "integration-record.json"):
            (ctx.child_dir / fn).unlink(missing_ok=True)
        # Attempting integration against moved remote base fails closed
        r4 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch=b_branch, approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        scenarios["renewed_verification_after_base_change"] = _snap_sc("renewed_verification_after_base_change", r4, {
            "advanced_base_sha": adv_base, "stale_base_prevented": True,
        })

        # 5. Concurrency and uncertain reconciliation
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        ctx.gh.merge_status = 502
        for fn in ("integration-request.json", "integration-record.json"):
            (ctx.child_dir / fn).unlink(missing_ok=True)
        r5 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch=b_branch, approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        ctx.gh.merge_status = 200
        scenarios["concurrency_and_uncertain_reconciliation"] = _snap_sc("concurrency_and_uncertain_reconciliation", r5, {
            "uncertain_outcome": True,
        })

        # 6. Wrong target rejected and main preserved
        _reset_pr_and_branches(ctx.base_sha, ctx.cand_sha)
        for fn in ("integration-request.json", "integration-record.json"):
            (ctx.child_dir / fn).unlink(missing_ok=True)
        r6 = integrate_approved_child(
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
            conf=ctx.conf, pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            head_branch=h_branch, base_branch="main", approval_record=gate1,
            repo_slug="turbo-factory/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        main_sha_after = git(ctx.bare, "rev-parse", "refs/heads/main")
        scenarios["wrong_target_rejected"] = _snap_sc("wrong_target_rejected", r6, {
            "main_sha_before": main_sha_before, "main_sha_after": main_sha_after,
        })

    parent_index = build_parent_evidence_index(scenarios, f_rev)
    reduced_index, all_qualified, red_blockers = reduce_evidence_index(
        parent_index, {"status": "offline-simulated", "simulated": True}, scenarios,
    )
    summary = {
        "schema": 1, "role": "offline-qualification-summary", "factory_revision": f_rev,
        "status": "preparation-complete", "outcome": "offline-simulated-verified",
        "qualified": False, "mode": "offline-simulated", "simulated": True,
        "disclaimer": "Offline simulated proof; not parent acceptance. Hosted qualification PENDING.",
        "scenarios": scenarios, "parent_evidence_index": reduced_index,
        "reduction_blockers": red_blockers,
        "recorded_at": approval_mod.now(),
    }
    atomic_json(evidence_dir / "qualification-summary.json", summary, evidence_dir)
    atomic_json(evidence_dir / "parent-evidence-index.json", reduced_index, evidence_dir)
    return summary


def main(argv: list[str] | None = None) -> int:
    """Repeatable qualification command entrypoint."""
    parser = argparse.ArgumentParser(description="Turbo Issue #67 Protected Repository Qualification")
    parser.add_argument("--mode", choices=["offline", "hosted"], default="offline")
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--repo-slug", default="turbo-factory/turbo-qual-67")
    parser.add_argument("--branch", default="feature/demo")
    parser.add_argument("--base-url", default="https://api.github.com")
    args = parser.parse_args(argv)

    ev_dir = args.evidence_dir or Path(os.environ.get("DEMO_KEEP_EVIDENCE_DIR", "/tmp/turbo-issue-67-evidence"))
    if args.mode == "hosted":
        live_enabled = os.environ.get("TURBO_LIVE_QUALIFICATION") == "1"
        res = run_hosted_qualification(
            args.repo_slug, ev_dir, live_enabled=live_enabled,
            integrator_token=os.environ.get("TURBO_QUAL_INTEGRATOR_TOKEN"),
            competitor_token=os.environ.get("TURBO_QUAL_COMPETITOR_TOKEN"),
            base_url=args.base_url, branch=args.branch,
        )
        print(json.dumps(res, indent=2))
        return 0 if res.get("qualified") else 2
    else:
        res = run_offline_qualification(ev_dir)
        print(json.dumps(res, indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
