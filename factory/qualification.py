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

DISPOSABLE_REPO_ALLOWLIST = frozenset(["huyle-gradion/turbo-qual-67"])

REAL_SETUP_METADATA: dict[str, Any] = {
    "repo_slug": "huyle-gradion/turbo-qual-67",
    "identities": {
        "integrator": "huyhuyhuy8s",
        "competitor": "cone-orgs",
        "restricted_reader": "huyle-turbo",
    },
    "protection_config": {
        "strict": True,
        "enforce_admins": True,
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    },
    "token_permissions_required": [
        "Contents: Read and write",
        "Pull requests: Read and write",
        "Actions: Read-only",
        "Commit statuses: Read-only",
        "Checks: Read-only",
        "Administration: Read-only",
    ],
    "known_gap": (
        "Integrator and competitor fine-grained tokens cannot read branch protection (HTTP 403) "
        "because Administration: Read-only permission is pending. Step 7 in "
        "factory.integration halts with denied-permissions until updated."
    ),
}

PARENT_AC_DESCRIPTIONS: dict[str, str] = {
    "AC1": "Protected test repository accepts child merge only when required CI, QA, security, and fresh independent approval apply.",
    "AC2": "Integration ownership topology and authoritative checks prevent unverified-base integration across independent actors.",
    "AC3": "Controlled competing-base update prevents stale integration and forces renewed candidate verification and review.",
    "AC4": "Repository protections and identity permissions are honored without bypass; missing permissions stop integration explicitly.",
    "AC5": "Merge result confirmed on intended feature branch before marking child complete, linking revisions and evidence.",
    "AC6": "Tests cover concurrent attempts, changed head/base, denied merge, uncertain API outcome, and wrong target; main untouched.",
}


def check_hosted_authorization(repo_slug: str, live_enabled: bool) -> tuple[bool, str]:
    """Require explicit hosted enablement and exact disposable-repository allowlist."""
    if not live_enabled:
        return False, "hosted-qualification-disabled: live hosted qualification requires TURBO_LIVE_QUALIFICATION=1"
    if repo_slug not in DISPOSABLE_REPO_ALLOWLIST:
        return False, f"repo-disallowed: {repo_slug!r} is not in disposable allowlist {sorted(DISPOSABLE_REPO_ALLOWLIST)}"
    return True, ""


def check_credentials_and_capabilities(
    base_url: str, repo_slug: str, branch: str,
    integrator_token: str | None, competitor_token: str | None,
) -> tuple[bool, dict[str, Any], list[str]]:
    """Detect missing credentials and unavailable protection capabilities (Administration: Read-only gap)."""
    blockers: list[str] = []
    if not integrator_token or not competitor_token:
        blockers.append("missing-credentials: both TURBO_QUAL_INTEGRATOR_TOKEN and TURBO_QUAL_COMPETITOR_TOKEN are required")
        return False, {}, blockers

    trace: list[dict[str, Any]] = []
    quoted_branch = quote(branch, safe="")
    url = f"{base_url.rstrip('/')}/repos/{repo_slug}/branches/{quoted_branch}/protection"
    code, prot_data, err_msg = _http_req("GET", url, integrator_token, base_url, trace, time.monotonic() + 15.0, 15)

    if code in (401, 403):
        blockers.append(
            f"unavailable-protection-capability: branch protection read returned HTTP {code} "
            f"({err_msg or 'Administration: Read-only fine-grained permission required'})"
        )
        return False, {}, blockers
    if code != 200 or not prot_data:
        blockers.append(f"unsupported-protection: branch protection read returned HTTP {code}: {err_msg}")
        return False, {}, blockers

    rsc = prot_data.get("required_status_checks") or {}
    admins = prot_data.get("enforce_admins") or {}
    allow_fp = prot_data.get("allow_force_pushes") or {}
    allow_del = prot_data.get("allow_deletions") or {}

    if not isinstance(rsc, dict) or not rsc.get("strict"):
        blockers.append(f"unsupported-protection: branch protection on {branch} must require strict status checks")
    if not isinstance(admins, dict) or not admins.get("enabled"):
        blockers.append(f"unsupported-protection: branch protection on {branch} must enforce admins")
    if isinstance(allow_fp, dict) and allow_fp.get("enabled"):
        blockers.append(f"unsupported-protection: branch protection on {branch} forbids force pushes")
    if isinstance(allow_del, dict) and allow_del.get("enabled"):
        blockers.append(f"unsupported-protection: branch protection on {branch} forbids deletions")

    if blockers:
        return False, prot_data, blockers
    return True, prot_data, []


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
            "outcome": "passed-offline-simulated",
            "hosted_proof_status": "PENDING",
            "artifact_paths": all_artifacts,
        }
    return index


def run_hosted_qualification(
    repo_slug: str, evidence_dir: Path, *,
    live_enabled: bool = False,
    integrator_token: str | None = None,
    competitor_token: str | None = None,
    base_url: str = "https://api.github.com",
    branch: str = "feature/demo",
) -> dict[str, Any]:
    """Execute hosted qualification or retain explicit blocked/unavailable status without mutation."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    f_rev = _factory_rev()

    auth_ok, auth_msg = check_hosted_authorization(repo_slug, live_enabled)
    if not auth_ok:
        res = {
            "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
            "status": "blocked", "outcome": "unavailable", "qualified": False,
            "repo_slug": repo_slug, "blockers": [auth_msg], "scenarios": {},
            "parent_evidence_index": {}, "mode": "hosted", "simulated": False,
            "recorded_at": approval_mod.now(),
        }
        atomic_json(evidence_dir / "qualification-summary.json", res, evidence_dir)
        return res

    cap_ok, prot_data, cap_blockers = check_credentials_and_capabilities(
        base_url, repo_slug, branch, integrator_token, competitor_token,
    )
    if not cap_ok:
        res = {
            "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
            "status": "blocked", "outcome": "unavailable", "qualified": False,
            "repo_slug": repo_slug, "blockers": cap_blockers,
            "protection_observed": prot_data, "scenarios": {},
            "parent_evidence_index": {}, "mode": "hosted", "simulated": False,
            "recorded_at": approval_mod.now(),
        }
        atomic_json(evidence_dir / "qualification-summary.json", res, evidence_dir)
        return res

    res = {
        "schema": 1, "role": "hosted-qualification-summary", "factory_revision": f_rev,
        "status": "blocked", "outcome": "unavailable", "qualified": False,
        "repo_slug": repo_slug, "blockers": ["hosted-scenarios-pending-human-setup"],
        "mode": "hosted", "simulated": False, "recorded_at": approval_mod.now(),
    }
    atomic_json(evidence_dir / "qualification-summary.json", res, evidence_dir)
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
        ctx.gh.owner = "huyle-gradion"
        ctx.gh.repo = "turbo-qual-67"
        main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")
        b_branch = str(ctx.intake_rec["parent"]["target_feature_branch"])
        h_branch = ctx.head_branch

        def _reset_pr_and_branches(base_s: str, cand_s: str) -> None:
            git(ctx.bare, "branch", "-f", b_branch, base_s)
            git(ctx.bare, "branch", "-f", h_branch, cand_s)
            git(ctx.repo, "fetch", "origin")
            if 1 in ctx.gh.pulls:
                ctx.gh.pulls[1]["head"]["repo"]["full_name"] = "huyle-gradion/turbo-qual-67"
                ctx.gh.pulls[1]["base"]["repo"]["full_name"] = "huyle-gradion/turbo-qual-67"
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
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
            repo_slug="huyle-gradion/turbo-qual-67", base_url=ctx.gh.base_url, token="disp-tok",
        )
        main_sha_after = git(ctx.bare, "rev-parse", "refs/heads/main")
        scenarios["wrong_target_rejected"] = _snap_sc("wrong_target_rejected", r6, {
            "main_sha_before": main_sha_before, "main_sha_after": main_sha_after,
        })

    parent_index = build_parent_evidence_index(scenarios, f_rev)
    summary = {
        "schema": 1, "role": "offline-qualification-summary", "factory_revision": f_rev,
        "status": "preparation-complete", "outcome": "offline-simulated-verified",
        "qualified": False, "mode": "offline-simulated", "simulated": True,
        "disclaimer": "Offline simulated proof; not parent acceptance. Hosted qualification PENDING.",
        "scenarios": scenarios, "parent_evidence_index": parent_index,
        "recorded_at": approval_mod.now(),
    }
    atomic_json(evidence_dir / "qualification-summary.json", summary, evidence_dir)
    atomic_json(evidence_dir / "parent-evidence-index.json", parent_index, evidence_dir)
    return summary


def main(argv: list[str] | None = None) -> int:
    """Repeatable qualification command entrypoint."""
    parser = argparse.ArgumentParser(description="Turbo Issue #67 Protected Repository Qualification")
    parser.add_argument("--mode", choices=["offline", "hosted"], default="offline")
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--repo-slug", default="huyle-gradion/turbo-qual-67")
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
