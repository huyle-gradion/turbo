"""Offline simulated qualification harness (#67, moved out of factory/ in #97).

A simulation built on the disposable test fakes in ``support_deliver``; it is not hosted proof.
Run as ``python3 -m qualification_offline --mode offline`` with ``PYTHONPATH=tests:.``.
"""
from __future__ import annotations

import argparse, json, shutil, sys
from pathlib import Path
from typing import Any

from factory import deliver as deliver_module
from factory.independent_review import approval as approval_mod
from factory.integration import _factory_rev, integrate_approved_child
from factory.paths import atomic_json, safe_dir
from factory.qualification import _record_invocation, _run_outcome, build_parent_evidence_index, reduce_evidence_index
from support import git
from support_deliver import setup_disposable_delivery_context


def run_offline_qualification(evidence_dir: Path) -> dict[str, Any]:
    """Execute all six parent #24 scenarios through real A+B interfaces and retain evidence."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    scenarios_dir = safe_dir(evidence_dir / "scenarios", create=True)
    f_rev = _factory_rev()

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

        def _snap_sc(name: str, res: Any, extra: dict[str, Any], expected_status: str, observed: bool) -> dict[str, Any]:
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
                "expected_status": expected_status,
                "integration_outcome": getattr(res, "outcome", None),
                "outcome": "verified" if observed else "failed",
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
        }, "confirmed", r1.status == "confirmed" and bool(r1.landed_sha))

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
        scenarios["prereq_missing_and_denied"] = _snap_sc("prereq_missing_and_denied", r2, {}, "denied-permissions", r2.status == "denied-permissions")

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
        scenarios["competing_base_rejection"] = _snap_sc("competing_base_rejection", r3, {}, "rejected-competing-base", r3.status == "rejected-competing-base")

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
            "advanced_base_sha": adv_base, "stale_base_prevented": r4.status == "stale-base-revision",
        }, "stale-base-revision", r4.status == "stale-base-revision" and not r4.landed_sha)

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
            "uncertain_outcome": r5.status == "uncertain",
        }, "uncertain", r5.status == "uncertain" and not r5.landed_sha)

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
        }, "unintended-target", r6.status == "unintended-target" and main_sha_before == main_sha_after)

    parent_index = build_parent_evidence_index(scenarios, f_rev, mode="offline-simulated")
    reduced_index, all_qualified, red_blockers = reduce_evidence_index(
        parent_index, {"status": "offline-simulated", "simulated": True}, scenarios,
    )
    summary = {
        "schema": 1, "role": "offline-qualification-summary", "factory_revision": f_rev,
        "status": "preparation-complete",
        "outcome": _run_outcome(scenarios, red_blockers, "offline-simulated-verified"),
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
    """Offline qualification entry point used by ``scripts/qualify-protected-demo.sh --mode offline``."""
    parser = argparse.ArgumentParser(description="Turbo #67 offline simulated qualification")
    parser.add_argument("--mode", choices=["offline"], default="offline")
    parser.add_argument("--evidence-dir", type=Path, default=Path("/tmp/turbo-issue-67-evidence"))
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    ev_dir, command = Path(args.evidence_dir), ["python3", "-m", "qualification_offline", *argv]
    for stale in ("qualification-summary.json", "parent-evidence-index.json"):
        (ev_dir / stale).unlink(missing_ok=True)  # persisted results describe only this run
    try:
        res = run_offline_qualification(ev_dir)
    except BaseException as exc:
        ev_dir.mkdir(parents=True, exist_ok=True)
        (ev_dir / "parent-evidence-index.json").unlink(missing_ok=True)
        crashed = {
            "schema": 1, "role": "offline-qualification-summary", "mode": "offline-simulated",
            "status": "failed", "outcome": "failed", "qualified": False,
            "blockers": [f"qualification-run-raised: {type(exc).__name__}: {exc}"],
            "recorded_at": approval_mod.now(),
        }
        _record_invocation(ev_dir, crashed, command, 1, [])
        raise
    rc = 0 if res.get("outcome") == "offline-simulated-verified" else 2
    _record_invocation(ev_dir, res, command, rc, [])
    print(json.dumps(res, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
