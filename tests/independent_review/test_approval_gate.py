"""Behavioral tests for the exact-candidate final approval gate (Issue #58)."""
from __future__ import annotations
import json, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path: sys.path.insert(0, _p)

from factory import ci_gate, ci_selection, config as config_module, independent_review, runner, security_review
from factory.paths import RuntimePaths
from support import git
from test_deliver import _make_disposable_product_workspace, _make_fake_agy
from tests.independent_review.test_independent_review import (
    CLEAN_AUTH_PY, DEFAULT_ASSESSMENT, EXPIRED_TEST_APPEND, PARSED_CHILD,
    _make_staged_reviewer_script, _valid_qa_record, _valid_security_record,
)
from tests.security_review.test_reviewer import REVIEWER_SCRIPT


def _valid_ci_record(
    candidate_sha: str, base_sha: str, home: Path, *, tested_sha: str | None = None,
    revision_kind: str | None = None, child: dict | None = None, conf: config_module.Config | None = None,
) -> dict:
    t_sha = tested_sha or candidate_sha
    r_kind = revision_kind or ("fast-forward-head" if t_sha == candidate_sha else "integration-merge")
    ci_dir = home / "ci-fixture"
    ci_dir.mkdir(parents=True, exist_ok=True)
    req_list = ci_selection.build_required_ci_checks(child or PARSED_CHILD, conf) if conf is not None else [
        {"id": "gate-1", "name": "guard/gate-1", "kind": "guard", "assesses": "gate-1"},
        {"id": "gate-2", "name": "guard/gate-2", "kind": "guard", "assesses": "gate-2"},
        {"id": "gate-3", "name": "guard/gate-3", "kind": "guard", "assesses": "gate-3"},
        {"id": "AC-1", "name": "criterion/AC-1", "kind": "criterion", "assesses": "AC-1"},
    ]
    checks = []
    for idx, req in enumerate(req_list, start=1):
        log_txt = f"ci check {req['name']} passed on {t_sha}\n"
        log_p = ci_dir / f"ci-{idx}-{req['name'].replace('/', '-')}-{candidate_sha[:8]}.log"
        log_p.write_text(log_txt, encoding="utf-8")
        checks.append({
            **req, "run_id": 100 + idx, "workflow_run_id": 200, "run_attempt": 1,
            "workflow_path": ".github/workflows/ci.yml", "policy_sha": base_sha, "artifact_id": 300 + idx,
            "producer": "github-actions", "status": "completed", "conclusion": "success",
            "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": t_sha, "revision_kind": r_kind,
            "html_url": f"https://github.com/example/chat-bridge/runs/{100 + idx}",
            "artifact_url": f"https://github.com/example/chat-bridge/actions/runs/200/artifacts/{300 + idx}",
            "output_path": str(log_p), "output_sha256": runner.digest_text(log_txt),
        })
    return {
        "status": "verified", "verified": True, "verification_scope": ci_gate.VERIFICATION_SCOPE_NOTE,
        "candidate_sha": candidate_sha, "base_sha": base_sha, "policy_sha": base_sha,
        "tested_sha": t_sha, "revision_kind": r_kind,
        "trusted_producers": ["github-actions"], "trusted_workflows": [".github/workflows/ci.yml"],
        "required_checks": req_list, "checks": checks, "blockers": [],
        "pr": {
            "pr_confirmed": True, "ci_verified": True, "verified": True, "state": "open",
            "merged": False, "head_sha": candidate_sha, "base_sha": base_sha,
        },
    }


class ApprovalGateGroup1Test(unittest.TestCase):
    def _setup_workspace(self, root: Path):
        repo, home, _ = _make_disposable_product_workspace(root)
        base_sha = git(repo, "rev-parse", "refs/heads/main")
        conf = config_module.load(RuntimePaths(repo=repo, home=home))
        child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
        git(repo, "checkout", "-q", "-b", "task/101-gate", base_sha)
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
        (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "feat: validate expired token")
        cand_sha = git(repo, "rev-parse", "HEAD")
        good_agy = _make_fake_agy(root, "agy-gate-good", _make_staged_reviewer_script(session_id="fresh-reviewer-gate"))
        return repo, home, base_sha, cand_sha, conf, child_dir, good_agy

    def test_ac1_verified_reconciliation_and_fresh_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, conf, child_dir, good_agy = self._setup_workspace(root)
            vcmd_fix = "python3 -c \"import pathlib, sys; sys.exit(0 if '# fixed-b1' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            vcmd_nla = "python3 -c \"import pathlib, sys; sys.exit(0 if not pathlib.Path('src/chat_bridge/temp_mod.py').exists() else 1)\""
            (repo / "src/chat_bridge/temp_mod.py").write_text("TEMP = 1\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 1 with two blockers")
            cand1 = git(repo, "rev-parse", "HEAD")
            child_ac1 = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, src/chat_bridge/temp_mod.py, tests/test_auth.py"}}
            fid1 = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "missing-b1-guard")
            fid2 = independent_review.compute_review_finding_id("scope-drift", "src/chat_bridge/temp_mod.py", "unneeded-temp-mod")
            r1_findings = [
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "missing-b1-guard", "title": "Missing b1 guard", "evidence": "r1-b1", "actionable_correction": "Add # fixed-b1", "verification_command": vcmd_fix},
                {"category": "scope-drift", "blocking": True, "target": "src/chat_bridge/temp_mod.py", "rule": "unneeded-temp-mod", "title": "Temp module added", "evidence": "r1-b2", "actionable_correction": "Remove temp_mod.py", "verification_command": vcmd_nla},
            ]
            agy1 = _make_fake_agy(root, "agy-ac1-r1", _make_staged_reviewer_script(session_id="rev-ac1-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "blockers"}}, findings=r1_findings))
            ci1, qa1, sec1 = _valid_ci_record(cand1, base_sha, home, child=child_ac1, conf=conf), _valid_qa_record(cand1, base_sha), _valid_security_record(cand1, base_sha, home)
            gate1 = independent_review.evaluate_approval_gate(
                candidate_sha=cand1, base_sha=base_sha, ci_record=ci1, qa_record=qa1, security_record=sec1,
                repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf,
                builder_session_id="builder-1", builder_summary="Round 1", round_num=1, agy_bin=str(agy1),
            )
            self.assertEqual((gate1["delivery_approved"], gate1["outcome"], gate1["approved_revision"]), (False, "rejected", None))
            self.assertEqual(set(gate1["historical_blockers"]["unresolved_ids"]), {fid1, fid2})

            # Round 2: fix fid1, but omit fid2 from reconciliation AND leave temp_mod.py in place -> rejected
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# fixed-b1\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 2 partial fix")
            cand2 = git(repo, "rev-parse", "HEAD")
            ci2, qa2, sec2 = _valid_ci_record(cand2, base_sha, home, child=child_ac1, conf=conf), _valid_qa_record(cand2, base_sha), _valid_security_record(cand2, base_sha, home)
            agy2_omit = _make_fake_agy(root, "agy-ac1-r2", _make_staged_reviewer_script(session_id="rev-ac1-2", outcome="review-passed", reconciliations=[{"finding_id": fid1, "resolution": "fixed", "evidence": "b1 fixed"}]))
            r2 = independent_review.review_candidate_independently(
                repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf, base_sha=base_sha, candidate_sha=cand2,
                builder_session_id="builder-1", builder_summary="Round 2", qa_record=qa2, security_record=sec2, round_num=2, agy_bin=str(agy2_omit), deadline=time.monotonic() + 30.0, limit_s=30,
            )
            gate2 = independent_review.evaluate_approval_gate(
                candidate_sha=cand2, base_sha=base_sha, ci_record=ci2, qa_record=qa2, security_record=sec2,
                review_record=r2, repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf,
            )
            self.assertEqual((gate2["delivery_approved"], gate2["approved_revision"]), (False, None))
            # Even if r2 record is tampered to strip omitted fid2 and claim review-passed, persisted history rejects it
            tampered_r2 = {
                **r2, "outcome": "review-passed", "review_verified": True, "blocking_findings": [], "open_finding_ids": [],
                "findings": [f for f in r2["findings"] if f["finding_id"] != fid2],
                "previous_findings_resolution": [r for r in r2["previous_findings_resolution"] if r["finding_id"] != fid2],
            }
            gate2_tampered = independent_review.evaluate_approval_gate(
                candidate_sha=cand2, base_sha=base_sha, ci_record=ci2, qa_record=qa2, security_record=sec2,
                review_record=tampered_r2, repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf,
            )
            self.assertEqual((gate2_tampered["delivery_approved"], gate2_tampered["status"]), (False, "unresolved-historical-blockers"))

            # Round 3: remove temp_mod.py and reconcile both blockers with passing execution evidence -> APPROVED
            (repo / "src/chat_bridge/temp_mod.py").unlink()
            git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "round 3 complete fix")
            cand3 = git(repo, "rev-parse", "HEAD")
            sec_agy = _make_fake_agy(root, "agy-sec-r3", REVIEWER_SCRIPT)
            real_sec3 = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf, base_sha=base_sha,
                candidate_sha=cand3, round_num=1, agy_bin=str(sec_agy), builder_session_id="builder-1", deadline=time.monotonic() + 30.0, limit_s=30,
            )
            qa3_round = {**_valid_qa_record(cand3, base_sha), "round": 1}
            qa_round_dir = child_dir / "automated-qa" / "round-1"; qa_round_dir.mkdir(parents=True, exist_ok=True)
            (qa_round_dir / "record.json").write_text(json.dumps(qa3_round), encoding="utf-8")
            qa3_summary = {"status": "qa-verified", "qa_verified": True, "rounds": 1, "open_finding_ids": [], "findings": []}
            (child_dir / "automated-qa" / "record.json").write_text(json.dumps(qa3_summary), encoding="utf-8")
            ci3 = _valid_ci_record(cand3, base_sha, home, child=child_ac1, conf=conf)
            (child_dir / "ci-verification.json").write_text(json.dumps(ci3), encoding="utf-8")
            agy3 = _make_fake_agy(root, "agy-ac1-r3", _make_staged_reviewer_script(
                session_id="rev-ac1-3", outcome="review-passed",
                reconciliations=[{"finding_id": fid1, "resolution": "fixed", "evidence": "b1 guard present"}, {"finding_id": fid2, "resolution": "no-longer-applicable", "evidence": "temp_mod removed"}],
            ))
            r3 = independent_review.review_candidate_independently(
                repo=repo, home=home, child_dir=child_dir, child=child_ac1, conf=conf, base_sha=base_sha, candidate_sha=cand3,
                builder_session_id="builder-1", builder_summary="Round 3", qa_record=qa3_summary, security_record=real_sec3,
                round_num=3, agy_bin=str(agy3), deadline=time.monotonic() + 30.0, limit_s=30,
            )
            self.assertFalse(r3["delivery_approved"])
            gate3 = independent_review.evaluate_approval_gate(
                candidate_sha=cand3, base_sha=base_sha, repo=repo, home=home, child_dir=child_dir,
                child=child_ac1, conf=conf, load_from_child_dir=True,
            )
            self.assertEqual(
                (gate3["delivery_approved"], gate3["status"], gate3["outcome"], gate3["approved_revision"], gate3["tested_sha"], gate3["revision_kind"], gate3["historical_blockers"]["all_verified_resolved"], set(gate3["historical_blockers"]["resolved_ids"])),
                (True, "approved", "approved", cand3, cand3, "fast-forward-head", True, {fid1, fid2}),
            )

            # Prerequisite failure matrix on cand3: missing, failing, stale, invalid, untrusted, or mismatched must reject
            def eval_g(**over):
                kw = {"candidate_sha": cand3, "base_sha": base_sha, "ci_record": ci3, "qa_record": qa3_round, "security_record": real_sec3, "review_record": r3, "repo": repo, "home": home, "child_dir": child_dir, "child": child_ac1, "conf": conf}
                kw.update(over)
                return independent_review.evaluate_approval_gate(**kw)

            for label, overrides, exp_status in (
                ("ci-missing", {"ci_record": None}, "ci-missing"),
                ("ci-failed-top", {"ci_record": {**ci3, "status": "ci-failed", "verified": False, "blockers": ["failed"]}}, "ci-failed"),
                ("ci-check-failed", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "conclusion": "failure"}, *ci3["checks"][1:]]}}, "ci-failed"),
                ("ci-check-pending", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "status": "in_progress"}, *ci3["checks"][1:]]}}, "ci-pending"),
                ("ci-check-skipped", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "conclusion": "skipped"}, *ci3["checks"][1:]]}}, "ci-skipped"),
                ("ci-untrusted-prod", {"ci_record": {**ci3, "trusted_producers": ["untrusted-ci"]}}, "ci-untrusted-producer"),
                ("ci-untrusted-wf", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "workflow_path": ".github/workflows/other.yml"}, *ci3["checks"][1:]]}}, "ci-untrusted-producer"),
                ("ci-missing-req-chk", {"ci_record": {**ci3, "checks": ci3["checks"][:-1]}}, "ci-missing"),
                ("ci-bad-digest", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "output_sha256": "0" * 64}, *ci3["checks"][1:]]}}, "ci-evidence-invalid"),
                ("ci-stale-cand", {"ci_record": {**ci3, "candidate_sha": cand2}}, "stale-ci-evidence"),
                ("ci-stale-base", {"ci_record": {**ci3, "base_sha": cand1}}, "stale-ci-evidence"),
                ("ci-stale-policy", {"ci_record": {**ci3, "policy_sha": cand1}}, "stale-ci-evidence"),
                ("ci-cached-result", {"ci_record": {**ci3, "checks": [{**ci3["checks"][0], "cached_result": True}, *ci3["checks"][1:]]}}, "stale-ci-evidence"),
                ("ci-closed-pr", {"ci_record": {**ci3, "pr": {**ci3["pr"], "state": "closed"}}}, "stale-ci-evidence"),
                ("ci-drifted-branch", {"ci_record": {**ci3, "head_branch": "main"}}, "stale-ci-evidence"),
                ("qa-missing", {"qa_record": None}, "qa-missing"),
                ("qa-failed", {"qa_record": {**qa3_round, "status": "qa-failed", "qa_verified": False}}, "qa-failed"),
                ("qa-invalid", {"qa_record": {**qa3_round, "criterion_coverage": []}}, "qa-invalid"),
                ("qa-stale-cand", {"qa_record": {**qa3_round, "candidate_sha": cand2}}, "stale-qa-evidence"),
                ("qa-tested-mismatch", {"qa_record": {**qa3_round, "tested_sha": cand2, "revision_kind": "integration-merge", "merge_parents": [base_sha, cand3], "ci_revalidation": {**qa3_round["ci_revalidation"], "tested_sha": cand2}}}, "stale-qa-evidence"),
                ("qa-wrapper-unverified", {"qa_record": {"status": "qa-failed", "qa_verified": False, "qa_rounds": [qa3_round]}}, "qa-failed"),
                ("sec-missing", {"security_record": None}, "security-review-missing"),
                ("sec-invalid-outcome", {"security_record": {**real_sec3, "outcome": "changes-requested", "ready": False}}, "security-review-invalid"),
                ("sec-failed", {"security_record": {**real_sec3, "outcome": "changes-requested", "ready": False, "blocking_findings": [{"finding_id": "SEC-1", "blocking": True, "status": "open"}]}}, "security-blockers-unresolved"),
                ("sec-untrusted", {"security_record": {**real_sec3, "role_separation_verified": False}}, "security-review-invalid"),
                ("sec-stale-cand", {"security_record": {**real_sec3, "reviewed_revision": cand2}}, "stale-security-review"),
                ("sec-wrapper-failed", {"security_record": {"security_review": real_sec3, "security_gate": {"status": "security-blockers-unresolved", "verified": False, "blockers": ["open"]}}}, "security-blockers-unresolved"),
                ("rev-missing", {"review_record": None}, "independent-review-missing"),
                ("rev-stale-cand", {"review_record": {**r3, "reviewed_revision": cand2}}, "stale-independent-review"),
                ("rev-stale-std", {"review_record": {**r3, "standards_sha": cand1}}, "stale-independent-review"),
                ("rev-failed-obs", {"review_record": {**r3, "observed_verification": {**r3["observed_verification"], "ok": False}}}, "verification-failed"),
            ):
                res = eval_g(**overrides)
                self.assertEqual((res["delivery_approved"], res["approved_revision"], res["status"]), (False, None, exp_status), f"failed prerequisite rejection for {label}: {res}")

            # Corrupt prior-blockers.json must fail closed
            (child_dir / "prior-blockers.json").write_text("{corrupt", encoding="utf-8")
            corrupt_res = eval_g()
            self.assertEqual((corrupt_res["delivery_approved"], corrupt_res["status"]), (False, "corrupt-prior-history"))


if __name__ == "__main__":
    unittest.main()
