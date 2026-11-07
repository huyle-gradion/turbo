"""Behavioral tests for the exact-candidate final approval gate (Issue #58)."""
from __future__ import annotations
import json, shutil, sys, tempfile, time, unittest
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
        log_txt = f"candidate_sha={candidate_sha}\nbase_sha={base_sha}\ntested_sha={t_sha}\nrevision_kind={r_kind}\nci check {req['name']} passed on {t_sha}\n"
        log_p = ci_dir / f"ci-{idx}-{req['name'].replace('/', '-')}-{candidate_sha[:8]}-{t_sha[:8]}.log"
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
        _valid_security_record("0" * 40, "0" * 40, home)
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

            for bad_r in (None, True, False, 0, -1, "3"):
                for k, base_rec in (("qa_record", qa3_round), ("security_record", real_sec3), ("review_record", r3)):
                    self.assertFalse(eval_g(**{k: {**base_rec, "round": bad_r}})["delivery_approved"], f"M1 {k} round={bad_r!r}")
                if bad_r is not None:
                    self.assertFalse(eval_g(round_num=bad_r)["delivery_approved"], f"M1 round_num={bad_r!r}")
            # M1: child_dir supplied with home=None must still enforce persisted unresolved history on gate2_tampered
            self.assertFalse(independent_review.evaluate_approval_gate(
                candidate_sha=cand2, base_sha=base_sha, ci_record=ci2, qa_record=qa2, security_record=sec2,
                review_record=tampered_r2, repo=repo, home=None, child_dir=child_dir, child=child_ac1, conf=conf,
            )["delivery_approved"])
            # M1: same-candidate prior QA/security blockers and newer superseding rounds cannot be bypassed
            (qa_round_dir / "record.json").write_text(json.dumps({**qa3_round, "round": 1, "findings": [{"finding_id": "QA-101-AC-1-DET", "status": "open"}]}), encoding="utf-8")
            self.assertEqual(eval_g(qa_record={**qa3_round, "round": 2, "findings": []})["status"], "qa-findings-open")
            (qa_round_dir / "record.json").write_text(json.dumps(qa3_round), encoding="utf-8")
            sec_r1_dir = child_dir / "security-round-1"; sec_r1_dir.mkdir(parents=True, exist_ok=True)
            (sec_r1_dir / "record.json").write_text(json.dumps({**real_sec3, "round": 1, "findings": [{"finding_id": "SEC-HIST-1", "blocking": True, "status": "open"}]}), encoding="utf-8")
            self.assertEqual(eval_g(security_record={**real_sec3, "round": 2, "findings": []})["status"], "security-blockers-unresolved")
            shutil.rmtree(sec_r1_dir)
            # Corrupt prior-blockers.json must fail closed
            (child_dir / "prior-blockers.json").write_text("{corrupt", encoding="utf-8")
            corrupt_res = eval_g()
            self.assertEqual((corrupt_res["delivery_approved"], corrupt_res["status"]), (False, "corrupt-prior-history"))

    def test_ac2_exact_candidate_approval_binding_and_stale_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_a, conf, child_dir, good_agy = self._setup_workspace(root)
            ci_a, qa_a, sec_a = _valid_ci_record(cand_a, base_sha, home, conf=conf), _valid_qa_record(cand_a, base_sha), _valid_security_record(cand_a, base_sha, home)
            rev_a = independent_review.review_candidate_independently(
                repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf, base_sha=base_sha, candidate_sha=cand_a,
                builder_session_id="builder-a", builder_summary="Candidate A", qa_record=qa_a, security_record=sec_a, round_num=1, agy_bin=str(good_agy), deadline=time.monotonic() + 30.0, limit_s=30,
            )
            self.assertFalse(rev_a["delivery_approved"])
            gate_a = independent_review.evaluate_approval_gate(
                candidate_sha=cand_a, base_sha=base_sha, ci_record=ci_a, qa_record=qa_a, security_record=sec_a,
                review_record=rev_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            self.assertEqual((gate_a["delivery_approved"], gate_a["approved_revision"], gate_a["candidate_sha"], gate_a["tested_sha"], gate_a["revision_kind"]), (True, cand_a, cand_a, cand_a, "fast-forward-head"))
            self.assertTrue(independent_review.verify_candidate_approval(cand_a, base_sha, gate_a, repo=repo, home=home)["delivery_approved"])

            # Integration-merge tested-revision semantics on cand_a
            git(repo, "checkout", "-q", "-b", "merge-sim-ac2", base_sha)
            git(repo, "merge", "--no-ff", "-q", "-m", "Merge cand_a into base", cand_a)
            merge_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "task/101-gate")
            ci_merge = _valid_ci_record(cand_a, base_sha, home, tested_sha=merge_sha, revision_kind="integration-merge", conf=conf)
            qa_merge = {**_valid_qa_record(cand_a, base_sha, tested_sha=merge_sha), "revision_kind": "integration-merge"}
            gate_merge = independent_review.evaluate_approval_gate(
                candidate_sha=cand_a, base_sha=base_sha, ci_record=ci_merge, qa_record=qa_merge, security_record=sec_a,
                review_record=rev_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            self.assertEqual((gate_merge["delivery_approved"], gate_merge["approved_revision"], gate_merge["tested_sha"], gate_merge["revision_kind"]), (True, cand_a, merge_sha, "integration-merge"))
            mismatch_merge = independent_review.evaluate_approval_gate(
                candidate_sha=cand_a, base_sha=base_sha, ci_record=ci_merge, qa_record=qa_a, security_record=sec_a,
                review_record=rev_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            self.assertEqual((mismatch_merge["delivery_approved"], mismatch_merge["status"]), (False, "stale-qa-evidence"))

            # Re-approve cand_a on disk before creating subsequent candidate B
            gate_a = independent_review.evaluate_approval_gate(
                candidate_sha=cand_a, base_sha=base_sha, ci_record=ci_a, qa_record=qa_a, security_record=sec_a,
                review_record=rev_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# candidate B change\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "candidate B")
            cand_b = git(repo, "rev-parse", "HEAD")
            self.assertNotEqual(cand_a, cand_b)

            # Approval issued for cand_a is rejected when evaluated for subsequent candidate B
            ver_b_from_a = independent_review.verify_candidate_approval(cand_b, base_sha, gate_a, repo=repo, home=home)
            self.assertEqual((ver_b_from_a["delivery_approved"], ver_b_from_a["approved_revision"], ver_b_from_a["status"], ver_b_from_a["stale_approved_revision"]), (False, None, "stale-candidate-revision", cand_a))
            gate_b_stale = independent_review.evaluate_approval_gate(
                candidate_sha=cand_b, base_sha=base_sha, ci_record=ci_a, qa_record=qa_a, security_record=sec_a,
                review_record=rev_a, prior_approval=gate_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            self.assertEqual((gate_b_stale["delivery_approved"], gate_b_stale["approved_revision"], gate_b_stale["status"], gate_b_stale["prior_approval_rejected"], gate_b_stale["superseded_approved_revision"]), (False, None, "stale-candidate-revision", True, cand_a))
            self.assertFalse(json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8"))["delivery_approved"])

            # Fresh prerequisites for cand_b, but test partial/relabelled cand_a evidence first
            ci_b, qa_b, sec_b = _valid_ci_record(cand_b, base_sha, home, conf=conf), _valid_qa_record(cand_b, base_sha), _valid_security_record(cand_b, base_sha, home)
            rev_b = independent_review.review_candidate_independently(
                repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf, base_sha=base_sha, candidate_sha=cand_b,
                builder_session_id="builder-b", builder_summary="Candidate B", qa_record=qa_b, security_record=sec_b, round_num=2, agy_bin=str(good_agy), deadline=time.monotonic() + 30.0, limit_s=30,
            )
            ci_a_deep = json.loads(json.dumps(ci_a).replace(cand_a, cand_b))
            for idx, c in enumerate(ci_a["checks"]): ci_a_deep["checks"][idx]["output_path"] = c["output_path"]
            qa_a_deep = json.loads(json.dumps(qa_a).replace(cand_a, cand_b))
            qa_a_deep["criterion_coverage"][0]["deterministic_check"]["output_path"] = qa_a["criterion_coverage"][0]["deterministic_check"]["output_path"]
            qa_a_deep["regression_checks"][0]["output_path"] = qa_a["regression_checks"][0]["output_path"]
            plain_log = home / "plain-unchanged.log"; plain_log.write_text("ok\n", encoding="utf-8"); plain_sha = runner.digest_text("ok\n")
            qa_no_art = {**qa_b, "criterion_coverage": [{**qa_b["criterion_coverage"][0], "deterministic_check": {k: v for k, v in qa_b["criterion_coverage"][0]["deterministic_check"].items() if k not in ("output_path", "output_sha256")}}]}
            qa_no_reg_art = {**qa_b, "regression_checks": [{k: v for k, v in qa_b["regression_checks"][0].items() if k not in ("output_path", "output_sha256")}]}
            for label, bad_kw in (
                ("stale-ci-a", {"ci_record": ci_a}),
                ("relabelled-ci-a", {"ci_record": {**ci_a, "candidate_sha": cand_b, "tested_sha": cand_b}}),
                ("deep-relabelled-ci-a", {"ci_record": ci_a_deep}),
                ("ci-unchanged-digest-no-prov", {"ci_record": {**ci_b, "checks": [{**ci_b["checks"][0], "output_path": str(plain_log), "output_sha256": plain_sha}, *ci_b["checks"][1:]]}}),
                ("relabelled-merge-ci-a", {"ci_record": {**ci_merge, "candidate_sha": cand_b}, "qa_record": {**qa_merge, "candidate_sha": cand_b}}),
                ("stale-qa-a", {"qa_record": qa_a}),
                ("relabelled-qa-a", {"qa_record": {**qa_a, "candidate_sha": cand_b, "tested_sha": cand_b}}),
                ("deep-relabelled-qa-a", {"qa_record": qa_a_deep}),
                ("qa-missing-det-art", {"qa_record": qa_no_art}),
                ("qa-missing-reg-art", {"qa_record": qa_no_reg_art}),
                ("qa-missing-reg-list", {"qa_record": {**qa_b, "regression_checks": None}}),
                ("qa-unchanged-digest-no-prov", {"qa_record": {**qa_b, "regression_checks": [{**qa_b["regression_checks"][0], "output_path": str(plain_log), "output_sha256": plain_sha}]}}),
                ("stale-sec-a", {"security_record": sec_a}),
                ("relabelled-sec-a", {"security_record": {**sec_a, "reviewed_revision": cand_b}}),
                ("stale-rev-a", {"review_record": rev_a}),
                ("relabelled-rev-a", {"review_record": {**rev_a, "reviewed_revision": cand_b, "round": 2}}),
            ):
                kw_b = {"candidate_sha": cand_b, "base_sha": base_sha, "ci_record": ci_b, "qa_record": qa_b, "security_record": sec_b, "review_record": rev_b, "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf, **bad_kw}
                res_b = independent_review.evaluate_approval_gate(**kw_b)
                self.assertEqual((res_b["delivery_approved"], res_b["approved_revision"]), (False, None), f"expected rejection for {label}")

            # Non-gate producers cannot issue delivery_approved=True
            for non_gate_rec in (rev_b, {**rev_b, "delivery_approved": True}, {**ci_b, "delivery_approved": True}, {**qa_b, "delivery_approved": True}, {**sec_b, "delivery_approved": True}):
                v_ng = independent_review.verify_candidate_approval(cand_b, base_sha, non_gate_rec, repo=repo, home=home)
                self.assertEqual((v_ng["delivery_approved"], v_ng["status"]), (False, "authority-violation"))
            for field_name, base_rec in (("ci_record", ci_b), ("qa_record", qa_b), ("security_record", sec_b), ("review_record", rev_b)):
                auth_kw = {"candidate_sha": cand_b, "base_sha": base_sha, "ci_record": ci_b, "qa_record": qa_b, "security_record": sec_b, "review_record": rev_b, "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf, field_name: {**base_rec, "delivery_approved": True}}
                auth_res = independent_review.evaluate_approval_gate(**auth_kw)
                self.assertEqual((auth_res["delivery_approved"], auth_res["status"]), (False, "authority-violation"))

            # Full fresh evidence on cand_b issues new approval bound to cand_b while gate_a remains rejected for cand_b
            gate_b = independent_review.evaluate_approval_gate(
                candidate_sha=cand_b, base_sha=base_sha, ci_record=ci_b, qa_record=qa_b, security_record=sec_b,
                review_record=rev_b, prior_approval=gate_a, repo=repo, home=home, child_dir=child_dir, child=PARSED_CHILD, conf=conf,
            )
            self.assertEqual((gate_b["delivery_approved"], gate_b["approved_revision"], gate_b["superseded_approved_revision"]), (True, cand_b, cand_a))
            self.assertTrue(independent_review.verify_candidate_approval(cand_b, base_sha, gate_b, repo=repo, home=home)["delivery_approved"])
            self.assertFalse(independent_review.verify_candidate_approval(cand_b, base_sha, gate_a, repo=repo, home=home)["delivery_approved"])
            fab_min = {
                "role": "delivery-approval-gate", "verification_scope": independent_review.APPROVAL_GATE_SCOPE_NOTE,
                "approved_revision": cand_b, "candidate_sha": cand_b, "base_sha": base_sha, "tested_sha": cand_b,
                "revision_kind": "fast-forward-head", "delivery_approved": True, "status": "approved", "outcome": "approved", "blockers": [],
                "prerequisites": {k: {"verified": True, "candidate_sha": cand_b, "base_sha": base_sha} for k in ("ci", "automated_qa", "security_review", "independent_review")},
            }
            for label, bad_ap in (
                ("minimal-fabricated", fab_min),
                ("relabelled-gate-a", json.loads(json.dumps(gate_a).replace(cand_a, cand_b))),
                ("unresolved-hist-claim", {**gate_b, "historical_blockers": {"total": 1, "resolved_ids": [], "unresolved_ids": ["REV-1"], "all_verified_resolved": False}}),
                ("fabricated-tested-sha", {**gate_b, "tested_sha": "f" * 40, "revision_kind": "integration-merge"}),
            ):
                self.assertFalse(independent_review.verify_candidate_approval(cand_b, base_sha, bad_ap, repo=repo, home=home)["delivery_approved"], f"M3 {label}")
            (child_dir / "prior-blockers.json").write_text(json.dumps({"schema": 1, "updated_in_round": 1, "reviewed_revision": cand_a, "findings": [{"finding_id": "REV-UNRES-M3", "category": "bug", "severity": "high", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "r", "title": "t", "evidence": "e", "actionable_correction": "c", "status": "open", "introduced_in_round": 1, "introduced_in_revision": cand_a, "last_seen_round": 1, "last_seen_revision": cand_a}]}), encoding="utf-8")
            self.assertFalse(independent_review.verify_candidate_approval(cand_b, base_sha, gate_b, repo=repo, home=home)["delivery_approved"], "M3 persisted-unresolved-history")

    def test_ac4_integrated_rejection_rules(self) -> None:
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_sha, conf, child_dir, good_agy = self._setup_workspace(root)
            ci_ok = _valid_ci_record(cand_sha, base_sha, home, conf=conf)
            qa_ok = _valid_qa_record(cand_sha, base_sha)
            sec_ok = _valid_security_record(cand_sha, base_sha, home)

            def run_gate(sub_name: str, **over):
                c_dir = child_dir / sub_name
                kw = {
                    "candidate_sha": cand_sha, "base_sha": base_sha, "ci_record": ci_ok, "qa_record": qa_ok,
                    "security_record": sec_ok, "repo": repo, "home": home, "child_dir": c_dir, "child": PARSED_CHILD,
                    "conf": conf, "builder_session_id": "builder-ac4", "builder_summary": "All checks passed.",
                    "round_num": 1, "agy_bin": str(good_agy),
                }
                kw.update(over)
                res = independent_review.evaluate_approval_gate(**kw)
                self.assertTrue(res["prerequisites"]["ci"]["verified"] and res["prerequisites"]["automated_qa"]["verified"] and res["prerequisites"]["security_review"]["verified"])
                return res

            # Baseline: clean review + valid CI/QA/Security approves
            ok_gate = run_gate("baseline-ok")
            self.assertEqual((ok_gate["delivery_approved"], ok_gate["approved_revision"], ok_gate["status"]), (True, cand_sha, "approved"))
            valid_rev = independent_review.read_json(child_dir / "baseline-ok" / "independent-review.json", home)

            # 1. Reviewer edits (Phase 1 & Phase 2 mutations, edit-then-restore, and tampered review record)
            edit_restore_agy = _make_fake_agy(
                root, "agy-ac4-er",
                "import os, pathlib\nf = pathlib.Path('src/chat_bridge/auth.py')\norig, st = f.read_bytes(), f.stat()\n"
                "f.write_bytes(orig + b'\\n# transient\\n'); f.write_bytes(orig); os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))\n"
                + _make_staged_reviewer_script(session_id="rev-ac4-er"),
            )
            for idx, (phase, kind) in enumerate(((1, "unstaged"), (1, "staged"), (1, "untracked"), (1, "commit"), (2, "unstaged"), (2, "untracked")), start=1):
                mut_agy = _make_fake_agy(root, f"agy-ac4-mut-{idx}", _make_staged_reviewer_script(session_id=f"rev-ac4-m{idx}", mutate_in_phase=phase, mutate_kind=kind))
                res_m = run_gate(f"mut-{idx}", agy_bin=str(mut_agy))
                self.assertEqual((res_m["delivery_approved"], res_m["approved_revision"], res_m["status"]), (False, None, "reviewer-modified-worktree"))
            res_er = run_gate("mut-er", agy_bin=str(edit_restore_agy))
            self.assertEqual((res_er["delivery_approved"], res_er["approved_revision"], res_er["status"]), (False, None, "reviewer-modified-worktree"))
            mut_rec = independent_review.read_json(child_dir / "mut-1" / "independent-review.json", home)
            res_mut_tampered = run_gate("mut-tampered", review_record={**mut_rec, "outcome": "review-passed", "review_verified": True, "role_separation_verified": True, "role_issues": []})
            self.assertEqual((res_mut_tampered["delivery_approved"], res_mut_tampered["status"]), (False, "reviewer-modified-worktree"))

            # 2. Reused builder identity (Phase 1 match, Phase 2 match, missing builder_session_id, tampered record)
            p1_reused_agy = _make_fake_agy(root, "agy-ac4-id1", _make_staged_reviewer_script(session_id="builder-ac4"))
            p2_reused_agy = _make_fake_agy(root, "agy-ac4-id2", _make_staged_reviewer_script(session_id="fresh-ac4", phase2_session_id="builder-ac4"))
            for label, kw_id in (
                ("p1-reused", {"agy_bin": str(p1_reused_agy)}),
                ("p2-reused", {"agy_bin": str(p2_reused_agy)}),
                ("missing-builder-id", {"builder_session_id": ""}),
                ("tampered-same-id", {"review_record": {**valid_rev, "reviewer_session_id": "builder-ac4"}}),
            ):
                res_id = run_gate(f"id-{label}", **kw_id)
                self.assertEqual((res_id["delivery_approved"], res_id["approved_revision"], res_id["status"]), (False, None, "reused-builder-identity"), label)

            # 3. Invalid review protocol (summary leak in Phase 1, missing diff, empty hypotheses, session drift, fenced JSON, unsatisfied dimension)
            with mock.patch.object(independent_review, "build_phase1_prompt", return_value="ROLE: independent-reviewer\nPHASE: 1\nBuilder summary: leaked!\nExact Base-to-Candidate Diff:\n" + Path(valid_rev["inspected_scope"]["diff_path"]).read_text(encoding="utf-8")):
                res_leak = run_gate("proto-leak")
            with mock.patch.object(independent_review, "build_phase1_prompt", return_value="ROLE: independent-reviewer\nPHASE: 1\nExact Base-to-Candidate Diff:\nno-diff\n"):
                res_nodiff = run_gate("proto-nodiff")
            empty_hyp_agy = _make_fake_agy(root, "agy-ac4-eh", _make_staged_reviewer_script(session_id="rev-eh", hypotheses=[]))
            drift_agy = _make_fake_agy(root, "agy-ac4-drift", _make_staged_reviewer_script(session_id="rev-d1", phase2_session_id="rev-d2"))
            fenced_agy = _make_fake_agy(
                root, "agy-ac4-fenced",
                _make_staged_reviewer_script(session_id="rev-fenced").replace(
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': out_sid, 'status': 'SUCCESS', 'response': resp}}))",
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': out_sid, 'status': 'SUCCESS', 'response': '```json\\n' + resp + '\\n```'}}))",
                ),
            )
            unsat_agy = _make_fake_agy(root, "agy-ac4-unsat", _make_staged_reviewer_script(session_id="rev-unsat", outcome="review-passed", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "missing"}}))
            for label, res_p in (
                ("leak", res_leak), ("nodiff", res_nodiff),
                ("empty-hyp", run_gate("proto-eh", agy_bin=str(empty_hyp_agy))),
                ("drift", run_gate("proto-drift", agy_bin=str(drift_agy))),
                ("fenced", run_gate("proto-fenced", agy_bin=str(fenced_agy))),
                ("unsat", run_gate("proto-unsat", agy_bin=str(unsat_agy))),
            ):
                self.assertEqual((res_p["delivery_approved"], res_p["approved_revision"], res_p["status"]), (False, None, "invalid-review-protocol"), label)

            # 4. Unsupported success claims (builder claim contradicted by failing check, prose-only reconciliation claims, forged check log)
            fail_child = {**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import sys; sys.exit(1)\""}]}
            res_bclaim = run_gate("claim-builder-false", child=fail_child, builder_summary="All tests passed with 0 failures!")
            self.assertEqual((res_bclaim["delivery_approved"], res_bclaim["approved_revision"], res_bclaim["status"]), (False, None, "unsupported-success-claim"))
            res_bclaim_tampered = run_gate("claim-builder-tampered", review_record={**valid_rev, "builder_summary_claim": {"summary": "passed", "treated_as_execution_evidence": True, "contradicted_by_observed_execution": False}})
            self.assertEqual((res_bclaim_tampered["delivery_approved"], res_bclaim_tampered["status"]), (False, "unsupported-success-claim"))
            concealed_rev = {**valid_rev, "builder_summary_claim": {"summary": "All checks passed.", "treated_as_execution_evidence": False, "contradicted_by_observed_execution": False}, "observed_verification": {**valid_rev["observed_verification"], "ok": True, "checks": [{**valid_rev["observed_verification"]["checks"][0], "ok": False, "exit_code": 1}, *valid_rev["observed_verification"]["checks"][1:]]}}
            self.assertEqual((run_gate("m4-concealed-contra", review_record=concealed_rev)["delivery_approved"], run_gate("m4-concealed-contra", review_record=concealed_rev)["status"]), (False, "unsupported-success-claim"))

            # M4: substituted review inputs (stripped standards, older diff, out-of-scope marked acceptable, unrelated Phase-2 prompt, missing context)
            old_diff_p, bad_p1_p, bad_p2_p = home / "m4-old.diff", home / "m4-p1.txt", home / "m4-p2.txt"
            old_diff_txt = "diff --git a/src/chat_bridge/auth.py b/src/chat_bridge/auth.py\n--- a/src/chat_bridge/auth.py\n+++ b/src/chat_bridge/auth.py\n@@ -1 +1 @@\n-# old\n+# new\n"
            old_diff_p.write_text(old_diff_txt, encoding="utf-8")
            bad_p1_p.write_text(independent_review._render_phase1_prompt(PARSED_CHILD, base_sha, cand_sha, old_diff_txt, valid_rev["applicable_standards"]), encoding="utf-8")
            bad_p2_p.write_text("Role: independent-reviewer\nPHASE: 2\nUnrelated prompt\n", encoding="utf-8")
            for m4_label, m4_over, m4_exp in (
                ("stripped-stds", {"review_record": {**valid_rev, "applicable_standards": valid_rev["applicable_standards"][:1]}}, "invalid-review"),
                ("older-diff", {"review_record": {**valid_rev, "inspected_scope": {**valid_rev["inspected_scope"], "diff_path": str(old_diff_p), "diff_sha256": runner.digest_text(old_diff_txt)}, "protocol_ordering": {**valid_rev["protocol_ordering"], "phase_1_prompt_path": str(bad_p1_p)}}}, "invalid-review-protocol"),
                ("false-in-scope", {"child": {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py"}}, "review_record": valid_rev}, "scope-violation"),
                ("unrelated-p2", {"review_record": {**valid_rev, "protocol_ordering": {**valid_rev["protocol_ordering"], "phase_2_prompt_path": str(bad_p2_p)}}}, "invalid-review-protocol"),
            ):
                m4_res = run_gate(f"m4-{m4_label}", **m4_over)
                self.assertEqual((m4_res["delivery_approved"], m4_res["status"]), (False, m4_exp), m4_label)
            self.assertFalse(independent_review.evaluate_approval_gate(candidate_sha=cand_sha, base_sha=base_sha, ci_record=ci_ok, qa_record=qa_ok, security_record=sec_ok, review_record=valid_rev, repo=None, home=home, child_dir=child_dir / "m4-no-repo", child=PARSED_CHILD, conf=conf)["delivery_approved"])

            vcmd_fail = "python3 -c \"import pathlib, sys; sys.exit(0 if '# ac4-never-added' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            fid_ac4 = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "ac4-unfixed-bug")
            prior_ac4 = [{"finding_id": fid_ac4, "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "ac4-unfixed-bug", "title": "Unfixed bug", "evidence": "r1-ev", "actionable_correction": "Add # ac4-never-added", "verification_command": vcmd_fail, "status": "open", "introduced_in_round": 1, "introduced_in_revision": base_sha}]
            for idx, bad_res in enumerate(("fixed", "no-longer-applicable", "thread-closed", "comment-resolved", "dismissed"), start=1):
                claim_agy = _make_fake_agy(root, f"agy-ac4-cl-{idx}", _make_staged_reviewer_script(session_id=f"rev-cl-{idx}", outcome="review-passed", reconciliations=[{"finding_id": fid_ac4, "resolution": bad_res, "evidence": f"claimed {bad_res} without fix"}]))
                res_cl = run_gate(f"claim-rec-{idx}", round_num=2, prior_findings=prior_ac4, agy_bin=str(claim_agy))
                self.assertEqual((res_cl["delivery_approved"], res_cl["approved_revision"], res_cl["status"]), (False, None, "unresolved-historical-blockers"), bad_res)
                self.assertIn(fid_ac4, res_cl["historical_blockers"]["unresolved_ids"])


if __name__ == "__main__":
    unittest.main()
