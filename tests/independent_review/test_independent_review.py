"""Unit and evaluation tests for the standalone independent-review role (Issue #52)."""

from __future__ import annotations

import json, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from factory import config as config_module, independent_review, intake_eval
from factory.paths import RuntimePaths
from support import git
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from tests.security_review.test_reviewer import CLEAN_AUTH_PY, EXPIRED_TEST_APPEND

PARSED_CHILD = intake_eval._evaluate("900", PARENT_TASK, [READY_CHILD])[1][0]


def _make_staged_reviewer_script(
    *,
    session_id: str = "ind-rev-1",
    phase2_session_id: str | None = None,
    hypotheses: list[str] | None = None,
    outcome: str = "review-passed",
    findings: list[dict] | None = None,
    assessment: dict | None = None,
    mutate_in_phase: int | None = None,
    mutate_kind: str = "unstaged",
) -> str:
    hyps = hypotheses if hypotheses is not None else [
        "Token validation might not strip whitespace or reject expired tokens",
        "Tests might only cover happy path without expired token assertion",
    ]
    f_list = findings if findings is not None else []
    assess = assessment if assessment is not None else {
        "requirement_compliance": {"status": "satisfied", "summary": "Implements validate_token expiry check."},
        "project_standards": {"status": "satisfied", "summary": "Follows repository conventions and scope."},
        "criterion_coverage": {"status": "satisfied", "summary": "AC-1 is covered by unit tests."},
        "edge_cases": {"status": "satisfied", "summary": "Expired prefix edge case handled."},
        "test_effectiveness": {"status": "satisfied", "summary": "Tests assert TokenExpiredError on expired token."},
        "qa_security_outcomes": {"status": "satisfied", "summary": "Same-revision QA and security evidence verified."},
    }
    p2_sid = phase2_session_id if phase2_session_id is not None else session_id
    return (
        "import json, pathlib, subprocess, sys\n"
        "prompt = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
        f"p1_sid, p2_sid = {session_id!r}, {p2_sid!r}\n"
        "if 'PHASE: 1 (pre-summary' in prompt:\n"
        "    assert 'Builder summary:' not in prompt, 'builder summary leaked into phase 1'\n"
        "    assert '@@ ' in prompt and 'diff --git' in prompt, 'exact diff missing from phase 1'\n"
        "    assert 'Requirements & Acceptance Criteria:' in prompt, 'requirements missing from phase 1'\n"
        "    assert 'Applicable Project Standards:' in prompt, 'project standards missing from phase 1'\n"
        f"    if {mutate_in_phase!r} == 1:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        f"        elif {mutate_kind!r} == 'staged': pathlib.Path('src/chat_bridge/auth.py').write_text('# stg\\n', encoding='utf-8'); subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
        f"        elif {mutate_kind!r} == 'commit': pathlib.Path('src/chat_bridge/auth.py').write_text('# cmt\\n', encoding='utf-8'); subprocess.run(['git', 'commit', '-am', 'rev edit'], check=True)\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut\\n', encoding='utf-8')\n"
        f"    resp = json.dumps({{'hypotheses': {hyps!r}}})\n"
        "    print(json.dumps({'event': 'result', 'result': {'conversation_id': p1_sid, 'status': 'SUCCESS', 'response': resp}}))\n"
        "else:\n"
        "    assert 'PHASE: 2 (substantive-assessment' in prompt, 'missing phase 2 header'\n"
        "    assert 'Persisted Phase-1 Hypotheses:' in prompt, 'missing persisted hypotheses in phase 2'\n"
        "    assert 'Builder Summary (untrusted claim):' in prompt, 'missing builder summary in phase 2'\n"
        f"    if {mutate_in_phase!r} == 2:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut2\\n', encoding='utf-8')\n"
        f"    resp = json.dumps({{'outcome': {outcome!r}, 'assessment': {assess!r}, 'findings': {f_list!r}}})\n"
        "    print(json.dumps({'event': 'result', 'result': {'conversation_id': p2_sid, 'status': 'SUCCESS', 'response': resp}}))\n"
    )


def _valid_qa_record(candidate_sha: str, base_sha: str) -> dict:
    return {
        "schema": 1, "role": "automated-qa", "status": "qa-verified", "qa_verified": True,
        "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": candidate_sha,
        "open_finding_ids": [], "findings": [],
    }


def _valid_security_record(candidate_sha: str, base_sha: str, home: Path) -> dict:
    sec_dir = home / "sec-fixture"
    sec_dir.mkdir(parents=True, exist_ok=True)
    out_p = sec_dir / "rev-stdout.txt"; out_p.write_text("ok\n", encoding="utf-8")
    chk_p = sec_dir / "chk.txt"; chk_p.write_text("ok\n", encoding="utf-8")
    from factory import runner, worker as worker_module
    return {
        "schema": 1, "role": "security-reviewer", "reviewer_executed": True, "reviewer_session_id": "sec-rev-1",
        "builder_session_id": "builder-session-1", "role_separation_verified": True, "role_issues": [],
        "reviewer_stdout_path": str(out_p), "reviewed_revision": candidate_sha, "base_sha": base_sha, "policy_sha": base_sha,
        "inspected_scope": {"changed_paths": ["src/chat_bridge/auth.py", "tests/test_auth.py"], "deterministic_ok": True},
        "applicable_policies": [{"id": "SEC-POL-01", "name": "no-hardcoded-secrets"}],
        "findings": [], "blocking_findings": [], "non_blocking_suggestions": [], "previous_findings_resolution": [],
        "safety": {"probes": [{"name": n, "attempted": True, "denied": True} for n in worker_module.REQUIRED_SAFETY_PROBES]},
        "independent_verification": {
            "executed": True, "ok": True, "head_sha": candidate_sha, "security_probe_ok": True,
            "checks": [{"name": "criterion/AC-1", "ok": True, "exit_code": 0, "timed_out": False, "head_sha": candidate_sha,
                        "output_path": str(chk_p), "output_sha256": runner.digest_text("ok\n")}],
        },
        "outcome": "approved", "ready": True,
    }


class IndependentReviewTest(unittest.TestCase):
    def _setup_workspace(self, root: Path):
        repo, home, _ = _make_disposable_product_workspace(root)
        base_sha = git(repo, "rev-parse", "refs/heads/main")
        conf = config_module.load(RuntimePaths(repo=repo, home=home))
        child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
        git(repo, "checkout", "-q", "-b", "task/101-clean", base_sha)
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
        (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "feat: validate expired token")
        cand_sha = git(repo, "rev-parse", "HEAD")
        return repo, home, base_sha, cand_sha, conf, child_dir

    def test_ac1_fresh_session_enforced_input_ordering_and_identity_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_sha, conf, child_dir = self._setup_workspace(root)
            qa_rec = _valid_qa_record(cand_sha, base_sha)
            sec_rec = _valid_security_record(cand_sha, base_sha, home)
            good_agy = _make_fake_agy(root, "agy-good", _make_staged_reviewer_script(session_id="fresh-reviewer-99"))

            def run_rev(**overrides):
                kwargs = {
                    "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf,
                    "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-session-1",
                    "builder_summary": "All checks passed and requirements met.",
                    "qa_record": qa_rec, "security_record": sec_rec, "agy_bin": str(good_agy),
                    "deadline": time.monotonic() + 30.0, "limit_s": 30,
                }
                kwargs.update(overrides)
                return independent_review.review_candidate_independently(**kwargs)

            rec = run_rev(round_num=1)
            self.assertEqual((rec["outcome"], rec["review_verified"], rec["delivery_approved"]), ("review-passed", True, False))
            self.assertEqual(rec["reviewer_session_id"], "fresh-reviewer-99")
            self.assertEqual(rec["builder_session_id"], "builder-session-1")
            self.assertTrue(rec["role_separation_verified"])
            ordering = rec["protocol_ordering"]
            self.assertTrue(ordering["enforced"])
            self.assertTrue(ordering["phase_1_omitted_builder_summary"])
            self.assertTrue(ordering["phase_1_included_exact_diff"])
            self.assertTrue(ordering["hypotheses_persisted_before_summary"])
            p1_prompt = Path(ordering["phase_1_prompt_path"]).read_text(encoding="utf-8")
            p2_prompt = Path(ordering["phase_2_prompt_path"]).read_text(encoding="utf-8")
            self.assertNotIn("All checks passed and requirements met.", p1_prompt)
            self.assertIn("diff --git a/src/chat_bridge/auth.py", p1_prompt)
            self.assertIn("All checks passed and requirements met.", p2_prompt)
            self.assertTrue(Path(ordering["hypotheses_path"]).is_file())
            self.assertEqual(len(rec["failure_hypotheses"]), 2)
            self.assertTrue(Path(rec["inspected_scope"]["diff_path"]).is_file())

            # Missing builder identity
            no_builder_id = run_rev(round_num=2, builder_session_id="")
            self.assertEqual((no_builder_id["outcome"], no_builder_id["review_verified"], no_builder_id["role_separation_verified"]),
                             ("invalid-review", False, False))
            self.assertTrue(any("builder_session_id" in i for i in no_builder_id["role_issues"]))

            # Reused builder session identity (self-approval attempt)
            reused_agy = _make_fake_agy(root, "agy-reused", _make_staged_reviewer_script(session_id="builder-session-1"))
            reused_rec = run_rev(round_num=3, agy_bin=str(reused_agy))
            self.assertEqual((reused_rec["outcome"], reused_rec["review_verified"], reused_rec["role_separation_verified"]),
                             ("invalid-review", False, False))
            self.assertTrue(any("matches builder session" in i for i in reused_rec["role_issues"]))

            # Missing reviewer session identity
            missing_rev_id_agy = _make_fake_agy(root, "agy-no-sid", _make_staged_reviewer_script(session_id=""))
            missing_sid_rec = run_rev(round_num=4, agy_bin=str(missing_rev_id_agy))
            self.assertEqual((missing_sid_rec["outcome"], missing_sid_rec["review_verified"]), ("invalid-review", False))

            # Empty hypotheses in Phase 1 prevents Phase 2 summary exposure and fails closed
            empty_hyp_agy = _make_fake_agy(root, "agy-no-hyp", _make_staged_reviewer_script(hypotheses=[]))
            empty_hyp_rec = run_rev(round_num=5, agy_bin=str(empty_hyp_agy))
            self.assertEqual((empty_hyp_rec["outcome"], empty_hyp_rec["review_verified"]), ("invalid-review", False))
            self.assertFalse(empty_hyp_rec["protocol_ordering"]["hypotheses_persisted_before_summary"])
            self.assertFalse(empty_hyp_rec["protocol_ordering"]["phase_2_executed"])

            # Attempted premature summary exposure in Phase 1 is rejected by protocol guard
            with unittest.mock.patch.object(
                independent_review, "build_phase1_prompt",
                return_value="PHASE: 1 (pre-summary)\nBuilder summary: leaked early\ndiff --git a/x b/x\n@@ -1 +1 @@\n",
            ):
                leaked_rec = run_rev(round_num=6)
            self.assertEqual((leaked_rec["outcome"], leaked_rec["review_verified"]), ("invalid-review", False))
            self.assertFalse(leaked_rec["protocol_ordering"]["phase_1_omitted_builder_summary"])
            self.assertFalse(leaked_rec["protocol_ordering"]["phase_2_executed"])

            # Attempted changed-path list substitution without exact unified diff hunks in Phase 1 is rejected
            with unittest.mock.patch.object(
                independent_review, "build_phase1_prompt",
                return_value="PHASE: 1 (pre-summary)\nChanged paths: src/chat_bridge/auth.py\n",
            ):
                path_only_rec = run_rev(round_num=7)
            self.assertEqual((path_only_rec["outcome"], path_only_rec["review_verified"]), ("invalid-review", False))
            self.assertFalse(path_only_rec["protocol_ordering"]["phase_1_included_exact_diff"])
            self.assertFalse(path_only_rec["protocol_ordering"]["phase_2_executed"])

    def test_ac2_substantive_assessment_observed_verification_and_upstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_sha, conf, child_dir = self._setup_workspace(root)
            qa_rec = _valid_qa_record(cand_sha, base_sha)
            sec_rec = _valid_security_record(cand_sha, base_sha, home)
            good_agy = _make_fake_agy(root, "agy-good-ac2", _make_staged_reviewer_script(session_id="rev-ac2"))

            def run_rev(**overrides):
                kwargs = {
                    "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf,
                    "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-1",
                    "builder_summary": "All checks passed with 0 failures.",
                    "qa_record": qa_rec, "security_record": sec_rec, "agy_bin": str(good_agy),
                    "deadline": time.monotonic() + 30.0, "limit_s": 30,
                }
                kwargs.update(overrides)
                return independent_review.review_candidate_independently(**kwargs)

            valid = run_rev(round_num=1)
            self.assertEqual((valid["outcome"], valid["review_verified"]), ("review-passed", True))
            for dim in independent_review.ASSESSMENT_KEYS:
                self.assertEqual(valid["assessment"][dim]["status"], "satisfied")
            obs_checks = valid["observed_verification"]["checks"]
            self.assertTrue(any(c["name"] == "criterion/AC-1" and c["assesses"] == "AC-1" and c["ok"] for c in obs_checks))
            for chk in obs_checks:
                self.assertTrue(Path(chk["output_path"]).is_file())
                self.assertEqual(chk["head_sha"], cand_sha)

            # Misleading "all checks passed" builder summary contradicted by actual failing check
            failing_child = {
                **PARSED_CHILD,
                "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import sys; sys.exit(1)\""}],
            }
            misleading = run_rev(round_num=2, child=failing_child, builder_summary="All checks passed! 100% green.")
            self.assertEqual((misleading["outcome"], misleading["review_verified"]), ("changes-requested", False))
            self.assertFalse(misleading["observed_verification"]["ok"])
            self.assertTrue(misleading["builder_summary_claim"]["contradicted_by_observed_execution"])
            self.assertFalse(misleading["builder_summary_claim"]["treated_as_execution_evidence"])
            self.assertTrue(any(f["category"] == "verification-gap" and f["rule"] == "check-failed" for f in misleading["blocking_findings"]))

            # Absent / unexecutable required check
            unexec_child = {**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": ""}]}
            absent_chk = run_rev(round_num=3, child=unexec_child)
            self.assertEqual((absent_chk["outcome"], absent_chk["review_verified"]), ("changes-requested", False))
            self.assertTrue(any(f["rule"] == "unexecutable-check" for f in absent_chk["blocking_findings"]))

            # Stale QA and stale security evidence cannot become a successful review
            stale_qa = {**qa_rec, "candidate_sha": "0" * 40}
            stale_sec = {**sec_rec, "reviewed_revision": "0" * 40}
            stale_res = run_rev(round_num=4, qa_record=stale_qa, security_record=stale_sec)
            self.assertEqual((stale_res["outcome"], stale_res["review_verified"]), ("changes-requested", False))
            self.assertEqual(stale_res["upstream_evidence"]["automated_qa"]["status"], "stale-qa-evidence")
            self.assertEqual(stale_res["upstream_evidence"]["security_review"]["status"], "stale-security-review")
            gap_rules = {f["rule"] for f in stale_res["blocking_findings"]}
            self.assertIn("stale-qa-evidence", gap_rules)
            self.assertIn("stale-security-evidence", gap_rules)

            # Missing QA/security evidence and failed QA evidence
            missing_up = run_rev(round_num=5, qa_record=None, security_record=None)
            self.assertEqual((missing_up["outcome"], missing_up["review_verified"]), ("changes-requested", False))
            self.assertFalse(missing_up["upstream_evidence"]["automated_qa"]["verified"])
            self.assertFalse(missing_up["upstream_evidence"]["security_review"]["verified"])

            # Timeout during observed check and malformed phase-2 reviewer output
            orig_exec = independent_review.worker_module.execute_stream
            def _timeout_on_verify(cwd, argv, env, timeout_s, **kw):
                if "unittest" in argv:
                    return 124, "", "timed out\n", 1000, True
                return orig_exec(cwd, argv, env, timeout_s, **kw)
            with unittest.mock.patch.object(independent_review.worker_module, "execute_stream", side_effect=_timeout_on_verify):
                to_rec = run_rev(round_num=6)
            self.assertEqual((to_rec["outcome"], to_rec["review_verified"]), ("changes-requested", False))
            self.assertTrue(any(f["rule"] == "check-timed-out" for f in to_rec["blocking_findings"]))

            bad_p2_agy = _make_fake_agy(root, "agy-bad-p2", _make_staged_reviewer_script(assessment={"requirement_compliance": {"status": "satisfied", "summary": "only 1"}}))
            bad_p2_rec = run_rev(round_num=7, agy_bin=str(bad_p2_agy))
            self.assertEqual((bad_p2_rec["outcome"], bad_p2_rec["review_verified"]), ("invalid-review", False))


if __name__ == "__main__":
    unittest.main()
