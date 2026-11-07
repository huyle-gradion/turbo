"""Unit and evaluation tests for the standalone independent-review role (Issue #52)."""
from __future__ import annotations
import dataclasses, json, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path: sys.path.insert(0, _p)

from factory import config as config_module, independent_review, intake_eval, runner, worker as worker_module
from factory.paths import RuntimePaths
from support import git
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from tests.security_review.test_reviewer import CLEAN_AUTH_PY, EXPIRED_TEST_APPEND

PARSED_CHILD = intake_eval._evaluate("900", PARENT_TASK, [READY_CHILD])[1][0]
DEFAULT_ASSESSMENT = {k: {"status": "satisfied", "summary": f"{k} satisfied on candidate."} for k in independent_review.ASSESSMENT_KEYS}

def _make_staged_reviewer_script(*, session_id: str = "ind-rev-1", phase2_session_id: str | None = None, hypotheses: list[str] | None = None, outcome: str = "review-passed", findings: list[dict] | None = None, reconciliations: list[dict] | None = None, assessment: dict | None = None, mutate_in_phase: int | None = None, mutate_kind: str = "unstaged") -> str:
    hyps = hypotheses if hypotheses is not None else ["Token validation might not strip whitespace or reject expired tokens", "Tests might only cover happy path without expired token assertion"]
    f_list, r_list, assess = findings or [], reconciliations or [], assessment or DEFAULT_ASSESSMENT
    return (
        "import json, pathlib, subprocess, sys\n"
        "prompt = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
        f"p1_sid, p2_override = {session_id!r}, {phase2_session_id!r}\n"
        "if 'PHASE: 1 (pre-summary' in prompt:\n"
        "    assert '--conversation' not in sys.argv and '--continue' not in sys.argv and '-c' not in sys.argv\n"
        "    for forbidden in ('Builder summary:', 'Builder Summary'): assert forbidden not in prompt\n"
        "    for req in ('@@ ', 'diff --git', 'Requirements & Acceptance Criteria:', 'Applicable Project Standards:'): assert req in prompt\n"
        "    pathlib.Path.home().joinpath('.phase1_sid').write_text(p1_sid, encoding='utf-8')\n"
        f"    if {mutate_in_phase!r} == 1:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        f"        elif {mutate_kind!r} == 'staged': pathlib.Path('src/chat_bridge/auth.py').write_text('# stg\\n', encoding='utf-8'); subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
        f"        elif {mutate_kind!r} == 'commit': pathlib.Path('src/chat_bridge/auth.py').write_text('# cmt\\n', encoding='utf-8'); subprocess.run(['git', 'commit', '-am', 'rev edit'], check=True)\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut\\n', encoding='utf-8')\n"
        f"    print(json.dumps({{'event': 'result', 'result': {{'conversation_id': p1_sid, 'status': 'SUCCESS', 'response': json.dumps({{'hypotheses': {hyps!r}}})}}}}))\n"
        "else:\n"
        "    assert '--conversation' in sys.argv, 'missing --conversation continuation flag in phase 2'\n"
        "    resumed_sid = sys.argv[sys.argv.index('--conversation') + 1]\n"
        "    assert resumed_sid == pathlib.Path.home().joinpath('.phase1_sid').read_text(encoding='utf-8').strip()\n"
        "    for req in ('PHASE: 2 (substantive-assessment', 'Persisted Phase-1 Hypotheses:', 'Prior Blocking Findings Requiring Verified Reconciliation:', 'Builder Summary (untrusted claim):'): assert req in prompt\n"
        f"    if {mutate_in_phase!r} == 2:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut2\\n', encoding='utf-8')\n"
        "    out_sid = p2_override if p2_override is not None else resumed_sid\n"
        f"    resp = json.dumps({{'outcome': {outcome!r}, 'assessment': {assess!r}, 'findings': {f_list!r}, 'reconciliations': {r_list!r}}})\n"
        "    print(json.dumps({'event': 'result', 'result': {'conversation_id': out_sid, 'status': 'SUCCESS', 'response': resp}}))\n"
    )

def _valid_qa_record(candidate_sha: str, base_sha: str, tested_sha: str | None = None) -> dict:
    t_sha = tested_sha or candidate_sha
    return {
        "schema": 1, "role": "automated-qa", "status": "qa-verified", "qa_verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": t_sha,
        "ci_revalidation": {"status": "verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": t_sha, "blockers": []},
        "role_separation": {"role": "automated-qa", "head_before": candidate_sha, "head_after": candidate_sha, "worktree_clean": True, "candidate_modified_by_qa": False},
        "criterion_coverage": [{"criterion_id": "AC-1", "description": "Reject expired auth tokens", "passed": True, "deterministic_check": {"command": "python3 -m unittest -v", "executed": True, "passed": True, "timed_out": False, "exit_code": 0, "status": "passed"}, "evaluation_cases": []}],
        "regression_checks": [{"id": "gate-2", "kind": "guard", "executed": True, "passed": True, "timed_out": False, "exit_code": 0}],
        "regression_passed": True, "open_finding_ids": [], "findings": [],
        "parent_acceptance_boundary": {"parent_gid": "900", "parent_accepted": False, "parent_acceptance_status": "pending-human-acceptance"},
    }

def _valid_security_record(candidate_sha: str, base_sha: str, home: Path) -> dict:
    sec_dir = home / "sec-fixture"; sec_dir.mkdir(parents=True, exist_ok=True)
    out_p, chk_p = sec_dir / "rev-stdout.txt", sec_dir / "chk.txt"
    out_p.write_text("ok\n", encoding="utf-8"); chk_p.write_text("ok\n", encoding="utf-8")
    return {
        "schema": 1, "role": "security-reviewer", "reviewer_executed": True, "reviewer_session_id": "sec-rev-1", "builder_session_id": "builder-session-1",
        "role_separation_verified": True, "role_issues": [], "reviewer_stdout_path": str(out_p), "reviewed_revision": candidate_sha, "base_sha": base_sha, "policy_sha": base_sha,
        "inspected_scope": {"changed_paths": ["src/chat_bridge/auth.py", "tests/test_auth.py"], "deterministic_ok": True},
        "applicable_policies": [{"id": "SEC-POL-01", "name": "no-hardcoded-secrets"}], "findings": [], "blocking_findings": [], "non_blocking_suggestions": [], "previous_findings_resolution": [],
        "safety": {"probes": [{"name": n, "attempted": True, "denied": True} for n in worker_module.REQUIRED_SAFETY_PROBES]},
        "independent_verification": {"executed": True, "ok": True, "head_sha": candidate_sha, "security_probe_ok": True, "checks": [{"name": "criterion/AC-1", "ok": True, "exit_code": 0, "timed_out": False, "head_sha": candidate_sha, "output_path": str(chk_p), "output_sha256": runner.digest_text("ok\n")}]},
        "outcome": "approved", "ready": True,
    }

class IndependentReviewTest(unittest.TestCase):
    def _setup_workspace(self, root: Path):
        repo, home, _ = _make_disposable_product_workspace(root)
        base_sha = git(repo, "rev-parse", "refs/heads/main")
        conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "900" / "attempt-1" / "children" / "101"
        git(repo, "checkout", "-q", "-b", "task/101-clean", base_sha)
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
        (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "feat: validate expired token")
        cand_sha = git(repo, "rev-parse", "HEAD")
        qa_rec, sec_rec = _valid_qa_record(cand_sha, base_sha), _valid_security_record(cand_sha, base_sha, home)
        good_agy = _make_fake_agy(root, "agy-good", _make_staged_reviewer_script(session_id="fresh-reviewer-99"))
        def run_rev(**overrides):
            kwargs = {"repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf, "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-session-1", "builder_summary": "All checks passed and requirements met.", "qa_record": qa_rec, "security_record": sec_rec, "agy_bin": str(good_agy), "deadline": time.monotonic() + 30.0, "limit_s": 30}
            kwargs.update(overrides)
            return independent_review.review_candidate_independently(**kwargs)
        return repo, home, base_sha, cand_sha, conf, child_dir, qa_rec, sec_rec, run_rev

    def test_ac1_fresh_session_enforced_input_ordering_and_identity_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            rec = run_rev(round_num=1)
            self.assertEqual((rec["outcome"], rec["review_verified"], rec["delivery_approved"]), ("review-passed", True, False))
            self.assertEqual((rec["reviewer_session_id"], rec["builder_session_id"], rec["role_separation_verified"]), ("fresh-reviewer-99", "builder-session-1", True))
            ordering = rec["protocol_ordering"]
            self.assertTrue(ordering["enforced"] and ordering["phase_1_omitted_builder_summary"] and ordering["phase_1_included_exact_diff"] and ordering["hypotheses_persisted_before_summary"])
            p1_prompt, p2_prompt = Path(ordering["phase_1_prompt_path"]).read_text(encoding="utf-8"), Path(ordering["phase_2_prompt_path"]).read_text(encoding="utf-8")
            self.assertNotIn("All checks passed and requirements met.", p1_prompt)
            self.assertIn("diff --git a/src/chat_bridge/auth.py", p1_prompt)
            self.assertIn("All checks passed and requirements met.", p2_prompt)
            self.assertTrue(Path(ordering["hypotheses_path"]).is_file() and Path(rec["inspected_scope"]["diff_path"]).is_file())
            self.assertEqual(len(rec["failure_hypotheses"]), 2)
            no_builder_id = run_rev(round_num=2, builder_session_id="")
            self.assertEqual((no_builder_id["outcome"], no_builder_id["review_verified"], no_builder_id["role_separation_verified"]), ("invalid-review", False, False))
            reused_agy = _make_fake_agy(root, "agy-reused", _make_staged_reviewer_script(session_id="builder-session-1"))
            reused_rec = run_rev(round_num=3, agy_bin=str(reused_agy))
            self.assertEqual((reused_rec["outcome"], reused_rec["review_verified"], reused_rec["role_separation_verified"]), ("invalid-review", False, False))
            missing_rev_id_agy = _make_fake_agy(root, "agy-no-sid", _make_staged_reviewer_script(session_id=""))
            self.assertEqual(run_rev(round_num=4, agy_bin=str(missing_rev_id_agy))["outcome"], "invalid-review")
            empty_hyp_agy = _make_fake_agy(root, "agy-no-hyp", _make_staged_reviewer_script(hypotheses=[]))
            empty_hyp_rec = run_rev(round_num=5, agy_bin=str(empty_hyp_agy))
            self.assertEqual((empty_hyp_rec["outcome"], empty_hyp_rec["protocol_ordering"]["phase_2_executed"]), ("invalid-review", False))
            with mock.patch.object(independent_review, "build_phase1_prompt", return_value="PHASE: 1\nBuilder summary: leaked\ndiff --git a/x b/x\n@@ -1 +1 @@\n"):
                leaked_rec = run_rev(round_num=6)
            self.assertEqual((leaked_rec["outcome"], leaked_rec["protocol_ordering"]["phase_1_omitted_builder_summary"], leaked_rec["protocol_ordering"]["phase_2_executed"]), ("invalid-review", False, False))
            with mock.patch.object(independent_review, "build_phase1_prompt", return_value="PHASE: 1\nChanged paths: src/chat_bridge/auth.py\n"):
                path_only_rec = run_rev(round_num=7)
            self.assertEqual((path_only_rec["outcome"], path_only_rec["protocol_ordering"]["phase_1_included_exact_diff"], path_only_rec["protocol_ordering"]["phase_2_executed"]), ("invalid-review", False, False))

    def test_ac2_substantive_assessment_observed_verification_and_upstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, cand_sha, _, _, qa_rec, sec_rec, run_rev = self._setup_workspace(root)
            valid = run_rev(round_num=1)
            self.assertEqual((valid["outcome"], valid["review_verified"]), ("review-passed", True))
            for dim in independent_review.ASSESSMENT_KEYS: self.assertEqual(valid["assessment"][dim]["status"], "satisfied")
            obs_checks = valid["observed_verification"]["checks"]
            self.assertTrue(any(c["name"] == "criterion/AC-1" and c["assesses"] == "AC-1" and c["ok"] for c in obs_checks))
            for chk in obs_checks: self.assertTrue(Path(chk["output_path"]).is_file() and chk["head_sha"] == cand_sha)
            failing_child = {**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import sys; sys.exit(1)\""}]}
            misleading = run_rev(round_num=2, child=failing_child, builder_summary="All checks passed! 100% green.")
            self.assertEqual((misleading["outcome"], misleading["review_verified"], misleading["observed_verification"]["ok"]), ("changes-requested", False, False))
            self.assertTrue(misleading["builder_summary_claim"]["contradicted_by_observed_execution"] and not misleading["builder_summary_claim"]["treated_as_execution_evidence"])
            self.assertTrue(any(f["category"] == "verification-gap" and f["rule"] == "check-failed" for f in misleading["blocking_findings"]))
            absent_chk = run_rev(round_num=3, child={**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": ""}]})
            self.assertEqual((absent_chk["outcome"], absent_chk["review_verified"]), ("changes-requested", False))
            self.assertTrue(any(f["rule"] == "unexecutable-check" for f in absent_chk["blocking_findings"]))
            stale_res = run_rev(round_num=4, qa_record={**qa_rec, "candidate_sha": "0" * 40}, security_record={**sec_rec, "reviewed_revision": "0" * 40})
            self.assertEqual((stale_res["outcome"], stale_res["review_verified"]), ("changes-requested", False))
            self.assertEqual((stale_res["upstream_evidence"]["automated_qa"]["status"], stale_res["upstream_evidence"]["security_review"]["status"]), ("stale-qa-evidence", "stale-security-review"))
            self.assertTrue({"stale-qa-evidence", "stale-security-evidence"}.issubset({f["rule"] for f in stale_res["blocking_findings"]}))
            missing_up = run_rev(round_num=5, qa_record=None, security_record=None)
            self.assertEqual((missing_up["outcome"], missing_up["review_verified"]), ("changes-requested", False))
            orig_exec = independent_review.worker_module.execute_stream
            with mock.patch.object(independent_review.worker_module, "execute_stream", side_effect=lambda cwd, argv, env, timeout_s, **kw: (124, "", "timed out\n", 1000, True) if "unittest" in argv else orig_exec(cwd, argv, env, timeout_s, **kw)):
                to_rec = run_rev(round_num=6)
            self.assertEqual((to_rec["outcome"], to_rec["review_verified"]), ("changes-requested", False))
            self.assertTrue(any(f["rule"] == "check-timed-out" for f in to_rec["blocking_findings"]))
            bad_p2_agy = _make_fake_agy(root, "agy-bad-p2", _make_staged_reviewer_script(assessment={"requirement_compliance": {"status": "satisfied", "summary": "only 1"}}))
            self.assertEqual(run_rev(round_num=7, agy_bin=str(bad_p2_agy))["outcome"], "invalid-review")

    def test_ac3_actionable_findings_categories_incomplete_rejection_and_identity_stability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, child_dir, _, _, run_rev = self._setup_workspace(root)
            five_cat_findings = [
                {"category": "missing-behavior", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "missing-whitespace-strip", "title": "Token whitespace not stripped", "evidence": "src/chat_bridge/auth.py:3", "actionable_correction": "Call token.strip() before prefix check."},
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted", "title": "Empty token returns valid sub", "evidence": "validate_token('') -> {'sub': ''}", "actionable_correction": "Raise ValueError on empty token."},
                {"category": "verification-gap", "blocking": True, "target": "tests/test_auth.py", "rule": "missing-blank-token-test", "title": "No test for blank token", "evidence": "tests/test_auth.py lacks blank token test", "actionable_correction": "Add test_blank_token in tests/test_auth.py."},
                {"category": "scope-drift", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "extra-helper-export", "title": "Unrequested helper in auth module", "evidence": "diff adds unrequested symbol", "actionable_correction": "Remove unrequested symbol."},
                {"category": "non-blocking-suggestion", "blocking": False, "target": "src/chat_bridge/auth.py", "rule": "docstring-nit", "title": "Add docstring to validate_token", "evidence": "line 2", "actionable_correction": "Optional docstring."},
            ]
            five_agy = _make_fake_agy(root, "agy-five", _make_staged_reviewer_script(session_id="rev-ac3-1", outcome="changes-requested", findings=five_cat_findings))
            r_five = run_rev(round_num=1, agy_bin=str(five_agy))
            self.assertEqual((r_five["outcome"], r_five["review_verified"], len(r_five["blocking_findings"]), len(r_five["non_blocking_suggestions"])), ("changes-requested", False, 4, 1))
            self.assertEqual({f["category"] for f in r_five["findings"]}, independent_review.FINDING_CATEGORIES)
            sugg_only_agy = _make_fake_agy(root, "agy-sugg-only", _make_staged_reviewer_script(session_id="rev-ac3-2", outcome="review-passed", findings=[five_cat_findings[4]]))
            r_sugg = run_rev(round_num=1, child_dir=child_dir / "sugg-only", agy_bin=str(sugg_only_agy))
            self.assertEqual((r_sugg["outcome"], r_sugg["review_verified"], r_sugg["delivery_approved"], len(r_sugg["blocking_findings"]), len(r_sugg["non_blocking_suggestions"])), ("review-passed", True, False, 0, 1))
            f_pos1 = [{"finding_id": "LINE-10-POS-0", "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted", "line": 10, "title": "Empty token bug", "evidence": "line 10: return {'sub': token}", "actionable_correction": "Reject empty token."}, five_cat_findings[0]]
            f_pos2 = [five_cat_findings[0], {"finding_id": "LINE-42-POS-1", "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted", "line": 42, "title": "Empty token bug shifted", "evidence": "line 42: return {'sub': token}", "actionable_correction": "Reject empty token."}]
            _, _, parsed_pos1, iss1 = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": DEFAULT_ASSESSMENT, "findings": f_pos1}))
            _, _, parsed_pos2, iss2 = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": DEFAULT_ASSESSMENT, "findings": f_pos2}))
            self.assertEqual((iss1, iss2), ([], []))
            id1 = [f["finding_id"] for f in parsed_pos1 if f["rule"] == "empty-token-accepted"][0]
            id2 = [f["finding_id"] for f in parsed_pos2 if f["rule"] == "empty-token-accepted"][0]
            self.assertEqual(id1, "REV-BUG-src-chat-bridge-auth-py-empty-token-accepted"); self.assertEqual(id1, id2)
            for bad_finding in (
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "r1", "evidence": "", "actionable_correction": "fix"},
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "r1", "evidence": "ev", "actionable_correction": ""},
                {"category": "bug", "blocking": True, "target": "", "rule": "r1", "evidence": "ev", "actionable_correction": "fix"},
                {"category": "unknown-cat", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "r1", "evidence": "ev", "actionable_correction": "fix"},
            ):
                _, _, _, bad_issues = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": DEFAULT_ASSESSMENT, "findings": [bad_finding]}))
                self.assertTrue(bad_issues, f"expected rejection for {bad_finding}")

    def test_ac4_ac5_reviewer_edit_prohibition_adversarial_coverage_and_disposable_demo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            for idx, (phase, kind) in enumerate(((1, "unstaged"), (1, "staged"), (1, "untracked"), (1, "commit"), (2, "unstaged"), (2, "untracked")), start=1):
                mut_agy = _make_fake_agy(root, f"agy-mut-{idx}", _make_staged_reviewer_script(session_id=f"rev-mut-{idx}", mutate_in_phase=phase, mutate_kind=kind))
                rec = run_rev(round_num=idx, agy_bin=str(mut_agy))
                self.assertEqual((rec["outcome"], rec["review_verified"], rec["role_separation_verified"], rec["delivery_approved"]), ("invalid-review", False, False, False))
                self.assertTrue(rec["worktree_integrity"]["candidate_modified_by_reviewer"])
                mut_ev_path = Path(rec["worktree_integrity"]["mutation_evidence_path"])
                self.assertTrue(mut_ev_path.is_file() and f"phase=phase{phase}" in mut_ev_path.read_text(encoding="utf-8"))
                self.assertFalse(rec["observed_verification"]["executed"])
            demo_dir = root / "demo"; demo_dir.mkdir(parents=True, exist_ok=True)
            summary = run_disposable_demo(demo_dir)
            self.assertEqual((summary["valid_review"]["outcome"], summary["valid_review"]["review_verified"], summary["valid_review"]["delivery_approved"]), ("review-passed", True, False))

    def test_m1_automated_qa_evidence_contract_and_integration_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_sha, _, child_dir, qa_rec, sec_rec, run_rev = self._setup_workspace(root)
            git(repo, "checkout", "-q", "-b", "pr-merge-test", base_sha)
            (repo / "README.md").write_text("base update\n", encoding="utf-8")
            git(repo, "add", "README.md"); git(repo, "commit", "-q", "-m", "base advance")
            git(repo, "checkout", "-q", "-b", "merge-sim", base_sha)
            git(repo, "merge", "--no-ff", "-q", "-m", "Merge candidate into base", cand_sha)
            merge_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "task/101-clean")
            merge_qa = {**_valid_qa_record(cand_sha, base_sha, tested_sha=merge_sha), "revision_kind": "integration-merge"}
            merge_rec = run_rev(round_num=10, qa_record=merge_qa)
            self.assertEqual((merge_rec["outcome"], merge_rec["review_verified"], merge_rec["upstream_evidence"]["automated_qa"]["verified"]), ("review-passed", True, True))
            bad_parents_rec = run_rev(round_num=11, qa_record={**merge_qa, "merge_parents": [{}, {}]})
            self.assertEqual((bad_parents_rec["outcome"], bad_parents_rec["review_verified"], bad_parents_rec["upstream_evidence"]["automated_qa"]["verified"], (child_dir / "independent-review-round-11" / "record.json").is_file()), ("changes-requested", False, False, True))
            for label, bad_qa in (
                ("missing-role-sep", {k: v for k, v in qa_rec.items() if k != "role_separation"}), ("missing-ci-reval", {k: v for k, v in qa_rec.items() if k != "ci_revalidation"}),
                ("missing-reg-passed", {k: v for k, v in qa_rec.items() if k != "regression_passed"}), ("missing-coverage", {**qa_rec, "criterion_coverage": []}),
                ("unmet-criterion", {**qa_rec, "criterion_coverage": [{**qa_rec["criterion_coverage"][0], "criterion_id": "OTHER-AC"}]}),
                ("str-false-qa-verified", {**qa_rec, "qa_verified": "false"}), ("str-false-reg-passed", {**qa_rec, "regression_passed": "false"}),
                ("str-false-ci-reval", {**qa_rec, "ci_revalidation": {**qa_rec["ci_revalidation"], "verified": "false"}}),
                ("unverified-merge-sha", {**qa_rec, "tested_sha": "a" * 40, "revision_kind": "integration-merge"}),
                ("malformed-ci-reval", {**qa_rec, "ci_revalidation": "not-a-dict"}), ("malformed-role-sep", {**qa_rec, "role_separation": ["not-a-dict"]}),
                ("malformed-coverage", {**qa_rec, "criterion_coverage": ["not-a-dict"]}), ("malformed-findings", {**qa_rec, "findings": ["not-a-dict"]}),
                ("malformed-open-ids", {**qa_rec, "open_finding_ids": "not-a-list"}),
            ):
                qa_ev, _, gaps = independent_review.evaluate_upstream_evidence(cand_sha, base_sha, bad_qa, sec_rec, home=home, repo=repo, child=PARSED_CHILD)
                self.assertFalse(qa_ev["verified"], f"expected M1 rejection for {label}"); self.assertTrue(gaps)

    def test_m2_structural_summary_omission_and_execution_input_redaction(self) -> None:
        sentinel = "ghp_M2_SECRET_TOKEN_99"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# builder summary note\n", encoding="utf-8")
            git(repo, "add", "src/chat_bridge/auth.py"); git(repo, "commit", "-q", "-m", "diff with builder summary phrase")
            cand2 = git(repo, "rev-parse", "HEAD")
            qa2, sec2 = _valid_qa_record(cand2, base_sha), _valid_security_record(cand2, base_sha, home)
            cap_script = ("import pathlib, sys\np = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
                          "pathlib.Path.home().joinpath('cap1.txt' if 'PHASE: 1' in p else 'cap2.txt').write_text(p, encoding='utf-8')\n") + _make_staged_reviewer_script(session_id="rev-m2")
            cap_agy = _make_fake_agy(root, "agy-cap-m2", cap_script)
            crit_desc = PARSED_CHILD["criteria"][0]["description"]
            with mock.patch.dict("os.environ", {"TURBO_GITHUB_TOKEN": sentinel}):
                r_overlap = run_rev(round_num=1, candidate_sha=cand2, qa_record=qa2, security_record=sec2, agy_bin=str(cap_agy), builder_summary=crit_desc)
                self.assertEqual((r_overlap["outcome"], r_overlap["review_verified"]), ("review-passed", True))
                r_sec = run_rev(round_num=2, candidate_sha=cand2, qa_record=qa2, security_record=sec2, agy_bin=str(cap_agy), child={**PARSED_CHILD, "name": f"Auth {sentinel}"}, builder_summary=f"{crit_desc} SUMMARY_ONLY_M2 {sentinel}")
            self.assertEqual((r_sec["outcome"], r_sec["review_verified"]), ("review-passed", True))
            iso_home = Path(r_sec["safety"]["isolated_home"])
            p1_in, p2_in = (iso_home / "cap1.txt").read_text(encoding="utf-8"), (iso_home / "cap2.txt").read_text(encoding="utf-8")
            self.assertIn("# builder summary note", p1_in); self.assertIn(crit_desc, p1_in)
            self.assertNotIn("SUMMARY_ONLY_M2", p1_in); self.assertIn("SUMMARY_ONLY_M2", p2_in)
            self.assertNotIn(sentinel, p1_in); self.assertNotIn(sentinel, p2_in)

    def test_m3_two_phase_reviewer_session_continuation_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            valid = run_rev(round_num=1)
            self.assertEqual((valid["outcome"], valid["review_verified"], valid["protocol_ordering"].get("phase_2_continued_session_id")), ("review-passed", True, "fresh-reviewer-99"))
            drifted_agy = _make_fake_agy(root, "agy-drifted", _make_staged_reviewer_script(session_id="fresh-1", phase2_session_id="drifted-2"))
            drifted = run_rev(round_num=2, agy_bin=str(drifted_agy))
            self.assertEqual((drifted["outcome"], drifted["review_verified"], drifted["role_separation_verified"]), ("invalid-review", False, False))
            p2_builder_agy = _make_fake_agy(root, "agy-p2-builder", _make_staged_reviewer_script(session_id="fresh-1", phase2_session_id="builder-session-1"))
            p2_builder = run_rev(round_num=3, agy_bin=str(p2_builder_agy))
            self.assertEqual((p2_builder["outcome"], p2_builder["review_verified"], p2_builder["role_separation_verified"]), ("invalid-review", False, False))

    def test_m4_substantive_base_revision_standards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            git(repo, "checkout", "-q", "main")
            (repo / "CONTRIBUTING.md").write_text("# Contributing Guide\n\n## Coding Standards\n- STD-TOKEN-NORM-01: Always strip token whitespace before validation.\n", encoding="utf-8")
            git(repo, "add", "CONTRIBUTING.md"); git(repo, "commit", "-q", "-m", "add substantive standard")
            base_m4 = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "-b", "task/101-m4", base_m4)
            (repo / "CONTRIBUTING.md").write_text("# Contributing Guide\n- STD-WEAKENED-99: Whitespace normalization is optional.\n", encoding="utf-8")
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "cand attempts to weaken standard")
            cand_m4 = git(repo, "rev-parse", "HEAD")
            qa_m4, sec_m4 = _valid_qa_record(cand_m4, base_m4), _valid_security_record(cand_m4, base_m4, home)
            viol_assess = {**DEFAULT_ASSESSMENT, "project_standards": {"status": "unsatisfied", "summary": "Violated base standard STD-TOKEN-NORM-01."}}
            viol_finding = [{"category": "missing-behavior", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "std-token-norm-01", "title": "Base standard STD-TOKEN-NORM-01 violated", "evidence": "src/chat_bridge/auth.py lacks strip()", "actionable_correction": "Strip whitespace per STD-TOKEN-NORM-01."}]
            std_agy = _make_fake_agy(root, "agy-m4", "import sys\np = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\nstd_sec = p.split('Exact Base-to-Candidate Diff:', 1)[0]\nassert 'STD-TOKEN-NORM-01: Always strip token whitespace' in std_sec and 'STD-WEAKENED-99' not in std_sec\n" + _make_staged_reviewer_script(session_id="rev-m4", outcome="changes-requested", assessment=viol_assess, findings=viol_finding))
            child_m4 = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, tests/test_auth.py, CONTRIBUTING.md"}}
            rec = run_rev(round_num=1, base_sha=base_m4, candidate_sha=cand_m4, child=child_m4, qa_record=qa_m4, security_record=sec_m4, agy_bin=str(std_agy))
            p1_txt = Path(rec["protocol_ordering"]["phase_1_prompt_path"]).read_text(encoding="utf-8")
            self.assertIn("STD-TOKEN-NORM-01: Always strip token whitespace before validation.", p1_txt.split("Exact Base-to-Candidate Diff:", 1)[0])
            self.assertNotIn("STD-WEAKENED-99", p1_txt.split("Exact Base-to-Candidate Diff:", 1)[0])
            self.assertEqual((rec["outcome"], rec["review_verified"], rec["assessment"]["project_standards"]["status"]), ("changes-requested", False, "unsatisfied"))

    def test_m5_reviewer_write_and_host_execution_bypasses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            edit_restore = _make_fake_agy(root, "agy-edit-restore", "import os, pathlib\nf = pathlib.Path('src/chat_bridge/auth.py')\norig, st = f.read_bytes(), f.stat()\nf.write_bytes(orig + b'\\n# transient\\n'); f.write_bytes(orig); os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))\n" + _make_staged_reviewer_script(session_id="rev-m5-er"))
            r1 = run_rev(round_num=1, agy_bin=str(edit_restore))
            self.assertEqual((r1["outcome"], r1["review_verified"], r1["worktree_integrity"]["candidate_modified_by_reviewer"]), ("invalid-review", False, True))
            ignored_agy = _make_fake_agy(root, "agy-ignored", "import pathlib\npathlib.Path('.git/info/exclude').write_text('*.ignored\\n', encoding='utf-8')\npathlib.Path('secret.ignored').write_text('x', encoding='utf-8')\n" + _make_staged_reviewer_script(session_id="rev-m5-ig"))
            r2 = run_rev(round_num=2, agy_bin=str(ignored_agy))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["worktree_integrity"]["candidate_modified_by_reviewer"]), ("invalid-review", False, True))
            git_marker = root / "host-git-executed.sentinel"
            git_cfg_agy = _make_fake_agy(root, "agy-gitcfg", f"import pathlib\npathlib.Path('.git/config').write_text('[core]\\n\\tfsmonitor = touch {git_marker}\\n', encoding='utf-8')\n" + _make_staged_reviewer_script(session_id="rev-m5-cfg"))
            r3 = run_rev(round_num=3, agy_bin=str(git_cfg_agy))
            self.assertFalse(git_marker.exists())
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["worktree_integrity"]["candidate_modified_by_reviewer"]), ("invalid-review", False, True))
            site_marker = root / "sitecustomize-executed.sentinel"
            git(repo, "checkout", "-q", "-b", "task/101-site", base_sha)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
            (repo / "tests/sitecustomize.py").write_text(f"import pathlib; pathlib.Path({str(site_marker)!r}).write_text('pwn')\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "plant sitecustomize in tests")
            cand_site = git(repo, "rev-parse", "HEAD")
            child_site = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, tests/test_auth.py, tests/sitecustomize.py"}}
            r4 = run_rev(round_num=4, candidate_sha=cand_site, child=child_site, qa_record=_valid_qa_record(cand_site, base_sha), security_record=_valid_security_record(cand_site, base_sha, home))
            self.assertFalse(site_marker.exists()); self.assertTrue(r4["observed_verification"]["executed"])
            r5 = run_rev(round_num=5)
            self.assertEqual((r5["outcome"], r5["review_verified"], r5["worktree_integrity"]["candidate_modified_by_reviewer"]), ("review-passed", True, False))
            mode_restore = _make_fake_agy(root, "agy-mode-restore", "import pathlib\nf = pathlib.Path('src/chat_bridge/auth.py'); m = f.stat().st_mode; f.chmod(m ^ 0o111); f.chmod(m)\n" + _make_staged_reviewer_script(session_id="rev-m5-mr"))
            r_mode = run_rev(round_num=6, agy_bin=str(mode_restore))
            with mock.patch.object(independent_review, "_open_inotify_watch", return_value=None):
                r_no_inotify = run_rev(round_num=7, agy_bin=str(edit_restore))
            self.assertEqual(((r_mode["outcome"], r_mode["review_verified"], r_mode["worktree_integrity"]["candidate_modified_by_reviewer"], Path(r_mode["worktree_integrity"]["mutation_evidence_path"] or "/nonexistent").is_file()), (r_no_inotify["outcome"], r_no_inotify["review_verified"], r_no_inotify["worktree_integrity"]["candidate_modified_by_reviewer"], Path(r_no_inotify["worktree_integrity"]["mutation_evidence_path"] or "/nonexistent").is_file())), (("invalid-review", False, True, True), ("invalid-review", False, True, True)))

    def test_m6_required_checks_and_truthful_execution_recording(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            non_unit_conf = config_module.load(RuntimePaths(repo=repo, home=home))
            non_unit_conf = dataclasses.replace(non_unit_conf, gates={**non_unit_conf.gates, "2": dataclasses.replace(non_unit_conf.gates["2"], argv=(sys.executable, "-c", "print('smoke-only')"))})
            r1 = run_rev(round_num=1, conf=non_unit_conf)
            names1 = [c["name"] for c in r1["observed_verification"]["checks"]]
            self.assertIn("regression/gate-2", names1); self.assertIn("regression/full-suite", names1)
            with mock.patch("factory.ci_selection.select_ci_test_plan", return_value={"mode": "affected-only", "reason": "empty", "changed_paths": ["src/chat_bridge/auth.py"], "deleted_tests": [], "test_deletion_detected": False, "essential_guards": [], "criterion_checks": [], "affected_tests": []}):
                r2 = run_rev(round_num=2, conf=non_unit_conf)
                self.assertIn("regression/full-suite", [c["name"] for c in r2["observed_verification"]["checks"]])
            git(repo, "checkout", "-q", "-b", "task/101-prot-del", base_sha)
            (repo / "factory/ci_selection.py").parent.mkdir(parents=True, exist_ok=True)
            (repo / "factory/ci_selection.py").write_text("# modified policy\n", encoding="utf-8")
            (repo / "tests/test_auth.py").unlink()
            git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "touch protected policy and delete test")
            cand_pd = git(repo, "rev-parse", "HEAD")
            child_pd = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "factory/ci_selection.py, tests/test_auth.py"}}
            r3 = run_rev(round_num=3, candidate_sha=cand_pd, child=child_pd, qa_record=_valid_qa_record(cand_pd, base_sha), security_record=_valid_security_record(cand_pd, base_sha, home))
            fids3 = {f["finding_id"] for f in r3["blocking_findings"]}
            self.assertTrue(any("SCOPE-DRIFT" in fid for fid in fids3)); self.assertTrue(any("deleted-test-coverage" in fid for fid in fids3))
            orig_exec = worker_module.execute_stream
            def _sb_fail(wt, argv, env, timeout_s, *, isolated_home=None, allow_network=False):
                if not allow_network: raise worker_module.SandboxUnavailableError("landlock blocked in verify")
                return orig_exec(wt, argv, env, timeout_s, isolated_home=isolated_home, allow_network=allow_network)
            with mock.patch.object(worker_module, "execute_stream", side_effect=_sb_fail):
                r4 = run_rev(round_num=4, builder_summary="All checks passed.")
            chk4 = r4["observed_verification"]["checks"][0]
            self.assertEqual((chk4["executed"], chk4["exit_code"], r4["builder_summary_claim"]["contradicted_by_observed_execution"]), (False, None, False))
            slow_child = {**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import time; time.sleep(5)\""}]}
            r5 = run_rev(round_num=5, child=slow_child, deadline=time.monotonic() + 1.2, limit_s=1, builder_summary="All checks passed.")
            chk5 = next(c for c in r5["observed_verification"]["checks"] if c["kind"] == "criterion")
            self.assertEqual((chk5["executed"], chk5.get("completed"), chk5["timed_out"], chk5["ok"], r5["builder_summary_claim"]["contradicted_by_observed_execution"]), (True, False, True, False, True))
            orig_obs = independent_review._run_observed_verification
            with mock.patch.object(independent_review, "_run_observed_verification", side_effect=lambda *a, **kw: orig_obs(*a[:-2], time.monotonic() - 1.0, a[-1], **kw)):
                r6 = run_rev(round_num=6, builder_summary="All checks passed.")
            chk6 = r6["observed_verification"]["checks"][0]
            self.assertEqual((r6["observed_verification"]["executed"], chk6["executed"], chk6["exit_code"], chk6["timed_out"], r6["builder_summary_claim"]["contradicted_by_observed_execution"], r6["outcome"], r6["review_verified"]), (False, False, None, False, False, "changes-requested", False))

    def test_m7_coherent_actionable_review_findings(self) -> None:
        unsat = {**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "Missing edge case."}}
        _, _, _, i1 = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": unsat, "findings": []}))
        _, _, _, i2 = independent_review._parse_phase2_response(json.dumps({"outcome": "review-passed", "assessment": unsat, "findings": []}))
        self.assertTrue(i1 and i2)
        for bad_blk in ("true", 1, None):
            _, _, _, ib = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": unsat, "findings": [{"category": "bug", "blocking": bad_blk, "target": "src/a.py", "rule": "r1", "title": "t", "evidence": "e", "actionable_correction": "c"}]}))
            self.assertTrue(ib)
        for bad_t, bad_r in (("---", "valid-rule"), ("src/a.py", "???")):
            _, _, _, ip = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": unsat, "findings": [{"category": "bug", "blocking": True, "target": bad_t, "rule": bad_r, "title": "t", "evidence": "e", "actionable_correction": "c"}]}))
            self.assertTrue(ip)
        out_ok, _, f_ok, i_ok = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": unsat, "findings": [{"category": "bug", "blocking": True, "target": "src/a.py", "rule": "null-deref", "title": "Null", "evidence": "line 9", "actionable_correction": "Guard None."}]}))
        self.assertEqual((out_ok, len(f_ok), i_ok, f_ok[0]["finding_id"]), ("changes-requested", 1, [], "REV-BUG-src-a-py-null-deref"))

    def test_m8_preserve_evidence_on_operational_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, child_dir, _, _, run_rev = self._setup_workspace(root)
            nonexec = root / "agy-nonexec"
            nonexec.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8"); nonexec.chmod(0o644)
            r1, r2, r3 = run_rev(round_num=1, agy_bin=str(root / "missing-agy")), run_rev(round_num=2, agy_bin=str(nonexec)), run_rev(round_num=3, deadline=time.monotonic() - 1.0)
            with mock.patch.object(worker_module, "execute_stream", side_effect=OSError("execve failed")): r4 = run_rev(round_num=4)
            with mock.patch.object(worker_module, "execute_stream", side_effect=TimeoutError("phase timeout")): r5 = run_rev(round_num=5)
            for idx, rec in enumerate((r1, r2, r3, r4, r5), start=1):
                self.assertEqual((rec["outcome"], rec["review_verified"]), ("invalid-review", False))
                self.assertTrue(rec["role_issues"] and (child_dir / f"independent-review-round-{idx}" / "record.json").is_file())
            self.assertTrue((child_dir / "independent-review.json").is_file())

    def test_ac6_multi_round_blocker_reconciliation_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, child_dir, _, _, run_rev = self._setup_workspace(root)
            vcmd_fix = "python3 -c \"import pathlib, sys; sys.exit(0 if 'if not token:' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            vcmd_nla = "python3 -c \"import pathlib, sys; sys.exit(0 if not pathlib.Path('src/chat_bridge/legacy_helper.py').exists() else 1)\""
            (repo / "src/chat_bridge/legacy_helper.py").write_text("LEGACY = True\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 1 with blank-token bug and legacy helper")
            cand1 = git(repo, "rev-parse", "HEAD")
            child_ac6 = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, src/chat_bridge/legacy_helper.py, tests/test_auth.py"}}
            fid_fix = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "empty-token-accepted")
            fid_nla = independent_review.compute_review_finding_id("scope-drift", "src/chat_bridge/legacy_helper.py", "unneeded-legacy-helper")
            r1_findings = [
                {"finding_id": "TEMP-ID-1", "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted", "title": "Empty token accepted", "evidence": "round-1: validate_token('bearer ') returns empty sub", "actionable_correction": "Reject empty token with ValueError.", "verification_command": vcmd_fix},
                {"finding_id": "TEMP-ID-2", "category": "scope-drift", "blocking": True, "target": "src/chat_bridge/legacy_helper.py", "rule": "unneeded-legacy-helper", "title": "Legacy helper module added", "evidence": "round-1: legacy_helper.py is unnecessary", "actionable_correction": "Remove legacy_helper.py.", "verification_command": vcmd_nla},
                {"category": "non-blocking-suggestion", "blocking": False, "target": "src/chat_bridge/auth.py", "rule": "doc-nit", "title": "Docstring nit", "evidence": "line 1", "actionable_correction": "Optional docstring."},
            ]
            agy_r1 = _make_fake_agy(root, "agy-ac6-r1", _make_staged_reviewer_script(session_id="rev-ac6-r1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "Empty token not rejected."}}, findings=r1_findings))
            r1 = run_rev(round_num=1, candidate_sha=cand1, child=child_ac6, qa_record=_valid_qa_record(cand1, base_sha), security_record=_valid_security_record(cand1, base_sha, home), agy_bin=str(agy_r1))
            self.assertEqual((r1["outcome"], r1["review_verified"], r1["delivery_approved"], set(r1["open_finding_ids"])), ("changes-requested", False, False, {fid_fix, fid_nla}))
            self.assertTrue((child_dir / "prior-blockers.json").is_file() and r1["observed_verification"]["finding_verifications"][fid_fix]["reproduced"])

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# ineffective comment\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 2 ineffective fix")
            cand2 = git(repo, "rev-parse", "HEAD")
            r2_reconcils = [{"finding_id": fid_fix, "resolution": "fixed", "evidence": "round-2: builder edited auth.py"}, {"finding_id": fid_nla, "resolution": "no-longer-applicable", "evidence": "round-2: helper unused"}]
            agy_r2 = _make_fake_agy(root, "agy-ac6-r2", _make_staged_reviewer_script(session_id="rev-ac6-r2", outcome="review-passed", reconciliations=r2_reconcils))
            r2 = run_rev(round_num=2, candidate_sha=cand2, child=child_ac6, qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy_r2))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["delivery_approved"], set(r2["open_finding_ids"])), ("changes-requested", False, False, {fid_fix, fid_nla}))
            by_id_r2 = {f["finding_id"]: f for f in r2["blocking_findings"]}
            for fid, orig_ev in ((fid_fix, "round-1: validate_token('bearer ') returns empty sub"), (fid_nla, "round-1: legacy_helper.py is unnecessary")):
                f2 = by_id_r2[fid]
                self.assertEqual((f2["status"], f2["resolution"], f2["resolution_blocker"], f2["introduced_in_round"], f2["introduced_in_revision"], f2["last_seen_round"], f2["last_seen_revision"], f2["resolved_in_round"], f2["evidence"], len(f2["history"]), len(f2["evidence_history"])), ("open", None, "check-failed", 1, cand1, 2, cand2, None, orig_ev, 2, 2))

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY.replace("return {'sub': token}", "if not token:\n        raise ValueError('empty token')\n    return {'sub': token}"), encoding="utf-8")
            (repo / "src/chat_bridge/legacy_helper.py").unlink()
            git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "round 3 verified correction")
            cand3 = git(repo, "rev-parse", "HEAD")
            r3_reconcils = [{"finding_id": fid_fix, "resolution": "fixed", "evidence": "round-3: empty token raises ValueError"}, {"finding_id": fid_nla, "resolution": "no-longer-applicable", "evidence": "round-3: legacy_helper.py removed from candidate"}]
            agy_r3 = _make_fake_agy(root, "agy-ac6-r3", _make_staged_reviewer_script(session_id="rev-ac6-r3", outcome="review-passed", reconciliations=r3_reconcils))
            r3 = run_rev(round_num=3, candidate_sha=cand3, child=child_ac6, qa_record=_valid_qa_record(cand3, base_sha), security_record=_valid_security_record(cand3, base_sha, home), agy_bin=str(agy_r3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["delivery_approved"], r3["blocking_findings"], r3["open_finding_ids"]), ("review-passed", True, False, [], []))
            by_id_r3 = {f["finding_id"]: f for f in r3["findings"] if f["blocking"]}
            self.assertEqual((by_id_r3[fid_fix]["status"], by_id_r3[fid_fix]["resolution"], by_id_r3[fid_fix]["resolved_in_round"], by_id_r3[fid_fix]["resolved_in_revision"], by_id_r3[fid_fix]["introduced_in_round"], by_id_r3[fid_fix]["introduced_in_revision"], by_id_r3[fid_fix]["evidence"], len(by_id_r3[fid_fix]["history"]), len(by_id_r3[fid_fix]["evidence_history"])), ("resolved", "fixed", 3, cand3, 1, cand1, "round-1: validate_token('bearer ') returns empty sub", 3, 3))
            self.assertEqual((by_id_r3[fid_nla]["status"], by_id_r3[fid_nla]["resolution"], by_id_r3[fid_nla]["resolved_in_round"], by_id_r3[fid_nla]["resolved_in_revision"], len(by_id_r3[fid_nla]["history"])), ("resolved", "no-longer-applicable", 3, cand3, 3))
            self.assertEqual(([h["status"] for h in by_id_r3[fid_fix]["history"]], [h["resolution_blocker"] for h in by_id_r3[fid_fix]["history"]]), (["open", "open", "resolved"], ["active-finding", "check-failed", None]))
            for fid in (fid_fix, fid_nla):
                ver = by_id_r3[fid]["reproducer_verification"]
                self.assertTrue(ver["ok"] and ver["head_sha"] == cand3 and Path(ver["output_path"]).is_file())

    def test_ac7_omitted_blockers_and_invalid_resolutions_remain_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand1, _, _, _, _, run_rev = self._setup_workspace(root)
            vcmd_pass = "python3 -m unittest tests.test_auth -v"
            b1 = {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "b1-rule", "title": "Blocker 1", "evidence": "r1-b1-ev", "actionable_correction": "Fix b1.", "verification_command": vcmd_pass}
            b2 = {"category": "missing-behavior", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "b2-rule", "title": "Blocker 2", "evidence": "r1-b2-ev", "actionable_correction": "Fix b2."}
            fid1, fid2 = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "b1-rule"), independent_review.compute_review_finding_id("missing-behavior", "src/chat_bridge/auth.py", "b2-rule")
            agy1 = _make_fake_agy(root, "agy-ac7-1", _make_staged_reviewer_script(session_id="rev-ac7-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "requirement_compliance": {"status": "unsatisfied", "summary": "Two blockers."}}, findings=[b1, b2]))
            r1 = run_rev(round_num=1, agy_bin=str(agy1))
            self.assertEqual(set(r1["open_finding_ids"]), {fid1, fid2})

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# r2 update\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 2 commit")
            cand2 = git(repo, "rev-parse", "HEAD")
            agy2_omit = _make_fake_agy(root, "agy-ac7-2", _make_staged_reviewer_script(session_id="rev-ac7-2", outcome="review-passed", reconciliations=[{"finding_id": fid1, "resolution": "fixed", "evidence": "b1 verified"}]))
            r2 = run_rev(round_num=2, candidate_sha=cand2, qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2_omit))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["delivery_approved"], r2["open_finding_ids"]), ("changes-requested", False, False, [fid2]))
            res_map2 = {r["finding_id"]: r for r in r2["previous_findings_resolution"]}
            self.assertEqual((res_map2[fid1]["status"], res_map2[fid2]["status"], res_map2[fid2]["resolution_blocker"]), ("resolved", "open", "omitted-from-review"))

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# r3 update\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "round 3 commit")
            cand3 = git(repo, "rev-parse", "HEAD")
            agy3 = _make_fake_agy(root, "agy-ac7-3", _make_staged_reviewer_script(session_id="rev-ac7-3", outcome="review-passed", reconciliations=[{"finding_id": fid2, "resolution": "fixed", "evidence": "b2 now verified", "verification_command": vcmd_pass}]))
            r3 = run_rev(round_num=3, candidate_sha=cand3, qa_record=_valid_qa_record(cand3, base_sha), security_record=_valid_security_record(cand3, base_sha, home), agy_bin=str(agy3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["delivery_approved"], r3["open_finding_ids"]), ("review-passed", True, False, []))
            by_id3 = {f["finding_id"]: f for f in r3["findings"] if f["blocking"]}
            self.assertEqual((by_id3[fid1]["resolved_in_round"], by_id3[fid1]["resolved_in_revision"], by_id3[fid2]["resolved_in_round"], by_id3[fid2]["resolved_in_revision"]), (2, cand2, 3, cand3))

            obs_ok, valid_chk = r3["observed_verification"], r3["observed_verification"]["finding_verifications"][fid2]
            prior_open = [{**by_id3[fid2], "status": "open", "resolved_in_round": None, "resolved_in_revision": None, "last_seen_round": 2, "last_seen_revision": cand2, "verification_command": ""}]
            for label, rec_override, kw_extra, exp_blocker in (
                ("omitted", {}, {}, "omitted-from-review"),
                ("thread-closed", {fid2: {"finding_id": fid2, "resolution": "thread-closed", "evidence": "thread closed in PR"}}, {}, "thread-closure-only"),
                ("comment-resolved", {fid2: {"finding_id": fid2, "resolution": "comment-resolved", "evidence": "resolved comment"}}, {}, "thread-closure-only"),
                ("dismissed", {fid2: {"finding_id": fid2, "resolution": "dismissed", "evidence": "dismissed"}}, {}, "thread-closure-only"),
                ("unsupported-fixed", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "looks good in prose only"}}, {"obs_ver": {**obs_ok, "finding_verifications": {}}}, "unsupported-assertion"),
                ("unsupported-nla", {fid2: {"finding_id": fid2, "resolution": "no-longer-applicable", "evidence": "not needed anymore"}}, {"obs_ver": {**obs_ok, "finding_verifications": {}}}, "unsupported-assertion"),
                ("unbound-check", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "wrong target check"}}, {"obs_ver": {**obs_ok, "finding_verifications": {fid2: {**valid_chk, "finding_id": "REV-OTHER", "assesses": "OTHER-TARGET", "name": "finding/REV-OTHER"}}}}, "unsupported-assertion"),
                ("downgrade-sugg", {}, {"agent_findings": [{"finding_id": "REV-SUGG", "category": "non-blocking-suggestion", "blocking": False, "target": "src/chat_bridge/auth.py", "rule": "b2-rule", "title": "Downgraded", "evidence": "nit", "actionable_correction": "opt"}]}, "unsupported-assertion"),
                ("missing-ev-text", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": ""}}, {}, "missing-evidence"),
                ("unexecuted-chk", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "unexecuted"}}, {"obs_ver": {**obs_ok, "finding_verifications": {fid2: {**valid_chk, "executed": False, "ok": False}}}}, "missing-verification"),
                ("missing-log", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "missing log"}}, {"obs_ver": {**obs_ok, "finding_verifications": {fid2: {**valid_chk, "output_path": str(home / "nonexistent.log")}}}}, "missing-verification"),
                ("tampered-digest", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "bad digest"}}, {"obs_ver": {**obs_ok, "finding_verifications": {fid2: {**valid_chk, "output_sha256": "0" * 64}}}}, "missing-verification"),
                ("stale-ev-sha", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "old sha", "evidence_sha": cand1}}, {}, "stale-evidence"),
                ("stale-same-rev", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "same rev"}}, {"candidate_sha": cand2}, "stale-evidence"),
                ("stale-chk-sha", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "old chk"}}, {"obs_ver": {**obs_ok, "finding_verifications": {fid2: {**valid_chk, "head_sha": cand1}}}}, "stale-evidence"),
                ("stale-qa", {fid2: {"finding_id": fid2, "resolution": "fixed", "evidence": "stale qa"}}, {"qa_eval": {"status": "stale-qa-evidence", "verified": False}}, "stale-evidence"),
            ):
                kw = {"round_num": 3, "candidate_sha": cand3, "base_sha": base_sha, "agent_findings": [], "det_findings": [], "prior_findings": prior_open, "reconciliations": rec_override, "obs_ver": obs_ok, "qa_eval": {"status": "qa-verified", "verified": True}, "sec_eval": {"status": "approved", "verified": True}, "home": home, **kw_extra}
                _, blk_f, _, res_f = independent_review.reconcile_review_findings(**kw)
                self.assertEqual((len(blk_f), blk_f[0]["finding_id"], blk_f[0]["status"], res_f[0]["resolution_blocker"]), (1, fid2, "open", exp_blocker), f"failed invalid-resolution check for {label}")

    def test_reconcil_m1_persisted_blockers_and_corrupt_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand1, _, child_dir, _, _, run_rev = self._setup_workspace(root)
            fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "m1-persisted-rule")
            b1 = {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "m1-persisted-rule", "title": "M1 bug", "evidence": "r1-m1-ev", "actionable_correction": "Fix m1."}
            agy1 = _make_fake_agy(root, "agy-m1-1", _make_staged_reviewer_script(session_id="rev-m1-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "m1"}}, findings=[b1]))
            r1 = run_rev(round_num=1, agy_bin=str(agy1))
            self.assertEqual(r1["open_finding_ids"], [fid])
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m1 r2\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m1 r2")
            cand2 = git(repo, "rev-parse", "HEAD")
            agy2 = _make_fake_agy(root, "agy-m1-2", _make_staged_reviewer_script(session_id="rev-m1-2", outcome="review-passed"))
            r2 = run_rev(round_num=2, candidate_sha=cand2, prior_findings=[], qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["delivery_approved"], r2["open_finding_ids"]), ("changes-requested", False, False, [fid]))
            f2 = r2["blocking_findings"][0]
            self.assertEqual((f2["finding_id"], f2["status"], f2["resolution_blocker"], f2["introduced_in_round"], f2["introduced_in_revision"], f2["evidence"], len(f2["history"])), (fid, "open", "omitted-from-review", 1, cand1, "r1-m1-ev", 2))
            for corrupt_payload in ("{corrupt-json", json.dumps({"findings": "not-a-list"})):
                (child_dir / "prior-blockers.json").write_text(corrupt_payload, encoding="utf-8")
                with self.assertRaises(independent_review.errors_module.FactoryError):
                    independent_review._normalize_prior_findings(child_dir, home, 3, [])
                r3 = run_rev(round_num=3, candidate_sha=cand2, prior_findings=[], qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2))
                self.assertEqual((r3["outcome"], r3["review_verified"], r3["delivery_approved"]), ("invalid-review", False, False))
                self.assertTrue(r3["role_issues"] and fid in r3["open_finding_ids"] and any(f["finding_id"] == fid and f["status"] == "open" for f in r3["blocking_findings"]))

    def test_reconcil_m2_reject_forged_or_relabelled_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            vcmd = "python3 -c \"import pathlib, sys; sys.exit(0 if '# m2-fixed' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            fid_cmd = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "m2-cmd-bug")
            fid_nocmd = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "m2-nocmd-bug")
            r1_findings = [
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "m2-cmd-bug", "title": "M2 cmd", "evidence": "r1-cmd", "actionable_correction": "Add # m2-fixed", "verification_command": vcmd},
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "m2-nocmd-bug", "title": "M2 nocmd", "evidence": "r1-nocmd", "actionable_correction": "Fix nocmd"},
            ]
            agy1 = _make_fake_agy(root, "agy-m2-1", _make_staged_reviewer_script(session_id="rev-m2-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "m2"}}, findings=r1_findings))
            r1 = run_rev(round_num=1, agy_bin=str(agy1))
            self.assertEqual(set(r1["open_finding_ids"]), {fid_cmd, fid_nocmd})
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m2-unfixed\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m2 r2 unfixed")
            cand2 = git(repo, "rev-parse", "HEAD")
            unrelated_log = Path(r1["observed_verification"]["checks"][0]["output_path"])
            unrelated_sha = r1["observed_verification"]["checks"][0]["output_sha256"]
            forged_ver = {"finding_id": fid_nocmd, "name": f"finding/{fid_nocmd}", "assesses": fid_nocmd, "kind": "finding-reproducer", "command": vcmd, "argv": ["python3"], "executed": True, "completed": True, "ok": True, "exit_code": 0, "timed_out": False, "head_sha": cand2, "output_path": str(unrelated_log), "output_sha256": unrelated_sha, "provenance": "observed-finding-reproducer"}
            r2_reconcils = [
                {"finding_id": fid_cmd, "resolution": "fixed", "evidence": "forged over failing check", "reproducer_verification": {**forged_ver, "finding_id": fid_cmd, "name": f"finding/{fid_cmd}", "assesses": fid_cmd}},
                {"finding_id": fid_nocmd, "resolution": "fixed", "evidence": "reviewer-authored flags without execution", "reproducer_verification": forged_ver},
            ]
            agy2 = _make_fake_agy(root, "agy-m2-2", _make_staged_reviewer_script(session_id="rev-m2-2", outcome="review-passed", reconciliations=r2_reconcils))
            r2 = run_rev(round_num=2, candidate_sha=cand2, qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2))
            self.assertEqual((r2["outcome"], r2["review_verified"], set(r2["open_finding_ids"])), ("changes-requested", False, {fid_cmd, fid_nocmd}))
            ac1_chk = r2["observed_verification"]["checks"][0]
            relabelled_chk = {**ac1_chk, "finding_id": fid_cmd, "name": f"finding/{fid_cmd}", "assesses": fid_cmd, "kind": "finding-reproducer", "command": vcmd, "provenance": "observed-finding-reproducer"}
            flipped_fail_chk = {**r2["observed_verification"]["finding_verifications"][fid_cmd], "ok": True, "exit_code": 0}
            for bad_chk in (relabelled_chk, flipped_fail_chk, forged_ver):
                _, blk_m2, _, _ = independent_review.reconcile_review_findings(round_num=2, candidate_sha=cand2, base_sha=base_sha, agent_findings=[], det_findings=[], prior_findings=r1["blocking_findings"], reconciliations={fid_cmd: {"finding_id": fid_cmd, "resolution": "fixed", "evidence": "claim"}}, obs_ver={**r2["observed_verification"], "finding_verifications": {fid_cmd: bad_chk}}, qa_eval={"status": "qa-verified", "verified": True}, sec_eval={"status": "approved", "verified": True}, home=home)
                self.assertIn(fid_cmd, [f["finding_id"] for f in blk_m2])
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m2-fixed\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m2 r3 fixed")
            cand3 = git(repo, "rev-parse", "HEAD")
            r3_reconcils = [{"finding_id": fid_cmd, "resolution": "fixed", "evidence": "genuinely fixed"}, {"finding_id": fid_nocmd, "resolution": "fixed", "evidence": "genuinely fixed with cmd", "verification_command": vcmd}]
            agy3 = _make_fake_agy(root, "agy-m2-3", _make_staged_reviewer_script(session_id="rev-m2-3", outcome="review-passed", reconciliations=r3_reconcils))
            r3 = run_rev(round_num=3, candidate_sha=cand3, qa_record=_valid_qa_record(cand3, base_sha), security_record=_valid_security_record(cand3, base_sha, home), agy_bin=str(agy3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["open_finding_ids"]), ("review-passed", True, []))

    def test_reconcil_m3_preserve_prior_verification_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, child_dir, _, _, run_rev = self._setup_workspace(root)
            vcmd_orig = "python3 -c \"import pathlib, sys; sys.exit(0 if '# m3-real-fix' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "m3-repro-rule")
            b1 = {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "m3-repro-rule", "title": "M3 bug", "evidence": "r1-m3", "actionable_correction": "Add # m3-real-fix", "verification_command": vcmd_orig}
            agy1 = _make_fake_agy(root, "agy-m3-1", _make_staged_reviewer_script(session_id="rev-m3-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "m3"}}, findings=[b1]))
            r1 = run_rev(round_num=1, agy_bin=str(agy1))
            self.assertEqual(r1["open_finding_ids"], [fid])
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m3-still-broken\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m3 r2 unfixed")
            cand2 = git(repo, "rev-parse", "HEAD")
            agy2 = _make_fake_agy(root, "agy-m3-2", _make_staged_reviewer_script(session_id="rev-m3-2", outcome="review-passed", reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "trivial replacement", "verification_command": "python3 -c \"pass\""}]))
            r2 = run_rev(round_num=2, candidate_sha=cand2, qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["open_finding_ids"]), ("changes-requested", False, [fid]))
            f2 = r2["blocking_findings"][0]
            fver2 = r2["observed_verification"]["finding_verifications"][fid]
            persisted2 = json.loads((child_dir / "prior-blockers.json").read_text(encoding="utf-8"))["findings"][0]
            self.assertEqual((f2["verification_command"], persisted2["verification_command"], fver2["command"], fver2["ok"], f2["resolution_blocker"]), (vcmd_orig, vcmd_orig, vcmd_orig, False, "check-failed"))
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m3-real-fix\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m3 r3 fixed")
            cand3 = git(repo, "rev-parse", "HEAD")
            agy3 = _make_fake_agy(root, "agy-m3-3", _make_staged_reviewer_script(session_id="rev-m3-3", outcome="review-passed", reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "real fix verified"}]))
            r3 = run_rev(round_num=3, candidate_sha=cand3, qa_record=_valid_qa_record(cand3, base_sha), security_record=_valid_security_record(cand3, base_sha, home), agy_bin=str(agy3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["open_finding_ids"]), ("review-passed", True, []))

    def test_reconcil_m4_reject_generic_criterion_and_historical_deletion_shortcuts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            git(repo, "checkout", "-q", "main")
            (repo / "src/chat_bridge/needed.py").write_text("NEEDED = 1\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "base with needed.py")
            base_m4 = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "-b", "task/101-m4-reconcil", base_m4)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
            (repo / "src/chat_bridge/needed.py").unlink()
            git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "m4 r1 delete needed.py")
            cand1 = git(repo, "rev-parse", "HEAD")
            child_m4 = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, src/chat_bridge/needed.py, tests/test_auth.py"}}
            fid_ac1 = independent_review.compute_review_finding_id("missing-behavior", "AC-1", "m4-ac1-edge-case")
            fid_del = independent_review.compute_review_finding_id("bug", "src/chat_bridge/needed.py", "m4-accidental-deletion")
            r1_findings = [
                {"category": "missing-behavior", "blocking": True, "target": "AC-1", "rule": "m4-ac1-edge-case", "title": "AC-1 edge case", "evidence": "r1-ac1", "actionable_correction": "Add # m4-ac1-fixed"},
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/needed.py", "rule": "m4-accidental-deletion", "title": "Deleted needed.py", "evidence": "r1-del", "actionable_correction": "Restore or replace needed.py"},
            ]
            agy1 = _make_fake_agy(root, "agy-m4-r1", _make_staged_reviewer_script(session_id="rev-m4-r1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "criterion_coverage": {"status": "unsatisfied", "summary": "m4"}}, findings=r1_findings))
            r1 = run_rev(round_num=1, base_sha=base_m4, candidate_sha=cand1, child=child_m4, qa_record=_valid_qa_record(cand1, base_m4), security_record=_valid_security_record(cand1, base_m4, home), agy_bin=str(agy1))
            self.assertEqual(set(r1["open_finding_ids"]), {fid_ac1, fid_del})
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m4-noop\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m4 r2 noop")
            cand2 = git(repo, "rev-parse", "HEAD")
            r2_reconcils = [{"finding_id": fid_ac1, "resolution": "fixed", "evidence": "generic AC-1 passed"}, {"finding_id": fid_del, "resolution": "no-longer-applicable", "evidence": "needed.py still deleted"}]
            agy2 = _make_fake_agy(root, "agy-m4-r2", _make_staged_reviewer_script(session_id="rev-m4-r2", outcome="review-passed", reconciliations=r2_reconcils))
            r2 = run_rev(round_num=2, base_sha=base_m4, candidate_sha=cand2, child=child_m4, qa_record=_valid_qa_record(cand2, base_m4), security_record=_valid_security_record(cand2, base_m4, home), agy_bin=str(agy2))
            self.assertEqual((r2["outcome"], r2["review_verified"], set(r2["open_finding_ids"])), ("changes-requested", False, {fid_ac1, fid_del}))
            for f2 in r2["blocking_findings"]: self.assertEqual(f2["resolution_blocker"], "unsupported-assertion")
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m4-ac1-fixed\nNEEDED = 1\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m4 r3 genuine fix")
            cand3 = git(repo, "rev-parse", "HEAD")
            vcmd_ac1 = "python3 -c \"import pathlib, sys; sys.exit(0 if '# m4-ac1-fixed' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            vcmd_del = "python3 -c \"import pathlib, sys; sys.exit(0 if 'NEEDED = 1' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
            r3_reconcils = [{"finding_id": fid_ac1, "resolution": "fixed", "evidence": "edge case verified", "verification_command": vcmd_ac1}, {"finding_id": fid_del, "resolution": "no-longer-applicable", "evidence": "NEEDED moved to auth.py", "verification_command": vcmd_del}]
            agy3 = _make_fake_agy(root, "agy-m4-r3", _make_staged_reviewer_script(session_id="rev-m4-r3", outcome="review-passed", reconciliations=r3_reconcils))
            r3 = run_rev(round_num=3, base_sha=base_m4, candidate_sha=cand3, child=child_m4, qa_record=_valid_qa_record(cand3, base_m4), security_record=_valid_security_record(cand3, base_m4, home), agy_bin=str(agy3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["open_finding_ids"]), ("review-passed", True, []))

    def test_reconcil_m5_active_blocker_overrides_contradictory_fixed_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            vcmd = "python3 -m unittest tests.test_auth -v"
            fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "m5-active-rule")
            b1 = {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "m5-active-rule", "title": "M5 active bug", "evidence": "r1-m5-ev", "actionable_correction": "Fix m5.", "verification_command": vcmd}
            agy1 = _make_fake_agy(root, "agy-m5-1", _make_staged_reviewer_script(session_id="rev-m5-1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "m5"}}, findings=[b1]))
            r1 = run_rev(round_num=1, agy_bin=str(agy1))
            self.assertEqual(r1["open_finding_ids"], [fid])
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m5-r2\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m5 r2")
            cand2 = git(repo, "rev-parse", "HEAD")
            agy2 = _make_fake_agy(root, "agy-m5-2", _make_staged_reviewer_script(session_id="rev-m5-2", outcome="changes-requested", findings=[{**b1, "evidence": "r2-still-broken"}], reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "contradictory fixed claim"}]))
            r2 = run_rev(round_num=2, candidate_sha=cand2, qa_record=_valid_qa_record(cand2, base_sha), security_record=_valid_security_record(cand2, base_sha, home), agy_bin=str(agy2))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["open_finding_ids"]), ("changes-requested", False, [fid]))
            self.assertEqual((r2["blocking_findings"][0]["status"], r2["blocking_findings"][0]["resolution_blocker"]), ("open", "re-reported-by-reviewer"))
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# m5-r3\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "m5 r3")
            cand3 = git(repo, "rev-parse", "HEAD")
            agy3 = _make_fake_agy(root, "agy-m5-3", _make_staged_reviewer_script(session_id="rev-m5-3", outcome="review-passed", reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "now resolved without active finding"}]))
            r3 = run_rev(round_num=3, candidate_sha=cand3, qa_record=_valid_qa_record(cand3, base_sha), security_record=_valid_security_record(cand3, base_sha, home), agy_bin=str(agy3))
            self.assertEqual((r3["outcome"], r3["review_verified"], r3["open_finding_ids"]), ("review-passed", True, []))

def run_disposable_demo(tmp: Path) -> dict:
    repo, home, _ = _make_disposable_product_workspace(tmp)
    base_sha = git(repo, "rev-parse", "refs/heads/main")
    conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "demo-52" / "children" / "101"
    git(repo, "checkout", "-q", "-b", "task/101-auth", base_sha)
    (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
    (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-q", "-m", "feat: validate expired token")
    cand_sha = git(repo, "rev-parse", "HEAD")
    qa_rec, sec_rec = _valid_qa_record(cand_sha, base_sha), _valid_security_record(cand_sha, base_sha, home)
    good_agy = _make_fake_agy(tmp, "agy-demo-good", _make_staged_reviewer_script(session_id="fresh-reviewer-demo"))
    reused_agy = _make_fake_agy(tmp, "agy-demo-reused", _make_staged_reviewer_script(session_id="builder-demo-1"))
    mut_agy = _make_fake_agy(tmp, "agy-demo-mut", _make_staged_reviewer_script(session_id="fresh-reviewer-mut", mutate_in_phase=2, mutate_kind="unstaged"))
    def _call(round_num: int, **kw):
        args = {"repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf, "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-demo-1", "builder_summary": "All checks passed.", "qa_record": qa_rec, "security_record": sec_rec, "round_num": round_num, "agy_bin": str(good_agy), "deadline": time.monotonic() + 30.0, "limit_s": 30}
        args.update(kw)
        return independent_review.review_candidate_independently(**args)
    r_valid, r_self = _call(1), _call(2, agy_bin=str(reused_agy))
    r_false_claim = _call(3, child={**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import sys; sys.exit(1)\""}]}, builder_summary="All checks passed with zero errors!")
    r_missing_chk = _call(4, child={**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": ""}]})
    r_stale_up, r_mutated = _call(5, qa_record={**qa_rec, "candidate_sha": "0" * 40}), _call(6, agy_bin=str(mut_agy))
    rec_dir = home / "deliveries" / "demo-55" / "children" / "101"
    vcmd_demo = "python3 -c \"import pathlib, sys; sys.exit(0 if '# reconciled-fix' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
    fid_demo = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "demo-reconcil-bug")
    agy_d1 = _make_fake_agy(tmp, "agy-d1", _make_staged_reviewer_script(session_id="rev-d1", outcome="changes-requested", assessment={**DEFAULT_ASSESSMENT, "edge_cases": {"status": "unsatisfied", "summary": "bug"}}, findings=[{"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "demo-reconcil-bug", "title": "Demo bug", "evidence": "r1-demo-ev", "actionable_correction": "Add # reconciled-fix", "verification_command": vcmd_demo}]))
    d1 = _call(1, child_dir=rec_dir, agy_bin=str(agy_d1))
    (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# ineffective\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "demo r2 ineffective")
    cand_d2 = git(repo, "rev-parse", "HEAD")
    agy_d2 = _make_fake_agy(tmp, "agy-d2", _make_staged_reviewer_script(session_id="rev-d2", outcome="review-passed", reconciliations=[{"finding_id": fid_demo, "resolution": "fixed", "evidence": "r2-ineffective-claim"}]))
    d2 = _call(2, child_dir=rec_dir, candidate_sha=cand_d2, qa_record=_valid_qa_record(cand_d2, base_sha), security_record=_valid_security_record(cand_d2, base_sha, home), agy_bin=str(agy_d2))
    (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# reconciled-fix\n", encoding="utf-8"); git(repo, "add", "."); git(repo, "commit", "-q", "-m", "demo r3 verified fix")
    cand_d3 = git(repo, "rev-parse", "HEAD")
    agy_d3 = _make_fake_agy(tmp, "agy-d3", _make_staged_reviewer_script(session_id="rev-d3", outcome="review-passed", reconciliations=[{"finding_id": fid_demo, "resolution": "fixed", "evidence": "r3-verified-claim"}]))
    d3 = _call(3, child_dir=rec_dir, candidate_sha=cand_d3, qa_record=_valid_qa_record(cand_d3, base_sha), security_record=_valid_security_record(cand_d3, base_sha, home), agy_bin=str(agy_d3))
    summary = {
        "valid_review": {"outcome": r_valid["outcome"], "review_verified": r_valid["review_verified"], "delivery_approved": r_valid["delivery_approved"], "verification_scope": r_valid["verification_scope"], "ordering_enforced": r_valid["protocol_ordering"]["enforced"], "hypotheses_count": len(r_valid["failure_hypotheses"]), "record_path": str(child_dir / "independent-review-round-1" / "record.json")},
        "self_approval_rejected": {"outcome": r_self["outcome"], "review_verified": r_self["review_verified"]},
        "false_builder_claim_rejected": {"outcome": r_false_claim["outcome"], "review_verified": r_false_claim["review_verified"], "contradicted": r_false_claim["builder_summary_claim"]["contradicted_by_observed_execution"]},
        "missing_check_rejected": {"outcome": r_missing_chk["outcome"], "review_verified": r_missing_chk["review_verified"]},
        "stale_upstream_rejected": {"outcome": r_stale_up["outcome"], "review_verified": r_stale_up["review_verified"]},
        "reviewer_mutation_rejected": {"outcome": r_mutated["outcome"], "review_verified": r_mutated["review_verified"], "candidate_modified_by_reviewer": r_mutated["worktree_integrity"]["candidate_modified_by_reviewer"], "mutation_evidence_retained": Path(r_mutated["worktree_integrity"]["mutation_evidence_path"]).is_file()},
        "reconciliation_lifecycle": {"round_1_outcome": d1["outcome"], "round_2_ineffective_rejected": d2["outcome"], "round_2_blocker": d2["blocking_findings"][0]["resolution_blocker"], "round_3_reconciled_outcome": d3["outcome"], "round_3_review_verified": d3["review_verified"], "delivery_approved": d3["delivery_approved"], "history_rounds": len(d3["findings"][0]["history"])},
    }
    assert summary["valid_review"]["outcome"] == "review-passed" and summary["valid_review"]["review_verified"] is True and summary["valid_review"]["delivery_approved"] is False
    assert summary["self_approval_rejected"] == {"outcome": "invalid-review", "review_verified": False}
    assert summary["false_builder_claim_rejected"] == {"outcome": "changes-requested", "review_verified": False, "contradicted": True}
    assert summary["missing_check_rejected"] == {"outcome": "changes-requested", "review_verified": False}
    assert summary["stale_upstream_rejected"] == {"outcome": "changes-requested", "review_verified": False}
    assert summary["reviewer_mutation_rejected"] == {"outcome": "invalid-review", "review_verified": False, "candidate_modified_by_reviewer": True, "mutation_evidence_retained": True}
    assert summary["reconciliation_lifecycle"] == {"round_1_outcome": "changes-requested", "round_2_ineffective_rejected": "changes-requested", "round_2_blocker": "check-failed", "round_3_reconciled_outcome": "review-passed", "round_3_review_verified": True, "delivery_approved": False, "history_rounds": 3}
    return summary

if __name__ == "__main__":
    unittest.main()
