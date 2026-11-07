"""Unit and evaluation tests for the standalone independent-review role (Issue #52)."""

from __future__ import annotations

import json, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from factory import config as config_module, independent_review, intake_eval, runner, worker as worker_module
from factory.paths import RuntimePaths
from support import git
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from tests.security_review.test_reviewer import CLEAN_AUTH_PY, EXPIRED_TEST_APPEND

PARSED_CHILD = intake_eval._evaluate("900", PARENT_TASK, [READY_CHILD])[1][0]
DEFAULT_ASSESSMENT = {k: {"status": "satisfied", "summary": f"{k} satisfied on candidate."} for k in independent_review.ASSESSMENT_KEYS}


def _make_staged_reviewer_script(
    *, session_id: str = "ind-rev-1", phase2_session_id: str | None = None, hypotheses: list[str] | None = None,
    outcome: str = "review-passed", findings: list[dict] | None = None, assessment: dict | None = None,
    mutate_in_phase: int | None = None, mutate_kind: str = "unstaged",
) -> str:
    hyps = hypotheses if hypotheses is not None else [
        "Token validation might not strip whitespace or reject expired tokens",
        "Tests might only cover happy path without expired token assertion",
    ]
    f_list, assess = findings or [], assessment or DEFAULT_ASSESSMENT
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
        "    for req in ('PHASE: 2 (substantive-assessment', 'Persisted Phase-1 Hypotheses:', 'Builder Summary (untrusted claim):'): assert req in prompt\n"
        f"    if {mutate_in_phase!r} == 2:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut2\\n', encoding='utf-8')\n"
        "    out_sid = p2_override if p2_override is not None else resumed_sid\n"
        f"    resp = json.dumps({{'outcome': {outcome!r}, 'assessment': {assess!r}, 'findings': {f_list!r}}})\n"
        "    print(json.dumps({'event': 'result', 'result': {'conversation_id': out_sid, 'status': 'SUCCESS', 'response': resp}}))\n"
    )


def _valid_qa_record(candidate_sha: str, base_sha: str, tested_sha: str | None = None) -> dict:
    t_sha = tested_sha or candidate_sha
    return {
        "schema": 1, "role": "automated-qa", "status": "qa-verified", "qa_verified": True,
        "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": t_sha,
        "ci_revalidation": {"status": "verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": t_sha, "blockers": []},
        "role_separation": {"role": "automated-qa", "head_before": candidate_sha, "head_after": candidate_sha, "worktree_clean": True, "candidate_modified_by_qa": False},
        "criterion_coverage": [{
            "criterion_id": "AC-1", "description": "Reject expired auth tokens", "passed": True,
            "deterministic_check": {"command": "python3 -m unittest -v", "executed": True, "passed": True, "timed_out": False, "exit_code": 0, "status": "passed"},
            "evaluation_cases": [],
        }],
        "regression_checks": [{"id": "gate-2", "kind": "guard", "executed": True, "passed": True, "timed_out": False, "exit_code": 0}],
        "regression_passed": True, "open_finding_ids": [], "findings": [],
        "parent_acceptance_boundary": {"parent_gid": "900", "parent_accepted": False, "parent_acceptance_status": "pending-human-acceptance"},
    }


def _valid_security_record(candidate_sha: str, base_sha: str, home: Path) -> dict:
    sec_dir = home / "sec-fixture"; sec_dir.mkdir(parents=True, exist_ok=True)
    out_p, chk_p = sec_dir / "rev-stdout.txt", sec_dir / "chk.txt"
    out_p.write_text("ok\n", encoding="utf-8"); chk_p.write_text("ok\n", encoding="utf-8")
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
        conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "900" / "attempt-1" / "children" / "101"
        git(repo, "checkout", "-q", "-b", "task/101-clean", base_sha)
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
        (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "feat: validate expired token")
        cand_sha = git(repo, "rev-parse", "HEAD")
        qa_rec, sec_rec = _valid_qa_record(cand_sha, base_sha), _valid_security_record(cand_sha, base_sha, home)
        good_agy = _make_fake_agy(root, "agy-good", _make_staged_reviewer_script(session_id="fresh-reviewer-99"))

        def run_rev(**overrides):
            kwargs = {
                "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf,
                "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-session-1",
                "builder_summary": "All checks passed and requirements met.", "qa_record": qa_rec, "security_record": sec_rec,
                "agy_bin": str(good_agy), "deadline": time.monotonic() + 30.0, "limit_s": 30,
            }
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

            with unittest.mock.patch.object(independent_review, "build_phase1_prompt", return_value="PHASE: 1\nBuilder summary: leaked\ndiff --git a/x b/x\n@@ -1 +1 @@\n"):
                leaked_rec = run_rev(round_num=6)
            self.assertEqual((leaked_rec["outcome"], leaked_rec["protocol_ordering"]["phase_1_omitted_builder_summary"], leaked_rec["protocol_ordering"]["phase_2_executed"]), ("invalid-review", False, False))

            with unittest.mock.patch.object(independent_review, "build_phase1_prompt", return_value="PHASE: 1\nChanged paths: src/chat_bridge/auth.py\n"):
                path_only_rec = run_rev(round_num=7)
            self.assertEqual((path_only_rec["outcome"], path_only_rec["protocol_ordering"]["phase_1_included_exact_diff"], path_only_rec["protocol_ordering"]["phase_2_executed"]), ("invalid-review", False, False))

    def test_ac2_substantive_assessment_observed_verification_and_upstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, cand_sha, _, _, qa_rec, sec_rec, run_rev = self._setup_workspace(root)
            valid = run_rev(round_num=1)
            self.assertEqual((valid["outcome"], valid["review_verified"]), ("review-passed", True))
            for dim in independent_review.ASSESSMENT_KEYS:
                self.assertEqual(valid["assessment"][dim]["status"], "satisfied")
            obs_checks = valid["observed_verification"]["checks"]
            self.assertTrue(any(c["name"] == "criterion/AC-1" and c["assesses"] == "AC-1" and c["ok"] for c in obs_checks))
            for chk in obs_checks:
                self.assertTrue(Path(chk["output_path"]).is_file() and chk["head_sha"] == cand_sha)

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
            self.assertEqual((stale_res["upstream_evidence"]["automated_qa"]["status"], stale_res["upstream_evidence"]["security_review"]["status"]),
                             ("stale-qa-evidence", "stale-security-review"))
            self.assertTrue({"stale-qa-evidence", "stale-security-evidence"}.issubset({f["rule"] for f in stale_res["blocking_findings"]}))

            missing_up = run_rev(round_num=5, qa_record=None, security_record=None)
            self.assertEqual((missing_up["outcome"], missing_up["review_verified"]), ("changes-requested", False))

            orig_exec = independent_review.worker_module.execute_stream
            with unittest.mock.patch.object(
                independent_review.worker_module, "execute_stream",
                side_effect=lambda cwd, argv, env, timeout_s, **kw: (124, "", "timed out\n", 1000, True) if "unittest" in argv else orig_exec(cwd, argv, env, timeout_s, **kw),
            ):
                to_rec = run_rev(round_num=6)
            self.assertEqual((to_rec["outcome"], to_rec["review_verified"]), ("changes-requested", False))
            self.assertTrue(any(f["rule"] == "check-timed-out" for f in to_rec["blocking_findings"]))

            bad_p2_agy = _make_fake_agy(root, "agy-bad-p2", _make_staged_reviewer_script(assessment={"requirement_compliance": {"status": "satisfied", "summary": "only 1"}}))
            self.assertEqual(run_rev(round_num=7, agy_bin=str(bad_p2_agy))["outcome"], "invalid-review")

    def test_ac3_actionable_findings_categories_incomplete_rejection_and_identity_stability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            five_cat_findings = [
                {"category": "missing-behavior", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "missing-whitespace-strip",
                 "title": "Token whitespace not stripped", "evidence": "src/chat_bridge/auth.py:3", "actionable_correction": "Call token.strip() before prefix check."},
                {"category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted",
                 "title": "Empty token returns valid sub", "evidence": "validate_token('') -> {'sub': ''}", "actionable_correction": "Raise ValueError on empty token."},
                {"category": "verification-gap", "blocking": True, "target": "tests/test_auth.py", "rule": "missing-blank-token-test",
                 "title": "No test for blank token", "evidence": "tests/test_auth.py lacks blank token test", "actionable_correction": "Add test_blank_token in tests/test_auth.py."},
                {"category": "scope-drift", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "extra-helper-export",
                 "title": "Unrequested helper in auth module", "evidence": "diff adds unrequested symbol", "actionable_correction": "Remove unrequested symbol."},
                {"category": "non-blocking-suggestion", "blocking": False, "target": "src/chat_bridge/auth.py", "rule": "docstring-nit",
                 "title": "Add docstring to validate_token", "evidence": "line 2", "actionable_correction": "Optional docstring."},
            ]
            five_agy = _make_fake_agy(root, "agy-five", _make_staged_reviewer_script(session_id="rev-ac3-1", outcome="changes-requested", findings=five_cat_findings))
            r_five = run_rev(round_num=1, agy_bin=str(five_agy))
            self.assertEqual((r_five["outcome"], r_five["review_verified"], len(r_five["blocking_findings"]), len(r_five["non_blocking_suggestions"])), ("changes-requested", False, 4, 1))
            self.assertEqual({f["category"] for f in r_five["findings"]}, independent_review.FINDING_CATEGORIES)

            sugg_only_agy = _make_fake_agy(root, "agy-sugg-only", _make_staged_reviewer_script(session_id="rev-ac3-2", outcome="review-passed", findings=[five_cat_findings[4]]))
            r_sugg = run_rev(round_num=2, agy_bin=str(sugg_only_agy))
            self.assertEqual((r_sugg["outcome"], r_sugg["review_verified"], r_sugg["delivery_approved"], len(r_sugg["blocking_findings"]), len(r_sugg["non_blocking_suggestions"])),
                             ("review-passed", True, False, 0, 1))

            f_pos1 = [
                {"finding_id": "LINE-10-POS-0", "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted",
                 "line": 10, "title": "Empty token bug", "evidence": "line 10: return {'sub': token}", "actionable_correction": "Reject empty token."},
                five_cat_findings[0],
            ]
            f_pos2 = [
                five_cat_findings[0],
                {"finding_id": "LINE-42-POS-1", "category": "bug", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "empty-token-accepted",
                 "line": 42, "title": "Empty token bug shifted", "evidence": "line 42: return {'sub': token}", "actionable_correction": "Reject empty token."},
            ]
            _, _, parsed_pos1, iss1 = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": DEFAULT_ASSESSMENT, "findings": f_pos1}))
            _, _, parsed_pos2, iss2 = independent_review._parse_phase2_response(json.dumps({"outcome": "changes-requested", "assessment": DEFAULT_ASSESSMENT, "findings": f_pos2}))
            self.assertEqual((iss1, iss2), ([], []))
            id1 = [f["finding_id"] for f in parsed_pos1 if f["rule"] == "empty-token-accepted"][0]
            id2 = [f["finding_id"] for f in parsed_pos2 if f["rule"] == "empty-token-accepted"][0]
            self.assertEqual(id1, "REV-BUG-src-chat-bridge-auth-py-empty-token-accepted")
            self.assertEqual(id1, id2)

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
                self.assertEqual((rec["outcome"], rec["review_verified"], rec["role_separation_verified"], rec["delivery_approved"]),
                                 ("invalid-review", False, False, False), f"failed on phase={phase} kind={kind}: {rec['role_issues']}")
                self.assertTrue(rec["worktree_integrity"]["candidate_modified_by_reviewer"])
                mut_ev_path = Path(rec["worktree_integrity"]["mutation_evidence_path"])
                self.assertTrue(mut_ev_path.is_file() and f"phase=phase{phase}" in mut_ev_path.read_text(encoding="utf-8"))
                self.assertFalse(rec["observed_verification"]["executed"])

            demo_dir = root / "demo"; demo_dir.mkdir(parents=True, exist_ok=True)
            summary = run_disposable_demo(demo_dir)
            self.assertEqual((summary["valid_review"]["outcome"], summary["valid_review"]["review_verified"], summary["valid_review"]["delivery_approved"]),
                             ("review-passed", True, False))

    def test_m1_automated_qa_evidence_contract_and_integration_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, cand_sha, _, _, qa_rec, sec_rec, run_rev = self._setup_workspace(root)
            git(repo, "checkout", "-q", "-b", "pr-merge-test", base_sha)
            (repo / "README.md").write_text("base update\n", encoding="utf-8")
            git(repo, "add", "README.md"); git(repo, "commit", "-q", "-m", "base advance")
            git(repo, "checkout", "-q", base_sha)
            git(repo, "checkout", "-q", "-b", "merge-sim", base_sha)
            git(repo, "merge", "--no-ff", "-q", "-m", "Merge candidate into base", cand_sha)
            merge_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "task/101-clean")

            merge_qa = {** _valid_qa_record(cand_sha, base_sha, tested_sha=merge_sha), "revision_kind": "integration-merge"}
            merge_rec = run_rev(round_num=10, qa_record=merge_qa)
            self.assertEqual((merge_rec["outcome"], merge_rec["review_verified"], merge_rec["upstream_evidence"]["automated_qa"]["verified"]),
                             ("review-passed", True, True))

            for label, bad_qa in (
                ("missing-role-sep", {k: v for k, v in qa_rec.items() if k != "role_separation"}),
                ("missing-ci-reval", {k: v for k, v in qa_rec.items() if k != "ci_revalidation"}),
                ("missing-reg-passed", {k: v for k, v in qa_rec.items() if k != "regression_passed"}),
                ("missing-coverage", {**qa_rec, "criterion_coverage": []}),
                ("unmet-criterion", {**qa_rec, "criterion_coverage": [{**qa_rec["criterion_coverage"][0], "criterion_id": "OTHER-AC"}]}),
                ("str-false-qa-verified", {**qa_rec, "qa_verified": "false"}),
                ("str-false-reg-passed", {**qa_rec, "regression_passed": "false"}),
                ("str-false-ci-reval", {**qa_rec, "ci_revalidation": {**qa_rec["ci_revalidation"], "verified": "false"}}),
                ("unverified-merge-sha", {**qa_rec, "tested_sha": "a" * 40, "revision_kind": "integration-merge"}),
                ("malformed-ci-reval", {**qa_rec, "ci_revalidation": "not-a-dict"}),
                ("malformed-role-sep", {**qa_rec, "role_separation": ["not-a-dict"]}),
                ("malformed-coverage", {**qa_rec, "criterion_coverage": ["not-a-dict"]}),
                ("malformed-findings", {**qa_rec, "findings": ["not-a-dict"]}),
                ("malformed-open-ids", {**qa_rec, "open_finding_ids": "not-a-list"}),
            ):
                qa_ev, _, gaps = independent_review.evaluate_upstream_evidence(
                    cand_sha, base_sha, bad_qa, sec_rec, home=home, repo=repo, child=PARSED_CHILD
                )
                self.assertFalse(qa_ev["verified"], f"expected M1 rejection for {label}, got {qa_ev}")
                self.assertTrue(gaps, f"expected M1 gap finding for {label}")

    def test_m2_structural_summary_omission_and_execution_input_redaction(self) -> None:
        sentinel = "ghp_M2_SECRET_TOKEN_99"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, base_sha, _, _, _, _, _, run_rev = self._setup_workspace(root)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# builder summary note\n", encoding="utf-8")
            git(repo, "add", "src/chat_bridge/auth.py"); git(repo, "commit", "-q", "-m", "diff with builder summary phrase")
            cand2 = git(repo, "rev-parse", "HEAD")
            qa2, sec2 = _valid_qa_record(cand2, base_sha), _valid_security_record(cand2, base_sha, home)
            cap_script = (
                "import pathlib, sys\np = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
                "pathlib.Path.home().joinpath('cap1.txt' if 'PHASE: 1' in p else 'cap2.txt').write_text(p, encoding='utf-8')\n"
            ) + _make_staged_reviewer_script(session_id="rev-m2")
            cap_agy = _make_fake_agy(root, "agy-cap-m2", cap_script)
            crit_desc = PARSED_CHILD["criteria"][0]["description"]
            with unittest.mock.patch.dict("os.environ", {"TURBO_GITHUB_TOKEN": sentinel}):
                r_overlap = run_rev(round_num=1, candidate_sha=cand2, qa_record=qa2, security_record=sec2,
                                    agy_bin=str(cap_agy), builder_summary=crit_desc)
                self.assertEqual((r_overlap["outcome"], r_overlap["review_verified"]), ("review-passed", True))
                r_sec = run_rev(round_num=2, candidate_sha=cand2, qa_record=qa2, security_record=sec2, agy_bin=str(cap_agy),
                                child={**PARSED_CHILD, "name": f"Auth {sentinel}"},
                                builder_summary=f"{crit_desc} SUMMARY_ONLY_M2 {sentinel}")
            self.assertEqual((r_sec["outcome"], r_sec["review_verified"]), ("review-passed", True))
            iso_home = Path(r_sec["safety"]["isolated_home"])
            p1_in, p2_in = (iso_home / "cap1.txt").read_text(encoding="utf-8"), (iso_home / "cap2.txt").read_text(encoding="utf-8")
            self.assertIn("# builder summary note", p1_in)
            self.assertIn(crit_desc, p1_in)
            self.assertNotIn("SUMMARY_ONLY_M2", p1_in)
            self.assertIn("SUMMARY_ONLY_M2", p2_in)
            self.assertNotIn(sentinel, p1_in)
            self.assertNotIn(sentinel, p2_in)

    def test_m3_two_phase_reviewer_session_continuation_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, _, _, _, _, _, _, _, run_rev = self._setup_workspace(root)
            valid = run_rev(round_num=1)
            self.assertEqual((valid["outcome"], valid["review_verified"], valid["protocol_ordering"].get("phase_2_continued_session_id")),
                             ("review-passed", True, "fresh-reviewer-99"))
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
            viol_finding = [{"category": "missing-behavior", "blocking": True, "target": "src/chat_bridge/auth.py", "rule": "std-token-norm-01",
                             "title": "Base standard STD-TOKEN-NORM-01 violated", "evidence": "src/chat_bridge/auth.py lacks strip()", "actionable_correction": "Strip whitespace per STD-TOKEN-NORM-01."}]
            std_agy = _make_fake_agy(
                root, "agy-m4",
                "import sys\np = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
                "std_sec = p.split('Exact Base-to-Candidate Diff:', 1)[0]\n"
                "assert 'STD-TOKEN-NORM-01: Always strip token whitespace' in std_sec and 'STD-WEAKENED-99' not in std_sec\n"
                + _make_staged_reviewer_script(session_id="rev-m4", outcome="changes-requested", assessment=viol_assess, findings=viol_finding),
            )
            child_m4 = {**PARSED_CHILD, "scope": {**PARSED_CHILD["scope"], "in_scope": "src/chat_bridge/auth.py, tests/test_auth.py, CONTRIBUTING.md"}}
            rec = run_rev(round_num=1, base_sha=base_m4, candidate_sha=cand_m4, child=child_m4, qa_record=qa_m4, security_record=sec_m4, agy_bin=str(std_agy))
            p1_txt = Path(rec["protocol_ordering"]["phase_1_prompt_path"]).read_text(encoding="utf-8")
            self.assertIn("STD-TOKEN-NORM-01: Always strip token whitespace before validation.", p1_txt.split("Exact Base-to-Candidate Diff:", 1)[0])
            self.assertNotIn("STD-WEAKENED-99", p1_txt.split("Exact Base-to-Candidate Diff:", 1)[0])
            self.assertEqual((rec["outcome"], rec["review_verified"], rec["assessment"]["project_standards"]["status"]), ("changes-requested", False, "unsatisfied"))

    def test_m5_reviewer_write_and_host_execution_bypasses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, base_sha, _, _, _, _, run_rev = self._setup_workspace(root)
            edit_restore = _make_fake_agy(
                root, "agy-edit-restore",
                "import os, pathlib\nf = pathlib.Path('src/chat_bridge/auth.py')\norig, st = f.read_bytes(), f.stat()\n"
                "f.write_bytes(orig + b'\\n# transient\\n'); f.write_bytes(orig); os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))\n"
                + _make_staged_reviewer_script(session_id="rev-m5-er"),
            )
            r1 = run_rev(round_num=1, agy_bin=str(edit_restore))
            self.assertEqual((r1["outcome"], r1["review_verified"], r1["worktree_integrity"]["candidate_modified_by_reviewer"]), ("invalid-review", False, True))
            ignored_agy = _make_fake_agy(
                root, "agy-ignored",
                "import pathlib\npathlib.Path('.git/info/exclude').write_text('*.ignored\\n', encoding='utf-8')\n"
                "pathlib.Path('secret.ignored').write_text('x', encoding='utf-8')\n"
                + _make_staged_reviewer_script(session_id="rev-m5-ig"),
            )
            r2 = run_rev(round_num=2, agy_bin=str(ignored_agy))
            self.assertEqual((r2["outcome"], r2["review_verified"], r2["worktree_integrity"]["candidate_modified_by_reviewer"]), ("invalid-review", False, True))
            git_marker = root / "host-git-executed.sentinel"
            git_cfg_agy = _make_fake_agy(
                root, "agy-gitcfg",
                f"import pathlib\npathlib.Path('.git/config').write_text('[core]\\n\\tfsmonitor = touch {git_marker}\\n', encoding='utf-8')\n"
                + _make_staged_reviewer_script(session_id="rev-m5-cfg"),
            )
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
            r4 = run_rev(round_num=4, candidate_sha=cand_site, child=child_site, qa_record=_valid_qa_record(cand_site, base_sha),
                         security_record=_valid_security_record(cand_site, base_sha, home))
            self.assertFalse(site_marker.exists())
            self.assertTrue(r4["observed_verification"]["executed"])
            r5 = run_rev(round_num=5)
            self.assertEqual((r5["outcome"], r5["review_verified"], r5["worktree_integrity"]["candidate_modified_by_reviewer"]), ("review-passed", True, False))


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
        args = {
            "repo": repo, "home": home, "child_dir": child_dir, "child": PARSED_CHILD, "conf": conf,
            "base_sha": base_sha, "candidate_sha": cand_sha, "builder_session_id": "builder-demo-1",
            "builder_summary": "All checks passed.", "qa_record": qa_rec, "security_record": sec_rec,
            "round_num": round_num, "agy_bin": str(good_agy), "deadline": time.monotonic() + 30.0, "limit_s": 30,
        }
        args.update(kw)
        return independent_review.review_candidate_independently(**args)

    r_valid, r_self = _call(1), _call(2, agy_bin=str(reused_agy))
    r_false_claim = _call(3, child={**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": "python3 -c \"import sys; sys.exit(1)\""}]},
                          builder_summary="All checks passed with zero errors!")
    r_missing_chk = _call(4, child={**PARSED_CHILD, "criteria": [{**PARSED_CHILD["criteria"][0], "verification": ""}]})
    r_stale_up, r_mutated = _call(5, qa_record={**qa_rec, "candidate_sha": "0" * 40}), _call(6, agy_bin=str(mut_agy))

    summary = {
        "valid_review": {
            "outcome": r_valid["outcome"], "review_verified": r_valid["review_verified"],
            "delivery_approved": r_valid["delivery_approved"], "verification_scope": r_valid["verification_scope"],
            "ordering_enforced": r_valid["protocol_ordering"]["enforced"], "hypotheses_count": len(r_valid["failure_hypotheses"]),
            "record_path": str(child_dir / "independent-review-round-1" / "record.json"),
        },
        "self_approval_rejected": {"outcome": r_self["outcome"], "review_verified": r_self["review_verified"]},
        "false_builder_claim_rejected": {
            "outcome": r_false_claim["outcome"], "review_verified": r_false_claim["review_verified"],
            "contradicted": r_false_claim["builder_summary_claim"]["contradicted_by_observed_execution"],
        },
        "missing_check_rejected": {"outcome": r_missing_chk["outcome"], "review_verified": r_missing_chk["review_verified"]},
        "stale_upstream_rejected": {"outcome": r_stale_up["outcome"], "review_verified": r_stale_up["review_verified"]},
        "reviewer_mutation_rejected": {
            "outcome": r_mutated["outcome"], "review_verified": r_mutated["review_verified"],
            "candidate_modified_by_reviewer": r_mutated["worktree_integrity"]["candidate_modified_by_reviewer"],
            "mutation_evidence_retained": Path(r_mutated["worktree_integrity"]["mutation_evidence_path"]).is_file(),
        },
    }
    assert summary["valid_review"]["outcome"] == "review-passed" and summary["valid_review"]["review_verified"] is True
    assert summary["valid_review"]["delivery_approved"] is False
    assert summary["self_approval_rejected"] == {"outcome": "invalid-review", "review_verified": False}
    assert summary["false_builder_claim_rejected"] == {"outcome": "changes-requested", "review_verified": False, "contradicted": True}
    assert summary["missing_check_rejected"] == {"outcome": "changes-requested", "review_verified": False}
    assert summary["stale_upstream_rejected"] == {"outcome": "changes-requested", "review_verified": False}
    assert summary["reviewer_mutation_rejected"] == {
        "outcome": "invalid-review", "review_verified": False,
        "candidate_modified_by_reviewer": True, "mutation_evidence_retained": True,
    }
    return summary


if __name__ == "__main__":
    unittest.main()
