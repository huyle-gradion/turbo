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
    f_list, assess, p2_sid = findings or [], assessment or DEFAULT_ASSESSMENT, (phase2_session_id if phase2_session_id is not None else session_id)
    return (
        "import json, pathlib, subprocess, sys\n"
        "prompt = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
        f"p1_sid, p2_sid = {session_id!r}, {p2_sid!r}\n"
        "if 'PHASE: 1 (pre-summary' in prompt:\n"
        "    for forbidden in ('Builder summary:', 'Builder Summary'): assert forbidden not in prompt\n"
        "    for req in ('@@ ', 'diff --git', 'Requirements & Acceptance Criteria:', 'Applicable Project Standards:'): assert req in prompt\n"
        f"    if {mutate_in_phase!r} == 1:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        f"        elif {mutate_kind!r} == 'staged': pathlib.Path('src/chat_bridge/auth.py').write_text('# stg\\n', encoding='utf-8'); subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
        f"        elif {mutate_kind!r} == 'commit': pathlib.Path('src/chat_bridge/auth.py').write_text('# cmt\\n', encoding='utf-8'); subprocess.run(['git', 'commit', '-am', 'rev edit'], check=True)\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut\\n', encoding='utf-8')\n"
        f"    print(json.dumps({{'event': 'result', 'result': {{'conversation_id': p1_sid, 'status': 'SUCCESS', 'response': json.dumps({{'hypotheses': {hyps!r}}})}}}}))\n"
        "else:\n"
        "    for req in ('PHASE: 2 (substantive-assessment', 'Persisted Phase-1 Hypotheses:', 'Builder Summary (untrusted claim):'): assert req in prompt\n"
        f"    if {mutate_in_phase!r} == 2:\n"
        f"        if {mutate_kind!r} == 'untracked': pathlib.Path('reviewer_note.txt').write_text('x', encoding='utf-8')\n"
        "        else: pathlib.Path('src/chat_bridge/auth.py').write_text('# mut2\\n', encoding='utf-8')\n"
        f"    resp = json.dumps({{'outcome': {outcome!r}, 'assessment': {assess!r}, 'findings': {f_list!r}}})\n"
        "    print(json.dumps({'event': 'result', 'result': {'conversation_id': p2_sid, 'status': 'SUCCESS', 'response': resp}}))\n"
    )


def _valid_qa_record(candidate_sha: str, base_sha: str) -> dict:
    return {"schema": 1, "role": "automated-qa", "status": "qa-verified", "qa_verified": True,
            "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": candidate_sha, "open_finding_ids": [], "findings": []}


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
