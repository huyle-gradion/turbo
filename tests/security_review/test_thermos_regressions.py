"""Thermos regression tests for Issue #22 (Items 1-10)."""

from __future__ import annotations

import json, os, sys, tempfile, time, unittest, unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from factory import config as config_module, deliver_checks, security_review, worker as worker_module
from factory.errors import UsageError
from factory.paths import RuntimePaths
from support import git
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from test_intake import _DisposableAsanaServer
from tests.security_review.test_security_review import (
    CLEAN_AUTH_PY, EXPIRED_TEST_APPEND, REVIEWER_SCRIPT, _make_builder_script, _SyncingGitHubServer,
)


class ThermosRegressionsTest(unittest.TestCase):
    def _setup_clean_candidate(self, root: Path) -> tuple[Path, Path, Path, str, str, config_module.Config, Path]:
        repo, home, bare = _make_disposable_product_workspace(root)
        base_sha = git(repo, "rev-parse", "refs/heads/main")
        git(repo, "checkout", "-q", "-b", "feature/chat-auth", base_sha); git(repo, "push", "-q", "origin", "feature/chat-auth")
        conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "900" / "attempt-1" / "children" / "101"
        git(repo, "checkout", "-q", "-b", "task/101-auth", base_sha)
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
        (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "clean")
        cand_sha = git(repo, "rev-parse", "HEAD"); git(repo, "push", "-q", "origin", "task/101-auth")
        return repo, home, bare, base_sha, cand_sha, conf, child_dir

    def test_01_fail_closed_record_on_post_deliver_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            builder_agy, rev_agy = _make_fake_agy(root, "agy-builder", _make_builder_script("fix-with-usage")), _make_fake_agy(root, "agy-rev", REVIEWER_SCRIPT)
            in_flight, orig_rev = [], security_review.review_candidate_security
            def _spy_rev(**kw):
                in_flight.append((json.loads((home / "deliveries/900/record.json").read_text(encoding="utf-8")),
                                  json.loads((kw["child_dir"].parents[1] / "record.json").read_text(encoding="utf-8"))))
                return orig_rev(**kw)
            with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana, _SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a", "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
                run_sec = lambda: security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home), security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy), reviewer_agy_bin=str(rev_agy)))
                with (unittest.mock.patch.object(security_review, "review_candidate_security", side_effect=_spy_rev),
                      unittest.mock.patch.object(security_review, "evaluate_child_pr_with_security_gate", side_effect=deliver_checks.GitHubError("simulated PR update failure"))):
                    res = run_sec()
                parent_rec = json.loads((home / "deliveries/900/record.json").read_text(encoding="utf-8"))
                attempt_rec = json.loads((home / "deliveries/900/attempt-1/record.json").read_text(encoding="utf-8"))
                self.assertFalse(parent_rec["verified"], "persisted parent record must never remain verified=True on post-deliver failure")
                self.assertFalse(attempt_rec["verified"], "persisted attempt record must never remain verified=True on post-deliver failure")
                self.assertEqual((in_flight[0][0]["status"], in_flight[0][0]["verified"]), ("security-review-pending", False))
                self.assertEqual((in_flight[0][1]["status"], in_flight[0][1]["verified"]), ("security-review-pending", False))
                self.assertEqual((res.status, res.verified), ("pr-failed", False))
                with unittest.mock.patch.object(security_review, "review_candidate_security", side_effect=deliver_checks.AttemptTimeoutError("review timed out")):
                    res_to = run_sec()
                self.assertEqual((res_to.status, res_to.verified), ("timed-out", False))
                self.assertFalse(json.loads((home / "deliveries/900/record.json").read_text(encoding="utf-8"))["verified"])
                self.assertEqual(res_to.child["ci_verification"]["status"], "verified", "must preserve initial ci_verification when round 1 fails")
                gh_ev_txt = Path(res_to.evidence["github_evidence_path"]).read_text(encoding="utf-8")
                self.assertEqual(res_to.evidence["github_evidence_sha256"], security_review.runner.digest_text(gh_ev_txt))
                with unittest.mock.patch.object(security_review.delivery, "resolve_github_token", side_effect=UsageError("missing token after deliver")):
                    res_cfg = run_sec()
                self.assertFalse(res_cfg.verified)
                self.assertFalse(json.loads((home / "deliveries/900/record.json").read_text(encoding="utf-8"))["verified"])

    def test_02_independent_verification_tempfile_in_landlock_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, home, _, base_sha, cand_sha, conf, child_dir = self._setup_clean_candidate(Path(tmp))
            rev_agy = _make_fake_agy(Path(tmp), "agy-rev", REVIEWER_SCRIPT)
            vcmd = ("python3 -c \"import os, pathlib, tempfile; tdir = pathlib.Path(tempfile.gettempdir()).resolve(); "
                    "assert tdir.is_relative_to(pathlib.Path.home().resolve()), f'{tdir} not in HOME'; "
                    "f = tempfile.NamedTemporaryFile(dir=os.environ['TMPDIR'], delete=True); f.write(b'ok'); f.close()\"")
            child_tmp = {**READY_CHILD, "criteria": [{"id": "AC-1", "description": "Tempfile in sandbox TMPDIR", "verification": vcmd}]}
            rec = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=child_tmp, conf=conf,
                base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertTrue(rec["independent_verification"]["ok"], rec["independent_verification"])
            self.assertEqual(rec["outcome"], "approved")

    def test_03_failed_safety_probes_prevent_reviewer_and_verification_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, base_sha, cand_sha, conf, child_dir = self._setup_clean_candidate(root)
            marker = root / "reviewer-ran.marker"
            rev_agy = _make_fake_agy(
                root, "agy-rev-marker",
                f"import json, pathlib\npathlib.Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n"
                "print(json.dumps({'event':'result','result':{'conversation_id':'r1','status':'SUCCESS','response':'{\"outcome\":\"approved\",\"findings\":[]}'}}))\n")
            bad_probes = [{"name": "forbidden_credential_access", "attempted": True, "denied": False, "exit": 0}]
            with unittest.mock.patch.object(worker_module, "run_safety_probes", return_value=bad_probes):
                rec = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertFalse(marker.exists(), "reviewer should not execute when safety probes fail")
            self.assertEqual((rec["reviewer_executed"], rec["independent_verification"]["executed"], rec["outcome"]), (False, False, "invalid-review"))

            with unittest.mock.patch.object(worker_module, "run_safety_probes", side_effect=worker_module.SandboxUnavailableError("bwrap missing")):
                rec_sbx = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=2, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertFalse(marker.exists()); self.assertEqual((rec_sbx["outcome"], rec_sbx["ready"]), ("invalid-review", False))

    def test_04_repair_invariants_reject_noop_hollow_revert_and_permission_denial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            rev_agy = _make_fake_agy(root, "agy-rev", REVIEWER_SCRIPT)
            noop_agy = _make_fake_agy(root, "agy-noop", _make_builder_script("noop"))
            hollow_agy = _make_fake_agy(root, "agy-hollow", _make_builder_script("hollow-revert"))
            denied_agy = _make_fake_agy(root, "agy-denied", _make_builder_script("permission-denied"))
            mal_agy = _make_fake_agy(root, "agy-mal", _make_builder_script("malformed-output"))
            fix_agy = _make_fake_agy(root, "agy-fix", _make_builder_script("fix"))
            with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                  _SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a",
                                                        "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
                run_d = lambda agy: security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home),
                    security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(agy), reviewer_agy_bin=str(rev_agy)))
                r_noop, r_hollow, r_denied, r_mal = run_d(noop_agy), run_d(hollow_agy), run_d(denied_agy), run_d(mal_agy)
                orig_exec = worker_module.execute_stream
                def _timeout_on_repair(wt, argv, env, t_out, **kw):
                    if any("SECURITY REPAIR" in str(a) for a in argv):
                        return 124, "", "timed out", 1000, True
                    return orig_exec(wt, argv, env, t_out, **kw)
                orig_git_timed = security_review.delivery.git_timed
                def _git_timed_fail_after_timeout(wt, dl, lim, desc, *args):
                    if desc == "repair diff":
                        raise deliver_checks.AttemptTimeoutError("deadline expired before post-repair git_timed")
                    return orig_git_timed(wt, dl, lim, desc, *args)
                with (unittest.mock.patch.object(worker_module, "execute_stream", side_effect=_timeout_on_repair),
                      unittest.mock.patch.object(security_review.delivery, "git_timed", side_effect=_git_timed_fail_after_timeout)):
                    r_to = run_d(fix_agy)
            self.assertEqual((r_noop.status, r_noop.verified), ("missing-implementation", False))
            self.assertEqual((r_hollow.status, r_hollow.verified), ("missing-implementation", False))
            self.assertEqual((r_denied.status, r_denied.verified), ("permission-denied", False))
            self.assertEqual((r_mal.status, r_mal.verified), ("malformed-output", False))
            self.assertEqual((r_to.status, len(r_to.child["security_repair"]["repair_attempts"])), ("timed-out", 1))

    def test_05_ci_polling_round1_reuse_section_replacement_and_post_patch_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare, base_sha, cand_sha, conf, child_dir = self._setup_clean_candidate(root)
            rev_agy = _make_fake_agy(root, "agy-rev", REVIEWER_SCRIPT)
            clean_rev = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            scope_detail = {"status": "deterministic-verified", "provenance": "deterministic rules enforced"}
            with _SyncingGitHubServer(bare_repo=bare) as gh:
                pr_info = deliver_checks.open_and_confirm_pr(
                    gh.base_url, "tok-g", "example/chat-bridge", PARENT_TASK, READY_CHILD,
                    "task/101-auth", cand_sha, "feature/chat-auth", [], scope_detail, [], time.monotonic() + 30.0, 30)
                ev_gate = lambda pr_in, **kw: security_review.evaluate_child_pr_with_security_gate(
                    repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url, token="tok-g", repo_slug="example/chat-bridge",
                    parent=PARENT_TASK, child=READY_CHILD, conf=conf, pr_info=pr_in, head_branch="task/101-auth",
                    candidate_sha=cand_sha, base_branch="feature/chat-auth", base_sha=base_sha, scope_detail=scope_detail,
                    security_review_record=clean_rev, trace=[], deadline=time.monotonic() + 30.0, limit_s=30, **kw)
                g1 = ev_gate(pr_info)
                self.assertEqual(g1["verification_scope"], security_review.VERIFICATION_SCOPE_SECURITY_NOTE)
                orig_drift, calls = security_review.delivery.ci_gate._check_pr_revision_drift, []
                def _drift_on_second(*args, **kwargs):
                    calls.append(1)
                    return (({"head_sha": "deadbeef", "base_sha": base_sha, "state": "open", "body": gh.pulls[pr_info["number"]]["body"]}, ["PR head drifted"])
                            if len(calls) >= 2 else orig_drift(*args, **kwargs))
                with unittest.mock.patch.object(security_review.delivery.ci_gate, "_check_pr_revision_drift", side_effect=_drift_on_second):
                    g_drift = ev_gate(g1["pr"])
                self.assertEqual((g_drift["status"], g_drift["verified"]), ("stale-security-review", False))
                self.assertFalse(g_drift["pr"].get("ci_verified", False))
                self.assertFalse(g_drift["pr"].get("pr_confirmed", False))
                self.assertIn("verified=`False`", gh.pulls[pr_info["number"]]["body"])
                self.assertIn("sec-reviewer-1", gh.pulls[pr_info["number"]]["body"])
                self.assertEqual(gh.pulls[pr_info["number"]]["body"].count("## Security Review Evidence"), 1)
                with unittest.mock.patch.object(security_review.delivery.ci_gate, "evaluate_child_pr_ci_gate", wraps=security_review.delivery.ci_gate.evaluate_child_pr_ci_gate) as spy_ci:
                    ev_gate(pr_info, ci_result=g1)
                    self.assertEqual(spy_ci.call_count, 0, "round 1 matching ci_result must be reused without re-polling")
                    ev_gate(pr_info, ci_result={**g1, "candidate_sha": "other-sha"})
                    self.assertEqual(spy_ci.call_count, 1, "mismatched ci_result candidate_sha must re-poll")
                    ev_gate(pr_info, ci_result={**g1, "base_sha": ""})
                    self.assertEqual(spy_ci.call_count, 2, "missing ci_result base_sha must re-poll")
                    g_pend = ev_gate(pr_info, ci_result={**g1, "status": "ci-pending", "verified": False, "blockers": ["CI pending"]})
                    self.assertEqual((g_pend["status"], g_pend["verified"]), ("ci-pending", False))

    def test_06_redact_every_persisted_evidence_surface(self) -> None:
        sentinel = "ghp_SUPER_SECRET_SENTINEL_VALUE_42"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare, base_sha, _, conf, child_dir = self._setup_clean_candidate(root)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + f"# token={sentinel}\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "add comment")
            cand_sha = git(repo, "rev-parse", "HEAD"); git(repo, "push", "-q", "origin", "task/101-auth", "-f")
            rev_agy = _make_fake_agy(
                root, "agy-rev-leak",
                f"import json\nprint(json.dumps({{'event':'result','result':{{'conversation_id':'rev-1','status':'SUCCESS',"
                f"'response':json.dumps({{'outcome':'approved','findings':[{{'policy_id':'SEC-POL-04','rule':'note','blocking':False,'severity':'low','title':'Note {sentinel}','file_path':'src/chat_bridge/auth.py','evidence':'{sentinel}'}}]}})}}}}))\n")
            with (_SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_GITHUB_TOKEN": sentinel})):
                rec = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
                pr_info = deliver_checks.open_and_confirm_pr(
                    gh.base_url, sentinel, "example/chat-bridge", PARENT_TASK, READY_CHILD,
                    "task/101-auth", cand_sha, "feature/chat-auth", [], {"status": "deterministic-verified", "provenance": "ok"}, [], time.monotonic() + 30.0, 30)
                security_review.evaluate_child_pr_with_security_gate(
                    repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url, token=sentinel, repo_slug="example/chat-bridge",
                    parent=PARENT_TASK, child=READY_CHILD, conf=conf, pr_info=pr_info, head_branch="task/101-auth",
                    candidate_sha=cand_sha, base_branch="feature/chat-auth", base_sha=base_sha,
                    scope_detail={"status": "deterministic-verified", "provenance": "ok"}, security_review_record=rec,
                    trace=[], deadline=time.monotonic() + 30.0, limit_s=30)
                self.assertNotIn(sentinel, gh.pulls[pr_info["number"]]["body"])
            for path in (child_dir / "security-review.json", Path(rec["inspected_scope"]["diff_path"]), Path(rec["reviewer_stdout_path"])):
                self.assertNotIn(sentinel, path.read_text(encoding="utf-8"), f"unredacted sentinel in {path}")

    def test_07_reject_invalid_fenced_contradictory_and_null_blocking_reviewer_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, base_sha, cand_sha, conf, child_dir = self._setup_clean_candidate(root)
            for idx, bad_resp in enumerate((
                "{malformed", "```json\n{\"outcome\": \"approved\", \"findings\": []}\n```",
                json.dumps({"outcome": "approved"}),
                json.dumps({"outcome": "approved", "findings": [{"policy_id": "SEC-POL-01", "rule": "hardcoded-secret", "severity": "critical", "blocking": True, "file_path": "src/chat_bridge/auth.py"}]}),
                json.dumps({"outcome": "changes-requested", "findings": []}),
            )):
                agy = _make_fake_agy(root, f"agy-bad-{idx}", f"import json\nprint(json.dumps({{'event':'result','result':{{'conversation_id':'rev-{idx}','status':'SUCCESS','response':{bad_resp!r}}}}}))\n")
                rec = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(agy), deadline=time.monotonic() + 30.0, limit_s=30)
                self.assertEqual((rec["outcome"], rec["ready"]), ("invalid-review", False), f"case {idx} should fail closed")

            null_block_resp = json.dumps({"outcome": "changes-requested", "findings": [
                {"policy_id": "SEC-POL-01", "rule": "custom-crit", "severity": "critical", "blocking": None,
                 "title": "Critical null blocking", "file_path": "src/chat_bridge/auth.py", "line": 2, "evidence": "return {'sub': token}"}]})
            agy_null = _make_fake_agy(root, "agy-null-block", f"import json\nprint(json.dumps({{'event':'result','result':{{'conversation_id':'rev-null','status':'SUCCESS','response':{null_block_resp!r}}}}}))\n")
            rec_null = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(agy_null), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertEqual((rec_null["outcome"], len(rec_null["blocking_findings"]), rec_null["blocking_findings"][0]["blocking"]), ("changes-requested", 1, True))

    def test_08_comprehensive_candidate_scanning_and_verify_file_containment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, base_sha, _, conf, child_dir = self._setup_clean_candidate(root)
            (repo / "src/chat_bridge/auth.py").write_text("BACKDOOR_SECRET = 'sec-one'\nAPI_SECRET = 'sec-two'\n" + CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + "\nPRIVATE_KEY = 'test-secret-key'\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "secrets in impl and test")
            cand_sha = git(repo, "rev-parse", "HEAD")
            rev_agy = _make_fake_agy(
                root, "agy-rev-findings",
                "import json\nprint(json.dumps({'event':'result','result':{'conversation_id':'rev-8','status':'SUCCESS',"
                "'response':json.dumps({'outcome':'changes-requested','findings':[{'policy_id':'SEC-POL-01','rule':'hardcoded-secret','severity':'critical','blocking':True,'file_path':'src/chat_bridge/auth.py'}]})}}))\n")
            rec = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            by_file = {f["file_path"]: f for f in rec["blocking_findings"]}
            self.assertIn("tests/test_auth.py", by_file, "must scan changed test files for secrets")
            self.assertIn("sec-one", by_file["src/chat_bridge/auth.py"]["evidence"])
            self.assertIn("sec-two", by_file["src/chat_bridge/auth.py"]["evidence"], "must aggregate multiple matching lines")
            outside = root / "outside.py"; outside.write_text("x = 1\n", encoding="utf-8"); (repo / "link_outside.py").symlink_to(outside)
            self.assertEqual(security_review.main(["--repo", str(repo), "--verify-file", "../outside.py"]), 1)
            self.assertEqual(security_review.main(["--repo", str(repo), "--verify-file", "link_outside.py"]), 1)

    def test_09_pure_finding_reconciliation_multi_round_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _, base_sha, clean_sha, conf, child_dir = self._setup_clean_candidate(root)
            r1_agy = _make_fake_agy(
                root, "agy-r1",
                "import json\np={'outcome':'changes-requested','findings':[{'policy_id':'SEC-POL-04','rule':'unnormalized-sub',"
                "'severity':'high','blocking':True,'title':'Unnormalized sub','file_path':'src/chat_bridge/auth.py','line':3,"
                "'evidence':\"return {'sub': token}\",'actionable_correction':'Use str(token)'}]}\n"
                "print(json.dumps({'event':'result','result':{'conversation_id':'rev-1','status':'SUCCESS','response':json.dumps(p)}}))\n")
            r2_downgrade_agy = _make_fake_agy(
                root, "agy-r2-down",
                "import json\np={'outcome':'approved','findings':[{'policy_id':'SEC-POL-04','rule':'unnormalized-sub',"
                "'severity':'low','blocking':False,'title':'Unnormalized sub','file_path':'src/chat_bridge/auth.py','line':3,"
                "'evidence':\"return {'sub': token}\"}]}\n"
                "print(json.dumps({'event':'result','result':{'conversation_id':'rev-2','status':'SUCCESS','response':json.dumps(p)}}))\n")
            rev_c = lambda sha, rnum, agy, prior=None: security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                base_sha=base_sha, candidate_sha=sha, round_num=rnum, agy_bin=str(agy), prior_findings=prior, deadline=time.monotonic() + 30.0, limit_s=30)
            r1 = rev_c(clean_sha, 1, r1_agy)
            r2_down = rev_c(clean_sha, 2, r2_downgrade_agy, r1["findings"])
            self.assertFalse(r2_down["ready"]); self.assertNotEqual(r2_down["outcome"], "approved")
            self.assertFalse(security_review.evaluate_security_review_gate(clean_sha, base_sha, r2_down, home=home)["verified"])

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY.replace("{'sub': token}", "{'sub': str(token)}"), encoding="utf-8")
            git(repo, "add", "src/chat_bridge/auth.py"); git(repo, "commit", "-q", "-m", "fix r2"); sha_r2 = git(repo, "rev-parse", "HEAD")
            silent_agy = _make_fake_agy(root, "agy-silent", "import json\nprint(json.dumps({'event':'result','result':{'conversation_id':'rev-s','status':'SUCCESS','response':json.dumps({'outcome':'approved','findings':[]})}}))\n")
            r2_fixed = rev_c(sha_r2, 2, silent_agy, r1["findings"])
            self.assertEqual(r2_fixed["findings"][0]["resolved_in_revision"], sha_r2)

            (repo / "src/chat_bridge/auth.py").write_text((repo / "src/chat_bridge/auth.py").read_text(encoding="utf-8") + "# r3\n", encoding="utf-8")
            git(repo, "add", "src/chat_bridge/auth.py"); git(repo, "commit", "-q", "-m", "r3"); sha_r3 = git(repo, "rev-parse", "HEAD")
            r3 = rev_c(sha_r3, 3, silent_agy, r2_fixed["findings"])
            self.assertEqual(r3["findings"][0]["resolved_in_revision"], sha_r2, "must retain original round-2 resolved_in_revision in round 3")
            self.assertTrue(security_review.evaluate_security_review_gate(sha_r3, base_sha, r3, home=home)["verified"])

    def test_10_boundary_safe_dir_validation_factory_error_exit2_evidence_and_measurements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare, base_sha, cand_sha, conf, child_dir = self._setup_clean_candidate(root)
            rev_agy = _make_fake_agy(root, "agy-rev", REVIEWER_SCRIPT)
            child_dir.mkdir(parents=True, exist_ok=True); (child_dir / "security-round-9").symlink_to(root)
            with self.assertRaises(UsageError):
                security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=9, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            with self.assertRaises(UsageError):
                security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home),
                    security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(rev_agy), reviewer_agy_bin="--no-sandbox"))
            self.assertEqual(security_review.main(["--repo", str(repo), "--home", str(repo), "--task", "900"]), 2)

            builder_agy = _make_fake_agy(root, "agy-builder-meas", _make_builder_script("fix-with-usage"))
            rates = worker_module.RateCard(input_usd_per_1m=2.0, output_usd_per_1m=10.0)
            with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                  _SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a",
                                                        "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
                res = security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home),
                    security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy), reviewer_agy_bin=str(rev_agy), rates=rates))
            self.assertEqual((res.status, res.ci_verified, res.child["security_verified"], res.verified, res.delivery_approved), ("security-verified", True, True, False, False))
            self.assertNotIn("BACKDOOR_SECRET", Path(res.evidence["candidate_diff_path"]).read_text(encoding="utf-8"))
            gh_ev = json.loads(Path(res.evidence["github_evidence_path"]).read_text(encoding="utf-8"))
            self.assertEqual(gh_ev["ci_verification"]["candidate_sha"], res.child["candidate_sha"])
            self.assertEqual(res.measurements["usage"]["input_tokens"], 300, "must retain and aggregate repair builder token usage")
            self.assertEqual(res.measurements["usage"]["thinking_tokens"], 30)
            self.assertEqual(res.measurements["usage"]["cache_read_tokens"], 20)
            self.assertEqual((res.measurements["cost"]["state"], res.measurements["cost"]["usd"]), ("estimated", 0.0019))
            rep_cost = security_review.delivery._merge_measurements(
                {"usage": {"state": "reported"}, "cost": {"state": "reported", "usd": 0.05}},
                [{"usage": {"state": "reported"}, "cost": {"state": "reported", "usd": 0.03}}], 100)
            self.assertEqual((rep_cost["cost"]["state"], rep_cost["cost"]["usd"]), ("reported", 0.08))

    def test_11_no_premature_verified_record_persisted_before_security_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            builder_agy, rev_agy = _make_fake_agy(root, "agy-builder", _make_builder_script("fix-with-usage")), _make_fake_agy(root, "agy-rev", REVIEWER_SCRIPT)
            pre_gate_writes, orig_atomic, orig_deliver = [], security_review.delivery.deliver_module.atomic_json, security_review.delivery.deliver_module.deliver_ci_prerequisite
            def _spy_atomic(path: Path, payload: dict, root_dir: Path | None = None) -> None:
                if path.name == "record.json" and not list(home.glob("deliveries/900/attempt-*/children/*/security-review.json")):
                    pre_gate_writes.append((str(path), dict(payload)))
                return orig_atomic(path, payload, root_dir)
            def _interrupt_on_deliver_return(*args, **kwargs):
                orig_deliver(*args, **kwargs)
                raise KeyboardInterrupt("interrupted immediately as deliver_ci_prerequisite returned")
            with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana, _SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a", "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
                run_sec = lambda: security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home), security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy), reviewer_agy_bin=str(rev_agy)))
                with unittest.mock.patch.object(security_review.delivery.deliver_module, "deliver_ci_prerequisite", side_effect=_interrupt_on_deliver_return):
                    with self.assertRaises(KeyboardInterrupt):
                        run_sec()
                interrupted_parent = json.loads((home / "deliveries/900/record.json").read_text(encoding="utf-8"))
                interrupted_attempt = json.loads((home / "deliveries/900/attempt-1/record.json").read_text(encoding="utf-8"))
                self.assertEqual((interrupted_parent["status"], interrupted_parent["verified"]), ("security-review-pending", False))
                self.assertEqual((interrupted_attempt["status"], interrupted_attempt["verified"]), ("security-review-pending", False))
                self.assertFalse(interrupted_parent["child"]["verified"])
                self.assertFalse(interrupted_parent["child"]["pr"]["verified"])
                with unittest.mock.patch.object(security_review.delivery.deliver_module, "atomic_json", side_effect=_spy_atomic):
                    res = run_sec()
                self.assertEqual((res.status, res.child["security_verified"], res.verified, res.delivery_approved), ("security-verified", True, False, False)); self.assertGreaterEqual(len(pre_gate_writes), 2)
                for wpath, wpayload in pre_gate_writes:
                    self.assertFalse(wpayload.get("verified"), f"premature verified=True written to {wpath} before security gate")
                    self.assertEqual(wpayload.get("status"), "security-review-pending", f"premature status written to {wpath}")
                    self.assertFalse((wpayload.get("child") or {}).get("verified"), f"premature child.verified=True written to {wpath}")


if __name__ == "__main__":
    unittest.main()
