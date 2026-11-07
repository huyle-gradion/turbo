"""Unit tests for the standalone security reviewer role and gate (Issue #22 Slice 1)."""

from __future__ import annotations

import json, sys, tempfile, time, unittest, unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from factory import config as config_module, security_review, worker as worker_module
from factory.errors import UsageError
from factory.paths import RuntimePaths
from support import git
from test_deliver import READY_CHILD, _make_disposable_product_workspace, _make_fake_agy

CLEAN_AUTH_PY = (
    "class TokenExpiredError(Exception): pass\ndef validate_token(token: str) -> dict[str, str]:\n"
    "    if token.startswith('expired:'): raise TokenExpiredError('expired')\n    return {'sub': token}\n"
)
EXPIRED_TEST_APPEND = (
    "\n    def test_expired(self) -> None:\n        from chat_bridge.auth import TokenExpiredError\n"
    "        with self.assertRaises(TokenExpiredError): validate_token('expired:1')\n"
)
REVIEWER_SCRIPT = (
    "import json, pathlib, sys\nprompt = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
    "for req in ('Role: security-reviewer', 'Applicable security policies:', 'SEC-POL-01', 'Sub-task constraints:', 'Required JSON response schema:'):\n"
    "    assert req in prompt, f'missing {req} in reviewer prompt'\n"
    "af = pathlib.Path('src/chat_bridge/auth.py'); txt = af.read_text(encoding='utf-8') if af.is_file() else ''\n"
    "findings = [{'policy_id': 'SEC-POL-01', 'rule': 'hardcoded-secret', 'severity': 'critical', 'blocking': True, 'title': 'Hardcoded secret',\n"
    "             'file_path': 'src/chat_bridge/auth.py', 'line': 2, 'evidence': 'BACKDOOR_SECRET', 'actionable_correction': 'Remove BACKDOOR_SECRET',\n"
    "             'verification_command': 'python3 -m factory.security_review --verify-file src/chat_bridge/auth.py --rule hardcoded-secret'}] if 'BACKDOOR_SECRET' in txt else []\n"
    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'sec-reviewer-1', 'status': 'SUCCESS', 'response': json.dumps({'outcome': 'changes-requested' if findings else 'approved', 'findings': findings})}}))\n"
)


class SecurityReviewerTest(unittest.TestCase):
    def test_clean_vulnerable_omitted_reviewer_and_omitted_unfixed_prior_finding(self) -> None:
        self.assertIsInstance(security_review.DEFECT_PATTERNS[0], security_review.DefectRule)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _ = _make_disposable_product_workspace(root)
            base_sha = git(repo, "rev-parse", "refs/heads/main")
            conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            rev_agy = _make_fake_agy(root, "agy-reviewer", REVIEWER_SCRIPT)

            git(repo, "checkout", "-q", "-b", "task/101-clean", base_sha)
            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "clean")
            clean_sha = git(repo, "rev-parse", "HEAD")

            rev_call = lambda sha, rnum, agy, prior=None, b_id="builder-conv-1": security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf, base_sha=base_sha,
                candidate_sha=sha, round_num=rnum, agy_bin=agy, prior_findings=prior, builder_session_id=b_id,
                deadline=time.monotonic() + 30.0, limit_s=30)

            no_rev = rev_call(clean_sha, 1, None)
            self.assertEqual((no_rev["reviewer_executed"], no_rev["outcome"], no_rev["ready"]), (False, "security-review-missing", False))
            self.assertEqual(security_review.evaluate_security_review_gate(
                clean_sha, base_sha, {**no_rev, "outcome": "approved", "role_separation_verified": True}, home=home)["status"], "security-review-missing")

            clean_rev = rev_call(clean_sha, 1, str(rev_agy))
            self.assertEqual((clean_rev["reviewer_executed"], clean_rev["outcome"], clean_rev["role_separation_verified"]), (True, "approved", True))
            self.assertIn("SEC-POL-01", clean_rev["reviewer_prompt_policies"])

            custom_r1_agy = _make_fake_agy(
                root, "agy-custom-r1",
                "import json\np={'outcome':'changes-requested','findings':[{'policy_id':'SEC-POL-04','rule':'unnormalized-sub',"
                "'severity':'high','blocking':True,'title':'Unnormalized sub','file_path':'src/chat_bridge/auth.py','line':3,"
                "'evidence':\"return {'sub': token}\",'actionable_correction':'Cast token with str(token)'}]}\n"
                "print(json.dumps({'event':'result','result':{'conversation_id':'rev-r1','status':'SUCCESS','response':json.dumps(p)}}))\n")
            silent_r2_agy = _make_fake_agy(
                root, "agy-silent-r2",
                "import json\nprint(json.dumps({'event':'result','result':{'conversation_id':'rev-r2','status':'SUCCESS',"
                "'response':json.dumps({'outcome':'approved','findings':[]})}}))\n")
            r1_custom = rev_call(clean_sha, 1, str(custom_r1_agy))
            custom_fid = r1_custom["blocking_findings"][0]["finding_id"]
            self.assertTrue(r1_custom["blocking_findings"][0]["reproducer_verification"]["reproduced"])

            r2_unfixed = rev_call(clean_sha, 2, str(silent_r2_agy), prior=r1_custom["findings"], b_id="builder-conv-2")
            self.assertEqual((r2_unfixed["outcome"], r2_unfixed["previous_findings_resolution"][0]["status"]), ("changes-requested", "open"))
            self.assertFalse(r2_unfixed["previous_findings_resolution"][0]["reproducer_verification"]["ok"])
            self.assertEqual(security_review.evaluate_security_review_gate(clean_sha, base_sha, r2_unfixed, home=home)["status"], "security-blockers-unresolved")

            (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY.replace("{'sub': token}", "{'sub': str(token)}"), encoding="utf-8")
            git(repo, "add", "src/chat_bridge/auth.py"); git(repo, "commit", "-q", "-m", "fix sub cast")
            fixed_sha = git(repo, "rev-parse", "HEAD")
            r3_fixed = rev_call(fixed_sha, 3, str(silent_r2_agy), prior=r2_unfixed["findings"], b_id="builder-conv-3")
            self.assertEqual((r3_fixed["outcome"], r3_fixed["previous_findings_resolution"][0]["finding_id"], r3_fixed["previous_findings_resolution"][0]["status"]),
                             ("approved", custom_fid, "resolved"))
            self.assertTrue(r3_fixed["previous_findings_resolution"][0]["reproducer_verification"]["ok"])
            self.assertEqual(security_review.evaluate_security_review_gate(fixed_sha, base_sha, r3_fixed, home=home)["status"], "verified")

            mut_reviewer = _make_fake_agy(
                root, "agy-reviewer-mutate",
                "import json, pathlib\npathlib.Path('src/chat_bridge/auth.py').write_text('# mut\\n', encoding='utf-8')\n"
                "print(json.dumps({'event':'result','result':{'conversation_id':'sec-rev-mut','status':'SUCCESS','response':'{}'}}))\n")
            mut_rev = rev_call(clean_sha, 1, str(mut_reviewer))
            self.assertEqual((mut_rev["outcome"], mut_rev["role_separation_verified"]), ("invalid-review", False))

    def test_reviewer_thermos_sandbox_probes_strict_json_scanning_and_containment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _ = _make_disposable_product_workspace(root)
            base_sha = git(repo, "rev-parse", "refs/heads/main")
            conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            git(repo, "checkout", "-q", "-b", "task/101-rev", base_sha)
            (repo / "src/chat_bridge/auth.py").write_text("BACKDOOR_SECRET = 's1'\nAPI_SECRET = 's2'\n" + CLEAN_AUTH_PY, encoding="utf-8")
            (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND + "\nPRIVATE_KEY = 'tk'\n", encoding="utf-8")
            git(repo, "add", "."); git(repo, "commit", "-q", "-m", "cand")
            cand_sha = git(repo, "rev-parse", "HEAD")
            rev_agy = _make_fake_agy(
                root, "agy-rev-1",
                "import json\nprint(json.dumps({'event':'result','result':{'conversation_id':'rev-1','status':'SUCCESS',"
                "'response':json.dumps({'outcome':'changes-requested','findings':[{'policy_id':'SEC-POL-01','rule':'hardcoded-secret','severity':'critical','blocking':None,'file_path':'src/chat_bridge/auth.py'}]})}}))\n")
            rec = security_review.review_candidate_security(
                repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                base_sha=base_sha, candidate_sha=cand_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            by_file = {f["file_path"]: f for f in rec["blocking_findings"]}
            self.assertIn("tests/test_auth.py", by_file)
            self.assertIn("s1", by_file["src/chat_bridge/auth.py"]["evidence"])
            self.assertIn("s2", by_file["src/chat_bridge/auth.py"]["evidence"])
            with unittest.mock.patch.object(worker_module, "run_safety_probes", return_value=[{"name": "forbidden_credential_access", "attempted": True, "denied": False, "exit": 0}]):
                rec_bad = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=2, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertEqual((rec_bad["reviewer_executed"], rec_bad["independent_verification"]["executed"], rec_bad["outcome"]), (False, False, "invalid-review"))
            (child_dir / "security-round-9").symlink_to(root)
            with self.assertRaises(UsageError):
                security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
                    base_sha=base_sha, candidate_sha=cand_sha, round_num=9, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
            self.assertEqual(security_review.main(["--repo", str(repo), "--home", str(repo), "--task", "900"]), 2)


if __name__ == "__main__":
    unittest.main()
