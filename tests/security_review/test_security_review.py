"""Tests for security review gate integration, bounded repair, and 9-outcome demo (Issue #22 Slice 2)."""

from __future__ import annotations

import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from factory import config as config_module, deliver_checks, security_review
from factory.paths import RuntimePaths
from support import git
from test_deliver import PARENT_TASK, READY_CHILD, _make_disposable_product_workspace, _make_fake_agy
from test_deliver_checks import _DisposableGitHubServer
from test_intake import _DisposableAsanaServer


class _SyncingGitHubServer(_DisposableGitHubServer):
    def _resolve_branch_sha(self, branch: str) -> str | None:
        sha = super()._resolve_branch_sha(branch)
        for pobj in (self.pulls.values() if sha else ()):
            if pobj.get("head", {}).get("ref") == branch:
                pobj["head"]["sha"] = sha
        return sha


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


def _make_builder_script(mode: str) -> str:
    vuln_block = (
        "    af.write_text('class TokenExpiredError(Exception): pass\\nBACKDOOR_SECRET = \"seed-bypass-token\"\\n"
        "def validate_token(token: str) -> dict[str, str]:\\n    if token == BACKDOOR_SECRET: return {\"sub\":\"admin\",\"bypass\":\"true\"}\\n"
        "    if token.startswith(\"expired:\"): raise TokenExpiredError(\"expired\")\\n    return {\"sub\": token}\\n', encoding='utf-8')\n"
        "    tf.write_text(tf.read_text(encoding='utf-8') + '\\n    def test_expired(self):\\n"
        "        from chat_bridge.auth import TokenExpiredError\\n        with self.assertRaises(TokenExpiredError): validate_token(\"expired:x\")\\n', encoding='utf-8')\n"
        "    subprocess.run(['git', 'add', '.'], check=True); subprocess.run(['git', 'commit', '-q', '-m', 'vuln'], check=True)\n"
        "    res = {'conversation_id': 'builder-round-0', 'status': 'SUCCESS', 'response': 'ok', 'usage': {'input_tokens': 100, 'output_tokens': 50, 'total_tokens': 150}}\n"
    )
    repair_blocks = {
        "fix": (
            "    af.write_text('class TokenExpiredError(Exception): pass\\ndef validate_token(token: str) -> dict[str, str]:\\n"
            "    if token.startswith(\"expired:\"): raise TokenExpiredError(\"expired\")\\n    return {\"sub\": token}\\n', encoding='utf-8')\n"
            "    subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True); subprocess.run(['git', 'commit', '-q', '-m', 'fix'], check=True)\n"
            "    res = {'conversation_id': 'builder-repair-1', 'status': 'SUCCESS', 'response': 'ok'}\n"
        ),
        "fix-with-usage": (
            "    af.write_text('class TokenExpiredError(Exception): pass\\ndef validate_token(token: str) -> dict[str, str]:\\n"
            "    if token.startswith(\"expired:\"): raise TokenExpiredError(\"expired\")\\n    return {\"sub\": token}\\n', encoding='utf-8')\n"
            "    subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True); subprocess.run(['git', 'commit', '-q', '-m', 'fix'], check=True)\n"
            "    res = {'conversation_id': 'builder-repair-1', 'status': 'SUCCESS', 'response': 'ok', 'usage': {'input_tokens': 200, 'output_tokens': 80, 'total_tokens': 280}}\n"
        ),
        "stubborn": (
            "    af.write_text('# claim fixed\\n' + af.read_text(encoding='utf-8'), encoding='utf-8')\n"
            "    subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True); subprocess.run(['git', 'commit', '-q', '-m', 'claim'], check=True)\n"
            "    res = {'conversation_id': 'builder-stubborn', 'status': 'SUCCESS', 'response': 'claimed fixed'}\n"
        ),
        "tamper": (
            "    pathlib.Path('AGENTS.md').write_text('# weakened\\n', encoding='utf-8')\n"
            "    subprocess.run(['git', 'add', '.'], check=True); subprocess.run(['git', 'commit', '-q', '-m', 'tamper'], check=True)\n"
            "    res = {'conversation_id': 'builder-tamper', 'status': 'SUCCESS', 'response': 'tampered'}\n"
        ),
        "noop": "    res = {'conversation_id': 'builder-noop', 'status': 'SUCCESS', 'response': 'no changes'}\n",
        "hollow-revert": (
            "    subprocess.run(['git', 'checkout', 'HEAD~1', '--', 'src/chat_bridge/auth.py'], check=True)\n"
            "    subprocess.run(['git', 'commit', '-q', '-m', 'revert impl to base'], check=True)\n"
            "    res = {'conversation_id': 'builder-hollow', 'status': 'SUCCESS', 'response': 'reverted'}\n"
        ),
        "permission-denied": (
            "    print(json.dumps({'event': 'step', 'step_update': {'state': 'PERMISSION_DENIED', 'error': 'permission denied by sandbox'}}))\n"
            "    res = {'conversation_id': 'builder-denied', 'status': 'ERROR', 'error': 'permission denied'}\n"
        ),
    }
    return (
        "import json, pathlib, subprocess, sys\n"
        "prompt = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
        "af, tf = pathlib.Path('src/chat_bridge/auth.py'), pathlib.Path('tests/test_auth.py')\n"
        f"if 'SECURITY REPAIR' not in prompt:\n{vuln_block}else:\n{repair_blocks[mode]}"
        "print(json.dumps({'event': 'result', 'result': res}))\n"
    )


VULN_THEN_FIX_SCRIPT = _make_builder_script("fix")


def run_disposable_demo(tmp: Path) -> dict[str, Any]:
    repo, home, bare = _make_disposable_product_workspace(tmp)
    base_sha = git(repo, "rev-parse", "refs/heads/main")
    git(repo, "checkout", "-q", "-b", "feature/chat-auth", base_sha); git(repo, "push", "-q", "origin", "feature/chat-auth")
    conf, child_dir = config_module.load(RuntimePaths(repo=repo, home=home)), home / "deliveries" / "demo" / "children" / "101"
    scope_detail = {"status": "deterministic-verified", "provenance": "deterministic rules enforced"}

    git(repo, "checkout", "-q", "-b", "task/101-auth", base_sha)
    (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY, encoding="utf-8")
    (repo / "tests/test_auth.py").write_text((repo / "tests/test_auth.py").read_text(encoding="utf-8") + EXPIRED_TEST_APPEND, encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-q", "-m", "clean")
    cand1_sha = git(repo, "rev-parse", "HEAD"); git(repo, "push", "-q", "origin", "task/101-auth")

    rev_agy = _make_fake_agy(tmp, "agy-reviewer", REVIEWER_SCRIPT)
    sugg_agy = _make_fake_agy(
        tmp, "agy-sugg",
        "import json\nprint(json.dumps({'event':'result','result':{'conversation_id':'rev-sugg','status':'SUCCESS','response':json.dumps("
        "{'outcome':'approved','findings':[{'policy_id':'SEC-POL-04','rule':'strip-token','blocking':False,'severity':'low',"
        "'title':'Optional whitespace normalization','file_path':'src/chat_bridge/auth.py','line':4}]})}}))\n")
    clean_rev = security_review.review_candidate_security(
        repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf,
        base_sha=base_sha, candidate_sha=cand1_sha, round_num=1, agy_bin=str(rev_agy), deadline=time.monotonic() + 30.0, limit_s=30)
    sugg_rev = security_review.review_candidate_security(
        repo=repo, home=home, child_dir=child_dir, child=READY_CHILD, conf=conf, base_sha=base_sha,
        candidate_sha=cand1_sha, round_num=1, agy_bin=str(sugg_agy), deadline=time.monotonic() + 30.0, limit_s=30)
    repair_agy = _make_fake_agy(tmp, "agy-repair", _make_builder_script("fix"))
    stubborn_agy = _make_fake_agy(tmp, "agy-stubborn", _make_builder_script("stubborn"))

    with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
          _SyncingGitHubServer(bare_repo=bare) as gh,
          unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a",
                                                "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
        pr_info = deliver_checks.open_and_confirm_pr(
            gh.base_url, "tok-g", "example/chat-bridge", PARENT_TASK, READY_CHILD,
            "task/101-auth", cand1_sha, "feature/chat-auth", [], scope_detail, [], time.monotonic() + 30.0, 30)
        ev = lambda rec, sha=cand1_sha: security_review.evaluate_child_pr_with_security_gate(
            repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url, token="tok-g", repo_slug="example/chat-bridge",
            parent=PARENT_TASK, child=READY_CHILD, conf=conf, pr_info=pr_info, head_branch="task/101-auth", candidate_sha=sha,
            base_branch="feature/chat-auth", base_sha=base_sha, scope_detail=scope_detail, security_review_record=rec,
            trace=[], deadline=time.monotonic() + 30.0, limit_s=30)
        r_clean, r_missing, r_sugg = ev(clean_rev), ev(None), ev(sugg_rev)
        r_nover = ev({**clean_rev, "independent_verification": {**clean_rev["independent_verification"], "checks": []}})
        r_unres = ev({**clean_rev, "blocking_findings": [{"finding_id": "SEC-POL-01-x", "blocking": True, "status": "open", "title": "secret"}]})
        (repo / "src/chat_bridge/auth.py").write_text(CLEAN_AUTH_PY + "# v2\n", encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-q", "-m", "v2"); cand2_sha = git(repo, "rev-parse", "HEAD"); git(repo, "push", "-q", "origin", "task/101-auth")
        r_stale = ev(clean_rev, cand2_sha)

        run_cli = lambda agy, cap: json.loads(subprocess.run(
            [sys.executable, "-m", "factory.security_review", "--repo", str(repo), "--home", str(home),
             "--task", "900", "--agy-bin", str(agy), "--reviewer-agy-bin", str(rev_agy), "--max-repair-rounds", str(cap), "--json"],
            capture_output=True, text=True, check=False).stdout)
        d_vuln, d_corr, d_exh = run_cli(repair_agy, 0), run_cli(repair_agy, 2), run_cli(stubborn_agy, 2)

    r1_f0 = d_corr["child"]["security_repair"]["rounds"][0]["blocking_findings"][0]
    r2_res0 = d_corr["child"]["security_review"]["previous_findings_resolution"][0]
    assert r1_f0["reproducer_verification"]["reproduced"] is True and r1_f0["reproducer_verification"]["exit_code"] == 1
    assert r2_res0["reproducer_verification"]["ok"] is True and r2_res0["reproducer_verification"]["exit_code"] == 0
    summary = {
        "clean": {"status": r_clean["status"], "verified": r_clean["verified"]},
        "vulnerable": {"status": d_vuln["status"], "verified": d_vuln["verified"], "finding_id": d_vuln["child"]["security_review"]["blocking_findings"][0]["finding_id"]},
        "corrected": {"status": d_corr["status"], "verified": d_corr["verified"], "repairs_used": d_corr["child"]["security_repair"]["repairs_used"],
                      "failure_before_exit": r1_f0["reproducer_verification"]["exit_code"], "pass_after_exit": r2_res0["reproducer_verification"]["exit_code"],
                      "resolved_findings": [x["finding_id"] for x in d_corr["child"]["security_review"]["previous_findings_resolution"] if x["status"] == "resolved"],
                      "evidence_path": d_corr["evidence"]["security_review_path"]},
        "missing-review": {"status": r_missing["status"], "verified": r_missing["verified"]},
        "stale-review": {"status": r_stale["status"], "verified": r_stale["verified"]},
        "unresolved-blocker": {"status": r_unres["status"], "verified": r_unres["verified"]},
        "non-blocking-suggestion": {"status": r_sugg["status"], "verified": r_sugg["verified"], "suggestions": len(r_sugg["security_gate"]["non_blocking_suggestions"])},
        "missing-verification": {"status": r_nover["status"], "verified": r_nover["verified"]},
        "exhausted-repair": {"status": d_exh["status"], "verified": d_exh["verified"], "repairs_used": d_exh["child"]["security_repair"]["repairs_used"]},
    }
    assert summary["clean"] == {"status": "verified", "verified": True} and summary["missing-review"] == {"status": "security-review-missing", "verified": False}
    assert summary["vulnerable"]["status"] == "security-blockers-unresolved" and not summary["vulnerable"]["verified"]
    assert summary["corrected"]["status"] == "verified" and summary["corrected"]["verified"] and summary["corrected"]["repairs_used"] == 1
    assert summary["stale-review"] == {"status": "stale-security-review", "verified": False} and summary["unresolved-blocker"] == {"status": "security-blockers-unresolved", "verified": False}
    assert summary["non-blocking-suggestion"] == {"status": "verified", "verified": True, "suggestions": 1} and summary["missing-verification"] == {"status": "security-verification-missing", "verified": False}
    assert summary["exhausted-repair"] == {"status": "security-repair-exhausted", "verified": False, "repairs_used": 2}
    return summary


class SecurityReviewSlice2Test(unittest.TestCase):
    def test_all_nine_outcomes_and_protection_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            demo_dir = root / "demo"
            demo_dir.mkdir(parents=True, exist_ok=True)
            summary = run_disposable_demo(demo_dir)
            self.assertEqual(summary["corrected"]["status"], "verified")
            self.assertEqual((summary["corrected"]["failure_before_exit"], summary["corrected"]["pass_after_exit"]), (1, 0))

            tamper_dir = root / "tamper"
            tamper_dir.mkdir(parents=True, exist_ok=True)
            repo, home, bare = _make_disposable_product_workspace(tamper_dir)
            rev_agy = _make_fake_agy(tamper_dir, "agy-reviewer", REVIEWER_SCRIPT)
            tamper_agy = _make_fake_agy(tamper_dir, "agy-tamper", _make_builder_script("tamper"))
            with (_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                  _SyncingGitHubServer(bare_repo=bare) as gh,
                  unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok-a",
                                                        "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok-g"})):
                res_tamper = security_review.deliver_with_security_review(
                    RuntimePaths(repo=repo, home=home),
                    security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=30, agy_bin=str(tamper_agy), reviewer_agy_bin=str(rev_agy), max_repair_rounds=2))
                self.assertEqual((res_tamper.status, res_tamper.verified), ("scope-violation", False))

    def test_cli_verify_file_skill_docs_and_demo_script(self) -> None:
        skill_text = (ROOT / "skills/security-review/SKILL.md").read_text(encoding="utf-8")
        for needle in ("name: security-review", 'FACTORY_ROOT="', 'FACTORY="$FACTORY_ROOT/bin/factory"'):
            self.assertIn(needle, skill_text)
        self.assertTrue((ROOT / "docs/security-review/README.md").is_file())
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(security_review.main(["--repo", tmp, "--verify-file", "sample.py"]), 0)
            p.write_text("BACKDOOR_SECRET = 'abc'\n", encoding="utf-8")
            self.assertEqual(security_review.main(["--repo", tmp, "--verify-file", "sample.py", "--rule", "hardcoded-secret"]), 1)
        proc = subprocess.run(["bash", str(ROOT / "scripts/demo-security-review.sh")], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("DEMO_SECURITY_REVIEW_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
