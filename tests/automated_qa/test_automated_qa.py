"""Tests for automated QA delivery orchestration, repair safety, and CLI runner (#21)."""

from __future__ import annotations

import dataclasses
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import unittest
from unittest import mock

import factory.automated_qa as qa_pkg
from factory import ci_gate, config as config_module, deliver, deliver_checks, gitio, worker as worker_module
from factory.automated_qa import (
    QADeliveryResult, QADeliverySpec, QAEvaluationCase, __main__ as qa_main, run_automated_qa_delivery,
)
from factory.automated_qa.delivery import _merge_measurements
from factory.errors import UsageError
from automated_qa.test_automated_qa_eval import WHITESPACE_QA_CASE
from test_deliver import PARENT_TASK, READY_CHILD, TEST_AUTHOR_SCRIPT, _make_disposable_product_workspace, _make_fake_agy
from test_deliver_checks import _DisposableGitHubServer
from test_intake import _DisposableAsanaServer


class _SyncGitHubServer(_DisposableGitHubServer):
    def _resolve_branch_sha(self, branch: str) -> str | None:
        if sha := super()._resolve_branch_sha(branch):
            for pobj in self.pulls.values():
                if pobj.get("head", {}).get("ref") == branch:
                    pobj["head"]["sha"] = sha
        return sha


SEEDED_INITIAL_COMMIT = (
    "pathlib.Path('src/chat_bridge/auth.py').write_text("
    "'class TokenExpiredError(Exception):\\n    pass\\n\\n"
    "def validate_token(token: str) -> dict[str, str]:\\n"
    "    if token.startswith(\"expired:\"):\\n"
    "        raise TokenExpiredError(\"token expired\")\\n"
    "    return {\"sub\": token}\\n', encoding='utf-8')\n"
    "pathlib.Path('tests/test_auth.py').write_text("
    "'import sys, pathlib, unittest\\n"
    "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / \"src\"))\\n"
    "from chat_bridge.auth import TokenExpiredError, validate_token\\n\\n"
    "class AuthTest(unittest.TestCase):\\n"
    "    def test_valid_token(self) -> None:\\n"
    "        self.assertEqual(validate_token(\"user-1\"), {\"sub\": \"user-1\"})\\n"
    "    def test_expired_token(self) -> None:\\n"
    "        with self.assertRaises(TokenExpiredError):\\n"
    "            validate_token(\"expired:123\")\\n', encoding='utf-8')\n"
    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py', 'tests/test_auth.py'], check=True)\n"
    "subprocess.run(['git', 'commit', '-q', '-m', 'feat(auth): reject expired auth tokens'], check=True)\n"
)

RESULT_EMIT = (
    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c-101', "
    "'status': 'SUCCESS', 'response': 'done', 'usage': {'input_tokens': 500, "
    "'output_tokens': 120, 'thinking_tokens': 10, 'cache_read_tokens': 0, 'total_tokens': 630}}}))\n"
)


def _repair_script(repair_body: str, initial_extra: str = "") -> str:
    init_block = (SEEDED_INITIAL_COMMIT + initial_extra).strip().replace("\n", "\n    ")
    rep_block = (repair_body.strip() or "pass").replace("\n", "\n    ")
    return (
        "import json, pathlib, subprocess\n"
        "prompt = next((sys.argv[i + 1] for i, a in enumerate(sys.argv[:-1]) if a == '--print'), '')\n"
        f"if 'QA-101-AC-1-QA-AC-1-WHITESPACE' in prompt:\n    {rep_block}\n"
        f"else:\n    {init_block}\n" + RESULT_EMIT
    )


DEMO_REPAIR_BUILDER_SCRIPT = _repair_script(
    "pathlib.Path('src/chat_bridge/auth.py').write_text("
    "'class TokenExpiredError(Exception):\\n    pass\\n\\n"
    "def validate_token(token: str) -> dict[str, str]:\\n"
    "    normalized = token.strip()\\n"
    "    if normalized.startswith(\"expired:\"):\\n"
    "        raise TokenExpiredError(\"token expired\")\\n"
    "    return {\"sub\": normalized}\\n', encoding='utf-8')\n"
    "p = pathlib.Path('tests/test_auth.py')\n"
    "p.write_text(p.read_text(encoding='utf-8') + "
    "'\\n    def test_whitespace_expired_token(self) -> None:\\n"
    "        with self.assertRaises(TokenExpiredError):\\n"
    "            validate_token(\"  expired:123  \")\\n', encoding='utf-8')\n"
    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py', 'tests/test_auth.py'], check=True)\n"
    "subprocess.run(['git', 'commit', '-q', '-m', 'fix(auth): strip token whitespace before expiry check'], check=True)"
)


def _run_qa_with_servers(
    root: Path, script: str, cases: tuple[QAEvaluationCase, ...] = (WHITESPACE_QA_CASE,),
    max_attempts: int = 2, rates: worker_module.RateCard | None = None, test_author_script: str | None = None,
) -> QADeliveryResult:
    repo, home, bare = _make_disposable_product_workspace(root)
    wrapper = _make_fake_agy(root, "fake-qa-agy", script, test_author_script)
    with _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana, _SyncGitHubServer(bare_repo=bare) as gh:
        keys = ("TURBO_ASANA_API_URL", "ASANA_ACCESS_TOKEN", "TURBO_GITHUB_API_URL", "TURBO_GITHUB_TOKEN")
        old_env = {k: os.environ.get(k) for k in keys}
        os.environ.update({
            "TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "disposable-asana-token",
            "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "disposable-gh-token",
        })
        try:
            return run_automated_qa_delivery(
                config_module.RuntimePaths(repo=repo, home=home),
                QADeliverySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(wrapper), rates=rates, qa_cases=cases, max_correction_attempts=max_attempts),
            )
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class AutomatedQADeliveryTest(unittest.TestCase):
    def test_seeded_failure_routes_to_builder_and_re_verifies_on_new_revision(self) -> None:
        self.assertNotIn("tests.automated_qa", sys.modules)
        with tempfile.TemporaryDirectory() as tmp:
            rates = worker_module.RateCard(input_usd_per_1m=2.0, output_usd_per_1m=10.0)
            qa_res = _run_qa_with_servers(Path(tmp), DEMO_REPAIR_BUILDER_SCRIPT, rates=rates)
            self.assertEqual((qa_res.status, qa_res.ci_verified, qa_res.qa_verified, qa_res.merged, qa_res.parent_accepted), ("qa-verified", True, True, False, False))
            self.assertEqual((qa_res.correction_attempts_used, len(qa_res.qa_rounds)), (1, 2))
            r1, r2 = qa_res.qa_rounds[0], qa_res.qa_rounds[1]
            self.assertEqual((r1["status"], r2["status"]), ("qa-failed", "qa-verified"))
            self.assertNotEqual(r1["candidate_sha"], r2["candidate_sha"])
            f_final = qa_res.findings[0]
            self.assertEqual(
                (f_final["finding_id"], f_final["status"], f_final["created_round"], f_final["resolved_round"], len(f_final["history"])),
                ("QA-101-AC-1-QA-AC-1-WHITESPACE", "resolved", 1, 2, 2),
            )
            rep_disk = json.loads((Path(qa_res.evidence["attempt_dir"]) / "children/101/automated-qa/repair-1/record.json").read_text(encoding="utf-8"))
            self.assertEqual((bool(rep_disk["isolated_home"]), len(rep_disk["probes"]), bool(rep_disk["github_requests"]), Path(rep_disk["github_requests_path"]).is_file()), (True, 2, True, True))
            self.assertIn("ASANA_ACCESS_TOKEN", rep_disk["stripped_env_keys"])
            self.assertEqual(qa_res.measurements["usage"]["total_tokens"], 1260)
            self.assertAlmostEqual(qa_res.measurements["cost"]["usd"], 0.0044, places=6)
            rec_disk = json.loads((Path(qa_res.evidence["attempt_dir"]) / "record.json").read_text(encoding="utf-8"))
            self.assertEqual((rec_disk["ci_verified"], rec_disk["qa_verified"], rec_disk["verified"], rec_disk["delivery_approved"]), (True, True, False, False))

    def test_scope_violation_exhaustion_and_truthful_ci_verification(self) -> None:
        scope_violating_script = _repair_script(
            "pathlib.Path('AGENTS.md').write_text('# tampered\\n', encoding='utf-8')\n"
            "subprocess.run(['git', 'add', 'AGENTS.md'], check=True)\n"
            "subprocess.run(['git', 'commit', '-q', '-m', 'chore: tamper'], check=True)"
        )
        delete_round1_test_script = _repair_script(
            "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(t): return {}\\n', encoding='utf-8')\n"
            "subprocess.run(['git', 'rm', '-q', 'tests/test_extra_round1.py'], check=True)\n"
            "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
            "subprocess.run(['git', 'commit', '-q', '-m', 'fix(auth): drop test'], check=True)",
        )
        extra_test_author = TEST_AUTHOR_SCRIPT.replace(  # the test author, not the implementer, owns the round-1 test
            "subprocess.run(['git', 'add', 'tests/test_auth.py'], check=True)\n",
            "pathlib.Path('tests/test_extra_round1.py').write_text('import unittest\\n', encoding='utf-8')\n"
            "subprocess.run(['git', 'add', 'tests/test_auth.py', 'tests/test_extra_round1.py'], check=True)\n",
        )
        test_only_repair_script = _repair_script(
            "p = pathlib.Path('tests/test_auth.py')\n"
            "p.write_text(p.read_text(encoding='utf-8') + '# comment\\n', encoding='utf-8')\n"
            "subprocess.run(['git', 'add', 'tests/test_auth.py'], check=True)\n"
            "subprocess.run(['git', 'commit', '-q', '-m', 'test(auth): update test only'], check=True)"
        )
        stubborn_script = (
            "import json, pathlib, subprocess\n"
            "m = '# rev-' + subprocess.run(['git', 'rev-list', '--count', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()\n"
            + SEEDED_INITIAL_COMMIT
            + "p = pathlib.Path('src/chat_bridge/auth.py')\n"
            "p.write_text(p.read_text(encoding='utf-8') + m + '\\n', encoding='utf-8')\n"
            "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
            "subprocess.run(['git', 'commit', '--amend', '-q', '-m', f'fix(auth): adjustment {m}'], check=True)\n" + RESULT_EMIT
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for sub, script, expected_st, author in (
                ("scope", scope_violating_script, "scope-violation", None),
                ("deltest", delete_round1_test_script, "spec-check-conflict", extra_test_author),
                ("testonly", test_only_repair_script, "missing-implementation", None),
            ):
                (root / sub).mkdir()
                res = _run_qa_with_servers(root / sub, script, test_author_script=author)
                self.assertEqual((res.status, res.ci_verified, res.qa_verified, res.child["verified"]), (expected_st, False, False, False))

            (root / "stale").mkdir()
            with mock.patch.object(ci_gate, "revalidate_child_verification", return_value={"verified": False, "status": "stale-revision", "blockers": ["base advanced"]}):
                stale_res = _run_qa_with_servers(root / "stale", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((stale_res.status, stale_res.ci_verified, stale_res.qa_verified, stale_res.child["verified"]), ("stale-revision", False, False, False))

            orig_ci_gate = ci_gate.evaluate_child_pr_ci_gate
            for sub, blk, expected_st in (
                ("ci-pending-ordinary", ["check runs missing"], "ci-pending"),
                ("ci-pending-expired", ["CI checks still pending when time allowance expired: Gate 1"], "timed-out"),
            ):
                (root / sub).mkdir()

                def mock_pending_ci(blockers=blk, **kw):
                    if (Path(kw["child_dir"]) / "automated-qa").exists():
                        return {"status": "ci-pending", "verified": False, "tested_sha": None, "checks": [], "blockers": blockers}
                    return orig_ci_gate(**kw)

                with mock.patch.object(ci_gate, "evaluate_child_pr_ci_gate", side_effect=mock_pending_ci):
                    p_res = _run_qa_with_servers(root / sub, DEMO_REPAIR_BUILDER_SCRIPT)
                self.assertEqual((p_res.status, p_res.ci_verified, p_res.qa_verified), (expected_st, False, False))

            (root / "exhaust").mkdir()
            ex_res = _run_qa_with_servers(root / "exhaust", stubborn_script, max_attempts=2)
            self.assertEqual((ex_res.status, ex_res.ci_verified, ex_res.qa_verified, ex_res.correction_attempts_used, len(ex_res.qa_rounds)), ("qa-exhausted", True, False, 2, 3))

    def test_repair_safety_evidence_short_circuit_and_remote_main_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orig_probes = worker_module.run_safety_probes
            orig_exec = worker_module.execute_stream
            orig_git_timed = deliver_checks.git_timed
            repair_builder_calls: list[tuple[str, ...]] = []

            def fake_probes(env, wt, wdir, hm, *, deadline=None):
                if "repair-" in str(wdir):
                    return [{"name": "forbidden_credential_access", "attempted": True, "denied": False}]
                return orig_probes(env, wt, wdir, hm, deadline=deadline)

            def spy_exec(cwd, argv, env, timeout_s, *, isolated_home=None, allow_network=True):
                if "repair-" in str(cwd):
                    repair_builder_calls.append(argv)
                return orig_exec(cwd, argv, env, timeout_s, isolated_home=isolated_home, allow_network=allow_network)

            (root / "probes").mkdir()
            with (
                mock.patch.object(worker_module, "run_safety_probes", side_effect=fake_probes),
                mock.patch.object(worker_module, "execute_stream", side_effect=spy_exec),
            ):
                probe_res = _run_qa_with_servers(root / "probes", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((probe_res.status, probe_res.ci_verified, repair_builder_calls), ("unsafe-environment", False, []))
            p_rec = json.loads((Path(probe_res.evidence["attempt_dir"]) / "children/101/automated-qa/repair-1/record.json").read_text(encoding="utf-8"))
            self.assertEqual((bool(p_rec["isolated_home"]), p_rec["probes"][0]["denied"]), (True, False))

            (root / "shortcircuit").mkdir()
            repair_git_phases: list[str] = []

            def spy_git_timed(repo_p, deadline, limit_s, phase, *args):
                if phase in ("repair diff", "git fetch origin", "fetch repair commit"):
                    repair_git_phases.append(phase)
                return orig_git_timed(repo_p, deadline, limit_s, phase, *args)

            with mock.patch.object(deliver_checks, "git_timed", side_effect=spy_git_timed):
                sc_res = _run_qa_with_servers(root / "shortcircuit", _repair_script("pass"))
            self.assertEqual((sc_res.status, sc_res.ci_verified, repair_git_phases), ("missing-implementation", False, []))

            (root / "remotemain").mkdir()
            orig_remote_ref = gitio.remote_ref
            rm_vals = iter([None, "f" * 40])

            def fake_remote_ref(r, b):
                if b == "main" and any(f.name == "_run_repair_attempt" for f in traceback.extract_stack()):
                    return next(rm_vals, "f" * 40)
                return orig_remote_ref(r, b)

            with mock.patch("factory.gitio.remote_ref", side_effect=fake_remote_ref):
                rm_res = _run_qa_with_servers(root / "remotemain", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((rm_res.status, rm_res.ci_verified), ("scope-violation", False))

            (root / "timeout").mkdir()

            def timeout_exec(cwd, argv, env, timeout_s, *, isolated_home=None, allow_network=True):
                if "repair-" in str(cwd):
                    return (124, "out disposable-asana-token", "err disposable-gh-token", 50, True)
                return orig_exec(cwd, argv, env, timeout_s, isolated_home=isolated_home, allow_network=allow_network)

            with mock.patch.object(worker_module, "execute_stream", side_effect=timeout_exec):
                to_res = _run_qa_with_servers(root / "timeout", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((to_res.status, to_res.ci_verified), ("timed-out", False))
            for fp in Path(to_res.evidence["attempt_dir"]).rglob("*"):
                if fp.is_file():
                    txt = fp.read_text(encoding="utf-8")
                    self.assertNotIn("disposable-asana-token", txt)
                    self.assertNotIn("disposable-gh-token", txt)

            (root / "pubfail").mkdir()
            orig_gh_req = deliver_checks.github_request

            def fail_repair_pr_get(method, url, token, base_url, trace, deadline, limit_s, payload=None):
                if method == "GET" and "/pulls/" in url and len(trace) == 0:
                    res = orig_gh_req(method, url, token, base_url, trace, deadline, limit_s, payload=payload)
                    return {**res, "head": {"sha": "0" * 40}}
                return orig_gh_req(method, url, token, base_url, trace, deadline, limit_s, payload=payload)

            with mock.patch.object(deliver_checks, "github_request", side_effect=fail_repair_pr_get):
                pf_res = _run_qa_with_servers(root / "pubfail", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((pf_res.status, pf_res.ci_verified), ("pr-failed", False))
            pf_rec = json.loads((Path(pf_res.evidence["attempt_dir"]) / "children/101/automated-qa/repair-1/record.json").read_text(encoding="utf-8"))
            self.assertEqual((pf_rec["status"], bool(pf_rec["github_requests"]), Path(pf_rec["github_requests_path"]).is_file()), ("pr-failed", True, True))

    def test_measurement_aggregation_and_ambiguous_input_rejection(self) -> None:
        rates = worker_module.RateCard(input_usd_per_1m=2.0, output_usd_per_1m=10.0)
        base_tok = {k: 0 for k in worker_module.TOKEN_KEYS}
        init_ok = {
            "elapsed_ms": 100, "reported_duration_seconds": 1.0,
            "usage": {"state": "reported", "provenance": "p", **base_tok, "input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
            "cost": {"state": "estimated", "usd": 0.0007, "input_rate_usd_per_1m": 2.0, "output_rate_usd_per_1m": 10.0, "provenance": "p"},
        }
        m_no_rep = _merge_measurements(init_ok, [], 120, rates)
        self.assertEqual((m_no_rep["initial_measurements"], m_no_rep["repair_measurements"]), (init_ok, []))

        zero_run = {"usage": {"state": "reported", "provenance": "p", **base_tok}, "cost": {"state": "reported", "usd": 0.0, "provenance": "p"}}
        m_zero = _merge_measurements(zero_run, [{"measurements": zero_run}], 200, rates)
        self.assertEqual((m_zero["usage"]["state"], m_zero["usage"]["total_tokens"], m_zero["cost"]["usd"]), ("reported", 0, 0.0))

        bool_run = {
            "usage": {"state": "reported", "provenance": "p", **base_tok, "input_tokens": True, "output_tokens": False, "total_tokens": 1},
            "cost": {"state": "reported", "usd": True, "provenance": "p"},
        }
        m_bool = _merge_measurements(init_ok, [{"measurements": bool_run}], 200, rates)
        self.assertEqual((m_bool["usage"]["state"], m_bool["cost"]["state"], m_bool["cost"]["usd"]), ("unavailable", "unavailable", None))

        empty_rep = {"usage": {"state": "reported", "provenance": "p", **{k: None for k in worker_module.TOKEN_KEYS}}, "cost": {"state": "unavailable", "usd": None, "provenance": "p"}}
        self.assertEqual(_merge_measurements(empty_rep, [{"measurements": empty_rep}], 200, rates)["usage"]["state"], "unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bad_max in (True, False, -1, 6, "2"):
                with self.subTest(bad_max=bad_max), self.assertRaises(UsageError):
                    run_automated_qa_delivery(
                        config_module.RuntimePaths(repo=root, home=root),
                        QADeliverySpec(task_ref="900", time_limit_seconds=60, max_correction_attempts=bad_max),  # type: ignore[arg-type]
                    )

            (root / "mismatch").mkdir()
            orig_deliver = deliver.deliver_ci_prerequisite

            def mismatched_gid_deliver(paths, spec, **kw):
                res = orig_deliver(paths, spec, **kw)
                return dataclasses.replace(res, child={**(res.child or {}), "gid": "999-unknown"})

            with mock.patch.object(deliver, "deliver_ci_prerequisite", side_effect=mismatched_gid_deliver):
                mm_res = _run_qa_with_servers(root / "mismatch", DEMO_REPAIR_BUILDER_SCRIPT)
            self.assertEqual((mm_res.status, mm_res.ci_verified, mm_res.qa_verified), ("intake-contract-mismatch", False, False))

    def test_cli_error_formatting_and_module_exports(self) -> None:
        self.assertNotIn("_run_repair_attempt", qa_pkg.__all__)
        self.assertEqual(QADeliverySpec.__module__, "factory.automated_qa.delivery")
        self.assertEqual(QADeliveryResult.__module__, "factory.automated_qa.delivery")
        argv = ["--repo", "/tmp/repo", "--home", "/tmp/home", "--task", "900"]
        for exc, expected_msg in ((OSError("disk full"), "filesystem error: disk full"), (RuntimeError("boom"), "internal error: boom")):
            with (
                mock.patch("factory.automated_qa.__main__.resolve_paths", return_value=mock.sentinel.paths),
                mock.patch("factory.automated_qa.__main__.run_from_cli", side_effect=exc),
            ):
                err = io.StringIO()
                with mock.patch("sys.stderr", err):
                    code = qa_main.main(argv)
                self.assertEqual(code, 2)
                self.assertIn(expected_msg, err.getvalue())


if __name__ == "__main__":
    unittest.main()
