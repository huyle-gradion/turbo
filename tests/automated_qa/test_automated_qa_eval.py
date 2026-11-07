"""Tests for automated QA criterion evaluation, rubrics, regression checks, and finding reconciliation (#21)."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from factory import ci_selection, config as config_module, worker as worker_module
from factory.automated_qa import (
    QAEvaluationCase, QARubric, evaluate_child_qa, load_qa_cases_file, reconcile_findings,
)
from factory.errors import UsageError
from support import git
from test_deliver import (
    GOOD_BUILDER_SCRIPT, PARENT_TASK, READY_CHILD,
    _make_disposable_product_workspace, _make_fake_agy, _run_deliver,
)
from test_deliver_checks import _DisposableGitHubServer
from test_intake import _DisposableAsanaServer


def _case(
    case_id: str, cid: str = "AC-1", cmd: str = "python3 -c \"import sys; sys.exit(0)\"",
    *, exit_code: int = 0, checks: tuple[str, ...] = ("exits 0",), tokens: tuple[str, ...] = (),
    correction: str = "", rubric_id: str = "R-1", summary: str = "Must exit as expected",
) -> QAEvaluationCase:
    return QAEvaluationCase(
        case_id=case_id, criterion_id=cid, description=f"Case {case_id}", command=cmd,
        rubric=QARubric(
            rubric_id=rubric_id, summary=summary, required_checks=checks,
            expected_exit_code=exit_code, required_output_tokens=tokens, requested_correction=correction,
        ),
    )


WHITESPACE_QA_CASE = _case(
    "QA-AC-1-WHITESPACE", "AC-1",
    "python3 -c \"import sys; sys.path.insert(0, 'src'); from chat_bridge.auth import validate_token; validate_token('  expired:abc  ')\"",
    exit_code=1, checks=("raises TokenExpiredError on whitespace-padded expired token",), tokens=("TokenExpiredError",),
    rubric_id="RUBRIC-AC-1-WHITESPACE", summary="validate_token strips whitespace before checking expired prefix and raises TokenExpiredError",
    correction="Normalize token with token.strip() in src/chat_bridge/auth.py before checking the 'expired:' prefix, and add a regression test in tests/test_auth.py.",
)


@contextlib.contextmanager
def _delivered_child_fixture(root: Path):
    repo, home, bare = _make_disposable_product_workspace(root)
    good_wrapper = _make_fake_agy(root, "fake-good-qa", GOOD_BUILDER_SCRIPT)
    with (
        _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
        _DisposableGitHubServer(bare_repo=bare) as gh,
    ):
        res, deliver_payload = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(good_wrapper))
        assert (res.returncode, deliver_payload["status"]) == (0, "verified")
        conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
        attempt_dir = Path(deliver_payload["evidence"]["attempt_dir"])
        child_dir = attempt_dir / "children" / "101"
        intake_rec = json.loads((attempt_dir / "intake-record.json").read_text(encoding="utf-8"))
        parent_contract, child_contract, child_rec = intake_rec["parent"], intake_rec["children"][0], deliver_payload["child"]

        def run_qa(**overrides):
            kwargs = {
                "repo": repo, "home": home, "child_dir": child_dir, "base_url": gh.base_url,
                "token": "disposable-gh-token", "repo_slug": "example/chat-bridge",
                "parent": parent_contract, "child": child_contract, "child_record": child_rec,
                "conf": conf, "qa_cases": (), "round_number": 1, "deadline": time.monotonic() + 30.0, "limit_s": 30,
            }
            kwargs.update(overrides)
            return evaluate_child_qa(**kwargs)

        yield repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa


class AutomatedQAEvalTest(unittest.TestCase):
    def test_clean_qa_symbolic_revision_and_parent_human_acceptance_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _delivered_child_fixture(Path(tmp)) as (
            repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
        ):
            qa_case = _case(
                "QA-AC-1-EXPIRED", "AC-1", "python3 -m unittest discover -s tests -p test_auth.py -v",
                checks=("exit_code == 0", "test_expired_token passes"), tokens=("OK",), rubric_id="RUBRIC-AC-1",
            )
            qa_round = run_qa(qa_cases=(qa_case,))
            self.assertEqual((qa_round["role"], qa_round["status"], qa_round["qa_verified"]), ("automated-qa", "qa-verified", True))
            self.assertTrue(qa_round["role_separation"]["worktree_clean"])
            self.assertFalse(qa_round["role_separation"]["candidate_modified_by_qa"])
            self.assertEqual(qa_round["findings"], [])
            self.assertTrue(Path(qa_round["ci_revalidation"]["github_requests_path"]).is_file())

            with mock.patch("factory.ci_gate.revalidate_child_verification", return_value={"verified": True, "status": "verified"}):
                sym_round = run_qa(child_record={**child_rec, "candidate_sha": child_rec["head_branch"]}, qa_cases=(qa_case,), round_number=2)
            self.assertEqual((sym_round["status"], sym_round["qa_verified"]), ("qa-verified", True))
            self.assertFalse(sym_round["role_separation"]["candidate_modified_by_qa"])
            self.assertEqual(sym_round["role_separation"]["head_before"], child_rec["candidate_sha"])

            boundary = qa_round["parent_acceptance_boundary"]
            self.assertEqual((boundary["parent_accepted"], boundary["parent_acceptance_status"]), (False, "pending-human-acceptance"))
            human_crit = [c for c in boundary["parent_criteria"] if c["id"] == "P-AC-2"][0]
            self.assertEqual(
                (human_crit["classification"], human_crit["evaluated_by_automated_qa"], human_crit["status"]),
                ("human-judgment", False, "pending-human-acceptance"),
            )
            with self.assertRaises(UsageError):
                run_qa(qa_cases=(qa_case,), approve_parent_acceptance=True)

    def test_seeded_finding_identity_missing_verification_and_stale_evidence_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _delivered_child_fixture(Path(tmp)) as (
            repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
        ):
            round1 = run_qa(qa_cases=(WHITESPACE_QA_CASE,), round_number=1)
            self.assertEqual((round1["status"], round1["qa_verified"], len(round1["findings"])), ("qa-failed", False, 1))
            f1, expected_fid = round1["findings"][0], "QA-101-AC-1-QA-AC-1-WHITESPACE"
            self.assertEqual(
                (f1["finding_id"], f1["criterion_id"], f1["status"], f1["created_round"], f1["created_candidate_sha"]),
                (expected_fid, "AC-1", "open", 1, child_rec["candidate_sha"]),
            )
            self.assertIn("token.strip()", f1["requested_correction"])
            self.assertTrue(Path(f1["failing_evidence"]["output_path"]).is_file())

            round2_missing = run_qa(qa_cases=(), prior_findings=round1["findings"], round_number=2)
            f2_missing = round2_missing["findings"][0]
            self.assertEqual(
                (round2_missing["status"], f2_missing["finding_id"], f2_missing["status"], f2_missing["resolution_blocker"], len(f2_missing["history"])),
                ("qa-failed", expected_fid, "open", "missing-verification", 2),
            )

            git(repo, "push", "-q", "origin", f"{child_rec['candidate_sha']}:refs/heads/feature/chat-auth")
            round_stale = run_qa(qa_cases=(), prior_findings=round1["findings"], round_number=3)
            self.assertEqual(
                (round_stale["status"], round_stale["qa_verified"], round_stale["findings"][0]["resolution_blocker"]),
                ("stale-revision", False, "stale-evidence"),
            )

    def test_finding_identity_collisions_and_reserved_deterministic_id_preserve_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _delivered_child_fixture(Path(tmp)) as (
            repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
        ):
            dot_fail = _case("auth.expired", "AC-1", "python3 -c \"import sys; sys.exit(1)\"")
            slash_pass = _case("auth/expired", "AC-1", "python3 -c \"import sys; sys.exit(0)\"")
            r_punct = run_qa(qa_cases=(dot_fail, slash_pass), round_number=1)
            self.assertEqual((r_punct["status"], r_punct["qa_verified"]), ("qa-failed", False))
            self.assertTrue(len(r_punct["open_finding_ids"]) >= 1)

            two_crit_child = {
                **child_contract,
                "criteria": [{**child_contract["criteria"][0], "id": "AC"}, {**child_contract["criteria"][0], "id": "AC-1"}],
            }
            c_shift_fail = _case("1-FOO", "AC", "python3 -c \"import sys; sys.exit(1)\"")
            c_shift_pass = _case("FOO", "AC-1", "python3 -c \"import sys; sys.exit(0)\"")
            r_shift = run_qa(child=two_crit_child, qa_cases=(c_shift_fail, c_shift_pass), round_number=2)
            self.assertEqual((r_shift["status"], r_shift["qa_verified"]), ("qa-failed", False))
            self.assertTrue(len(r_shift["open_finding_ids"]) >= 1)

            failing_det_child = {
                **child_contract,
                "criteria": [{**child_contract["criteria"][0], "id": "AC-1", "verification": "python3 -c \"import sys; sys.exit(1)\""}],
            }
            user_det_pass = _case("DETERMINISTIC", "AC-1", "python3 -c \"import sys; sys.exit(0)\"")
            r_det = run_qa(child=failing_det_child, qa_cases=(user_det_pass,), round_number=3)
            self.assertEqual((r_det["status"], r_det["qa_verified"]), ("qa-failed", False))
            self.assertIn("QA-101-AC-1-DETERMINISTIC", r_det["open_finding_ids"])

            r_norm_det = run_qa(qa_cases=(dataclasses.replace(user_det_pass, case_id="det-erministic"),), round_number=4)
            self.assertEqual((r_norm_det["status"], r_norm_det["qa_verified"]), ("qa-failed", False))
            self.assertTrue(len(r_norm_det["open_finding_ids"]) >= 1)

    def test_invalid_rubric_guidance_unknown_criteria_grouping_and_empty_criteria(self) -> None:
        for bad_rub in (
            {"expected_exit_code": True},
            {"expected_exit_code": "zero"},
            {"required_checks": "bare-string"},
            {"required_output_tokens": "bare-token"},
            {"forbidden_output_tokens": 123},
        ):
            with self.subTest(bad_rub=bad_rub), self.assertRaises(UsageError):
                QARubric.from_dict(bad_rub)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_cases_file = root / "bad-cases.json"
            bad_cases_file.write_text(json.dumps({"cases": ["not-a-dict"]}), encoding="utf-8")
            with self.assertRaises(UsageError):
                load_qa_cases_file(bad_cases_file)

            with _delivered_child_fixture(root) as (
                repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
            ):
                empty_crit_round = run_qa(child={**child_contract, "criteria": []}, round_number=1)
                self.assertEqual((empty_crit_round["status"], empty_crit_round["qa_verified"]), ("qa-failed", False))
                self.assertTrue(any(f["classification"] == "verification-gap" for f in empty_crit_round["findings"]))

                vague_with_guidance = _case(
                    "QA-AC-1-VAGUE", "AC-1", "python3 -m unittest discover -s tests -p test_auth.py -v",
                    checks=(), rubric_id="looks good", summary="lgtm",
                    correction="Replace vague rubric with concrete exit code and token assertions.",
                )
                r_vague = run_qa(qa_cases=(vague_with_guidance,), round_number=2)
                self.assertEqual((r_vague["status"], r_vague["qa_verified"]), ("qa-failed", False))
                self.assertEqual(
                    r_vague["findings"][0]["requested_correction"],
                    "Replace vague rubric with concrete exit code and token assertions.",
                )

                u1 = dataclasses.replace(
                    WHITESPACE_QA_CASE, case_id="QA-UNKNOWN-1", criterion_id="AC-999",
                    rubric=dataclasses.replace(WHITESPACE_QA_CASE.rubric, requested_correction="Fix unknown case 1 mapping."),
                )
                u2 = dataclasses.replace(
                    WHITESPACE_QA_CASE, case_id="QA-UNKNOWN-2", criterion_id="AC-999",
                    rubric=dataclasses.replace(WHITESPACE_QA_CASE.rubric, requested_correction="Fix unknown case 2 mapping."),
                )
                unmatched_round = run_qa(qa_cases=(u1, u2), round_number=3)
                self.assertEqual((unmatched_round["status"], unmatched_round["qa_verified"]), ("qa-failed", False))
                unknown_covs = [c for c in unmatched_round["criterion_coverage"] if c["criterion_id"] == "AC-999"]
                self.assertEqual(len(unknown_covs), 1)
                self.assertIsNone(unknown_covs[0]["deterministic_check"])
                self.assertEqual([e["case_id"] for e in unknown_covs[0]["evaluation_cases"]], ["QA-UNKNOWN-1", "QA-UNKNOWN-2"])
                f_by_case = {f["case_id"]: f for f in unmatched_round["findings"]}
                self.assertNotIn("DETERMINISTIC", f_by_case)
                self.assertEqual(f_by_case["QA-UNKNOWN-1"]["requested_correction"], "Fix unknown case 1 mapping.")
                self.assertEqual(f_by_case["QA-UNKNOWN-2"]["requested_correction"], "Fix unknown case 2 mapping.")

    def test_missing_or_unexecutable_verifier_and_timeout_propagation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _delivered_child_fixture(Path(tmp)) as (
            repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
        ):
            missing_bin_child = {
                **child_contract, "criteria": [{**child_contract["criteria"][0], "verification": "/nonexistent/bin/pytest -q"}],
            }
            r_missing_bin = run_qa(child=missing_bin_child, round_number=1)
            det_m = r_missing_bin["criterion_coverage"][0]["deterministic_check"]
            self.assertEqual((det_m["executed"], det_m["passed"], det_m["exit_code"]), (False, False, None))
            self.assertTrue(Path(det_m["output_path"]).is_file())
            self.assertEqual(r_missing_bin["findings"][0]["resolution_blocker"], "missing-verification")

            noexec_pytest = Path(tmp) / "pytest"
            noexec_pytest.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            noexec_pytest.chmod(0o644)
            perm_child = {
                **child_contract, "criteria": [{**child_contract["criteria"][0], "verification": f"{noexec_pytest} -q"}],
            }
            r_perm = run_qa(child=perm_child, round_number=2)
            det_p = r_perm["criterion_coverage"][0]["deterministic_check"]
            self.assertEqual((det_p["executed"], det_p["passed"], det_p["exit_code"]), (False, False, None))
            self.assertTrue(Path(det_p["output_path"]).is_file())
            self.assertEqual(r_perm["findings"][0]["resolution_blocker"], "missing-verification")

            orig_exec = worker_module.execute_stream

            def timeout_on_selected_reg(cwd, argv, env, timeout_s, *, isolated_home=None, allow_network=True):
                if "discover" in argv and "-q" in argv:
                    return (124, "", "[factory] worker timed out after 1s\n", 1000, True)
                return orig_exec(cwd, argv, env, timeout_s, isolated_home=isolated_home, allow_network=allow_network)

            with mock.patch.object(worker_module, "execute_stream", side_effect=timeout_on_selected_reg):
                r_timeout = run_qa(round_number=3)
            self.assertEqual((r_timeout["status"], r_timeout["qa_verified"]), ("timed-out", False))
            self.assertTrue(any(c.get("timed_out") for c in r_timeout["regression_checks"]))

    def test_finding_resolution_metadata_preservation_reopening_and_transitions(self) -> None:
        child = {"gid": "101", "scope": {"in_scope": "src/chat_bridge/"}}
        det_ok = {
            "command": "python3 -m unittest", "argv": ["python3", "-m", "unittest"],
            "executed": True, "passed": True, "exit_code": 0, "output_path": "/tmp/det.txt", "output_sha256": "1" * 64,
        }

        def _make_cov(**case_fields):
            base_case = {
                "case_id": "CASE-1", "rubric_id": "R-1", "rubric": {"requested_correction": "Updated correction guidance"},
                "command": "python3 -c pass", "argv": ["python3", "-c", "pass"], "executed": True, "passed": True,
                "exit_code": 0, "status": "passed", "rubric_failures": [], "output_path": "/tmp/c.txt", "output_sha256": "2" * 64,
            }
            return [{"criterion_id": "AC-1", "description": "Reject expired tokens", "deterministic_check": det_ok, "evaluation_cases": [{**base_case, **case_fields}]}]

        cov_gap = _make_cov(executed=False, passed=False, status="invalid-rubric", rubric_issues=["vague rubric"], output_path=None, output_sha256=None)
        cov_fail = _make_cov(passed=False, exit_code=1, status="failed", rubric_failures=["expected exit_code 0, got 1"])
        cov_pass = _make_cov()

        def _rec(r_num: int, sha_ch: str, cov, prior=None):
            return reconcile_findings(
                child_gid="101", child=child, candidate_sha=sha_ch * 40, base_sha="0" * 40, tested_sha=sha_ch * 40,
                round_number=r_num, criterion_coverage=cov, regression_passed=True, ci_reval_ok=True, prior_findings=prior,
            )

        f_r1 = _rec(1, "a", cov_gap)
        self.assertEqual((f_r1[0]["classification"], f_r1[0]["resolution_blocker"]), ("verification-gap", "missing-verification"))

        f_r2 = _rec(2, "b", cov_fail, f_r1)
        self.assertEqual(
            (f_r2[0]["classification"], f_r2[0]["requested_correction"], f_r2[0]["resolution_blocker"]),
            ("behavioral-failure", "Updated correction guidance", "check-failed"),
        )

        f_r3 = _rec(3, "c", cov_pass, f_r2)
        self.assertEqual((f_r3[0]["status"], f_r3[0]["resolved_round"], f_r3[0]["resolved_candidate_sha"]), ("resolved", 3, "c" * 40))

        f_r4 = _rec(4, "d", cov_pass, f_r3)
        self.assertEqual(
            (f_r4[0]["status"], f_r4[0]["resolved_round"], f_r4[0]["resolved_candidate_sha"], f_r4[0]["latest_round"], f_r4[0]["latest_candidate_sha"]),
            ("resolved", 3, "c" * 40, 4, "d" * 40),
        )

        f_r5 = _rec(5, "e", cov_fail, f_r4)
        self.assertEqual(
            (f_r5[0]["status"], f_r5[0]["resolved_round"], f_r5[0]["resolved_candidate_sha"], f_r5[0]["created_round"], len(f_r5[0]["history"])),
            ("open", None, None, 1, 5),
        )
        self.assertEqual(f_r5[0]["history"][2]["status"], "resolved")

    def test_verification_isolated_home_and_regression_sibling_test_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_op_home = root / "operator-home"
            jetski_dir = fake_op_home / ".gemini" / "antigravity-cli"
            jetski_dir.mkdir(parents=True)
            (jetski_dir / "jetski_state.pbtxt").write_text("SECRET_JETSKI_TOKEN\n", encoding="utf-8")

            with _delivered_child_fixture(root) as (
                repo, home, gh, conf, child_dir, parent_contract, child_contract, child_rec, run_qa
            ):
                probe_case = _case(
                    "QA-CRED-PROBE", "AC-1",
                    "python3 -c \"import pathlib, sys; p = pathlib.Path.home() / '.gemini/antigravity-cli/jetski_state.pbtxt'; "
                    "print('LEAK: sentinel-asana-secret-999 sentinel-gh-secret-888'); sys.exit(99 if p.exists() else 1)\"",
                    checks=("isolated verify home",), rubric_id="RUBRIC-CRED",
                )
                with (
                    mock.patch.object(Path, "home", return_value=fake_op_home),
                    mock.patch.dict(os.environ, {"ASANA_ACCESS_TOKEN": "sentinel-asana-secret-999", "TURBO_GITHUB_TOKEN": "sentinel-gh-secret-888"}),
                ):
                    round_rec = run_qa(token="sentinel-gh-secret-888", qa_cases=(probe_case,), round_number=1)
                self.assertEqual(round_rec["criterion_coverage"][0]["evaluation_cases"][0]["exit_code"], 1)
                for file_path in (child_dir / "automated-qa").rglob("*"):
                    if file_path.is_file():
                        content = file_path.read_text(encoding="utf-8")
                        self.assertNotIn("sentinel-asana-secret-999", content)
                        self.assertNotIn("sentinel-gh-secret-888", content)

                conf_no_cmd_gates = dataclasses.replace(conf, gates={"3": conf.gates["3"]})
                with mock.patch.object(
                    ci_selection, "select_ci_test_plan", return_value={"mode": "affected-only", "affected_tests": [], "reason": "none"}
                ):
                    empty_reg = run_qa(conf=conf_no_cmd_gates, round_number=2)
                self.assertEqual((empty_reg["regression_passed"], empty_reg["qa_verified"], empty_reg["status"]), (False, False, "regression-failed"))

                git(repo, "checkout", "-q", child_rec["head_branch"])
                (repo / "tests" / "sibling_fixture.py").write_text("SIBLING_OK = True\n", encoding="utf-8")
                test_auth_p = repo / "tests" / "test_auth.py"
                test_auth_p.write_text(
                    "import sibling_fixture\n" + test_auth_p.read_text(encoding="utf-8")
                    + "\n    def test_sibling_imported(self) -> None:\n        self.assertTrue(sibling_fixture.SIBLING_OK)\n",
                    encoding="utf-8",
                )
                git(repo, "add", "tests/sibling_fixture.py", "tests/test_auth.py")
                git(repo, "commit", "-q", "-m", "test: import sibling fixture in test_auth")
                new_sha = git(repo, "rev-parse", "HEAD")
                git(repo, "checkout", "-q", "main")
                env_without_py_path = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
                with (
                    mock.patch.dict(os.environ, env_without_py_path, clear=True),
                    mock.patch("factory.ci_gate.revalidate_child_verification", return_value={"verified": True, "status": "verified"}),
                    mock.patch.object(
                        ci_selection, "select_ci_test_plan",
                        return_value={"mode": "affected-only", "affected_tests": ["tests.test_auth"], "reason": "mapped"},
                    ),
                ):
                    sib_round = run_qa(child_record={**child_rec, "candidate_sha": new_sha}, round_number=3)
                self.assertEqual((sib_round["regression_passed"], sib_round["qa_verified"], sib_round["status"]), (True, True, "qa-verified"))


if __name__ == "__main__":
    unittest.main()
