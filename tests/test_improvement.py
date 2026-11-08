"""Tests for bounded factory-improvement proposals and comparisons (#68)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from factory.errors import UsageError
from factory.improvement import (
    AUTHORITY_NOTE, create_proposal, evaluate_proposal, main as improvement_main,
    proposal_digest, validate_proposal, validate_report_for_review,
)
from factory.worker import RateCard


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _sample_fixtures(root: Path):
    obs_file = _write_file(root / "evidence" / "failure.txt", "ERROR: check timed out\n")
    cand_file = _write_file(root / "content" / "cand_check.py", "def check(): return 'improved'\n")
    imp_case = {
        "case_id": "IMP-01", "description": "Candidate succeeds where baseline fails",
        "command": "python3 -c \"import sys; from pathlib import Path; p = Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
        "rubric": {
            "rubric_id": "RUBRIC-IMP-01", "summary": "exits 0 on improved content",
            "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": [],
        },
    }
    reg_case = {
        "case_id": "REG-01", "description": "Regression invariant passes on both",
        "command": "python3 -c \"import sys; sys.exit(0)\"",
        "rubric": {
            "rubric_id": "RUBRIC-REG-01", "summary": "exits 0 always",
            "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": [],
        },
    }
    return obs_file, cand_file, imp_case, reg_case


class ImprovementWorkflowTest(unittest.TestCase):
    def test_actual_baseline_failure_and_candidate_improvement_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-01", failure_description="observed failure",
                failure_artifacts=[{"path": str(obs)}], kind="check", target_path="target.py",
                content_path=cand, baseline_identity="base-sha-1", candidate_identity="cand-sha-2",
                expected_improvement_description="Fix timeout", improvement_cases=[imp], regression_cases=[reg],
            )
            ev_dir = root / "evidence_dir"
            report = evaluate_proposal(proposal, ev_dir)
            self.assertEqual(report["eligibility"], "improvement-eligible")
            self.assertTrue(report["comparison"]["rule_satisfied"])
            self.assertTrue(report["comparison"]["baseline_demonstrated_failure"])
            self.assertTrue(report["comparison"]["candidate_demonstrated_success"])
            self.assertTrue(report["comparison"]["candidate_regressions_passed"])
            self.assertEqual(report["authority_note"], AUTHORITY_NOTE)
            self.assertEqual(validate_report_for_review(report, proposal_json=json.dumps(proposal, indent=2, sort_keys=True) + "\n"), [])

    def test_candidate_improvement_rejected_by_regression_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, _ = _sample_fixtures(root)
            failing_reg = {
                "case_id": "REG-FAIL", "description": "Regression fails on candidate",
                "command": "python3 -c \"import sys, pathlib; sys.exit(1 if pathlib.Path('target.py').exists() else 0)\"",
                "rubric": {"rubric_id": "R-REG", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-reg-fail", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[imp], regression_cases=[failing_reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            self.assertEqual(report["eligibility"], "ineligible")
            self.assertFalse(report["comparison"]["candidate_regressions_passed"])
            self.assertTrue(any("candidate failed required regression" in r for r in report["eligibility_reasons"]))

    def test_both_sides_passing_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, _, reg = _sample_fixtures(root)
            passing_imp = {
                "case_id": "IMP-TRIVIAL", "description": "Passes on both", "command": "python3 -c \"import sys; sys.exit(0)\"",
                "rubric": {"rubric_id": "R-TRIVIAL", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-both-pass", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[passing_imp], regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            self.assertEqual(report["eligibility"], "ineligible")
            self.assertFalse(report["comparison"]["baseline_demonstrated_failure"])
            self.assertTrue(any("no behavioral improvement demonstrated" in r for r in report["eligibility_reasons"]))

    def test_baseline_launch_failure_is_not_behavioral_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, _, reg = _sample_fixtures(root)
            launch_fail_imp = {
                "case_id": "IMP-LAUNCH", "description": "Launch failure",
                "command": "python3 -c \"import sys, pathlib; (sys.exit(0) if pathlib.Path('target.py').exists() else sys.exit(124))\"",
                "rubric": {"rubric_id": "R-LAUNCH", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-launch", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[launch_fail_imp], regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            self.assertEqual(report["eligibility"], "ineligible")

    def test_proposal_validation_rejects_missing_cases_or_bad_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            with self.assertRaises(UsageError):
                create_proposal(
                    proposal_id="bad", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                    kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                    candidate_identity="c1", expected_improvement_description="exp",
                    improvement_cases=[imp], regression_cases=[],
                )
            dup_imp = [imp, dict(imp)]
            with self.assertRaises(UsageError):
                create_proposal(
                    proposal_id="bad2", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                    kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                    candidate_identity="c1", expected_improvement_description="exp",
                    improvement_cases=dup_imp, regression_cases=[reg],
                )

    def test_incomplete_or_tampered_proposal_and_content_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-tamper", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[imp], regression_cases=[reg],
            )
            cand.write_text("tampered content", encoding="utf-8")
            with self.assertRaises(UsageError):
                evaluate_proposal(proposal, root / "ev")

    def test_unavailable_measurements_remain_unavailable_and_not_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-meas", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[imp], regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            b_cost = report["measurements"]["baseline"]["cost"]
            b_usage = report["measurements"]["baseline"]["usage"]
            self.assertEqual(b_cost["state"], "unavailable")
            self.assertIsNone(b_cost["usd"])
            self.assertEqual(b_usage["state"], "unavailable")
            self.assertIsNone(b_usage["input_tokens"])

    def test_append_only_attempts_and_interrupted_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-append", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[imp], regression_cases=[reg],
            )
            ev_dir = root / "evidence_dir"
            interrupted_imp = {
                "case_id": "IMP-01", "description": "Crash", "command": "python3 -c \"import sys; sys.exit(0)\"",
                "rubric": {"rubric_id": "R1", "summary": "s", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            prop_crash = dict(proposal)
            attempts_dir = ev_dir / "attempts"
            attempts_dir.mkdir(parents=True, exist_ok=True)
            attempt_1 = attempts_dir / "attempt-1"
            attempt_1.mkdir()
            manifest_1 = attempt_1 / "attempt-manifest.json"
            manifest_1.write_text(json.dumps({"attempt_number": 1, "status": "interrupted", "eligibility": "ineligible"}), encoding="utf-8")
            bytes_before = manifest_1.read_bytes()

            report = evaluate_proposal(proposal, ev_dir)
            self.assertEqual(report["eligibility"], "improvement-eligible")
            attempt_2 = attempts_dir / "attempt-2"
            self.assertTrue(attempt_2.is_dir())
            self.assertTrue((attempt_2 / "report.json").is_file())
            self.assertEqual(manifest_1.read_bytes(), bytes_before)

    def test_cli_invocation_seam(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            cases_file = _write_file(root / "cases.json", json.dumps({"improvement_cases": [imp], "regression_cases": [reg]}))
            prop_out = root / "out_proposal.json"
            code = improvement_main([
                "create-proposal", "--out", str(prop_out), "--proposal-id", "prop-cli",
                "--failure-desc", "cli failure", "--failure-artifact", str(obs),
                "--kind", "check", "--target-path", "target.py", "--content-file", str(cand),
                "--baseline-identity", "base-cli", "--candidate-identity", "cand-cli",
                "--expected-improvement", "fix cli", "--cases-file", str(cases_file),
            ])
            self.assertEqual(code, 0)
            self.assertTrue(prop_out.is_file())

            ev_dir = root / "cli_evidence"
            eval_code = improvement_main(["evaluate", "--proposal", str(prop_out), "--evidence-dir", str(ev_dir), "--json"])
            self.assertEqual(eval_code, 0)
            self.assertTrue((ev_dir / "attempts" / "attempt-1" / "report.json").is_file())

    def test_shared_policy_and_delivery_state_remain_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "synthetic_repo"
            repo.mkdir()
            (repo / "AGENTS.md").write_text("# Agents Rule\n", encoding="utf-8")
            (repo / "guards").mkdir()
            (repo / "guards" / "allowlist.txt").write_text("allow-all\n", encoding="utf-8")
            before_snapshot = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()}

            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-shared", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp", improvement_cases=[imp], regression_cases=[reg],
            )
            ev_dir = root / "ev"
            report = evaluate_proposal(proposal, ev_dir, repo=repo)
            self.assertEqual(report["eligibility"], "improvement-eligible")

            after_snapshot = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()}
            self.assertEqual(before_snapshot, after_snapshot)



if __name__ == "__main__":
    unittest.main()
