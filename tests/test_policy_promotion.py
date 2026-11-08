"""Tests for factory-policy promotion gate and exact-version selection (#69, Part B of #32)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from factory.errors import UsageError
from factory.improvement import create_proposal, evaluate_proposal
from factory.promotion import (
    REVIEW_PACKET_AUTHORITY_NOTE,
    REVIEW_PACKET_SCHEMA_VERSION,
    build_review_packet,
)


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _sample_fixtures(root: Path):
    obs_file = _write_file(root / "evidence" / "failure.txt", "ERROR: check timed out\n")
    cand_file = _write_file(root / "content" / "cand_check.py", "def check(): return 'improved'\n")
    imp_case = {
        "case_id": "IMP-01",
        "description": "Candidate succeeds where baseline fails",
        "command": "python3 -c \"import sys; from pathlib import Path; p = Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
        "rubric": {
            "rubric_id": "RUBRIC-IMP-01",
            "summary": "exits 0 on improved content",
            "expected_exit_code": 0,
            "required_output_tokens": [],
            "forbidden_output_tokens": [],
        },
    }
    reg_case = {
        "case_id": "REG-01",
        "description": "Regression invariant passes on both",
        "command": "python3 -c \"import sys; sys.exit(0)\"",
        "rubric": {
            "rubric_id": "RUBRIC-REG-01",
            "summary": "exits 0 always",
            "expected_exit_code": 0,
            "required_output_tokens": [],
            "forbidden_output_tokens": [],
        },
    }
    return obs_file, cand_file, imp_case, reg_case


class PolicyPromotionGroup1Test(unittest.TestCase):
    """AC group 1: review packet generation without submission or promotion side effects."""

    def test_complete_eligible_packet_with_provenance_and_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-pkt-01",
                failure_description="observed timeout failure",
                failure_artifacts=[{"path": str(obs)}],
                kind="check",
                target_path="target.py",
                content_path=cand,
                baseline_identity="base-rev-100",
                candidate_identity="cand-rev-200",
                expected_improvement_description="Eliminates timeout",
                improvement_cases=[imp],
                regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            self.assertEqual(report["eligibility"], "improvement-eligible")

            packet = build_review_packet(report)
            self.assertEqual(packet["schema_version"], REVIEW_PACKET_SCHEMA_VERSION)
            self.assertEqual(packet["authority_note"], REVIEW_PACKET_AUTHORITY_NOTE)
            self.assertIn("not approved", packet["authority_note"].lower())
            self.assertEqual(packet["proposal_id"], "prop-pkt-01")
            self.assertEqual(packet["proposal_digest"], report["proposal_digest"])
            self.assertEqual(packet["candidate_content_digest"], report["candidate_content_digest"])
            self.assertEqual(packet["factory_revision"], report["factory_revision"])

            # Proposed change & content identity
            self.assertEqual(packet["proposed_change"]["kind"], "check")
            self.assertEqual(packet["proposed_change"]["target_path"], "target.py")
            self.assertEqual(packet["proposed_change"]["content_sha256"], report["candidate_content_digest"])

            # Observed failure and evidence
            self.assertEqual(packet["observed_failure"]["description"], "observed timeout failure")
            self.assertTrue(len(packet["observed_failure"]["artifacts"]) > 0)

            # Expected improvement & identities
            self.assertEqual(packet["expected_improvement"]["description"], "Eliminates timeout")
            self.assertEqual(packet["baseline"]["identity"], "base-rev-100")
            self.assertEqual(packet["candidate"]["identity"], "cand-rev-200")

            # Complete comparison & regressions
            self.assertTrue(packet["comparison"]["rule_satisfied"])
            self.assertTrue(packet["comparison"]["baseline_demonstrated_failure"])
            self.assertTrue(packet["comparison"]["candidate_demonstrated_success"])
            self.assertTrue(packet["comparison"]["candidate_regressions_passed"])
            self.assertEqual(len(packet["candidate_results"]["improvement_cases"]), 1)
            self.assertEqual(len(packet["candidate_results"]["regression_cases"]), 1)

            # Measurement provenance
            self.assertIn("baseline", packet["measurements"])
            self.assertIn("candidate", packet["measurements"])
            for side in ("baseline", "candidate"):
                m = packet["measurements"][side]
                self.assertIn("usage", m)
                self.assertIn("cost", m)
                self.assertIn("provenance", m["usage"])
                self.assertIn("provenance", m["cost"])

            # Human submission instructions
            instructions = packet["submission_instructions"]
            self.assertIn("issue", instructions.lower())
            self.assertIn("pull request", instructions.lower())
            self.assertIn("main", instructions)
            self.assertIn("gh-review", instructions)

            # Ensure markdown body exists
            self.assertIn("markdown_body", packet)
            self.assertIn("Eliminates timeout", packet["markdown_body"])

    def test_ineligible_or_regression_failing_report_rejected_by_packet_builder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, _ = _sample_fixtures(root)
            failing_reg = {
                "case_id": "REG-FAIL",
                "description": "Fails regression",
                "command": "python3 -c \"import sys; sys.exit(1)\"",
                "rubric": {"rubric_id": "R-FAIL", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-ineligible",
                failure_description="fail",
                failure_artifacts=[{"path": str(obs)}],
                kind="check",
                target_path="target.py",
                content_path=cand,
                baseline_identity="b1",
                candidate_identity="c1",
                expected_improvement_description="exp",
                improvement_cases=[imp],
                regression_cases=[failing_reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            self.assertEqual(report["eligibility"], "ineligible")

            with self.assertRaises(UsageError) as cm:
                build_review_packet(report)
            self.assertIn("ineligible", str(cm.exception).lower())

    def test_tampered_report_results_rejected_despite_eligible_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-tamper",
                failure_description="fail",
                failure_artifacts=[{"path": str(obs)}],
                kind="check",
                target_path="target.py",
                content_path=cand,
                baseline_identity="b1",
                candidate_identity="c1",
                expected_improvement_description="exp",
                improvement_cases=[imp],
                regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            # Falsify report: claim improvement-eligible but mark comparison not satisfied
            report["comparison"]["rule_satisfied"] = False
            with self.assertRaises(UsageError):
                build_review_packet(report)

    def test_cli_build_review_packet_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-cli-pkt",
                failure_description="failure",
                failure_artifacts=[{"path": str(obs)}],
                kind="check",
                target_path="target.py",
                content_path=cand,
                baseline_identity="b1",
                candidate_identity="c1",
                expected_improvement_description="exp",
                improvement_cases=[imp],
                regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            report_p = root / "report.json"
            report_p.write_text(json.dumps(report, indent=2), encoding="utf-8")
            pkt_out = root / "packet.json"

            from factory.improvement import main as imp_main
            rc = imp_main(["build-review-packet", "--report", str(report_p), "--out", str(pkt_out)])
            self.assertEqual(rc, 0)
            self.assertTrue(pkt_out.is_file())
            data = json.loads(pkt_out.read_text(encoding="utf-8"))
            self.assertEqual(data["proposal_id"], "prop-cli-pkt")
            self.assertEqual(data["schema_version"], REVIEW_PACKET_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
