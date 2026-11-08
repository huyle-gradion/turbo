"""Tests for factory-policy promotion gate and exact-version selection (#69, Part B of #32)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from factory.errors import UsageError
from factory.improvement import create_proposal, evaluate_proposal
from factory.promotion import (
    REVIEW_PACKET_AUTHORITY_NOTE,
    REVIEW_PACKET_SCHEMA_VERSION,
    build_review_packet,
    resolve_approved_version,
    validate_storage_path,
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
        "rubric": {"rubric_id": "RUBRIC-IMP-01", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
    }
    reg_case = {
        "case_id": "REG-01",
        "description": "Regression invariant passes on both",
        "command": "python3 -c \"import sys; sys.exit(0)\"",
        "rubric": {"rubric_id": "RUBRIC-REG-01", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
    }
    return obs_file, cand_file, imp_case, reg_case


def _proof(base_sha: str, merge_sha: str, pr_num: int = 42, **extra: Any) -> dict[str, Any]:
    pr_data = {
        "number": pr_num, "state": "closed", "merged": True,
        "base": {"ref": "main", "sha": base_sha}, "merge_commit_sha": merge_sha,
        "merged_by": {"login": "huyle-gradion"},
    }
    pr_data.update(extra)
    return {"provider": "github", "repo_slug": "huyle-gradion/turbo", "pr_number": pr_num, "pr_data": pr_data}


class PolicyPromotionGroup1Test(unittest.TestCase):
    """AC group 1: review packet generation without submission or promotion side effects."""

    def test_complete_eligible_packet_with_provenance_and_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-pkt-01", failure_description="observed timeout failure",
                failure_artifacts=[{"path": str(obs)}], kind="check", target_path="target.py",
                content_path=cand, baseline_identity="base-rev-100", candidate_identity="cand-rev-200",
                expected_improvement_description="Eliminates timeout", improvement_cases=[imp], regression_cases=[reg],
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

            self.assertEqual(packet["proposed_change"]["kind"], "check")
            self.assertEqual(packet["proposed_change"]["target_path"], "target.py")
            self.assertEqual(packet["proposed_change"]["content_sha256"], report["candidate_content_digest"])

            self.assertEqual(packet["observed_failure"]["description"], "observed timeout failure")
            self.assertTrue(len(packet["observed_failure"]["artifacts"]) > 0)
            self.assertEqual(packet["expected_improvement"]["description"], "Eliminates timeout")
            self.assertEqual(packet["baseline"]["identity"], "base-rev-100")
            self.assertEqual(packet["candidate"]["identity"], "cand-rev-200")

            self.assertTrue(packet["comparison"]["rule_satisfied"])
            self.assertTrue(packet["comparison"]["baseline_demonstrated_failure"])
            self.assertTrue(packet["comparison"]["candidate_demonstrated_success"])
            self.assertTrue(packet["comparison"]["candidate_regressions_passed"])
            self.assertEqual(len(packet["candidate_results"]["improvement_cases"]), 1)
            self.assertEqual(len(packet["candidate_results"]["regression_cases"]), 1)

            for side in ("baseline", "candidate"):
                m = packet["measurements"][side]
                self.assertIn("usage", m)
                self.assertIn("cost", m)
                self.assertIn("provenance", m["usage"])
                self.assertIn("provenance", m["cost"])

            instructions = packet["submission_instructions"]
            self.assertIn("issue", instructions.lower())
            self.assertIn("pull request", instructions.lower())
            self.assertIn("main", instructions)
            self.assertIn("gh-review", instructions)
            self.assertIn("Eliminates timeout", packet["markdown_body"])

    def test_ineligible_or_regression_failing_report_rejected_by_packet_builder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, _ = _sample_fixtures(root)
            failing_reg = {
                "case_id": "REG-FAIL", "description": "Fails", "command": "python3 -c \"import sys; sys.exit(1)\"",
                "rubric": {"rubric_id": "R-FAIL", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-ineligible", failure_description="fail", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[failing_reg],
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
                proposal_id="prop-tamper", failure_description="fail", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            report["comparison"]["rule_satisfied"] = False
            with self.assertRaises(UsageError):
                build_review_packet(report)

    def test_cli_build_review_packet_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            proposal = create_proposal(
                proposal_id="prop-cli-pkt", failure_description="failure", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            report = evaluate_proposal(proposal, root / "ev")
            report_p = root / "report.json"
            report_p.write_text(json.dumps(report, indent=2), encoding="utf-8")
            pkt_out = root / "packet.json"
            from factory.improvement import main as imp_main
            self.assertEqual(imp_main(["build-review-packet", "--report", str(report_p), "--out", str(pkt_out)]), 0)
            self.assertTrue(pkt_out.is_file())
            data = json.loads(pkt_out.read_text(encoding="utf-8"))
            self.assertEqual(data["proposal_id"], "prop-cli-pkt")
            self.assertEqual(data["schema_version"], REVIEW_PACKET_SCHEMA_VERSION)


class PolicyPromotionGroup2Test(unittest.TestCase):
    """AC group 2: authoritative exact-version selection, storage contracts, and refusal behavior."""

    def _init_git_repo(self, root: Path, cand_bytes: bytes, rel_path: str = "factory/checks/custom.py") -> tuple[Path, str, str]:
        repo_dir = root / "git_repo"
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main", "-q"], cwd=repo_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Maintainer"], cwd=repo_dir, check=True)
        subprocess.run(["git", "config", "user.email", "maintainer@example.com"], cwd=repo_dir, check=True)

        (repo_dir / "README.md").write_text("# Project\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo_dir, check=True)
        base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()

        subprocess.run(["git", "checkout", "-q", "-b", "feat/imp-42"], cwd=repo_dir, check=True)
        cand_dest = repo_dir / rel_path
        cand_dest.parent.mkdir(parents=True, exist_ok=True)
        cand_dest.write_bytes(cand_bytes)
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "feat: candidate check"], cwd=repo_dir, check=True)

        subprocess.run(["git", "checkout", "-q", "main"], cwd=repo_dir, check=True)
        subprocess.run(["git", "merge", "-q", "--no-ff", "feat/imp-42", "-m", "Merge pull request #42 from feat/imp-42"], cwd=repo_dir, check=True)
        merge_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()
        subprocess.run(["git", "checkout", "-q", base_sha], cwd=repo_dir, check=True)
        return repo_dir, base_sha, merge_sha

    def _eval_eligible(self, root: Path, repo_dir: Path, cand: Path, base_sha: str, rel_path: str = "target.py"):
        obs = _write_file(root / "evidence" / "failure.txt", "ERROR: check timed out\n")
        imp_case = {
            "case_id": "IMP-01", "description": "Candidate succeeds",
            "command": f"python3 -c \"import sys; from pathlib import Path; p = Path('{rel_path}'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
            "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
        }
        reg_case = {
            "case_id": "REG-01", "description": "Regression", "command": "python3 -c \"import sys; sys.exit(0)\"",
            "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
        }
        proposal = create_proposal(
            proposal_id="prop-test", failure_description="fail", failure_artifacts=[{"path": str(obs)}],
            kind="check", target_path=rel_path, content_path=cand, baseline_identity=base_sha,
            candidate_identity="cand-1", expected_improvement_description="fix",
            improvement_cases=[imp_case], regression_cases=[reg_case],
        )
        report = evaluate_proposal(proposal, root / "ev", repo=repo_dir)
        return proposal, report

    def test_successful_approved_version_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            cand_bytes = cand.read_bytes()
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand_bytes, rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha, rel_path="target.py")
            self.assertEqual(report["eligibility"], "improvement-eligible")

            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertTrue(res.verified)
            self.assertEqual(res.status, "resolved")
            self.assertEqual(res.selected_version, merge_sha)
            self.assertEqual(res.content_bytes, cand_bytes)
            self.assertEqual(res.content_sha256, report["candidate_content_digest"])
            self.assertEqual(res.provenance["pr_number"], 42)
            self.assertEqual(res.provenance["merge_commit_sha"], merge_sha)

    def test_unapproved_proposals_cannot_be_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, _ = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof={})
            self.assertFalse(res.verified)
            self.assertEqual(res.status, "untrusted-approval-source")
            self.assertIsNone(res.content_bytes)

    def test_candidate_local_approval_flags_and_delivery_approval_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, _ = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            fake_proof = {"approved": True, "delivery_approved": True, "status": "approved"}
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=fake_proof)
            self.assertFalse(res.verified)
            self.assertEqual(res.status, "untrusted-approval-source")
            self.assertIsNone(res.content_bytes)

    def test_unmerged_or_caller_controlled_sources_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)

            open_proof = {"provider": "github", "repo_slug": "huyle-gradion/turbo", "pr_number": 99, "pr_data": {"state": "open", "merged": False, "base": {"ref": "main"}}}
            self.assertEqual(resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=open_proof).status, "unmerged-revision")

            feat_proof = {"provider": "github", "repo_slug": "huyle-gradion/turbo", "pr_number": 100, "pr_data": {"state": "closed", "merged": True, "base": {"ref": "feature/other"}, "merge_commit_sha": merge_sha}}
            self.assertEqual(resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=feat_proof).status, "unintended-target")

    def test_changed_proposal_content_invalidates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            mutated = json.loads(json.dumps(proposal))
            mutated["expected_improvement"]["description"] = "altered"
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=mutated, approval_proof=_proof(base_sha, merge_sha))
            self.assertFalse(res.verified)
            self.assertEqual(res.status, "binding-mismatch")

    def test_changed_candidate_content_invalidates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, b"different bytes\n", rel_path="target.py")
            proposal, report = self._eval_eligible(root, None, cand, base_sha)
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertFalse(res.verified)
            self.assertEqual(res.status, "mismatched-approved-content")

    def test_changed_evaluation_evidence_invalidates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            report["baseline_results"]["improvement_cases"][0]["rubric_passed"] = True
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertFalse(res.verified)
            self.assertIn(res.status, ("binding-mismatch", "ineligible-proposal"))

    def test_regression_failing_or_ineligible_proposals_rejected_despite_approval_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            obs = _write_file(root / "evidence" / "failure.txt", "ERROR\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            failing_reg = {
                "case_id": "REG-FAIL", "description": "Fails", "command": "python3 -c \"import sys; sys.exit(1)\"",
                "rubric": {"rubric_id": "R-FAIL", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            imp_case = {
                "case_id": "IMP-01", "description": "Imp",
                "command": "python3 -c \"import sys, pathlib; p = pathlib.Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
                "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            proposal = create_proposal(
                proposal_id="prop-reg-fail", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity=base_sha,
                candidate_identity="c1", expected_improvement_description="fix",
                improvement_cases=[imp_case], regression_cases=[failing_reg],
            )
            report = evaluate_proposal(proposal, root / "ev", repo=repo_dir)
            self.assertEqual(report["eligibility"], "ineligible")
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertFalse(res.verified)
            self.assertEqual(res.status, "ineligible-proposal")

    def test_selection_returns_precisely_approved_version_not_newer_local_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            approved_bytes = cand.read_bytes()
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, approved_bytes, rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            (repo_dir / "target.py").write_text("mutated local dirty code\n")
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertTrue(res.verified)
            self.assertEqual(res.content_bytes, approved_bytes)
            self.assertNotEqual(res.content_bytes, b"mutated local dirty code\n")

    def test_storage_contract_excludes_context_instructions_observations(self) -> None:
        for ok_path, kind in [
            ("factory/checks/custom.py", "check"),
            ("skills/new-skill/SKILL.md", "skill"),
            ("factory/lessons/lesson-01.md", "lesson"),
        ]:
            ok, _ = validate_storage_path(ok_path, kind)
            self.assertTrue(ok)

        for bad_path, kind in [
            ("pilot/issue-packet.md", "lesson"),
            ("examples/sample.json", "tool"),
            ("tests/test_foo.py", "check"),
            ("evidence/attempt-1/rep.json", "check"),
            ("attempts/manifest.json", "lesson"),
            ("homes/env.txt", "tool"),
            ("context/spec.md", "lesson"),
        ]:
            ok, err = validate_storage_path(bad_path, kind)
            self.assertFalse(ok, f"Expected {bad_path} to be rejected")
            self.assertIn("excluded", err.lower())

    def test_no_delivery_activation_occurs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand.read_bytes(), rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            res = resolve_approved_version(repo=repo_dir, report=report, proposal=proposal, approval_proof=_proof(base_sha, merge_sha))
            self.assertTrue(res.verified)
            self.assertFalse((repo_dir / "factory.json").exists())
            self.assertFalse((repo_dir / "delivery-config.json").exists())

    def test_cli_resolve_approved_version_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            cand_bytes = cand.read_bytes()
            repo_dir, base_sha, merge_sha = self._init_git_repo(root, cand_bytes, rel_path="target.py")
            proposal, report = self._eval_eligible(root, repo_dir, cand, base_sha)
            report_p = root / "report.json"
            report_p.write_text(json.dumps(report, indent=2), encoding="utf-8")
            proof_p = root / "proof.json"
            proof_p.write_text(json.dumps(_proof(base_sha, merge_sha), indent=2), encoding="utf-8")
            out_bytes_p = root / "selected.py"

            from factory.improvement import main as imp_main
            rc = imp_main(["resolve-approved", "--repo", str(repo_dir), "--report", str(report_p), "--proof", str(proof_p), "--out", str(out_bytes_p)])
            self.assertEqual(rc, 0)
            self.assertTrue(out_bytes_p.is_file())
            self.assertEqual(out_bytes_p.read_bytes(), cand_bytes)


if __name__ == "__main__":
    unittest.main()
