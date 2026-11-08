"""Tests for bounded factory-improvement proposals and comparisons (#68)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import unittest.mock

import factory.improvement
from factory.errors import UsageError
from factory.improvement import (
    AUTHORITY_NOTE, canonicalize_draft_references, create_proposal, evaluate_proposal,
    main as improvement_main, proposal_digest, validate_proposal, validate_proposal_structure,
    validate_report_for_review,
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

    def test_group1_rejects_normalized_directory_target_spellings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            for bad_target in (".", "./", ".//", "dir/.", "", "dir//target.py"):
                with self.subTest(target=bad_target):
                    with self.assertRaises(UsageError):
                        create_proposal(
                            proposal_id=f"prop-bad-tgt", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                            kind="check", target_path=bad_target, content_path=cand, baseline_identity="b1",
                            candidate_identity="c1", expected_improvement_description="exp",
                            improvement_cases=[imp], regression_cases=[reg],
                        )

    def test_group1_rejects_leaf_and_ancestor_symlinks_outside_worktree(self) -> None:
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)

            # 1. Tracked leaf symlink
            repo_leaf = root / "repo_leaf"
            repo_leaf.mkdir()
            leaf_sentinel = root / "leaf_sentinel.txt"
            leaf_sentinel.write_text("PRISTINE_LEAF", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo_leaf, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo_leaf, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo_leaf, check=True)
            (repo_leaf / "target.py").symlink_to(leaf_sentinel)
            subprocess.run(["git", "add", "target.py"], cwd=repo_leaf, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "leaf symlink"], cwd=repo_leaf, check=True)

            prop_leaf = create_proposal(
                proposal_id="prop-leaf", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            with self.assertRaises(UsageError):
                evaluate_proposal(prop_leaf, root / "ev_leaf", repo=repo_leaf)
            self.assertEqual(leaf_sentinel.read_text(encoding="utf-8"), "PRISTINE_LEAF")

            # 2. Tracked ancestor symlink
            repo_anc = root / "repo_anc"
            repo_anc.mkdir()
            anc_sentinel_dir = root / "anc_sentinel_dir"
            anc_sentinel_dir.mkdir()
            (anc_sentinel_dir / "target.py").write_text("PRISTINE_ANC", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo_anc, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo_anc, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo_anc, check=True)
            (repo_anc / "sub").symlink_to(anc_sentinel_dir)
            subprocess.run(["git", "add", "sub"], cwd=repo_anc, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "ancestor symlink"], cwd=repo_anc, check=True)

            prop_anc = create_proposal(
                proposal_id="prop-anc", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="sub/target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            with self.assertRaises(UsageError):
                evaluate_proposal(prop_anc, root / "ev_anc", repo=repo_anc)
            self.assertEqual((anc_sentinel_dir / "target.py").read_text(encoding="utf-8"), "PRISTINE_ANC")

    def test_group1_rejects_dangling_symlink_and_existing_directory_targets(self) -> None:
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)

            # Dangling symlink
            repo_dangle = root / "repo_dangle"
            repo_dangle.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo_dangle, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo_dangle, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo_dangle, check=True)
            (repo_dangle / "target.py").symlink_to(root / "nonexistent_target_file")
            subprocess.run(["git", "add", "target.py"], cwd=repo_dangle, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "dangling symlink"], cwd=repo_dangle, check=True)

            prop = create_proposal(
                proposal_id="prop-dangle", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            with self.assertRaises(UsageError):
                evaluate_proposal(prop, root / "ev_dangle", repo=repo_dangle)

            # Existing directory destination
            repo_dir = root / "repo_dir"
            repo_dir.mkdir()
            (repo_dir / "target.py").mkdir()
            (repo_dir / "target.py" / "keep.txt").write_text("keep", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo_dir, check=True)
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "target is dir"], cwd=repo_dir, check=True)
            with self.assertRaises(UsageError):
                evaluate_proposal(prop, root / "ev_dir", repo=repo_dir)

    def test_group1_normal_nested_target_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            nested_imp = {
                "case_id": "IMP-NESTED", "description": "Candidate nested target",
                "command": "python3 -c \"import sys, pathlib; p = pathlib.Path('a/b/c/target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
                "rubric": {"rubric_id": "R-NESTED", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            prop = create_proposal(
                proposal_id="prop-nested", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="a/b/c/target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[nested_imp], regression_cases=[reg],
            )
            report = evaluate_proposal(prop, root / "ev_nested")
            self.assertEqual(report["eligibility"], "improvement-eligible")

    def test_group2_draft_references_canonicalized_before_persistence(self) -> None:
        import subprocess, sys
        from factory.improvement import FACTORY_ROOT
        env = dict(os.environ)
        env["PYTHONPATH"] = str(FACTORY_ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft_dir = root / "draft_dir"
            draft_dir.mkdir()
            obs = _write_file(draft_dir / "evidence" / "failure.txt", "failure\n")
            cand = _write_file(draft_dir / "content" / "cand.py", "def check(): return 'improved'\n")
            inp_file = _write_file(draft_dir / "inputs" / "data.txt", "payload\n")

            f_sha = hashlib.sha256(obs.read_bytes()).hexdigest()
            c_sha = hashlib.sha256(cand.read_bytes()).hexdigest()
            i_sha = hashlib.sha256(inp_file.read_bytes()).hexdigest()

            imp_case = {
                "case_id": "IMP-01",
                "command": "python3 -c \"import sys, pathlib; p = pathlib.Path('target.py'); sys.exit(0 if (p.exists() and 'improved' in p.read_text()) else 1)\"",
                "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                "inputs": [{"path": "inputs/data.txt", "target_path": "staged/data.txt", "sha256": i_sha}],
            }
            reg_case = {
                "case_id": "REG-01",
                "command": "python3 -c \"import sys; sys.exit(0)\"",
                "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            draft = {
                "schema_version": 1, "proposal_id": "prop-group2",
                "observed_failure": {"description": "f", "artifacts": [{"path": "evidence/failure.txt", "sha256": f_sha}]},
                "proposed_change": {"kind": "check", "target_path": "target.py", "content_path": "content/cand.py", "content_sha256": c_sha},
                "baseline": {"identity": "b1"}, "candidate": {"identity": "c1", "content_sha256": c_sha},
                "expected_improvement": {"description": "exp", "rule": "baseline-failed-candidate-passed"},
                "improvement_cases": [imp_case], "regression_cases": [reg_case],
                "execution_conditions": {
                    "time_limit_seconds": 30, "allow_network": False, "env_sanitized": True,
                    "permitted_substitution": {"target_path": "target.py", "content_sha256": c_sha},
                },
            }
            draft_p = _write_file(draft_dir / "draft.json", json.dumps(draft))

            out_proposal = root / "elsewhere" / "proposal.json"
            outside_dir = root / "outside"
            outside_dir.mkdir()

            res = subprocess.run(
                [sys.executable, "-m", "factory.improvement", "create-proposal", "--out", str(out_proposal), "--from-file", str(draft_p)],
                cwd=outside_dir, capture_output=True, text=True, env=env,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            saved = json.loads(out_proposal.read_text(encoding="utf-8"))
            self.assertEqual(saved["proposed_change"]["content_path"], str(cand.resolve()))
            self.assertEqual(saved["observed_failure"]["artifacts"][0]["path"], str(obs.resolve()))
            self.assertEqual(saved["improvement_cases"][0]["inputs"][0]["path"], str(inp_file.resolve()))
            self.assertEqual(saved["improvement_cases"][0]["inputs"][0]["target_path"], "staged/data.txt")

            third_dir = root / "third"
            third_dir.mkdir()
            eval_res = subprocess.run(
                [sys.executable, "-m", "factory.improvement", "evaluate", "--proposal", str(out_proposal), "--evidence-dir", str(root / "ev")],
                cwd=third_dir, capture_output=True, text=True, env=env,
            )
            self.assertEqual(eval_res.returncode, 0, eval_res.stderr)

    def test_group2_rejects_wrong_hashes_without_recomputing(self) -> None:
        import subprocess, sys
        from factory.improvement import FACTORY_ROOT
        env = dict(os.environ)
        env["PYTHONPATH"] = str(FACTORY_ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft_dir = root / "draft_dir"
            draft_dir.mkdir()
            obs = _write_file(draft_dir / "evidence" / "failure.txt", "failure\n")
            cand = _write_file(draft_dir / "content" / "cand.py", "cand\n")
            inp_file = _write_file(draft_dir / "inputs" / "data.txt", "data\n")

            f_sha = hashlib.sha256(obs.read_bytes()).hexdigest()
            c_sha = hashlib.sha256(cand.read_bytes()).hexdigest()
            i_sha = hashlib.sha256(inp_file.read_bytes()).hexdigest()

            for bad_field in ("artifact", "content", "input"):
                with self.subTest(bad_field=bad_field):
                    draft = {
                        "schema_version": 1, "proposal_id": f"prop-bad-{bad_field}",
                        "observed_failure": {"description": "f", "artifacts": [{"path": "evidence/failure.txt", "sha256": ("badsha" if bad_field == "artifact" else f_sha)}]},
                        "proposed_change": {"kind": "check", "target_path": "target.py", "content_path": "content/cand.py", "content_sha256": ("badsha" if bad_field == "content" else c_sha)},
                        "baseline": {"identity": "b1"}, "candidate": {"identity": "c1", "content_sha256": ("badsha" if bad_field == "content" else c_sha)},
                        "expected_improvement": {"description": "exp", "rule": "baseline-failed-candidate-passed"},
                        "improvement_cases": [{
                            "case_id": "IMP-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                            "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                            "inputs": [{"path": "inputs/data.txt", "target_path": "staged/data.txt", "sha256": ("badsha" if bad_field == "input" else i_sha)}],
                        }],
                        "regression_cases": [{
                            "case_id": "REG-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                            "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                        }],
                        "execution_conditions": {
                            "time_limit_seconds": 30, "allow_network": False, "env_sanitized": True,
                            "permitted_substitution": {"target_path": "target.py", "content_sha256": ("badsha" if bad_field == "content" else c_sha)},
                        },
                    }
                    draft_p = _write_file(draft_dir / f"draft_{bad_field}.json", json.dumps(draft))
                    out_p = root / f"out_{bad_field}.json"
                    res = subprocess.run(
                        [sys.executable, "-m", "factory.improvement", "create-proposal", "--out", str(out_p), "--from-file", str(draft_p)],
                        cwd=root, capture_output=True, text=True, env=env,
                    )
                    self.assertEqual(res.returncode, 1)
                    self.assertFalse(out_p.exists())

    def test_group3_report_validation_acceptance_and_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            prop = create_proposal(
                proposal_id="prop-g3", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            report = evaluate_proposal(prop, root / "ev_g3")

            # 1. Genuine eligible report accepted
            self.assertEqual(validate_report_for_review(report), [])
            prop_str = json.dumps(prop, indent=2, sort_keys=True) + "\n"
            self.assertEqual(validate_report_for_review(report, proposal_json=prop_str), [])

            # 2. Retained-report validation passes without external files
            obs.unlink()
            cand.unlink()
            self.assertFalse(obs.exists())
            self.assertFalse(cand.exists())
            self.assertEqual(validate_report_for_review(report), [])

            # 3. Genuine ineligible record accepted as valid record
            cand_inel = _write_file(root / "cand_inel.py", "def check(): return 'improved'\n")
            obs_inel = _write_file(root / "obs_inel.txt", "err\n")
            failing_reg = {
                "case_id": "REG-FAIL", "description": "Fails", "command": "python3 -c \"import sys; sys.exit(1)\"",
                "rubric": {"rubric_id": "R-FAIL", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            prop_inel = create_proposal(
                proposal_id="prop-inel", failure_description="f", failure_artifacts=[{"path": str(obs_inel)}],
                kind="check", target_path="target.py", content_path=cand_inel, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[failing_reg],
            )
            rep_inel = evaluate_proposal(prop_inel, root / "ev_inel")
            self.assertEqual(rep_inel["eligibility"], "ineligible")
            self.assertEqual(validate_report_for_review(rep_inel), [])

            # 4. Table-driven mutations rejected
            def mut_cand_digest(r: dict) -> tuple[dict, str | None]:
                r["candidate_content_digest"] = "bad" * 8
                return r, None

            def mut_embedded_prop(r: dict) -> tuple[dict, str | None]:
                r["proposal"]["proposal_id"] = "tampered"
                return r, None

            def mut_ext_binding(r: dict) -> tuple[dict, str | None]:
                return r, json.dumps({"schema_version": 1, "proposal_id": "different"}, indent=2) + "\n"

            def mut_unknown_eligibility(r: dict) -> tuple[dict, str | None]:
                r["eligibility"] = "approved"
                return r, None

            def mut_empty_regressions(r: dict) -> tuple[dict, str | None]:
                r["candidate_results"]["regression_cases"] = []
                return r, None

            def mut_mismatched_case_id(r: dict) -> tuple[dict, str | None]:
                r["candidate_results"]["improvement_cases"][0]["case_id"] = "OTHER-01"
                return r, None

            def mut_mismatched_rubric(r: dict) -> tuple[dict, str | None]:
                r["candidate_results"]["improvement_cases"][0]["rubric"]["expected_exit_code"] = 99
                return r, None

            def mut_contradicting_outcomes(r: dict) -> tuple[dict, str | None]:
                r["candidate_results"]["improvement_cases"][0]["rubric_passed"] = False
                r["candidate_results"]["improvement_cases"][0]["rubric_failures"] = ["failed"]
                return r, None

            def mut_malformed_comp(r: dict) -> tuple[dict, str | None]:
                r["comparison"] = "not_a_dict"
                return r, None

            def mut_malformed_results(r: dict) -> tuple[dict, str | None]:
                r["baseline_results"] = None
                return r, None

            def mut_malformed_prop(r: dict) -> tuple[dict, str | None]:
                r["proposal"] = 123
                return r, None

            mutations = [
                ("candidate_digest", mut_cand_digest),
                ("embedded_prop_without_digest", mut_embedded_prop),
                ("ext_proposal_binding", mut_ext_binding),
                ("unknown_eligibility", mut_unknown_eligibility),
                ("empty_regressions", mut_empty_regressions),
                ("mismatched_case_id", mut_mismatched_case_id),
                ("mismatched_rubric", mut_mismatched_rubric),
                ("contradicting_raw_outcomes", mut_contradicting_outcomes),
                ("malformed_comparison", mut_malformed_comp),
                ("malformed_results", mut_malformed_results),
                ("malformed_proposal", mut_malformed_prop),
            ]

            for label, mutator in mutations:
                with self.subTest(mutation=label):
                    clone = json.loads(json.dumps(report))
                    mutated, ext_json = mutator(clone)
                    issues = validate_report_for_review(mutated, proposal_json=ext_json)
                    self.assertIsInstance(issues, list)
                    self.assertGreater(len(issues), 0, f"Mutation {label!r} was unexpectedly accepted")

    def test_group_a_malformed_structures_and_shared_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)
            prop = create_proposal(
                proposal_id="prop-ga", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )
            report = evaluate_proposal(prop, root / "ev_ga")

            # 1. Non-dict baseline/candidate mutations
            for bad_obj in ("string", None, 123, []):
                for key in ("baseline", "candidate"):
                    with self.subTest(key=key, bad_obj=bad_obj):
                        clone = json.loads(json.dumps(report))
                        clone["proposal"][key] = bad_obj
                        clone["proposal_digest"] = proposal_digest(clone["proposal"])
                        issues = validate_report_for_review(clone)
                        self.assertIsInstance(issues, list)
                        self.assertGreater(len(issues), 0)

            # 2. List/dict unhashable case_ids in results and proposal
            for unhashable_id in (["IMP-01"], {"id": "IMP-01"}):
                with self.subTest(unhashable_result_id=unhashable_id):
                    clone = json.loads(json.dumps(report))
                    clone["candidate_results"]["improvement_cases"][0]["case_id"] = unhashable_id
                    issues = validate_report_for_review(clone)
                    self.assertIsInstance(issues, list)
                    self.assertGreater(len(issues), 0)
                with self.subTest(unhashable_proposal_id=unhashable_id):
                    clone = json.loads(json.dumps(report))
                    clone["proposal"]["improvement_cases"][0]["case_id"] = unhashable_id
                    clone["proposal_digest"] = proposal_digest(clone["proposal"])
                    issues = validate_report_for_review(clone)
                    self.assertIsInstance(issues, list)
                    self.assertGreater(len(issues), 0)

            # 3. Missing/non-list rubric_failures
            for bad_rf in (True, 1, 0, False, None, "str", {"err": 1}):
                with self.subTest(bad_rubric_failures=bad_rf):
                    clone = json.loads(json.dumps(report))
                    clone["candidate_results"]["improvement_cases"][0]["rubric_failures"] = bad_rf
                    issues = validate_report_for_review(clone)
                    self.assertIsInstance(issues, list)
                    self.assertGreater(len(issues), 0)

            # 4. Rebound embedded proposals with weakened/unexecutable commands, boolean exit code, non-string tokens
            rebound_mutations = [
                ("weakened_cmd", lambda p: p["improvement_cases"][0].update({"command": "python3 -m unittest -k 'not slow'"})),
                ("unexecutable_cmd", lambda p: p["improvement_cases"][0].update({"command": "echo 'unclosed quote"})),
                ("bool_exit_code", lambda p: p["improvement_cases"][0]["rubric"].update({"expected_exit_code": True})),
                ("non_str_tokens", lambda p: p["improvement_cases"][0]["rubric"].update({"required_output_tokens": [123]})),
            ]
            for label, mut_fn in rebound_mutations:
                with self.subTest(rebound_label=label):
                    clone = json.loads(json.dumps(report))
                    mut_fn(clone["proposal"])
                    clone["proposal_digest"] = proposal_digest(clone["proposal"])
                    # Keep results rubric aligned if rubric was modified
                    clone["candidate_results"]["improvement_cases"][0]["rubric"] = dict(clone["proposal"]["improvement_cases"][0]["rubric"])
                    clone["baseline_results"]["improvement_cases"][0]["rubric"] = dict(clone["proposal"]["improvement_cases"][0]["rubric"])
                    issues = validate_report_for_review(clone)
                    self.assertIsInstance(issues, list)
                    self.assertGreater(len(issues), 0, f"Expected {label!r} to be rejected")

    def test_group_b_candidate_launch_failures_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, imp, reg = _sample_fixtures(root)

            # 1. Candidate regression commands exiting 124, 126, 127 with rubrics expecting those codes
            for code in (124, 126, 127):
                with self.subTest(candidate_reg_exit=code):
                    reg_launch = {
                        "case_id": f"REG-LAUNCH-{code}", "description": "Launch fail regression",
                        "command": f"python3 -c \"import sys; sys.exit({code})\"",
                        "rubric": {"rubric_id": f"R-REG-{code}", "expected_exit_code": code, "required_output_tokens": [], "forbidden_output_tokens": []},
                    }
                    prop = create_proposal(
                        proposal_id=f"prop-reg-code-{code}", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                        kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                        candidate_identity="c1", expected_improvement_description="exp",
                        improvement_cases=[imp], regression_cases=[reg_launch],
                    )
                    rep = evaluate_proposal(prop, root / f"ev_reg_{code}")
                    self.assertEqual(rep["eligibility"], "ineligible")
                    self.assertFalse(rep["comparison"]["candidate_regressions_passed"])
                    self.assertFalse(rep["comparison"]["rule_satisfied"])
                    self.assertEqual(validate_report_for_review(rep), [])

                    # Forged report claiming eligibility must be rejected by review
                    forged = json.loads(json.dumps(rep))
                    forged["eligibility"] = "improvement-eligible"
                    forged["comparison"]["candidate_regressions_passed"] = True
                    forged["comparison"]["rule_satisfied"] = True
                    forged["eligibility_reasons"] = []
                    self.assertGreater(len(validate_report_for_review(forged)), 0)

            # 2. Candidate improvement command exiting 124, 126, 127
            for code in (124, 126, 127):
                with self.subTest(candidate_imp_exit=code):
                    imp_launch = {
                        "case_id": f"IMP-LAUNCH-{code}", "description": "Candidate launch fail",
                        "command": f"python3 -c \"import sys, pathlib; p = pathlib.Path('target.py'); sys.exit({code} if (p.exists() and 'improved' in p.read_text()) else 1)\"",
                        "rubric": {"rubric_id": f"R-IMP-{code}", "expected_exit_code": code, "required_output_tokens": [], "forbidden_output_tokens": []},
                    }
                    prop = create_proposal(
                        proposal_id=f"prop-imp-code-{code}", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                        kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                        candidate_identity="c1", expected_improvement_description="exp",
                        improvement_cases=[imp_launch], regression_cases=[reg],
                    )
                    rep = evaluate_proposal(prop, root / f"ev_imp_{code}")
                    self.assertEqual(rep["eligibility"], "ineligible")
                    self.assertFalse(rep["comparison"]["candidate_demonstrated_success"])
                    self.assertFalse(rep["comparison"]["rule_satisfied"])
                    self.assertEqual(validate_report_for_review(rep), [])

                    # Forged report claiming candidate_demonstrated_success must be rejected
                    forged = json.loads(json.dumps(rep))
                    forged["eligibility"] = "improvement-eligible"
                    forged["comparison"]["candidate_demonstrated_success"] = True
                    forged["comparison"]["rule_satisfied"] = True
                    forged["eligibility_reasons"] = []
                    self.assertGreater(len(validate_report_for_review(forged)), 0)

    def test_group4_case_inputs_and_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs = _write_file(root / "obs.txt", "observed failure\n")
            cand = _write_file(root / "worker.py", "def process(s):\n    return s.strip().upper()\n")
            input_file = _write_file(root / "input.txt", "staged-input-data\n")
            in_sha = hashlib.sha256(b"staged-input-data\n").hexdigest()

            imp_case = {
                "case_id": "IMP-INP",
                "description": "Candidate uses staged input and succeeds where baseline fails",
                "command": "python3 -c \"import sys; from pathlib import Path; in_p = Path('data/in.txt'); tgt = Path('lib/worker.py'); sys.exit(0 if (in_p.exists() and in_p.read_text() == 'staged-input-data\\n' and tgt.exists()) else 1)\"",
                "rubric": {"rubric_id": "R-IMP", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                "inputs": [{"path": str(input_file), "target_path": "data/in.txt", "sha256": in_sha}],
            }
            reg_case = {
                "case_id": "REG-INP",
                "description": "Both consume identical staged input bytes",
                "command": "python3 -c \"import sys; from pathlib import Path; in_p = Path('data/in.txt'); sys.exit(0 if (in_p.exists() and in_p.read_text() == 'staged-input-data\\n') else 1)\"",
                "rubric": {"rubric_id": "R-REG", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                "inputs": [{"path": str(input_file), "target_path": "data/in.txt", "sha256": in_sha}],
            }

            # 1. Successful evaluation with real sandboxed input staging
            prop = create_proposal(
                proposal_id="prop-inp", failure_description="fail", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="lib/worker.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="use input",
                improvement_cases=[imp_case], regression_cases=[reg_case],
            )
            rep = evaluate_proposal(prop, root / "ev_inp")
            self.assertEqual(rep["eligibility"], "improvement-eligible")
            self.assertTrue(rep["comparison"]["rule_satisfied"])
            self.assertTrue(rep["comparison"]["baseline_demonstrated_failure"])
            self.assertTrue(rep["comparison"]["candidate_demonstrated_success"])
            self.assertTrue(rep["comparison"]["candidate_regressions_passed"])

            # 2. Retained report validates without external input files
            input_file.unlink()
            obs.unlink()
            cand.unlink()
            self.assertEqual(validate_report_for_review(rep), [])

            # 3. Canonicalization keeps target_path relative and requires explicit target_path
            draft = {
                "schema_version": 1, "proposal_id": "prop-canon",
                "observed_failure": {"description": "f", "artifacts": [{"path": "obs.txt", "sha256": in_sha}]},
                "proposed_change": {"kind": "check", "target_path": "lib/worker.py", "content_path": "worker.py", "content_sha256": in_sha},
                "baseline": {"identity": "b1"}, "candidate": {"identity": "c1", "content_sha256": in_sha},
                "expected_improvement": {"description": "exp", "rule": "baseline-failed-candidate-passed"},
                "improvement_cases": [{
                    "case_id": "IMP-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                    "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                    "inputs": [{"path": "inputs/test.txt", "target_path": "staged/test.txt", "sha256": in_sha}],
                }],
                "regression_cases": [{
                    "case_id": "REG-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                    "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                }],
                "execution_conditions": {
                    "time_limit_seconds": 30, "allow_network": False, "env_sanitized": True,
                    "permitted_substitution": {"target_path": "lib/worker.py", "content_sha256": in_sha},
                },
            }
            canonicalize_draft_references(draft, root)
            self.assertEqual(draft["improvement_cases"][0]["inputs"][0]["target_path"], "staged/test.txt")
            self.assertTrue(Path(draft["improvement_cases"][0]["inputs"][0]["path"]).is_absolute())

            # 4. Structural validation rejects missing target_path (path does not default to target)
            no_tgt = json.loads(json.dumps(draft))
            del no_tgt["improvement_cases"][0]["inputs"][0]["target_path"]
            issues = validate_proposal_structure(no_tgt)
            self.assertTrue(any("target_path" in iss for iss in issues))

            # 5. Unsafe destinations rejected
            for bad_tgt in ("../escaped.txt", "/etc/passwd", "staged/../escape.txt", "staged/./x.txt"):
                bad_draft = json.loads(json.dumps(draft))
                bad_draft["improvement_cases"][0]["inputs"][0]["target_path"] = bad_tgt
                issues = validate_proposal_structure(bad_draft)
                self.assertTrue(any("target_path" in iss for iss in issues), f"Target {bad_tgt!r} should be rejected")

            # 6. Ambiguous collisions within case inputs rejected
            coll_draft = json.loads(json.dumps(draft))
            coll_draft["improvement_cases"][0]["inputs"].append(
                {"path": str(root / "other.txt"), "target_path": "staged/test.txt", "sha256": in_sha}
            )
            issues = validate_proposal_structure(coll_draft)
            self.assertTrue(any("duplicate input target_path" in iss for iss in issues))

            # Overlapping destinations in case inputs rejected
            overlap_draft = json.loads(json.dumps(draft))
            overlap_draft["improvement_cases"][0]["inputs"].append(
                {"path": str(root / "other.txt"), "target_path": "staged/test.txt/nested.txt", "sha256": in_sha}
            )
            issues = validate_proposal_structure(overlap_draft)
            self.assertTrue(any("overlapping" in iss for iss in issues))

            # 7. Substitution-target conflicts rejected
            sub_coll_draft = json.loads(json.dumps(draft))
            sub_coll_draft["improvement_cases"][0]["inputs"][0]["target_path"] = "lib/worker.py"
            issues = validate_proposal_structure(sub_coll_draft)
            self.assertTrue(any("conflicts with proposed_change" in iss for iss in issues))

            sub_overlap_draft = json.loads(json.dumps(draft))
            sub_overlap_draft["improvement_cases"][0]["inputs"][0]["target_path"] = "lib"
            issues = validate_proposal_structure(sub_overlap_draft)
            self.assertTrue(any("overlaps with proposed_change" in iss for iss in issues))

            # 8. Evaluation rejects changed/mismatched input bytes
            input_file2 = _write_file(root / "input2.txt", "real-content\n")
            in2_sha = hashlib.sha256(b"real-content\n").hexdigest()
            cand2 = _write_file(root / "cand2.py", "def check(): pass\n")
            obs2 = _write_file(root / "obs2.txt", "err\n")
            prop_mismatch = create_proposal(
                proposal_id="prop-mismatch", failure_description="f", failure_artifacts=[{"path": str(obs2)}],
                kind="check", target_path="target.py", content_path=cand2, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[{
                    "case_id": "IMP-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                    "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                    "inputs": [{"path": str(input_file2), "target_path": "in.txt", "sha256": in2_sha}],
                }],
                regression_cases=[{
                    "case_id": "REG-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                    "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                }],
            )
            input_file2.write_text("mutated-content\n")
            with self.assertRaises(UsageError):
                evaluate_proposal(prop_mismatch, root / "ev_mismatch")

    def test_group5_guaranteed_cleanup_and_external_homes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs = _write_file(root / "obs.txt", "err\n")
            cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
            imp = {
                "case_id": "IMP-01", "description": "imp",
                "command": "python3 -c \"import sys; sys.exit(0)\"",
                "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            reg = {
                "case_id": "REG-01", "description": "reg",
                "command": "python3 -c \"import sys; sys.exit(0)\"",
                "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            prop = create_proposal(
                proposal_id="prop-g5", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[imp], regression_cases=[reg],
            )

            # 1. Status-sensitive case in git repo: no _home artifact, no false regression
            repo_dir = root / "git_repo"
            repo_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
            _write_file(repo_dir / "target.py", "def check(): return 'base'\n")
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo_dir, check=True)

            status_imp = {
                "case_id": "IMP-GIT", "description": "Candidate improves target and introduces no untracked _home",
                "command": "python3 -c \"import sys, subprocess, pathlib; out = subprocess.check_output(['git', 'status', '--porcelain'], text=True); p = pathlib.Path('target.py'); has_untracked = any(line.startswith('??') for line in out.splitlines()); sys.exit(0 if (not has_untracked and 'improved' in p.read_text()) else 1)\"",
                "rubric": {"rubric_id": "R-GIT", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            status_reg = {
                "case_id": "REG-GIT", "description": "No untracked files introduced by evaluation on baseline or candidate",
                "command": "python3 -c \"import sys, subprocess; out = subprocess.check_output(['git', 'status', '--porcelain'], text=True); sys.exit(0 if not any(line.startswith('??') for line in out.splitlines()) else 1)\"",
                "rubric": {"rubric_id": "R-GIT-REG", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            }
            prop_git = create_proposal(
                proposal_id="prop-git", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                candidate_identity="c1", expected_improvement_description="exp",
                improvement_cases=[status_imp], regression_cases=[status_reg],
            )
            ev_git = root / "ev_git"
            rep_git = evaluate_proposal(prop_git, ev_git, repo=repo_dir)
            self.assertEqual(rep_git["eligibility"], "improvement-eligible")

            # Check homes location and distinctness across sides/cases
            homes_dir = ev_git / "attempts" / "attempt-1" / "homes"
            self.assertTrue(homes_dir.is_dir())
            b_imp_home = homes_dir / "baseline" / "IMP-GIT"
            c_imp_home = homes_dir / "candidate" / "IMP-GIT"
            c_reg_home = homes_dir / "candidate" / "REG-GIT"
            self.assertTrue(b_imp_home.is_dir())
            self.assertTrue(c_imp_home.is_dir())
            self.assertTrue(c_reg_home.is_dir())
            self.assertNotEqual(b_imp_home, c_imp_home)
            self.assertNotEqual(c_imp_home, c_reg_home)

            # Ensure no worktrees remain orphaned after successful run
            wt_dir = ev_git / "attempts" / "attempt-1" / "worktrees"
            self.assertTrue(not wt_dir.exists() or len(list(wt_dir.iterdir())) == 0)

            # 2. Preparation failure after directory creation cleans up worktree
            def fail_prep(src_repo, dest_worktree, ref):
                dest_worktree.mkdir(parents=True, exist_ok=True)
                (dest_worktree / "leak.txt").write_text("partial")
                raise RuntimeError("simulated prep failure")

            with unittest.mock.patch("factory.worker.prepare_isolated_git_checkout", side_effect=fail_prep):
                ev_prep = root / "ev_prep"
                with self.assertRaises(RuntimeError):
                    evaluate_proposal(prop, ev_prep, repo=repo_dir)
                prep_manifest = json.loads((ev_prep / "attempts" / "attempt-1" / "attempt-manifest.json").read_text())
                self.assertEqual(prep_manifest["status"], "failed")
                prep_wt_dir = ev_prep / "attempts" / "attempt-1" / "worktrees"
                self.assertTrue(not prep_wt_dir.exists() or len(list(prep_wt_dir.iterdir())) == 0)

            # 3. Execution interruption cleans up worktree and preserves interrupted evidence
            with unittest.mock.patch("factory.improvement._execute_case", side_effect=KeyboardInterrupt("simulated interrupt")):
                ev_intr = root / "ev_intr"
                with self.assertRaises(KeyboardInterrupt):
                    evaluate_proposal(prop, ev_intr)
                intr_manifest = json.loads((ev_intr / "attempts" / "attempt-1" / "attempt-manifest.json").read_text())
                self.assertEqual(intr_manifest["status"], "interrupted")
                intr_wt_dir = ev_intr / "attempts" / "attempt-1" / "worktrees"
                self.assertTrue(not intr_wt_dir.exists() or len(list(intr_wt_dir.iterdir())) == 0)

            # 4. Per-case persistence failure cleans up worktree and propagates original failure
            orig_write_json = factory.improvement._write_json
            def fail_per_case(path, data):
                if path.name == "IMP-01.json":
                    raise OSError("simulated per-case persistence error")
                return orig_write_json(path, data)

            with unittest.mock.patch("factory.improvement._write_json", side_effect=fail_per_case):
                ev_pers = root / "ev_pers"
                with self.assertRaises(OSError):
                    evaluate_proposal(prop, ev_pers)
                pers_wt_dir = ev_pers / "attempts" / "attempt-1" / "worktrees"
                self.assertTrue(not pers_wt_dir.exists() or len(list(pers_wt_dir.iterdir())) == 0)

            # 5. Substitution or staging failure cleanup
            with unittest.mock.patch("factory.improvement._write_confined_file", side_effect=UsageError("staging fail")):
                ev_sub = root / "ev_sub"
                prop_with_inp = create_proposal(
                    proposal_id="prop-sub-fail", failure_description="f", failure_artifacts=[{"path": str(obs)}],
                    kind="check", target_path="target.py", content_path=cand, baseline_identity="b1",
                    candidate_identity="c1", expected_improvement_description="exp",
                    improvement_cases=[{
                        "case_id": "IMP-01", "command": "python3 -c \"import sys; sys.exit(0)\"",
                        "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
                        "inputs": [{"path": str(obs), "target_path": "staged.txt", "sha256": hashlib.sha256(b"err\n").hexdigest()}],
                    }],
                    regression_cases=[reg],
                )
                with self.assertRaises(UsageError):
                    evaluate_proposal(prop_with_inp, ev_sub)
                sub_wt_dir = ev_sub / "attempts" / "attempt-1" / "worktrees"
                self.assertTrue(not sub_wt_dir.exists() or len(list(sub_wt_dir.iterdir())) == 0)

            # 6. Secondary failure in failure recording does not replace original exception
            sec_calls = [0]
            def fail_secondary_json(path, data):
                sec_calls[0] += 1
                if sec_calls[0] > 1:
                    raise OSError("simulated secondary write failure")
                return orig_write_json(path, data)

            with unittest.mock.patch("factory.improvement._execute_case", side_effect=KeyError("original-error")):
                with unittest.mock.patch("factory.improvement._write_json", side_effect=fail_secondary_json):
                    ev_sec = root / "ev_sec"
                    with self.assertRaises(KeyError) as cm:
                        evaluate_proposal(prop, ev_sec)
                    self.assertEqual(str(cm.exception), "'original-error'")



if __name__ == "__main__":
    unittest.main()
