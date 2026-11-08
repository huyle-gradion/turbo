"""Regressions for attempt error-handling and staging failures (#74)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import unittest.mock

import factory.improvement
from factory.errors import UsageError
from factory.improvement import create_proposal, evaluate_proposal


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _setup_fixture(root: Path):
    obs = _write_file(root / "obs.txt", "observed failure\n")
    cand = _write_file(root / "cand.py", "def check(): return 'improved'\n")
    inp = _write_file(root / "input.txt", "input payload\n")
    in_sha = hashlib.sha256(b"input payload\n").hexdigest()
    prop = create_proposal(
        proposal_id="prop-stage-err",
        failure_description="failure",
        failure_artifacts=[{"path": str(obs)}],
        kind="check",
        target_path="target.py",
        content_path=cand,
        baseline_identity="base-1",
        candidate_identity="cand-2",
        expected_improvement_description="fix",
        improvement_cases=[{
            "case_id": "IMP-01",
            "command": "python3 -c \"import sys; sys.exit(0)\"",
            "rubric": {"rubric_id": "R1", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
            "inputs": [{"path": str(inp), "target_path": "staged.txt", "sha256": in_sha}],
        }],
        regression_cases=[{
            "case_id": "REG-01",
            "command": "python3 -c \"import sys; sys.exit(0)\"",
            "rubric": {"rubric_id": "R2", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
        }],
    )
    ev_dir = root / "evidence"
    att1_dir = ev_dir / "attempts" / "attempt-1"
    att1_dir.mkdir(parents=True, exist_ok=True)
    att1_manifest = att1_dir / "attempt-manifest.json"
    att1_manifest.write_text(json.dumps({"status": "completed", "attempt_number": 1, "note": "prior"}), encoding="utf-8")
    att1_sha = hashlib.sha256(att1_manifest.read_bytes()).hexdigest()
    return obs, cand, inp, prop, ev_dir, att1_dir, att1_sha


class ImprovementStagingErrorsTest(unittest.TestCase):
    def _verify_common_invariants(self, ev_dir: Path, att1_dir: Path, att1_sha: str) -> dict:
        # 1. Prior attempt unchanged
        att1_now = (att1_dir / "attempt-manifest.json").read_bytes()
        self.assertEqual(hashlib.sha256(att1_now).hexdigest(), att1_sha)

        # 2. Retained attempt evidence exists
        att2_dir = ev_dir / "attempts" / "attempt-2"
        self.assertTrue(att2_dir.is_dir())
        manifest_file = att2_dir / "attempt-manifest.json"
        self.assertTrue(manifest_file.is_file())

        # 3. No orphaned worktrees
        wt_dir = att2_dir / "worktrees"
        self.assertTrue(not wt_dir.exists() or len(list(wt_dir.iterdir())) == 0)

        # 4. No case execution results
        self.assertFalse((att2_dir / "baseline").exists())
        self.assertFalse((att2_dir / "candidate").exists())

        return json.loads(manifest_file.read_text(encoding="utf-8"))

    def test_missing_input_bytes_fails_attempt_with_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    inp.unlink()

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            self.assertIn("input not found", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("input not found", manifest.get("error", ""))

    def test_changed_input_bytes_fails_attempt_with_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    inp.write_bytes(b"tampered input bytes\n")

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            self.assertIn("input sha mismatch", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("input sha mismatch", manifest.get("error", ""))

    def test_missing_candidate_bytes_fails_attempt_with_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    cand.unlink()

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            self.assertIn("content_path not found", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("content_path not found", manifest.get("error", ""))

    def test_changed_candidate_bytes_fails_attempt_with_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    cand.write_bytes(b"tampered candidate bytes\n")

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            self.assertIn("content_sha256 mismatch", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("content_sha256 mismatch", manifest.get("error", ""))

    def test_staging_read_error_fails_attempt_with_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            orig_read_bytes = Path.read_bytes
            fail_read = [False]

            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    fail_read[0] = True

            def hook_read(p_self):
                if fail_read[0] and p_self.resolve() == inp.resolve():
                    raise OSError("simulated staging disk read failure")
                return orig_read_bytes(p_self)

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with unittest.mock.patch.object(Path, "read_bytes", side_effect=hook_read, autospec=True):
                    with self.assertRaises(OSError) as ctx:
                        evaluate_proposal(prop, ev_dir)

            self.assertIn("simulated staging disk read failure", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("simulated staging disk read failure", manifest.get("error", ""))

    def test_staging_interruption_records_interrupted_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            orig_read_bytes = Path.read_bytes
            fail_read = [False]

            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    fail_read[0] = True

            def hook_read(p_self):
                if fail_read[0] and p_self.resolve() == inp.resolve():
                    raise KeyboardInterrupt("simulated staging interrupt")
                return orig_read_bytes(p_self)

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with unittest.mock.patch.object(Path, "read_bytes", side_effect=hook_read, autospec=True):
                    with self.assertRaises(KeyboardInterrupt) as ctx:
                        evaluate_proposal(prop, ev_dir)

            self.assertIn("simulated staging interrupt", str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "interrupted")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn("simulated staging interrupt", manifest.get("error", ""))

    def test_secondary_manifest_write_failure_preserves_original_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            fail_secondary_write = [False]

            def hook_write(path, data):
                if fail_secondary_write[0]:
                    raise OSError("secondary manifest write disk full")
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    inp.unlink()
                    fail_secondary_write[0] = True

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            # Secondary write failed, but original exception was preserved and re-raised!
            self.assertIn("input not found", str(ctx.exception))
            # Attempt 1 unchanged
            att1_now = (att1_dir / "attempt-manifest.json").read_bytes()
            self.assertEqual(hashlib.sha256(att1_now).hexdigest(), att1_sha)
            # No orphaned worktrees
            att2_dir = ev_dir / "attempts" / "attempt-2"
            wt_dir = att2_dir / "worktrees"
            self.assertTrue(not wt_dir.exists() or len(list(wt_dir.iterdir())) == 0)
