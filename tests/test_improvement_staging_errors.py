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

    def test_missing_or_changed_bytes_fail_attempt_with_terminal_evidence(self) -> None:
        cases = (
            (lambda inp, cand: inp.unlink(), "input not found"),
            (lambda inp, cand: inp.write_bytes(b"tampered input bytes\n"), "input sha mismatch"),
            (lambda inp, cand: cand.unlink(), "content_path not found"),
            (lambda inp, cand: cand.write_bytes(b"tampered candidate bytes\n"), "content_sha256 mismatch"),
        )
        for mutate, message in cases:
            with self.subTest(message):
                self._assert_staged_bytes_failure(mutate, message)

    def _assert_staged_bytes_failure(self, mutate, message: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs, cand, inp, prop, ev_dir, att1_dir, att1_sha = _setup_fixture(root)

            orig_write_json = factory.improvement._write_json
            def hook_write(path, data):
                orig_write_json(path, data)
                if Path(path).name == "attempt-manifest.json" and isinstance(data, dict) and data.get("status") == "in-progress":
                    mutate(inp, cand)

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with self.assertRaises(UsageError) as ctx:
                    evaluate_proposal(prop, ev_dir)

            self.assertIn(message, str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn(message, manifest.get("error", ""))

    def test_staging_read_error_or_interrupt_records_terminal_evidence(self) -> None:
        for error, status in (
            (OSError("simulated staging disk read failure"), "failed"),
            (KeyboardInterrupt("simulated staging interrupt"), "interrupted"),
        ):
            with self.subTest(status):
                self._assert_staging_read_failure(error, status)

    def _assert_staging_read_failure(self, error: BaseException, status: str) -> None:
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
                    raise error
                return orig_read_bytes(p_self)

            with unittest.mock.patch("factory.improvement._write_json", side_effect=hook_write):
                with unittest.mock.patch.object(Path, "read_bytes", side_effect=hook_read, autospec=True):
                    with self.assertRaises(type(error)) as ctx:
                        evaluate_proposal(prop, ev_dir)

            self.assertIn(str(error), str(ctx.exception))
            manifest = self._verify_common_invariants(ev_dir, att1_dir, att1_sha)
            self.assertEqual(manifest["status"], status)
            self.assertEqual(manifest["eligibility"], "ineligible")
            self.assertEqual(manifest["completed_cases"], [])
            self.assertIsNotNone(manifest["completed_at"])
            self.assertIn(str(error), manifest.get("error", ""))

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
