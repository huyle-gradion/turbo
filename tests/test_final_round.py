"""Final fix round: stage limits, active resume limits, replay integrity, manifest contract, state bounds."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from support import (
    cli, commit_probe, config, git, home_dir, make_repo, prepare, red,
    run_state, spend_record, staged, to_green, to_ready, to_red,
)

ISSUE = "7"


def resume(repo: Path, home: Path):
    return cli(repo, home, "resume", "--issue", ISSUE, "--pr", "none")


def stage(repo: Path, home: Path, commit: str):
    return cli(repo, home, "stage", "--issue", ISSUE, "--commit", commit)


class StageLimitTest(unittest.TestCase):
    def test_stage_refuses_after_the_operation_limit_is_spent(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, operations=1).returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            result = stage(repo, home, sha)
            state = run_state(home)
            later = stage(repo, home, sha)
        self.assertEqual(result.returncode, 1)
        self.assertIn("operation limit", result.stderr)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["prior_phase"], "red")
        self.assertEqual(state["stop_reason"], "not-ready")
        self.assertIsNone(state["expected_green_sha"])
        self.assertIsNone(state["stage"])
        self.assertEqual(state["counters"]["operations_used"], 1)
        self.assertEqual(later.returncode, 2)

    def test_stage_refuses_after_the_time_limit_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, time_limit="60m").returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            state = run_state(home)
            state["admitted_at"] = "2020-01-01T00:00:00Z"
            (home / "runs" / f"{ISSUE}.json").write_text(json.dumps(state), encoding="utf-8")
            result = stage(repo, home, sha)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("time limit exceeded", result.stderr)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["prior_phase"], "red")
        self.assertIsNone(state["expected_green_sha"])
        self.assertIsNone(state["stage"])


class ActiveLimitResumeTest(unittest.TestCase):
    def test_resume_refuses_an_expired_ready_run_as_superseded(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, time_limit="1s").returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            time.sleep(1.5)
            result = resume(repo, home)
            state = run_state(home)
            entry = state["resume_history"][-1]
            prompt = cli(repo, home, "prompt", "--issue", ISSUE)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(entry["verdict"], "refused")
        self.assertTrue(any(reason.startswith("limit-exhausted") for reason in entry["reasons"]))
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["stop_reason"], "superseded")
        self.assertEqual(state["prior_phase"], "ready")
        self.assertIn("new issue", state["stop_detail"].lower())
        self.assertEqual(state["counters"]["operations_used"], 0)
        self.assertNotIn("factory resume", prompt.stdout)
        self.assertIn("new issue", prompt.stdout.lower())

    def test_resume_refuses_an_operation_exhausted_red_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, operations=1).returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            result = resume(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "superseded")
        self.assertEqual(state["prior_phase"], "red")
        self.assertEqual(state["counters"]["operations_used"], 1)

    def test_resume_refuses_an_operation_exhausted_gated_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, operations=3).returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            assert stage(repo, home, sha).returncode == 0
            assert cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1").returncode == 0
            assert cli(repo, home, "gate", "--issue", ISSUE, "--gate", "2").returncode == 0
            result = resume(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "superseded")
        self.assertEqual(state["prior_phase"], "gates")
        self.assertEqual(state["gate_chain"], ["1", "2"])
        self.assertEqual(state["counters"]["operations_used"], 3)


class ReplayIntegrityTest(unittest.TestCase):
    def test_green_phase_replay_refuses_a_missing_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            Path(str(run_state(home)["replay"]["output_path"])).unlink()
            result = cli(repo, home, "replay", "--issue", ISSUE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing", result.stderr.lower())
        self.assertNotIn("already recorded", result.stdout)

    def test_local_verified_replay_refuses_a_modified_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            assert cli(repo, home, "manifest", "--issue", ISSUE).returncode == 0
            artifact = Path(str(run_state(home)["replay"]["output_path"]))
            artifact.write_bytes(artifact.read_bytes() + b"tamper\n")
            result = cli(repo, home, "replay", "--issue", ISSUE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("digest mismatch", result.stderr.lower())
        self.assertNotIn("already recorded", result.stdout)

    def test_staged_replay_refuses_a_missing_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            assert cli(repo, home, "replay", "--issue", ISSUE).returncode == 0
            Path(str(run_state(home)["replay"]["output_path"])).unlink()
            result = cli(repo, home, "replay", "--issue", ISSUE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing", result.stderr.lower())
        self.assertNotIn("already recorded", result.stdout)


class ManifestContractTest(unittest.TestCase):
    def test_manifest_refuses_edited_record_fields_without_overwriting(self):
        edits = (
            (("red", "expect"), "DifferentError"),
            (("replay", "selector"), "Other.test"),
            (("feature",), "S-other"),
            (("kind",), "bug"),
            (("budget", "usd"), 0.0),
            (("budget_admission", "source"), "someone else"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            assert cli(repo, home, "manifest", "--issue", ISSUE).returncode == 0
            target = home / "evidence" / ISSUE / "manifest.json"
            original = target.read_bytes()
            for keys, value in edits:
                with self.subTest(keys=keys):
                    mutated = json.loads(original)
                    node = mutated
                    for key in keys[:-1]:
                        node = node[key]
                    node[keys[-1]] = value
                    written = json.dumps(mutated).encode()
                    target.write_bytes(written)
                    result = cli(repo, home, "manifest", "--issue", ISSUE)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(target.read_bytes(), written)

    def test_new_spend_after_manifest_keeps_the_recorded_snapshot_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            assert cli(repo, home, "manifest", "--issue", ISSUE).returncode == 0
            target = home / "evidence" / ISSUE / "manifest.json"
            before = target.read_bytes()
            spend_record(repo, home, 55.0)
            result = cli(repo, home, "manifest", "--issue", ISSUE)
            after = target.read_bytes()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already exists", result.stdout)
        self.assertEqual(after, before)


class RunStateBoundsTest(unittest.TestCase):
    def test_malformed_state_is_a_clean_usage_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            (home / "runs" / f"{ISSUE}.json").write_text("{not json", encoding="utf-8")
            result = cli(repo, home, "status", "--issue", ISSUE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("corrupt state file", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_impossible_state_values_are_refused_cleanly(self):
        cases = (
            ("zero time limit", lambda state: state["limits"].update({"time_seconds": 0}), "time_seconds"),
            ("negative time limit", lambda state: state["limits"].update({"time_seconds": -1}), "time_seconds"),
            ("zero operation limit", lambda state: state["limits"].update({"operations": 0}), "operations"),
            ("negative operation limit", lambda state: state["limits"].update({"operations": -1}), "operations"),
            ("negative operations used", lambda state: state["counters"].update({"operations_used": -1}), "operations_used"),
            ("negative repairs used", lambda state: state["counters"].update({"repairs_used": -1}), "repairs_used"),
            ("negative repair cap", lambda state: state["counters"].update({"repair_cap": -2}), "repair_cap"),
            ("unknown stop reason", lambda state: state.update({"stop_reason": "mystery"}), "stop reason"),
            ("unknown prior phase", lambda state: state.update({"prior_phase": "mystery"}), "prior phase"),
            (
                "stopped without a reason",
                lambda state: state.update({"phase": "stopped", "stop_reason": None, "prior_phase": "ready"}),
                "stop_reason",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            path = home / "runs" / f"{ISSUE}.json"
            original = path.read_text(encoding="utf-8")
            for label, edit, fragment in cases:
                with self.subTest(label):
                    mutated = json.loads(original)
                    edit(mutated)
                    path.write_text(json.dumps(mutated), encoding="utf-8")
                    result = cli(repo, home, "status", "--issue", ISSUE)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(fragment, result.stderr.lower())
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn("internal error", result.stderr)
                    path.write_text(original, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
