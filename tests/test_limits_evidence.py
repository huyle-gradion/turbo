import json
import tempfile
import time
import unittest
from pathlib import Path

from support import (
    cli, commit_probe, config, git, home_dir, make_repo, prepare,
    private_mode, run_state, spend_record, to_ready,
)


class LimitTest(unittest.TestCase):
    def test_operation_limit_stops_before_the_next_child_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(prepare(repo, home, operations=2).returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            red = cli(
                repo, home, "red", "--issue", "7",
                "--test", "tests/test_probe.py",
                "--selector", "ProbeTest.test_answer",
                "--command", "python3 -m unittest discover -s tests -p test_probe.py -v",
                "--expect", "AssertionError",
            )
            sha = commit_probe(repo, 42, "implementation")
            self.assertEqual(cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode, 0)
            first = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "2")
            state = run_state(home)
        self.assertEqual(red.returncode, 0, red.stdout + red.stderr)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "not-ready")
        self.assertEqual(state["counters"]["operations_used"], 2)
        self.assertIn("operation", (result.stdout + result.stderr).lower())

    def test_time_limit_is_enforced_from_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(prepare(repo, home, time_limit="1s").returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            time.sleep(1.2)
            result = cli(
                repo, home, "red", "--issue", "7",
                "--test", "tests/test_probe.py",
                "--selector", "ProbeTest.test_answer",
                "--command", "python3 -m unittest discover -s tests -p test_probe.py -v",
                "--expect", "AssertionError",
            )
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "not-ready")
        self.assertIn("time", (result.stdout + result.stderr).lower())

    def test_status_reports_supervision_limits_as_unenforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(
                cli(repo, home, "prepare", "--issue", "7", "--feature", "S-1", "--kind", "feature",
                    "--model", "test-model", "--attest-model-account", "--time-limit", "60m",
                    "--operation-limit", "20", "--supervision-turns", "40", "--supervision-writes", "50").returncode,
                0,
            )
            result = cli(repo, home, "status", "--issue", "7", "--json")
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["issue"], 7)
        self.assertIn("supervision_turns", state["limits"])
        self.assertNotIn("writes", state["counters"])
        self.assertIn("not enforced", state["limits"]["enforcement"]["supervision_turns"])


class EvidenceTest(unittest.TestCase):
    def test_state_and_evidence_files_are_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            result = cli(
                repo, home, "red", "--issue", "7",
                "--test", "tests/test_probe.py",
                "--selector", "ProbeTest.test_answer",
                "--command", "python3 -m unittest discover -s tests -p test_probe.py -v",
                "--expect", "AssertionError",
            )
            state = run_state(home)
            output = Path(str(state["red"]["output_path"]))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(private_mode(home / "runs" / "7.json"), 0o600)
            self.assertEqual(private_mode(home / "config.json"), 0o600)
            self.assertEqual(private_mode(output), 0o600)

    def test_spend_record_is_explicitly_operator_declared(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            self.assertEqual(spend_record(repo, home, 42.5, source="manual export 2026-11-03").returncode, 0)
            config_data = json.loads((home / "config.json").read_text(encoding="utf-8"))
            week = next(iter(config_data["budget"]["weeks"].values()))
        self.assertEqual(week["usd"], 42.5)
        self.assertEqual(week["source"], "manual export 2026-11-03")
        self.assertIn("operator-declared", week["verification"])
        self.assertNotIn("invoice", json.dumps(config_data).lower())

    def test_spend_show_marks_an_unrecorded_week_unpriced(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            result = cli(repo, home, "spend", "show")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UNPRICED", result.stdout)


class DoctorTest(unittest.TestCase):
    def test_doctor_passes_a_complete_synthetic_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_doctor_fails_closed_without_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 1)
        self.assertIn("gate", (result.stdout + result.stderr).lower())

    def test_doctor_reports_gate_drift_for_an_admitted_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["2"]["argv"] = ["python3", "-c", "pass"]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 1)
        self.assertIn("digest", (result.stdout + result.stderr).lower())

    def test_status_works_after_a_stop_without_gate_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            assert prepare(repo, home).returncode == 1
            result = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing", result.stdout)


class PromptTest(unittest.TestCase):
    def test_prompt_prints_git_instructions_without_creating_the_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            result = cli(repo, home, "prompt", "--issue", "7")
            branches = git(repo, "branch", "--list", "run-issue-7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("git switch -c run-issue-7", result.stdout)
        self.assertEqual(branches, "")

    def test_invalid_stop_reason_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            result = cli(repo, home, "stop", "--issue", "7", "--reason", "finished")
        self.assertEqual(result.returncode, 2)

    def test_non_finite_spend_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            result = cli(repo, home, "spend", "record", "--usd", "nan", "--source", "bad export")
            config_data = json.loads((home / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(config_data["budget"]["weeks"], {})



if __name__ == "__main__":
    unittest.main()
