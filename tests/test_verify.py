import json
import unittest
from pathlib import Path

from support import (
    cli, commit_probe, commit, configure_turbo, evidence_files, git, home_dir,
    make_repo, marker_gate, prepare, red, run_state, spend_record, staged,
    staged_turbo, workspace,
)

ISSUE = "7"
ALWAYS_FAILS = 'python3 -c "import sys; print(\'AssertionError\'); sys.exit(1)"'


def verify(repo: Path, home: Path, issue: str = ISSUE):
    return cli(repo, home, "verify", "--issue", issue)


def turbo_staged(repo: Path, home: Path, *, operations: int = 5, **kwargs: object) -> str:
    return staged_turbo(repo, home, operations=operations, **kwargs)


class ManualRefusalTest(unittest.TestCase):
    def test_manual_verify_refuses_before_any_child_or_state_change(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "gate-one-ran"
            staged(repo, home, gate1=marker_gate(marker))
            before = run_state(home)
            files = evidence_files(home)
            result = verify(repo, home)
            after = run_state(home)
            files_after = evidence_files(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("native-turbo", (result.stdout + result.stderr).lower())
        self.assertFalse(marker.exists())
        self.assertEqual(before["counters"], after["counters"])
        self.assertEqual(before["phase"], after["phase"])
        self.assertEqual(files, files_after)

    def test_manual_verify_refuses_after_green_too(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import to_green
            to_green(repo, home)
            result = verify(repo, home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("native-turbo", (result.stdout + result.stderr).lower())


class TurboBundleTest(unittest.TestCase):
    def test_five_total_operations_complete_the_bundle(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            sha = turbo_staged(repo, home, operations=5)
            result = verify(repo, home)
            state = run_state(home)
            manifest = json.loads(Path(str(state["manifest_path"])).read_text(encoding="utf-8"))
            files = evidence_files(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(state["green_sha"], sha)
        self.assertEqual(state["counters"]["operations_used"], 5)
        self.assertEqual(state["verified_by"], "native-turbo-verify")
        self.assertEqual(manifest["execution_profile"], "native-turbo")
        self.assertEqual(manifest["verification_mode"], "native-turbo-verify")
        self.assertEqual(manifest["profile_attestation"]["host"], "antigravity-native")
        self.assertEqual(manifest["green_sha"], sha)
        self.assertEqual(len(files), 5)

    def test_four_operation_limit_refuses_before_any_child(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "gate-one-ran"
            turbo_staged(repo, home, operations=4, gate1=marker_gate(marker))
            result = verify(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(marker.exists())
        self.assertEqual(state["phase"], "gates")
        self.assertEqual(state["counters"]["operations_used"], 1)
        self.assertEqual(state["gate_observations"], [])

    def test_first_failure_stops_the_bundle_and_the_next_verify_reruns_gate_one(self):
        failing_gate_two = ["python3", "-c", "import sys; sys.exit(1)"]
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=10, gate2=failing_gate_two)
            first = verify(repo, home)
            stopped = run_state(home)
            second = verify(repo, home)
            state = run_state(home)
        self.assertEqual(first.returncode, 1)
        self.assertEqual(stopped["gate_chain"], [])
        self.assertEqual(stopped["gate_attempts"][-1]["gate"], "2")
        self.assertIsNone(stopped.get("replay"))
        self.assertIsNone(stopped.get("green"))
        self.assertEqual([item["gate"] for item in stopped["gate_observations"]], ["1", "2"])
        self.assertEqual(stopped["counters"]["operations_used"], 3)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(state["gate_chain"], [])
        self.assertEqual([item["gate"] for item in state["gate_observations"]], ["1", "2", "1", "2"])
        self.assertEqual(state["counters"]["operations_used"], 5)

    def test_a_noop_gate_two_cannot_mask_a_failing_red_replay(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home, gate2=["python3", "-c", "pass"])
            self.assertEqual(prepare(repo, home, operations=10).returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            self.assertEqual(red(repo, home, command=ALWAYS_FAILS).returncode, 0)
            sha = commit_probe(repo, 42, "implementation")
            self.assertEqual(cli(repo, home, "stage", "--issue", ISSUE, "--commit", sha).returncode, 0)
            result = verify(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIsNotNone(state.get("replay"))
        self.assertEqual(state["replay"]["exit"], 1)
        self.assertIsNone(state.get("green"))
        self.assertEqual(state["phase"], "gates")

    def test_a_manual_prefix_is_reused_and_the_remaining_steps_run_in_order(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5, gate2=["python3", "-c", "pass"])
            self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1").returncode, 0)
            result = verify(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(state["counters"]["operations_used"], 5)
        self.assertEqual(state["gate_chain"], ["1", "2", "3"])

    def test_a_recorded_passing_replay_is_not_executed_again(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5, gate2=["python3", "-c", "pass"])
            for gate in ("1", "2", "3"):
                self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", gate).returncode, 0)
            self.assertEqual(cli(repo, home, "replay", "--issue", ISSUE).returncode, 0)
            before = list((home / "evidence" / ISSUE).glob("replay-*.txt"))
            result = verify(repo, home)
            after = list((home / "evidence" / ISSUE).glob("replay-*.txt"))
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(before), 1)
        self.assertEqual(len(after), 1)
        self.assertEqual(state["counters"]["operations_used"], 5)

    def test_repeated_verify_after_local_verified_uses_no_children_or_new_bytes(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5)
            self.assertEqual(verify(repo, home).returncode, 0)
            state = run_state(home)
            path = Path(str(state["manifest_path"]))
            before_bytes = path.read_bytes()
            before_files = evidence_files(home)
            second = verify(repo, home)
            after = run_state(home)
            after_bytes = path.read_bytes()
            after_files = evidence_files(home)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(before_bytes, after_bytes)
        self.assertEqual(before_files, after_files)
        self.assertEqual(after["counters"]["operations_used"], 5)

    def test_verify_from_the_green_phase_revalidates_without_children(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5, gate2=["python3", "-c", "pass"])
            for gate in ("1", "2", "3"):
                self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", gate).returncode, 0)
            self.assertEqual(cli(repo, home, "replay", "--issue", ISSUE).returncode, 0)
            self.assertEqual(cli(repo, home, "green", "--issue", ISSUE).returncode, 0)
            before_files = evidence_files(home)
            result = verify(repo, home)
            state = run_state(home)
            after_files = evidence_files(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(before_files, after_files)
        self.assertEqual(state["counters"]["operations_used"], 5)


class DriftAndTamperTest(unittest.TestCase):
    def test_drift_refuses_before_a_child(self):
        def profile(repo: Path, home: Path) -> None:
            self.assertEqual(cli(repo, home, "configure", "--profile", "manual").returncode, 0)

        def identity(repo: Path, home: Path) -> None:
            path = home / "runs" / f"{ISSUE}.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            state["red"]["test"]["blob_sha256"] = "0" * 64
            path.write_text(json.dumps(state), encoding="utf-8")

        def moved_head(repo: Path, home: Path) -> None:
            commit(repo, "README.md", "# moved\n", "move head")

        for drift in (profile, identity, moved_head):
            with self.subTest(drift=drift.__name__), workspace() as tmp:
                repo = make_repo(Path(tmp))
                home = home_dir(Path(tmp))
                marker = Path(tmp) / "gate-one-ran"
                turbo_staged(repo, home, operations=5, gate1=marker_gate(marker))
                drift(repo, home)
                result = verify(repo, home)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                if drift is profile:
                    state = run_state(home)
                    self.assertEqual(state["counters"]["operations_used"], 1)
                    self.assertEqual(state["phase"], "gates")

    def test_a_tampered_gate_prefix_refuses_without_rerunning_it(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=10, gate2=["python3", "-c", "pass"])
            self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1").returncode, 0)
            self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", "2").returncode, 0)
            state = run_state(home)
            Path(str(state["gate_observations"][0]["output_path"])).unlink()
            result = verify(repo, home)
            after = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr.lower())
        self.assertEqual(after["gate_chain"], ["1", "2"])
        self.assertEqual(after["counters"]["operations_used"], 3)
        self.assertEqual(len(after["gate_observations"]), 2)

    def test_a_tampered_replay_refuses_without_reexecuting_it(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=10, gate2=["python3", "-c", "pass"])
            for gate in ("1", "2", "3"):
                self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", gate).returncode, 0)
            self.assertEqual(cli(repo, home, "replay", "--issue", ISSUE).returncode, 0)
            state = run_state(home)
            Path(str(state["replay"]["output_path"])).write_text("tampered\n", encoding="utf-8")
            before = len(list((home / "evidence" / ISSUE).glob("replay-*.txt")))
            result = verify(repo, home)
            after = run_state(home)
            now = len(list((home / "evidence" / ISSUE).glob("replay-*.txt")))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr.lower())
        self.assertEqual(before, now)
        self.assertEqual(after["counters"]["operations_used"], 5)


class BudgetAndTimeTest(unittest.TestCase):
    def test_the_bugfix_line_and_the_weekly_stop_refuse_a_feature_before_a_child(self):
        for spend in (165.0, 200.0):
            with self.subTest(spend=spend), workspace() as tmp:
                repo = make_repo(Path(tmp))
                home = home_dir(Path(tmp))
                marker = Path(tmp) / "gate-one-ran"
                turbo_staged(repo, home, operations=10, gate1=marker_gate(marker))
                self.assertEqual(spend_record(repo, home, spend).returncode, 0)
                result = verify(repo, home)
                state = run_state(home)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(marker.exists())
                self.assertEqual(state["stop_reason"], "budget")
                self.assertEqual(state["counters"]["operations_used"], 1)

    def test_an_expired_time_limit_refuses_before_a_child(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "gate-one-ran"
            turbo_staged(repo, home, operations=10, gate1=marker_gate(marker))
            path = home / "runs" / f"{ISSUE}.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            state["admitted_at"] = "2020-01-01T00:00:00Z"
            path.write_text(json.dumps(state), encoding="utf-8")
            result = verify(repo, home)
            after = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(marker.exists())
        self.assertEqual(after["stop_reason"], "not-ready")
        self.assertIn("time limit", (result.stdout + result.stderr).lower())
        self.assertEqual(after["counters"]["operations_used"], 1)


class PhaseTest(unittest.TestCase):
    def test_turbo_prompt_offers_the_single_verify_bundle(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5)
            result = cli(repo, home, "prompt", "--issue", ISSUE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"factory verify --issue {ISSUE}", result.stdout)
        self.assertNotIn(f"factory gate --issue {ISSUE}", result.stdout)

    def test_wrong_phase_is_refused_before_work(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
            before = run_state(home)
            result = verify(repo, home)
            after = run_state(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before["counters"], after["counters"])
        self.assertEqual(before["phase"], after["phase"])
        self.assertEqual(evidence_files(home), [])

    def test_a_stopped_run_is_refused(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            turbo_staged(repo, home, operations=5)
            self.assertEqual(cli(repo, home, "stop", "--issue", ISSUE, "--reason", "not-ready").returncode, 0)
            before = run_state(home)
            result = verify(repo, home)
            after = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before["counters"], after["counters"])
        self.assertEqual(after["phase"], "stopped")


if __name__ == "__main__":
    unittest.main()
