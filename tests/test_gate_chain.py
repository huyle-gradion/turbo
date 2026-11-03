import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from support import (
    cli, commit, commit_probe, config, git, home_dir, make_repo,
    prepare, red, run_state, staged, to_green,
)


class GateChainTest(unittest.TestCase):
    def test_gate_order_is_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            second = cli(repo, home, "gate", "--issue", "7", "--gate", "2")
            third = cli(repo, home, "gate", "--issue", "7", "--gate", "3")
            first = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            second_ok = cli(repo, home, "gate", "--issue", "7", "--gate", "2")
        self.assertNotEqual(second.returncode, 0)
        self.assertNotEqual(third.returncode, 0)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second_ok.returncode, 0, second_ok.stdout + second_ok.stderr)

    def test_gate_three_catches_a_committed_protected_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            commit(repo, "AGENTS.md", "policy\n", "policy change")
            head = git(repo, "rev-parse", "HEAD")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", head).returncode == 0
            for gate in ("1", "2"):
                assert cli(repo, home, "gate", "--issue", "7", "--gate", gate).returncode == 0
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "3")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["counters"]["repairs_used"], 1)
        self.assertEqual(state["gate_attempts"][-1]["gate"], "3")
        self.assertEqual(state["gate_chain"], [])

    def test_repair_cap_is_total_and_does_not_reset(self):
        failing = [sys.executable, "-c", "import sys; sys.exit(1)"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home, gate1=failing)
            exits = [cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode for _ in range(3)]
            state = run_state(home)
            fourth = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
        self.assertEqual(exits, [1, 1, 1])
        self.assertEqual(state["counters"]["repairs_used"], 3)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["stop_reason"], "retry-cap")
        self.assertNotEqual(fourth.returncode, 0)

    def test_gate_config_drift_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            marker = Path(tmp) / "drift-marker"
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["2"]["argv"] = [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("digest", result.stderr.lower())
        self.assertFalse(marker.exists())

    def test_green_does_not_execute_the_gate_ladder(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            one = Path(tmp) / "g1"
            two = Path(tmp) / "g2"
            staged(
                repo, home,
                gate1=[sys.executable, "-c", f"open({str(one)!r}, 'w').write('x')"],
                gate2=[sys.executable, "-c", f"open({str(two)!r}, 'w').write('x')"],
            )
            result = cli(repo, home, "green", "--issue", "7")
            self.assertFalse(one.exists())
            self.assertFalse(two.exists())
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode, 0)
            self.assertTrue(one.exists())
            self.assertFalse(two.exists())
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "2").returncode, 0)
            self.assertTrue(two.exists())
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "3").returncode, 0)
            replay_attempt = cli(repo, home, "green", "--issue", "7")
            self.assertNotEqual(replay_attempt.returncode, 0)
            self.assertEqual(cli(repo, home, "replay", "--issue", "7").returncode, 0)
            files_before_green = len(list((home / "evidence" / "7").glob("replay-*.txt")))
            final = cli(repo, home, "green", "--issue", "7")
            files_after_green = len(list((home / "evidence" / "7").glob("replay-*.txt")))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(final.returncode, 0, final.stdout + final.stderr)
        self.assertEqual(files_before_green, files_after_green)

    def test_gates_and_green_do_not_create_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            before = git(repo, "rev-parse", "HEAD")
            for gate in ("1", "2", "3"):
                assert cli(repo, home, "gate", "--issue", "7", "--gate", gate).returncode == 0
            assert cli(repo, home, "replay", "--issue", "7").returncode == 0
            assert cli(repo, home, "green", "--issue", "7").returncode == 0
            after = git(repo, "rev-parse", "HEAD")
        self.assertEqual(before, after)

    def test_gate_rerun_adds_evidence_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode, 0)
            first_path = Path(str(run_state(home)["gate_observations"][0]["output_path"]))
            first_bytes = first_path.read_bytes()
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode, 0)
            state = run_state(home)
            self.assertEqual(first_path.read_bytes(), first_bytes)
            self.assertEqual(len(state["gate_observations"]), 2)
        self.assertNotEqual(Path(str(state["gate_observations"][1]["output_path"])), first_path)

    def test_gate_timeout_is_bounded(self):
        slow = [sys.executable, "-c", "import time; time.sleep(5)"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert cli(repo, home, "configure", "--gate", "1", "--declare-host-deny", "--timeout", "1", "--", *slow).returncode == 0
            assert prepare(repo, home).returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode == 0
            started = time.monotonic()
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 1)
        self.assertLess(elapsed, 10)

    def test_gate_passes_argv_without_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "argv.txt"
            argv = [
                sys.executable,
                "-c",
                "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])",
                str(marker),
                "A B",
            ]
            staged(repo, home, gate1=argv)
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            written = marker.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(written, "A B")

    def test_manifest_refuses_after_gate_configuration_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["2"]["argv"] = ["python3", "-c", "pass"]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            result = cli(repo, home, "manifest", "--issue", "7")
            manifest = home / "evidence" / "7" / "manifest.json"
            exists = manifest.exists()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(exists)


    def test_docs_gate_failure_cannot_become_local_verified(self):
        docs_gate = [sys.executable, "-c", "import sys; print('QC001'); sys.exit(1)"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home, gate2=docs_gate)
            self.assertEqual(cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode, 0)
            failed = cli(repo, home, "gate", "--issue", "7", "--gate", "2")
            green_attempt = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
            evidence = Path(str(state["gate_observations"][-1]["output_path"])).read_text(encoding="utf-8")
        self.assertEqual(failed.returncode, 1)
        self.assertIn("QC001", evidence)
        self.assertNotEqual(green_attempt.returncode, 0)
        self.assertNotEqual(state["phase"], "local-verified")
        self.assertIsNone(state["green"])



if __name__ == "__main__":
    unittest.main()
