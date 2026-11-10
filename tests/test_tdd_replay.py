import hashlib
import unittest
from pathlib import Path

from support import (
    PROBE_TEST, cli, commit, commit_probe, config, git, home_dir, make_repo,
    prepare, red, run_state, staged, workspace,
)

SLOW_WHEN_FIXED = (
    "python3 -c \"import pathlib, time; "
    "time.sleep(4.2 if '42' in pathlib.Path('probe_impl.py').read_text() else 0); "
    "print('AssertionError'); raise SystemExit(1)\""
)


class ReplayTest(unittest.TestCase):
    def test_green_requires_a_recorded_replay_of_the_red_command(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            sha = staged(repo, home)
            for gate in ("1", "2", "3"):
                assert cli(repo, home, "gate", "--issue", "7", "--gate", gate).returncode == 0
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
            replay = cli(repo, home, "replay", "--issue", "7")
            green = cli(repo, home, "green", "--issue", "7")
            after = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("replay", result.stderr.lower())
        self.assertEqual(state["phase"], "gates")
        self.assertIsNone(state["green"])
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)
        self.assertEqual(after["phase"], "green")
        self.assertEqual(after["green_sha"], sha)
        self.assertEqual(after["replay"]["exit"], 0)

    def test_replay_records_the_exact_red_argv_and_test_identity(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            before = run_state(home)["counters"]["operations_used"]
            result = cli(repo, home, "replay", "--issue", "7")
            state = run_state(home)
            record = state.get("replay")
            self.assertIsNotNone(record)
            output = Path(record["output_path"])
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            second = cli(repo, home, "replay", "--issue", "7")
            files = list((home / "evidence" / "7").glob("replay-*.txt"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, 1)
        self.assertEqual(state["counters"]["operations_used"], 2)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(len(files), 1)
        self.assertIn("not re-executed", second.stdout)
        self.assertEqual(record["argv"], state["red"]["argv"])
        self.assertEqual(record["selector"], state["red"]["test"]["selector"])
        self.assertEqual(record["test_blob_sha256"], state["red"]["test"]["blob_sha256"])
        self.assertEqual(record["gate_digest"], state["gate_digest"])
        self.assertEqual(record["head_sha"], state["expected_green_sha"])
        self.assertEqual(record["exit"], 0)
        self.assertEqual(record["provenance"], "observed-helper-execution")
        self.assertEqual(record["output_sha256"], digest)

    def test_replay_timeout_is_recorded_and_never_passes(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(prepare(repo, home, time_limit="5s").returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            first = red(repo, home, command=SLOW_WHEN_FIXED)
            sha = commit_probe(repo, 42, "implementation")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode == 0
            result = cli(repo, home, "replay", "--issue", "7")
            state = run_state(home)
            record = state.get("replay")
            text = Path(record["output_path"]).read_text(encoding="utf-8") if record else ""
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(result.returncode, 1)
        self.assertIsNotNone(record)
        self.assertEqual(record["exit"], 124)
        self.assertIn("timed out", text)

    def test_replay_execution_failure_is_recorded_and_never_passes(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(prepare(repo, home).returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            (repo / "tools").mkdir()
            script = repo / "tools" / "probe.sh"
            script.write_text("#!/bin/sh\necho AssertionError\nexit 1\n", encoding="utf-8")
            script.chmod(0o755)
            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_probe.py").write_text(PROBE_TEST, encoding="utf-8")
            git(repo, "add", "tools/probe.sh", "tests/test_probe.py")
            git(repo, "update-index", "--chmod=+x", "tools/probe.sh")
            git(repo, "commit", "-q", "-m", "failing test")
            first = red(repo, home, command="./tools/probe.sh", test="tests/test_probe.py")
            commit(repo, "probe_impl.py", "def answer():\n    return 42\n", "implementation")
            git(repo, "rm", "-q", "tools/probe.sh")
            git(repo, "commit", "-q", "-m", "drop the probe runner")
            sha = git(repo, "rev-parse", "HEAD")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode == 0
            result = cli(repo, home, "replay", "--issue", "7")
            state = run_state(home)
            record = state.get("replay")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(result.returncode, 1)
        self.assertIsNotNone(record)
        self.assertEqual(record["exit"], 127)

    def test_replay_refuses_a_dirty_tree(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            (repo / "README.md").write_text("# dirty\n", encoding="utf-8")
            result = cli(repo, home, "replay", "--issue", "7")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("dirty", result.stderr.lower())
        self.assertIsNone(state.get("replay"))

    def test_replay_refuses_a_moved_head(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            git(repo, "commit", "-q", "--allow-empty", "-m", "new head")
            result = cli(repo, home, "replay", "--issue", "7")
        self.assertEqual(result.returncode, 1)
        self.assertIn("staged", result.stderr.lower())

    def test_stage_refuses_a_commit_that_does_not_descend_from_the_red_commit(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            state = run_state(home)
            red_sha = state["red_sha"]
            base_sha = state["base_sha"]
            staged_sha = state["expected_green_sha"]
            git(repo, "reset", "--hard", "-q", base_sha)
            commit_probe(repo, 0, "rewritten failing test")
            rewritten = commit_probe(repo, 43, "rewritten history")
            result = cli(repo, home, "stage", "--issue", "7", "--commit", rewritten)
            after = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("red commit", result.stderr.lower())
        self.assertNotEqual(rewritten, red_sha)
        self.assertEqual(after["expected_green_sha"], staged_sha)


if __name__ == "__main__":
    unittest.main()
