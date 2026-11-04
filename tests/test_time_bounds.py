import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from support import cli, commit_probe, config, git, home_dir, make_repo, prepare, red, run_state, staged

from factory import gates as gates_module
from factory.errors import PolicyError
from factory.paths import resolve_paths
from factory.runner import ChildResult


class ChildTimeoutTest(unittest.TestCase):
    def test_gate_child_timeout_is_capped_by_the_remaining_admitted_time(self):
        slow = ["python3", "-c", "import time; time.sleep(9)"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, gate1=slow)
            assert prepare(repo, home, time_limit="5s").returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode == 0
            started = time.monotonic()
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            elapsed = time.monotonic() - started
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertLess(elapsed, 8.0)
        self.assertEqual(state["gate_observations"][-1]["exit"], 124)

    def test_elapsed_time_is_rechecked_after_the_child_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, time_limit="10s").returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            assert red(repo, home).returncode == 0
            sha = commit_probe(repo, 42, "implementation")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode == 0
            state = run_state(home)
            stale = datetime.now(timezone.utc) - timedelta(seconds=6)
            state["admitted_at"] = stale.isoformat(timespec="seconds").replace("+00:00", "Z")
            (home / "runs" / "7.json").write_text(json.dumps(state), encoding="utf-8")
            paths = resolve_paths(str(repo), str(home))

            def slow_child(*_args, **_kwargs):
                time.sleep(4.6)
                return ChildResult(("python3", "-c", "pass"), 0, "ok\n", 4600)

            with mock.patch.object(gates_module.runner, "execute", side_effect=slow_child):
                with self.assertRaises(PolicyError):
                    gates_module.execute(paths, 7, "1")
            final = run_state(home)
        self.assertEqual(final["phase"], "stopped")
        self.assertEqual(final["stop_reason"], "not-ready")
        self.assertIn("time limit", final["stop_detail"].lower())
        self.assertEqual(final["gate_chain"], [])


if __name__ == "__main__":
    unittest.main()
