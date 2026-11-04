import json
import tempfile
import unittest
from pathlib import Path

from support import cli, config, git, home_dir, make_repo, prepare, run_state, spend_record, to_ready


class AdmissionTest(unittest.TestCase):
    def test_prepare_without_config_is_refused_without_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            (home / "config.json").unlink()
            result = prepare(repo, home)
            self.assertFalse((home / "runs" / "7.json").exists())
        self.assertEqual(result.returncode, 2)
        self.assertIn("config", result.stderr.lower())

    def test_missing_gates_stop_admission_instead_of_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            self.assertEqual(spend_record(repo, home, 12.5).returncode, 0)
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["stop_reason"], "missing")
        self.assertNotEqual(state["phase"], "ready")

    def test_unknown_spend_is_unpriced_and_stops_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, spend=None)
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "budget")
        self.assertEqual(state["budget"]["state"], "unknown")
        self.assertIsNone(state["budget"]["usd"])
        self.assertIn("UNPRICED", result.stdout + result.stderr)

    def test_known_spend_admits_a_ready_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, spend=12.5)
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "ready")
        self.assertEqual(state["budget"]["state"], "known")
        self.assertEqual(state["budget"]["usd"], 12.5)
        self.assertEqual(state["counters"]["operations_used"], 0)
        self.assertEqual(state["counters"]["repairs_used"], 0)
        self.assertEqual(len(state["gate_digest"]), 64)
        self.assertTrue(state["admitted_at"].endswith("Z"))

    def test_bug_quota_leaves_only_bug_work_between_the_two_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, spend=165)
            bug = prepare(repo, home, kind="bug")
            state = run_state(home)
        self.assertEqual(bug.returncode, 0, bug.stdout + bug.stderr)
        self.assertEqual(state["kind"], "bug")
        self.assertEqual(state["phase"], "ready")

    def test_weekly_stop_blocks_every_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, spend=200)
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "budget")

    def test_gate_one_requires_an_explicit_host_deny_declaration(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            self.assertEqual(cli(repo, home, "configure", "--timezone", "UTC").returncode, 0)
            result = cli(repo, home, "configure", "--gate", "1", "--", "python3", "-c", "pass")
            saved = json.loads((home / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("1", saved["gates"])

    def test_model_account_attestation_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = prepare(repo, home, attest=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("attest", result.stderr.lower())

    def test_invalid_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = prepare(repo, home, time_limit="soon")
            missing = prepare(repo, home, operations=0)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(missing.returncode, 2)

    def test_dirty_tree_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            (repo / "README.md").write_text("# uncommitted\n", encoding="utf-8")
            result = prepare(repo, home)
            self.assertFalse((home / "runs" / "7.json").exists())
        self.assertEqual(result.returncode, 2)

    def test_existing_run_branch_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            git(repo, "branch", "run-issue-7")
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "missing")

    def test_second_prepare_on_a_ready_run_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            result = prepare(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state["phase"], "ready")


if __name__ == "__main__":
    unittest.main()
