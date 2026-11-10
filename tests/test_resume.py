import unittest
from pathlib import Path

from support import cli, git, home_dir, make_repo, run_state, spend_record, to_green, to_red, workspace


def resume(repo: Path, home: Path, pr: str | None = None, extra_path: str | None = None):
    args = ["resume", "--issue", "7"]
    if pr is not None:
        args += ["--pr", pr]
    return cli(repo, home, *args, extra_path=extra_path)


class ResumeTest(unittest.TestCase):
    def test_default_pr_state_is_unknown_and_refuses(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            result = resume(repo, home)
            entry = run_state(home)["resume_history"][-1]
        self.assertEqual(result.returncode, 1)
        self.assertEqual(entry["verdict"], "refused")
        self.assertIn("pr-unknown", entry["reasons"])

    def test_pr_none_and_consistent_head_resumes_appends_history_without_gh(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            fake_bin = Path(tmp) / "fake-bin"
            fake_bin.mkdir()
            marker = Path(tmp) / "gh-called"
            gh = fake_bin / "gh"
            gh.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
            gh.chmod(0o755)
            first = resume(repo, home, "none", extra_path=str(fake_bin))
            second = resume(repo, home, "none", extra_path=str(fake_bin))
            state = run_state(home)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(len(state["resume_history"]), 2)
        for entry in state["resume_history"]:
            self.assertEqual(entry["verdict"], "consistent")
            self.assertEqual(entry["reasons"], [])
        self.assertEqual(state["counters"]["operations_used"], 1)
        self.assertFalse(marker.exists())

    def test_dirty_tree_refuses_and_preserves_work(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            (repo / "README.md").write_text("# uncommitted\n", encoding="utf-8")
            result = resume(repo, home, "none")
            entry = run_state(home)["resume_history"][-1]
            content = (repo / "README.md").read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertIn("working-tree-dirty", entry["reasons"])
        self.assertEqual(content, "# uncommitted\n")

    def test_head_mismatch_refuses(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            git(repo, "commit", "-q", "--allow-empty", "-m", "unrecorded")
            result = resume(repo, home, "none")
            entry = run_state(home)["resume_history"][-1]
        self.assertEqual(result.returncode, 1)
        self.assertIn("head-mismatch", entry["reasons"])

    def test_remote_ref_mismatch_refuses(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            git(repo, "switch", "-q", "main")
            git(repo, "commit", "-q", "--allow-empty", "-m", "other")
            other = git(repo, "rev-parse", "HEAD")
            git(repo, "switch", "-q", "run-issue-7")
            git(repo, "update-ref", "refs/remotes/origin/run-issue-7", other)
            result = resume(repo, home, "none")
            entry = run_state(home)["resume_history"][-1]
            local = git(repo, "rev-parse", "HEAD")
            red_sha = run_state(home)["red_sha"]
        self.assertEqual(result.returncode, 1)
        self.assertIn("remote-ref-mismatch", entry["reasons"])
        self.assertEqual(local, red_sha)

    def test_cancelled_lane_stays_stopped(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            self.assertEqual(cli(repo, home, "stop", "--issue", "7", "--reason", "cancelled").returncode, 0)
            result = resume(repo, home, "none")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["stop_reason"], "cancelled")

    def test_budget_stop_recovers_only_with_no_pr_and_keeps_counters(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            self.assertEqual(cli(repo, home, "stop", "--issue", "7", "--reason", "budget").returncode, 0)
            self.assertEqual(spend_record(repo, home, 20.0).returncode, 0)
            refused = resume(repo, home, "exists")
            refused_state = run_state(home)
            result = resume(repo, home, "none")
            state = run_state(home)
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(refused_state["phase"], "stopped")
        self.assertEqual(refused_state["stop_reason"], "budget")
        self.assertIn("pr-exists", refused_state["resume_history"][-1]["reasons"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "red")
        self.assertEqual(state["counters"]["operations_used"], 1)

    def test_local_verified_run_resumes_consistently(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            self.assertEqual(cli(repo, home, "manifest", "--issue", "7").returncode, 0)
            result = resume(repo, home, "none")
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(state["resume_history"][-1]["verdict"], "consistent")

    def test_missing_run_is_refused(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = resume(repo, home, "none")
        self.assertEqual(result.returncode, 2)

    def test_prepare_does_not_discard_a_mid_run_stop(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            self.assertEqual(cli(repo, home, "stop", "--issue", "7", "--reason", "budget").returncode, 0)
            result = cli(
                repo, home, "prepare", "--issue", "7", "--feature", "S-1", "--kind", "feature",
                "--model", "test-model", "--attest-model-account", "--time-limit", "60m",
                "--operation-limit", "20",
            )
            state = run_state(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state["phase"], "stopped")
        self.assertIsNotNone(state["red"])



if __name__ == "__main__":
    unittest.main()
