import hashlib
import json
import unittest
from pathlib import Path

from support import (
    cli, commit, commit_probe, git, home_dir, make_repo,
    private_mode, red, run_state, staged, to_green, to_ready, workspace,
)


class FlowTest(unittest.TestCase):
    def test_full_flow_reaches_local_verified_idempotently(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            sha = to_green(repo, home)
            repeat = cli(repo, home, "green", "--issue", "7")
            before = run_state(home)
            result = cli(repo, home, "manifest", "--issue", "7")
            state = run_state(home)
            manifest_path = Path(str(state["manifest_path"]))
            digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            written = json.loads(manifest_path.read_text(encoding="utf-8"))
            mode = private_mode(manifest_path)
            second = cli(repo, home, "manifest", "--issue", "7")
            after = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            manifests = list(manifest_path.parent.glob("manifest*.json"))
        self.assertEqual(repeat.returncode, 0, repeat.stdout + repeat.stderr)
        self.assertEqual(before["green_sha"], sha)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(digest, after)
        self.assertEqual(len(manifests), 1)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(state["green_sha"], sha)
        self.assertNotEqual(state["red_sha"], state["green_sha"])
        self.assertEqual(before["phase"], "green")
        self.assertEqual(state["gate_chain"], ["1", "2", "3"])
        self.assertEqual(state["red"]["test"]["blob_sha256"], state["green"]["test_blob_sha256"])
        self.assertEqual(written["issue"], 7)
        self.assertEqual(written["red_sha"], state["red_sha"])
        self.assertEqual(written["green_sha"], sha)
        self.assertEqual(written["gate_digest"], state["gate_digest"])
        self.assertEqual(len(written["evidence"]), 5)
        self.assertEqual(written["phase"], "local-verified")
        self.assertEqual(written["replay"]["argv"], state["red"]["argv"])
        self.assertEqual(written["replay"]["head_sha"], sha)
        self.assertEqual(written["provenance"]["red"], "observed-helper-execution")
        self.assertEqual(written["provenance"]["replay"], "observed-helper-execution")
        self.assertEqual(written["provenance"]["gates"], ["observed-helper-execution"])
        self.assertIn("local-verified", written["provenance"]["green"])
        self.assertIn("not an independent QC approval", written["approval"])
        self.assertIn("not used", written["provenance"]["capture_ingest"])
        self.assertEqual(mode, 0o600)

    def test_red_rejects_a_passing_test(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 42, "already passes")
            result = red(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "not-ready")
        self.assertIsNone(state["red"])
        self.assertEqual(state["phase"], "stopped")

    def test_red_rejects_a_wrong_failure_reason(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit(repo, "tests/failure.txt", "x\n", "failure probe")
            result = red(repo, home, expect="AssertionError", command="python3 -c \"import sys; print('WRONG'); sys.exit(3)\"", test="tests/failure.txt")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "not-ready")
        self.assertIsNone(state["red"])

    def test_red_marker_is_language_agnostic(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit(repo, "tests/failure.txt", "x\n", "failure probe")
            result = red(repo, home, expect="BOOM", command="python3 -c \"import sys; print('BOOM'); sys.exit(3)\"", test="tests/failure.txt")
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["phase"], "red")
        self.assertEqual(state["red"]["test"]["file"], "tests/failure.txt")

    def test_red_requires_a_clean_committed_test_snapshot(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_probe.py").write_text("print('draft')\n", encoding="utf-8")
            result = red(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(state["red"])

    def test_red_test_must_be_committed_at_head(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            (repo / "tests" / "test_probe.py").write_text("import unittest\n", encoding="utf-8")
            result = red(repo, home)
            state = run_state(home)
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(state["red"])

    def test_red_and_green_must_be_different_commits(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            self.assertEqual(red(repo, home).returncode, 0)
            red_sha = run_state(home)["red_sha"]
            result = cli(repo, home, "stage", "--issue", "7", "--commit", str(red_sha))
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["phase"], "red")
        self.assertIsNone(state["expected_green_sha"])

    def test_green_refuses_a_dirty_working_tree(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            (repo / "README.md").write_text("# dirty\n", encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["phase"], "gates")



if __name__ == "__main__":
    unittest.main()
