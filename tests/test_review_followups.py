import json
import unittest
from pathlib import Path

from support import (
    cli, commit, commit_probe, config, git, home_dir, make_repo, prepare,
    run_state, staged, to_ready, workspace,
)

from factory import gitio


def gates_and_replay(repo: Path, home: Path) -> None:
    for gate in ("1", "2", "3"):
        result = cli(repo, home, "gate", "--issue", "7", "--gate", gate)
        assert result.returncode == 0, result.stdout + result.stderr
    result = cli(repo, home, "replay", "--issue", "7")
    assert result.returncode == 0, result.stdout + result.stderr


class PathEncodingTest(unittest.TestCase):
    def test_gate_three_catches_a_non_ascii_protected_file(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home, protected=["docs/é.md", "guards"])
            commit(repo, "docs/é.md", "policy\n", "unicode policy change")
            head = git(repo, "rev-parse", "HEAD")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", head).returncode == 0
            assert cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode == 0
            assert cli(repo, home, "gate", "--issue", "7", "--gate", "2").returncode == 0
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "3")
            state = run_state(home)
            evidence = Path(str(state["gate_observations"][-1]["output_path"])).read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertIn("docs/é.md", evidence)

    def test_gate_three_catches_a_renamed_protected_file(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            commit(repo, "guards/policy.py", "RULE = 1\n", "protected file")
            staged(repo, home, protected=["guards"])
            git(repo, "mv", "guards/policy.py", "policy_moved.py")
            git(repo, "commit", "-q", "-m", "rename the guard")
            head = git(repo, "rev-parse", "HEAD")
            assert cli(repo, home, "stage", "--issue", "7", "--commit", head).returncode == 0
            assert cli(repo, home, "gate", "--issue", "7", "--gate", "1").returncode == 0
            assert cli(repo, home, "gate", "--issue", "7", "--gate", "2").returncode == 0
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "3")
            state = run_state(home)
            evidence = Path(str(state["gate_observations"][-1]["output_path"])).read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertIn("guards/policy.py", evidence)

    def test_status_paths_keep_non_ascii_and_both_sides_of_a_rename(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            commit(repo, "guards/policy.py", "RULE = 1\n", "protected file")
            git(repo, "mv", "guards/policy.py", "policy_moved.py")
            (repo / "docs").mkdir()
            (repo / "docs" / "é.md").write_text("draft\n", encoding="utf-8")
            paths = gitio.dirty_paths(repo)
        self.assertIn("policy_moved.py", paths)
        self.assertIn("guards/policy.py", paths)
        self.assertIn("docs/é.md", paths)


class PromptFollowupTest(unittest.TestCase):
    def test_prompt_offers_no_gate_four_after_the_chain_is_complete(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            gates_and_replay(repo, home)
            result = cli(repo, home, "prompt", "--issue", "7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("--gate 4", result.stdout)
        self.assertNotIn("factory replay", result.stdout)
        self.assertIn("factory green", result.stdout)

    def test_restaging_clears_the_old_replay_and_prompt_asks_again(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            gates_and_replay(repo, home)
            commit_probe(repo, 41, "second implementation")
            head = git(repo, "rev-parse", "HEAD")
            restaged = cli(repo, home, "stage", "--issue", "7", "--commit", head)
            state = run_state(home)
            prompt = cli(repo, home, "prompt", "--issue", "7")
        self.assertEqual(restaged.returncode, 0, restaged.stdout + restaged.stderr)
        self.assertIsNone(state.get("replay"))
        self.assertIn("factory replay", prompt.stdout)


class RecoveryDeadEndTest(unittest.TestCase):
    def test_exhausted_operation_limit_is_marked_superseded_not_resumable(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            assert prepare(repo, home, operations=1).returncode == 0
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            from support import red
            assert red(repo, home).returncode == 0
            assert cli(repo, home, "stop", "--issue", "7", "--reason", "not-ready").returncode == 0
            result = cli(repo, home, "resume", "--issue", "7", "--pr", "none")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "superseded")
        self.assertIn("new issue", state["stop_detail"].lower())
        self.assertEqual(state["counters"]["operations_used"], 1)

    def test_gate_configuration_drift_is_marked_superseded_with_instructions(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            assert cli(repo, home, "stop", "--issue", "7", "--reason", "not-ready").returncode == 0
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["2"]["argv"] = ["python3", "-c", "pass"]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            result = cli(repo, home, "resume", "--issue", "7", "--pr", "none")
            state = run_state(home)
            prompt = cli(repo, home, "prompt", "--issue", "7")
            entry = state["resume_history"][-1]
        self.assertEqual(result.returncode, 1)
        self.assertEqual(state["stop_reason"], "superseded")
        self.assertIn("new issue", state["stop_detail"].lower())
        self.assertIn("lane-stopped", entry["reasons"])
        self.assertNotIn("factory resume", prompt.stdout)
        self.assertNotIn("factory prepare", prompt.stdout)

    def test_prompt_never_offers_prepare_for_a_mid_run_stop(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import to_red
            to_red(repo, home)
            assert cli(repo, home, "stop", "--issue", "7", "--reason", "not-ready").returncode == 0
            result = cli(repo, home, "prompt", "--issue", "7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("factory prepare", result.stdout)
        self.assertNotIn("re-prepare", result.stdout)
        self.assertIn("resume", result.stdout)


class AdmissionInputTest(unittest.TestCase):
    def test_blank_feature_is_refused_before_writing_state(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = prepare(repo, home, feature="   ")
            exists = (home / "runs" / "7.json").exists()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(exists)

    def test_blank_model_is_refused_before_writing_state(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = prepare(repo, home, model="")
            exists = (home / "runs" / "7.json").exists()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(exists)

    def test_detached_head_is_refused_before_writing_state(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            git(repo, "switch", "--detach", "-q")
            result = prepare(repo, home)
            exists = (home / "runs" / "7.json").exists()
        self.assertEqual(result.returncode, 2)
        self.assertIn("branch", result.stderr.lower())
        self.assertFalse(exists)

    def test_empty_stop_detail_leaves_reloadable_state(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            stopped = cli(repo, home, "stop", "--issue", "7", "--reason", "cancelled", "--detail", "")
            status = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)


class ProvenanceTest(unittest.TestCase):
    def test_green_refuses_attested_red_provenance(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            gates_and_replay(repo, home)
            state = run_state(home)
            state["red"]["provenance"] = "attested-import"
            (home / "runs" / "7.json").write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
            after = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("observed", result.stderr.lower())
        self.assertIsNone(after["green"])

    def test_green_refuses_a_replay_with_a_different_selector(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            gates_and_replay(repo, home)
            state = run_state(home)
            state["replay"]["selector"] = "Other.test"
            (home / "runs" / "7.json").write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
            after = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(after["green"])

    def test_manifest_refuses_a_replay_with_a_different_selector(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            gates_and_replay(repo, home)
            assert cli(repo, home, "green", "--issue", "7").returncode == 0
            state = run_state(home)
            state["replay"]["selector"] = "Other.test"
            (home / "runs" / "7.json").write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "manifest", "--issue", "7")
            manifest = home / "evidence" / "7" / "manifest.json"
        self.assertEqual(result.returncode, 1)
        self.assertFalse(manifest.exists())

    def test_manifest_records_the_expected_red_marker(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green_sha = staged(repo, home)
            gates_and_replay(repo, home)
            assert cli(repo, home, "green", "--issue", "7").returncode == 0
            assert cli(repo, home, "manifest", "--issue", "7").returncode == 0
            state = run_state(home)
            payload = json.loads(Path(str(state["manifest_path"])).read_text(encoding="utf-8"))
        self.assertTrue(to_green_sha)
        self.assertEqual(payload["red"].get("expect"), "AssertionError")
        self.assertEqual(state["red"].get("expect"), "AssertionError")


if __name__ == "__main__":
    unittest.main()
