import tempfile
import unittest
from pathlib import Path

from support import cli, git, home_dir, make_repo, run_state, to_green


def replay_then_gates(repo: Path, home: Path) -> None:
    for gate in ("1", "2", "3"):
        result = cli(repo, home, "gate", "--issue", "7", "--gate", gate)
        assert result.returncode == 0, result.stdout + result.stderr
    result = cli(repo, home, "replay", "--issue", "7")
    assert result.returncode == 0, result.stdout + result.stderr


class GreenArtifactTest(unittest.TestCase):
    def test_green_refuses_a_deleted_red_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import staged
            staged(repo, home)
            replay_then_gates(repo, home)
            Path(str(run_state(home)["red"]["output_path"])).unlink()
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr.lower())
        self.assertEqual(state["phase"], "gates")
        self.assertIsNone(state["green"])

    def test_green_refuses_a_modified_red_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import staged
            staged(repo, home)
            replay_then_gates(repo, home)
            target = Path(str(run_state(home)["red"]["output_path"]))
            target.write_text("rewritten evidence\n", encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr.lower())
        self.assertEqual(state["phase"], "gates")

    def test_green_refuses_a_symlinked_gate_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import staged
            staged(repo, home)
            replay_then_gates(repo, home)
            target = Path(str(run_state(home)["gate_observations"][0]["output_path"]))
            copy = target.with_name("gate-copy.txt")
            copy.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(copy)
            result = cli(repo, home, "green", "--issue", "7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr.lower())

    def test_green_refuses_a_missing_replay_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import staged
            staged(repo, home)
            replay_then_gates(repo, home)
            Path(str(run_state(home)["replay"]["output_path"])).unlink()
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr.lower())
        self.assertEqual(state["phase"], "gates")

    def test_green_refuses_an_artifact_path_outside_the_private_home(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            from support import staged
            staged(repo, home)
            replay_then_gates(repo, home)
            state = run_state(home)
            inside = Path(str(state["red"]["output_path"]))
            outside = Path(tmp) / "outside-red.txt"
            outside.write_bytes(inside.read_bytes())
            state["red"]["output_path"] = str(outside)
            (home / "runs" / "7.json").write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private home", result.stderr.lower())


class RepeatedGreenTest(unittest.TestCase):
    def test_repeated_green_revalidates_the_staged_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            sha = to_green(repo, home)
            git(repo, "commit", "-q", "--allow-empty", "-m", "moving head")
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("match", result.stderr.lower())
        self.assertEqual(state["phase"], "green")
        self.assertEqual(state["green_sha"], sha)

    def test_repeated_green_refuses_a_dirty_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            (repo / "README.md").write_text("# dirty\n", encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("dirty", result.stderr.lower())
        self.assertEqual(state["phase"], "green")

    def test_repeated_green_refuses_when_a_gate_artifact_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            target = Path(str(run_state(home)["gate_observations"][0]["output_path"]))
            target.write_text("tampered\n", encoding="utf-8")
            result = cli(repo, home, "green", "--issue", "7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr.lower())


class ManifestArtifactTest(unittest.TestCase):
    def test_manifest_refuses_a_modified_gate_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            target = Path(str(run_state(home)["gate_observations"][0]["output_path"]))
            target.write_text("tampered\n", encoding="utf-8")
            result = cli(repo, home, "manifest", "--issue", "7")
            manifest = home / "evidence" / "7" / "manifest.json"
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr.lower())
        self.assertFalse(manifest.exists())

    def test_manifest_refuses_a_corrupt_existing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            target = home / "evidence" / "7" / "manifest.json"
            target.write_text("{not json", encoding="utf-8")
            result = cli(repo, home, "manifest", "--issue", "7")
            content = target.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corrupt", result.stderr.lower())
        self.assertEqual(content, "{not json")

    def test_manifest_refuses_a_partial_existing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            target = home / "evidence" / "7" / "manifest.json"
            target.write_text('{"schema": 1}', encoding="utf-8")
            result = cli(repo, home, "manifest", "--issue", "7")
            content = target.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(content, '{"schema": 1}')

    def test_manifest_refuses_a_symlinked_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            elsewhere = Path(tmp) / "elsewhere.json"
            elsewhere.write_text("{}\n", encoding="utf-8")
            target = home / "evidence" / "7" / "manifest.json"
            target.symlink_to(elsewhere)
            result = cli(repo, home, "manifest", "--issue", "7")
            content = elsewhere.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr.lower())
        self.assertEqual(content, "{}\n")

    def test_manifest_refuses_to_recreate_a_deleted_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            assert cli(repo, home, "manifest", "--issue", "7").returncode == 0
            target = Path(str(run_state(home)["manifest_path"]))
            target.unlink()
            result = cli(repo, home, "manifest", "--issue", "7")
            exists = target.exists()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr.lower())
        self.assertFalse(exists)


if __name__ == "__main__":
    unittest.main()
