import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import ROOT, cli, config, git, home_dir, make_repo, private_mode


class HelpTest(unittest.TestCase):
    def test_help_lists_the_operator_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            result = cli(repo, home_dir(Path(tmp)), "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("init", "configure", "doctor", "status", "spend", "prepare", "red", "stage", "replay", "gate", "green", "manifest", "prompt", "stop", "resume"):
            self.assertIn(name, result.stdout)

    def test_launcher_runs_from_an_unrelated_directory(self):
        launcher = ROOT / "bin" / "factory"
        self.assertTrue(os.access(launcher, os.X_OK), "bin/factory must be executable")
        with tempfile.TemporaryDirectory() as tmp:
            shadow = Path(tmp) / "factory"
            shadow.mkdir()
            (shadow / "__init__.py").write_text("raise RuntimeError('shadow package used')\n", encoding="utf-8")
            result = subprocess.run([str(launcher), "--help"], cwd=tmp, capture_output=True, text=True, timeout=60)
            env = dict(os.environ, PATH=f"{ROOT / 'bin'}{os.pathsep}{os.environ['PATH']}")
            on_path = subprocess.run(["factory", "--help"], cwd=tmp, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("prepare", result.stdout)
        self.assertEqual(on_path.returncode, 0, on_path.stderr)


class InitTest(unittest.TestCase):
    def test_rejects_a_non_git_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "plain"
            plain.mkdir()
            result = cli(plain, home_dir(Path(tmp)), "init")
        self.assertEqual(result.returncode, 2)
        self.assertIn("git", result.stderr.lower())

    def test_rejects_a_subdirectory_of_a_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            (repo / "sub").mkdir()
            result = cli(repo / "sub", home_dir(Path(tmp)), "init")
        self.assertEqual(result.returncode, 2)

    def test_rejects_home_inside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            result = cli(repo, repo / ".factory", "init")
            self.assertFalse((repo / ".factory").exists())
        self.assertEqual(result.returncode, 2)
        self.assertIn("inside", result.stderr)

    def test_rejects_a_symlink_that_resolves_inside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            alias = Path(tmp) / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            result = cli(repo, alias / "state", "init")
            self.assertFalse((repo / "state").exists())
        self.assertEqual(result.returncode, 2)
        self.assertIn("inside", result.stderr)

    def test_creates_private_runtime_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            first = cli(repo, home, "init")
            binding = json.loads((home / "config.json").read_text(encoding="utf-8"))
            second = cli(repo, home, "init")
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(binding["repo"], str(repo.resolve()))
            self.assertEqual(private_mode(home), 0o700)
            self.assertEqual(private_mode(home / "config.json"), 0o600)

    def test_binding_another_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            other = Path(tmp) / "other"
            other.mkdir()
            (other / "README.md").write_text("other\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=other, check=True)
            subprocess.run(["git", "config", "user.email", "x@example.test"], cwd=other, check=True)
            subprocess.run(["git", "config", "user.name", "X"], cwd=other, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=other, check=True)
            subprocess.run(["git", "add", "README.md"], cwd=other, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=other, check=True)
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(other, home, "init")
            configure = cli(other, home, "configure", "--timezone", "UTC")
        self.assertEqual(result.returncode, 2)
        self.assertIn("bound", result.stderr.lower())
        self.assertEqual(configure.returncode, 2)


class SafetyTest(unittest.TestCase):
    def test_state_directory_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            outside = Path(tmp) / "outside"
            outside.mkdir()
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            (home / "runs").rmdir()
            (home / "runs").symlink_to(outside, target_is_directory=True)
            result = cli(repo, home, "status", "--issue", "7")
            self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_corrupt_state_is_a_clean_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            (home / "runs" / "7.json").write_text("{not json", encoding="utf-8")
            result = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(result.returncode, 2)
        self.assertIn("corrupt", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_config_is_not_silently_recreated(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            (home / "config.json").unlink()
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            self.assertFalse((home / "config.json").exists())
        self.assertEqual(result.returncode, 2)
        self.assertIn("config", result.stderr.lower())

    def test_unknown_issue_is_refused_without_creating_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "status", "--issue", "99")
            self.assertFalse((home / "runs" / "99.json").exists())
        self.assertEqual(result.returncode, 2)

    def test_factory_never_writes_into_the_product_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(cli(repo, home, "doctor").returncode, 0)
            self.assertEqual(git(repo, "status", "--porcelain"), "")
            self.assertFalse((repo / ".factory").exists())
            self.assertTrue((home / "runs").is_dir())


if __name__ == "__main__":
    unittest.main()
