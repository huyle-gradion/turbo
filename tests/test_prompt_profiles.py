"""The generated prompt must match the operator's declared execution profile."""

import tempfile
import unittest
from pathlib import Path

from support import (
    cli, configure_turbo, home_dir, make_repo, prepare, run_state, staged_turbo,
    to_ready,
)

ISSUE = "7"
OLD_MANUAL_APPROVAL = "Each command below needs the operator's own approval"
NATIVE_HOST = "native host permissions"
HUMAN_DECISION = "Human QC and merge stay human decisions."


class ManualPromptTest(unittest.TestCase):
    def test_manual_prompt_keeps_the_operator_approval_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            result = cli(repo, home, "prompt", "--issue", ISSUE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(OLD_MANUAL_APPROVAL, result.stdout)
        self.assertIn(HUMAN_DECISION, result.stdout)
        self.assertNotIn(NATIVE_HOST, result.stdout)


class NativeTurboPromptTest(unittest.TestCase):
    def test_turbo_ready_prompt_uses_the_selected_host_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home).returncode, 0)
            result = cli(repo, home, "prompt", "--issue", ISSUE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        self.assertNotIn(OLD_MANUAL_APPROVAL, output)
        self.assertIn(NATIVE_HOST, output)
        self.assertIn("no redundant per-command approval", output)
        self.assertIn("Never automate Enter", output)
        self.assertIn("change host permissions", output)
        self.assertIn("grants no new authority", output)
        self.assertIn(HUMAN_DECISION, output)
        self.assertIn("never creates commits or branches", output)
        self.assertIn("never calls a model or network service", output)

    def test_turbo_local_verified_prompt_keeps_the_native_wording(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged_turbo(repo, home, operations=5)
            gates = cli(repo, home, "prompt", "--issue", ISSUE)
            self.assertEqual(gates.returncode, 0, gates.stdout + gates.stderr)
            self.assertNotIn(OLD_MANUAL_APPROVAL, gates.stdout)
            self.assertIn(NATIVE_HOST, gates.stdout)
            self.assertIn(f"factory verify --issue {ISSUE}", gates.stdout)
            verified = cli(repo, home, "verify", "--issue", ISSUE)
            state = run_state(home)
            result = cli(repo, home, "prompt", "--issue", ISSUE)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertEqual(state["phase"], "local-verified")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(OLD_MANUAL_APPROVAL, result.stdout)
        self.assertIn(NATIVE_HOST, result.stdout)
        self.assertIn("Evidence is local-verified.", result.stdout)


if __name__ == "__main__":
    unittest.main()
