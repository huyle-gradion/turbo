import json
import unittest
from dataclasses import replace
from pathlib import Path

from support import (
    cli, commit_probe, config, git, home_dir, make_repo, prepare,
    red, run_state, spend_record, staged, to_green, to_red, workspace,
)

from factory.budget import attestation, week_key
from factory.budgetpolicy import BudgetPolicy, WeekSpend
from factory.errors import PolicyError


def policy(spend: float | None) -> BudgetPolicy:
    base = BudgetPolicy(timezone="UTC")
    if spend is None:
        return base
    week = week_key(base)
    return replace(
        base,
        weeks={week: WeekSpend(usd=spend, state="known", source="test export", recorded_at="2026-11-03T00:00:00Z")},
    )


def drop_current_week(home: Path) -> None:
    data = json.loads((home / "config.json").read_text(encoding="utf-8"))
    data["budget"]["weeks"] = {
        "2026-W01": {
            "usd": 12.5,
            "state": "known",
            "source": "old export",
            "recorded_at": "2026-01-05T00:00:00Z",
        }
    }
    (home / "config.json").write_text(json.dumps(data), encoding="utf-8")


class BudgetLineTest(unittest.TestCase):
    def test_feature_is_allowed_below_the_bugfix_line(self):
        for spend in (0.0, 12.5, 159.99):
            with self.subTest(spend=spend):
                position = attestation(policy(spend), "feature")
                self.assertEqual(position.usd, spend)

    def test_feature_is_refused_from_the_bugfix_line_to_the_weekly_stop(self):
        for spend in (160.0, 165.0, 199.99):
            with self.subTest(spend=spend):
                with self.assertRaises(PolicyError) as caught:
                    attestation(policy(spend), "feature")
                message = str(caught.exception)
                self.assertIn("only bug work remains admissible", message)
                self.assertIn("160.00", message)
                self.assertIn("200.00", message)
                self.assertNotIn("operator admits it as such", message)

    def test_bug_is_allowed_from_the_bugfix_line_to_the_weekly_stop(self):
        for spend in (159.99, 160.0, 165.0, 199.99):
            with self.subTest(spend=spend):
                position = attestation(policy(spend), "bug")
                self.assertEqual(position.usd, spend)

    def test_the_weekly_stop_refuses_every_kind(self):
        for kind in ("bug", "feature"):
            for spend in (200.0, 240.0):
                with self.subTest(kind=kind, spend=spend):
                    with self.assertRaises(PolicyError) as caught:
                        attestation(policy(spend), kind)
                    self.assertIn("weekly stop reached", str(caught.exception))

    def test_unknown_spend_stays_unpriced_for_both_kinds(self):
        for kind in ("bug", "feature"):
            with self.subTest(kind=kind):
                with self.assertRaises(PolicyError) as caught:
                    attestation(policy(None), kind)
                self.assertIn("UNPRICED", str(caught.exception))


class BudgetRecheckTest(unittest.TestCase):
    def test_a_new_weekly_stop_stops_an_ongoing_feature_run(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            self.assertEqual(spend_record(repo, home, 200.0).returncode, 0)
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("weekly stop", result.stderr.lower())
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["stop_reason"], "budget")
        self.assertEqual(state["gate_chain"], [])

    def test_a_new_bugfix_line_stops_an_ongoing_feature_run(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            self.assertEqual(spend_record(repo, home, 160.0).returncode, 0)
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("only bug work", result.stderr.lower())
        self.assertEqual(state["stop_reason"], "budget")

    def test_a_bug_run_continues_between_the_bugfix_line_and_the_weekly_stop(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home, spend=12.5)
            self.assertEqual(prepare(repo, home, kind="bug").returncode, 0)
            git(repo, "switch", "-q", "-c", "run-issue-7")
            commit_probe(repo, 0, "failing test")
            self.assertEqual(red(repo, home).returncode, 0)
            sha = commit_probe(repo, 42, "implementation")
            self.assertEqual(cli(repo, home, "stage", "--issue", "7", "--commit", sha).returncode, 0)
            self.assertEqual(spend_record(repo, home, 175.0).returncode, 0)
            result = cli(repo, home, "gate", "--issue", "7", "--gate", "1")
            state = run_state(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["gate_chain"], ["1"])

    def test_an_unknown_week_stops_work_in_progress(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            sha = commit_probe(repo, 42, "implementation")
            drop_current_week(home)
            result = cli(repo, home, "stage", "--issue", "7", "--commit", sha)
            state = run_state(home)
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNPRICED", result.stderr)
        self.assertEqual(state["stop_reason"], "budget")
        self.assertIsNone(state["expected_green_sha"])

    def test_resume_refuses_when_the_declared_position_reaches_the_weekly_stop(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_red(repo, home)
            self.assertEqual(spend_record(repo, home, 200.0).returncode, 0)
            result = cli(repo, home, "resume", "--issue", "7", "--pr", "none")
            entry = run_state(home)["resume_history"][-1]
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("budget" in reason for reason in entry["reasons"]), entry["reasons"])


class ManifestBudgetTest(unittest.TestCase):
    def test_manifest_keeps_the_admission_position_separate_from_the_current_one(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            self.assertEqual(spend_record(repo, home, 175.0).returncode, 0)
            result = cli(repo, home, "manifest", "--issue", "7")
            state = run_state(home)
            payload = json.loads(Path(str(state["manifest_path"])).read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = payload.get("budget_current")
        self.assertIsNotNone(current)
        self.assertEqual(payload["budget_admission"]["usd"], 12.5)
        self.assertEqual(current["usd"], 175.0)
        self.assertFalse(current["admissible"])
        self.assertIn("only bug work", current["refusal"])
        self.assertEqual(state["budget"]["usd"], 175.0)

    def test_manifest_marks_an_unpriced_current_week_instead_of_reusing_admission(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            drop_current_week(home)
            result = cli(repo, home, "manifest", "--issue", "7")
            state = run_state(home)
            payload = json.loads(Path(str(state["manifest_path"])).read_text(encoding="utf-8"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = payload.get("budget_current")
        self.assertIsNotNone(current)
        self.assertEqual(current["state"], "unknown")
        self.assertIsNone(current["usd"])
        self.assertFalse(current["admissible"])


if __name__ == "__main__":
    unittest.main()
