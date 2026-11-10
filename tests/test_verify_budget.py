"""Completed-run revalidation must stay read-only while the live budget still admits it."""

import json
import unittest
from pathlib import Path

from support import (
    cli, commit_probe, configure_turbo, evidence_files, git, home_dir,
    make_repo, prepare, red, run_state, snapshotted, spend_record, workspace,
)

ISSUE = "7"
RUN_STATE = ("runs", f"{ISSUE}.json")


def verify(repo: Path, home: Path, issue: str = ISSUE):
    return cli(repo, home, "verify", "--issue", issue)


def manifest_cli(repo: Path, home: Path, issue: str = ISSUE):
    return cli(repo, home, "manifest", "--issue", issue)


@snapshotted
def completed(repo: Path, home: Path, *, kind: str = "feature") -> None:
    configure_turbo(repo, home)
    admitted = prepare(repo, home, kind=kind, operations=5)
    assert admitted.returncode == 0, admitted.stdout + admitted.stderr
    git(repo, "switch", "-q", "-c", f"run-issue-{ISSUE}")
    commit_probe(repo, 0, "failing test")
    failed = red(repo, home)
    assert failed.returncode == 0, failed.stdout + failed.stderr
    sha = commit_probe(repo, 42, "implementation")
    staged = cli(repo, home, "stage", "--issue", ISSUE, "--commit", sha)
    assert staged.returncode == 0, staged.stdout + staged.stderr
    result = verify(repo, home)
    assert result.returncode == 0, result.stdout + result.stderr


def snapshot(home: Path) -> dict[str, object]:
    state = run_state(home)
    manifest = Path(str(state["manifest_path"]))
    run_path = home.joinpath(*RUN_STATE)
    return {
        "state": state,
        "manifest": manifest,
        "manifest_bytes": manifest.read_bytes(),
        "run_bytes": run_path.read_bytes(),
        "files": evidence_files(home),
    }


def rewrite_run(home: Path, update: dict[str, object]) -> bytes:
    path = home.joinpath(*RUN_STATE)
    state = json.loads(path.read_text(encoding="utf-8"))
    state.update(update)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path.read_bytes()


class CompletedSpendRefreshTest(unittest.TestCase):
    def test_repeated_spend_updates_below_the_threshold_leave_the_completed_snapshot_alone(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            before = snapshot(home)
            self.assertEqual(spend_record(repo, home, 20.0).returncode, 0)
            first = verify(repo, home)
            first_manifest = manifest_cli(repo, home)
            middle = snapshot(home)
            first_weeks = json.loads((home / "config.json").read_text(encoding="utf-8"))["budget"]["weeks"]
            self.assertEqual(spend_record(repo, home, 30.0).returncode, 0)
            second = verify(repo, home)
            manifest_again = manifest_cli(repo, home)
            after = snapshot(home)
            weeks = json.loads((home / "config.json").read_text(encoding="utf-8"))["budget"]["weeks"]
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(first_manifest.returncode, 0, first_manifest.stdout + first_manifest.stderr)
        self.assertEqual(before["manifest_bytes"], middle["manifest_bytes"])
        self.assertEqual(before["run_bytes"], middle["run_bytes"])
        self.assertEqual(before["files"], middle["files"])
        self.assertEqual(middle["state"]["budget"]["usd"], 12.5)
        self.assertEqual(middle["state"]["counters"], before["state"]["counters"])
        self.assertEqual(middle["state"]["phase"], "local-verified")
        self.assertIn(20.0, [item["usd"] for item in first_weeks.values()])
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(manifest_again.returncode, 0, manifest_again.stdout + manifest_again.stderr)
        self.assertEqual(before["manifest_bytes"], after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])
        self.assertEqual(before["files"], after["files"])
        self.assertEqual(after["state"]["budget"]["usd"], 12.5)
        self.assertEqual(after["state"]["counters"], before["state"]["counters"])
        self.assertIn(30.0, [item["usd"] for item in weeks.values()])


class CompletedTimeTest(unittest.TestCase):
    def test_an_aged_completed_run_revalidates_without_a_child_or_state_change(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            admitted = "2020-01-01T00:00:00Z"
            state = run_state(home)
            manifest = Path(str(state["manifest_path"]))
            aged_bytes = rewrite_run(home, {"admitted_at": admitted})
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["admitted_at"] = admitted
            manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            manifest_bytes = manifest.read_bytes()
            files_before = evidence_files(home)
            result = verify(repo, home)
            run_bytes = home.joinpath(*RUN_STATE).read_bytes()
            state = run_state(home)
            manifest_after = manifest.read_bytes()
            files_after = evidence_files(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(aged_bytes, run_bytes)
        self.assertEqual(manifest_bytes, manifest_after)
        self.assertEqual(files_before, files_after)
        self.assertEqual(state["phase"], "local-verified")
        self.assertIsNone(state["stop_reason"])


class CompletedRefusalTest(unittest.TestCase):
    def test_a_feature_at_the_bugfix_line_refuses_without_mutating_the_completed_run(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            before = snapshot(home)
            self.assertEqual(spend_record(repo, home, 160.0).returncode, 0)
            result = verify(repo, home)
            after = snapshot(home)
            future = prepare(repo, home, issue=8)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("bug-fix quota", result.stderr)
        self.assertEqual(before["manifest_bytes"], after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])
        self.assertEqual(before["files"], after["files"])
        self.assertEqual(after["state"]["phase"], "local-verified")
        self.assertIsNone(after["state"]["stop_reason"])
        self.assertEqual(after["state"]["counters"], before["state"]["counters"])
        self.assertEqual(future.returncode, 1, future.stdout + future.stderr)

    def test_a_bug_run_revalidates_at_the_bugfix_line_and_refuses_at_the_weekly_stop_read_only(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home, kind="bug")
            before = snapshot(home)
            self.assertEqual(spend_record(repo, home, 160.0).returncode, 0)
            line = verify(repo, home)
            middle = snapshot(home)
            self.assertEqual(spend_record(repo, home, 200.0).returncode, 0)
            result = verify(repo, home)
            after = snapshot(home)
        self.assertEqual(line.returncode, 0, line.stdout + line.stderr)
        self.assertEqual(before["manifest_bytes"], middle["manifest_bytes"])
        self.assertEqual(before["run_bytes"], middle["run_bytes"])
        self.assertEqual(before["files"], middle["files"])
        self.assertEqual(middle["state"]["budget"]["usd"], 12.5)
        self.assertEqual(middle["state"]["counters"], before["state"]["counters"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("weekly stop", result.stderr)
        self.assertEqual(before["manifest_bytes"], after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])
        self.assertEqual(before["files"], after["files"])
        self.assertEqual(after["state"]["phase"], "local-verified")
        self.assertIsNone(after["state"]["stop_reason"])
        self.assertEqual(after["state"]["counters"], before["state"]["counters"])

    def test_an_unpriced_week_refuses_as_policy_not_corruption(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            before = snapshot(home)
            path = home / "config.json"
            conf = json.loads(path.read_text(encoding="utf-8"))
            recorded = next(iter(conf["budget"]["weeks"].values()))
            conf["budget"]["weeks"] = {"2999-W01": recorded}
            path.write_text(json.dumps(conf, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = verify(repo, home)
            after = snapshot(home)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("UNPRICED", result.stderr)
        self.assertNotIn("corrupt", result.stderr.lower())
        self.assertNotIn("manifest", result.stderr.lower())
        self.assertEqual(before["manifest_bytes"], after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])

    def test_profile_drift_still_refuses_without_mutating_the_completed_run(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            before = snapshot(home)
            self.assertEqual(cli(repo, home, "configure", "--profile", "manual").returncode, 0)
            result = verify(repo, home)
            after = snapshot(home)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(before["manifest_bytes"], after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])
        self.assertEqual(before["files"], after["files"])


class CompletedIntegrityTest(unittest.TestCase):
    def test_a_tampered_manifest_still_refuses_and_is_not_rewritten(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            before = snapshot(home)
            manifest = before["manifest"]
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["green_sha"] = "0" * 40
            manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tampered_bytes = manifest.read_bytes()
            result = verify(repo, home)
            after = snapshot(home)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("mismatch", result.stderr)
        self.assertEqual(tampered_bytes, after["manifest_bytes"])
        self.assertEqual(before["run_bytes"], after["run_bytes"])

    def test_a_completed_run_without_a_manifest_records_gains_nothing(self):
        with workspace() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            completed(repo, home)
            state = run_state(home)
            manifest = Path(str(state["manifest_path"]))
            manifest.unlink()
            run_bytes = rewrite_run(home, {"manifest_path": None})
            result = verify(repo, home)
            run_after = home.joinpath(*RUN_STATE).read_bytes()
            manifest_exists = manifest.exists()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("manifest", result.stderr.lower())
        self.assertEqual(run_bytes, run_after)
        self.assertFalse(manifest_exists)


if __name__ == "__main__":
    unittest.main()
