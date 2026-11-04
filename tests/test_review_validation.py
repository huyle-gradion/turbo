"""Review fixes: protected-path validity, command argv identity, replay provenance."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from support import (
    cli, commit, config, evidence_files, git, home_dir, make_repo, marker_gate,
    run_state, spend_record, staged, staged_turbo, to_green,
)

from factory import config as config_module
from factory.paths import resolve_paths

ISSUE = "7"


def state_path(home: Path) -> Path:
    return home / "runs" / f"{ISSUE}.json"


def doctor_check(repo: Path, home: Path, name: str) -> tuple[int, dict]:
    result = cli(repo, home, "doctor", "--json")
    checks = json.loads(result.stdout)
    return result.returncode, next(item for item in checks if item["name"] == name)


def forge_replay(home: Path, state: dict, provenance: str = "attested-import") -> Path:
    directory = home / "evidence" / ISSUE
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / f"replay-{str(state['expected_green_sha'])[:12]}.txt"
    artifact.write_text("forged replay output\n", encoding="utf-8")
    state["replay"] = {
        "head_sha": state["expected_green_sha"],
        "argv": state["red"]["argv"],
        "selector": state["red"]["test"]["selector"],
        "exit": 0,
        "output_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "output_path": str(artifact),
        "at": "2026-01-01T00:00:00Z",
        "duration_ms": 1,
        "test_blob_sha256": state["red"]["test"]["blob_sha256"],
        "gate_digest": state["gate_digest"],
        "provenance": provenance,
    }
    state_path(home).write_text(json.dumps(state), encoding="utf-8")
    return artifact


GOLDEN_CONFIG = {
    "schema": 1,
    "repo": "/synthetic/repo",
    "home": "/synthetic/home",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "execution_profile": "manual",
    "native_turbo_attestation": None,
    "budget": {
        "weekly_usd": 200.0,
        "bugfix_usd": 160.0,
        "stop_usd": 200.0,
        "timezone": "UTC",
        "source": "fixture",
        "weeks": {},
    },
    "gates": {
        "1": {
            "kind": "command",
            "label": "gate one",
            "argv": ["python3", "-c", "pass"],
            "timeout_seconds": 900,
            "declaration": "host-denies-writes",
        },
        "2": {
            "kind": "command",
            "label": "gate two",
            "argv": ["python3", "-m", "unittest"],
            "timeout_seconds": 900,
            "declaration": "not-applicable",
        },
        "3": {
            "kind": "protected-paths",
            "label": "gate three",
            "paths": ["AGENTS.md", "./guards/", "docs/my spec.md"],
            "timeout_seconds": 900,
            "declaration": "not-applicable",
        },
    },
}

GOLDEN_DIGEST = "3d1edb5fc3d060c2df93205dc8192aa2e41ce361caa009b105cb7b14508f75cb"


class ProtectedEntryBoundaryTest(unittest.TestCase):
    def test_configure_rejects_unusable_protected_entries(self):
        entries = ["", " ", " docs/spec.md", "docs/spec.md ", "\tguards", "/etc/passwd", "../secrets", "docs/../../x"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            before = (home / "config.json").read_bytes()
            for entry in entries:
                with self.subTest(entry=entry):
                    result = cli(repo, home, "configure", "--gate", "3", "--protected", entry)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual((home / "config.json").read_bytes(), before)

    def test_a_stored_padded_protected_path_refuses_load_before_a_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "gate-one-ran"
            staged(repo, home, gate1=marker_gate(marker))
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["3"]["paths"] = ["AGENTS.md", " docs/spec.md"]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            before = run_state(home)
            doctor_code, config_check = doctor_check(repo, home, "config")
            result = cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1")
            after = run_state(home)
            marker_ran = marker.exists()
        self.assertEqual(doctor_code, 1)
        self.assertFalse(config_check["ok"])
        self.assertIn("whitespace", config_check["detail"])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("whitespace", result.stderr)
        self.assertFalse(marker_ran)
        self.assertEqual(after["counters"], before["counters"])
        self.assertEqual(after["gate_observations"], before["gate_observations"])

    def test_valid_entries_keep_their_spelling_and_still_catch_changes(self):
        entries = ["./guards/", "docs/my spec.md"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home, protected=entries)
            commit(repo, "guards/policy.py", "RULE = 1\n", "guard change")
            commit(repo, "docs/my spec.md", "spec\n", "spec change")
            head = git(repo, "rev-parse", "HEAD")
            assert cli(repo, home, "stage", "--issue", ISSUE, "--commit", head).returncode == 0
            for gate in ("1", "2"):
                assert cli(repo, home, "gate", "--issue", ISSUE, "--gate", gate).returncode == 0
            result = cli(repo, home, "gate", "--issue", ISSUE, "--gate", "3")
            state = run_state(home)
            stored = json.loads((home / "config.json").read_text(encoding="utf-8"))["gates"]["3"]["paths"]
            digest = config_module.digest(config_module.load(resolve_paths(str(repo), str(home))))
            evidence = Path(str(state["gate_observations"][-1]["output_path"])).read_text(encoding="utf-8")
        self.assertEqual(stored, entries)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(digest, state["gate_digest"])
        self.assertIn("guards/policy.py", evidence)
        self.assertIn("docs/my spec.md", evidence)

    def test_valid_entries_keep_the_recorded_digest(self):
        conf = config_module.Config.from_dict(GOLDEN_CONFIG)
        self.assertEqual(conf.gates["3"].paths, ("AGENTS.md", "./guards/", "docs/my spec.md"))
        self.assertEqual(config_module.digest(conf), GOLDEN_DIGEST)


class CommandArgvBoundaryTest(unittest.TestCase):
    def test_configure_rejects_a_blank_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            before = (home / "config.json").read_bytes()
            result = cli(repo, home, "configure", "--gate", "1", "--declare-host-deny", "--", " ")
            after = (home / "config.json").read_bytes()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("executable", result.stderr)
        self.assertEqual(after, before)

    def test_a_stored_blank_executable_refuses_load_before_a_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "gate-one-ran"
            staged(repo, home, gate1=marker_gate(marker))
            payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
            payload["gates"]["1"]["argv"] = [" "]
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            before = run_state(home)
            doctor_code, config_check = doctor_check(repo, home, "config")
            result = cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1")
            after = run_state(home)
            marker_ran = marker.exists()
        self.assertEqual(doctor_code, 1)
        self.assertFalse(config_check["ok"])
        self.assertIn("blank", config_check["detail"])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("blank", result.stderr)
        self.assertFalse(marker_ran)
        self.assertEqual(after["counters"], before["counters"])
        self.assertEqual(after["gate_observations"], before["gate_observations"])

    def test_gate_command_data_arguments_are_preserved_exactly(self):
        args = [" ", "A B", "  padded  "]
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            marker = Path(tmp) / "argv.json"
            script = "import json, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))"
            argv = [sys.executable, "-c", script, str(marker), *args]
            staged(repo, home, gate1=argv)
            stored = json.loads((home / "config.json").read_text(encoding="utf-8"))["gates"]["1"]["argv"]
            result = cli(repo, home, "gate", "--issue", ISSUE, "--gate", "1")
            state = run_state(home)
            observed = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(stored, argv)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(observed, args)
        self.assertEqual(state["gate_observations"][-1]["argv"], argv)


class ReplayProvenanceTest(unittest.TestCase):
    def test_replay_does_not_reuse_an_unobserved_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home)
            forged = forge_replay(home, run_state(home))
            before = run_state(home)
            result = cli(repo, home, "replay", "--issue", ISSUE)
            after = run_state(home)
            artifacts = sorted((home / "evidence" / ISSUE).glob("replay-*.txt"))
            forged_text = forged.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("executing", result.stdout)
        self.assertEqual(after["replay"]["provenance"], "observed-helper-execution")
        self.assertNotEqual(after["replay"]["output_path"], str(forged))
        self.assertEqual(forged_text, "forged replay output\n")
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(after["counters"]["operations_used"], before["counters"]["operations_used"] + 1)

    def test_verify_reruns_an_unobserved_replay_instead_of_reusing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged_turbo(repo, home, operations=5)
            forged = forge_replay(home, run_state(home))
            result = cli(repo, home, "verify", "--issue", ISSUE)
            after = run_state(home)
            forged_text = forged.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("replay: executing", result.stdout)
        self.assertEqual(after["phase"], "local-verified")
        self.assertEqual(after["replay"]["provenance"], "observed-helper-execution")
        self.assertNotEqual(after["replay"]["output_path"], str(forged))
        self.assertEqual(forged_text, "forged replay output\n")
        self.assertEqual(after["counters"]["operations_used"], 5)

    def test_a_completed_run_refuses_a_tampered_replay_without_state_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_green(repo, home)
            state = run_state(home)
            self.assertEqual(state["replay"]["provenance"], "observed-helper-execution")
            state["replay"]["provenance"] = "attested-import"
            state_path(home).write_text(json.dumps(state), encoding="utf-8")
            before_bytes = state_path(home).read_bytes()
            before_files = evidence_files(home)
            replay = cli(repo, home, "replay", "--issue", ISSUE)
            green = cli(repo, home, "green", "--issue", ISSUE)
            after_bytes = state_path(home).read_bytes()
            after_files = evidence_files(home)
        self.assertNotEqual(replay.returncode, 0)
        self.assertNotIn("executing", replay.stdout)
        self.assertNotIn("not re-executed", replay.stdout)
        self.assertNotEqual(green.returncode, 0)
        self.assertEqual(after_bytes, before_bytes)
        self.assertEqual(after_files, before_files)


def manifest_payload(home: Path) -> dict:
    state = run_state(home)
    return json.loads(Path(str(state["manifest_path"])).read_text(encoding="utf-8"))


class MidRunSpendTest(unittest.TestCase):
    """The admission position is fixed at prepare; later spend belongs only to budget_current."""

    def test_manual_flow_keeps_the_admission_position_when_spend_rises_before_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged(repo, home, spend=12.5)
            self.assertEqual(spend_record(repo, home, 50.0).returncode, 0)
            self.assertEqual(cli(repo, home, "resume", "--issue", ISSUE, "--pr", "none").returncode, 0)
            for gate in ("1", "2", "3"):
                self.assertEqual(cli(repo, home, "gate", "--issue", ISSUE, "--gate", gate).returncode, 0)
            self.assertEqual(cli(repo, home, "replay", "--issue", ISSUE).returncode, 0)
            self.assertEqual(cli(repo, home, "green", "--issue", ISSUE).returncode, 0)
            result = cli(repo, home, "manifest", "--issue", ISSUE)
            payload = manifest_payload(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(payload["budget_admission"]["usd"], 12.5)
        self.assertEqual(payload["budget_current"]["usd"], 50.0)

    def test_native_turbo_verify_keeps_the_admission_position_when_spend_rises_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            staged_turbo(repo, home, operations=5, spend=12.5)
            self.assertEqual(spend_record(repo, home, 50.0).returncode, 0)
            result = cli(repo, home, "verify", "--issue", ISSUE)
            payload = manifest_payload(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(payload["budget_admission"]["usd"], 12.5)
        self.assertEqual(payload["budget_current"]["usd"], 50.0)


class ManifestRepositoryStateTest(unittest.TestCase):
    """Sealing and revalidating both require the repository that green recorded."""

    MUTATIONS = {
        "new commit": (
            lambda repo: commit(repo, "notes.txt", "notes\n", "late change"),
            "does not match the recorded commit",
        ),
        "dirty tree": (
            lambda repo: (repo / "scratch.txt").write_text("scratch\n", encoding="utf-8"),
            "working tree is dirty",
        ),
        "wrong branch": (
            lambda repo: git(repo, "switch", "-q", "-c", "other"),
            "current branch is not",
        ),
    }

    def assert_refused(self, result) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_changed_repository_is_refused_before_the_first_seal(self):
        for label, (mutate, fragment) in self.MUTATIONS.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                repo = make_repo(Path(tmp))
                home = home_dir(Path(tmp))
                to_green(repo, home)
                mutate(repo)
                result = cli(repo, home, "manifest", "--issue", ISSUE)
                state = run_state(home)
                sealed = (home / "evidence" / ISSUE / "manifest.json").exists()
            self.assert_refused(result)
            self.assertIn(fragment, result.stderr.lower())
            self.assertEqual(state["phase"], "green")
            self.assertIsNone(state["manifest_path"])
            self.assertFalse(sealed)

    def test_a_changed_repository_is_refused_on_revalidation(self):
        for label, (mutate, fragment) in self.MUTATIONS.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                repo = make_repo(Path(tmp))
                home = home_dir(Path(tmp))
                to_green(repo, home)
                self.assertEqual(cli(repo, home, "manifest", "--issue", ISSUE).returncode, 0)
                manifest = Path(str(run_state(home)["manifest_path"]))
                before = manifest.read_bytes()
                mutate(repo)
                result = cli(repo, home, "manifest", "--issue", ISSUE)
                state = run_state(home)
                after = manifest.read_bytes()
            self.assert_refused(result)
            self.assertIn(fragment, result.stderr.lower())
            self.assertEqual(before, after)
            self.assertEqual(state["phase"], "local-verified")
            self.assertEqual(state["manifest_path"], str(manifest))


if __name__ == "__main__":
    unittest.main()
