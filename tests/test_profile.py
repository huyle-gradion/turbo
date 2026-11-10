import json
import tempfile
import unittest
from pathlib import Path

from support import (
    cli, config, config_json, configure_turbo, home_dir, make_repo,
    prepare, spend_record, to_ready,
)


class ProfileConfigurationTest(unittest.TestCase):
    def test_native_turbo_needs_the_explicit_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            saved = config_json(home)
            self.assertEqual(saved["execution_profile"], "manual")
            self.assertIsNone(saved.get("native_turbo_attestation"))
            result = cli(repo, home, "configure", "--profile", "native-turbo")
            saved = config_json(home)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(saved["execution_profile"], "manual")
            self.assertIn("attest", result.stderr.lower())
            # The attestation without the profile is refused too.
            result = cli(repo, home, "configure", "--attest-native-turbo", "antigravity-native")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(saved["execution_profile"], "manual")

    def test_manual_reset_removes_the_old_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            gate = config_json(home)["gates"]["1"]
            self.assertEqual(gate["declaration"], "host-policy-operator-probed")
            self.assertFalse(gate["declare_host_deny"])
            result = cli(repo, home, "configure", "--profile", "manual")
            saved = config_json(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(saved["execution_profile"], "manual")
        self.assertIsNone(saved["native_turbo_attestation"])

    def test_turbo_refuses_to_claim_a_host_write_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", "antigravity-native")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            attestation = config_json(home)["native_turbo_attestation"]
            self.assertEqual(config_json(home)["execution_profile"], "native-turbo")
            self.assertEqual(attestation["host"], "antigravity-native")
            self.assertEqual(attestation["declaration"], "host-policy-operator-probed")
            self.assertIn("operator", attestation["statement"].lower())
            result = cli(repo, home, "configure", "--gate", "1", "--declare-host-deny", "--", "python3", "-c", "pass")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("1", saved["gates"])

    def test_switching_to_turbo_with_a_host_deny_gate_one_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            gate = config_json(home)["gates"]["1"]
            self.assertEqual(gate["declaration"], "host-denies-writes")
            self.assertTrue(gate["declare_host_deny"])
            result = cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", "antigravity-native")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(saved["execution_profile"], "manual")


class DigestTest(unittest.TestCase):
    def test_doctor_reports_drift_after_a_profile_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
            spend_record(repo, home, 20.0)
            passed = cli(repo, home, "doctor")
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            self.assertEqual(cli(repo, home, "configure", "--profile", "manual").returncode, 0)
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 1)
        self.assertIn("digest", (result.stdout + result.stderr).lower())

    def test_doctor_reports_drift_after_a_budget_policy_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            self.assertEqual(prepare(repo, home).returncode, 0)
            payload = config_json(home)
            payload["budget"]["stop_usd"] = 180.0
            (home / "config.json").write_text(json.dumps(payload), encoding="utf-8")
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 1)
        self.assertIn("digest", (result.stdout + result.stderr).lower())


class RunSnapshotTest(unittest.TestCase):
    def test_old_run_fixture_defaults_to_manual(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            path = home / "runs" / "7.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            state.pop("execution_profile", None)
            state.pop("profile_attestation", None)
            state.pop("verified_by", None)
            path.write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "status", "--issue", "7", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["execution_profile"], "manual")
        self.assertIsNone(payload["profile_attestation"])
        self.assertEqual(payload["verified_by"], "manual")

    def test_unknown_profile_is_a_clean_corrupt_state_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            to_ready(repo, home)
            path = home / "runs" / "7.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            state["execution_profile"] = "mystery"
            path.write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(result.returncode, 2)
        self.assertIn("profile", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_native_turbo_run_without_attestation_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
            path = home / "runs" / "7.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(state["execution_profile"], "native-turbo")
            self.assertEqual(state["profile_attestation"]["host"], "antigravity-native")
            self.assertEqual(state["verified_by"], "manual")
            state["profile_attestation"] = None
            path.write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(result.returncode, 2)
        self.assertIn("attestation", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
