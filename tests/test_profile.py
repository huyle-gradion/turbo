import json
import tempfile
import unittest
from pathlib import Path

from support import (
    cli, config, config_json, configure_turbo, home_dir, make_repo,
    prepare, run_state, spend_record, to_ready,
)


class ProfileConfigurationTest(unittest.TestCase):
    def test_default_profile_is_manual_with_no_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            saved = config_json(home)
        self.assertEqual(saved["execution_profile"], "manual")
        self.assertIsNone(saved.get("native_turbo_attestation"))

    def test_native_turbo_needs_the_explicit_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "configure", "--profile", "native-turbo")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(saved["execution_profile"], "manual")
        self.assertIn("attest", result.stderr.lower())

    def test_attestation_without_the_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "configure", "--attest-native-turbo", "antigravity-native")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(saved["execution_profile"], "manual")

    def test_turbo_records_the_operator_host_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            self.assertEqual(cli(repo, home, "init").returncode, 0)
            result = cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", "antigravity-native")
            saved = config_json(home)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(saved["execution_profile"], "native-turbo")
        self.assertEqual(saved["native_turbo_attestation"]["host"], "antigravity-native")
        self.assertEqual(saved["native_turbo_attestation"]["declaration"], "host-policy-operator-probed")
        self.assertIn("operator", saved["native_turbo_attestation"]["statement"].lower())

    def test_manual_reset_removes_the_old_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
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
            self.assertEqual(cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", "antigravity-native").returncode, 0)
            result = cli(repo, home, "configure", "--gate", "1", "--declare-host-deny", "--", "python3", "-c", "pass")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("1", saved["gates"])

    def test_switching_to_turbo_with_a_host_deny_gate_one_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            result = cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", "antigravity-native")
            saved = config_json(home)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(saved["execution_profile"], "manual")

    def test_manual_gate_one_keeps_the_host_deny_declaration_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            saved = config_json(home)
        self.assertEqual(saved["gates"]["1"]["declaration"], "host-denies-writes")
        self.assertTrue(saved["gates"]["1"]["declare_host_deny"])

    def test_turbo_gate_one_records_the_operator_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            saved = config_json(home)
        self.assertEqual(saved["gates"]["1"]["declaration"], "host-policy-operator-probed")
        self.assertFalse(saved["gates"]["1"]["declare_host_deny"])


class DigestTest(unittest.TestCase):
    def test_doctor_still_passes_after_a_new_weekly_spend_declaration(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
            spend_record(repo, home, 20.0)
            result = cli(repo, home, "doctor")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_doctor_reports_drift_after_a_profile_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
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
    def test_prepare_snapshots_the_profile_and_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            configure_turbo(repo, home)
            self.assertEqual(prepare(repo, home, operations=5).returncode, 0)
            state = run_state(home)
        self.assertEqual(state["execution_profile"], "native-turbo")
        self.assertEqual(state["profile_attestation"]["host"], "antigravity-native")
        self.assertEqual(state["verified_by"], "manual")

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
            state["profile_attestation"] = None
            path.write_text(json.dumps(state), encoding="utf-8")
            result = cli(repo, home, "status", "--issue", "7")
        self.assertEqual(result.returncode, 2)
        self.assertIn("attestation", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
