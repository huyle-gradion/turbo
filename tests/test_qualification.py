"""Tests for protected repository qualification harness (#67)."""
from __future__ import annotations

import json, os, shutil, tempfile, unittest
from pathlib import Path
from typing import Any

from factory.qualification import (
    DISPOSABLE_REPO_ALLOWLIST, build_parent_evidence_index,
    check_credentials_and_capabilities, check_hosted_authorization,
    run_hosted_qualification, run_offline_qualification,
)
from test_deliver_checks import _DisposableGitHubServer


class QualificationSafetyAndCapabilityTest(unittest.TestCase):
    def test_hosted_authorization_guards(self) -> None:
        """Reject unallowlisted repositories and missing live enablement without mutation."""
        # 1. Disabled live qualification
        ok, msg = check_hosted_authorization("huyle-gradion/turbo-qual-67", live_enabled=False)
        self.assertFalse(ok)
        self.assertIn("hosted-qualification-disabled", msg)

        # 2. Disallowed repository slug
        ok, msg = check_hosted_authorization("huyle-gradion/other-repo", live_enabled=True)
        self.assertFalse(ok)
        self.assertIn("repo-disallowed", msg)

        # 3. Allowlisted repo with explicit live enablement
        ok, msg = check_hosted_authorization("huyle-gradion/turbo-qual-67", live_enabled=True)
        self.assertTrue(ok)
        self.assertEqual(msg, "")

        # 4. run_hosted_qualification without enablement produces blocked result and never qualifies
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = Path(tmp) / "ev"
            res = run_hosted_qualification(
                "huyle-gradion/turbo-qual-67", ev_dir, live_enabled=False,
                integrator_token="tok1", competitor_token="tok2",
            )
            self.assertEqual(res["status"], "blocked")
            self.assertEqual(res["outcome"], "unavailable")
            self.assertFalse(res["qualified"])
            self.assertTrue(any("hosted-qualification-disabled" in b for b in res["blockers"]))

    def test_credential_and_capability_detection(self) -> None:
        """Detect missing tokens and 403 on branch protection read (Administration: Read-only gap)."""
        # 1. Missing credentials
        ok, prot, blockers = check_credentials_and_capabilities(
            "http://127.0.0.1:9999", "huyle-gradion/turbo-qual-67", "feature/demo",
            integrator_token=None, competitor_token="tok",
        )
        self.assertFalse(ok)
        self.assertTrue(any("missing-credentials" in b for b in blockers))

        # 2. Token present, but branch protection read returns 403 (Administration: Read-only gap)
        with _DisposableGitHubServer(owner="huyle-gradion", repo="turbo-qual-67", protection_status=403) as gh:
            ok, prot, blockers = check_credentials_and_capabilities(
                gh.base_url, "huyle-gradion/turbo-qual-67", "feature/demo",
                integrator_token="valid-tok", competitor_token="valid-tok2",
            )
            self.assertFalse(ok)
            self.assertTrue(any("unavailable-protection-capability" in b for b in blockers))

        # 3. run_hosted_qualification detects capability gap, retains blocked result, qualified=False
        with _DisposableGitHubServer(owner="huyle-gradion", repo="turbo-qual-67", protection_status=403) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "huyle-gradion/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-tok", competitor_token="valid-tok2",
                    base_url=gh.base_url,
                )
                self.assertEqual(res["status"], "blocked")
                self.assertEqual(res["outcome"], "unavailable")
                self.assertFalse(res["qualified"])
                self.assertTrue(any("unavailable-protection-capability" in b for b in res["blockers"]))


class QualificationOfflineExecutionTest(unittest.TestCase):
    def test_offline_qualification_scenarios_and_evidence(self) -> None:
        """Execute all six parent #24 scenarios through actual A+B implementation and verify evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = Path(tmp) / "ev"
            summary = run_offline_qualification(ev_dir)

            self.assertEqual(summary["status"], "preparation-complete")
            self.assertFalse(summary["qualified"], "Qualification cannot be claimed until hosted proof runs")
            self.assertEqual(summary["mode"], "offline-simulated")
            self.assertTrue(summary["simulated"])

            scenarios = summary["scenarios"]
            self.assertIn("confirmed_landing", scenarios)
            self.assertIn("prereq_missing_and_denied", scenarios)
            self.assertIn("competing_base_rejection", scenarios)
            self.assertIn("renewed_verification_after_base_change", scenarios)
            self.assertIn("concurrency_and_uncertain_reconciliation", scenarios)
            self.assertIn("wrong_target_rejected", scenarios)

            # Assert main was preserved
            wt = scenarios["wrong_target_rejected"]
            self.assertEqual(wt["main_sha_before"], wt["main_sha_after"])
            self.assertNotEqual(wt["main_sha_before"], "unknown")

            # Check parent index
            index = summary["parent_evidence_index"]
            for ac_id in ("AC1", "AC2", "AC3", "AC4", "AC5", "AC6"):
                self.assertIn(ac_id, index)
                entry = index[ac_id]
                self.assertEqual(entry["hosted_proof_status"], "PENDING")
                self.assertTrue(len(entry["scenarios"]) >= 1)
                self.assertTrue(len(entry["artifact_paths"]) >= 1)
                for ap in entry["artifact_paths"]:
                    self.assertTrue(Path(ap).exists(), f"Artifact path {ap} does not exist")


if __name__ == "__main__":
    unittest.main()
