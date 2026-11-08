"""Integration tests proving the four-stage disposable delivery approval lifecycle (Issue #62 AC3)."""
from __future__ import annotations

import json, tempfile, unittest
from pathlib import Path

from support_deliver import PROVENANCE_NOTE, run_delivery_lifecycle_demo


class DeliveryApprovalLifecycleTest(unittest.TestCase):
    def test_runnable_four_stage_disposable_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp) / "demo-evidence"
            summary = run_delivery_lifecycle_demo(evidence_dir)

            self.assertTrue(summary.get("success"))
            self.assertEqual(summary.get("provenance"), PROVENANCE_NOTE)
            self.assertTrue(summary.get("factory_revision"))

            stages = summary.get("stages", {})
            s1 = stages.get("stage_1_blocker", {})
            s2 = stages.get("stage_2_ineffective", {})
            s3 = stages.get("stage_3_verified", {})
            s4 = stages.get("stage_4_subsequent_stale", {})

            # 1. Blocker: scripted reviewer identifies finding; delivery rejects
            self.assertFalse(s1.get("delivery_approved"))
            self.assertIsNone(s1.get("approved_revision"))
            self.assertEqual(s1.get("status"), "changes-requested")
            self.assertEqual(s1.get("finding_status"), "open")

            # 2. Ineffective correction: reviewer claims fix, but reproducer executes and fails; delivery rejects
            self.assertFalse(s2.get("delivery_approved"))
            self.assertIsNone(s2.get("approved_revision"))
            self.assertTrue(s2.get("reproducer_executed"))
            self.assertFalse(s2.get("reproducer_ok"))
            self.assertEqual(s2.get("finding_status"), "open")
            self.assertEqual(s2.get("resolution_blocker"), "check-failed")
            self.assertFalse(any("revision binding" in b or "CI check" in b for b in s2.get("blockers", [])))
            s2_deliv = json.loads((evidence_dir / "stages" / "stage-2-ineffective" / "delivery-result.json").read_text(encoding="utf-8"))
            self.assertTrue(s2_deliv.get("ci_verified"))

            # 3. Verified correction: actual correction passes reproducer and checks; delivery APPROVES
            self.assertTrue(s3.get("delivery_approved"))
            self.assertEqual(s3.get("status"), "verified")
            self.assertEqual(s3.get("approved_revision"), s3.get("candidate_sha"))
            self.assertTrue(s3.get("reproducer_ok"))
            self.assertEqual(s3.get("finding_status"), "resolved")
            self.assertEqual(s3.get("reconciliation_history_rounds"), 3)

            # 4. Subsequent revision: candidate advances; stale approval reuse rejected
            self.assertFalse(s4.get("delivery_approved"))
            self.assertIsNone(s4.get("approved_revision"))
            self.assertEqual(s4.get("prior_approved_revision"), s3.get("candidate_sha"))

            # Retained snapshot inspection
            self.assertTrue((evidence_dir / "lifecycle-summary.json").is_file())
            for s_name in ("stage-1-blocker", "stage-2-ineffective", "stage-3-verified", "stage-4-subsequent-stale"):
                s_dir = evidence_dir / "stages" / s_name
                self.assertTrue((s_dir / "stage-summary.json").is_file(), f"missing stage-summary.json in {s_dir}")
                self.assertTrue((s_dir / "delivery-result.json").is_file(), f"missing delivery-result.json in {s_dir}")
                self.assertTrue((s_dir / "approval-gate.json").is_file(), f"missing approval-gate.json in {s_dir}")


if __name__ == "__main__":
    unittest.main()
