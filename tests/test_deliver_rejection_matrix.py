"""Tests proving the delivery rejection matrix and exact-candidate control (Issue #62 AC1)."""
from __future__ import annotations

import json, os, shutil, tempfile, unittest
from pathlib import Path

from factory import deliver as deliver_module
from factory.paths import atomic_json
from support import ROOT
from support_deliver import setup_disposable_delivery_context
from test_deliver import _run_deliver


class DeliveryRejectionMatrixTest(unittest.TestCase):
    def test_rejection_matrix_12_combinations_and_positive_control(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = setup_disposable_delivery_context(root)
            try:
                # 1. Fully valid positive control
                ctx.restore_valid_evidence()
                r_ok = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(
                    (r_ok.status, r_ok.verified, r_ok.delivery_approved, r_ok.approval_outcome, r_ok.approved_revision, r_ok.candidate_sha, r_ok.base_sha, r_ok.blockers),
                    ("verified", True, True, "approved", ctx.cand_sha, ctx.cand_sha, ctx.base_sha, []),
                )
                self.assertEqual(
                    (r_ok.child["verified"], r_ok.child["delivery_approved"], r_ok.child["approval_outcome"], r_ok.child["approved_revision"], r_ok.child["candidate_sha"], r_ok.child["base_sha"]),
                    (True, True, "approved", ctx.cand_sha, ctx.cand_sha, ctx.base_sha),
                )
                self.assertEqual(
                    (r_ok.child["pr"]["verified"], r_ok.child["pr"]["delivery_approved"], r_ok.child["pr"]["approved_revision"], r_ok.child["pr"]["head_sha"], r_ok.child["pr"]["base_sha"]),
                    (True, True, ctx.cand_sha, ctx.cand_sha, ctx.base_sha),
                )

                # Positive control through the real CLI driver
                cli_res, cli_payload = _run_deliver(ctx.repo, ctx.home, ctx.asana.base_url, ctx.gh.base_url, agy_bin=str(ctx.builder_agy))
                self.assertEqual(cli_res.returncode, 0, cli_res.stdout + cli_res.stderr)
                self.assertEqual(
                    (cli_payload["status"], cli_payload["verified"], cli_payload["delivery_approved"], cli_payload["approved_revision"]),
                    ("verified", True, True, ctx.cand_sha),
                )

                # 2. 12 combinations: 4 prerequisites x 3 rejection modes (missing, failing, stale)
                stale_sha = "0" * 40

                matrix_cases = [
                    # CI cases
                    ("ci-missing", "ci", "missing", "ci-missing", "missing CI verification"),
                    ("ci-failing", "ci", "failing", "ci-failed", "failed"),
                    ("ci-stale", "ci", "stale", "stale-ci-evidence", "stale CI"),
                    # QA cases
                    ("qa-missing", "qa", "missing", "qa-missing", "missing automated QA"),
                    ("qa-failing", "qa", "failing", "qa-failed", "QA"),
                    ("qa-stale", "qa", "stale", "stale-qa-evidence", "stale"),
                    # Security cases
                    ("security-missing", "security", "missing", "security-review-missing", "security"),
                    ("security-failing", "security", "failing", "security-blockers-unresolved", "security"),
                    ("security-stale", "security", "stale", "stale-security-review", "stale"),
                    # Independent review cases
                    ("review-missing", "independent_review", "missing", "independent-review-missing", "independent review"),
                    ("review-failing", "independent_review", "failing", "changes-requested", "REV-1"),
                    ("review-stale", "independent_review", "stale", "stale-independent-review", "stale"),
                ]

                self.assertEqual(len(matrix_cases), 12, "Matrix must cover exactly 12 combinations")

                for label, prereq, mode, exp_status, exp_blocker_token in matrix_cases:
                    with self.subTest(prerequisite=prereq, mode=mode, label=label):
                        ctx.restore_valid_evidence()

                        # Apply single isolated perturbation
                        if prereq == "ci":
                            if mode == "missing":
                                (ctx.child_dir / "ci-verification.json").unlink(missing_ok=True)
                                att_rec = dict(ctx.valid_snapshots["att_record"])
                                att_rec["child"]["ci_verification"] = None
                                atomic_json(ctx.att_dir / "record.json", att_rec, ctx.home)
                            elif mode == "failing":
                                ci = dict(ctx.valid_snapshots["ci"])
                                ci["status"], ci["verified"], ci["blockers"] = "ci-failed", False, ["CI checks failed"]
                                ci["checks"] = [{**ci["checks"][0], "conclusion": "failure"}, *ci["checks"][1:]]
                                atomic_json(ctx.child_dir / "ci-verification.json", ci, ctx.home)
                            elif mode == "stale":
                                ci = dict(ctx.valid_snapshots["ci"])
                                ci["candidate_sha"] = stale_sha
                                atomic_json(ctx.child_dir / "ci-verification.json", ci, ctx.home)
                        elif prereq == "qa":
                            if mode == "missing":
                                shutil.rmtree(ctx.child_dir / "automated-qa", ignore_errors=True)
                            elif mode == "failing":
                                qa_round = dict(ctx.valid_snapshots["qa_round"])
                                qa_round["status"], qa_round["qa_verified"], qa_round["blockers"] = "qa-failed", False, ["QA checks failed"]
                                atomic_json(ctx.child_dir / "automated-qa" / "round-1" / "record.json", qa_round, ctx.home)
                                atomic_json(ctx.child_dir / "automated-qa" / "record.json", {"status": "qa-failed", "qa_verified": False, "rounds": 1, "open_finding_ids": ["QA-1"], "findings": []}, ctx.home)
                            elif mode == "stale":
                                qa_round = dict(ctx.valid_snapshots["qa_round"])
                                qa_round["candidate_sha"] = stale_sha
                                atomic_json(ctx.child_dir / "automated-qa" / "round-1" / "record.json", qa_round, ctx.home)
                                atomic_json(ctx.child_dir / "automated-qa" / "record.json", {"status": "qa-verified", "qa_verified": True, "rounds": 1, "open_finding_ids": [], "findings": []}, ctx.home)
                        elif prereq == "security":
                            if mode == "missing":
                                (ctx.child_dir / "security-review.json").unlink(missing_ok=True)
                            elif mode == "failing":
                                sec = dict(ctx.valid_snapshots["sec"])
                                sec["outcome"], sec["ready"], sec["status"] = "changes-requested", False, "security-blockers-unresolved"
                                sec["blocking_findings"] = [{"finding_id": "SEC-1", "blocking": True, "status": "open"}]
                                atomic_json(ctx.child_dir / "security-review.json", sec, ctx.home)
                            elif mode == "stale":
                                sec = dict(ctx.valid_snapshots["sec"])
                                sec["reviewed_revision"] = stale_sha
                                atomic_json(ctx.child_dir / "security-review.json", sec, ctx.home)
                        elif prereq == "independent_review":
                            if mode == "missing":
                                (ctx.child_dir / "independent-review.json").unlink(missing_ok=True)
                            elif mode == "failing":
                                rev = dict(ctx.valid_snapshots["ir"])
                                rev["outcome"], rev["review_verified"] = "changes-requested", False
                                rev["blocking_findings"] = [{"finding_id": "REV-1", "blocking": True, "status": "open"}]
                                rev["open_finding_ids"] = ["REV-1"]
                                atomic_json(ctx.child_dir / "independent-review.json", rev, ctx.home)
                            elif mode == "stale":
                                rev = dict(ctx.valid_snapshots["ir"])
                                rev["reviewed_revision"] = stale_sha
                                atomic_json(ctx.child_dir / "independent-review.json", rev, ctx.home)

                        res = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                        self.assertEqual(res.status, exp_status, f"status mismatch for {label}")
                        self.assertFalse(res.delivery_approved, f"delivery_approved should be False for {label}")
                        self.assertIsNone(res.approved_revision, f"approved_revision should be None for {label}")
                        self.assertFalse(res.verified, f"verified should be False for {label}")
                        self.assertEqual(res.approval_outcome, "rejected", f"approval_outcome mismatch for {label}")
                        self.assertTrue(len(res.blockers) > 0, f"expected blockers for {label}")
                        self.assertTrue(
                            any(exp_blocker_token in b for b in res.blockers),
                            f"expected blocker token {exp_blocker_token!r} in {res.blockers} for {label}",
                        )

                        # Check persisted delivery state on disk
                        gate_p = ctx.child_dir / "approval-gate.json"
                        self.assertTrue(gate_p.is_file(), f"approval-gate.json missing for {label}")
                        gate_rec = json.loads(gate_p.read_text(encoding="utf-8"))
                        self.assertEqual(gate_rec.get("status"), exp_status, f"gate status mismatch on disk for {label}")
                        self.assertFalse(gate_rec.get("delivery_approved"), f"gate delivery_approved should be False for {label}")
                        self.assertIsNone(gate_rec.get("approved_revision"), f"gate approved_revision should be None for {label}")

                        att_rec = json.loads((ctx.att_dir / "record.json").read_text(encoding="utf-8"))
                        self.assertEqual(att_rec.get("status"), exp_status, f"attempt status mismatch on disk for {label}")
                        self.assertFalse(att_rec.get("delivery_approved"), f"attempt delivery_approved should be False for {label}")
                        self.assertIsNone(att_rec.get("approved_revision"), f"attempt approved_revision should be None for {label}")
                        self.assertFalse(att_rec["child"].get("delivery_approved"), f"child delivery_approved should be False for {label}")
                        self.assertFalse(att_rec["child"].get("verified"), f"child verified should be False for {label}")
                        self.assertFalse(att_rec["child"]["pr"].get("delivery_approved"), f"PR delivery_approved should be False for {label}")
                        self.assertFalse(att_rec["child"]["pr"].get("verified"), f"PR verified should be False for {label}")
            finally:
                ctx.asana.__exit__(None, None, None)
                ctx.gh.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
