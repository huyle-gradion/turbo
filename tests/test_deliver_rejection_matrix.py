"""Tests proving the delivery rejection matrix and exact-candidate control (Issue #62 AC1)."""
from __future__ import annotations

import json, os, shutil, tempfile, time, unittest
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
            with setup_disposable_delivery_context(root) as ctx:
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



class DeliveryHistoricalAndProtocolRejectionTest(unittest.TestCase):
    """Enforced delivery boundary tests for historical findings and invalid review (Issue #62 AC2)."""

    def test_persisted_historical_blocker_omitted_from_reconciliation(self) -> None:
        from factory import independent_review
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "hist-omitted-rule")
                b1 = {
                    "finding_id": fid, "category": "bug", "blocking": True,
                    "target": "src/chat_bridge/auth.py", "rule": "hist-omitted-rule",
                    "title": "Historical bug", "evidence": "r1-ev", "actionable_correction": "Fix hist",
                    "status": "open", "introduced_in_round": 1, "introduced_in_revision": ctx.cand_sha,
                    "created_round": 1, "created_candidate_sha": ctx.cand_sha,
                }
                atomic_json(ctx.child_dir / "prior-blockers.json", {"schema": 1, "round": 1, "updated_in_round": 1, "findings": [b1]}, ctx.home)
                r1_dir = ctx.child_dir / "independent-review-round-1"
                r1_rec = dict(ctx.valid_snapshots["ir"])
                r1_rec["findings"] = [b1]
                r1_rec["blocking_findings"] = [b1]
                r1_rec["open_finding_ids"] = [fid]
                atomic_json(r1_dir / "record.json", r1_rec, ctx.home)

                # Round 2 review passes but completely omits fid from reconciliation
                rev_r2 = dict(ctx.valid_snapshots["ir"])
                rev_r2["round"] = 2
                rev_r2["outcome"] = "review-passed"
                rev_r2["review_verified"] = True
                rev_r2["findings"] = []
                rev_r2["previous_findings_resolution"] = []
                rev_r2["blocking_findings"] = []
                rev_r2["open_finding_ids"] = []
                atomic_json(ctx.child_dir / "independent-review.json", rev_r2, ctx.home)
                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)

                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res.status, "unresolved-historical-blockers")
                self.assertFalse(res.delivery_approved)
                self.assertIsNone(res.approved_revision)
                self.assertFalse(res.verified)
                self.assertTrue(any(fid in b and "omitted" in b for b in res.blockers), res.blockers)

                gate_rec = json.loads((ctx.child_dir / "approval-gate.json").read_text(encoding="utf-8"))
                self.assertEqual(gate_rec["status"], "unresolved-historical-blockers")
                self.assertFalse(gate_rec["delivery_approved"])
                self.assertIn(fid, gate_rec["historical_blockers"]["unresolved_ids"])


    def test_ineffective_fixed_claim_contradicted_by_actual_reproducer_execution(self) -> None:
        from factory import independent_review
        from tests.independent_review.test_independent_review import _make_staged_reviewer_script
        from test_deliver import _make_fake_agy
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                vcmd = "python3 -c \"import pathlib, sys; sys.exit(0 if '# genuine-fix-marker' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
                fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "ineffective-repro-rule")
                b1 = {
                    "finding_id": fid, "category": "bug", "blocking": True,
                    "target": "src/chat_bridge/auth.py", "rule": "ineffective-repro-rule",
                    "title": "Repro bug", "evidence": "r1-repro", "actionable_correction": "Add # genuine-fix-marker",
                    "verification_command": vcmd, "status": "open",
                    "introduced_in_round": 1, "introduced_in_revision": ctx.base_sha,
                    "last_seen_round": 1, "last_seen_revision": ctx.base_sha,
                }
                atomic_json(ctx.child_dir / "prior-blockers.json", {"schema": 1, "round": 1, "updated_in_round": 1, "findings": [b1]}, ctx.home)
                r1_rec = {**ctx.valid_snapshots["ir"], "round": 1, "reviewed_revision": ctx.base_sha, "findings": [b1], "blocking_findings": [b1], "open_finding_ids": [fid]}
                atomic_json(ctx.child_dir / "independent-review-round-1" / "record.json", r1_rec, ctx.home)

                # Scripted reviewer claims fixed resolution, but reproducer executes on candidate lacking marker and fails
                reconcils = [{"finding_id": fid, "resolution": "fixed", "evidence": "claimed fix in prose"}]
                script_ineffective = _make_staged_reviewer_script(session_id="rev-ineff", outcome="review-passed", reconciliations=reconcils)
                agy_ineff = _make_fake_agy(root, "agy-ineff", script_ineffective)

                r2 = independent_review.review_candidate_independently(
                    repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
                    conf=ctx.conf, base_sha=ctx.base_sha, candidate_sha=ctx.cand_sha,
                    builder_session_id="c-101", builder_summary="Claimed fix.",
                    qa_record=ctx.valid_snapshots["qa_round"], security_record=ctx.valid_snapshots["sec"],
                    round_num=2, agy_bin=str(agy_ineff), deadline=time.monotonic() + 30.0, limit_s=30,
                )
                self.assertFalse(r2["review_verified"])
                self.assertIn(fid, r2["open_finding_ids"])
                self.assertEqual(r2["blocking_findings"][0]["resolution_blocker"], "check-failed")

                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)
                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertFalse(res.delivery_approved)
                self.assertIsNone(res.approved_revision)
                self.assertFalse(res.verified)
                self.assertIn(res.status, ("changes-requested", "unresolved-historical-blockers"))
                self.assertTrue(any("failed trusted execution verification" in b or fid in b or "check-failed" in b for b in res.blockers), res.blockers)


    def test_unsupported_resolution_claims_cannot_resolve_blocker(self) -> None:
        from factory import independent_review
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "unsupported-res-rule")
                b1 = {
                    "finding_id": fid, "category": "bug", "blocking": True,
                    "target": "src/chat_bridge/auth.py", "rule": "unsupported-res-rule",
                    "title": "Bug", "evidence": "r1-res", "actionable_correction": "Fix",
                    "status": "open", "introduced_in_round": 1, "introduced_in_revision": ctx.cand_sha,
                }
                atomic_json(ctx.child_dir / "prior-blockers.json", {"schema": 1, "round": 1, "updated_in_round": 1, "findings": [b1]}, ctx.home)
                atomic_json(ctx.child_dir / "independent-review-round-1" / "record.json", {**ctx.valid_snapshots["ir"], "round": 1, "findings": [b1], "blocking_findings": [b1], "open_finding_ids": [fid]}, ctx.home)

                for unsupported_claim in ("thread-closed", "dismissed", "comment-resolved"):
                    with self.subTest(claim=unsupported_claim):
                        rev_rec = dict(ctx.valid_snapshots["ir"])
                        rev_rec["round"] = 2
                        rev_rec["outcome"] = "review-passed"
                        rev_rec["review_verified"] = True
                        resolved_finding = {**b1, "status": "resolved", "resolution": unsupported_claim, "last_seen_revision": ctx.cand_sha}
                        resolution_entry = {"finding_id": fid, "status": "resolved", "resolution": unsupported_claim, "candidate_sha": ctx.cand_sha, "verified_on_revision": ctx.cand_sha, "resolution_evidence": "closed in thread"}
                        rev_rec["findings"] = [resolved_finding]
                        rev_rec["previous_findings_resolution"] = [resolution_entry]
                        rev_rec["blocking_findings"] = []
                        rev_rec["open_finding_ids"] = []
                        atomic_json(ctx.child_dir / "independent-review.json", rev_rec, ctx.home)
                        (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)

                        res = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                        self.assertEqual(res.status, "unresolved-historical-blockers", f"claim={unsupported_claim}")
                        self.assertFalse(res.delivery_approved)
                        self.assertIsNone(res.approved_revision)
                        self.assertTrue(any(fid in b and "unresolved" in b for b in res.blockers), res.blockers)


    def test_reviewer_worktree_mutation_rejected_by_delivery(self) -> None:
        from factory import independent_review
        from tests.independent_review.test_independent_review import _make_staged_reviewer_script
        from test_deliver import _make_fake_agy
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                script_mutating = _make_staged_reviewer_script(session_id="rev-mut", mutate_in_phase=2, mutate_kind="unstaged")
                agy_mut = _make_fake_agy(root, "agy-mut", script_mutating)

                r_mut = independent_review.review_candidate_independently(
                    repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract,
                    conf=ctx.conf, base_sha=ctx.base_sha, candidate_sha=ctx.cand_sha,
                    builder_session_id="c-101", builder_summary="Valid builder summary.",
                    qa_record=ctx.valid_snapshots["qa_summary"], security_record=ctx.valid_snapshots["sec"],
                    round_num=2, agy_bin=str(agy_mut), deadline=time.monotonic() + 30.0, limit_s=30,
                )
                self.assertFalse(r_mut["review_verified"])
                self.assertTrue(r_mut["worktree_integrity"]["candidate_modified_by_reviewer"])

                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)
                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res.status, "reviewer-modified-worktree")
                self.assertFalse(res.delivery_approved)
                self.assertIsNone(res.approved_revision)
                self.assertTrue(any("modified the candidate worktree" in b for b in res.blockers), res.blockers)


    def test_invalid_review_identity_and_protocol_rejected_by_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                # 1. Reused builder session identity
                ctx.restore_valid_evidence()
                rev_reused = dict(ctx.valid_snapshots["ir"])
                rev_reused["reviewer_session_id"] = "c-101"
                rev_reused["builder_session_id"] = "c-101"
                atomic_json(ctx.child_dir / "independent-review.json", rev_reused, ctx.home)
                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)

                res_sid = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res_sid.status, "reused-builder-identity")
                self.assertFalse(res_sid.delivery_approved)
                self.assertIsNone(res_sid.approved_revision)
                self.assertTrue(any("reused session identity" in b for b in res_sid.blockers), res_sid.blockers)

                # 2. Protocol ordering violation (hypotheses not persisted before summary)
                ctx.restore_valid_evidence()
                rev_proto = dict(ctx.valid_snapshots["ir"])
                rev_proto["protocol_ordering"] = {**rev_proto["protocol_ordering"], "hypotheses_persisted_before_summary": False}
                atomic_json(ctx.child_dir / "independent-review.json", rev_proto, ctx.home)
                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)

                res_proto = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res_proto.status, "invalid-review-protocol")
                self.assertFalse(res_proto.delivery_approved)
                self.assertIsNone(res_proto.approved_revision)
                self.assertTrue(any("protocol ordering" in b for b in res_proto.blockers), res_proto.blockers)



class TestDisposableDeliveryContextSafety(unittest.TestCase):
    """Verify exception safety, server termination, and environment restoration."""

    def test_environment_restoration_and_server_teardown(self) -> None:
        from support_deliver import run_delivery_lifecycle_demo
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orig_asana = "https://orig.asana.example"
            with unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": orig_asana}):
                os.environ.pop("TURBO_GITHUB_TOKEN", None)
                os.environ.pop("ASANA_ACCESS_TOKEN", None)
                os.environ.pop("TURBO_GITHUB_API_URL", None)

                with setup_disposable_delivery_context(root) as ctx:
                    self.assertNotEqual(os.environ["TURBO_ASANA_API_URL"], orig_asana)
                    self.assertEqual(os.environ["TURBO_GITHUB_TOKEN"], "disposable-gh-token")
                    ctx.restore_valid_evidence()
                    r = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                    self.assertTrue(r.delivery_approved)

                self.assertEqual(os.environ.get("TURBO_ASANA_API_URL"), orig_asana)
                self.assertNotIn("TURBO_GITHUB_TOKEN", os.environ)
                self.assertEqual(ctx.asana._server.fileno(), -1)
                self.assertEqual(ctx.gh._server.fileno(), -1)

                demo_res = run_delivery_lifecycle_demo(root / "demo-out")
                self.assertTrue(demo_res["stages"]["stage_3_verified"]["delivery_approved"])
                self.assertEqual(os.environ.get("TURBO_ASANA_API_URL"), orig_asana)
                self.assertNotIn("TURBO_GITHUB_TOKEN", os.environ)

    def test_cleanup_on_partial_acquisition_and_boundary_failures(self) -> None:
        from test_deliver import _DisposableAsanaServer, _DisposableGitHubServer
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case-1").mkdir()
            (root / "case-2").mkdir()
            (root / "case-3").mkdir()
            # Partial acquisition failure: entering second server fails
            asana_instances = []
            orig_asana_enter = _DisposableAsanaServer.__enter__

            def track_asana_enter(srv):
                asana_instances.append(srv)
                return orig_asana_enter(srv)

            with unittest.mock.patch.object(_DisposableAsanaServer, "__enter__", track_asana_enter):
                with unittest.mock.patch.object(_DisposableGitHubServer, "__enter__", side_effect=RuntimeError("gh-fail")):
                    with self.assertRaises(RuntimeError):
                        with setup_disposable_delivery_context(root / "case-1"):
                            pass
            self.assertTrue(len(asana_instances) >= 1)
            self.assertEqual(asana_instances[-1]._server.fileno(), -1)
            self.assertNotIn("TURBO_ASANA_API_URL", os.environ)

            # Boundary failure during deliver_feature in setup
            with unittest.mock.patch("factory.deliver.deliver_feature", side_effect=RuntimeError("deliver-fail")):
                with self.assertRaises(RuntimeError):
                    with setup_disposable_delivery_context(root / "case-2"):
                        pass
            self.assertNotIn("TURBO_ASANA_API_URL", os.environ)

            # Failure raised inside caller block
            saved_ctx = []
            with self.assertRaises(ValueError):
                with setup_disposable_delivery_context(root / "case-3") as ctx:
                    saved_ctx.append(ctx)
                    raise ValueError("inside-context-error")
            self.assertEqual(saved_ctx[0].asana._server.fileno(), -1)
            self.assertEqual(saved_ctx[0].gh._server.fileno(), -1)
            self.assertNotIn("TURBO_ASANA_API_URL", os.environ)


if __name__ == "__main__":
    unittest.main()

