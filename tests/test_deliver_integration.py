"""Focused behavioral tests for final delivery confirmed integration and completion (#78)."""
from __future__ import annotations

import copy, json, os, shutil, tempfile, unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from factory import deliver as deliver_module
from factory.deliver_checks import AttemptTimeoutError
from factory.integration import integrate_approved_child
import factory.integration as integration_mod
from factory.paths import atomic_json
from support import git
from support_deliver import setup_disposable_delivery_context
from test_deliver import _make_disposable_product_workspace


class DeliverIntegrationBehaviorTest(unittest.TestCase):
    def test_fresh_final_delivery_integrates_and_records_confirmed_completion(self) -> None:
        """Fresh delivery invokes protected integration and records completion once approved."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")
                ctx.restore_valid_evidence()

                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)

                self.assertEqual(res.status, "completed")
                self.assertTrue(res.merged)
                self.assertTrue(res.delivery_approved)
                self.assertEqual(res.approval_outcome, "approved")
                self.assertEqual(res.approved_revision, ctx.cand_sha)
                self.assertIsNotNone(res.landed_sha)
                self.assertEqual(git(ctx.bare, "rev-parse", f"refs/heads/{res.feature_branch}"), res.landed_sha)
                self.assertEqual(git(ctx.bare, "rev-parse", "refs/heads/main"), main_sha_before)

                # Authoritative completion evidence bindings (AC4, AC5)
                ev = res.evidence
                self.assertEqual(ev.get("task_gid"), res.task_gid)
                self.assertIn(res.task_gid, ev.get("parent_task_url", ""))
                self.assertIn("101", ev.get("child_task_url", ""))
                self.assertIn("pull/1", ev.get("pr_url", ""))
                self.assertEqual(ev.get("reviewed_revision"), ctx.cand_sha)
                self.assertEqual(ev.get("tested_revision"), res.tested_sha)
                self.assertTrue(bool(res.tested_sha))
                self.assertEqual(ev.get("original_base_sha"), ctx.base_sha)
                self.assertEqual(ev.get("landed_sha"), res.landed_sha)
                self.assertTrue(ev.get("completion_confirmed"))
                self.assertTrue(Path(ev.get("ci_verification_path", "")).is_file())
                self.assertTrue(Path(ev.get("approval_gate_path", "")).is_file())
                self.assertTrue(Path(ev.get("integration_record_path", "")).is_file())

                # Check persisted attempt record.json
                rec = json.loads((ctx.att_dir / "record.json").read_text(encoding="utf-8"))
                self.assertEqual(rec["status"], "completed")
                self.assertTrue(rec["merged"])
                self.assertEqual(rec["landed_sha"], res.landed_sha)
                self.assertEqual(rec["child"]["status"], "completed")
                self.assertTrue(rec["child"]["merged"])

    def test_prerequisite_callers_have_no_integration_or_completion_authority(self) -> None:
        """deliver_ci_prerequisite caller never gains integration or completion authority."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                res = deliver_module.deliver_ci_prerequisite(ctx.paths, ctx.spec)

                self.assertNotEqual(res.status, "completed")
                self.assertFalse(res.merged)
                self.assertFalse(res.delivery_approved)
                self.assertIsNone(getattr(res, "landed_sha", None))
                self.assertFalse((ctx.child_dir / "integration-request.json").exists())
                self.assertFalse((ctx.child_dir / "integration-record.json").exists())
                self.assertFalse(ctx.gh.pulls[1]["merged"])

    def test_denied_integration_preserves_approval_without_completion(self) -> None:
        """Approval passes but provider denied merge produces rejection without completion."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                ctx.gh.merge_status = 403

                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)

                self.assertEqual(res.status, "denied-permissions")
                self.assertTrue(res.delivery_approved)
                self.assertEqual(res.approval_outcome, "approved")
                self.assertFalse(res.merged)
                self.assertIsNone(res.landed_sha)
                self.assertFalse(ctx.gh.pulls[1]["merged"])
                self.assertTrue(any("denied" in b.lower() for b in res.blockers))

                # Integration record persisted as rejected
                rec_data = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec_data["status"], rec_data["approval_status"]), ("denied-permissions", "approved"))
                self.assertIsNone(rec_data["landed_sha"])

    def test_uncertain_outcome_preserves_approval_without_completion(self) -> None:
        """Transport error during merge yields uncertain status without duplicate mutation."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                ctx.gh.merge_status = 502

                res = deliver_module.deliver_feature(ctx.paths, ctx.spec)

                self.assertEqual(res.status, "uncertain")
                self.assertTrue(res.delivery_approved)
                self.assertFalse(res.merged)
                self.assertIsNone(res.landed_sha)
                self.assertTrue(any("uncertain" in b.lower() for b in res.blockers))

    def test_timeout_after_success_and_resumed_recovery(self) -> None:
        """Disconnect after mutation yields uncertain, and resume recovers without duplicate PUT."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")
                ctx.gh.disconnect_after_merge = True

                # First call: mutation succeeds remotely but connection drops
                res1 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res1.status, "uncertain")
                self.assertFalse(res1.merged)
                self.assertTrue((ctx.child_dir / "integration-request.json").is_file())
                put_count_1 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_1, 1)

                # Resume delivery: recovers confirmed landing without duplicate mutation
                ctx.gh.disconnect_after_merge = False
                res2 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res2.status, "completed")
                self.assertTrue(res2.merged)
                self.assertIsNotNone(res2.landed_sha)
                put_count_2 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_2, 1, "Recovery must not issue another PUT merge mutation")

                # Repeated call does not duplicate integration
                res3 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res3.status, "completed")
                self.assertTrue(res3.merged)
                put_count_3 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_3, 1, "Repeated delivery must not issue another PUT merge mutation")
                self.assertEqual(git(ctx.bare, "rev-parse", "refs/heads/main"), main_sha_before)

    def test_confirmation_timeout_preserves_approval_and_resumes_without_duplicate_put(self) -> None:
        """Confirmation timeout preserves approval, prevents completion, and resume completes without another PUT."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")

                orig_http = integration_mod._http_req
                put_state = {"done": False, "fail_conf": True}

                def fake_http(*args: Any, **kw: Any) -> Any:
                    method = args[0]
                    if method == "PUT":
                        put_state["done"] = True
                    elif method == "GET" and put_state["done"] and put_state["fail_conf"] and "pulls/1" in args[1]:
                        raise AttemptTimeoutError("injected confirmation GET timeout")
                    return orig_http(*args, **kw)

                with patch.object(integration_mod, "_http_req", side_effect=fake_http):
                    res1 = deliver_module.deliver_feature(ctx.paths, ctx.spec)

                self.assertEqual(res1.status, "uncertain")
                self.assertFalse(res1.merged)
                self.assertIsNone(res1.landed_sha)
                self.assertTrue(res1.delivery_approved)
                self.assertTrue((ctx.child_dir / "approval-gate.json").is_file())
                self.assertTrue((ctx.child_dir / "integration-record.json").is_file())
                rec1 = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec1["status"], rec1["mutation_outcome"]), ("uncertain", "succeeded"))
                put_count_1 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_1, 1)

                # Resume delivery without fault: confirms landing without new mutation
                put_state["fail_conf"] = False
                res2 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res2.status, "completed")
                self.assertTrue(res2.merged)
                self.assertIsNotNone(res2.landed_sha)
                put_count_2 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_2, 1, "Resume must not issue another PUT merge mutation")
                self.assertEqual(git(ctx.bare, "rev-parse", "refs/heads/main"), main_sha_before)

    def test_confirmation_503_preserves_approval_and_resumes_without_duplicate_put(self) -> None:
        """Returned confirmation 503 preserves approval, prevents completion, and resume completes without another PUT while main ref is unchanged."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()
                main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")

                orig_http = integration_mod._http_req
                put_state = {"done": False, "fail_conf": True}

                def fake_http(*args: Any, **kw: Any) -> Any:
                    method = args[0]
                    if method == "PUT":
                        put_state["done"] = True
                    elif method == "GET" and put_state["done"] and put_state["fail_conf"] and "pulls/1" in args[1]:
                        trace = args[4]
                        trace.append({"method": "GET", "url": args[1], "status": 503})
                        return 503, {}, "HTTP 503 Service Unavailable"
                    return orig_http(*args, **kw)

                with patch.object(integration_mod, "_http_req", side_effect=fake_http):
                    res1 = deliver_module.deliver_feature(ctx.paths, ctx.spec)

                self.assertEqual(res1.status, "uncertain")
                self.assertFalse(res1.merged)
                self.assertIsNone(res1.landed_sha)
                self.assertTrue(res1.delivery_approved)
                self.assertEqual(res1.approval_outcome, "approved")
                self.assertTrue((ctx.child_dir / "approval-gate.json").is_file())
                self.assertTrue((ctx.child_dir / "integration-record.json").is_file())
                rec1 = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec1["status"], rec1["outcome"], rec1["confirmation_status"]), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(rec1["mutation_outcome"], "succeeded")
                self.assertEqual(rec1["approval_status"], "approved")
                self.assertIsNone(rec1["landed_sha"])
                put_count_1 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_1, 1)

                # Resume delivery without fault: confirms landing without new mutation
                put_state["fail_conf"] = False
                res2 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertEqual(res2.status, "completed")
                self.assertTrue(res2.merged)
                self.assertIsNotNone(res2.landed_sha)
                put_count_2 = len([r for r in ctx.gh.requests if r["method"] == "PUT"])
                self.assertEqual(put_count_2, 1, "Resume must not issue another PUT merge mutation")
                self.assertEqual(git(ctx.bare, "rev-parse", "refs/heads/main"), main_sha_before)

    def test_changed_candidate_and_changed_base_prevent_new_mutation(self) -> None:
        """Changed candidate or base invalidates authorization and prevents new mutation."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                ctx.restore_valid_evidence()

                # Changed candidate
                new_cand = git(
                    ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                    "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "New cand",
                )
                git(ctx.bare, "branch", "-f", ctx.head_branch, new_cand)
                git(ctx.repo, "fetch", "origin")
                res_cand = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertFalse(res_cand.delivery_approved)
                self.assertFalse(res_cand.merged)
                self.assertNotEqual(res_cand.status, "completed")
                self.assertFalse(ctx.gh.pulls[1]["merged"])

                # Restore and advance base
                ctx.restore_valid_evidence()
                new_base = git(
                    ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                    "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Advanced base",
                )
                git(ctx.bare, "update-ref", f"refs/heads/{ctx.intake_rec['parent']['target_feature_branch']}", new_base, ctx.base_sha)
                git(ctx.repo, "fetch", "origin")
                res_base = deliver_module.deliver_feature(ctx.paths, ctx.spec)
                self.assertFalse(res_base.merged)
                self.assertNotEqual(res_base.status, "completed")
                self.assertFalse(ctx.gh.pulls[1]["merged"])

    def test_cached_confirmation_mismatched_target_or_repo_fails_closed(self) -> None:
        """Cached confirmed integration record with mismatched repo, PR, or target is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with setup_disposable_delivery_context(root) as ctx:
                gate = deliver_module.enforce_delivery_approval(
                    candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha, repo=ctx.repo, home=ctx.home,
                    child_dir=ctx.child_dir, child=ctx.child_contract, conf=ctx.conf,
                )
                b_branch = str(ctx.intake_rec["parent"]["target_feature_branch"])
                spoofed_rec = {
                    "schema": 1, "role": "child-integration-result", "status": "confirmed", "outcome": "confirmed",
                    "repo_slug": "attacker/spoofed-repo", "pr_number": 999,
                    "candidate_sha": ctx.cand_sha, "base_sha": ctx.base_sha,
                    "head_branch": ctx.head_branch, "base_branch": b_branch, "landed_sha": "e" * 40,
                }
                atomic_json(ctx.child_dir / "integration-record.json", spoofed_rec, ctx.home)

                res = integrate_approved_child(
                    repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir, child=ctx.child_contract, conf=ctx.conf,
                    pr_number=1, candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
                    head_branch=ctx.head_branch, base_branch=b_branch, approval_record=gate,
                    repo_slug="example/chat-bridge", base_url=ctx.gh.base_url, token="disposable-token",
                )
                self.assertEqual((res.status, res.outcome), ("repo-slug-mismatch", "rejected"))
                self.assertIsNone(res.landed_sha)


if __name__ == "__main__":
    unittest.main()
