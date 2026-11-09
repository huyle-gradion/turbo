"""Focused behavioral tests for protected child integration (#65)."""
from __future__ import annotations

import json, os, shutil, tempfile, threading, unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import quote

from factory import deliver as deliver_module
from factory.deliver_checks import AttemptTimeoutError
from factory.integration import integrate_approved_child
import factory.integration as integration_mod
from support import git
from support_deliver import setup_disposable_delivery_context
from test_deliver import _make_disposable_product_workspace


class IntegrationBehaviorTest(unittest.TestCase):
    def _setup_ctx(self, ctx: Any) -> tuple[dict[str, Any], str]:
        gate = deliver_module.enforce_delivery_approval(
            candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha,
            repo=ctx.repo, home=ctx.home, child_dir=ctx.child_dir,
            child=ctx.child_contract, conf=ctx.conf,
        )
        b_branch = str(ctx.intake_rec["parent"]["target_feature_branch"])
        git(ctx.bare, "branch", "-f", b_branch, ctx.base_sha)
        git(ctx.bare, "branch", "-f", ctx.head_branch, ctx.cand_sha)
        git(ctx.repo, "fetch", "origin")
        return gate, b_branch

    def _call(self, ctx: Any, gate: Any, b_branch: str, **kw: Any) -> Any:
        return integrate_approved_child(
            repo=kw.get("repo", ctx.repo), home=ctx.home, child_dir=kw.get("child_dir", ctx.child_dir),
            child=kw.get("child", ctx.child_contract), conf=ctx.conf, pr_number=kw.get("pr_number", 1),
            candidate_sha=kw.get("cand_sha", ctx.cand_sha), base_sha=kw.get("base_sha", ctx.base_sha),
            head_branch=kw.get("head_branch", ctx.head_branch), base_branch=b_branch,
            approval_record=gate, repo_slug=kw.get("repo_slug", "example/chat-bridge"),
            base_url=ctx.gh.base_url, token=kw.get("token", "disposable-gh-token"),
            **{k: v for k, v in kw.items() if k not in ("repo", "child_dir", "child", "pr_number", "cand_sha", "base_sha", "head_branch", "repo_slug", "token")},
        )

    def test_successful_approved_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                self.assertTrue(gate.get("delivery_approved"))
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("confirmed", "confirmed"))
                self.assertEqual(git(ctx.bare, "rev-parse", f"refs/heads/{b_branch}"), res.landed_sha)
                self.assertTrue(ctx.gh.pulls[1]["merged"] and ctx.gh.pulls[1]["state"] == "closed")
                self.assertTrue((ctx.child_dir / "integration-request.json").is_file())
                rec_data = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec_data["status"], rec_data["landed_sha"]), ("confirmed", res.landed_sha))
                self.assertTrue(rec_data["protection_observed"]["required_status_checks"]["strict"])

    def test_concurrent_attempts_from_independent_processes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            root = Path(tmp_str)
            with setup_disposable_delivery_context(root) as ctx:
                gate1, b_branch = self._setup_ctx(ctx)
                head2 = "task/102-auth"
                git(ctx.bare, "branch", "-f", head2, ctx.cand_sha)
                git(ctx.repo, "fetch", "origin")
                child_dir2 = ctx.att_dir / "children" / "102"
                shutil.copytree(ctx.child_dir, child_dir2)
                ctx.gh.pulls[2] = {
                    "number": 2, "state": "open", "merged": False, "title": "Child 2",
                    "head": {"ref": head2, "sha": ctx.cand_sha, "repo": {"full_name": "example/chat-bridge"}},
                    "base": {"ref": b_branch, "sha": ctx.base_sha, "repo": {"full_name": "example/chat-bridge"}},
                }
                barrier, results = threading.Barrier(2), [None, None]

                def worker(idx: int, pnum: int, cdir: Path, hbranch: str) -> None:
                    client_repo = root / f"client-repo-{idx}"
                    shutil.copytree(ctx.repo, client_repo)
                    results[idx] = self._call(ctx, gate1, b_branch, repo=client_repo, child_dir=cdir, pr_number=pnum, head_branch=hbranch, on_before_merge=lambda: barrier.wait(timeout=10.0))

                t1 = threading.Thread(target=worker, args=(0, 1, ctx.child_dir, ctx.head_branch))
                t2 = threading.Thread(target=worker, args=(1, 2, child_dir2, head2))
                t1.start(); t2.start(); t1.join(timeout=15.0); t2.join(timeout=15.0)
                self.assertEqual({r.status for r in results if r is not None}, {"confirmed", "rejected-competing-base"})

    def test_controlled_competing_base_update_at_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                def advance_competing_base() -> None:
                    new_b = git(ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test", "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Competing SWE push")
                    git(ctx.bare, "update-ref", f"refs/heads/{b_branch}", new_b, ctx.base_sha)
                res = self._call(ctx, gate, b_branch, on_before_merge=advance_competing_base)
                self.assertEqual((res.status, res.outcome), ("rejected-competing-base", "rejected"))
                self.assertFalse(ctx.gh.pulls[1]["merged"])
                self.assertIn("base branch was modified", " ".join(res.blockers).lower())

    def test_changed_head_and_changed_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                res_h = self._call(ctx, gate, b_branch, cand_sha="a" * 40)
                self.assertEqual(res_h.status, "stale-candidate-revision")
                res_b = self._call(ctx, gate, b_branch, base_sha="b" * 40)
                self.assertEqual(res_b.status, "stale-candidate-revision")
                self.assertFalse(ctx.gh.pulls[1]["merged"])

    def test_stale_or_forged_approval_and_failed_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                _, b_branch = self._setup_ctx(ctx)
                forged = {"role": "attacker", "delivery_approved": True, "status": "approved", "approved_revision": ctx.cand_sha}
                res_f = self._call(ctx, forged, b_branch)
                self.assertEqual(res_f.status, "authority-violation")
                (ctx.child_dir / "approval-gate.json").unlink(missing_ok=True)
                res_m = self._call(ctx, None, b_branch)
                self.assertEqual(res_m.status, "approval-missing")
                self.assertFalse(ctx.gh.pulls[1]["merged"])

    def test_denied_permissions_unsupported_protections_and_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                ctx.gh.branch_protections = {}
                self.assertEqual(self._call(ctx, gate, b_branch).status, "unsupported-protection")
                ctx.gh.branch_protections = {b_branch: {"required_status_checks": {"strict": False}, "enforce_admins": {"enabled": True}}}
                self.assertEqual(self._call(ctx, gate, b_branch).status, "unsupported-protection")
                ctx.gh.protection_status = 403
                self.assertEqual(self._call(ctx, gate, b_branch).status, "denied-permissions")
                ctx.gh.protection_status, ctx.gh.branch_protections = 200, None

    def test_wrong_target_branches_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            repo, home, _ = _make_disposable_product_workspace(Path(tmp_str))
            cdir = Path(tmp_str) / "c"
            cdir.mkdir()
            for bad in ("main", "master", "release/v1"):
                res = integrate_approved_child(
                    repo=repo, home=home, child_dir=cdir, child={"gid": "1"}, conf=None, pr_number=1,
                    candidate_sha="a" * 40, base_sha="b" * 40, head_branch="task/1", base_branch=bad,
                )
                self.assertEqual((res.status, res.outcome), ("unintended-target", "rejected"))

    def test_timeout_uncertain_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                def to_hook() -> None: raise AttemptTimeoutError("timeout")
                self.assertEqual(self._call(ctx, gate, b_branch, on_before_merge=to_hook).status, "hook-failure")
                ctx.gh.merge_status = 502
                res_500 = self._call(ctx, gate, b_branch)
                self.assertEqual((res_500.status, res_500.outcome), ("uncertain", "uncertain"))
                ctx.gh.merge_status = 200

    def test_pre_mutation_persistence_failure_aborts_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                (ctx.child_dir / "integration-request.json").mkdir(parents=True, exist_ok=True)
                self.assertEqual(self._call(ctx, gate, b_branch).status, "persistence-failed")
                self.assertFalse(ctx.gh.pulls[1]["merged"])

    def test_credential_redaction_in_persisted_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                kwarg_secret = "synthetic-kwarg-token/with-special%chars"
                quoted_secret = "synthetic-kwarg-token%2Fwith-special%25chars"
                old_env = {k: os.environ.pop(k, None) for k in ("GITHUB_TOKEN", "GH_TOKEN", "TURBO_GITHUB_TOKEN")}
                try:
                    res = self._call(ctx, gate, b_branch, token=kwarg_secret)
                    self.assertEqual(res.status, "confirmed")
                    req_txt = (ctx.child_dir / "integration-request.json").read_text(encoding="utf-8")
                    rec_txt = (ctx.child_dir / "integration-record.json").read_text(encoding="utf-8")
                    combined = req_txt + rec_txt
                    self.assertNotIn(kwarg_secret, combined)
                    self.assertNotIn(quoted_secret, combined)
                finally:
                    for k, v in old_env.items():
                        if v is not None: os.environ[k] = v

    def test_transport_disconnect_after_mutation_yields_uncertain_and_no_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                ctx.gh.disconnect_after_merge = True
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("uncertain", "uncertain"))
                rec_data = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec_data["status"], rec_data["outcome"]), ("uncertain", "uncertain"))
                self.assertTrue(ctx.gh.pulls[1]["merged"] and ctx.gh.pulls[1]["state"] == "closed")
                put_reqs = [r for r in ctx.gh.requests if r["method"] == "PUT"]
                self.assertEqual(len(put_reqs), 1)

    def test_branch_protection_contract_and_single_encoded_segment(self) -> None:
        import urllib.request, urllib.error
        from urllib.parse import quote
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                res = self._call(ctx, gate, b_branch)
                self.assertEqual(res.status, "confirmed")
                prot_reqs = [r for r in ctx.gh.requests if r["path"].endswith("/protection")]
                self.assertTrue(prot_reqs)
                outbound_path = prot_reqs[0]["path"]
                encoded_segment = quote(b_branch, safe="")
                expected_path = f"/api/v3/repos/example/chat-bridge/branches/{encoded_segment}/protection"
                self.assertEqual(outbound_path, expected_path)
                prefix = "/api/v3/repos/example/chat-bridge/branches/"
                extracted_segment = outbound_path[len(prefix):-len("/protection")]
                self.assertNotIn("/", extracted_segment)
                raw_url = f"{ctx.gh.base_url}/repos/example/chat-bridge/branches/{b_branch}/protection"
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(urllib.request.Request(raw_url, headers={"Authorization": "Bearer token"}))
                self.assertEqual(cm.exception.code, 404)
                pct_branch = "feature/pct%test"
                ctx.gh.branch_protections = {pct_branch: {"required_status_checks": {"strict": True}, "enforce_admins": {"enabled": True}}}
                enc_pct_url = f"{ctx.gh.base_url}/repos/example/chat-bridge/branches/{quote(pct_branch, safe='')}/protection"
                with urllib.request.urlopen(urllib.request.Request(enc_pct_url, headers={"Authorization": "Bearer token"})) as resp:
                    self.assertEqual(resp.status, 200)

    def test_result_persistence_failure_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                (ctx.child_dir / "integration-record.json").mkdir(parents=True, exist_ok=True)
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("persistence-failed", "rejected"))
                self.assertIsNone(res.landed_sha)
                self.assertIsNone(res.record_path)
                self.assertIsNotNone(res.request_path)
                self.assertTrue((ctx.child_dir / "integration-request.json").is_file())
                self.assertTrue(any("failed to persist integration record" in b for b in res.blockers))

                # Recover usable confirmation from retained request and authoritative remote observations
                shutil.rmtree(ctx.child_dir / "integration-record.json")
                res_rec = self._call(ctx, gate, b_branch)
                self.assertEqual((res_rec.status, res_rec.outcome), ("confirmed", "confirmed"))
                self.assertIsNotNone(res_rec.landed_sha)
                self.assertTrue(res_rec.reconciled)
                self.assertTrue((ctx.child_dir / "integration-record.json").is_file())
                rec_data = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec_data["status"], rec_data["mutation_outcome"]), ("confirmed", "already-merged"))
                self.assertTrue(rec_data["reconciled"])

                early_dir = ctx.att_dir / "children" / "early"
                early_dir.mkdir(parents=True, exist_ok=True)
                (early_dir / "integration-record.json").mkdir(parents=True, exist_ok=True)
                res_e = self._call(ctx, gate, b_branch, child_dir=early_dir, pr_number=999)
                self.assertEqual((res_e.status, res_e.outcome), ("pr-not-found", "rejected"))
                self.assertIsNone(res_e.record_path)
                self.assertTrue(any("failed to persist integration record" in b for b in res_e.blockers))

    def test_misleading_merge_response_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)

                # 1. Provider claims merged in PUT response, but PR remains open in follow-up
                ctx.gh.verify_override = {"merged": False, "state": "open"}
                res1 = self._call(ctx, gate, b_branch)
                self.assertEqual((res1.status, res1.outcome), ("misleading-merge-response", "rejected"))
                self.assertIsNone(res1.landed_sha)
                ctx.gh.verify_override = {}

                # 2. Provider claims merged, but target branch in follow-up is not intended
                ctx.gh.verify_override = {"base_ref": "feature/unintended-branch"}
                res2 = self._call(ctx, gate, b_branch)
                self.assertEqual((res2.status, res2.outcome), ("branch-ref-mismatch", "rejected"))
                self.assertIsNone(res2.landed_sha)
                ctx.gh.verify_override = {}

                # 3. Provider claims merged, but repo slug in follow-up does not match
                ctx.gh.verify_override = {"repo_full_name": "attacker/spoofed"}
                res3 = self._call(ctx, gate, b_branch)
                self.assertEqual((res3.status, res3.outcome), ("repo-slug-mismatch", "rejected"))
                self.assertIsNone(res3.landed_sha)
                ctx.gh.verify_override = {}

                # 4. Landed commit does not exist in repository
                ctx.gh.verify_override = {"merge_commit_sha": "0" * 40}
                res4 = self._call(ctx, gate, b_branch)
                self.assertEqual((res4.status, res4.outcome), ("missing-landed-commit", "rejected"))
                self.assertIsNone(res4.landed_sha)
                ctx.gh.verify_override = {}

    def test_landing_relationship_mismatched_tree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                wrong_tree_commit = git(
                    ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                    "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-p", ctx.cand_sha, "-m", "wrong tree commit",
                )
                git(ctx.bare, "update-ref", "refs/heads/wrong-tree-branch", wrong_tree_commit)
                ctx.gh.verify_override = {"merge_commit_sha": wrong_tree_commit}
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("invalid-landing-relationship", "rejected"))
                self.assertIn("tree", " ".join(res.blockers).lower())

    def test_landing_relationship_single_parent_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                single_p = git(
                    ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                    "commit-tree", f"{ctx.cand_sha}^{{tree}}", "-p", ctx.cand_sha, "-m", "single parent",
                )
                git(ctx.bare, "update-ref", "refs/heads/single-parent-branch", single_p)
                ctx.gh.verify_override = {"merge_commit_sha": single_p}
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("invalid-landing-relationship", "rejected"))
                self.assertIn("parents", " ".join(res.blockers).lower())

    def test_landing_relationship_unreachable_commit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                unreachable = git(
                    ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
                    "commit-tree", f"{ctx.cand_sha}^{{tree}}", "-p", ctx.base_sha, "-p", ctx.cand_sha, "-m", "unreachable",
                )
                git(ctx.bare, "update-ref", "refs/heads/unreachable-branch", unreachable)
                ctx.gh.verify_override = {"merge_commit_sha": unreachable}
                res = self._call(ctx, gate, b_branch)
                self.assertEqual((res.status, res.outcome), ("landed-commit-not-on-base", "rejected"))

    def test_retry_reconciliation_and_retained_confirmed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")

                # Disconnect after mutation yields uncertain on first call
                ctx.gh.disconnect_after_merge = True
                res1 = self._call(ctx, gate, b_branch)
                self.assertEqual((res1.status, res1.outcome), ("uncertain", "uncertain"))
                self.assertTrue((ctx.child_dir / "integration-request.json").is_file())
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Retry reconciles remote state, positively confirms landing, writes confirmed record without another mutation
                ctx.gh.disconnect_after_merge = False
                res2 = self._call(ctx, gate, b_branch)
                self.assertEqual((res2.status, res2.outcome), ("confirmed", "confirmed"))
                self.assertTrue(res2.reconciled)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Repeated call on confirmed landing does not duplicate mutation or overwrite evidence
                res3 = self._call(ctx, gate, b_branch)
                self.assertEqual((res3.status, res3.outcome), ("confirmed", "confirmed"))
                self.assertTrue(res3.reconciled)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Changed candidate is rejected and does not overwrite confirmed record
                res_c = self._call(ctx, gate, b_branch, cand_sha="f" * 40)
                self.assertEqual((res_c.status, res_c.outcome), ("stale-candidate-revision", "rejected"))
                rec_retained = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual(rec_retained["status"], "confirmed")
                self.assertEqual(rec_retained["candidate_sha"], ctx.cand_sha)

                # Recovery with substituted post-merge base is rejected and does not overwrite confirmed record
                res_b = self._call(ctx, gate, b_branch, base_sha=res2.landed_sha)
                self.assertEqual((res_b.status, res_b.outcome), ("stale-base-revision", "rejected"))
                rec_retained2 = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual(rec_retained2["status"], "confirmed")

                # Main branch remains completely unchanged
                self.assertEqual(git(ctx.bare, "rev-parse", "refs/heads/main"), main_sha_before)

    def test_separate_provider_and_remote_git_base_drift_with_genuine_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                drifted_sha = "d" * 40
                ctx.gh.verify_override = {"base_sha": drifted_sha}
                res_p = self._call(ctx, gate, b_branch)
                self.assertEqual(res_p.status, "stale-base-revision")
                self.assertTrue(any(f"PR #1 base SHA {drifted_sha}" in b for b in res_p.blockers))
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 0)

                ctx.gh.verify_override = {"base_sha": ctx.base_sha}
                new_b = git(ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test", "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Remote drift")
                git(ctx.bare, "update-ref", f"refs/heads/{b_branch}", new_b, ctx.base_sha)
                res_r = self._call(ctx, gate, b_branch)
                self.assertEqual(res_r.status, "stale-base-revision")
                self.assertTrue(any(f"remote origin/{b_branch} ({new_b})" in b for b in res_r.blockers))
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 0)

    def test_confirmation_get_timeout_after_successful_put_persists_uncertainty(self) -> None:
        """Confirmation GET timeout after PUT returns normally, persists uncertainty, and recovers without duplicate PUT."""
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                orig_http = integration_mod._http_req
                put_state = {"done": False}

                def fake_http(*args: Any, **kw: Any) -> Any:
                    method = args[0]
                    if method == "PUT":
                        put_state["done"] = True
                    elif method == "GET" and put_state["done"] and "pulls/1" in args[1]:
                        raise AttemptTimeoutError("injected confirmation GET timeout")
                    return orig_http(*args, **kw)

                with patch.object(integration_mod, "_http_req", side_effect=fake_http):
                    res = self._call(ctx, gate, b_branch)

                self.assertEqual((res.status, res.outcome, res.confirmation_status), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(res.mutation_outcome, "succeeded")
                self.assertIsNone(res.landed_sha)
                self.assertFalse(res.reconciled)
                self.assertEqual(res.approval_status, "approved")
                self.assertEqual(res.request_path, str(ctx.child_dir / "integration-request.json"))
                self.assertEqual(res.record_path, str(ctx.child_dir / "integration-record.json"))
                self.assertTrue((ctx.child_dir / "integration-record.json").is_file())

                rec = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec["status"], rec["outcome"], rec["confirmation_status"]), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(rec["mutation_outcome"], "succeeded")
                self.assertIsNone(rec["landed_sha"])
                self.assertFalse(rec["reconciled"])
                self.assertEqual(rec["approval_status"], "approved")
                self.assertEqual(rec["candidate_sha"], ctx.cand_sha)
                self.assertEqual(rec["base_sha"], ctx.base_sha)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Retry confirms existing landing without duplicate PUT
                res_rec = self._call(ctx, gate, b_branch)
                self.assertEqual((res_rec.status, res_rec.outcome), ("confirmed", "confirmed"))
                self.assertTrue(res_rec.reconciled)
                self.assertIsNotNone(res_rec.landed_sha)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Repeat recovery keeps confirmed state and single PUT
                res_rep = self._call(ctx, gate, b_branch)
                self.assertEqual((res_rep.status, res_rep.outcome), ("confirmed", "confirmed"))
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

    def test_confirmation_git_inspection_timeout_after_successful_put_persists_uncertainty(self) -> None:
        """Confirmation git timeouts (fetch, commit inspection, parent inspection) persist uncertainty and recover."""
        phases = ("git fetch origin", "inspect landed commit", "verify landed parents")
        for target_phase in phases:
            with self.subTest(phase=target_phase):
                with tempfile.TemporaryDirectory() as tmp_str:
                    with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                        gate, b_branch = self._setup_ctx(ctx)
                        orig_git_timed = integration_mod.git_timed
                        put_done = False

                        def on_merge(pr_num: int, payload: dict[str, Any]) -> None:
                            nonlocal put_done
                            put_done = True
                        ctx.gh.on_before_merge = on_merge

                        def fake_git_timed(repo: Any, dl: Any, limit_s: Any, phase: str, *args: Any) -> Any:
                            if phase == target_phase and (target_phase != "git fetch origin" or put_done):
                                raise AttemptTimeoutError(f"injected timeout during {target_phase}")
                            return orig_git_timed(repo, dl, limit_s, phase, *args)

                        with patch.object(integration_mod, "git_timed", side_effect=fake_git_timed):
                            res = self._call(ctx, gate, b_branch)

                        self.assertEqual((res.status, res.outcome, res.confirmation_status), ("uncertain", "uncertain", "uncertain"))
                        self.assertEqual(res.mutation_outcome, "succeeded")
                        self.assertIsNone(res.landed_sha)
                        self.assertFalse(res.reconciled)
                        self.assertEqual(res.request_path, str(ctx.child_dir / "integration-request.json"))
                        self.assertEqual(res.record_path, str(ctx.child_dir / "integration-record.json"))
                        self.assertTrue((ctx.child_dir / "integration-record.json").is_file())

                        rec = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                        self.assertEqual((rec["status"], rec["outcome"], rec["confirmation_status"]), ("uncertain", "uncertain", "uncertain"))
                        self.assertEqual(rec["mutation_outcome"], "succeeded")
                        self.assertIsNone(rec["landed_sha"])
                        self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                        # Retry confirms existing landing without duplicate PUT
                        res_rec = self._call(ctx, gate, b_branch)
                        self.assertEqual((res_rec.status, res_rec.outcome), ("confirmed", "confirmed"))
                        self.assertTrue(res_rec.reconciled)
                        self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

    def test_reconciliation_confirmation_timeout_persists_uncertainty(self) -> None:
        """Reconciliation confirmation timeouts (GET or git) persist uncertainty and recover without additional PUT."""
        # 1. Reconciliation confirmation GET timeout
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                ctx.gh.disconnect_after_merge = True
                res1 = self._call(ctx, gate, b_branch)
                self.assertEqual((res1.status, res1.outcome), ("uncertain", "uncertain"))
                ctx.gh.disconnect_after_merge = False
                self.assertTrue((ctx.child_dir / "integration-request.json").is_file())
                (ctx.child_dir / "integration-record.json").unlink(missing_ok=True)

                orig_http = integration_mod._http_req
                get_state = {"count": 0}

                def fake_http(*args: Any, **kw: Any) -> Any:
                    method = args[0]
                    if method == "GET" and "pulls/1" in args[1]:
                        get_state["count"] += 1
                        if get_state["count"] == 2:
                            raise AttemptTimeoutError("injected reconciliation confirmation GET timeout")
                    return orig_http(*args, **kw)

                with patch.object(integration_mod, "_http_req", side_effect=fake_http):
                    res2 = self._call(ctx, gate, b_branch)

                self.assertEqual((res2.status, res2.outcome, res2.confirmation_status), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(res2.mutation_outcome, "already-merged")
                self.assertTrue(res2.reconciled)
                self.assertIsNone(res2.landed_sha)
                self.assertEqual(res2.request_path, str(ctx.child_dir / "integration-request.json"))
                self.assertEqual(res2.record_path, str(ctx.child_dir / "integration-record.json"))
                self.assertTrue((ctx.child_dir / "integration-record.json").is_file())

                rec2 = json.loads((ctx.child_dir / "integration-record.json").read_text(encoding="utf-8"))
                self.assertEqual((rec2["status"], rec2["outcome"], rec2["confirmation_status"]), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(rec2["mutation_outcome"], "already-merged")
                self.assertTrue(rec2["reconciled"])
                self.assertIsNone(rec2["landed_sha"])
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

                # Retry confirms existing landing without duplicate PUT
                res3 = self._call(ctx, gate, b_branch)
                self.assertEqual((res3.status, res3.outcome), ("confirmed", "confirmed"))
                self.assertTrue(res3.reconciled)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

        # 2. Reconciliation git inspection timeout
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                ctx.gh.disconnect_after_merge = True
                self._call(ctx, gate, b_branch)
                ctx.gh.disconnect_after_merge = False
                (ctx.child_dir / "integration-record.json").unlink(missing_ok=True)

                orig_git_timed = integration_mod.git_timed

                def fake_git_timed(repo: Any, dl: Any, limit_s: Any, phase: str, *args: Any) -> Any:
                    if phase == "inspect landed commit":
                        raise AttemptTimeoutError("injected reconciliation git timeout")
                    return orig_git_timed(repo, dl, limit_s, phase, *args)

                with patch.object(integration_mod, "git_timed", side_effect=fake_git_timed):
                    res_g = self._call(ctx, gate, b_branch)

                self.assertEqual((res_g.status, res_g.outcome, res_g.confirmation_status), ("uncertain", "uncertain", "uncertain"))
                self.assertEqual(res_g.mutation_outcome, "already-merged")
                self.assertTrue(res_g.reconciled)
                self.assertIsNone(res_g.landed_sha)
                self.assertEqual(len([r for r in ctx.gh.requests if r["method"] == "PUT"]), 1)

    def test_confirmation_timeout_diagnostic_redacts_synthetic_secrets(self) -> None:
        """Confirmation timeout diagnostics redact both raw and urlencoded synthetic secrets from disk evidence."""
        with tempfile.TemporaryDirectory() as tmp_str:
            with setup_disposable_delivery_context(Path(tmp_str)) as ctx:
                gate, b_branch = self._setup_ctx(ctx)
                raw_secret = "synthetic-secret-token/special%chars"
                enc_secret = quote(raw_secret, safe="")

                orig_http = integration_mod._http_req
                put_state = {"done": False}

                def fake_http(*args: Any, **kw: Any) -> Any:
                    method = args[0]
                    if method == "PUT":
                        put_state["done"] = True
                    elif method == "GET" and put_state["done"] and "pulls/1" in args[1]:
                        raise AttemptTimeoutError(f"timed out with {raw_secret} and {enc_secret}")
                    return orig_http(*args, **kw)

                with patch.object(integration_mod, "_http_req", side_effect=fake_http):
                    res = self._call(ctx, gate, b_branch, token=raw_secret)

                self.assertEqual(res.status, "uncertain")
                req_txt = (ctx.child_dir / "integration-request.json").read_text(encoding="utf-8")
                rec_txt = (ctx.child_dir / "integration-record.json").read_text(encoding="utf-8")
                for s in (raw_secret, enc_secret):
                    self.assertNotIn(s, req_txt)
                    self.assertNotIn(s, rec_txt)
                    self.assertFalse(any(s in b for b in res.blockers))
