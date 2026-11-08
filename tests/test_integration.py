"""Focused behavioral tests for protected child integration (#65)."""
from __future__ import annotations

import json, os, shutil, tempfile, threading, unittest
from pathlib import Path
from typing import Any

from factory import deliver as deliver_module
from factory.deliver_checks import AttemptTimeoutError
from factory.integration import integrate_approved_child
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
