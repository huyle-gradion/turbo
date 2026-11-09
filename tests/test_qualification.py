"""Tests for protected repository qualification harness (#67)."""
from __future__ import annotations

import json, os, shutil, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from factory.qualification import (
    DISPOSABLE_REPO_ALLOWLIST, build_parent_evidence_index,
    check_branch_protection_and_topology, check_credentials_and_capabilities,
    check_hosted_authorization, check_seed_and_workflow_capabilities,
    get_submitted_review, observe_identity_and_permissions,
    reduce_evidence_index, run_hosted_qualification, run_offline_qualification,
)


class _HostedQualificationFakeServer:
    """Fake GitHub API server for qualification foundation testing."""

    def __init__(
        self,
        *,
        users: dict[str, dict[str, Any]] | None = None,
        repo_perms: dict[str, dict[str, Any]] | None = None,
        protections: dict[str, dict[str, Any]] | None = None,
        protection_status: int = 200,
        contents: dict[str, dict[str, Any]] | None = None,
        reviews: dict[int, dict[str, Any]] | None = None,
        default_branch: str = "main",
    ) -> None:
        self.users = users if users is not None else {
            "valid-int-tok": {"login": "huyhuyhuy8s"},
            "valid-comp-tok": {"login": "cone-orgs"},
        }
        self.repo_perms = repo_perms if repo_perms is not None else {
            "valid-int-tok": {"admin": True, "push": True, "pull": True},
            "valid-comp-tok": {"admin": False, "push": True, "pull": True},
        }
        self.protection_status = protection_status
        def_prot = {
            "required_status_checks": {"strict": True, "contexts": ["ci/build"]},
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True},
        }
        self.protections = protections if protections is not None else {"main": def_prot, "feature/demo": def_prot}
        self.contents = contents if contents is not None else {
            ".github/workflows/ci.yml": {"sha": "wf123", "name": "ci.yml"},
            ".factory/policy.json": {"sha": "pol123", "name": "policy.json"},
        }
        self.reviews = reviews if reviews is not None else {
            42: {"id": 42, "state": "APPROVED", "user": {"login": "cone-orgs"}},
        }
        self.default_branch = default_branch
        self.requests: list[dict[str, Any]] = []

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _send_json(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                auth = self.headers.get("Authorization", "")
                tok = auth.split("Bearer ", 1)[-1] if "Bearer " in auth else auth.split("token ", 1)[-1]
                path = urlparse(self.path).path
                outer.requests.append({"path": path, "token": tok})

                if path == "/api/v3/user":
                    if tok in outer.users:
                        return self._send_json(200, outer.users[tok])
                    return self._send_json(401, {"message": "Bad credentials"})

                if path == "/api/v3/repos/turbo-factory/turbo-qual-67":
                    perms = outer.repo_perms.get(tok, {"admin": False, "push": False, "pull": True})
                    return self._send_json(200, {
                        "full_name": "turbo-factory/turbo-qual-67",
                        "default_branch": outer.default_branch,
                        "owner": {"login": "turbo-factory", "type": "Organization"},
                        "permissions": perms,
                    })

                prefix_prot = "/api/v3/repos/turbo-factory/turbo-qual-67/branches/"
                if path.startswith(prefix_prot) and path.endswith("/protection"):
                    if outer.protection_status != 200:
                        return self._send_json(outer.protection_status, {"message": f"Protection HTTP {outer.protection_status}"})
                    raw_b = path[len(prefix_prot) : -len("/protection")]
                    bname = unquote(raw_b)
                    if bname in outer.protections:
                        return self._send_json(200, outer.protections[bname])
                    return self._send_json(404, {"message": "Branch not protected"})

                prefix_cont = "/api/v3/repos/turbo-factory/turbo-qual-67/contents/"
                if path.startswith(prefix_cont):
                    cpath = unquote(path[len(prefix_cont):])
                    if cpath in outer.contents:
                        return self._send_json(200, outer.contents[cpath])
                    return self._send_json(404, {"message": "File not found"})

                prefix_rev = "/api/v3/repos/turbo-factory/turbo-qual-67/pulls/1/reviews/"
                if path.startswith(prefix_rev):
                    rid = int(path[len(prefix_rev):])
                    if rid in outer.reviews:
                        return self._send_json(200, outer.reviews[rid])
                    return self._send_json(404, {"message": "Review not found"})

                return self._send_json(404, {"message": "Not Found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/api/v3"
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self) -> _HostedQualificationFakeServer:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()


class QualificationSafetyAndCapabilityTest(unittest.TestCase):
    def test_hosted_authorization_guards(self) -> None:
        """Reject unallowlisted repositories, disallowed branches, wrong origins, and missing live flag."""
        # 1. Disabled live qualification
        ok, msg = check_hosted_authorization("turbo-factory/turbo-qual-67", live_enabled=False)
        self.assertFalse(ok)
        self.assertIn("hosted-qualification-disabled", msg)

        # 2. Disallowed repository slug (including old redirecting slug)
        ok, msg = check_hosted_authorization("huyle-gradion/turbo-qual-67", live_enabled=True)
        self.assertFalse(ok)
        self.assertIn("repo-disallowed", msg)

        # 3. Disallowed target branch (e.g. main)
        ok, msg = check_hosted_authorization("turbo-factory/turbo-qual-67", live_enabled=True, target_branch="main")
        self.assertFalse(ok)
        self.assertIn("target-branch-disallowed", msg)

        # 4. Wrong origin (must be fixed https://api.github.com)
        ok, msg = check_hosted_authorization("turbo-factory/turbo-qual-67", live_enabled=True, base_url="https://evil.example.com")
        self.assertFalse(ok)
        self.assertIn("wrong-origin", msg)

        # 5. Allowlisted repo, branch, and origin
        ok, msg = check_hosted_authorization("turbo-factory/turbo-qual-67", live_enabled=True)
        self.assertTrue(ok)
        self.assertEqual(msg, "")

        # 6. run_hosted_qualification with wrong origin prevents qualification
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = Path(tmp) / "ev"
            res = run_hosted_qualification(
                "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                integrator_token="tok1", competitor_token="tok2",
                base_url="https://wrong-origin.example.com",
            )
            self.assertEqual(res["status"], "blocked")
            self.assertEqual(res["outcome"], "unavailable")
            self.assertFalse(res["qualified"])
            self.assertTrue(any("wrong-origin" in b for b in res["blockers"]))

    def test_missing_tokens_prevent_qualification(self) -> None:
        """Missing tokens record unavailable status across all checks and prevent qualification."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = Path(tmp) / "ev"
            res = run_hosted_qualification(
                "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                integrator_token=None, competitor_token="tok2",
                allow_test_origin=True,
            )
            self.assertEqual(res["status"], "blocked")
            self.assertEqual(res["outcome"], "unavailable")
            self.assertFalse(res["qualified"])
            self.assertTrue(any("missing-credentials" in b for b in res["blockers"]))
            self.assertEqual(res["preflight"]["identities"]["integrator"]["status"], "unavailable")

    def test_wrong_identities_and_permissions_prevent_qualification(self) -> None:
        """Wrong account identity or insufficient repo permission stops qualification explicitly."""
        # 1. Integrator token has wrong login
        with _HostedQualificationFakeServer(users={"int-tok": {"login": "attacker"}, "comp-tok": {"login": "cone-orgs"}}) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="int-tok", competitor_token="comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertEqual(res["status"], "blocked")
                self.assertTrue(any("wrong-identity" in b for b in res["blockers"]))

        # 2. Competitor token has wrong login
        with _HostedQualificationFakeServer(users={"int-tok": {"login": "huyhuyhuy8s"}, "comp-tok": {"login": "intruder"}}) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="int-tok", competitor_token="comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertTrue(any("wrong-identity" in b for b in res["blockers"]))

        # 3. Integrator lacks admin permission
        bad_perms = {
            "valid-int-tok": {"admin": False, "push": True, "pull": True},
            "valid-comp-tok": {"admin": False, "push": True, "pull": True},
        }
        with _HostedQualificationFakeServer(repo_perms=bad_perms) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertTrue(any("insufficient-permissions" in b for b in res["blockers"]))

    def test_both_branch_protection_and_empty_contexts_prevent_qualification(self) -> None:
        """Branch protection must cover both branches and reject empty required status check contexts."""
        # 1. 403 on branch protection read
        with _HostedQualificationFakeServer(protection_status=403) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertTrue(any("unavailable-protection-capability" in b for b in res["blockers"]))

        # 2. Empty required check contexts on feature/demo
        empty_ctx_protections = {
            "main": {"required_status_checks": {"strict": True, "contexts": ["ci/build"]}, "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}, "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True}},
            "feature/demo": {"required_status_checks": {"strict": True, "contexts": []}, "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}, "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True}},
        }
        with _HostedQualificationFakeServer(protections=empty_ctx_protections) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertTrue(any("empty-required-check-contexts" in b for b in res["blockers"]))

    def test_missing_seed_assets_prevent_qualification(self) -> None:
        """Missing seed assets (workflow or policy) on feature/demo prevent qualification."""
        with _HostedQualificationFakeServer(contents={}) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"])
                self.assertTrue(any("missing-seed" in b for b in res["blockers"]))

    def test_missing_artifacts_and_simulated_prevent_qualification(self) -> None:
        """Missing evidence artifacts and simulated observations prevent hosted qualification."""
        # 1. Missing artifact path in index
        fake_index = {
            "AC1": {
                "ac_id": "AC1", "scenarios": ["s1"],
                "artifact_paths": ["/tmp/nonexistent-artifact-123.json"],
                "hosted_proof_status": "VERIFIED",
            }
        }
        reduced, qualified, blockers = reduce_evidence_index(
            fake_index, {"status": "verified"}, {"s1": {"outcome": "passed", "simulated": False}},
        )
        self.assertFalse(qualified)
        self.assertTrue(any("missing-artifacts" in b for b in blockers))
        self.assertEqual(reduced["AC1"]["subchecks"]["artifacts"], "missing")

        # 2. Simulated observations prevent hosted qualification even if scenarios pass
        fake_index2 = {
            "AC1": {
                "ac_id": "AC1", "scenarios": ["s1"],
                "artifact_paths": [],
                "hosted_proof_status": "VERIFIED",
            }
        }
        reduced2, qualified2, blockers2 = reduce_evidence_index(
            fake_index2, {"status": "verified"}, {"s1": {"outcome": "passed", "simulated": True}},
        )
        self.assertFalse(qualified2)
        self.assertEqual(reduced2["AC1"]["hosted_proof_status"], "PENDING")

        # 3. Fake provider tests never promote hosted qualification
        with _HostedQualificationFakeServer() as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                res = run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    base_url=gh.base_url, allow_test_origin=True,
                )
                self.assertFalse(res["qualified"], "Fake-provider tests must NEVER promote hosted status")
                self.assertEqual(res["status"], "blocked")
                self.assertIn("hosted-scenarios-pending-human-setup", res["blockers"])

    def test_qualification_token_redaction_and_ledger(self) -> None:
        """Explicitly redact qualification tokens in persistence and record operation ledger."""
        secret_int = "ghp_SECRET_INTEGRATOR_ABC_123"
        secret_comp = "ghp_SECRET_COMPETITOR_XYZ_789"
        custom_users = {secret_int: {"login": "huyhuyhuy8s"}, secret_comp: {"login": "cone-orgs"}}
        custom_perms = {secret_int: {"admin": True, "push": True, "pull": True}, secret_comp: {"admin": False, "push": True, "pull": True}}

        with _HostedQualificationFakeServer(users=custom_users, repo_perms=custom_perms) as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                run_hosted_qualification(
                    "turbo-factory/turbo-qual-67", ev_dir, live_enabled=True,
                    integrator_token=secret_int, competitor_token=secret_comp,
                    base_url=gh.base_url, allow_test_origin=True,
                )

                # Verify files exist
                ledger_path = ev_dir / "operation-ledger.jsonl"
                summary_path = ev_dir / "qualification-summary.json"
                preflight_path = ev_dir / "preflight-observations.json"
                index_path = ev_dir / "parent-evidence-index.json"

                self.assertTrue(ledger_path.exists())
                self.assertTrue(summary_path.exists())
                self.assertTrue(preflight_path.exists())
                self.assertTrue(index_path.exists())

                # Verify token values NEVER appear in any persisted file
                for path in (ledger_path, summary_path, preflight_path, index_path):
                    content = path.read_text(encoding="utf-8")
                    self.assertNotIn(secret_int, content, f"Secret integrator token leaked in {path.name}")
                    self.assertNotIn(secret_comp, content, f"Secret competitor token leaked in {path.name}")

                # Verify ledger recorded operations
                ledger_lines = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
                self.assertTrue(len(ledger_lines) >= 4)
                self.assertEqual(ledger_lines[0]["seq"], 1)
                self.assertEqual(ledger_lines[0]["actor"], "integrator")

    def test_get_submitted_review_by_id(self) -> None:
        """Read submitted PR review by ID from object endpoint rather than array responses."""
        with _HostedQualificationFakeServer() as gh:
            code, data, msg = get_submitted_review(gh.base_url, "turbo-factory/turbo-qual-67", 1, 42, "valid-int-tok")
            self.assertEqual(code, 200)
            self.assertEqual(data.get("id"), 42)
            self.assertEqual(data.get("state"), "APPROVED")
            self.assertEqual(data.get("user", {}).get("login"), "cone-orgs")


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
