"""Tests for protected repository qualification harness (#67)."""
from __future__ import annotations

import base64, json, os, shutil, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from factory.qualification import (
    CALC_CANDIDATE_SRC, CALC_CANDIDATE_TEST,
    DISPOSABLE_REPO_ALLOWLIST, REQUIRED_SEED_ASSETS, SEED_ASSETS_DIR,
    assert_landed_landing_properties,
    build_parent_evidence_index, check_branch_protection_and_topology,
    check_credentials_and_capabilities, check_hosted_authorization,
    check_qualification_pr_ci, check_seed_and_workflow_capabilities,
    create_qualification_pull_request, evaluate_qualification_qa,
    get_submitted_review, observe_identity_and_permissions,
    prepare_qualification_candidate, reduce_evidence_index,
    resolve_agy_bin,
    run_hosted_qualification, run_offline_qualification,
    run_scenario_1_confirmed_landing, run_scenario_2_prereq_missing_and_denied,
    run_scenario_3_competing_base_rejection, run_scenario_4_renewed_verification_after_base_change,
    submit_qualification_pr_review, verify_qualification_pr_review,
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
            "src/calc.py": {"sha": "calc123", "name": "calc.py", "content": base64.b64encode(b"def add(a, b): return a + b\ndef multiply(a, b): return a * b\ndef subtract(a, b): return a - b\n").decode()},
            "tests/test_calc.py": {"sha": "testcalc123", "name": "test_calc.py", "content": base64.b64encode(b"import unittest\nclass T(unittest.TestCase):\n def test_add(self): pass\n def test_multiply(self): pass\n def test_subtract(self): pass\n").decode()},
            "qa/qa-cases.json": {"sha": "qa123", "name": "qa-cases.json"},
        }
        self.reviews = reviews if reviews is not None else {
            42: {"id": 42, "state": "APPROVED", "commit_id": "c1234567890abcdef1234567890abcdef1234567", "user": {"login": "cone-orgs"}},
            43: {"id": 43, "state": "APPROVED", "commit_id": "c1234567890abcdef1234567890abcdef1234567", "user": {"login": "huyhuyhuy8s"}},
        }
        self.pulls: dict[int, dict[str, Any]] = {
            1: {
                "number": 1,
                "title": "Existing PR",
                "state": "open",
                "head": {"sha": "c1234567890abcdef1234567890abcdef1234567", "ref": "feat/qual-candidate-101"},
                "base": {"sha": "b1234567890abcdef1234567890abcdef1234567", "ref": "feature/demo"},
                "user": {"login": "cone-orgs"},
            }
        }
        self.check_runs: list[dict[str, Any]] = [
            {
                "id": 501,
                "name": "build",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "c1234567890abcdef1234567890abcdef1234567",
                "app": {"slug": "github-actions"},
            }
        ]
        self.default_branch = default_branch
        self.branch_heads: dict[str, str] = {}
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
                outer.requests.append({"method": "GET", "path": path, "token": tok})

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
                    cpath = unquote(path[len(prefix_cont):]).split("?")[0]
                    if cpath in outer.contents:
                        return self._send_json(200, outer.contents[cpath])
                    return self._send_json(404, {"message": "File not found"})

                if "/commits/" in path and path.endswith("/check-runs"):
                    return self._send_json(200, {"total_count": len(outer.check_runs), "check_runs": outer.check_runs})

                prefix_pr = "/api/v3/repos/turbo-factory/turbo-qual-67/pulls/"
                if path.startswith(prefix_pr) and not "/reviews" in path:
                    pr_id_str = path[len(prefix_pr):]
                    if pr_id_str.isdigit() and int(pr_id_str) in outer.pulls:
                        return self._send_json(200, outer.pulls[int(pr_id_str)])

                if "/reviews/" in path:
                    prefix_rev = path[:path.rfind("/reviews/") + len("/reviews/")]
                    rid_str = path[len(prefix_rev):]
                    if rid_str.isdigit():
                        rid = int(rid_str)
                        if rid in outer.reviews:
                            return self._send_json(200, outer.reviews[rid])
                    return self._send_json(404, {"message": "Review not found"})

                return self._send_json(404, {"message": "Not Found"})

            def do_POST(self) -> None:
                auth = self.headers.get("Authorization", "")
                tok = auth.split("Bearer ", 1)[-1] if "Bearer " in auth else auth.split("token ", 1)[-1]
                path = urlparse(self.path).path
                len_hdr = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(len_hdr).decode("utf-8") if len_hdr > 0 else "{}"
                try:
                    body = json.loads(raw_body)
                except Exception:
                    body = {}
                outer.requests.append({"method": "POST", "path": path, "token": tok, "body": body})

                # Create pull request
                if path == "/api/v3/repos/turbo-factory/turbo-qual-67/pulls":
                    pr_num = len(outer.pulls) + 1
                    user_login = outer.users.get(tok, {}).get("login", "unknown")
                    ref_h = body.get("head", "")
                    ref_b = body.get("base", "feature/demo")
                    h_sha = outer.branch_heads.get(ref_h, "c1234567890abcdef1234567890abcdef1234567")
                    b_sha = outer.branch_heads.get(ref_b, "b1234567890abcdef1234567890abcdef1234567")
                    pr_obj = {
                        "number": pr_num,
                        "title": body.get("title", "Candidate PR"),
                        "state": "open",
                        "head": {"sha": h_sha, "ref": ref_h, "repo": {"full_name": "turbo-factory/turbo-qual-67"}},
                        "base": {"sha": b_sha, "ref": ref_b, "repo": {"full_name": "turbo-factory/turbo-qual-67"}},
                        "user": {"login": user_login},
                    }
                    outer.pulls[pr_num] = pr_obj
                    return self._send_json(201, pr_obj)

                # Submit pull request review
                prefix_pr_rev = "/api/v3/repos/turbo-factory/turbo-qual-67/pulls/"
                if path.startswith(prefix_pr_rev) and path.endswith("/reviews"):
                    user_login = outer.users.get(tok, {}).get("login", "unknown")
                    pr_id_str = path[len(prefix_pr_rev):-len("/reviews")]
                    pr_id = int(pr_id_str) if pr_id_str.isdigit() else 1
                    pr_author = outer.pulls.get(pr_id, {}).get("user", {}).get("login", "cone-orgs")
                    if user_login == pr_author:
                        return self._send_json(422, {"message": "Unprocessable Entity: Author cannot review own PR"})

                    rev_id = len(outer.reviews) + 100
                    ev = body.get("event", "APPROVE")
                    rev_obj = {
                        "id": rev_id,
                        "state": "APPROVED" if ev == "APPROVE" else ev,
                        "commit_id": body.get("commit_id", ""),
                        "body": body.get("body", ""),
                        "user": {"login": user_login},
                    }
                    outer.reviews[rev_id] = rev_obj
                    return self._send_json(200, rev_obj)

                return self._send_json(404, {"message": "Not Found"})

            def do_PUT(self) -> None:
                auth = self.headers.get("Authorization", "")
                tok = auth.split("Bearer ", 1)[-1] if "Bearer " in auth else auth.split("token ", 1)[-1]
                path = urlparse(self.path).path
                len_hdr = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(len_hdr).decode("utf-8") if len_hdr > 0 else "{}"
                try: body = json.loads(raw_body)
                except Exception: body = {}
                outer.requests.append({"method": "PUT", "path": path, "token": tok, "body": body})

                if "/pulls/" in path and path.endswith("/merge"):
                    pr_id_str = path.split("/pulls/")[1].split("/merge")[0]
                    pr_id = int(pr_id_str) if pr_id_str.isdigit() else 1
                    pr = outer.pulls.get(pr_id, {})
                    pr["state"] = "closed"
                    pr["merged"] = True
                    return self._send_json(200, {"sha": "l1234567890abcdef1234567890abcdef1234567", "merged": True, "message": "Pull Request successfully merged"})

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

    def test_both_branch_protection_empty_contexts_and_missing_seed_assets_prevent_qualification(self) -> None:
        """Branch protection must cover both branches, reject empty required check contexts, and require seed assets."""
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

        # 3. Missing seed assets (workflow or policy) on feature/demo
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
                self.assertIn("hosted-scenarios-5-and-6-pending-slice-5", res["blockers"])

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


class QualificationCandidatePreparationTest(unittest.TestCase):
    def test_seed_assets_integrity_and_rubric_execution(self) -> None:
        """Validate seed assets, deterministic QA cases, and rubric execution."""
        from factory.automated_qa import load_qa_cases_file

        self.assertTrue(SEED_ASSETS_DIR.exists())
        for path_suffix, desc in REQUIRED_SEED_ASSETS:
            local_rel = path_suffix.replace(".factory/", "factory/")
            full_path = SEED_ASSETS_DIR / local_rel
            self.assertTrue(full_path.exists(), f"Missing required seed asset: {desc} at {local_rel}")

        qa_file = SEED_ASSETS_DIR / "qa" / "qa-cases.json"
        cases = load_qa_cases_file(qa_file)
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0].case_id, "QA-CALC-1")
        self.assertEqual(cases[1].case_id, "QA-CALC-2")

        # Execute QA against seed product fixture
        ok, qa_rec, blockers = evaluate_qualification_qa(SEED_ASSETS_DIR, qa_cases=cases)
        self.assertTrue(ok)
        self.assertEqual(qa_rec["status"], "verified")
        self.assertTrue(qa_rec["qa_verified"])
        self.assertEqual(len(blockers), 0)

        # Candidate commit fixture defines genuine operations and executable tests
        for op in ("add", "multiply", "subtract"):
            self.assertIn(f"def {op}", CALC_CANDIDATE_SRC)
            self.assertIn(f"def test_{op}", CALC_CANDIDATE_TEST)
        self.assertIn("class CalcTest", CALC_CANDIDATE_TEST)

    def test_qualification_pr_creation_and_actor_separation(self) -> None:
        """Validate candidate PR creation by competitor and rejection of self-review."""
        with _HostedQualificationFakeServer() as gh:
            # Competitor creates candidate PR
            code, pr_data, msg = create_qualification_pull_request(
                gh.base_url, "turbo-factory/turbo-qual-67", "feat/candidate-101", "feature/demo",
                "feat: candidate PR", "Test candidate PR body", "valid-comp-tok",
            )
            self.assertEqual(code, 201)
            pr_num = pr_data["number"]
            self.assertEqual(pr_data["user"]["login"], "cone-orgs")

            # Competitor attempts to review own PR -> rejected 422
            code_self, _, _ = submit_qualification_pr_review(
                gh.base_url, "turbo-factory/turbo-qual-67", pr_num, "c1234567890abcdef1234567890abcdef1234567",
                "APPROVE", "Self-approval attempt", "valid-comp-tok",
            )
            self.assertEqual(code_self, 422)

            # Integrator submits review -> accepted 200
            code_int, rev_data, _ = submit_qualification_pr_review(
                gh.base_url, "turbo-factory/turbo-qual-67", pr_num, "c1234567890abcdef1234567890abcdef1234567",
                "APPROVE", "Independent approval", "valid-int-tok",
            )
            self.assertEqual(code_int, 200)
            self.assertEqual(rev_data["user"]["login"], "huyhuyhuy8s")

    def test_qualification_pr_review_revision_binding_and_verification(self) -> None:
        """Review readback verifies exact candidate commit_id and independent reviewer."""
        cand_sha = "c1234567890abcdef1234567890abcdef1234567"
        with _HostedQualificationFakeServer() as gh:
            # 1. Matching candidate SHA and expected reviewer
            ok, data, blockers = verify_qualification_pr_review(
                gh.base_url, "turbo-factory/turbo-qual-67", 1, 43, cand_sha,
                expected_reviewer="huyhuyhuy8s", token="valid-int-tok",
            )
            self.assertTrue(ok)
            self.assertEqual(data["commit_id"], cand_sha)
            self.assertEqual(len(blockers), 0)

            # 2. Candidate SHA drift
            ok_drift, _, drift_blockers = verify_qualification_pr_review(
                gh.base_url, "turbo-factory/turbo-qual-67", 1, 43, "stale-sha-9999999999999999999999999999999999999999",
                expected_reviewer="huyhuyhuy8s", token="valid-int-tok",
            )
            self.assertFalse(ok_drift)
            self.assertTrue(any("review-revision-drift" in b for b in drift_blockers))

            # 3. Wrong reviewer
            ok_role, _, role_blockers = verify_qualification_pr_review(
                gh.base_url, "turbo-factory/turbo-qual-67", 1, 43, cand_sha,
                expected_reviewer="wrong-user", token="valid-int-tok",
            )
            self.assertFalse(ok_role)
            self.assertTrue(any("reviewer-role-violation" in b for b in role_blockers))

            # 4. Submitted review is read by ID from the object endpoint, not an array response
            code, data, msg = get_submitted_review(gh.base_url, "turbo-factory/turbo-qual-67", 1, 42, "valid-int-tok")
            self.assertEqual(code, 200)
            self.assertEqual(data.get("id"), 42)
            self.assertEqual(data.get("state"), "APPROVED")
            self.assertEqual(data.get("user", {}).get("login"), "cone-orgs")

    def test_qualification_pr_ci_verification(self) -> None:
        """Verify CI check run inspection against required context and trusted producer."""
        cand_sha = "c1234567890abcdef1234567890abcdef1234567"
        base_sha = "b1234567890abcdef1234567890abcdef1234567"
        with _HostedQualificationFakeServer() as gh:
            # 1. Success with trusted producer
            ok, rec, blockers = check_qualification_pr_ci(
                gh.base_url, "turbo-factory/turbo-qual-67", cand_sha, base_sha, "valid-int-tok",
                required_contexts=("build",),
            )
            self.assertTrue(ok)
            self.assertEqual(rec["status"], "verified")
            self.assertEqual(len(blockers), 0)

            # 2. Missing required context
            ok_miss, _, miss_blockers = check_qualification_pr_ci(
                gh.base_url, "turbo-factory/turbo-qual-67", cand_sha, base_sha, "valid-int-tok",
                required_contexts=("nonexistent-check",),
            )
            self.assertFalse(ok_miss)
            self.assertTrue(any("missing-ci-check" in b for b in miss_blockers))

    def test_prepare_qualification_candidate_reviewer_capability(self) -> None:
        """Missing reviewer executable records unavailable and blocks preparation; a supported one prepares."""
        cand_sha = "c1234567890abcdef1234567890abcdef1234567"
        base_sha = "b1234567890abcdef1234567890abcdef1234567"
        with _HostedQualificationFakeServer() as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                rec = prepare_qualification_candidate(
                    gh.base_url, "turbo-factory/turbo-qual-67", ev_dir,
                    candidate_sha=cand_sha, base_sha=base_sha,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    agy_bin=None, allow_test_origin=True,
                )
                self.assertEqual(rec["status"], "blocked")
                self.assertEqual(rec["outcome"], "unavailable")
                self.assertTrue(any("unsupported-reviewer-capability" in b for b in rec["blockers"]))
                self.assertEqual(rec["prerequisites"]["security"]["status"], "unavailable")
                self.assertEqual(rec["prerequisites"]["independent_review"]["status"], "unavailable")
                self.assertEqual(rec["builder"]["kind"], "deterministic-qualification-process")
                self.assertEqual(rec["builder"]["actor"], "cone-orgs")

                # Verify file was written
                prep_file = ev_dir / "candidate-preparation.json"
                self.assertTrue(prep_file.exists())

        # When supported reviewer executable is provided, candidate preparation succeeds
        with _HostedQualificationFakeServer() as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                # Create a temporary dummy executable reviewer
                fake_agy = Path(tmp) / "mock-agy"
                fake_agy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                fake_agy.chmod(0o755)

                rec = prepare_qualification_candidate(
                    gh.base_url, "turbo-factory/turbo-qual-67", ev_dir,
                    candidate_sha=cand_sha, base_sha=base_sha,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    agy_bin=str(fake_agy), allow_test_origin=True,
                )
                self.assertEqual(rec["status"], "prepared")
                self.assertEqual(rec["outcome"], "prepared")
                self.assertEqual(len(rec["blockers"]), 0)
                self.assertTrue(rec["prerequisites"]["qa"]["qa_verified"])
                self.assertEqual(rec["prerequisites"]["ci"]["status"], "verified")
                self.assertEqual(rec["prerequisites"]["github_review"]["state"], "APPROVED")
                self.assertEqual(rec["builder"]["candidate_sha"], cand_sha)


class HostedScenariosExecutionTest(unittest.TestCase):
    def test_hosted_scenarios_simulated_execution(self) -> None:
        """Verify scenario runners 1-4, boundary coordination, and renewal flows."""
        from support_deliver import setup_disposable_delivery_context

        with _HostedQualificationFakeServer() as gh:
            with tempfile.TemporaryDirectory() as tmp:
                ev_dir = Path(tmp) / "ev"
                ws = ev_dir / "ws"
                ws.mkdir(parents=True)
                with setup_disposable_delivery_context(ws) as ctx:
                    from support import git
                    git(ctx.bare, "update-ref", "refs/heads/feature/demo", ctx.base_sha)
                    gh.branch_heads = {
                        "feat/qual-candidate-101": ctx.cand_sha,
                        "feat/qual-unapp-sc2-r2": ctx.cand_sha,
                        "feat/qual-cand-sc3-r2": ctx.cand_sha,
                        "feat/qual-adv-sc3-r2": ctx.cand_sha,
                        "feat/qual-cand-sc3-r3": ctx.cand_sha,
                        "feat/qual-adv-sc3-r3": ctx.cand_sha,
                        "feature/demo": ctx.base_sha,
                    }
                    # Scenario 1: Confirmed landing
                    s1 = run_scenario_1_confirmed_landing(
                        gh.base_url, "turbo-factory/turbo-qual-67", ev_dir, ctx,
                        "valid-int-tok", "valid-comp-tok", allow_test_origin=True,
                    )
                    self.assertEqual(s1["scenario"], "confirmed_landing")
                    self.assertEqual(s1["head_branch"], "feat/qual-candidate-101")

                    # Scenario 2: Prereq missing and denied
                    s2 = run_scenario_2_prereq_missing_and_denied(
                        gh.base_url, "turbo-factory/turbo-qual-67", ev_dir, ctx,
                        "valid-int-tok", "valid-comp-tok", allow_test_origin=True,
                    )
                    self.assertEqual(s2["scenario"], "prereq_missing_and_denied")
                    self.assertTrue(s2["missing_prereq_rejected"])
                    self.assertTrue(s2["stale_prereq_rejected"])
                    self.assertTrue(s2["main_preserved"])

                    # Scenario 3: Competing base rejection
                    s3, cand_br3, base_prime, cand_pr3 = run_scenario_3_competing_base_rejection(
                        gh.base_url, "turbo-factory/turbo-qual-67", ev_dir, ctx,
                        "valid-int-tok", "valid-comp-tok", allow_test_origin=True,
                    )
                    self.assertEqual(s3["scenario"], "competing_base_rejection")
                    self.assertTrue(s3["main_preserved"])

                    # Scenario 4: Renewed verification after base change
                    s4 = run_scenario_4_renewed_verification_after_base_change(
                        gh.base_url, "turbo-factory/turbo-qual-67", ev_dir, ctx,
                        "valid-int-tok", "valid-comp-tok", cand_br3, base_prime, cand_pr3,
                        allow_test_origin=True,
                    )
                    self.assertEqual(s4["scenario"], "renewed_verification_after_base_change")
                    self.assertTrue(s4["old_evidence_rejected"])


if __name__ == "__main__":
    unittest.main()
