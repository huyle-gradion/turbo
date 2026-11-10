"""The seed CI workflow emits the gate's required checks; the seed install has a dry-run plan (#109)."""
from __future__ import annotations

import fnmatch, json, re, shutil, subprocess, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from factory import ci_gate, qualification
from factory.ci_selection import build_required_ci_checks
from factory.errors import UsageError
from factory.qualification import CALC_CANDIDATE_SRC, SEED_ASSETS_DIR
from test_qualification_prereqs import HEAD_BRANCH, REPO, _seeded_origin

WORKFLOW = SEED_ASSETS_DIR / ".github" / "workflows" / "ci.yml"
# Per-check fields the gate reads from each `turbo-ci-evidence.json` checks entry (ci_gate / deliver_checks).
EVIDENCE_FIELDS = ("check_name", "candidate_sha", "base_sha", "tested_sha", "policy_sha", "workflow_path",
                   "exit_code", "conclusion", "log_text")


def _blocks(text: str, indent: int) -> dict[str, str]:
    """Stdlib-only structural split: `key:` lines at exactly `indent` spaces -> the text up to the next such key."""
    keys = list(re.finditer(rf"(?m)^ {{{indent}}}([^\s#:][^:]*):", text))
    return {m.group(1).strip().strip("'\""): text[m.end():(keys[i + 1].start() if i + 1 < len(keys) else len(text))]
            for i, m in enumerate(keys)}


def _scalars(block: str, key: str) -> list[str]:
    return [v.strip().strip("'\"") for v in re.findall(rf"(?m)^\s*-?\s*{key}:\s*(\S.*?)\s*$", block)]


class _Recorder:
    """Loopback stand-in for the GitHub API that records every request and performs nothing."""

    def __enter__(self) -> "_Recorder":
        self.requests: list[tuple[str, str]] = []
        rec = self.requests

        class H(BaseHTTPRequestHandler):
            def _any(self) -> None:
                rec.append((self.command, self.path))
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"message": "Not Found"}')
            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _any
            def log_message(self, *a: object) -> None: pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        return self

    def __exit__(self, *a: object) -> None:
        self.srv.shutdown()
        self.srv.server_close()


class SeedCiAndInstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """Required check names exactly as hosted preparation derives them: hosted context -> build_required_ci_checks."""
        tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, tmp, True)
        origin, _bare, _cand, _base = _seeded_origin(tmp, CALC_CANDIDATE_SRC)
        with mock.patch("factory.qualification.HOSTED_CLONE_URL_TEMPLATE", f"{origin}/{{repo_slug}}.git"), \
                qualification.hosted_scenario_context(tmp / "ws", REPO, "valid-int-tok", blockers=[]) as ctx:
            child = {**ctx.child_contract, "head_branch": HEAD_BRANCH}
            cls.required = [r["name"] for r in build_required_ci_checks(child, ctx.conf)]

    def test_seed_workflow_defines_each_required_check_with_gate_evidence(self) -> None:
        """AC1: one job per required check, named as the gate expects, each uploading a gate-readable evidence artifact."""
        self.assertIn("criterion/CRIT-CALC-1", self.required)  # the seed contract's criteria reach the gate
        text = WORKFLOW.read_text(encoding="utf-8")
        top = _blocks(text, 0)
        with self.subTest("trusted workflow path and event"):
            self.assertIn(".github/workflows/ci.yml", ci_gate.TRUSTED_WORKFLOW_PATHS)
            on = _blocks(top["on"], 2)
            self.assertIn("pull_request", on)
            self.assertIn("pull_request", ci_gate.TRUSTED_WORKFLOW_EVENTS)
            patterns = re.findall(r"[\w./*-]+", on["pull_request"].split("branches:", 1)[-1]) if "branches:" in on["pull_request"] else ["*"]
            self.assertTrue(any(fnmatch.fnmatch("feature/demo", p) for p in patterns), patterns)
        names = {}  # check-run name = the job's literal `name:` (job ids cannot hold '/'), else the job id
        for jid, blk in _blocks(top["jobs"], 2).items():
            m = re.search(r"(?m)^ {4}name:\s*(.+?)\s*$", blk)
            names[m.group(1).strip("'\"") if m else jid] = blk
        with self.subTest("exactly the required check names"):
            self.assertEqual(sorted(names), sorted(self.required))
        artifact_names: list[str] = []
        for check in self.required:
            blk = names.get(check, "")
            with self.subTest("evidence artifact", check=check):
                self.assertRegex(blk, r"uses:\s*actions/upload-artifact@")
                arts = [n for n in _scalars(blk, "name") if n.startswith("turbo-ci-evidence")]
                self.assertEqual(len(arts), 1, f"{check}: one turbo-ci-evidence* artifact, got {arts}")
                artifact_names += arts
                self.assertTrue(any(p.endswith("turbo-ci-evidence.json") for p in _scalars(blk, "path")), check)
                for field in EVIDENCE_FIELDS:
                    self.assertIn(field, blk, f"{check}: evidence entry lacks {field}")
                self.assertIn(".github/workflows/ci.yml", blk, f"{check}: workflow_path must be the trusted path")
                self.assertGreaterEqual(blk.count(check), 2, f"{check}: evidence must be keyed by the check name")
        with self.subTest("artifact names unique per run"):
            self.assertEqual(len(artifact_names), len(set(artifact_names)), artifact_names)
        with self.subTest("seed policy lists the same checks"):
            policy = json.loads((SEED_ASSETS_DIR / "factory" / "policy.json").read_text(encoding="utf-8"))
            self.assertEqual(sorted(policy["required_checks"]), sorted(self.required))

    def test_seed_install_dry_run_plans_without_mutating_and_refuses_unsafe_targets(self) -> None:
        """AC2: the plan installs the seed files and sets protection contexts to the gate's names; dry run mutates nothing."""
        expected_files = {}
        for f in sorted(p for p in SEED_ASSETS_DIR.rglob("*") if p.is_file()):
            rel = f.relative_to(SEED_ASSETS_DIR).as_posix()
            expected_files[".factory/" + rel[len("factory/"):] if rel.startswith("factory/") else rel] = f.read_text(encoding="utf-8")
        real_popen = subprocess.Popen
        spawned: list[list[str]] = []

        def guarded_popen(args, *a, **kw):  # type: ignore[no-untyped-def]
            argv = [str(x) for x in (args if isinstance(args, (list, tuple)) else [args])]
            spawned.append(argv)
            if "push" in argv:
                raise AssertionError(f"seed install pushed: {argv}")
            return real_popen(args, *a, **kw)

        with _Recorder() as gh, mock.patch("subprocess.Popen", side_effect=guarded_popen):
            plan = qualification.plan_seed_install(REPO, "feature/demo")
            with self.subTest("plan"):
                self.assertEqual((plan["repo_slug"], plan["branch"]), (REPO, "feature/demo"))
                self.assertEqual(plan["files"], expected_files)
                self.assertTrue({p for p, _ in qualification.REQUIRED_SEED_ASSETS} <= set(plan["files"]))
                self.assertIn(".factory/child-contract.json", plan["files"])
                self.assertCountEqual(plan["required_status_contexts"], self.required)
            with self.subTest("dry run"):
                res = qualification.install_seed(gh.url, REPO, "feature/demo", "tok", dry_run=True)
                self.assertIs(res["dry_run"], True)
                self.assertEqual(res["plan"], plan)
                self.assertEqual([r for r in gh.requests if r[0] != "GET"], [])
            for slug, branch in (("someone/else", "feature/demo"), (REPO, "main")):
                with self.subTest("refused", slug=slug, branch=branch):
                    before = len(gh.requests)
                    with self.assertRaises(UsageError):
                        qualification.plan_seed_install(slug, branch)
                    with self.assertRaises(UsageError):
                        qualification.install_seed(gh.url, slug, branch, "tok", dry_run=False)
                    self.assertEqual(len(gh.requests), before)
        self.assertFalse([a for a in spawned if "push" in a])


if __name__ == "__main__":
    unittest.main()
