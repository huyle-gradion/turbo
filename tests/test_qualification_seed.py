"""The seed CI workflow emits the gate's required checks; the seed install has a dry-run plan (#109)."""
from __future__ import annotations

import contextlib, fnmatch, io, json, os, re, shutil, subprocess, sys, tempfile, textwrap, threading, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

from factory import ci_gate, qualification
from factory.ci_selection import build_required_ci_checks
from factory.errors import UsageError
from factory.qualification import CALC_CANDIDATE_SRC, SEED_ASSETS_DIR
from support import commit, git, make_repo
from test_deliver_checks import _DisposableGitHubServer
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


class _SeedGitHub(_DisposableGitHubServer):
    """The deliver-checks fake plus the git-data and branch-protection routes that seed apply writes through."""

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        base, outer = super()._make_handler(), self

        class H(base):  # type: ignore[valid-type, misc]
            def _seed_route(self) -> bool:
                path, pre = urlparse(self.path).path, f"/api/v3/repos/{outer.owner}/{outer.repo}"
                rel = path[len(pre):] if path.startswith(pre) else ""
                if not (rel.startswith(("/git/", "/commits/")) or rel.endswith("/protection/required_status_checks")) \
                        or rel.endswith("/check-runs"):
                    return False
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                self._record_or_redirect(body)
                if rel.startswith("/git/ref/"):
                    self._send_json(404, {"message": "Not Found"})  # the seed branch does not exist yet
                elif rel.startswith("/commits/"):
                    self._send_json(200, {"sha": "b" * 40, "commit": {"tree": {"sha": "c" * 40}}})
                elif rel.startswith("/git/"):
                    self._send_json(201, {"sha": "d" * 40, "ref": body.get("ref")})
                else:
                    self._send_json(200, {"contexts": body.get("contexts")})
                return True

            def do_GET(self) -> None:
                self._seed_route() or super().do_GET()

            def do_POST(self) -> None:
                self._seed_route() or super().do_POST()

            def do_PATCH(self) -> None:
                self._seed_route() or super().do_PATCH()
        return H


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

    def test_seed_evidence_scripts_record_merge_commit_provenance(self) -> None:
        """F1: each job's evidence heredoc, run on a PR merge commit, keys the manifest by the check name and records
        base = policy = HEAD^1, candidate = HEAD^2, tested = HEAD, as deliver_checks and ci_gate require."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        repo = make_repo(tmp)
        base = commit(repo, ".factory/policy.json", (SEED_ASSETS_DIR / "factory" / "policy.json").read_text(), "seed")
        git(repo, "checkout", "-q", "-b", "cand")
        cand = commit(repo, "src/calc.py", CALC_CANDIDATE_SRC, "candidate")
        git(repo, "checkout", "-q", base)
        git(repo, "merge", "--no-ff", "-q", "-m", "merge", cand)
        merge = git(repo, "rev-parse", "HEAD")
        jobs = {}
        for blk in _blocks(_blocks(WORKFLOW.read_text(encoding="utf-8"), 0)["jobs"], 2).values():
            jobs[re.search(r"(?m)^ {4}name:\s*(.+?)\s*$", blk).group(1).strip("'\"")] = blk
        self.assertCountEqual(jobs, self.required)
        for check, blk in jobs.items():
            with self.subTest(check=check):
                scripts = re.findall(r"(?ms)python3 - <<'PY'\n(.*?)^\s*PY$", blk)
                self.assertEqual(len(scripts), 1, "one evidence heredoc per job")
                env_blk = blk.split("Write CI evidence", 1)[1]
                (ev := repo / "ci-ev").mkdir(exist_ok=True)
                (ev / "log.txt").write_text("ok\n", encoding="utf-8")
                env = {**os.environ, "CHECK_NAME": _scalars(env_blk, "CHECK_NAME")[0], "COMMAND": "c", "EXIT_CODE": "0",
                       "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1"}
                subprocess.run([sys.executable, "-"], input=textwrap.dedent(scripts[0]), text=True, cwd=repo, env=env, check=True)
                manifest = json.loads((ev / "turbo-ci-evidence.json").read_text(encoding="utf-8"))
                self.assertEqual((manifest["workflow_run_id"], manifest["run_attempt"]), (4242, 1))
                self.assertEqual(list(manifest["checks"]), [check], "manifest key must equal check_name")
                rec = manifest["checks"][check]
                self.assertEqual(rec["check_name"], check)
                self.assertEqual({k: rec[k] for k in ("base_sha", "policy_sha", "candidate_sha", "tested_sha")},
                                 {"base_sha": base, "policy_sha": base, "candidate_sha": cand, "tested_sha": merge})
                self.assertIn(rec["workflow_path"], ci_gate.TRUSTED_WORKFLOW_PATHS)
                self.assertEqual((rec["exit_code"], rec["conclusion"]), (0, "success"))

    def test_seed_apply_targets_only_the_feature_branch_and_the_cli_gate_holds(self) -> None:
        """F2: apply opens the seed PR into feature/demo (never main), writes refs only under feat/qual-*, and sets
        that branch's contexts; CLI --apply without live enablement exits 2 before any request."""
        owner, name = REPO.split("/")
        with _SeedGitHub(owner=owner, repo=name) as gh:
            res = qualification.install_seed(gh.base_url, REPO, "feature/demo", "tok", dry_run=False, allow_test_origin=True)
            self.assertEqual(res["status"], "applied", res)
            writes = [r for r in gh.requests if r["method"] != "GET"]
            pulls = [r["body"] for r in writes if r["path"].endswith("/pulls")]
            self.assertEqual([(p["base"], p["head"]) for p in pulls], [("feature/demo", "feat/qual-seed-install")])
            refs = [r for r in writes if "/git/refs" in r["path"]]
            self.assertTrue(refs)
            for r in refs:
                self.assertTrue((r["body"].get("ref") or r["path"].split("/git/refs/", 1)[-1]).startswith(
                    ("refs/heads/feat/qual-", "heads/feat%2Fqual-")), r)
            prot = [r for r in writes if r["path"].endswith("/protection/required_status_checks")]
            self.assertEqual([r["path"].split("/branches/")[1].split("/")[0] for r in prot], ["feature%2Fdemo"])
            self.assertCountEqual(prot[0]["body"]["contexts"], self.required)
            self.assertFalse([r for r in gh.requests if "main" in r["path"] or (r["body"] or {}).get("base") == "main"])
        clean = {k: v for k, v in os.environ.items() if not k.startswith("TURBO_")}
        for extra in ({}, {"TURBO_QUAL_INTEGRATOR_TOKEN": "tok", "TURBO_QUAL_COMPETITOR_TOKEN": "tok2"}):
            with self.subTest(env=sorted(extra)), _SeedGitHub(owner=owner, repo=name) as gh, \
                    mock.patch.dict(os.environ, {**clean, **extra}, clear=True), \
                    mock.patch.object(qualification, "HOSTED_API_ORIGIN", gh.base_url), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                rc = qualification.main(["--mode", "install-seed", "--apply", "--base-url", gh.base_url, "--repo-slug", REPO])
                self.assertEqual((rc, gh.requests), (2, []))


if __name__ == "__main__":
    unittest.main()
