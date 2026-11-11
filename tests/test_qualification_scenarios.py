"""Hosted scenarios 1-4 are repeatable per run through the factory integration boundary (#98)."""
from __future__ import annotations

import ast, base64, contextlib, json, os, re, subprocess, tempfile, threading, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, unquote, urlparse

from factory import qualification
from factory.ci_selection import build_required_ci_checks
from factory.paths import RuntimePaths
from factory.qualification import CALC_CANDIDATE_SRC, CANDIDATE_BRANCH_PREFIX, SEED_ASSETS_DIR
from support import git
from test_deliver_checks import _DisposableGitHubServer
from test_qualification_prereqs import _GOOD_REVIEWERS, _OK, REPO, _dispatching_agy, _seeded_origin

TOKENS = {"int-tok": "qual-int", "comp-tok": "qual-comp", "read-tok": "qual-read"}  # test-only accounts; the runner must take them from config
EXPECTED_LOGINS = {"integrator": "qual-int", "competitor": "qual-comp", "reader": "qual-read"}
ADMINS = ("qual-int", "qual-comp")  # the competitor is admin: it lands its advance through integrate_approved_child
LIVE_LOGINS = ("huyhuyhuy8s", "cone-orgs", "huyle-turbo")  # the live accounts #98 found hardcoded
API, SLUG = "/api/v3", f"/api/v3/repos/{REPO}"


class _ProviderGitHub(_DisposableGitHubServer):
    """The delivery fake plus what a hosted run uses: identities, git data, PR list/close, reviews, strict merges that
    need an approval by a non-author, `update-branch`, and ref activity derived from the origin's real ref moves."""

    def __init__(self, bare: Path) -> None:
        super().__init__(bare_repo=bare, owner=REPO.split("/")[0], repo=REPO.split("/")[1])
        self.lock, self.reviews, self.activity, self.refs, self.merges = threading.RLock(), {}, [], {}, []
        self.inject_force_push, self.root = False, self.sha("feature/demo", True)
        self.fail_first_poll, self.fail_path = False, None  # one failing read of the PR polled after update-branch
        self.fail_activity: int | None = None  # one failing ref-activity read: its status, or 0 for no response at all
        self.observe()

    def g(self, *args: str, who: str | None = None, inp: str | None = None, env: dict | None = None) -> str:
        ident = {f"GIT_{r}_{k}": v for r in ("AUTHOR", "COMMITTER") for k, v in (("NAME", who or "t"), ("EMAIL", "t@example.test"))}
        return subprocess.run(["git", *args], cwd=self.bare_repo, input=inp, capture_output=True, text=True, check=True,
                              env={**os.environ, **ident, **(env or {})}).stdout.strip()

    def sha(self, ref: str, branch: bool = False) -> str | None:
        for r in (f"refs/heads/{ref}",) + (() if branch else (ref,)):
            with contextlib.suppress(subprocess.CalledProcessError):
                return self.g("rev-parse", "--verify", "-q", f"{r}^{{commit}}")
        return None

    def anc(self, old: str, new: str) -> bool:
        return subprocess.run(["git", "merge-base", "--is-ancestor", old, new], cwd=self.bare_repo).returncode == 0

    def observe(self) -> None:  # the provider's ref history: every head transition, typed by ancestry
        with self.lock:
            now = dict(ln.split() for ln in self.g("for-each-ref", "refs/heads", "--format=%(refname:short) %(objectname)").splitlines())
            for ref in sorted(set(now) | set(self.refs)):
                old, new = self.refs.get(ref), now.get(ref)
                if old != new:
                    kind = "branch_creation" if old is None else "branch_deletion" if new is None else "push" if self.anc(old, new) else "force_push"
                    self.activity.insert(0, {"ref": f"refs/heads/{ref}", "activity_type": kind, "before": old or "0" * 40, "after": new or "0" * 40})
            self.refs = now

    def route(self, method: str, p: str, q: dict, b: dict, who: str | None) -> tuple[int, object]:
        nf, protected = (404, {"message": "Not Found"}), (lambda br: br == "main" or br.startswith("feature/"))
        m = re.fullmatch(rf"{SLUG}/(pulls|git/refs/heads|git/ref/heads|contents|commits)/(.+?)(?:/(reviews|merge|update-branch)(?:/(\d+))?)?", p)
        kind, key, sub = (m[1], m[2], m[3]) if m else (None, None, None)
        pr = self.pulls.get(int(key)) if kind == "pulls" and key.isdigit() else None
        if (method, p) == ("GET", f"{API}/user"):
            return (200, {"login": who}) if who else (401, {"message": "Bad credentials"})
        if (method, p) == ("GET", SLUG):
            return 200, {"full_name": REPO, "permissions": {"admin": who in ADMINS, "push": who in ADMINS, "pull": True}}
        if p == f"{SLUG}/actions/permissions":
            return (200, {"enabled": True}) if who in ADMINS else (403, {"message": "Must have admin rights to Repository."})
        if p == f"{SLUG}/activity":
            ref = q.get("ref", "")
            ref = ref if not ref or ref.startswith("refs/") else f"refs/heads/{ref}"
            acts = [a for a in self.activity if ref in ("", a["ref"])]
            if self.inject_force_push:  # a force push the run did not make, visible only in the provider's history
                acts[:0] = [{"ref": r, "activity_type": "force_push", "before": self.root, "after": self.refs[r[11:]]}
                            for r in ([ref] if ref else ["refs/heads/" + br for br in self.refs])
                            if r.startswith("refs/heads/" + CANDIDATE_BRANCH_PREFIX) and r[11:] in self.refs]
            return 200, [a for a in acts if q.get("activity_type") in (None, a["activity_type"])]
        if (method, p) == ("GET", f"{SLUG}/pulls"):
            head, st = q.get("head", "").split(":")[-1], q.get("state", "open")
            return 200, [x for x in self.pulls.values() if head in ("", x["head"]["ref"]) and st in ("all", x["state"])]
        if (method, p) == ("POST", f"{SLUG}/pulls"):
            head, base = b["head"].split(":")[-1], b["base"]
            hs, bs = self.sha(head, True), self.sha(base, True)
            if not (hs and bs) or any(x["state"] == "open" and x["head"]["ref"] == head for x in self.pulls.values()):
                return 422, {"message": "Validation Failed"}
            n = len(self.pulls) + 1
            self.pulls[n] = {"number": n, "state": "open", "merged": False, "title": b.get("title", ""), "body": b.get("body", ""),
                             "html_url": f"https://github.com/{REPO}/pull/{n}", "user": {"login": who}, "created_head": hs,
                             "head": {"ref": head, "sha": hs, "repo": {"full_name": REPO}}, "base": {"ref": base, "sha": bs, "repo": {"full_name": REPO}}}
            return 201, self.pulls[n]
        if method == "POST" and p == f"{SLUG}/git/blobs":
            return 201, {"sha": self.g("hash-object", "-w", "--stdin", inp=b["content"])}
        if method == "POST" and p == f"{SLUG}/git/trees":
            with tempfile.TemporaryDirectory() as d:
                env = {"GIT_INDEX_FILE": str(Path(d) / "index")}
                self.g("read-tree", b.get("base_tree") or "--empty", env=env)
                for e in b["tree"]:
                    self.g("update-index", "--add", "--cacheinfo", f"{e['mode']},{e['sha']},{e['path']}", env=env)
                return 201, {"sha": self.g("write-tree", env=env)}
        if method == "POST" and p == f"{SLUG}/git/commits":
            return 201, {"sha": self.g("commit-tree", b["tree"], *[a for s in b.get("parents", []) for a in ("-p", s)], "-m", b["message"], who=who)}
        if method == "POST" and p == f"{SLUG}/git/refs":
            name = b["ref"].removeprefix("refs/heads/")
            if self.sha(name, True) or protected(name):
                return 422, {"message": "Reference already exists"}
            self.g("update-ref", b["ref"], b["sha"])
            return 201, {"ref": b["ref"], "object": {"sha": b["sha"]}}
        if kind in ("git/ref/heads", "git/refs/heads"):
            old = self.sha(key, True)
            if method == "GET":
                return (200, {"object": {"sha": old, "type": "commit"}}) if old else nf
            if method == "DELETE":
                if protected(key) or not old:
                    return 422, {"message": "Reference cannot be deleted"}
                self.g("update-ref", "-d", f"refs/heads/{key}", old)
                return 204, {}
            if protected(key) or not old or not (b.get("force") or self.anc(old, b["sha"])):
                return 422, {"message": "Protected branch update failed" if protected(key) else "Update is not a fast forward"}
            self.g("update-ref", f"refs/heads/{key}", b["sha"], old)
            return 200, {"ref": f"refs/heads/{key}", "object": {"sha": b["sha"]}}
        if kind == "contents":
            raw = subprocess.run(["git", "cat-file", "blob", f"{self.sha(q.get('ref', 'HEAD'))}:{key}"], cwd=self.bare_repo, capture_output=True)
            return (200, {"content": base64.b64encode(raw.stdout).decode()}) if raw.returncode == 0 else nf
        if kind == "commits":
            if not (sha := self.sha(key)):
                return nf
            return 200, {"sha": sha, "commit": {"tree": {"sha": self.g("rev-parse", f"{sha}^{{tree}}")}},
                         "parents": [{"sha": s} for s in self.g("rev-list", "--parents", "-n1", sha).split()[1:]]}
        if pr and sub == "reviews":
            if method == "GET":
                rv = self.reviews.get(int(m[4] or 0))
                return (200, rv) if rv and rv["pull_number"] == pr["number"] else nf
            if pr["user"]["login"] == who and b.get("event") == "APPROVE":
                return 422, {"message": "Can not approve your own pull request"}
            rid = 1000 + len(self.reviews)
            self.reviews[rid] = {"id": rid, "pull_number": pr["number"], "state": {"APPROVE": "APPROVED"}.get(b.get("event"), "COMMENTED"),
                                 "commit_id": b.get("commit_id") or pr["head"]["sha"], "user": {"login": who}}
            return 200, self.reviews[rid]
        if pr and method == "PATCH" and not sub:
            pr.update({k: b[k] for k in ("title", "body", "state") if k in b})
            return 200, pr
        if not (pr and pr["state"] == "open" and method == "PUT"):
            return (405, {"message": "Pull Request is not mergeable"}) if method == "PUT" else nf
        head, base_sha = pr["head"]["sha"], self.sha(pr["base"]["ref"], True)
        if sub == "update-branch":  # merge the current base into the head branch; never a force push
            self.fail_path = p.removesuffix("/update-branch") if self.fail_first_poll else None
            if b.get("expected_head_sha") not in (None, head):
                return 422, {"message": "expected_head_sha does not match"}
            if not self.anc(base_sha, head):
                tree = self.g("merge-tree", "--write-tree", head, base_sha).split()[0]
                new = self.g("commit-tree", tree, "-p", head, "-p", base_sha, "-m", "Merge base into head", who=who)
                self.g("update-ref", f"refs/heads/{pr['head']['ref']}", new, head)
            return 202, {"message": "Updating pull request branch."}
        if b.get("sha") not in (None, head):
            return 409, {"message": "Head branch was modified. Review and try the merge again."}
        if not self.anc(base_sha, head):  # strict protection: the head must contain the current base
            return 405, {"message": "Base branch was modified. Review and try the merge again."}
        if not any(rv["pull_number"] == pr["number"] and rv["state"] == "APPROVED" and rv["commit_id"] == head
                   and rv["user"]["login"] != pr["user"]["login"] for rv in self.reviews.values()):
            return 405, {"message": "At least 1 approving review is required by reviewers with write access."}
        landed = self.g("commit-tree", f"{head}^{{tree}}", "-p", base_sha, "-p", head, "-m", f"Merge pull request #{pr['number']}", who=who)
        self.g("update-ref", f"refs/heads/{pr['base']['ref']}", landed, base_sha)
        pr.update(state="closed", merged=True, merge_commit_sha=landed)
        self.merges.append((pr["number"], who))
        return 200, {"sha": landed, "merged": True, "message": "Pull Request successfully merged"}

    def _make_handler(self) -> type:
        outer = self

        class Handler(super()._make_handler()):
            def _record_or_redirect(self, body: dict | None = None) -> str | None:
                outer.observe()
                for pr in outer.pulls.values():  # open PRs follow their refs, as on the provider
                    if pr["state"] == "open":
                        pr["head"]["sha"] = outer.sha(pr["head"]["ref"], True) or pr["head"]["sha"]
                        pr["base"]["sha"] = outer.sha(pr["base"]["ref"], True) or pr["base"]["sha"]
                return super()._record_or_redirect(body)

            def _serve(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                u = urlparse(self.path)
                p = unquote(u.path)
                if self.command == "GET" and p == outer.fail_path:
                    outer.fail_path = None
                    return self._send_json(503, {"message": "Service Unavailable"})
                if self.command == "GET" and p == f"{SLUG}/activity" and (code := outer.fail_activity) is not None:
                    outer.fail_activity, self.close_connection = None, True
                    return self._send_json(code, {"message": "Service Unavailable"}) if code else None
                if self.command == "GET" and (p.endswith(("/check-runs", "/protection")) or "/actions/" in p and "permissions" not in p
                                              or re.fullmatch(rf"{SLUG}/pulls/\d+", p)):
                    return super().do_GET()  # CI runs, artifacts, protection and PR reads stay the delivery fake's
                self._record_or_redirect(body)
                who = TOKENS.get((self.headers.get("Authorization") or "").removeprefix("Bearer "))
                try:
                    code, out = outer.route(self.command, p, {k: v[0] for k, v in parse_qs(u.query).items()}, body, who)
                except subprocess.CalledProcessError as exc:
                    code, out = 409, {"message": f"git: {exc.stderr}"}
                outer.observe()
                self._send_json(code, out)

            do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _serve

        return Handler


def _literal_live_state(source: str) -> list[str]:
    """Literal commit SHAs, account logins and PR numbers in the hosted runner's source."""
    found = [f"sha {s}" for s in re.findall(r"(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])", source)]
    found += [f"login {login}" for login in LIVE_LOGINS if login in source]
    prish = lambda name: "pr_num" in name.lower() or name.lower() in ("pr_number", "pr_id")
    pos_int = lambda v: isinstance(v, ast.Constant) and type(v.value) is int and v.value > 0
    for node in ast.walk(ast.parse(source)):
        pairs: list[tuple[str, ast.AST]] = []
        if isinstance(node, ast.keyword) and node.arg:
            pairs.append((node.arg, node.value))
            if node.arg in ("expected_login", "expected_reviewer") and isinstance(node.value, ast.Constant):
                found.append(f"{node.arg}={node.value.value!r} at line {node.value.lineno}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for tgt in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(tgt, ast.Tuple) and isinstance(node.value, ast.Tuple):
                    pairs += [(t.id, v) for t, v in zip(tgt.elts, node.value.elts) if isinstance(t, ast.Name)]
                elif isinstance(tgt, ast.Name) and node.value is not None:
                    pairs.append((tgt.id, node.value))
        elif isinstance(node, ast.arguments):
            args = node.posonlyargs + node.args
            pairs += list(zip([a.arg for a in args[len(args) - len(node.defaults):]], node.defaults))
            pairs += [(a.arg, d) for a, d in zip(node.kwonlyargs, node.kw_defaults) if d is not None]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"/pulls/\d", node.value) or re.fullmatch(r"[0-9a-f]{7,39}", node.value):
                found.append(f"literal {node.value!r} at line {node.lineno}")
        found += [f"{n}={v.value} at line {v.lineno}" for n, v in pairs if prish(n) and pos_int(v)]
    return found


class HostedScenarioRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="turbo-qual-98-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        env = mock.patch.dict(os.environ, {"TURBO_LIVE_QUALIFICATION": "0", "GIT_ALLOW_PROTOCOL": "file"})
        env.start()
        self.addCleanup(env.stop)

    @contextlib.contextmanager
    def _provider(self):
        """A seeded disposable origin (with a stale fixed-name candidate branch left by older runs) and its provider."""
        origin, bare, _, _ = _seeded_origin(self.tmp, CALC_CANDIDATE_SRC)
        agy = _dispatching_agy(self.tmp, *_GOOD_REVIEWERS)
        seed = {k: json.loads((SEED_ASSETS_DIR / "factory" / f"{k}.json").read_text(encoding="utf-8")) for k in ("policy", "child-contract")}
        conf = qualification._policy_conf(RuntimePaths(repo=SEED_ASSETS_DIR, home=SEED_ASSETS_DIR), seed["policy"])
        with _ProviderGitHub(bare) as gh:  # every check the gate requires, passing in the fake CI
            gh.ci_spec = {"checks": [(r["name"], r["kind"], _OK) for r in build_required_ci_checks(seed["child-contract"], conf)]}
            yield gh, origin, agy

    def _run(self, gh: _ProviderGitHub, origin: Path, agy: str, reader: str | None = "read-tok") -> SimpleNamespace:
        """One hosted run, as an operator starts it, against the fake provider; integration attempts are recorded."""
        calls: list[dict] = []
        real = qualification.integrate_approved_child

        def integrate(**kw: object) -> object:
            hook, seen = kw.get("on_before_merge"), {"hook_requests": None}
            if callable(hook):
                def hooked() -> None:
                    start = len(gh.requests)
                    hook()
                    seen["hook_requests"] = gh.requests[start:]
                kw["on_before_merge"] = hooked
            res = real(**kw)
            calls.append({"kw": kw, "res": res, **seen, "pr_after": json.loads(json.dumps(gh.pulls.get(kw["pr_number"], {})))})
            return res

        before, n_req, q = set(gh.pulls), len(gh.requests), "factory.qualification."
        with contextlib.ExitStack() as st:
            for name, val in (("HOSTED_API_ORIGIN", gh.base_url), ("HOSTED_CLONE_URL_TEMPLATE", f"{origin}/{{repo_slug}}.git")):
                st.enter_context(mock.patch(q + name, val))
            for fn in ("check_branch_protection_and_topology", "check_seed_and_workflow_capabilities"):
                st.enter_context(mock.patch(q + fn, return_value=(True, {}, [])))
            st.enter_context(mock.patch(q + "resolve_agy_bin", return_value=agy))
            st.enter_context(mock.patch(q + "integrate_approved_child", side_effect=integrate))
            res = qualification.run_hosted_qualification(
                REPO, self.tmp / "ev", live_enabled=True, integrator_token="int-tok", competitor_token="comp-tok",
                base_url=gh.base_url, expected_logins=EXPECTED_LOGINS, reader_token=reader)
        sc = res.get("scenarios") or {}
        probes = [q["auth"] for q in gh.requests[n_req:] if q["path"].endswith("/actions/permissions")]
        return SimpleNamespace(res=res, calls=calls, created=sorted(set(gh.pulls) - before), probes=probes,
                               s2=sc.get("prereq_missing_and_denied") or {},
                               s1=sc.get("confirmed_landing") or {}, s3=sc.get("competing_base_rejection") or {},
                               s4=sc.get("renewed_verification_after_base_change") or {})

    def _attempt(self, r: SimpleNamespace, pr: object, **match: object) -> dict:
        hits = [c for c in r.calls if c["kw"]["pr_number"] == pr and all(c["kw"].get(k) == v for k, v in match.items())]
        self.assertTrue(hits, f"no integrate_approved_child attempt for PR {pr!r} {match}")
        return hits[-1]

    def _assert_landed(self, gh: _ProviderGitHub, r: SimpleNamespace, sc: dict, base: str, cand: str) -> None:
        """Landed through the factory boundary in this run: a real merge of the PR the run created, on `base`."""
        pr = sc.get("pr_number")
        self.assertIn(pr, r.created, f"landed PR {pr} was not created in this run {r.created}")
        att = self._attempt(r, pr, candidate_sha=cand)
        self.assertEqual((att["res"].status, att["res"].mutation_outcome, att["res"].reconciled), ("confirmed", "succeeded", False))
        self.assertEqual((att["kw"]["base_sha"], gh.pulls[pr]["merge_commit_sha"]), (base, sc["landed_sha"]))
        self.assertIn((pr, TOKENS["int-tok"]), gh.merges)
        landed = sc["landed_sha"]
        self.assertEqual(git(gh.bare_repo, "rev-list", "--parents", "-n1", landed).split()[1:], [base, cand])
        self.assertEqual(git(gh.bare_repo, "rev-parse", f"{landed}^{{tree}}"), git(gh.bare_repo, "rev-parse", f"{att['res'].tested_sha}^{{tree}}"))

    def test_hosted_runner_has_no_literal_live_state(self) -> None:
        """AC1: factory/qualification.py (whole module, hosted runner and its helpers) holds no literal 40-hex or
        short-hex commit SHA, no live account login, no constant expected_login/expected_reviewer, and no positive
        integer bound to a PR-number name or written into a `/pulls/<n>` path."""
        with self.subTest("the scan recognises the shapes #98 found"):
            probe = 'pr_num = 5\nx, cand_pr_num = 1, 9\nu = f"/pulls/11"\nf(expected_login="x", pr_number=3)\ns = "' + "ab12" * 10 + '"'
            self.assertEqual(len(_literal_live_state(probe)), 6, _literal_live_state(probe))
        self.assertEqual(_literal_live_state(Path(qualification.__file__).read_text(encoding="utf-8")), [])
        with self.subTest("the CLI passes the reader token and expected reader login through"):
            env = {"TURBO_QUAL_INTEGRATOR_TOKEN": "int-tok", "TURBO_QUAL_COMPETITOR_TOKEN": "comp-tok", "TURBO_QUAL_READER_TOKEN": "read-tok",
                   **{f"TURBO_QUAL_EXPECTED_{k.upper()}": v for k, v in EXPECTED_LOGINS.items()}}
            with mock.patch.dict(os.environ, env), mock.patch("builtins.print"), \
                    mock.patch("factory.qualification.run_hosted_qualification", return_value={"qualified": False}) as run:
                qualification.main(["--mode", "hosted", "--evidence-dir", str(self.tmp / "cli")])
            self.assertEqual((run.call_args.kwargs.get("reader_token"), run.call_args.kwargs.get("expected_logins")), ("read-tok", EXPECTED_LOGINS))

    def test_each_run_lands_rejects_and_renews_its_own_prs(self) -> None:
        """AC2-AC4 and repeatability: two runs against one origin each create, verify and land their own uniquely named
        candidates through integrate_approved_child, reject a same-run competitor advance at the pre-merge boundary,
        renew against the advanced base without force push, close what they leave open, and never touch `main`."""
        with self._provider() as (gh, origin, agy):
            main_before = gh.sha("main", True)
            runs = [self._run(gh, origin, agy) for _ in range(2)]
            main_after = gh.sha("main", True)
        for i, r in enumerate(runs, 1):
            s1, s3, s4 = r.s1, r.s3, r.s4
            with self.subTest(run=i, check="identities come from configuration"):
                ids = r.res["preflight"]["identities"]
                self.assertEqual({k: (ids.get(k) or {}).get("login") for k in EXPECTED_LOGINS}, EXPECTED_LOGINS)
                self.assertEqual([(ids.get(k) or {}).get(f) for k in ("competitor", "reader") for f in ("expected_role", "observed_role")],
                                 ["admin", "admin", "read", "read"], "competitor is admin, reader is read-only")
                self.assertEqual(r.res["preparation"]["builder"]["actor"], "qual-int", "the integrator token builds the candidate")
            with self.subTest(run=i, check="scenario 2 permission denial is the reader's real 403"):
                self.assertEqual(r.probes, ["Bearer read-tok"], "the permission-denial probe must use only the reader token")
                self.assertEqual((r.s2["permission_denial"]["observed"], r.s2["permission_denial"]["status"]), (True, "HTTP 403"))
            with self.subTest(run=i, check="scenario 2 own candidate passes the factory gate and is denied by provider protection"):
                self.assertEqual(r.s2.get("outcome"), "verified", r.s2)
                self.assertEqual((r.s2["missing_prereq_rejected"], r.s2["stale_prereq_rejected"]), (True, True))
                pd = r.s2["protection_denial"]
                self.assertIn(pd["pr_number"], r.created)
                self.assertEqual((pd["status"], pd["denial_source"], pd["pr_unmerged"]), ("denied-protection", "provider", True))
                self.assertEqual((self._attempt(r, pd["pr_number"])["res"].status, gh.pulls[pd["pr_number"]]["merged"]), ("denied-protection", False))
                self.assertNotIn(pd["pr_number"], [n for n, _ in gh.merges])
            with self.subTest(run=i, check="AC2 scenario 1 lands the PR it created"):
                self.assertEqual(s1.get("outcome"), "verified", s1)
                pr = gh.pulls.get(s1.get("pr_number"), {})
                self.assertEqual((s1["candidate_sha"], s1["head_branch"]), (pr.get("created_head"), pr.get("head", {}).get("ref")))
                self._assert_landed(gh, r, s1, s1["base_sha"], s1["candidate_sha"])
            with self.subTest(run=i, check="AC3 factory rejects the same-run competitor advance"):
                self.assertEqual(s3.get("outcome"), "verified", s3)
                cand_pr, adv_pr = s3.get("candidate_pr_number"), s3.get("advance_pr_number")
                self.assertTrue({cand_pr, adv_pr} <= set(r.created), (cand_pr, adv_pr, r.created))
                att = self._attempt(r, cand_pr, base_sha=s3["initial_base_sha"])
                self.assertEqual((att["res"].status, s3["denial_source"]), ("rejected-competing-base", "provider"))
                self.assertEqual(s3["candidate_merge_status"], att["res"].status)
                self.assertIs(att["pr_after"].get("merged"), False, "the candidate PR merged in scenario 3")
                adv = gh.pulls[adv_pr]
                adv_att = self._attempt(r, adv_pr, token="comp-tok")  # the advance lands through the factory boundary, not a raw merge
                self.assertEqual((adv_att["res"].status, adv_att["kw"]["base_sha"]), ("confirmed", s3["initial_base_sha"]))
                self.assertEqual((adv["user"]["login"], adv["merged"], adv["merge_commit_sha"]), ("qual-comp", True, s3["advanced_base_sha"]))
                self.assertIn(("PUT", f"{SLUG}/pulls/{adv_pr}/merge", "Bearer comp-tok"),
                              [(q["method"], unquote(q["path"]), q["auth"]) for q in att["hook_requests"] or []],
                              "the competitor's advance was not merged inside on_before_merge")
            with self.subTest(run=i, check="AC4 stale evidence, renewal against B', no force push"):
                self.assertEqual(s4.get("outcome"), "verified", s4)
                self.assertIs(s4["old_evidence_rejected"], True)
                self.assertRegex(str(s4.get("old_evidence_status")), r"^stale-", "old evidence must be rejected as stale, not missing")
                b2, c2 = s3["advanced_base_sha"], s4["renewed_candidate_sha"]
                self.assertEqual(s4["renewed_base_sha"], b2)
                self.assertTrue(gh.anc(b2, c2), "renewed candidate does not contain the advanced base")
                self.assertIn(c2, gh.check_runs_by_sha, "CI did not run for the renewed candidate")
                self.assertTrue(any(rv["pull_number"] == s4["pr_number"] and rv["commit_id"] == c2 and rv["state"] == "APPROVED"
                                    and rv["user"]["login"] == "qual-comp" for rv in gh.reviews.values()), gh.reviews)
                self._assert_landed(gh, r, s4, b2, c2)
                head_ref = "refs/heads/" + gh.pulls[s4["pr_number"]]["head"]["ref"]
                self.assertNotIn("force_push", [a["activity_type"] for a in gh.activity if a["ref"] == head_ref])
                self.assertIs(s4["head_merged_without_force_push"], True)
            with self.subTest(run=i, check="cleanup and target"):
                for n in r.created:
                    self.assertEqual((gh.pulls[n]["state"], gh.pulls[n]["base"]["ref"]), ("closed", "feature/demo"), f"PR {n}")
                    self.assertTrue(gh.pulls[n]["head"]["ref"].startswith(CANDIDATE_BRANCH_PREFIX), gh.pulls[n]["head"]["ref"])
                self.assertEqual((s3.get("main_sha_before"), s3.get("main_sha_after")), (main_before, main_before))
        with self.subTest("runs are independent"):
            self.assertEqual(main_after, main_before)
            heads = [{gh.pulls[n]["head"]["ref"] for n in r.created} for r in runs]
            self.assertTrue(all(heads), heads)
            self.assertFalse(heads[0] & heads[1], f"run-unique branch names reused: {heads}")
            self.assertNotEqual(runs[0].s1.get("landed_sha"), runs[1].s1.get("landed_sha"))

    def test_force_push_in_provider_ref_history_fails_renewal(self) -> None:
        """AC4: head_merged_without_force_push is read from the provider's ref history: a force push recorded there for
        the renewed head fails scenario 4, and the run still closes every PR it left unmerged. The run also has no reader
        token: the permission-denial subcheck is unavailable (never probed with another token) and the run cannot qualify."""
        def s4_reads(r: SimpleNamespace) -> list[tuple]:  # the ledgered reads from scenario 4's update-branch to its ref-activity read
            texts = [f.read_text(encoding="utf-8") for f in sorted((self.tmp / "ev").rglob("operation-ledger.jsonl"))]
            self.assertFalse([t for t in TOKENS if any(t in x for x in texts)], "a token reached the ledger")
            put = ("PUT", f"{SLUG}/pulls/{r.s4.get('pr_number')}/update-branch", 202)
            rows = next((rs for x in texts if put in (rs := [(e["method"], urlparse(e["url"]).path, e["status_code"])
                                                             for e in map(json.loads, x.splitlines())])), [])
            self.assertIn(put, rows, "scenario 4's update-branch is not in any ledger")
            after = rows[rows.index(put) + 1:]
            return after[:next((i for i, row in enumerate(after) if row[1] == f"{SLUG}/activity"), len(after)) + 1]

        root = self.tmp
        for code in (503, 0):  # #128: a failed ref-activity read is ledgered with its status (0: no response) and decides nothing
            self.tmp = Path(tempfile.mkdtemp(dir=root))
            with self.subTest(activity=code), self._provider() as (gh, origin, agy):
                gh.fail_activity = code
                r = self._run(gh, origin, agy)
                self.assertEqual(s4_reads(r)[-1], ("GET", f"{SLUG}/activity", code))
                self.assertIsNone(r.s4.get("head_merged_without_force_push"), r.s4)
        self.tmp = Path(tempfile.mkdtemp(dir=root))
        with self._provider() as (gh, origin, agy):
            gh.inject_force_push = gh.fail_first_poll = True
            r = self._run(gh, origin, agy, reader=None)
        with self.subTest("#128: the ledger records scenario 4's polling and ref-activity reads, the failed one with its status"):
            pr = f"{SLUG}/pulls/{r.s4.get('pr_number')}"
            self.assertEqual(s4_reads(r), [("GET", pr, 503), ("GET", pr, 200), ("GET", f"{SLUG}/activity", 200)])
        pd = r.s2.get("permission_denial") or {}
        self.assertEqual((r.probes, pd.get("observed"), pd.get("status")), ([], None, "unavailable"), pd)
        self.assertNotEqual(r.s2.get("outcome"), "verified")
        self.assertIs(r.res["qualified"], False)
        self.assertTrue(any("reader" in b for b in r.res["blockers"]), r.res["blockers"])
        self.assertIs(r.s4.get("head_merged_without_force_push"), False, r.s4)
        self.assertEqual(r.s4.get("outcome"), "failed")
        self.assertTrue(r.created)
        for n in r.created:
            self.assertEqual(gh.pulls[n]["state"], "closed", f"PR {n} left open")

    def test_no_scenario_context_leaves_no_run_branch_or_open_pr(self) -> None:
        """#128 N2: preflight is clean but the hosted repository has no .factory/child-contract.json, so no scenario
        context opens and no scenario runs; the run leaves no branch of its own and no open PR behind."""
        with self._provider() as (gh, origin, agy):
            with tempfile.TemporaryDirectory() as d:
                env = {"GIT_INDEX_FILE": str(Path(d) / "index"), "GIT_WORK_TREE": d}
                gh.g("read-tree", "feature/demo", env=env)
                gh.g("update-index", "--force-remove", ".factory/child-contract.json", env=env)
                tree = gh.g("write-tree", env=env)
            gh.g("update-ref", "refs/heads/feature/demo", gh.g("commit-tree", tree, "-p", "feature/demo", "-m", "no contract"))
            r = self._run(gh, origin, agy)
            heads = gh.g("for-each-ref", "refs/heads", "--format=%(refname:short)").split()
        self.assertEqual((r.res["preflight"]["status"], r.res.get("scenarios")), ("verified", {}), r.res["preflight"]["blockers"])
        self.assertTrue(any(b.startswith("scenario-context-unavailable") for b in r.res["blockers"]), r.res["blockers"])
        self.assertEqual([h for h in heads if h.startswith(f"{CANDIDATE_BRANCH_PREFIX}{r.res['run_id']}")], [], "per-run branch left behind")
        self.assertEqual([n for n, pr in gh.pulls.items() if pr["state"] == "open"], [], "PR left open")

    def test_reader_with_wrong_login_or_write_access_blocks_preflight(self) -> None:
        """The reader behind scenario 2's 403 is pinned: a token of another login, or one with push or admin rights,
        is a preflight blocker, so the run makes no provider mutation, runs no scenario and never fires the probe."""
        root = self.tmp
        for case, patch, blocker in (("wrong login", mock.patch.dict(TOKENS, {"read-tok": "qual-other"}), "wrong-identity: reader"),
                                     ("write access", mock.patch(f"{__name__}.ADMINS", ADMINS + ("qual-read",)), "excess-permissions: reader")):
            self.tmp = Path(tempfile.mkdtemp(dir=root))
            with self.subTest(case), self._provider() as (gh, origin, agy), patch:
                refs, n_req = dict(gh.refs), len(gh.requests)
                r = self._run(gh, origin, agy)
                writes = [(q["method"], unquote(q["path"])) for q in gh.requests[n_req:] if q["method"] != "GET"]
                self.assertEqual((r.created, writes, gh.refs), ([], [], refs), "a blocked preflight mutated the provider")
                self.assertTrue(any(b.startswith(blocker) for b in r.res["preflight"]["blockers"]), r.res["preflight"]["blockers"])
                self.assertEqual((r.probes, r.calls, r.res.get("scenarios") or {}, r.res["qualified"]), ([], [], {}, False))


if __name__ == "__main__":
    unittest.main()
