"""Hosted qualification records only real prerequisite evidence (#97)."""
from __future__ import annotations

import ast, contextlib, copy, inspect, json, os, re, shutil, stat, sys, tempfile, time, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from factory import automated_qa, ci_gate, independent_review, qualification, security_review
from factory.ci_selection import build_required_ci_checks
from factory.independent_review import approval
from factory.qualification import CALC_CANDIDATE_SRC, CALC_CANDIDATE_TEST, SEED_ASSETS_DIR, prepare_qualification_candidate
from support import ROOT, commit, git, make_repo
from test_deliver_checks import _DisposableGitHubServer
from test_qualification import _HostedQualificationFakeServer
from test_deliver import _make_fake_agy
from tests.independent_review.test_independent_review import _make_staged_reviewer_script
from tests.security_review.test_reviewer import REVIEWER_SCRIPT as SEC_REVIEWER_SCRIPT

REPO = "turbo-factory/turbo-qual-67"
HEAD_BRANCH = "feat/qual-candidate-101"
BASE_SHA = "b1234567890abcdef1234567890abcdef1234567"
PASSING_SRC = (
    "def add(a, b):\n    return a + b\n\n"
    "def multiply(a, b):\n    return a * b\n\n"
    "def subtract(a, b):\n    return a - b\n"
)
FAILING_SRC = PASSING_SRC.replace("return a + b", "return a - b")


def _candidate_checkout(tmp: Path, src: str) -> tuple[Path, str, str]:
    """Synthetic checkout: a seed-copy commit, then a candidate commit with `src`. Returns (repo, seed_sha, cand_sha)."""
    repo = make_repo(tmp)
    commit(repo, "qa/qa-cases.json", (SEED_ASSETS_DIR / "qa" / "qa-cases.json").read_text(encoding="utf-8"), "qa cases")
    seed_sha = commit(repo, "src/calc.py", (SEED_ASSETS_DIR / "src" / "calc.py").read_text(encoding="utf-8"), "seed copy")
    cand_sha = commit(repo, "src/calc.py", src, "candidate")
    return repo, seed_sha, cand_sha


def _hosted_origin(case: Path, *, with_contract: bool) -> tuple[Path, str, str]:
    """A local bare repo standing in for github.com/REPO; returns (origin root for the URL template, cand, base)."""
    repo = make_repo(case)
    seed = SEED_ASSETS_DIR
    commit(repo, ".factory/policy.json", (seed / "factory" / "policy.json").read_text(encoding="utf-8"), "policy")
    if with_contract:
        commit(repo, ".factory/child-contract.json", (seed / "factory" / "child-contract.json").read_text(encoding="utf-8"), "contract")
    commit(repo, "qa/qa-cases.json", (seed / "qa" / "qa-cases.json").read_text(encoding="utf-8"), "qa cases")
    base = commit(repo, "src/calc.py", (seed / "src" / "calc.py").read_text(encoding="utf-8"), "seed copy")
    git(repo, "branch", "feature/demo", base)
    git(repo, "checkout", "-q", "-b", HEAD_BRANCH)
    cand = commit(repo, "src/calc.py", PASSING_SRC, "candidate")
    origin = case / "origin"
    git(case, "clone", "-q", "--bare", str(repo), str(origin / f"{REPO}.git"))
    return origin, cand, base


def _seeded_origin(case: Path, src: str) -> tuple[Path, Path, str, str]:
    """A local bare origin with the whole reproducible seed on feature/demo (factory/ -> .factory/, as documented)
    and a candidate commit on HEAD_BRANCH; returns (origin root for the URL template, bare, cand, base)."""
    repo = make_repo(case)
    for f in sorted(p for p in SEED_ASSETS_DIR.rglob("*") if p.is_file()):
        rel = f.relative_to(SEED_ASSETS_DIR).as_posix()
        dst = repo / (".factory/" + rel[len("factory/"):] if rel.startswith("factory/") else rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(f.read_bytes())
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "seed")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "branch", "feature/demo", base)
    git(repo, "checkout", "-q", "-b", HEAD_BRANCH)
    commit(repo, "tests/test_calc.py", CALC_CANDIDATE_TEST, "candidate tests")
    cand = commit(repo, "src/calc.py", src, "candidate")
    bare = case / "origin" / f"{REPO}.git"
    git(case, "clone", "-q", "--bare", str(repo), str(bare))
    return case / "origin", bare, cand, base


_OK = [sys.executable, "-c", "print('ok')"]
_REVIEWER_BLOCKERS = ("unsupported-reviewer-capability", "reviewer-not-run")


def _fake_reviewer(tmp: Path) -> str:
    """An executable that exists but is not a reviewer: it runs nothing and produces no review record."""
    exe = tmp / "bin" / "agy"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755)
    return str(exe)


def _dispatching_agy(case: Path, security_src: str, independent_src: str) -> str:
    """One fake agy for both reviewers (resolve_agy_bin returns one binary): a prompt naming the security-reviewer
    role runs `security_src`, any other prompt runs `independent_src` (the staged two-phase independent reviewer)."""
    body = ("_p = sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''\n"
            f"exec({security_src!r} if 'Role: security-reviewer' in _p else {independent_src!r})\n")
    return str(_make_fake_agy(case, "agy", body))


_SEC_NO_SESSION = SEC_REVIEWER_SCRIPT.replace("'conversation_id': 'sec-reviewer-1', ", "")
_GOOD_REVIEWERS = (SEC_REVIEWER_SCRIPT, _make_staged_reviewer_script())


class QualificationRealPrerequisiteTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp(prefix="turbo-qual-97-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = Path(tmp)
        # GIT_ALLOW_PROTOCOL=file: a broken clone-origin seam fails offline instead of reaching github.com (#104).
        env = mock.patch.dict(os.environ, {"TURBO_LIVE_QUALIFICATION": "0", "GIT_ALLOW_PROTOCOL": "file"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AGY_BIN", None)

    def _prepare(self, *, resolved: str | None | type = ..., ci_conclusion: str = "success",
                 src: str = PASSING_SRC, head_at_seed: bool = False, with_checkout: bool = True,
                 extra_env: dict[str, str] | None = None) -> tuple[dict, list[dict], str]:
        """Run preparation against the fake GitHub server; `resolved=...` leaves the real resolver in place."""
        case = Path(tempfile.mkdtemp(dir=self.tmp))
        repo, seed_sha, cand_sha = _candidate_checkout(case, src)
        if head_at_seed:
            git(repo, "checkout", "-q", seed_sha)
        patches = [mock.patch.dict(os.environ, extra_env or {})]
        if resolved is not ...:
            patches.append(mock.patch("factory.qualification.resolve_agy_bin", return_value=resolved))
        with _HostedQualificationFakeServer() as gh:
            gh.branch_heads[HEAD_BRANCH] = cand_sha
            gh.branch_heads["feature/demo"] = BASE_SHA
            for run in gh.check_runs:
                run.update(head_sha=cand_sha, conclusion=ci_conclusion)
            for p in patches:
                p.start()
            try:
                rec = prepare_qualification_candidate(
                    gh.base_url, REPO, case / "ev", head_branch=HEAD_BRANCH,
                    candidate_sha=cand_sha, base_sha=BASE_SHA,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                    agy_bin=None, allow_test_origin=True,
                    product_dir=repo if with_checkout else None,
                )
            finally:
                for p in reversed(patches):
                    p.stop()
            return rec, list(gh.requests), cand_sha

    def _gated_prepare(self, *, src: str = CALC_CANDIDATE_SRC, ci: str = "pass", move_head: bool = False,
                       raise_in: str | None = None, reviewers: tuple[str, str] | None = None,
                       ir_limit_s: int | None = None, restamp: str | None = None) -> SimpleNamespace:
        """#108 in the hosted order: run_hosted_qualification opens the scenario context while the candidate branch does
        not exist on the origin yet; preparation's PR lookup is when it appears. CI comes from the delivery fake GitHub
        server (`ci`: pass | fail | missing). Scenario 1's delivery gate is captured, and its child folder is read back
        through the gate's own CI and QA checks; scenarios 2-4 only record the candidate SHA they were given.
        #104: `reviewers` = (security, independent) script bodies behind ONE fake agy, which the resolver returns;
        `restamp` names an entry point whose returned record is relabelled as a review of the base revision."""
        case = Path(tempfile.mkdtemp(dir=self.tmp))
        origin, bare, cand, base = _seeded_origin(case, src)
        git(bare, "update-ref", "-d", f"refs/heads/{HEAD_BRANCH}")  # fresh run: no candidate when the context clones
        owner, name = REPO.split("/")
        pr = {"number": 1, "state": "open", "merged": False, "title": "q", "body": "",
              "html_url": f"https://github.com/{REPO}/pull/1",
              "head": {"ref": HEAD_BRANCH, "sha": cand, "repo": {"full_name": REPO}},
              "base": {"ref": "feature/demo", "sha": base, "repo": {"full_name": REPO}}}
        captured: dict[str, object] = {}
        scenario_shas: dict[str, str] = {}
        gates: list[tuple[dict, dict]] = []
        target: list[str] = []
        ctx_dirs: list[Path] = []  # the scenario context's child folder, as opened
        calls: list[tuple[str, dict]] = []  # wrapped entry-point calls and review submissions, in order
        agy = _dispatching_agy(case, *reviewers) if reviewers else None

        def _entry(mod: object, fn: str, override: dict | None = None) -> mock._patch:
            real = getattr(mod, fn)
            def call(*a: object, **kw: object) -> object:
                if raise_in == fn:
                    raise RuntimeError(f"{fn} unavailable")
                calls.append((fn, dict(kw)))
                out = real(*a, **{**kw, **(override or {})})
                out = {**out, "reviewed_revision": base} if restamp == fn else out
                captured[fn] = json.loads(json.dumps(out))
                return out
            return mock.patch.object(mod, fn, side_effect=call)

        real_ctx = qualification.hosted_scenario_context

        @contextlib.contextmanager
        def _ctx(*a: object, **kw: object) -> object:
            with real_ctx(*a, **kw) as ctx:
                ctx_dirs.append(ctx.child_dir)
                checks = [(r["name"], r["kind"], _OK)
                          for r in build_required_ci_checks({**ctx.child_contract, "head_branch": HEAD_BRANCH}, ctx.conf)]
                target.append(checks[-1][0])
                if ci == "fail":
                    checks[-1] = (target[0], checks[-1][1], [sys.executable, "-c", "raise SystemExit(1)"])
                elif ci == "missing":
                    checks = checks[:-1] + [("lint/unrelated", "guard", _OK)]
                gh.ci_spec = {"checks": checks}
                yield ctx

        def _pulls(*_a: object, **_kw: object) -> list[dict]:  # preparation creates the candidate after the clone
            git(bare, "update-ref", f"refs/heads/{HEAD_BRANCH}", cand)
            return [copy.deepcopy(pr)]

        sig = inspect.signature(qualification.submit_qualification_pr_review)

        def _submit(*a: object, **kw: object) -> tuple:  # the fake server has no reviews endpoint; record the request
            calls.append(("submit_qualification_pr_review", dict(sig.bind(*a, **kw).arguments)))
            return 200, {"id": 77}, ""

        def _advance(_pr: dict) -> None:  # the head branch moves while CI evidence is being recorded
            if git(bare, "rev-parse", f"refs/heads/{HEAD_BRANCH}") == cand:
                moved = git(bare, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit-tree",
                            f"{cand}^{{tree}}", "-p", cand, "-m", "moved")
                git(bare, "update-ref", f"refs/heads/{HEAD_BRANCH}", moved)

        real_gate = qualification.deliver_module.enforce_delivery_approval

        def _gate(**kw: object) -> dict:
            out = real_gate(**kw)
            gates.append((kw, out))
            return out

        def _scenario(label: str, result: object) -> object:
            def run(_url: str, _slug: str, _ev: Path, ctx: SimpleNamespace, *_a: object, **_kw: object) -> object:
                scenario_shas[label] = ctx.cand_sha
                return result
            return run

        sc = {"outcome": "failed", "status": "blocked", "blockers": ["not run in this test"], "artifacts": []}
        q = "factory.qualification."
        fakes = {"check_hosted_authorization": (True, ""), "observe_identity_and_permissions": (True, {}, []),
                 "check_branch_protection_and_topology": (True, {}, []), "check_seed_and_workflow_capabilities": (True, {}, []),
                 "get_remote_file_content": (200, "subtract test_subtract", ""),
                 "get_remote_commit": (200, {"sha": base}, ""), "resolve_agy_bin": agy,
                 "integrate_approved_child": SimpleNamespace(status="blocked", landed_sha=None, tested_sha=None, blockers=[]),
                 "assert_landed_landing_properties": (False, {}, ["not landed in this test"]),
                 "verify_qualification_pr_review": (True, {"state": "APPROVED", "commit_id": cand, "user": {"login": "cone-orgs"}}, [])}
        with contextlib.ExitStack() as st:
            gh = st.enter_context(_DisposableGitHubServer(bare_repo=bare, owner=owner, repo=name))
            gh.pulls[1] = copy.deepcopy(pr)
            # file:// so the clone receives only reachable objects, not the not-yet-pushed candidate (a local path hardlinks all).
            st.enter_context(mock.patch(q + "HOSTED_CLONE_URL_TEMPLATE", f"file://{origin}/{{repo_slug}}.git"))
            st.enter_context(mock.patch(q + "HOSTED_API_ORIGIN", gh.base_url))
            # #108 F4: preparation's CI/QA wait is bounded by this module constant, so a wrong-head regression fails fast.
            st.enter_context(mock.patch.object(qualification, "GATED_CI_QA_LIMIT_S", 15))
            for fn, rv in fakes.items():
                st.enter_context(mock.patch(q + fn, return_value=rv))
            st.enter_context(mock.patch(q + "get_remote_pulls", side_effect=_pulls))
            st.enter_context(mock.patch.object(qualification.deliver_module, "enforce_delivery_approval", side_effect=_gate))
            st.enter_context(mock.patch(q + "run_scenario_2_prereq_missing_and_denied", _scenario("sc2", sc)))
            st.enter_context(mock.patch(q + "run_scenario_3_competing_base_rejection", _scenario("sc3", (sc, HEAD_BRANCH, base, 3))))
            st.enter_context(mock.patch(q + "run_scenario_4_renewed_verification_after_base_change", _scenario("sc4", sc)))
            st.enter_context(_entry(ci_gate, "evaluate_child_pr_ci_gate"))
            st.enter_context(_entry(automated_qa, "evaluate_child_qa"))
            st.enter_context(_entry(security_review, "review_candidate_security"))
            ir_over = {"deadline": time.monotonic() + ir_limit_s, "limit_s": ir_limit_s} if ir_limit_s else None
            st.enter_context(_entry(independent_review, "review_candidate_independently", ir_over))
            st.enter_context(mock.patch(q + "submit_qualification_pr_review", side_effect=_submit))
            st.enter_context(mock.patch(q + "hosted_scenario_context", _ctx))
            if move_head:
                gh.on_patch_pull = _advance
            res = qualification.run_hosted_qualification(
                REPO, case / "ev", live_enabled=True, integrator_token="valid-int-tok", competitor_token="valid-comp-tok",
                base_url=gh.base_url)
            self.assertEqual(len(gates), 1, f"scenario 1 did not evaluate its delivery gate once: {res['blockers']}")
            gate_kw, gate = gates[0]
            child, child_dir, home, repo = gate_kw["child"], Path(gate_kw["child_dir"]), gate_kw["home"], gate_kw["repo"]
            ev = approval.load_prerequisite_evidence(child_dir, home)
            ci_eval = approval.evaluate_ci_prerequisite(cand, base, ev["ci_record"], repo=repo, home=home,
                                                        child=child, conf=gate_kw["conf"])
            qa_eval = approval.evaluate_qa_prerequisite(
                cand, base, ev["qa_record"], child_dir=child_dir, home=home, repo=repo, child=child,
                expected_tested_sha=ci_eval.get("tested_sha")) if isinstance(ev["qa_record"], dict) else {"status": "qa-missing"}
            qa_rounds = sorted((child_dir / "automated-qa").glob("round-*/record.json"))
            scenario_shas["sc1"] = res["scenarios"]["confirmed_landing"]["candidate_sha"]
            return SimpleNamespace(rec=res["preparation"], ev=ev, ci_eval=ci_eval, qa_eval=qa_eval, cand=cand, base=base,
                                   target=target[0], captured=captured, child_dir=child_dir, qa_rounds=qa_rounds,
                                   gate_kw=gate_kw, gate=gate, scenario_shas=scenario_shas, ctx_child_dir=ctx_dirs[0],
                                   sc1=res["scenarios"]["confirmed_landing"], sc1_gate_dirs=[Path(kw["child_dir"]) for kw, _ in gates],
                                   calls=list(calls), agy=agy,
                                   approvals=[kw for fn, kw in calls if fn == "submit_qualification_pr_review" and kw["event"] == "APPROVE"])

    def _named(self, r: SimpleNamespace, prefix: str) -> None:
        """Preparation names `prefix` among its own blockers (reviewer blockers always block, so `blocked` alone says nothing)."""
        self.assertEqual(r.rec["status"], "blocked")
        own = [b for b in r.rec["blockers"] if not b.startswith(_REVIEWER_BLOCKERS)]
        self.assertTrue(any(b.startswith(prefix) for b in own), f"no {prefix!r} blocker in {own}")

    def test_hosted_preparation_writes_gate_format_ci_and_qa(self) -> None:
        """#108 AC1/AC3: passing required checks give a ci-verification.json and an automated_qa record for the exact
        head, both accepted by the delivery gate's own CI and QA checks, and both exactly as the entry points made them.
        In the hosted order, scenarios 1-4 get the candidate preparation verified (F1), and scenario 1's delivery gate
        reads the folder preparation wrote, so its CI and QA prerequisites verify (F2)."""
        r = self._gated_prepare()
        self.assertEqual(r.scenario_shas, dict.fromkeys(("sc1", "sc2", "sc3", "sc4"), r.cand), "scenarios got another SHA")
        self.assertEqual((r.gate_kw["candidate_sha"], r.gate["candidate_sha"]), (r.cand, r.cand), r.gate_kw)
        gate_pre = r.gate.get("prerequisites") or {}
        self.assertEqual(((gate_pre.get("ci") or {}).get("status"), (gate_pre.get("automated_qa") or {}).get("status")),
                         ("verified", "qa-verified"), f"scenario 1's gate did not read preparation's records: {gate_pre}")
        self.assertEqual(r.ci_eval["status"], "verified", r.ci_eval)
        self.assertEqual(r.qa_eval["status"], "qa-verified", r.qa_eval)
        self.assertEqual((r.ev["ci_record"]["candidate_sha"], r.ev["qa_record"]["candidate_sha"]), (r.cand, r.cand))
        self.assertEqual(r.ev["ci_record"]["selection_plan"]["changed_paths"], ["src/calc.py", "tests/test_calc.py"],
                         "CI selection did not see the candidate's diff (was the candidate fetched after the clone?)")
        self.assertEqual(r.ev["ci_record"], r.captured["evaluate_child_pr_ci_gate"], "persisted CI record is not the CI gate's output")
        self.assertEqual(r.ev["qa_record"], r.captured["evaluate_child_qa"], "persisted QA record is not automated QA's output")
        ci, qa = r.rec["prerequisites"]["ci"], r.rec["prerequisites"]["qa"]
        self.assertEqual((ci.get("status"), ci.get("candidate_sha")), ("verified", r.cand), ci)
        self.assertEqual((qa.get("qa_verified"), qa.get("candidate_sha")), (True, r.cand), qa)
        # Real reviewers are #104: they still block, but nothing else does.
        self.assertEqual(r.rec["status"], "blocked")
        self.assertEqual([b for b in r.rec["blockers"] if not b.startswith(_REVIEWER_BLOCKERS)], [], r.rec["blockers"])

    def test_hosted_preparation_blocks_on_rejected_or_unavailable_ci_and_qa(self) -> None:
        """#108 AC2/AC3: the gate's own checks reject failed, missing or other-head CI and a failing QA case, and
        preparation names the reason; QA does not run on a candidate whose CI did not verify; an entry point that
        cannot run leaves no record and blocks as unavailable."""
        for name, kw in (("failed required check", dict(ci="fail")), ("missing required check", dict(ci="missing")),
                         ("evidence for a different head", dict(move_head=True))):
            with self.subTest(name):
                r = self._gated_prepare(**kw)
                ci_rec = r.ev["ci_record"]
                self.assertIsInstance(ci_rec, dict, "the CI gate's record is persisted even when it does not verify")
                self.assertEqual(ci_rec["candidate_sha"], r.cand)
                self.assertNotEqual(r.ci_eval["status"], "verified", r.ci_eval)
                self.assertNotEqual(r.rec["prerequisites"]["ci"].get("status"), "verified")
                self._named(r, "ci-not-verified")
                self.assertTrue(ci_rec["blockers"], ci_rec)
                for b in ci_rec["blockers"]:
                    self.assertTrue(any(b in pb for pb in r.rec["blockers"]), f"gate reason {b!r} not named in {r.rec['blockers']}")
                if not kw.get("move_head"):
                    self.assertTrue(any(r.target in pb for pb in r.rec["blockers"]), r.rec["blockers"])
                self.assertNotIn("evaluate_child_qa", r.captured, "QA ran on a candidate whose CI did not verify")
                self.assertEqual(r.qa_rounds, [])
        with self.subTest("QA case failing on the candidate"):
            r = self._gated_prepare(src=CALC_CANDIDATE_SRC.replace("return a + b", "return a - b"))
            self.assertEqual(r.ci_eval["status"], "verified", r.ci_eval)
            self.assertEqual(r.ev["qa_record"]["candidate_sha"], r.cand)
            self.assertNotEqual(r.qa_eval["status"], "qa-verified", r.qa_eval)
            self.assertIsNot(r.rec["prerequisites"]["qa"].get("qa_verified"), True)
            self._named(r, "qa-not-verified")
            self.assertTrue(any("QA-CALC-1" in b or "CRIT-CALC-1" in b for b in r.rec["blockers"]), r.rec["blockers"])
        for fn, key in (("evaluate_child_pr_ci_gate", "ci"), ("evaluate_child_qa", "qa")):
            with self.subTest(f"{fn} cannot run: unavailable, nothing hand-written"):
                r = self._gated_prepare(raise_in=fn)
                if key == "ci":
                    self.assertFalse((r.child_dir / "ci-verification.json").exists(), "a CI record was synthesized")
                self.assertEqual(r.qa_rounds if key == "qa" else [], [], "a QA record was synthesized")
                self.assertEqual(r.rec["prerequisites"][key].get("status"), "unavailable", r.rec["prerequisites"][key])
                self.assertNotEqual(r.ci_eval["status"] if key == "ci" else r.qa_eval["status"],
                                    "verified" if key == "ci" else "qa-verified")
                self._named(r, f"{key}-unavailable")

    def test_real_reviewers_positive_control(self) -> None:
        """#104 AC1/AC3: with CI and QA verified (#108) and runnable reviewers, preparation stores the security and
        independent-review records the factory entry points produced for the exact head; the delivery gate for that head
        passes, scenario 1's gate reads the same child folder, and exactly one operator-account APPROVE follows."""
        r = self._gated_prepare(reviewers=_GOOD_REVIEWERS)
        self.assertEqual((r.rec["status"], r.rec["blockers"]), ("prepared", []), r.rec["blockers"])
        for fn, name, ok_key, sid in (("review_candidate_security", "security-review.json", "ready", "sec-reviewer-1"),
                                      ("review_candidate_independently", "independent-review.json", "review_verified", "ind-rev-1")):
            disk = json.loads((r.child_dir / name).read_text(encoding="utf-8"))
            self.assertEqual(disk, r.captured[fn], f"{name} is not the entry point's record")
            self.assertEqual((disk[ok_key], disk["reviewed_revision"], disk["reviewer_session_id"]), (True, r.cand, sid))
            kw = next(k for f, k in r.calls if f == fn)
            self.assertEqual((kw["agy_bin"], kw["candidate_sha"], kw["child_dir"]), (r.agy, r.cand, r.ctx_child_dir))
            pre = r.rec["prerequisites"]["security" if fn.endswith("security") else "independent_review"]
            self.assertEqual((pre.get("status"), pre.get("candidate_sha"), pre.get("reviewer_bin"), pre.get("reviewer_session_id")),
                             ("verified", r.cand, r.agy, sid), pre)
        self.assertIs(r.gate.get("delivery_approved"), True, r.gate)
        self.assertEqual(r.sc1_gate_dirs[:1], [r.ctx_child_dir], "scenario 1 gated a folder other than ctx.child_dir")
        self.assertEqual((r.sc1["ci_verified"], r.sc1["competitor_approved"]), (True, True), r.sc1)
        self.assertEqual(len(r.approvals), 1, r.approvals)
        self.assertEqual((r.approvals[0]["candidate_sha"], r.calls[-1][0]), (r.cand, "submit_qualification_pr_review"))
        rev = r.rec["prerequisites"]["github_review"]
        self.assertEqual((rev.get("kind"), rev.get("independent_review")), ("operator-account-approval", False), rev)

    def test_any_failed_prerequisite_blocks_real_reviewers(self) -> None:
        """#104 AC2/AC3: from the positive baseline, one failing reviewer (exit, timeout, unverified or silent) or CI or
        QA alone blocks with the failure named and sends no APPROVE; a workspace that cannot be made private is a
        scenario-context-unavailable blocker, not an exception."""
        good_sec, good_ir = _GOOD_REVIEWERS
        silent, crash = "pass\n", "raise SystemExit(3)\n"
        variants = {
            "security reviewer fails": dict(reviewers=(crash, good_ir), role="security"),
            "security reviewer returns unverified": dict(reviewers=(_SEC_NO_SESSION, good_ir), role="security"),
            "security reviewer exits 0 with no output": dict(reviewers=(silent, good_ir), role="security"),
            "independent reviewer fails": dict(reviewers=(good_sec, crash), role="independent"),
            "independent reviewer times out": dict(reviewers=(good_sec, "import time\ntime.sleep(60)\n"), ir_limit_s=8,
                                                   role="independent"),
            "independent reviewer returns unverified": dict(
                reviewers=(good_sec, _make_staged_reviewer_script(outcome="changes-requested")), role="independent"),
            "independent reviewer exits 0 with no output": dict(reviewers=(good_sec, silent), role="independent"),
            "CI failure alone": dict(reviewers=_GOOD_REVIEWERS, ci="fail", role="ci"),
            "QA failure alone": dict(reviewers=_GOOD_REVIEWERS, src=CALC_CANDIDATE_SRC.replace("return a + b", "return a - b"),
                                     role="qa"),
        }
        for name, kw in variants.items():
            with self.subTest(name):
                role = kw.pop("role")
                r = self._gated_prepare(**kw)
                self.assertEqual(r.rec["status"], "blocked")
                self.assertEqual(r.approvals, [], f"{name}: APPROVE sent despite a failed prerequisite")
                self.assertNotEqual(r.rec["prerequisites"]["github_review"].get("kind"), "operator-account-approval")
                self.assertTrue(any(role in b.lower() for b in r.rec["blockers"]), r.rec["blockers"])
                if role in ("security", "independent"):
                    fn, key, ok_key = (("review_candidate_security", "security", "ready") if role == "security"
                                       else ("review_candidate_independently", "independent_review", "review_verified"))
                    self.assertTrue(fn in r.captured, f"the {role} reviewer entry point was not run")
                    self.assertIsNot(r.captured[fn][ok_key], True, r.captured[fn])
                    self.assertEqual(json.loads((r.child_dir / f"{role}-review.json").read_text(encoding="utf-8")),
                                     r.captured[fn], "the blocking record is not the entry point's own")
                    self.assertNotEqual(r.rec["prerequisites"][key].get("status"), "verified", r.rec["prerequisites"][key])
                    self.assertTrue(any(role in b.lower() and r.cand in b and str(r.captured[fn]["outcome"]) in b
                                        for b in r.rec["blockers"]), r.rec["blockers"])
        for fn, role, key in (("review_candidate_security", "security", "security"),
                              ("review_candidate_independently", "independent", "independent_review")):
            with self.subTest(f"{role} reviewer entry point raises: unavailable"):
                r = self._gated_prepare(reviewers=_GOOD_REVIEWERS, raise_in=fn)
                self.assertEqual((r.rec["status"], r.approvals), ("blocked", []), r.rec["blockers"])
                self.assertEqual(r.rec["prerequisites"][key]["status"], "unavailable", r.rec["prerequisites"][key])
                self.assertTrue(any(b.startswith(f"{role}-review-unavailable for {r.cand}") for b in r.rec["blockers"]),
                                r.rec["blockers"])
        with self.subTest("security record for another revision is not credited"):
            r = self._gated_prepare(reviewers=_GOOD_REVIEWERS, restamp="review_candidate_security")
            self.assertEqual((r.rec["status"], r.approvals), ("blocked", []), r.rec["blockers"])
            self.assertEqual(r.rec["prerequisites"]["security"]["status"], "not-verified", r.rec["prerequisites"]["security"])
            self.assertTrue(any(b.startswith("security-review-not-verified") and r.cand in b for b in r.rec["blockers"]),
                            r.rec["blockers"])
        with self.subTest("workspace cannot be made private: scenario-context-unavailable"):
            ev = self.tmp / "ev-ws"
            ev.mkdir()
            (self.tmp / "elsewhere").mkdir()
            (ev / "workspace").symlink_to(self.tmp / "elsewhere", target_is_directory=True)
            ok3 = (True, {}, [])
            fakes = {"check_hosted_authorization": (True, ""), "observe_identity_and_permissions": ok3,
                     "check_branch_protection_and_topology": ok3, "check_seed_and_workflow_capabilities": ok3,
                     "prepare_qualification_candidate": {"status": "blocked", "blockers": [], "prerequisites": {}}}
            with contextlib.ExitStack() as st:
                for fn, rv in fakes.items():
                    st.enter_context(mock.patch("factory.qualification." + fn, return_value=rv))
                res = qualification.run_hosted_qualification(
                    REPO, ev, live_enabled=True, integrator_token="valid-int-tok", competitor_token="valid-comp-tok")
            self.assertTrue(any(b.startswith("scenario-context-unavailable:") for b in res["blockers"]), res["blockers"])
            self.assertEqual(res["scenarios"], {})
            self.assertEqual(list((self.tmp / "elsewhere").iterdir()), [], "the workspace was written through the link")

    def test_factory_has_no_test_imports(self) -> None:
        """#97/#102 AC1: no .py under factory/ imports tests/support code or adds tests/ to sys.path; qualification keeps only the hosted path."""
        offences: list[str] = []
        sources = sorted((ROOT / "factory").rglob("*.py"))
        self.assertGreater(len(sources), 10)
        for rel, node in [(p.relative_to(ROOT), n) for p in sources for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"), filename=str(p)))]:
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            elif isinstance(node, ast.Call):
                call = ast.unparse(node)
                if re.match(r"sys\.path\.(insert|append|extend)\(", call) and "tests" in call:
                    offences.append(f"{rel}:{node.lineno}: {call}")
                if re.match(r"(importlib\.)?(import_module|__import__)\(", call) and re.search(r"['\"](tests|support)", call):
                    offences.append(f"{rel}:{node.lineno}: {call}")
            offences += [f"{rel}:{node.lineno}: import {n}" for n in names if n.split(".")[0] in ("tests", "support", "support_deliver")]
        self.assertEqual(offences, [], "factory/ must not depend on test code")
        self.assertFalse(hasattr(qualification, "run_offline_qualification"), "offline simulation belongs in tests/")

    def test_reviewer_presence_is_not_review(self) -> None:
        """AC2: without a reviewer that actually ran, security and independent review never read verified/approved."""
        fake = _fake_reviewer(self.tmp)
        variants = {
            "resolver-none": dict(resolved=None),
            "resolver-returns-existing-executable": dict(resolved=fake),
            "agy-on-path-and-AGY_BIN": dict(extra_env={"PATH": f"{Path(fake).parent}{os.pathsep}{os.environ.get('PATH', '')}", "AGY_BIN": fake}),
        }
        for name, kwargs in variants.items():
            with self.subTest(name):
                rec, _, _ = self._prepare(**kwargs)
                sec, ir = rec["prerequisites"]["security"], rec["prerequisites"]["independent_review"]
                for label, r in (("security", sec), ("independent_review", ir)):
                    self.assertNotIn(r.get("status"), ("verified", "approved", "passed"), f"{label}: {r}")
                    self.assertIsNot(r.get("ready"), True, label)
                    self.assertIsNot(r.get("approved"), True, label)
                if name == "resolver-none":
                    self.assertEqual(sec["status"], "unavailable")
                    self.assertEqual(ir["status"], "unavailable")
                self.assertEqual(rec["status"], "blocked")
                self.assertNotEqual(rec["outcome"], "prepared")

    def test_qa_runs_against_candidate_commit(self) -> None:
        """AC3: QA evidence names the candidate SHA it ran against and reflects the candidate's content, not the seed."""
        with self.subTest("failing candidate at checkout HEAD"):
            rec, _, cand = self._prepare(resolved=None, src=FAILING_SRC)
            qa = rec["prerequisites"]["qa"]
            self.assertEqual(qa.get("candidate_sha"), cand, qa)
            self.assertIsNot(qa.get("qa_verified"), True, qa)
            self.assertNotEqual(qa.get("status"), "verified", qa)
        with self.subTest("passing candidate at checkout HEAD"):
            rec, _, cand = self._prepare(resolved=None, src=PASSING_SRC)
            qa = rec["prerequisites"]["qa"]
            self.assertEqual(qa.get("candidate_sha"), cand, qa)
            self.assertIs(qa.get("qa_verified"), True, qa)
        with self.subTest("checkout left at seed copy while candidate fails"):
            rec, _, cand = self._prepare(resolved=None, src=FAILING_SRC, head_at_seed=True)
            qa = rec["prerequisites"]["qa"]
            self.assertIsNot(qa.get("qa_verified"), True, qa)
        with self.subTest("no candidate checkout: never falls back to the seed copy"):
            rec, _, cand = self._prepare(resolved=None, with_checkout=False)
            qa = rec["prerequisites"]["qa"]
            self.assertIsNot(qa.get("qa_verified"), True, qa)
            self.assertNotEqual(qa.get("status"), "verified", qa)
        with self.subTest("hosted: a leftover, locally modified candidate-checkout is not reused"):
            case = Path(tempfile.mkdtemp(dir=self.tmp))
            repo, _, cand = _candidate_checkout(case, FAILING_SRC)
            (case / "ev").mkdir()
            git(case, "clone", "-q", str(repo), str(case / "ev" / "candidate-checkout"))  # at cand, then dirtied
            (case / "ev" / "candidate-checkout" / "src" / "calc.py").write_text(PASSING_SRC, encoding="utf-8")
            fakes = {"check_hosted_authorization": dict(return_value=(True, "")), "fetch_remote_repo": {},
                     "get_remote_pulls": dict(return_value=[{"number": 1, "head": {"sha": cand}, "base": {"sha": BASE_SHA}}]),
                     "get_remote_file_content": dict(return_value=(200, "subtract test_subtract", "")),
                     "get_remote_commit": dict(return_value=(200, {"sha": BASE_SHA}, "")),
                     "poll_ci_check": dict(return_value=(True, {"status": "verified", "candidate_sha": cand}, [])),
                     "resolve_agy_bin": dict(return_value=None),
                     "clone_remote_repo": dict(side_effect=lambda dest, *a: git(Path(dest).parent, "clone", "-q", str(repo), str(dest)))}
            with contextlib.ExitStack() as st, _HostedQualificationFakeServer() as gh:
                for name, kw in fakes.items():
                    st.enter_context(mock.patch("factory.qualification." + name, **kw))
                rec = prepare_qualification_candidate(
                    gh.base_url, REPO, case / "ev", head_branch=HEAD_BRANCH, base_sha=BASE_SHA,
                    integrator_token="valid-int-tok", competitor_token="valid-comp-tok", allow_test_origin=False)
            self.assertIsNot(rec["prerequisites"]["qa"].get("qa_verified"), True, rec["prerequisites"]["qa"])

    def test_no_approval_when_prerequisite_not_passed(self) -> None:
        """AC4: no APPROVE review request is sent for a head whose prerequisites failed or are unavailable."""
        fake = _fake_reviewer(self.tmp)
        variants = {
            "reviewer-unavailable": dict(resolved=None),
            "ci-failed": dict(resolved=fake, ci_conclusion="failure"),
            "qa-failed": dict(resolved=fake, src=FAILING_SRC),
        }
        for name, kwargs in variants.items():
            with self.subTest(name):
                rec, requests, _ = self._prepare(**kwargs)
                approvals = [
                    r for r in requests
                    if r["method"] == "POST" and re.search(r"/pulls/\d+/reviews$", r["path"])
                    and (r.get("body") or {}).get("event") == "APPROVE"
                ]
                self.assertEqual(approvals, [], f"{name}: approval submitted despite unmet prerequisite")
                self.assertEqual(rec["status"], "blocked")
        # Scenario 1 credits CI and approval only when they were recorded for the SHA it lands (ctx.cand_sha).
        from support_deliver import setup_disposable_delivery_context
        (self.tmp / "ws").mkdir()
        with _HostedQualificationFakeServer() as gh, setup_disposable_delivery_context(self.tmp / "ws") as ctx:
            git(ctx.bare, "update-ref", "refs/heads/feature/demo", ctx.base_sha)
            gh.branch_heads = {HEAD_BRANCH: ctx.cand_sha, "feature/demo": ctx.base_sha}
            for label, sha, want in (("other-head", "f" * 40, False), ("landed-head", ctx.cand_sha, True)):
                with self.subTest(f"scenario-1 evidence for {label}"):
                    prep = {"prerequisites": {"ci": {"status": "verified", "candidate_sha": sha},
                                              "github_review": {"state": "APPROVED", "commit_id": sha}}}
                    sc = qualification.run_scenario_1_confirmed_landing(
                        gh.base_url, REPO, self.tmp / f"ev-sc1-{label}", ctx, "valid-int-tok", "valid-comp-tok",
                        allow_test_origin=True, prep_record=prep)
                    self.assertIs(sc["ci_verified"], want, sc)
                    self.assertIs(sc["competitor_approved"], want, sc)
                    if not want:
                        self.assertEqual(sc["outcome"], "failed")

    def test_hosted_clone_path_offline(self) -> None:
        """#104: the clone origin is injectable (HOSTED_CLONE_URL_TEMPLATE), so the hosted clone paths run offline."""
        def _origin(with_contract: bool) -> tuple[Path, Path, str, str, contextlib.AbstractContextManager]:
            case = Path(tempfile.mkdtemp(dir=self.tmp))
            origin, cand, base = _hosted_origin(case, with_contract=with_contract)
            seam = mock.patch("factory.qualification.HOSTED_CLONE_URL_TEMPLATE", f"{origin}/{{repo_slug}}.git")
            return case, origin, cand, base, seam

        with self.subTest("no child contract: scenario-context-unavailable, no examples/ fallback"):
            case, _, _, _, seam = _origin(with_contract=False)
            blockers: list[str] = []
            entered = False
            with seam, contextlib.suppress(qualification._ScenarioContextUnavailable), qualification.hosted_scenario_context(
                    case / "ws", REPO, "valid-int-tok", blockers=blockers):
                entered = True
            self.assertFalse(entered, "a scenario context was built without the hosted child contract")
            self.assertTrue(any(b.startswith("scenario-context-unavailable") for b in blockers), blockers)

        with self.subTest("context from the hosted clone; workspace recreated 0700"):
            case, _, cand, base, seam = _origin(with_contract=True)
            ws = case / "ws"
            ws.mkdir(mode=0o755)
            os.chmod(ws, 0o755)
            (ws / "stale").write_text("leftover", encoding="utf-8")
            with seam, qualification.hosted_scenario_context(ws, REPO, "valid-int-tok", blockers=[]) as ctx:
                self.assertEqual(stat.S_IMODE(ws.stat().st_mode), 0o700)
                self.assertFalse((ws / "stale").exists(), "workspace was reused")
                self.assertEqual(ctx.child_contract, json.loads((SEED_ASSETS_DIR / "factory" / "child-contract.json").read_text(encoding="utf-8")))
                self.assertEqual((ctx.cand_sha, ctx.base_sha), (cand, base))
                self.assertEqual(git(ctx.repo, "rev-parse", "HEAD"), base)

        for name, symlinked in (("candidate-checkout cloned from the origin", False), ("symlinked candidate-checkout refused", True)):
            with self.subTest(name):
                case, _, cand, _, seam = _origin(with_contract=True)
                outside = case / "outside"
                outside.mkdir()
                (case / "ev").mkdir()
                if symlinked:
                    (case / "ev" / "candidate-checkout").symlink_to(outside, target_is_directory=True)
                fakes = {"check_hosted_authorization": dict(return_value=(True, "")),
                         "get_remote_pulls": dict(return_value=[{"number": 1, "head": {"sha": cand}, "base": {"sha": BASE_SHA}}]),
                         "get_remote_file_content": dict(return_value=(200, "subtract test_subtract", "")),
                         "get_remote_commit": dict(return_value=(200, {"sha": BASE_SHA}, "")),
                         "poll_ci_check": dict(return_value=(True, {"status": "verified", "candidate_sha": cand}, [])),
                         "resolve_agy_bin": dict(return_value=None)}
                with contextlib.ExitStack() as st, _HostedQualificationFakeServer() as gh:
                    st.enter_context(seam)
                    for fn, kw in fakes.items():
                        st.enter_context(mock.patch("factory.qualification." + fn, **kw))
                    rec = prepare_qualification_candidate(
                        gh.base_url, REPO, case / "ev", head_branch=HEAD_BRANCH, base_sha=BASE_SHA,
                        integrator_token="valid-int-tok", competitor_token="valid-comp-tok", allow_test_origin=False)
                qa = rec["prerequisites"]["qa"]
                if symlinked:
                    self.assertEqual(list(outside.iterdir()), [], "the clone wrote through the candidate-checkout symlink")
                    self.assertIsNot(qa.get("qa_verified"), True, qa)
                    self.assertTrue(any("candidate-checkout" in b for b in rec["blockers"]), rec["blockers"])
                else:
                    self.assertEqual(qa.get("candidate_sha"), cand, qa)
                    self.assertIs(qa.get("qa_verified"), True, qa)


if __name__ == "__main__":
    unittest.main()
