"""Hosted qualification records only real prerequisite evidence (#97)."""
from __future__ import annotations

import ast, contextlib, os, re, shutil, tempfile, unittest
from pathlib import Path
from unittest import mock

from factory import qualification
from factory.qualification import SEED_ASSETS_DIR, prepare_qualification_candidate
from support import ROOT, commit, git, make_repo
from test_qualification import _HostedQualificationFakeServer

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


def _fake_reviewer(tmp: Path) -> str:
    """An executable that exists but is not a reviewer: it runs nothing and produces no review record."""
    exe = tmp / "bin" / "agy"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755)
    return str(exe)


class QualificationRealPrerequisiteTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp(prefix="turbo-qual-97-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = Path(tmp)
        env = mock.patch.dict(os.environ, {"TURBO_LIVE_QUALIFICATION": "0"})
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

    def test_qualification_has_no_test_imports(self) -> None:
        """AC1: factory/qualification.py imports no tests/support code, adds no tests/ path, and keeps only the hosted path."""
        path = ROOT / "factory" / "qualification.py"
        offences: list[str] = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            elif isinstance(node, ast.Call):
                call = ast.unparse(node)
                if re.match(r"sys\.path\.(insert|append|extend)\(", call) and "tests" in call:
                    offences.append(f"{node.lineno}: {call}")
                if re.match(r"(importlib\.)?(import_module|__import__)\(", call) and re.search(r"['\"](tests|support)", call):
                    offences.append(f"{node.lineno}: {call}")
            offences += [f"{node.lineno}: import {n}" for n in names if n.split(".")[0] in ("tests", "support", "support_deliver")]
        self.assertEqual(offences, [], "factory/qualification.py must not depend on test code")
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


if __name__ == "__main__":
    unittest.main()
