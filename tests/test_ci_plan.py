"""Turbo's own CI plan: run only the touched areas, or shard the full suite (#115).

Area map pinned here (coarse; the planner owns the exact file lists):

| Changed path                                              | Plan                    |
|-----------------------------------------------------------|-------------------------|
| docs/**, pilot/**, root *.md, LICENSE,                    | docs-only, no tests     |
| examples/*.example.json                                   |                         |
| docs/security-review/** (read by test_security_review.py) | area:review             |
| skills/**                                                 | area:skills             |
| factory/deliver.py, integration.py, lifecycle.py,         | area:delivery           |
| tests/test_deliver*.py, test_delivery_*.py,               |                         |
| test_integration.py                                       |                         |
| factory/{independent_review,security_review,               | area:review and         |
| automated_qa}/** and the matching tests/ packages         | area:delivery (imports) |
| factory/qualification.py, examples/qualification/**,      | area:qualification      |
| tests/test_qualification*.py                              |                         |
| any other factory/*.py and its tests                      | area:core               |
| push event, no paths, unmapped path, deleted tests/**.py, | full, N shards          |
| CI or verification-chain path (.github, scripts, bin,     |                         |
| tests/support.py, factory/ci_selection.py, factory/cli.py)|                         |

Smoke runs when factory/, bin/, scripts/ or skills/ changed, and always on full.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import ROOT

PLANNER = ROOT / "scripts" / "ci_plan.py"
REVIEW_TESTS = ("tests/independent_review/", "tests/security_review/", "tests/automated_qa/")
QUAL_TESTS = ("tests/test_qualification",)
DELIVERY = "factory/deliver.py"


def all_tests(repo):
    return sorted(p.relative_to(repo).as_posix() for p in (repo / "tests").rglob("test_*.py"))


def plan(repo, changed, deleted=(), event="pull_request", shards=None):
    with tempfile.TemporaryDirectory() as tmp:
        changed_file, deleted_file = Path(tmp) / "changed", Path(tmp) / "deleted"
        changed_file.write_text("".join(p + "\n" for p in changed), encoding="utf-8")
        deleted_file.write_text("".join(p + "\n" for p in deleted), encoding="utf-8")
        argv = [sys.executable, "-I", str(PLANNER), "--repo", str(repo),
                "--changed-file", str(changed_file), "--deleted-file", str(deleted_file), "--event", event]
        if shards is not None:
            argv += ["--shards", str(shards)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=tmp)
    if result.returncode != 0:
        raise AssertionError(f"planner exited {result.returncode}: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


class CiPlanTest(unittest.TestCase):
    def assert_full(self, out, repo, shards=4):
        self.assertEqual(out["mode"], "full")
        self.assertTrue(out["smoke"])
        self.assertEqual([j["name"] for j in out["jobs"]], [f"shard:{i}" for i in range(1, shards + 1)])
        self.assertTrue(all(j["tests"] for j in out["jobs"]), "no empty shard")
        planned = [t for j in out["jobs"] for t in j["tests"]]
        self.assertEqual(sorted(planned), all_tests(repo), "every test file exactly once")

    def test_plan_selects_touched_areas_or_the_full_suite(self):
        # (label, changed, deleted, event, mode, area names, smoke, tests that must run, prefixes that must not)
        cases = (
            ("delivery only", [DELIVERY], [], "pull_request", "areas", {"delivery"}, True,
             {"tests/test_deliver.py", "tests/test_integration.py", "tests/test_delivery_lifecycle.py"},
             REVIEW_TESTS + QUAL_TESTS),
            ("docs only", ["docs/delivery/integration-ownership.md", "pilot/README.md", "CHANGELOG.md",
                           "AGENTS.md", "LICENSE", "examples/config.example.json"],
             [], "pull_request", "docs-only", set(), False, set(), ()),
            ("docs mixed with delivery", ["docs/delivery/README.md", "factory/integration.py"], [], "pull_request",
             "areas", {"delivery"}, True, {"tests/test_integration.py"}, REVIEW_TESTS + QUAL_TESTS),
            ("two areas", ["factory/qualification.py", "factory/integration.py"], [], "pull_request",
             "areas", {"qualification", "delivery"}, True,
             {"tests/test_qualification_prereqs.py", "tests/test_integration.py"}, REVIEW_TESTS),
            # Delivery code and tests import the review packages and their test helpers.
            *((f"review path {p}", [p], [], "pull_request", "areas", {"review", "delivery"}, p.startswith("factory/"),
               {"tests/test_deliver.py", "tests/independent_review/test_approval_gate.py",
                "tests/security_review/test_security_review.py", "tests/automated_qa/test_automated_qa.py"}, QUAL_TESTS)
              for p in ("factory/independent_review/approval.py", "factory/security_review/delivery.py",
                        "factory/automated_qa/delivery.py", "factory/automated_qa/__init__.py",
                        "tests/security_review/test_reviewer.py", "tests/independent_review/test_independent_review.py",
                        "tests/automated_qa/test_automated_qa_eval.py")),
            ("test read by two areas", ["skills/run-issue/SKILL.md", "factory/security_review/delivery.py"], [],
             "pull_request", "areas", {"skills", "review", "delivery"}, True,
             {"tests/test_bundle.py", "tests/security_review/test_security_review.py"}, ()),
            ("docs read by a test", ["docs/security-review/README.md"], [], "pull_request", "areas", {"review"}, False,
             {"tests/security_review/test_security_review.py"}, ()),
            ("qualification seed example", ["examples/qualification/seed/factory/child-contract.json"], [],
             "pull_request", "areas", {"qualification"}, False,
             {"tests/test_qualification.py", "tests/test_qualification_prereqs.py"}, REVIEW_TESTS),
            ("skill text", ["skills/run-issue/SKILL.md"], [], "pull_request", "areas", {"skills"}, True,
             {"tests/test_bundle.py"}, ()),
            ("core module", ["factory/verify.py"], [], "pull_request", "areas", {"core"}, True,
             {"tests/test_verify.py"}, ()),
            ("test file only", ["tests/test_integration.py"], [], "pull_request", "areas", {"delivery"}, False,
             {"tests/test_integration.py"}, REVIEW_TESTS),
            ("push to main", [DELIVERY], [], "push", "full", None, True, set(), ()),
            ("no changed paths", [], [], "pull_request", "full", None, True, set(), ()),
            ("unmapped path", ["newdir/unknown.txt"], [], "pull_request", "full", None, True, set(), ()),
            *((f"deleted {p}", [DELIVERY], [p], "pull_request", "full", None, True, set(), ())
              for p in ("tests/test_flow.py", "tests/automated_qa/test_automated_qa_eval.py", "tests/support_deliver.py")),
            *((f"chain file {p}", [p], [], "pull_request", "full", None, True, set(), ())
              for p in (".github/workflows/ci.yml", "factory/ci_selection.py", "tests/support.py",
                        "bin/factory", "factory/cli.py", "scripts/ci_plan.py")),
        )
        for label, changed, deleted, event, mode, areas, smoke, must, must_not in cases:
            with self.subTest(label):
                out = plan(ROOT, changed, deleted, event)
                self.assertIsInstance(out["reason"], str)
                self.assertTrue(out["reason"])
                if mode == "full":
                    self.assert_full(out, ROOT)
                    continue
                self.assertEqual(out["mode"], mode)
                self.assertEqual(out["smoke"], smoke)
                self.assertEqual({j["name"] for j in out["jobs"]}, {f"area:{a}" for a in areas})
                planned = [t for j in out["jobs"] for t in j["tests"]]
                self.assertEqual(len(planned), len(set(planned)), "a test file runs at most once")
                self.assertTrue(all((ROOT / t).is_file() for t in planned), planned)
                self.assertTrue(all(j["tests"] for j in out["jobs"]), "no empty area job")
                self.assertLessEqual(must, set(planned))
                jobs = {j["name"]: j["tests"] for j in out["jobs"]}
                if "area:delivery" in jobs:
                    self.assertIn("tests/test_deliver.py", jobs["area:delivery"])
                self.assertEqual([t for t in planned if t.startswith(must_not)] if must_not else [], [])

    def test_full_plan_shards_the_candidate_checkout_not_the_planner_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "candidate repo"
            shutil.copytree(ROOT / "factory", repo / "factory")
            for name in ("test_a.py", "test_b.py", "test_c.py", "helper.py", "pkg/test_d.py", "pkg/test_e.py"):
                (repo / "tests" / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / "tests" / name).write_text("", encoding="utf-8")
            self.assert_full(plan(repo, [DELIVERY], event="push", shards=3), repo, shards=3)
            self.assertEqual(len(all_tests(repo)), 5)


if __name__ == "__main__":
    unittest.main()
