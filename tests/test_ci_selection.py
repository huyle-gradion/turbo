"""Tests for authoritative CI test selection and deterministic spec/check policy (Issue #20)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import tempfile
import unittest

from factory import ci_selection, config as config_module
from support import ROOT, config, git, home_dir, make_repo


class CiSelectionTest(unittest.TestCase):
    def test_explicit_dependency_mappings_cover_impl_and_test_pairs_and_downstream_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home = make_repo(root), home_dir(root)
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            child = {
                "gid": "101",
                "name": "Slice",
                "criteria": [
                    {
                        "id": "AC-1",
                        "parent_coverage": ["P-AC-1"],
                        "verification": "python3 -m unittest discover -s tests -p test_intake_eval.py -v",
                    }
                ],
            }
            plan = ci_selection.select_ci_test_plan(
                child,
                conf,
                ("factory/intake_eval.py", "tests/test_intake_eval.py"),
            )
            self.assertEqual(plan["mode"], "affected-only")
            self.assertEqual(
                plan["affected_tests"],
                ["tests/test_intake_eval.py", "tests/test_intake.py", "tests/test_deliver.py"],
            )
            self.assertEqual(len(plan["essential_guards"]), 2)
            self.assertEqual(len(plan["criterion_checks"]), 1)

            plan_deliver_checks_test = ci_selection.select_ci_test_plan(
                child,
                conf,
                ("tests/test_deliver_checks.py",),
            )
            self.assertEqual(plan_deliver_checks_test["mode"], "affected-only")
            self.assertEqual(
                plan_deliver_checks_test["affected_tests"],
                ["tests/test_deliver_checks.py", "tests/test_deliver.py"],
            )

            plan_leaf_test = ci_selection.select_ci_test_plan(
                child,
                conf,
                ("factory/admission.py", "tests/test_admission.py"),
            )
            self.assertEqual(plan_leaf_test["mode"], "affected-only")
            self.assertEqual(
                plan_leaf_test["affected_tests"],
                ["tests/test_admission.py", "tests/test_review_validation.py"],
            )

    def test_shared_fixtures_unmapped_tests_and_deletions_force_full_suite_without_factory_dir_heuristic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home = make_repo(root), home_dir(root)
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            child = {"gid": "101", "name": "Slice", "criteria": []}

            self.assertFalse((repo / "factory").exists())
            (repo / "src").mkdir()
            (repo / "src" / "auth.py").write_text("x = 1\n", encoding="utf-8")
            custom_rules = {"src/auth.py": ("tests/test_auth.py",)}
            plan_missing_mapped = ci_selection.select_ci_test_plan(
                child,
                conf,
                ("src/auth.py",),
                dependency_rules=custom_rules,
                repo=repo,
            )
            self.assertEqual(plan_missing_mapped["mode"], "full-suite")
            self.assertTrue(plan_missing_mapped["test_deletion_detected"])
            self.assertEqual(plan_missing_mapped["deleted_tests"], ["tests/test_auth.py"])

            (repo / "tests").mkdir()
            (repo / "tests" / "test_auth.py").write_text("x = 1\n", encoding="utf-8")
            plan_present = ci_selection.select_ci_test_plan(
                child,
                conf,
                ("src/auth.py",),
                dependency_rules=custom_rules,
                repo=repo,
            )
            self.assertEqual(plan_present["mode"], "affected-only")
            self.assertEqual(plan_present["affected_tests"], ["tests/test_auth.py"])

            for full_trigger in (
                (),
                ("tests/support.py",),
                ("tests/test_bundle.py",),
                ("tests/test_unmapped_helper.py",),
                ("factory/ci_selection.py",),
                ("factory/ci_gate.py",),
                ("factory/deliver_checks.py",),
                ("factory/sandbox.py",),
                ("factory/config.py",),
                ("unknown/path.py",),
            ):
                with self.subTest(paths=full_trigger):
                    res = ci_selection.select_ci_test_plan(child, conf, full_trigger)
                    self.assertEqual(res["mode"], "full-suite")

    def test_spec_check_conflicts_support_unittest_discover_globs_without_inventing_test_paths_and_report_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home = make_repo(root), home_dir(root)
            (repo / "src").mkdir()
            (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_auth.py").write_text("import unittest\n", encoding="utf-8")
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))

            valid_glob_child = {
                "gid": "101",
                "name": "Valid glob",
                "scope": {
                    "in_scope": "`src/app.py`, `tests/test_*.py`",
                    "out_of_scope": "none",
                    "constraints": "Keep helper pure; do not touch `AGENTS.md`",
                },
                "criteria": [
                    {
                        "id": "AC-1",
                        "description": "Verify that conflicts with expired tokens raise an error",
                        "verification": "python3 -m unittest discover -s tests -p 'test_*.py' -v",
                    }
                ],
            }
            conflicts = ci_selection.detect_spec_check_conflicts(
                valid_glob_child,
                conf,
                ("src/app.py", "tests/test_auth.py"),
                repo=repo,
            )
            self.assertEqual(conflicts, [])

            policy_report = ci_selection.evaluate_spec_check_policy(
                valid_glob_child,
                conf,
                ("src/app.py", "tests/test_auth.py"),
                repo=repo,
            )
            self.assertTrue(policy_report["deterministic_ok"])
            self.assertFalse(policy_report["semantic_verified"])
            self.assertEqual(policy_report["status"], "deterministic-only-semantic-unverified")
            self.assertTrue(policy_report["ambiguous_clauses"])

            non_test_cmd_child = {
                "gid": "102",
                "name": "Top-level script check",
                "scope": {
                    "in_scope": "`src/app.py`",
                    "out_of_scope": "`tests/app.py`",
                    "constraints": "none",
                },
                "criteria": [
                    {
                        "id": "AC-1",
                        "description": "Run app module check",
                        "verification": "python3 src/app.py",
                    }
                ],
            }
            self.assertEqual(
                ci_selection.detect_spec_check_conflicts(non_test_cmd_child, conf, ("src/app.py",), repo=repo),
                [],
            )

            missing_glob_child = {
                **valid_glob_child,
                "criteria": [
                    {
                        "id": "AC-1",
                        "description": "Missing pattern",
                        "verification": "python3 -m unittest discover -s tests -p 'test_nonexistent_*.py' -v",
                    }
                ],
            }
            self.assertTrue(
                ci_selection.detect_spec_check_conflicts(missing_glob_child, conf, ("src/app.py",), repo=repo)
            )

            excluded_glob_child = {
                **valid_glob_child,
                "scope": {
                    "in_scope": "`src/app.py`, `tests/`",
                    "out_of_scope": "`tests/test_auth.py`",
                    "constraints": "none",
                },
            }
            self.assertTrue(
                ci_selection.detect_spec_check_conflicts(excluded_glob_child, conf, ("src/app.py",), repo=repo)
            )

    def test_ci_workflow_plans_from_the_trusted_base_and_always_runs_guards(self) -> None:
        wf_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        jobs = dict(re.findall(r"^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)", wf_text.split("\njobs:\n", 1)[1], re.M | re.S))
        self.assertIn("feature/**", wf_text.split("\njobs:\n", 1)[0].split("pull_request:", 1)[1])
        self.assertNotIn('git checkout "$BASE_SHA"', wf_text)
        self.assertIn('git archive "$BASE_SHA"', jobs["plan"])
        diffs = re.findall(r"git diff [^\n]*", jobs["plan"])
        self.assertTrue(len(diffs) >= 2 and all("--no-renames" in d for d in diffs), "a rename counts as a delete")
        self.assertTrue(any("--diff-filter=D" in d and '"$WORK/deleted"' in d for d in diffs))
        on_error = re.search(r'if ! python3 -I "\$PLANNER".*?; then(.*?)\n\s*fi\n', jobs["plan"], re.S)
        self.assertIn("--event push", on_error.group(1), "a planner error forces the full suite")
        validator = textwrap.dedent(jobs["plan"].split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0])
        full = [t.relative_to(ROOT).as_posix() for t in (ROOT / "tests").rglob("test_*.py")]
        for event, mode, tests, ok in (("push", "full", full, True), ("push", "full", full[1:], False),
                                       ("push", "docs-only", [], False), ("pull_request", "docs-only", [], True)):
            with tempfile.TemporaryDirectory() as tmp, self.subTest(validator=(event, mode, len(tests))):
                plan_file = Path(tmp) / "plan.json"
                jobs_out = [{"name": "shard:1", "tests": tests}] if tests else []
                plan_file.write_text(json.dumps({"mode": mode, "jobs": jobs_out, "smoke": True}), encoding="utf-8")
                ran = subprocess.run([sys.executable, "-I", "-", str(plan_file), event], input=validator,
                                     cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(ran.returncode == 0, ok, ran.stderr)
        needs = re.search(r"(?m)^    needs: \[(.*)\]$", jobs["ci"]).group(1)
        self.assertEqual(set(needs.split(", ")), {"plan", "guards", "tests", "smoke"})
        reads = dict(re.findall(r"(?m)^          (\w+): \$\{\{ needs\.(\w+)\.result \}\}$", jobs["ci"]))
        self.assertEqual(set(reads.values()), {"plan", "guards", "tests", "smoke"})
        gate = jobs["ci"].split("run: |\n", 1)[1]
        ok_runs = ({}, {"tests": "skipped", "smoke": "skipped"})
        bad_runs = ({"plan": "failure"}, {"plan": "skipped"}, {"guards": "failure"}, {"tests": "failure"},
                    {"tests": "cancelled"}, {"smoke": "failure"}, {"smoke": "cancelled"})
        for results, ok in [(r, True) for r in ok_runs] + [(r, False) for r in bad_runs]:
            with self.subTest(aggregate=results):
                env = {var: results.get(job, "success") for var, job in reads.items()}
                ran = subprocess.run(["bash", "-c", gate], env={**env, "MODE": "areas", "PATH": "/usr/bin:/bin"},
                                     capture_output=True, text=True)
                self.assertEqual(ran.returncode == 0, ok, ran.stdout)
        fallback = re.search(r'if \[ -f "\$WORK/trusted/scripts/ci_plan\.py" \]; then\s*PLANNER="\$WORK/trusted/(.*?)"\s*else(.*?)\n\s*fi\n', jobs["plan"], re.S)
        self.assertIsNotNone(fallback, "the plan job must prefer the planner from the trusted base tree")
        self.assertEqual(fallback.group(1), "scripts/ci_plan.py")
        self.assertIn("EVENT=push", fallback.group(2), "a base without a planner forces the full suite")
        self.assertNotRegex(jobs["guards"], r"(?m)^    if:", "essential guards always run")
        self.assertRegex(jobs["ci"], r"(?m)^    name: Unit tests and smoke scripts$")
        self.assertRegex(jobs["ci"], r"(?m)^    if: always\(\)$")
        self.assertIn("${{ join(matrix.job.tests, ' ') }}", jobs["tests"].split("env:", 1)[1].split("run:", 1)[0])
        run_scripts = re.findall(r"^( +)run: (?:\|\n((?:\1 .*\n|\n)*)|(.*))", wf_text, re.M)
        self.assertGreaterEqual(len(run_scripts), 5)
        self.assertFalse([r for r in run_scripts if "${{" in r[1] + r[2]], "no expression is inlined into a script")

        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            (repo / "factory").mkdir(exist_ok=True)
            for src_file in (ROOT / "factory").glob("*.py"):
                (repo / "factory" / src_file.name).write_text(src_file.read_text(encoding="utf-8"), encoding="utf-8")
            (repo / "scripts").mkdir(exist_ok=True)
            (repo / "scripts" / "smoke.sh").write_text("#!/bin/sh\necho base-smoke\n", encoding="utf-8")
            (repo / "tests").mkdir(exist_ok=True)
            for name in ("test_intake_eval.py", "test_intake.py", "test_deliver.py"):
                (repo / "tests" / name).write_text("import unittest\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-q", "-m", "trusted base")
            base_sha = git(repo, "rev-parse", "HEAD")

            git(repo, "checkout", "-q", "-b", "task/101-narrow")
            (repo / "factory" / "intake_eval.py").write_text("# narrow change\n", encoding="utf-8")
            (repo / "tests" / "test_intake_eval.py").write_text("# test update\n", encoding="utf-8")
            git(repo, "add", "factory/intake_eval.py", "tests/test_intake_eval.py")
            git(repo, "commit", "-q", "-m", "narrow impl + test change")

            plan = ci_selection.run_trusted_base_selection(repo, base_sha)
            self.assertEqual(plan["mode"], "affected-only")
            self.assertEqual(
                plan["affected_tests"],
                ["tests/test_intake_eval.py", "tests/test_intake.py", "tests/test_deliver.py"],
            )
            self.assertEqual(git(repo, "status", "--porcelain"), "")

            (repo / "factory" / "ci_selection.py").write_text(
                "def select_ci_test_plan(*a, **kw):\n    return {'mode': 'affected-only', 'affected_tests': []}\n",
                encoding="utf-8",
            )
            (repo / "scripts" / "smoke.sh").write_text("#!/bin/sh\necho candidate-smoke\n", encoding="utf-8")
            git(repo, "add", "factory/ci_selection.py", "scripts/smoke.sh")
            git(repo, "commit", "-q", "-m", "candidate modifies selector and smoke script")

            tampered_plan = ci_selection.run_trusted_base_selection(repo, base_sha)
            self.assertEqual(tampered_plan["mode"], "full-suite")
            self.assertIn("shared-or-cross-cutting", tampered_plan["reason"])
            self.assertIn("candidate-smoke", (repo / "scripts" / "smoke.sh").read_text(encoding="utf-8"))
            self.assertEqual(git(repo, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
