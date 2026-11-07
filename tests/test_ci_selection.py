"""Tests for authoritative CI test selection and deterministic spec/check policy (Issue #20)."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
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

    def test_ci_workflow_triggers_on_feature_branches_and_runs_trusted_selector_without_mutating_candidate_checkout(self) -> None:
        wf_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("feature/**", wf_text)
        self.assertNotIn("git checkout \"$BASE_SHA\"", wf_text)
        self.assertIn("from factory.ci_selection import select_ci_test_plan", wf_text)
        wf_plan_lines = [line.strip() for line in wf_text.splitlines() if line.strip().startswith("PLAN=$(python3 -I -c")]
        self.assertEqual(len(wf_plan_lines), 1)
        wf_plan_cmd = wf_plan_lines[0]

        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            (repo / "factory").mkdir(exist_ok=True)
            for src_file in (ROOT / "factory").glob("*.py"):
                (repo / "factory" / src_file.name).write_text(src_file.read_text(encoding="utf-8"), encoding="utf-8")
            (repo / "scripts").mkdir(exist_ok=True)
            (repo / "scripts" / "smoke.sh").write_text("#!/bin/sh\necho base-smoke\n", encoding="utf-8")
            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_intake_eval.py").write_text("import unittest\n", encoding="utf-8")
            (repo / "tests" / "test_intake.py").write_text("import unittest\n", encoding="utf-8")
            (repo / "tests" / "test_deliver.py").write_text("import unittest\n", encoding="utf-8")
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
            wf_exec = subprocess.run(
                [
                    "bash",
                    "-e",
                    "-c",
                    f'CHANGED=$(git diff --name-only "{base_sha}"...HEAD)\n'
                    f'DELETED=$(git diff --diff-filter=D --name-only "{base_sha}"...HEAD)\n'
                    'TRUSTED_DIR=$(mktemp -d)\n'
                    'trap \'rm -rf "$TRUSTED_DIR"\' EXIT\n'
                    f'git archive "{base_sha}" | tar -x -C "$TRUSTED_DIR"\n'
                    f'{wf_plan_cmd}\n'
                    'printf "%s" "$PLAN"\n',
                ],
                cwd=str(repo),
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(json.loads(wf_exec.stdout)["affected_tests"], plan["affected_tests"])
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
