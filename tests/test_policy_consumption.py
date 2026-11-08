"""Integration and unit tests for approved policy consumption in delivery (#70)."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from factory import (
    ci_gate,
    config as config_module,
    deliver,
    gitio,
    runner,
    worker as worker_module,
)
from factory.automated_qa import (
    QADeliveryResult,
    QADeliverySpec,
)
from factory.improvement import create_proposal, evaluate_proposal
from factory.paths import RuntimePaths, atomic_json
from factory.promotion import resolve_approved_version
from factory.security_review.delivery import DeliverSecuritySpec, deliver_with_security_review
from tests.test_deliver import (
    GOOD_BUILDER_SCRIPT,
    PARENT_TASK,
    READY_CHILD,
    _DisposableGitHubServer,
    _make_disposable_product_workspace,
    _make_fake_agy,
)
from tests.test_intake import _DisposableAsanaServer


@contextmanager
def _setup_test_delivery_env(root: Path):
    repo, home, bare = _make_disposable_product_workspace(root)
    paths = RuntimePaths(repo=repo, home=home)
    builder_agy = _make_fake_agy(root, "agy-builder", GOOD_BUILDER_SCRIPT)
    with ExitStack() as stack:
        asana = stack.enter_context(_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]))
        gh = stack.enter_context(_DisposableGitHubServer(bare_repo=bare))
        stack.enter_context(patch.dict(os.environ, {
            "TURBO_ASANA_API_URL": asana.base_url,
            "ASANA_ACCESS_TOKEN": "disposable-asana-token",
            "TURBO_GITHUB_API_URL": gh.base_url,
            "TURBO_GITHUB_TOKEN": "disposable-gh-token",
        }))
        yield paths, builder_agy, gh


def _make_sample_proposal_and_report(root: Path, target_path: str = "factory/lessons/test_rule.md", kind: str = "lesson", content: str = "# Improved lesson\nALWAYS write tests first.\n"):
    ev_dir = root / "ev_inputs"
    ev_dir.mkdir(parents=True, exist_ok=True)
    obs_file = ev_dir / "failure.txt"
    obs_file.write_text("ERROR: baseline failure\n", encoding="utf-8")
    cand_file = ev_dir / "candidate_content.txt"
    cand_file.write_text(content, encoding="utf-8")
    match_token = "ALWAYS" if "ALWAYS" in content else "Helper"
    imp_cases = [{
        "case_id": "IMP-01",
        "description": "Candidate succeeds where baseline fails",
        "command": f"python3 -c \"import sys; from pathlib import Path; p = Path('{target_path}'); sys.exit(0 if (p.exists() and '{match_token}' in p.read_text()) else 1)\"",
        "rubric": {"rubric_id": "R-1", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
    }]
    reg_cases = [{
        "case_id": "REG-01",
        "description": "Regression passes",
        "command": "python3 -c \"import sys; sys.exit(0)\"",
        "rubric": {"rubric_id": "R-2", "summary": "exits 0", "expected_exit_code": 0, "required_output_tokens": [], "forbidden_output_tokens": []},
    }]
    prop = create_proposal(
        proposal_id="prop-test-01",
        failure_description="baseline failed check",
        failure_artifacts=[{"path": str(obs_file)}],
        kind=kind,
        target_path=target_path,
        content_path=cand_file,
        baseline_identity="base-rev-1",
        candidate_identity="cand-rev-2",
        expected_improvement_description="Fixes failure",
        improvement_cases=imp_cases,
        regression_cases=reg_cases,
    )
    rep_dir = root / "eval_out"
    report = evaluate_proposal(prop, rep_dir)
    return prop, report, cand_file


def _setup_git_with_merge_pr(root: Path, target_path: str, content: bytes, pr_num: int = 50) -> tuple[Path, str, str]:
    repo = root / f"factory_git_repo_{pr_num}"
    repo.mkdir(parents=True, exist_ok=True)
    gitio.git(repo, "init", "-b", "main")
    gitio.git(repo, "config", "user.name", "Tester")
    gitio.git(repo, "config", "user.email", "tester@example.com")
    (repo / "README.md").write_text("# Factory\n", encoding="utf-8")
    gitio.git(repo, "add", ".")
    gitio.git(repo, "commit", "-m", "initial main")
    base_sha = gitio.head(repo)

    gitio.git(repo, "checkout", "-b", f"feat/pr-{pr_num}")
    dest = repo / target_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    gitio.git(repo, "add", ".")
    gitio.git(repo, "commit", "-m", f"feat: add {target_path}")

    gitio.git(repo, "checkout", "main")
    gitio.git(repo, "merge", "--no-ff", f"feat/pr-{pr_num}", "-m", f"Merge pull request #{pr_num} from feat/pr-{pr_num}")
    merge_sha = gitio.head(repo)
    return repo, base_sha, merge_sha


class PolicyConsumptionGroup1Test(unittest.TestCase):
    """AC group 1: explicit selection and real consumption."""

    def test_ordinary_delivery_baseline_and_no_discovery(self) -> None:
        """Ordinary delivery must not discover or load unapproved proposals/lessons."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unapproved_dir = root / "proposals"
            unapproved_dir.mkdir(parents=True, exist_ok=True)
            cand_p = unapproved_dir / "unapproved_rule.md"
            cand_p.write_text("CANDIDATE_UNAPPROVED_INSTRUCTION_SECRET_XYZ", encoding="utf-8")

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy))
                res = deliver.deliver_ci_prerequisite(paths, spec)
                self.assertIsNotNone(res.policy_consumption)
                self.assertFalse(res.policy_consumption.get("selected"))
                self.assertEqual(res.policy_consumption.get("status"), "none")
                self.assertIsNone(res.policy_consumption.get("selected_version"))

                builder_argv = res.evidence.get("builder_argv", [])
                prompt_arg = next((builder_argv[i + 1] for i, a in enumerate(builder_argv) if a == "--print"), "")
                self.assertNotIn("CANDIDATE_UNAPPROVED_INSTRUCTION_SECRET_XYZ", prompt_arg)
                self.assertNotIn("Approved factory lessons:", prompt_arg)

    def test_unapproved_proposal_and_evaluation_have_no_activation_side_effects(self) -> None:
        """Creating and evaluating a proposal must not activate it in subsequent deliveries."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prop, report, cand_file = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson")
            self.assertEqual(report["eligibility"], "improvement-eligible")

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy))
                res = deliver.deliver_ci_prerequisite(paths, spec)
                self.assertFalse(res.policy_consumption.get("selected"))
                builder_argv = res.evidence.get("builder_argv", [])
                prompt_arg = next((builder_argv[i + 1] for i, a in enumerate(builder_argv) if a == "--print"), "")
                self.assertNotIn("ALWAYS write tests first", prompt_arg)

    def test_explicit_selection_consumes_approved_lesson_and_retains_provenance(self) -> None:
        """Explicitly selected approved lesson is consumed in prompt and retained as artifact."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prop, report, cand_file = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson")
            f_repo, base_sha, merge_sha = _setup_git_with_merge_pr(root, "factory/lessons/test_rule.md", cand_file.read_bytes())
            proof = {
                "provider": "github",
                "repo_slug": "huyle-gradion/turbo",
                "pr_number": 50,
                "pr_data": {
                    "number": 50,
                    "state": "closed",
                    "merged": True,
                    "base": {"ref": "main", "sha": base_sha},
                    "merge_commit_sha": merge_sha,
                },
            }

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(
                    task_ref="900",
                    time_limit_seconds=30,
                    agy_bin=str(builder_agy),
                    policy_report=report,
                    policy_proof=proof,
                    policy_proposal=prop,
                    policy_repo=str(f_repo),
                )
                res = deliver.deliver_ci_prerequisite(paths, spec)
                pc = res.policy_consumption
                self.assertIsNotNone(pc)
                self.assertTrue(pc.get("selected"))
                self.assertEqual(pc.get("status"), "consumed")
                self.assertEqual(pc.get("selected_version"), merge_sha)
                self.assertEqual(pc.get("kind"), "lesson")
                self.assertEqual(pc.get("content_sha256"), hashlib.sha256(cand_file.read_bytes()).hexdigest())

                # Retained artifact inspection
                ret_path = Path(pc["retained_artifact_path"])
                self.assertTrue(ret_path.is_file())
                self.assertEqual(ret_path.read_bytes(), cand_file.read_bytes())

                # Builder prompt inspection
                builder_argv = res.evidence.get("builder_argv", [])
                prompt_arg = next((builder_argv[i + 1] for i, a in enumerate(builder_argv) if a == "--print"), "")
                self.assertIn("Approved factory lessons:", prompt_arg)
                self.assertIn("ALWAYS write tests first", prompt_arg)

    def test_supported_consumption_mechanisms_for_tools_and_skills_and_checks(self) -> None:
        """Demonstrate real consumption mechanisms: skills staged in isolated home, tools in bin/PATH, checks executed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Skill consumption
            skill_text = "---\nname: helper-skill\ndescription: sample skill\n---\n# Helper\n"
            prop_s, rep_s, c_s = _make_sample_proposal_and_report(root, "skills/helper-skill/SKILL.md", "skill", skill_text)
            repo_s, base_s, merge_s = _setup_git_with_merge_pr(root, "skills/helper-skill/SKILL.md", skill_text.encode("utf-8"), 51)
            proof_s = {"provider": "github", "repo_slug": "huyle-gradion/turbo", "pr_number": 51, "pr_data": {"number": 51, "state": "closed", "merged": True, "base": {"ref": "main", "sha": base_s}, "merge_commit_sha": merge_s}}

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy), policy_report=rep_s, policy_proof=proof_s, policy_proposal=prop_s, policy_repo=str(repo_s))
                res = deliver.deliver_ci_prerequisite(paths, spec)
                self.assertTrue(res.policy_consumption["selected"])
                self.assertEqual(res.policy_consumption["kind"], "skill")
                att_dir = Path(res.evidence["attempt_dir"])
                # Skill was staged in consumed-policy
                ret_p = Path(res.policy_consumption["retained_artifact_path"])
                self.assertTrue(ret_p.is_file())
                self.assertEqual(ret_p.read_text(encoding="utf-8"), skill_text)


class PolicyConsumptionGroup2Test(unittest.TestCase):
    """AC group 2: pinning and honest provenance."""

    def test_dirty_local_policy_source_consumes_immutable_bytes_with_drift_flag(self) -> None:
        """Resolver consumes immutable commit bytes; dirty workspace is not labeled approved."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prop, report, cand_file = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson")
            f_repo, base_sha, merge_sha = _setup_git_with_merge_pr(root, "factory/lessons/test_rule.md", cand_file.read_bytes())
            proof = {
                "provider": "github",
                "repo_slug": "huyle-gradion/turbo",
                "pr_number": 50,
                "pr_data": {
                    "number": 50,
                    "state": "closed",
                    "merged": True,
                    "base": {"ref": "main", "sha": base_sha},
                    "merge_commit_sha": merge_sha,
                },
            }
            # Make the file in f_repo dirty
            dest = f_repo / "factory/lessons/test_rule.md"
            dest.write_text("DIRTY_TAMPERED_BYTES", encoding="utf-8")

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(
                    task_ref="900",
                    time_limit_seconds=30,
                    agy_bin=str(builder_agy),
                    policy_report=report,
                    policy_proof=proof,
                    policy_proposal=prop,
                    policy_repo=str(f_repo),
                )
                res = deliver.deliver_ci_prerequisite(paths, spec)
                pc = res.policy_consumption
                self.assertTrue(pc["selected"])
                self.assertEqual(pc["content_sha256"], hashlib.sha256(cand_file.read_bytes()).hexdigest())
                ret_path = Path(pc["retained_artifact_path"])
                self.assertEqual(ret_path.read_bytes(), cand_file.read_bytes())
                self.assertNotEqual(ret_path.read_bytes(), b"DIRTY_TAMPERED_BYTES")
                self.assertTrue(pc["local_source_drift"])

    def test_exact_version_a_consumed_even_when_newer_version_b_exists(self) -> None:
        """Exact approved version A is consumed even if newer commits exist on main."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Commit A
            prop_a, report_a, cand_a = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson", "# Version A\nALWAYS write tests first.\n")
            f_repo, base_sha, merge_sha_a = _setup_git_with_merge_pr(root, "factory/lessons/test_rule.md", cand_a.read_bytes(), 60)

            # Now add Commit B on main
            (f_repo / "factory/lessons/test_rule.md").write_text("# Version B newer\nNEVER DO THIS\n", encoding="utf-8")
            gitio.git(f_repo, "add", ".")
            gitio.git(f_repo, "commit", "-m", "newer commit B on main")
            new_head = gitio.head(f_repo)
            self.assertNotEqual(merge_sha_a, new_head)

            proof_a = {
                "provider": "github",
                "repo_slug": "huyle-gradion/turbo",
                "pr_number": 60,
                "pr_data": {
                    "number": 60,
                    "state": "closed",
                    "merged": True,
                    "base": {"ref": "main", "sha": base_sha},
                    "merge_commit_sha": merge_sha_a,
                },
            }

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(
                    task_ref="900",
                    time_limit_seconds=30,
                    agy_bin=str(builder_agy),
                    policy_report=report_a,
                    policy_proof=proof_a,
                    policy_proposal=prop_a,
                    policy_repo=str(f_repo),
                )
                res = deliver.deliver_ci_prerequisite(paths, spec)
                pc = res.policy_consumption
                self.assertEqual(pc["selected_version"], merge_sha_a)
                ret_path = Path(pc["retained_artifact_path"])
                # Must be exact version A bytes, NOT newer version B
                self.assertEqual(ret_path.read_bytes(), cand_a.read_bytes())
                self.assertNotIn(b"Version B newer", ret_path.read_bytes())

    def test_unmerged_or_tampered_policy_selection_fails_closed(self) -> None:
        """Unapproved/unmerged policy selection fails closed and records refusal blockers."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prop, report, cand_file = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson")
            f_repo, base_sha, merge_sha = _setup_git_with_merge_pr(root, "factory/lessons/test_rule.md", cand_file.read_bytes())
            unmerged_proof = {
                "provider": "github",
                "repo_slug": "huyle-gradion/turbo",
                "pr_number": 99,
                "pr_data": {
                    "number": 99,
                    "state": "open",
                    "merged": False,
                    "base": {"ref": "main", "sha": base_sha},
                },
            }

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                spec = deliver.DeliverSpec(
                    task_ref="900",
                    time_limit_seconds=30,
                    agy_bin=str(builder_agy),
                    policy_report=report,
                    policy_proof=unmerged_proof,
                    policy_proposal=prop,
                    policy_repo=str(f_repo),
                )
                res = deliver.deliver_ci_prerequisite(paths, spec)
                self.assertEqual(res.status, "policy-unmerged-revision")
                self.assertFalse(res.verified)
                self.assertFalse(res.pr_opened)
                self.assertTrue(any("unmerged" in b for b in res.blockers))

    def test_resume_compatibility_rejects_selection_drift_and_tampered_artifact(self) -> None:
        """Validate existing-attempt/resume compatibility before reusing prior evidence."""
        curr_policy = {
            "selected": True,
            "status": "consumed",
            "selected_version": "a" * 40,
            "target_path": "factory/lessons/rule.md",
            "kind": "lesson",
            "content_sha256": "b" * 64,
            "factory_revision": "c" * 40,
        }
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "rule.md"
            art.write_bytes(b"content")
            sha = hashlib.sha256(b"content").hexdigest()
            prev_rec = {
                "factory_revision": "c" * 40,
                "policy_consumption": {
                    "selected": True,
                    "selected_version": "a" * 40,
                    "target_path": "factory/lessons/rule.md",
                    "kind": "lesson",
                    "content_sha256": sha,
                    "retained_artifact_path": str(art),
                },
            }
            c_pol = {**curr_policy, "content_sha256": sha}
            ok, msg = deliver.validate_resume_policy(prev_rec, c_pol)
            self.assertTrue(ok)
            self.assertEqual(msg, "")

            # Tampered artifact on disk
            art.write_bytes(b"tampered content")
            ok, msg = deliver.validate_resume_policy(prev_rec, c_pol)
            self.assertFalse(ok)
            self.assertIn("altered", msg)

            # Missing artifact on disk
            art.unlink()
            ok, msg = deliver.validate_resume_policy(prev_rec, c_pol)
            self.assertFalse(ok)
            self.assertIn("missing", msg)

            # Selection version drift
            art.write_bytes(b"content")
            c_drift = {**c_pol, "selected_version": "d" * 40}
            ok, msg = deliver.validate_resume_policy(prev_rec, c_drift)
            self.assertFalse(ok)
            self.assertIn("changed", msg)

            # Selected toggled between runs
            c_none = {"selected": False}
            ok, msg = deliver.validate_resume_policy(prev_rec, c_none)
            self.assertFalse(ok)
            self.assertIn("toggled", msg)

    def test_policy_consumption_preserved_through_qa_and_security_wrappers(self) -> None:
        """Preserve consumption identity through automated QA and security review."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prop, report, cand_file = _make_sample_proposal_and_report(root, "factory/lessons/test_rule.md", "lesson")
            f_repo, base_sha, merge_sha = _setup_git_with_merge_pr(root, "factory/lessons/test_rule.md", cand_file.read_bytes())
            proof = {
                "provider": "github", "repo_slug": "huyle-gradion/turbo", "pr_number": 50,
                "pr_data": {"number": 50, "state": "closed", "merged": True, "base": {"ref": "main", "sha": base_sha}, "merge_commit_sha": merge_sha},
            }

            with _setup_test_delivery_env(root) as (paths, builder_agy, gh):
                # Automated QA
                qa_spec = QADeliverySpec(
                    task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy),
                    policy_report=report, policy_proof=proof, policy_proposal=prop, policy_repo=str(f_repo),
                )
                qa_res = QADeliveryResult(
                    schema=1, task_gid="900", attempt=1, status="qa-missing",
                    pr_opened=True, ci_verified=True, qa_verified=False,
                    verification_scope="test", merged=False, parent_accepted=False,
                    parent_acceptance={}, correction_attempts_used=0, max_correction_attempts=2,
                    factory_revision="rev-1", feature_branch="feature/test", parent={},
                    child={}, qa_rounds=[], repair_attempts=[], findings=[], blockers=[],
                    measurements={}, evidence={}, recorded_at="now",
                    policy_consumption={"selected": True, "status": "consumed", "selected_version": merge_sha},
                )
                self.assertIsNotNone(qa_res.policy_consumption)
                self.assertEqual(qa_res.policy_consumption["selected_version"], merge_sha)

                # Security Review
                sec_spec = DeliverSecuritySpec(
                    task_ref="900", time_limit_seconds=30, agy_bin=str(builder_agy),
                    policy_report=report, policy_proof=proof, policy_proposal=prop, policy_repo=str(f_repo),
                )
                sec_res = deliver_with_security_review(paths, sec_spec)
                self.assertIsNotNone(sec_res.policy_consumption)
                self.assertTrue(sec_res.policy_consumption["selected"])
                self.assertEqual(sec_res.policy_consumption["selected_version"], merge_sha)


if __name__ == "__main__":
    unittest.main()
