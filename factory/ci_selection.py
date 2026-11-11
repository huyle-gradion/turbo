"""Authoritative CI test selection and deterministic spec/check policy (Issue #20)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from factory import config as config_module, gitio
from factory.deliver_checks import (
    _matches_path_rule,
    _verification_argv,
    extract_explicit_paths,
    is_test_path,
)

PROTECTED_POLICY_PATHS = (
    ".github",
    "factory.json",
    "bin/factory",
    "scripts/smoke.sh",
    "scripts/smoke-turbo.sh",
    "tests/support.py",
    "factory/ci_selection.py",
    "factory/ci_gate.py",
    "factory/deliver_checks.py",
    "factory/config.py",
    "factory/gates.py",
    "factory/runner.py",
    "factory/sandbox.py",
)

ESSENTIAL_GUARD_TESTS = (
    "tests/test_bundle.py",
    "tests/test_cli_paths.py",
    "tests/test_evidence_integrity.py",
)

FULL_SUITE_TRIGGER_PATHS = (
    *PROTECTED_POLICY_PATHS,
    *ESSENTIAL_GUARD_TESTS,
    "tests/test_smoke_script.py",
    "bin",
    "scripts",
    "guards",
    "pyproject.toml",
    "factory/__init__.py",
    "factory/__main__.py",
    "factory/args.py",
    "factory/cli.py",
    "factory/errors.py",
    "factory/gitio.py",
    "factory/integrity.py",
    "factory/jsonshape.py",
    "factory/limits.py",
    "factory/model.py",
    "factory/paths.py",
    "factory/store.py",
    "factory/worker.py",
)

DEFAULT_DEPENDENCY_RULES: dict[str, tuple[str, ...]] = {
    "factory/admission.py": ("tests/test_admission.py", "tests/test_review_validation.py"),
    "factory/budget.py": ("tests/test_budget_policy.py", "tests/test_verify_budget.py"),
    "factory/budgetpolicy.py": ("tests/test_budget_policy.py", "tests/test_verify_budget.py"),
    "factory/deliver.py": ("tests/test_deliver.py", "tests/test_deliver_checks.py"),
    "factory/doctor.py": ("tests/test_limits_evidence.py", "tests/test_review_validation.py"),
    "factory/gate_records.py": (
        "tests/test_gate_chain.py",
        "tests/test_evidence_integrity.py",
        "tests/test_review_validation.py",
    ),
    "factory/green.py": (
        "tests/test_flow.py",
        "tests/test_evidence_integrity.py",
        "tests/test_review_followups.py",
    ),
    "factory/intake.py": ("tests/test_intake.py", "tests/test_intake_eval.py", "tests/test_deliver.py"),
    "factory/intake_eval.py": ("tests/test_intake_eval.py", "tests/test_intake.py", "tests/test_deliver.py"),
    "factory/lifecycle.py": (
        "tests/test_resume.py",
        "tests/test_final_round.py",
        "tests/test_review_followups.py",
    ),
    "factory/manifest.py": ("tests/test_evidence_integrity.py", "tests/test_final_round.py"),
    "factory/profile.py": ("tests/test_profile.py", "tests/test_prompt_profiles.py"),
    "factory/prompt.py": ("tests/test_prompt_profiles.py", "tests/test_review_followups.py"),
    "factory/redstage.py": (
        "tests/test_flow.py",
        "tests/test_tdd_replay.py",
        "tests/test_review_followups.py",
    ),
    "factory/replay.py": (
        "tests/test_tdd_replay.py",
        "tests/test_final_round.py",
        "tests/test_review_followups.py",
    ),
    "factory/report.py": ("tests/test_flow.py", "tests/test_review_followups.py"),
    "factory/verify.py": (
        "tests/test_verify.py",
        "tests/test_verify_budget.py",
        "tests/test_review_validation.py",
    ),
    "tests/test_intake_eval.py": ("tests/test_intake_eval.py", "tests/test_intake.py", "tests/test_deliver.py"),
    "tests/test_intake.py": ("tests/test_intake.py", "tests/test_deliver.py"),
    "tests/test_deliver_checks.py": ("tests/test_deliver_checks.py", "tests/test_deliver.py"),
    "tests/test_admission.py": ("tests/test_admission.py",),
    "tests/test_budget_policy.py": ("tests/test_budget_policy.py",),
    "tests/test_ci_selection.py": ("tests/test_ci_selection.py",),
    "tests/test_deliver.py": ("tests/test_deliver.py",),
    "tests/test_final_round.py": ("tests/test_final_round.py",),
    "tests/test_flow.py": ("tests/test_flow.py",),
    "tests/test_gate_chain.py": ("tests/test_gate_chain.py",),
    "tests/test_limits_evidence.py": ("tests/test_limits_evidence.py",),
    "tests/test_profile.py": ("tests/test_profile.py",),
    "tests/test_prompt_profiles.py": ("tests/test_prompt_profiles.py",),
    "tests/test_resume.py": ("tests/test_resume.py",),
    "tests/test_review_followups.py": ("tests/test_review_followups.py",),
    "tests/test_review_validation.py": ("tests/test_review_validation.py",),
    "tests/test_tdd_replay.py": ("tests/test_tdd_replay.py",),
    "tests/test_time_bounds.py": ("tests/test_time_bounds.py",),
    "tests/test_verify.py": ("tests/test_verify.py",),
    "tests/test_verify_budget.py": ("tests/test_verify_budget.py",),
    "tests/test_worker.py": ("tests/test_worker.py",),
}

WEAKENED_CMD_RE = re.compile(
    r"(?:(?:^|\s)-k\s+['\"]?not\b|--skip\b|pytest\.skip|unittest\.skip|\bexit\s+0\b)",
    re.IGNORECASE,
)


def protected_chain_paths(conf: config_module.Config | None) -> tuple[str, ...]:
    gate3 = conf.gates.get("3") if conf is not None else None
    gate3_paths = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
    return tuple(dict.fromkeys([*gate3_paths, *PROTECTED_POLICY_PATHS]))


def build_required_ci_checks(child: dict[str, Any], conf: config_module.Config) -> list[dict[str, Any]]:
    required: list[dict[str, Any]] = []
    for gate_num in ("1", "2", "3"):
        gate = conf.gates.get(gate_num)
        if gate is not None:
            cmd_desc = (
                " ".join(gate.argv)
                if gate.kind == "command"
                else f"protected-paths: {', '.join(gate.paths)}"
            )
            required.append(
                {
                    "id": f"gate-{gate_num}",
                    "name": f"guard/gate-{gate_num}",
                    "kind": "guard",
                    "criterion_id": None,
                    "parent_coverage": [],
                    "command": cmd_desc,
                }
            )
    for crit in child.get("criteria") or []:
        cid = str(crit.get("id") or "AC").strip()
        required.append(
            {
                "id": cid,
                "name": f"criterion/{cid}",
                "kind": "criterion",
                "criterion_id": cid,
                "parent_coverage": list(crit.get("parent_coverage") or []),
                "command": str(crit.get("verification") or "").strip(),
            }
        )
    return required


def select_ci_test_plan(
    child: dict[str, Any] | None = None,
    conf: config_module.Config | None = None,
    changed_paths: tuple[str, ...] = (),
    dependency_rules: dict[str, tuple[str, ...]] | None = None,
    *,
    deleted_paths: tuple[str, ...] = (),
    repo: Path | None = None,
) -> dict[str, Any]:
    rules = dependency_rules if dependency_rules is not None else DEFAULT_DEPENDENCY_RULES
    norm_paths = tuple(dict.fromkeys(p.strip().strip("/") for p in changed_paths if p.strip().strip("/")))
    norm_deleted = tuple(dict.fromkeys(p.strip().strip("/") for p in deleted_paths if p.strip().strip("/")))
    deleted_tests = [p for p in norm_deleted if is_test_path(p)]
    if repo is not None:
        for path in norm_paths:
            if is_test_path(path) and not (repo / path).is_file() and path not in deleted_tests:
                deleted_tests.append(path)
    affected: list[str] = []
    mode = "affected-only" if norm_paths else "full-suite"
    reason = "explicit-dependency-rules" if norm_paths else "uncertain-impact: no changed paths supplied"
    for path in norm_paths:
        if any(_matches_path_rule(path, trig) for trig in FULL_SUITE_TRIGGER_PATHS):
            mode = "full-suite"
            reason = f"shared-or-cross-cutting: {path}"
            break
        mapped = tuple(
            target
            for pattern, targets in rules.items()
            if _matches_path_rule(path, pattern)
            for target in targets
        )
        if not mapped:
            mode = "full-suite"
            reason = f"uncertain-impact: unmapped path {path}"
            break
        if repo is not None:
            for target in mapped:
                if not (repo / target).is_file() and target not in deleted_tests:
                    deleted_tests.append(target)
        for target in mapped:
            if target not in affected:
                affected.append(target)
    if deleted_tests:
        mode = "full-suite"
        reason = f"test-deletion-detected: {', '.join(deleted_tests)}"
    required = build_required_ci_checks(child or {}, conf) if conf is not None else []
    return {
        "mode": mode,
        "reason": reason,
        "changed_paths": list(norm_paths),
        "deleted_tests": deleted_tests,
        "test_deletion_detected": bool(deleted_tests),
        "essential_guards": [c for c in required if c["kind"] == "guard" and c["id"] != "gate-2"],
        "criterion_checks": [c for c in required if c["kind"] == "criterion"],
        "affected_tests": affected if mode == "affected-only" else ["tests/test_*.py"],
        "cache_policy": {
            "cache_dependencies": True,
            "cache_verification_results_across_revisions": False,
        },
        "cancel_superseded_runs": True,
    }


def _extract_verification_targets(ver_str: str) -> list[str]:
    argv = _verification_argv(ver_str) or ()
    targets: list[str] = []
    if "unittest" in argv and "discover" in argv:
        start_dir = "tests"
        pattern = "test*.py"
        for idx, tok in enumerate(argv):
            if tok in ("-s", "--start-directory") and idx + 1 < len(argv):
                start_dir = argv[idx + 1].strip().strip("/")
            elif tok in ("-p", "--pattern") and idx + 1 < len(argv):
                pattern = argv[idx + 1].strip().strip("/")
        combined = f"{start_dir}/{pattern}" if start_dir else pattern
        if combined:
            targets.append(combined)
    explicit_paths, _ = extract_explicit_paths(ver_str)
    for path in explicit_paths:
        if "/" in path and path not in targets:
            targets.append(path)
    return targets


def evaluate_spec_check_policy(
    child: dict[str, Any],
    conf: config_module.Config,
    changed_paths: tuple[str, ...] = (),
    *,
    deleted_paths: tuple[str, ...] = (),
    repo: Path | None = None,
) -> dict[str, Any]:
    conflicts: list[str] = []
    ambiguous_clauses: list[str] = []
    scope = child.get("scope") or {}
    protected = protected_chain_paths(conf)
    in_raw = str(scope.get("in_scope") or "").strip()
    out_raw = str(scope.get("out_of_scope") or "").strip()
    con_raw = str(scope.get("constraints") or "").strip()
    in_paths, in_mode = extract_explicit_paths(in_raw)
    out_paths, out_mode = extract_explicit_paths(out_raw)
    con_paths, con_mode = extract_explicit_paths(con_raw, require_negation=True)
    forbidden = [*out_paths, *con_paths]
    for label, text, mode in (
        ("in_scope", in_raw, in_mode),
        ("out_of_scope", out_raw, out_mode),
        ("constraints", con_raw, con_mode),
    ):
        if mode == "semantic-only" or (label == "constraints" and text and text.lower() != "none"):
            ambiguous_clauses.append(f"{label}: {text}")
    for in_p in in_paths:
        if config_module.protected_match(in_p, protected) or any(_matches_path_rule(in_p, p) for p in protected):
            conflicts.append(f"in_scope path {in_p!r} conflicts with protected policy path")
        if any(_matches_path_rule(in_p, r) for r in forbidden):
            conflicts.append(
                f"in_scope path {in_p!r} conflicts with out_of_scope or negated constraint rules {forbidden}"
            )
    for path in changed_paths:
        if config_module.protected_match(path, PROTECTED_POLICY_PATHS) or any(
            _matches_path_rule(path, p) for p in PROTECTED_POLICY_PATHS
        ):
            conflicts.append(f"candidate modified protected verification/CI policy path {path!r}")
        if repo is not None and is_test_path(path) and not (repo / path).is_file():
            conflicts.append(f"candidate deleted test coverage file {path!r}")
    for dp in deleted_paths:
        if is_test_path(dp):
            conflicts.append(f"candidate deleted test coverage file {dp!r}")
    for crit in child.get("criteria") or []:
        cid = str(crit.get("id") or "AC").strip()
        ver_str = str(crit.get("verification") or "").strip()
        if _verification_argv(ver_str) is None:
            conflicts.append(f"criterion {cid} verification is not an executable check command: {ver_str!r}")
            continue
        if WEAKENED_CMD_RE.search(ver_str):
            conflicts.append(f"criterion {cid} verification command weakens or skips required tests: {ver_str!r}")
        for vp in _extract_verification_targets(ver_str):
            if any(_matches_path_rule(vp, r) or _matches_path_rule(r, vp) for r in forbidden):
                conflicts.append(f"criterion {cid} verification target {vp!r} is excluded by out_of_scope/constraints")
            if in_paths and not any(_matches_path_rule(vp, r) or _matches_path_rule(r, vp) for r in in_paths):
                conflicts.append(f"criterion {cid} verification target {vp!r} is outside explicit in_scope {in_paths}")
            if repo is not None:
                if "*" in vp or "?" in vp:
                    if not any(p.is_file() for p in repo.glob(vp)):
                        conflicts.append(
                            f"criterion {cid} verification target pattern {vp!r} matched no test files in candidate"
                        )
                elif vp.endswith(".py") and not (repo / vp).is_file():
                    conflicts.append(f"criterion {cid} verification target {vp!r} is missing or deleted in candidate")
    deterministic_ok = len(conflicts) == 0
    semantic_verified = deterministic_ok and len(ambiguous_clauses) == 0
    status = (
        "conflict"
        if not deterministic_ok
        else ("deterministic-only-semantic-unverified" if ambiguous_clauses else "deterministic-verified")
    )
    return {
        "status": status,
        "deterministic_ok": deterministic_ok,
        "semantic_verified": semantic_verified,
        "conflicts": conflicts,
        "ambiguous_clauses": ambiguous_clauses,
        "provenance": (
            "deterministic policy rules enforced; natural-language clauses are reported for human/independent review"
            if ambiguous_clauses
            else "deterministic policy rules enforced"
        ),
    }


def detect_spec_check_conflicts(
    child: dict[str, Any],
    conf: config_module.Config,
    changed_paths: tuple[str, ...] = (),
    *,
    deleted_paths: tuple[str, ...] = (),
    repo: Path | None = None,
) -> list[str]:
    return evaluate_spec_check_policy(
        child,
        conf,
        changed_paths,
        deleted_paths=deleted_paths,
        repo=repo,
    )["conflicts"]


def run_trusted_base_selection(repo: Path, base_sha: str, head_ref: str = "HEAD") -> dict[str, Any]:
    def read(*args: str) -> str:
        done = gitio._run_git(repo, args, timeout=None, text=True)
        done.check_returncode()
        return done.stdout

    changed_out = read("diff", "--name-only", f"{base_sha}...{head_ref}")
    deleted_out = read("diff", "--diff-filter=D", "--name-only", f"{base_sha}...{head_ref}")
    with tempfile.TemporaryDirectory() as trusted_tmp:
        archive = gitio._run_git(repo, ("archive", base_sha), timeout=None)
        if archive.returncode != 0:
            raise RuntimeError(f"git archive failed for {base_sha}")
        subprocess.run(["tar", "-x", "-C", trusted_tmp], input=archive.stdout, check=True)
        selector_file = Path(trusted_tmp) / "factory" / "ci_selection.py"
        if not selector_file.is_file():
            return select_ci_test_plan(
                changed_paths=tuple(changed_out.splitlines()),
                deleted_paths=tuple(deleted_out.splitlines()),
                repo=repo,
            )
        code = (
            "import json, pathlib, sys; "
            "sys.path.insert(0, sys.argv[1]); "
            "from factory.ci_selection import select_ci_test_plan; "
            "print(json.dumps(select_ci_test_plan("
            "changed_paths=tuple(sys.argv[2].splitlines()), "
            "deleted_paths=tuple(sys.argv[3].splitlines()), "
            "repo=pathlib.Path(sys.argv[4]))))"
        )
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code, trusted_tmp, changed_out, deleted_out, str(repo)],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)
