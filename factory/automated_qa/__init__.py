"""Automated QA criterion evaluation, finding reconciliation, and rubric checks (Issue #21)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
from typing import Any, Callable

from factory import (
    ci_gate, ci_selection, config as config_module, deliver_checks,
    gitio, intake, intake_eval, runner, worker as worker_module,
)
from factory.config import now
from factory.errors import UsageError
from factory.paths import atomic_json, safe_dir, write_evidence

QA_VERIFICATION_SCOPE_NOTE = (
    "ci-and-automated-qa-only; not security-reviewed, independently approved, merge-approved, or parent-accepted"
)
SLUG_RE = re.compile(r"[^A-Za-z0-9_-]+")
VALID_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def _str_tuple(raw: Any, field: str, *, strip: bool = False) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)) or any(not isinstance(x, str) for x in raw):
        raise UsageError(f"QA rubric {field} must be a list or tuple of strings")
    return tuple(s for x in raw if (s := (x.strip() if strip else x)))


def _is_reserved_deterministic(value: str) -> bool:
    return NON_ALNUM_RE.sub("", value).upper() == "DETERMINISTIC"


@dataclass(frozen=True, slots=True)
class QARubric:
    rubric_id: str
    summary: str
    required_checks: tuple[str, ...]
    expected_exit_code: int = 0
    required_output_tokens: tuple[str, ...] = ()
    forbidden_output_tokens: tuple[str, ...] = ()
    requested_correction: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> QARubric:
        if not isinstance(d, dict):
            raise UsageError("QA rubric must be a JSON object")
        raw_exit = d.get("expected_exit_code", 0)
        if isinstance(raw_exit, bool) or not isinstance(raw_exit, int):
            raise UsageError(f"QA rubric expected_exit_code must be an integer, got {raw_exit!r}")
        return cls(
            rubric_id=str(d.get("rubric_id") or "").strip(),
            summary=str(d.get("summary") or "").strip(),
            required_checks=_str_tuple(d.get("required_checks"), "required_checks", strip=True),
            expected_exit_code=raw_exit,
            required_output_tokens=_str_tuple(d.get("required_output_tokens"), "required_output_tokens"),
            forbidden_output_tokens=_str_tuple(d.get("forbidden_output_tokens"), "forbidden_output_tokens"),
            requested_correction=str(d.get("requested_correction") or "").strip(),
        )


@dataclass(frozen=True, slots=True)
class QAEvaluationCase:
    case_id: str
    criterion_id: str
    description: str
    command: str
    rubric: QARubric

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> QAEvaluationCase:
        if not isinstance(d, dict):
            raise UsageError("QA evaluation case must be a JSON object")
        raw_rub = d.get("rubric")
        if raw_rub is not None and not isinstance(raw_rub, dict):
            raise UsageError("QA evaluation case rubric must be a JSON object")
        return cls(
            case_id=str(d.get("case_id") or "").strip(),
            criterion_id=str(d.get("criterion_id") or "").strip(),
            description=str(d.get("description") or "").strip(),
            command=str(d.get("command") or "").strip(),
            rubric=QARubric.from_dict(raw_rub or {}),
        )


def _validate_rubric(case: QAEvaluationCase) -> list[str]:
    issues: list[str] = []
    rub = case.rubric
    for label, val in (("case_id", case.case_id), ("rubric_id", rub.rubric_id), ("summary", rub.summary)):
        if not val or intake_eval.VAGUE_VERIFICATION_RE.fullmatch(val):
            issues.append(f"case {case.case_id!r} has missing or vague {label} {val!r}")
    if case.case_id and not VALID_ID_RE.fullmatch(case.case_id):
        issues.append(f"case {case.case_id!r} contains ambiguous identifier characters")
    if case.criterion_id and not VALID_ID_RE.fullmatch(case.criterion_id):
        issues.append(f"case {case.case_id!r} criterion_id {case.criterion_id!r} contains ambiguous identifier characters")
    if _is_reserved_deterministic(case.case_id):
        issues.append(f"case {case.case_id!r} uses reserved deterministic check identifier")
    if not rub.required_checks:
        issues.append(f"case {case.case_id!r} rubric is missing explicit required_checks")
    for chk in rub.required_checks:
        if intake_eval.VAGUE_VERIFICATION_RE.fullmatch(chk) or intake_eval.HUMAN_JUDGMENT_RE.search(chk):
            issues.append(f"case {case.case_id!r} rubric contains non-repeatable or vague check {chk!r}")
    if deliver_checks._verification_argv(case.command) is None:
        issues.append(f"case {case.case_id!r} command is not an executable check: {case.command!r}")
    elif ci_selection.WEAKENED_CMD_RE.search(case.command):
        issues.append(f"case {case.case_id!r} command weakens or skips verification: {case.command!r}")
    return issues


def _run_isolated_check(
    worktree_dir: Path, isolated_home: Path, qa_env: dict[str, str], round_dir: Path,
    home: Path, stem: str, command: str, deadline: float, limit_s: int,
    *, explicit_argv: tuple[str, ...] | None = None, secrets: tuple[str, ...] = (),
    candidate_sha: str | None = None, base_sha: str | None = None, tested_sha: str | None = None,
) -> dict[str, Any]:
    argv = explicit_argv if explicit_argv is not None else deliver_checks._verification_argv(command)
    red_cmd = intake.redact_value(command, secrets)
    red_argv = list(intake.redact_value(list(argv or ()), secrets))
    b_hdr = f"candidate_sha={candidate_sha}\nbase_sha={base_sha}\ntested_sha={tested_sha}\n" if (candidate_sha and base_sha and tested_sha) else ""

    def _fail_result(msg: str, *, exit_code: int | None = None, timed_out: bool = False) -> dict[str, Any]:
        red_err = intake.redact_value(msg.rstrip("\n") + "\n", secrets)
        if b_hdr and not deliver_checks.KEY_VAL_RE.search(red_err): red_err = b_hdr + red_err
        ev_path = write_evidence(round_dir, stem, red_err, home)
        return {
            "command": red_cmd, "argv": red_argv, "executed": False, "passed": False,
            "exit_code": exit_code, "duration_ms": 0, "timed_out": timed_out, "output_path": str(ev_path),
            "output_sha256": runner.digest_text(red_err), "output_excerpt": red_err[:600].strip(),
        }

    if not argv or (explicit_argv is None and ci_selection.WEAKENED_CMD_RE.search(command)):
        return _fail_result(f"unexecutable or weakened check command: {command!r}")
    try:
        timeout_s = max(1, int(math.ceil(deliver_checks.remaining_seconds(deadline, f"QA check {stem}", limit_s))))
        exit_code, out_s, err_s, duration_ms, timed_out = worker_module.execute_stream(
            worktree_dir, argv, qa_env, timeout_s, isolated_home=isolated_home, allow_network=False
        )
    except (deliver_checks.AttemptTimeoutError, TimeoutError) as exc:
        return _fail_result(f"[factory] QA check timed out: {exc}", exit_code=124, timed_out=True)
    except (worker_module.SandboxUnavailableError, OSError) as exc:
        return _fail_result(f"[factory] QA check execution error: {exc}")
    redacted = intake.redact_value((out_s + err_s).strip() + "\n", secrets)
    if b_hdr and not deliver_checks.KEY_VAL_RE.search(redacted): redacted = b_hdr + redacted
    ev_path = write_evidence(round_dir, stem, redacted, home)
    return {
        "command": red_cmd, "argv": red_argv, "executed": not timed_out,
        "passed": not timed_out and exit_code == 0, "exit_code": exit_code, "duration_ms": duration_ms,
        "timed_out": timed_out, "output_path": str(ev_path),
        "output_sha256": runner.digest_text(redacted), "output_excerpt": redacted[:600].strip(),
    }


def build_parent_acceptance_boundary(parent: dict[str, Any]) -> dict[str, Any]:
    parent_criteria = [
        {
            "id": str(c.get("id") or ""),
            "description": str(c.get("description") or ""),
            "classification": str(c.get("classification") or "ambiguous"),
            "authority": (
                "human-acceptance-qa-and-assigned-swe"
                if (str(c.get("classification") or "") == "human-judgment" or c.get("human_judgment"))
                else "integrated-feature-gate-and-human-merge"
            ),
            "evaluated_by_automated_qa": False,
            "status": "pending-human-acceptance",
        }
        for c in (parent.get("criteria") or ())
    ]
    return {
        "parent_gid": str(parent.get("gid") or ""), "parent_accepted": False,
        "parent_acceptance_status": "pending-human-acceptance",
        "automated_qa_authority": "child-subtask-engineering-criteria-only",
        "parent_criteria": parent_criteria,
    }


_build_parent_acceptance_boundary = build_parent_acceptance_boundary


def _finding_id(child_gid: str, criterion_id: str, check_or_case_id: str, *, is_deterministic: bool = False) -> str:
    gid_slug, cid_slug = SLUG_RE.sub("-", child_gid), SLUG_RE.sub("-", criterion_id)
    if is_deterministic:
        return f"QA-{gid_slug}-{cid_slug}-DETERMINISTIC"
    case_slug = SLUG_RE.sub("-", check_or_case_id)
    prefix = "RESERVED-" if _is_reserved_deterministic(check_or_case_id) else ""
    return f"QA-{gid_slug}-{cid_slug}-{prefix}{case_slug}"


def _build_observed_check(
    *, child_gid: str, cid: str, case_id: str, rubric_id: str | None, raw: dict[str, Any],
    candidate_sha: str, base_sha: str, tested_sha: str, requested_correction: str,
    rubric_failures: list[str], is_invalid: bool = False, is_deterministic: bool = False,
) -> dict[str, Any]:
    fid = _finding_id(child_gid, cid, case_id, is_deterministic=is_deterministic)
    timed_out = bool(raw.get("timed_out"))
    executed = bool(raw.get("executed") and raw.get("output_path") and not is_invalid and not timed_out)
    passed = bool(raw.get("passed") and raw.get("output_path") and not is_invalid and not timed_out)
    return {
        "finding_id": fid, "criterion_id": cid, "case_id": case_id, "rubric_id": rubric_id,
        "classification": "verification-gap" if (is_invalid or not executed) else "behavioral-failure",
        "executed": executed, "passed": passed, "timed_out": timed_out,
        "evidence_sha": str(raw.get("candidate_sha") or candidate_sha),
        "failing_evidence": {
            "command": raw.get("command"), "argv": raw.get("argv", []), "exit_code": raw.get("exit_code"),
            "output_path": raw.get("output_path"), "output_sha256": raw.get("output_sha256"),
            "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": tested_sha,
            "rubric_failures": rubric_failures, "output_excerpt": raw.get("output_excerpt", ""),
        },
        "requested_correction": requested_correction,
    }


def _record_observation(observed: dict[str, dict[str, Any]], obs: dict[str, Any]) -> None:
    fid = obs["finding_id"]
    if fid not in observed:
        observed[fid] = obs
        return
    existing = observed[fid]
    merged_failures = list(dict.fromkeys([
        *existing["failing_evidence"].get("rubric_failures", []),
        *obs["failing_evidence"].get("rubric_failures", []),
        f"colliding finding identity {fid!r}",
    ]))
    primary = existing if not existing["passed"] else obs
    observed[fid] = {
        **primary, "classification": "verification-gap", "executed": False, "passed": False,
        "timed_out": bool(existing.get("timed_out") or obs.get("timed_out")),
        "failing_evidence": {**primary["failing_evidence"], "rubric_failures": merged_failures},
    }


def reconcile_findings(
    *, child_gid: str, child: dict[str, Any], candidate_sha: str, base_sha: str, tested_sha: str,
    round_number: int, criterion_coverage: list[dict[str, Any]], regression_passed: bool,
    ci_reval_ok: bool, prior_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    in_scope = str((child.get("scope") or {}).get("in_scope") or "declared child scope")
    observed: dict[str, dict[str, Any]] = {}
    for cov in criterion_coverage:
        cid, det = cov["criterion_id"], cov.get("deterministic_check")
        if isinstance(det, dict):
            det_failures = list(
                det.get("rubric_failures") or ([] if det.get("passed") else [f"deterministic check exited with {det.get('exit_code')}"])
            )
            _record_observation(observed, _build_observed_check(
                child_gid=child_gid, cid=cid, case_id="DETERMINISTIC", rubric_id=None, raw=det,
                candidate_sha=candidate_sha, base_sha=base_sha, tested_sha=tested_sha,
                requested_correction=f"Fix criterion {cid} ({cov['description']}) within {in_scope} so `{det.get('command')}` exits 0.",
                rubric_failures=det_failures, is_invalid=det.get("status") == "invalid-rubric", is_deterministic=True,
            ))
        for er in cov.get("evaluation_cases") or ():
            case_id = str(er["case_id"])
            rub_obj = er.get("rubric") if isinstance(er.get("rubric"), dict) else {}
            req_corr = str(rub_obj.get("requested_correction") or "").strip() or (
                f"Address evaluation case {case_id} for criterion {cid} "
                f"({er.get('description') or cov['description']}) within {in_scope} and add regression test coverage."
            )
            _record_observation(observed, _build_observed_check(
                child_gid=child_gid, cid=cid, case_id=case_id, rubric_id=er.get("rubric_id"), raw=er,
                candidate_sha=candidate_sha, base_sha=base_sha, tested_sha=tested_sha, requested_correction=req_corr,
                rubric_failures=list(er.get("rubric_failures") or er.get("rubric_issues") or []),
                is_invalid=er.get("status") == "invalid-rubric", is_deterministic=False,
            ))

    prior_by_id = {str(f["finding_id"]): f for f in (prior_findings or []) if isinstance(f, dict) and f.get("finding_id")}
    results: list[dict[str, Any]] = []
    for fid in dict.fromkeys([*prior_by_id, *observed]):
        prev, obs = prior_by_id.get(fid), observed.get(fid)
        if prev is None and obs is not None and obs["passed"]:
            continue
        prev_sha = str((prev or {}).get("latest_candidate_sha") or (prev or {}).get("created_candidate_sha") or "")
        if not ci_reval_ok or (obs is not None and obs["evidence_sha"] != candidate_sha):
            blocker, status = "stale-evidence", "open"
        elif obs is not None and obs.get("timed_out"):
            blocker, status = "timed-out", "open"
        elif obs is None or not obs["executed"]:
            blocker, status = "missing-verification", "open"
        elif not obs["passed"]:
            blocker, status = "check-failed", "open"
        elif prev is not None and prev.get("status") == "open" and candidate_sha == prev_sha:
            blocker, status = "missing-verification", "open"
        elif not regression_passed:
            blocker, status = "regression-failed", "open"
        else:
            blocker, status = None, "resolved"
        was_resolved = prev is not None and prev.get("status") == "resolved" and prev.get("resolved_round") is not None
        res_round = (int(prev["resolved_round"]) if was_resolved else round_number) if status == "resolved" else None
        res_sha = (str(prev.get("resolved_candidate_sha") or candidate_sha) if was_resolved else candidate_sha) if status == "resolved" else None
        hist = list((prev or {}).get("history") or [])
        ev = obs["failing_evidence"] if obs is not None else {}
        hist.append({
            "round": round_number, "candidate_sha": candidate_sha, "status": status,
            "executed": bool(obs and obs["executed"]), "exit_code": ev.get("exit_code"),
            "output_path": ev.get("output_path"), "output_sha256": ev.get("output_sha256"),
            "resolution_blocker": blocker,
        })
        results.append({
            "finding_id": fid,
            "criterion_id": obs["criterion_id"] if obs is not None else str((prev or {}).get("criterion_id") or ""),
            "case_id": obs["case_id"] if obs is not None else str((prev or {}).get("case_id") or ""),
            "rubric_id": obs["rubric_id"] if obs is not None else (prev or {}).get("rubric_id"),
            "classification": obs["classification"] if obs is not None else str((prev or {}).get("classification") or "behavioral-failure"),
            "status": status,
            "created_round": int((prev or {}).get("created_round") or round_number),
            "created_candidate_sha": str((prev or {}).get("created_candidate_sha") or prev_sha or candidate_sha),
            "latest_round": round_number, "latest_candidate_sha": candidate_sha,
            "resolved_round": res_round, "resolved_candidate_sha": res_sha,
            "resolution_blocker": blocker,
            "failing_evidence": obs["failing_evidence"] if (obs is not None and not obs["passed"]) else (prev or {}).get("failing_evidence"),
            "requested_correction": (
                obs["requested_correction"]
                if (obs is not None and obs.get("requested_correction"))
                else str((prev or {}).get("requested_correction") or "")
            ),
            "history": hist,
        })
    return results


def _run_regression_checks(
    worktree_dir: Path, qa_env: dict[str, str], child: dict[str, Any], conf: config_module.Config,
    changed_paths: tuple[str, ...], deleted_paths: tuple[str, ...], run_check: Callable[..., dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    plan = ci_selection.select_ci_test_plan(child, conf, changed_paths, deleted_paths=deleted_paths, repo=worktree_dir)
    reg_env = {**qa_env, "PYTHONPATH": "tests:."} if (worktree_dir / "tests").is_dir() else dict(qa_env)
    specs: list[tuple[str, str, str, tuple[str, ...], dict[str, Any]]] = [
        (f"gate-{gn}", "guard", f"regression-gate-{gn}", g.argv, {})
        for gn in ("1", "2") if (g := conf.gates.get(gn)) is not None and g.kind == "command" and g.argv
    ]
    affected = [str(t).strip() for t in (plan.get("affected_tests") or ()) if str(t).strip()]
    if plan.get("mode") == "affected-only":
        specs.extend(
            (f"selected-{idx}", "selected-regression", f"regression-selected-{idx}", (sys.executable, "-m", "unittest", target, "-v"), {"target": target})
            for idx, target in enumerate(affected, start=1)
        )
    elif plan.get("mode") == "full-suite" and not any("unittest" in argv and "discover" in argv for _, _, _, argv, _ in specs):
        specs.append((
            "selected-full-suite", "selected-regression", "regression-selected-full-suite",
            (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"), {"target": "tests/test_*.py"},
        ))
    reg_checks = [
        {"id": cid, "kind": kind, **extra, **run_check(stem, shlex.join(argv), explicit_argv=argv, env=reg_env)}
        for cid, kind, stem, argv, extra in specs
    ]
    return plan, reg_checks, bool(reg_checks) and all(c["passed"] for c in reg_checks)


def _case_result(
    case: QAEvaluationCase, cid: str, secrets: tuple[str, ...],
    *, check_res: dict[str, Any] | None = None, status: str, passed: bool, failures: list[str],
) -> dict[str, Any]:
    base = check_res or {
        "command": intake.redact_value(case.command, secrets), "argv": [],
        "executed": False, "timed_out": False, "exit_code": None,
        "output_path": None, "output_sha256": None, "output_excerpt": "",
    }
    return {
        **base, "case_id": case.case_id or "UNMATCHED-CASE", "criterion_id": cid,
        "description": case.description, "rubric": asdict(case.rubric), "rubric_id": case.rubric.rubric_id,
        "passed": passed, "status": status, "rubric_failures": failures,
    }


def _evaluate_criterion_coverage(
    child_gid: str, criteria_list: list[dict[str, Any]], qa_cases: tuple[QAEvaluationCase, ...],
    run_check: Callable[..., dict[str, Any]], secrets: tuple[str, ...],
) -> list[dict[str, Any]]:
    known_cids = {str(c.get("id") or "AC").strip() for c in criteria_list}
    cases_by_crit: dict[str, list[QAEvaluationCase]] = {}
    unmatched_by_crit: dict[str, list[QAEvaluationCase]] = {}
    seen_fids, colliding_fids = set(), set()
    for case in qa_cases:
        fid = _finding_id(child_gid, case.criterion_id, case.case_id)
        (colliding_fids if fid in seen_fids else seen_fids).add(fid)
        target_map = cases_by_crit if case.criterion_id in known_cids else unmatched_by_crit
        target_map.setdefault(case.criterion_id or "UNMATCHED-CRITERION", []).append(case)

    coverage: list[dict[str, Any]] = []
    if not criteria_list:
        msg = "child sub-task has no acceptance criteria to evaluate"
        coverage.append({
            "criterion_id": "CRITERIA-MISSING", "description": msg, "parent_coverage": [],
            "deterministic_check": {
                "command": "", "argv": [], "executed": False, "passed": False, "status": "invalid-rubric",
                "exit_code": None, "output_path": None, "output_sha256": None, "rubric_failures": [msg], "output_excerpt": msg,
            },
            "evaluation_cases": [], "passed": False,
        })

    for crit in criteria_list:
        cid, ver_cmd = str(crit.get("id") or "AC").strip(), str(crit.get("verification") or "").strip()
        det_res = run_check(f"criterion-{SLUG_RE.sub('-', cid).lower()}-det", ver_cmd)
        eval_results: list[dict[str, Any]] = []
        for case in cases_by_crit.get(cid, ()):
            rub_issues = _validate_rubric(case)
            fid = _finding_id(child_gid, cid, case.case_id)
            if fid in colliding_fids:
                rub_issues.append(f"duplicate or colliding QA evaluation case identity {fid!r} for ({cid!r}, {case.case_id!r})")
            if rub_issues:
                eval_results.append(_case_result(case, cid, secrets, status="invalid-rubric", passed=False, failures=rub_issues))
                continue
            c_res = run_check(f"case-{SLUG_RE.sub('-', case.case_id).lower()}", case.command)
            raw_out = Path(c_res["output_path"]).read_text(encoding="utf-8") if c_res["output_path"] else ""
            rub = case.rubric
            rub_failures = (
                [f"expected exit_code {rub.expected_exit_code}, got {c_res['exit_code']}"]
                if (not c_res["executed"] or c_res["exit_code"] != rub.expected_exit_code) else []
            )
            rub_failures.extend(f"missing required output token {t!r}" for t in rub.required_output_tokens if t not in raw_out)
            rub_failures.extend(f"found forbidden output token {t!r}" for t in rub.forbidden_output_tokens if t in raw_out)
            case_passed = len(rub_failures) == 0 and not c_res.get("timed_out")
            eval_results.append(
                _case_result(case, cid, secrets, check_res=c_res, status="passed" if case_passed else "failed", passed=case_passed, failures=rub_failures)
            )
        coverage.append({
            "criterion_id": cid, "description": str(crit.get("description") or ""),
            "parent_coverage": list(crit.get("parent_coverage") or []),
            "deterministic_check": det_res, "evaluation_cases": eval_results,
            "passed": bool(det_res["passed"]) and all(er["passed"] for er in eval_results),
        })

    for ucid, ucases in unmatched_by_crit.items():
        coverage.append({
            "criterion_id": ucid, "description": f"Unknown child criterion {ucid!r}", "parent_coverage": [],
            "deterministic_check": None,
            "evaluation_cases": [
                _case_result(
                    case, ucid, secrets, status="invalid-rubric", passed=False,
                    failures=[f"QA case {case.case_id!r} references unknown child criterion {case.criterion_id!r}", *_validate_rubric(case)],
                )
                for case in ucases
            ],
            "passed": False,
        })
    return coverage


def evaluate_child_qa(
    *, repo: Path, home: Path, child_dir: Path, base_url: str, token: str, repo_slug: str,
    parent: dict[str, Any], child: dict[str, Any], child_record: dict[str, Any], conf: config_module.Config,
    qa_cases: tuple[QAEvaluationCase, ...] = (), prior_findings: list[dict[str, Any]] | None = None,
    round_number: int = 1, deadline: float, limit_s: int, approve_parent_acceptance: bool = False,
) -> dict[str, Any]:
    if approve_parent_acceptance:
        raise UsageError("parent task human acceptance is outside automated QA authority")
    secrets = deliver_checks.collect_redaction_secrets()
    if token.strip() and token.strip() not in secrets:
        secrets = (*secrets, token.strip())
    child_gid = str(child.get("gid") or child_record.get("gid") or "")
    candidate_sha = str(child_record.get("candidate_sha") or "")
    base_sha = str(child_record.get("base_sha") or "")
    tested_sha = str(child_record.get("tested_sha") or "")
    diff_obj = child_record.get("diff") or {}
    changed_paths = tuple(diff_obj.get("changed_paths") or ())
    deleted_paths = tuple(diff_obj.get("deleted_paths") or ())
    qa_root = safe_dir(child_dir / "automated-qa", create=True, root=home)
    round_dir = safe_dir(qa_root / f"round-{round_number}", create=True, root=home)
    boundary = build_parent_acceptance_boundary(parent)
    reval_trace: list[dict[str, Any]] = []
    ci_reval_rec = (
        {**child_record, "status": "verified", "verified": True}
        if child_record.get("ci_verified") is True and (child_record.get("ci_verification") or {}).get("verified") is True
        else child_record
    )
    try:
        reval = dict(ci_gate.revalidate_child_verification(
            repo=repo, base_url=base_url, token=token, repo_slug=repo_slug,
            child_record=ci_reval_rec, trace=reval_trace, deadline=deadline, limit_s=limit_s,
        ))
    except (deliver_checks.AttemptTimeoutError, TimeoutError) as exc:
        reval = {"verified": False, "status": "timed-out", "blockers": [str(exc)]}
    except deliver_checks.GitHubError as exc:
        reval = {"verified": False, "status": "pr-failed", "blockers": [str(exc)]}
    reval_trace_red = intake.redact_value(reval_trace, secrets)
    reval_trace_path = write_evidence(
        round_dir, "revalidation-github-requests", json.dumps(reval_trace_red, indent=2, sort_keys=True) + "\n", home
    )
    reval.update(github_requests=reval_trace_red, github_requests_path=str(reval_trace_path))
    ci_reval_ok = bool(reval.get("verified"))
    worktree_dir = round_dir / "worktree"
    qa_home = safe_dir(round_dir / "qa-home", create=True, root=home)
    qa_env, _ = worker_module.sanitized_env(dict(os.environ), worktree_dir, qa_home)
    qa_env["HOME"] = str(qa_home)
    qa_env.pop("PYTHONPATH", None)
    resolved_sha = worker_module.prepare_isolated_git_checkout(repo, worktree_dir, candidate_sha, deadline=deadline)

    def run_check(
        stem: str, command: str, *, explicit_argv: tuple[str, ...] | None = None, env: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return _run_isolated_check(
            worktree_dir, qa_home, env or qa_env, round_dir, home, stem,
            command, deadline, limit_s, explicit_argv=explicit_argv, secrets=secrets,
            candidate_sha=candidate_sha, base_sha=base_sha, tested_sha=tested_sha or resolved_sha,
        )

    try:
        criteria_list = list(child.get("criteria") or [])
        criterion_coverage = _evaluate_criterion_coverage(child_gid, criteria_list, qa_cases, run_check, secrets)
        reg_plan, reg_checks, reg_passed = _run_regression_checks(
            worktree_dir, qa_env, child, conf, changed_paths, deleted_paths, run_check
        )
        head_after, dirty_after = gitio.head(worktree_dir), gitio.status_porcelain(worktree_dir, builder_copy=True)
        role_separation = {
            "role": "automated-qa", "head_before": resolved_sha, "head_after": head_after,
            "worktree_clean": dirty_after == "", "candidate_modified_by_qa": head_after != resolved_sha or dirty_after != "",
        }
        any_timed_out = (
            reval.get("status") == "timed-out"
            or any(
                bool((c.get("deterministic_check") or {}).get("timed_out"))
                or any(bool(er.get("timed_out")) for er in (c.get("evaluation_cases") or ()))
                for c in criterion_coverage
            )
            or any(bool(rc.get("timed_out")) for rc in reg_checks)
        )
        findings = reconcile_findings(
            child_gid=child_gid, child=child, candidate_sha=resolved_sha, base_sha=base_sha, tested_sha=tested_sha,
            round_number=round_number, criterion_coverage=criterion_coverage, regression_passed=reg_passed,
            ci_reval_ok=ci_reval_ok, prior_findings=prior_findings,
        )
        open_findings = [f for f in findings if f["status"] != "resolved"]
        qa_verified = (
            ci_reval_ok and not any_timed_out and not role_separation["candidate_modified_by_qa"]
            and bool(criteria_list) and bool(criterion_coverage)
            and all(c["passed"] for c in criterion_coverage) and reg_passed and len(open_findings) == 0
        )
        if any_timed_out:
            status = "timed-out"
        elif not ci_reval_ok:
            status = str(reval.get("status") or "stale-revision")
        elif role_separation["candidate_modified_by_qa"]:
            status = "qa-role-violation"
        elif not reg_passed and all(c["passed"] for c in criterion_coverage):
            status = "regression-failed"
        else:
            status = "qa-verified" if qa_verified else "qa-failed"
        record = intake.redact_value(
            {
                "schema": 1, "role": "automated-qa", "round": round_number, "child_gid": child_gid,
                "status": status, "qa_verified": qa_verified, "verification_scope": QA_VERIFICATION_SCOPE_NOTE,
                "candidate_sha": resolved_sha, "base_sha": base_sha, "tested_sha": tested_sha,
                "ci_revalidation": reval, "role_separation": role_separation, "criterion_coverage": criterion_coverage,
                "regression_selection": reg_plan, "regression_checks": reg_checks, "regression_passed": reg_passed,
                "findings": findings, "open_finding_ids": [f["finding_id"] for f in open_findings],
                "parent_acceptance_boundary": boundary, "recorded_at": now(),
            },
            secrets,
        )
        atomic_json(round_dir / "record.json", record, home)
        return record
    finally:
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)


def load_qa_cases_file(path: Path) -> tuple[QAEvaluationCase, ...]:
    if not path.is_file():
        raise UsageError(f"QA evaluation cases file does not exist: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageError(f"invalid QA evaluation cases JSON in {path}: {exc}") from exc
    items = raw.get("cases") if isinstance(raw, dict) else raw
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise UsageError(f"QA evaluation cases file {path} must contain a JSON list of case objects")
    return tuple(QAEvaluationCase.from_dict(item) for item in items)


_DELIVERY_EXPORTS = ("QADeliveryResult", "QADeliverySpec", "run_automated_qa_delivery", "run_from_cli")


def __getattr__(name: str) -> Any:
    if name in _DELIVERY_EXPORTS:
        return getattr(importlib.import_module("factory.automated_qa.delivery"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "QA_VERIFICATION_SCOPE_NOTE",
    "QADeliveryResult",
    "QADeliverySpec",
    "QAEvaluationCase",
    "QARubric",
    "build_parent_acceptance_boundary",
    "evaluate_child_qa",
    "load_qa_cases_file",
    "reconcile_findings",
    "run_automated_qa_delivery",
    "run_from_cli",
]
