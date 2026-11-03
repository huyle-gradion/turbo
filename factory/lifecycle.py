"""Stop, limit enforcement, budget recheck, and offline resume."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from factory import budget, config as config_module, gitio
from factory.config import now
from factory.errors import PolicyError, UsageError
from factory.gate_records import ResumeEntry
from factory.model import (
    PHASES,
    RECOVERABLE_STOPS,
    STOP_REASONS,
    TERMINAL_STOPS,
    BudgetPosition,
    Run,
)
from factory.paths import RuntimePaths
from factory.store import require_run, save_run

ACTIVE = ("ready", "red", "gates", "green")


def _moment(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def check_elapsed(run: Run) -> str | None:
    if run.limits is None or run.admitted_at is None:
        return None
    try:
        admitted = _moment(run.admitted_at)
    except ValueError:
        return "admitted_at is not a valid timestamp"
    if admitted is None:
        return None
    elapsed = (datetime.now(timezone.utc) - admitted).total_seconds()
    if elapsed > run.limits.time_seconds:
        return f"time limit exceeded: {int(elapsed)}s > {run.limits.time_seconds}s"
    return None


def check_limits(run: Run) -> str | None:
    detail = check_elapsed(run)
    if detail is not None:
        return detail
    if run.limits is not None and run.counters.operations_used >= run.limits.operations:
        return f"operation limit reached: {run.counters.operations_used}/{run.limits.operations}"
    return None


def remaining_seconds(run: Run) -> int | None:
    if run.limits is None or run.admitted_at is None:
        return None
    try:
        admitted = _moment(run.admitted_at)
    except ValueError:
        return None
    if admitted is None:
        return None
    return int(run.limits.time_seconds - (datetime.now(timezone.utc) - admitted).total_seconds())


def child_timeout(run: Run, configured: int) -> int:
    remaining = remaining_seconds(run)
    bounded = configured if remaining is None else min(configured, remaining)
    return max(1, int(bounded))


def stop_with(paths: RuntimePaths, run: Run, reason: str, detail: str | None) -> Run:
    if reason not in STOP_REASONS:
        raise UsageError(f"unknown stop reason: {reason}")
    if run.phase == "stopped":
        return run
    cleaned = detail.strip() if detail else ""
    stopped = replace(
        run,
        phase="stopped",
        stop_reason=reason,
        stop_detail=cleaned or None,
        prior_phase=run.phase,
        stopped_at=now(),
    )
    return save_run(paths, stopped)


def stop(paths: RuntimePaths, issue: int, reason: str, detail: str | None) -> Run:
    run = require_run(paths, issue)
    if reason not in STOP_REASONS:
        raise UsageError(f"unknown stop reason: {reason}")
    return stop_with(paths, run, reason, detail)


def enforce_limits(paths: RuntimePaths, run: Run) -> Run:
    detail = check_limits(run)
    if detail is not None:
        stop_with(paths, run, "not-ready", detail)
        raise PolicyError(detail)
    return run


def verify_elapsed(paths: RuntimePaths, run: Run) -> Run:
    detail = check_elapsed(run)
    if detail is not None:
        stop_with(paths, run, "not-ready", detail)
        raise PolicyError(detail)
    return run


def require_budget(paths: RuntimePaths, run: Run) -> Run:
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    config_module.require_complete(conf)
    try:
        current = budget.attestation(conf.budget, run.kind)
    except PolicyError as exc:
        stop_with(paths, run, "budget", str(exc))
        raise
    if run.budget != current:
        return save_run(paths, replace(run, budget=current))
    return run


def _superseded_detail(failure: str) -> str:
    return (
        f"non-recoverable: {failure}. Start a new issue and a new run identifier; "
        "counters are preserved, not reset."
    )


def expected_head(run: Run) -> str | None:
    match run.phase:
        case "ready":
            return run.base_sha
        case "red":
            return run.red_sha
        case "gates":
            return run.expected_green_sha
        case "green" | "local-verified":
            return run.green_sha
        case "stopped":
            prior = replace(run, phase=run.prior_phase or "unadmitted")
            return expected_head(prior)
        case "unadmitted":
            return None
        case unreachable:
            raise AssertionError(unreachable)


def _recover(paths: RuntimePaths, run: Run) -> tuple[bool, str | None]:
    """Return (recoverable_in_place, detail). A false flag is a dead end for this run."""
    if run.stop_reason not in RECOVERABLE_STOPS:
        return False, f"terminal stop: {run.stop_reason}"
    if run.prior_phase not in PHASES or run.prior_phase == "unadmitted":
        return False, "not-admitted"
    try:
        conf = config_module.load(paths)
        config_module.require_binding(conf, paths)
        config_module.require_complete(conf)
        if config_module.digest(conf) != run.gate_digest:
            return False, "gate configuration changed (digest mismatch); a stopped run has no re-stage path"
        budget.attestation(conf.budget, run.kind)
    except UsageError as exc:
        return True, f"config: {exc}"
    except PolicyError as exc:
        return True, f"budget: {exc}"
    if run.prior_phase in ACTIVE or run.prior_phase == "local-verified":
        detail = check_limits(run)
        if detail is not None:
            return False, f"{detail}; the admitted limits cannot be extended in place"
    return True, None


def _current_position(paths: RuntimePaths, run: Run, reasons: list[str]) -> BudgetPosition | None:
    if run.phase not in ACTIVE:
        return None
    try:
        conf = config_module.load(paths)
        config_module.require_binding(conf, paths)
        config_module.require_complete(conf)
        if config_module.digest(conf) != run.gate_digest:
            reasons.append("config: gate configuration changed (digest mismatch)")
            return None
        return budget.attestation(conf.budget, run.kind)
    except UsageError as exc:
        reasons.append(f"config: {exc}")
    except PolicyError as exc:
        reasons.append(f"budget: {exc}")
    return None


def resume(paths: RuntimePaths, issue: int, pr_state: str) -> ResumeEntry:
    run = require_run(paths, issue)
    reasons: list[str] = []
    current_branch = gitio.branch(paths.repo)
    dirty_text = gitio.status_porcelain(paths.repo)
    current_head = gitio.head(paths.repo)
    previous_phase = run.phase

    if run.phase == "unadmitted" or (run.phase == "stopped" and run.prior_phase == "unadmitted"):
        entry = ResumeEntry(now(), "refused", ("not-admitted",), pr_state, current_head, current_branch, bool(dirty_text), previous_phase)
        return save_entry(paths, run, entry)

    if current_branch != run.branch:
        reasons.append("branch-mismatch")
    if dirty_text:
        reasons.append("working-tree-dirty")
    expected = expected_head(run)
    if expected is None:
        reasons.append("head-unknown")
    elif current_head != expected:
        reasons.append("head-mismatch")

    remote = gitio.remote_ref(paths.repo, run.branch)
    if remote is not None and remote != current_head:
        reasons.append("remote-ref-mismatch")

    match pr_state:
        case "none":
            pass
        case "exists":
            reasons.append("pr-exists")
        case "unknown":
            reasons.append("pr-unknown")
        case unreachable:
            raise UsageError(f"unknown PR state: {pr_state}")

    refreshed = _current_position(paths, run, reasons)
    base = run if refreshed is None else replace(run, budget=refreshed)

    if run.phase in ACTIVE:
        exhausted = check_limits(run)
        if exhausted is not None:
            base = replace(
                base,
                phase="stopped",
                stop_reason="superseded",
                stop_detail=_superseded_detail(f"{exhausted}; the admitted limits cannot be extended in place"),
                prior_phase=run.phase,
                stopped_at=now(),
            )
            reasons.append(f"limit-exhausted: {exhausted}")

    recovered = False
    if run.phase == "stopped":
        if run.stop_reason in TERMINAL_STOPS:
            reasons.append("lane-stopped")
        else:
            recoverable, failure = _recover(paths, run)
            if failure is None:
                recovered = True
            elif recoverable:
                reasons.append(f"stop:{failure}")
            else:
                base = replace(base, stop_reason="superseded", stop_detail=_superseded_detail(failure))
                reasons.append("lane-stopped")

    verdict = "consistent" if not reasons else "refused"
    entry = ResumeEntry(now(), verdict, tuple(reasons), pr_state, current_head, current_branch, bool(dirty_text), previous_phase)
    if recovered and not reasons:
        restored = replace(
            base,
            phase=run.prior_phase or run.phase,
            stop_reason=None,
            stop_detail=None,
            prior_phase=None,
            stopped_at=None,
            resume_history=(*run.resume_history, entry),
        )
        save_run(paths, restored)
        return entry
    return save_entry(paths, base, entry)


def save_entry(paths: RuntimePaths, run: Run, entry: ResumeEntry) -> ResumeEntry:
    updated = replace(run, resume_history=(*run.resume_history, entry))
    save_run(paths, updated)
    return entry
